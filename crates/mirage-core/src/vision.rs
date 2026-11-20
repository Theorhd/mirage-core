//! Sans-I/O XTLS-Vision framing, TLS-in-TLS inner handshake detection,
//! random padding, and direct-copy transition state machine.

use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::tls_parser::HELLO_RETRY_REQUEST_RANDOM;
use crate::vless::VlessUuid;

/// Errors produced by XTLS-Vision framing / unpadding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VisionError {
    /// Encountered an unknown Vision command byte (`0x03..=0xFF`).
    UnknownCommand(u8),
}

impl fmt::Display for VisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand(cmd) => write!(f, "unknown Vision command byte 0x{cmd:02x}"),
        }
    }
}

impl core::error::Error for VisionError {}

/// Vision padding commands matching Xray-core (`proxy/proxy.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionCommand {
    /// More padded blocks follow (`0x00`).
    Continue,
    /// Padding ends; continue proxying over outer Reality TLS 1.3 (`0x01`).
    End,
    /// Padding ends and stream switches to direct raw TCP copy (`0x02`).
    Direct,
}

impl VisionCommand {
    const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::Continue),
            0x01 => Some(Self::End),
            0x02 => Some(Self::Direct),
            _ => None,
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::Continue => 0x00,
            Self::End => 0x01,
            Self::Direct => 0x02,
        }
    }
}

/// Default Xray-core Vision padding seed `[min_long_threshold, rand_range, base_len, short_rand_range]`.
const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];

/// Maximum Vision chunk content size so header (up to 21 bytes) + content + up to 255B padding fits cleanly.
const MAX_VISION_BLOCK_TOTAL: usize = 8192;

/// Maximum number of outbound packets wrapped with Vision padding before forcing `CommandPaddingEnd`.
const MAX_VISION_PADDING_PACKETS: usize = 32;

/// Inner TLS 1.3 `supported_versions` extension bytes (`0x002b`, len `2`, `0x0304`).
const TLS13_SUPPORTED_VERSIONS_BYTES: &[u8] = &[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];

/// Maximum bytes buffered from a fragmented inner `ServerHello` header.
const MAX_INNER_SH_BUF: usize = 512;

/// TLS inspection state separating uplink (`ClientHello`) from downlink (`ServerHello`)
/// so uplink traffic can never tamper with XTLS `ServerHello` detection.
#[derive(Debug, Clone)]
pub struct VisionTlsFilter {
    uplink_packets_remaining: usize,
    downlink_packets_remaining: usize,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher_suite: u16,
    remaining_server_hello: usize,
    sh_header_buf: Vec<u8>,
    sh_header_parsed: bool,
    sh_tail: [u8; 5],
    sh_tail_len: u8,
}

impl Default for VisionTlsFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl VisionTlsFilter {
    /// Creates a new TLS inspection state (inspecting up to 8 initial packets per direction).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            uplink_packets_remaining: 8,
            downlink_packets_remaining: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher_suite: 0,
            remaining_server_hello: 0,
            sh_header_buf: Vec::new(),
            sh_header_parsed: false,
            sh_tail: [0u8; 5],
            sh_tail_len: 0,
        }
    }

    /// Inspects an uplink (`Client -> Upstream`) payload chunk solely for an inner
    /// TLS `ClientHello` marker. Never modifies downlink `ServerHello` state.
    pub fn inspect_uplink(&mut self, data: &[u8]) {
        if self.uplink_packets_remaining == 0 || data.is_empty() {
            return;
        }
        self.uplink_packets_remaining = self.uplink_packets_remaining.saturating_sub(1);
        if data.len() >= 6
            && data.first() == Some(&0x16)
            && data.get(1) == Some(&0x03)
            && data.get(5) == Some(&0x01)
        {
            self.is_tls = true;
            self.uplink_packets_remaining = 0;
        }
    }

    /// Inspects a downlink (`Upstream -> Client`) payload chunk for inner TLS 1.3
    /// `ServerHello` markers, rejecting `HelloRetryRequest` and handling fragmented headers.
    pub fn inspect_downlink(&mut self, data: &[u8]) {
        if self.downlink_packets_remaining == 0 || data.is_empty() {
            return;
        }
        self.downlink_packets_remaining = self.downlink_packets_remaining.saturating_sub(1);

        if self.remaining_server_hello == 0 && data.len() >= 6 {
            let b0 = *data.first().unwrap_or(&0);
            let b1 = *data.get(1).unwrap_or(&0);
            let b2 = *data.get(2).unwrap_or(&0);
            let b3 = *data.get(3).unwrap_or(&0);
            let b4 = *data.get(4).unwrap_or(&0);
            let b5 = *data.get(5).unwrap_or(&0);

            if b0 == 0x16 && b1 == 0x03 && b2 == 0x03 && b5 == 0x02 {
                let rec_len = usize::from(u16::from_be_bytes([b3, b4]));
                self.remaining_server_hello = 5usize.saturating_add(rec_len);
                self.is_tls = true;
                self.is_tls12_or_above = true;
                self.sh_header_buf.clear();
                self.sh_header_parsed = false;
                self.sh_tail_len = 0;
                self.cipher_suite = 0;
            }
        }

        if self.remaining_server_hello > 0 {
            let check_len = self.remaining_server_hello.min(data.len());
            self.remaining_server_hello = self.remaining_server_hello.saturating_sub(data.len());
            let Some(slice) = data.get(..check_len) else {
                return;
            };

            if !self.sh_header_parsed && self.sh_header_buf.len() < MAX_INNER_SH_BUF {
                let need = MAX_INNER_SH_BUF.saturating_sub(self.sh_header_buf.len());
                let take = need.min(slice.len());
                if let Some(part) = slice.get(..take) {
                    self.sh_header_buf.extend_from_slice(part);
                }
            }

            if !self.sh_header_parsed && self.sh_header_buf.len() >= 45 {
                if self.sh_header_buf.get(11..43) == Some(HELLO_RETRY_REQUEST_RANDOM.as_slice()) {
                    // HelloRetryRequest: not a final ServerHello; wait for the real ServerHello.
                    self.remaining_server_hello = 0;
                    self.sh_header_buf.clear();
                    self.sh_tail_len = 0;
                    return;
                }
                let sid_len = usize::from(*self.sh_header_buf.get(43).unwrap_or(&0));
                let cs_off = 44usize.saturating_add(sid_len);
                if let (Some(&c0), Some(&c1)) = (
                    self.sh_header_buf.get(cs_off),
                    self.sh_header_buf.get(cs_off.saturating_add(1)),
                ) {
                    self.cipher_suite = u16::from_be_bytes([c0, c1]);
                    self.sh_header_parsed = true;
                }
            }

            // Scan across chunk boundary using the 5-byte sliding tail.
            let tail_len = usize::from(self.sh_tail_len);
            let mut combined = Vec::with_capacity(tail_len.saturating_add(slice.len()));
            if let Some(tail) = self.sh_tail.get(..tail_len) {
                combined.extend_from_slice(tail);
            }
            combined.extend_from_slice(slice);

            if self.sh_header_parsed
                && combined
                    .windows(TLS13_SUPPORTED_VERSIONS_BYTES.len())
                    .any(|w| w == TLS13_SUPPORTED_VERSIONS_BYTES)
            {
                if matches!(self.cipher_suite, 0x1301..=0x1304) {
                    self.enable_xtls = true;
                }
                self.downlink_packets_remaining = 0;
                self.remaining_server_hello = 0;
                return;
            }

            let new_tail_len = slice.len().min(5);
            if let Some(tail_src) = slice.get(slice.len().saturating_sub(new_tail_len)..) {
                if let Some(dst) = self.sh_tail.get_mut(..new_tail_len) {
                    dst.copy_from_slice(tail_src);
                }
                self.sh_tail_len = u8::try_from(new_tail_len).unwrap_or(0);
            }

            if self.remaining_server_hello == 0 {
                self.downlink_packets_remaining = 0;
            }
        }
    }

    /// Returns `true` if inner TLS 1.3 handshake was detected and XTLS direct copy is allowed.
    #[must_use]
    pub const fn enable_xtls(&self) -> bool {
        self.enable_xtls
    }

    /// Returns `true` once downlink TLS inspection has completed.
    #[must_use]
    pub const fn is_downlink_finished(&self) -> bool {
        self.downlink_packets_remaining == 0
    }

    /// Returns `true` once uplink TLS inspection has completed.
    #[must_use]
    pub const fn is_uplink_finished(&self) -> bool {
        self.uplink_packets_remaining == 0
    }

    /// Returns `true` if any inner TLS ClientHello/ServerHello was detected.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Returns `true` if inner TLS 1.2+ ServerHello was detected.
    #[must_use]
    pub const fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    /// Returns remaining downlink packets before filtering stops.
    #[must_use]
    pub const fn remaining_packets(&self) -> usize {
        self.downlink_packets_remaining
    }
}

/// Checks whether `buf` consists of one or more complete TLS 1.3 `ApplicationData`
/// (`0x17 0x03 0x03 <u16 len> <payload>`) records with no trailing partial bytes.
#[must_use]
pub fn is_complete_tls_app_data_records(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let mut offset = 0usize;
    while offset < buf.len() {
        let Some(hdr) = buf.get(offset..offset.saturating_add(5)) else {
            return false;
        };
        if hdr.first() != Some(&0x17) || hdr.get(1) != Some(&0x03) || hdr.get(2) != Some(&0x03) {
            return false;
        }
        let b3 = *hdr.get(3).unwrap_or(&0);
        let b4 = *hdr.get(4).unwrap_or(&0);
        let rec_len = usize::from(u16::from_be_bytes([b3, b4]));
        let Some(next) = offset.checked_add(5).and_then(|v| v.checked_add(rec_len)) else {
            return false;
        };
        if next > buf.len() {
            return false;
        }
        offset = next;
    }
    offset == buf.len()
}

/// Mode of the Vision unpadder after processing buffered bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpadMode {
    /// Actively decoding Vision padded blocks.
    Padding,
    /// Padding ended (`CommandPaddingEnd`), pass subsequent outer-TLS bytes verbatim.
    Passthrough,
    /// Direct copy triggered (`CommandPaddingDirect`); switch to raw TCP copy.
    DirectCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnpadStep {
    Initial(usize),
    Header(usize),
    Content(usize),
    Padding(usize),
}

/// Stateful Sans-I/O XTLS-Vision unpadder for uplink (`Client -> Server`).
#[derive(Debug)]
pub struct VisionUnpadder {
    user_uuid: VlessUuid,
    mode: UnpadMode,
    step: UnpadStep,
    uuid_buf: [u8; 16],
    hdr_buf: [u8; 5],
    current_command: VisionCommand,
    content_len: usize,
    padding_len: usize,
}

impl Drop for VisionUnpadder {
    fn drop(&mut self) {
        self.uuid_buf.zeroize();
        self.hdr_buf.zeroize();
    }
}

/// Output produced by [`VisionUnpadder::feed`].
#[derive(Clone, PartialEq, Eq)]
pub struct UnpaddedOutput {
    /// Unpadded inner payload bytes ready to forward to upstream.
    pub payload: Zeroizing<Vec<u8>>,
    /// Current unpadder mode after processing this chunk.
    pub mode: UnpadMode,
    /// Any trailing bytes that belong to raw direct-copy mode (after `CommandPaddingDirect`).
    pub direct_trailing: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for UnpaddedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnpaddedOutput")
            .field("payload_len", &self.payload.len())
            .field("mode", &self.mode)
            .field("direct_trailing_len", &self.direct_trailing.len())
            .finish()
    }
}

impl VisionUnpadder {
    /// Creates a new Vision unpadder bound to the authenticated client UUID.
    #[must_use]
    pub fn new(user_uuid: VlessUuid) -> Self {
        Self {
            user_uuid,
            mode: UnpadMode::Padding,
            step: UnpadStep::Initial(0),
            uuid_buf: [0u8; 16],
            hdr_buf: [0u8; 5],
            current_command: VisionCommand::Continue,
            content_len: 0,
            padding_len: 0,
        }
    }

    /// Returns the current mode (`Padding`, `Passthrough`, or `DirectCopy`).
    #[must_use]
    pub const fn mode(&self) -> UnpadMode {
        self.mode
    }

    /// Feeds decrypted outer-TLS uplink bytes and returns unpadded inner payload
    /// plus updated mode, failing closed on unknown Vision command bytes.
    pub fn feed(&mut self, input: &[u8]) -> Result<UnpaddedOutput, VisionError> {
        if self.mode != UnpadMode::Padding {
            return Ok(UnpaddedOutput {
                payload: Zeroizing::new(if self.mode == UnpadMode::Passthrough {
                    input.to_vec()
                } else {
                    Vec::new()
                }),
                mode: self.mode,
                direct_trailing: Zeroizing::new(if self.mode == UnpadMode::DirectCopy {
                    input.to_vec()
                } else {
                    Vec::new()
                }),
            });
        }

        let slice = input;
        let mut payload = Zeroizing::new(Vec::with_capacity(input.len()));

        let mut idx = 0usize;
        while idx < slice.len() {
            match self.step {
                UnpadStep::Initial(pos) => {
                    let avail = slice.len().saturating_sub(idx);
                    let need = 16usize.saturating_sub(pos);
                    let take = need.min(avail);
                    if let (Some(dst), Some(src)) = (
                        self.uuid_buf.get_mut(pos..pos.saturating_add(take)),
                        slice.get(idx..idx.saturating_add(take)),
                    ) {
                        dst.copy_from_slice(src);
                    }
                    idx = idx.saturating_add(take);
                    let next_pos = pos.saturating_add(take);
                    if next_pos == 16 {
                        let matched = self.user_uuid.ct_eq_bytes(&self.uuid_buf);
                        if matched {
                            self.uuid_buf.zeroize();
                            self.step = UnpadStep::Header(0);
                        } else {
                            self.mode = UnpadMode::Passthrough;
                            payload.extend_from_slice(&self.uuid_buf);
                            self.uuid_buf.zeroize();
                            if let Some(rem) = slice.get(idx..) {
                                payload.extend_from_slice(rem);
                            }
                            return Ok(UnpaddedOutput {
                                payload,
                                mode: self.mode,
                                direct_trailing: Zeroizing::new(Vec::new()),
                            });
                        }
                    } else {
                        self.step = UnpadStep::Initial(next_pos);
                    }
                }
                UnpadStep::Header(pos) => {
                    let Some(&b) = slice.get(idx) else {
                        break;
                    };
                    idx = idx.saturating_add(1);
                    if let Some(slot) = self.hdr_buf.get_mut(pos) {
                        *slot = b;
                    }
                    let next_pos = pos.saturating_add(1);
                    if next_pos == 5 {
                        let cmd_raw = *self.hdr_buf.first().unwrap_or(&0xFF);
                        let Some(cmd) = VisionCommand::from_u8(cmd_raw) else {
                            self.uuid_buf.zeroize();
                            self.hdr_buf.zeroize();
                            return Err(VisionError::UnknownCommand(cmd_raw));
                        };
                        self.current_command = cmd;
                        let c0 = *self.hdr_buf.get(1).unwrap_or(&0);
                        let c1 = *self.hdr_buf.get(2).unwrap_or(&0);
                        let p0 = *self.hdr_buf.get(3).unwrap_or(&0);
                        let p1 = *self.hdr_buf.get(4).unwrap_or(&0);
                        self.hdr_buf.zeroize();
                        self.content_len = usize::from(u16::from_be_bytes([c0, c1]));
                        self.padding_len = usize::from(u16::from_be_bytes([p0, p1]));

                        if self.content_len > 0 {
                            self.step = UnpadStep::Content(self.content_len);
                        } else if self.padding_len > 0 {
                            self.step = UnpadStep::Padding(self.padding_len);
                        } else if self.finish_block(slice.get(idx..).unwrap_or(&[]), &mut payload) {
                            return Ok(self
                                .build_terminal_output(payload, slice.get(idx..).unwrap_or(&[])));
                        }
                    } else {
                        self.step = UnpadStep::Header(next_pos);
                    }
                }
                UnpadStep::Content(rem) => {
                    let avail = slice.len().saturating_sub(idx);
                    let take = rem.min(avail);
                    if let Some(chunk) = slice.get(idx..idx.saturating_add(take)) {
                        payload.extend_from_slice(chunk);
                    }
                    idx = idx.saturating_add(take);
                    let new_rem = rem.saturating_sub(take);
                    if new_rem > 0 {
                        self.step = UnpadStep::Content(new_rem);
                    } else if self.padding_len > 0 {
                        self.step = UnpadStep::Padding(self.padding_len);
                    } else if self.finish_block(slice.get(idx..).unwrap_or(&[]), &mut payload) {
                        return Ok(
                            self.build_terminal_output(payload, slice.get(idx..).unwrap_or(&[]))
                        );
                    }
                }
                UnpadStep::Padding(rem) => {
                    let avail = slice.len().saturating_sub(idx);
                    let skip = rem.min(avail);
                    idx = idx.saturating_add(skip);
                    let new_rem = rem.saturating_sub(skip);
                    if new_rem > 0 {
                        self.step = UnpadStep::Padding(new_rem);
                    } else if self.finish_block(slice.get(idx..).unwrap_or(&[]), &mut payload) {
                        return Ok(
                            self.build_terminal_output(payload, slice.get(idx..).unwrap_or(&[]))
                        );
                    }
                }
            }
        }

        Ok(UnpaddedOutput {
            payload,
            mode: self.mode,
            direct_trailing: Zeroizing::new(Vec::new()),
        })
    }

    fn build_terminal_output(
        &self,
        payload: Zeroizing<Vec<u8>>,
        trailing: &[u8],
    ) -> UnpaddedOutput {
        // Only populate `direct_trailing` when switching to DirectCopy; for `End`,
        // `finish_block` already appended `trailing` to `payload`.
        let direct_trailing = if self.mode == UnpadMode::DirectCopy {
            Zeroizing::new(trailing.to_vec())
        } else {
            Zeroizing::new(Vec::new())
        };
        UnpaddedOutput {
            payload,
            mode: self.mode,
            direct_trailing,
        }
    }

    fn finish_block(&mut self, trailing: &[u8], payload: &mut Vec<u8>) -> bool {
        match self.current_command {
            VisionCommand::Continue => {
                self.step = UnpadStep::Header(0);
                false
            }
            VisionCommand::End => {
                self.mode = UnpadMode::Passthrough;
                self.step = UnpadStep::Initial(0);
                payload.extend_from_slice(trailing);
                true
            }
            VisionCommand::Direct => {
                self.mode = UnpadMode::DirectCopy;
                self.step = UnpadStep::Initial(0);
                true
            }
        }
    }
}

/// Stateful Sans-I/O XTLS-Vision padder for downlink (`Upstream -> Client`).
#[derive(Debug)]
pub struct VisionPadder {
    user_uuid: VlessUuid,
    wrote_uuid: bool,
    is_padding: bool,
    direct_copy_pending: bool,
    packets_padded: usize,
}

impl VisionPadder {
    /// Creates a new Vision padder bound to the authenticated client UUID.
    #[must_use]
    pub fn new(user_uuid: VlessUuid) -> Self {
        Self {
            user_uuid,
            wrote_uuid: false,
            is_padding: true,
            direct_copy_pending: false,
            packets_padded: 0,
        }
    }

    /// Returns `true` if padding has completed and `CommandPaddingDirect` was emitted.
    #[must_use]
    pub const fn direct_copy_active(&self) -> bool {
        self.direct_copy_pending
    }

    /// Returns `true` if Vision padding is still wrapping outbound packets.
    #[must_use]
    pub const fn is_padding(&self) -> bool {
        self.is_padding
    }

    /// Wraps an outbound payload chunk (if `is_padding`) using `tls_filter` state
    /// and a 4-byte random value `rand_u32` injected from the OS CSPRNG.
    pub fn wrap_outbound(
        &mut self,
        payload: &[u8],
        tls_filter: &VisionTlsFilter,
        rand_u32: u32,
    ) -> Zeroizing<Vec<u8>> {
        if !self.is_padding {
            return Zeroizing::new(payload.to_vec());
        }

        // Empty initial packet -> emit long Vision padding to mask VLESS response header.
        if payload.is_empty() {
            self.packets_padded = self.packets_padded.saturating_add(1);
            return self.encode_block(&[], VisionCommand::Continue, true, rand_u32);
        }

        self.packets_padded = self.packets_padded.saturating_add(1);

        let is_complete_app = tls_filter.is_tls()
            && payload.len() >= 6
            && payload.get(..3) == Some(&[0x17, 0x03, 0x03])
            && is_complete_tls_app_data_records(payload);

        let mut command = VisionCommand::Continue;
        let mut long_padding = tls_filter.is_tls();

        if is_complete_app {
            if tls_filter.enable_xtls() {
                self.direct_copy_pending = true;
                command = VisionCommand::Direct;
            } else {
                command = VisionCommand::End;
            }
            self.is_padding = false;
            long_padding = false;
        } else if (!tls_filter.is_tls12_or_above() && tls_filter.remaining_packets() == 0)
            || self.packets_padded >= MAX_VISION_PADDING_PACKETS
        {
            self.is_padding = false;
            command = VisionCommand::End;
        }

        // Leave 256 bytes of padding headroom so multi-block TLS flights keep non-zero random padding.
        let max_content = MAX_VISION_BLOCK_TOTAL.saturating_sub(21 + 256);
        if payload.len() <= max_content {
            return self.encode_block(payload, command, long_padding, rand_u32);
        }

        // Split oversized chunks so each Vision block stays <= MAX_VISION_BLOCK_TOTAL
        // without allocating an intermediate `Vec<&[u8]>` or per-chunk `Vec<u8>`.
        let chunks = payload.chunks(max_content);
        let num_chunks = chunks.len();
        let last_idx = num_chunks.saturating_sub(1);
        let mut out = Zeroizing::new(Vec::with_capacity(
            payload.len().saturating_add(num_chunks.saturating_mul(64)),
        ));
        let mut step_rand = rand_u32;
        for (idx, chunk) in chunks.enumerate() {
            let chunk_cmd = if idx == last_idx {
                command
            } else {
                VisionCommand::Continue
            };
            let chunk_long = long_padding && idx < last_idx;
            self.encode_block_into(&mut out, chunk, chunk_cmd, chunk_long, step_rand >> 16);
            step_rand = step_rand
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
        }
        out
    }

    fn encode_block(
        &mut self,
        content: &[u8],
        command: VisionCommand,
        long_padding: bool,
        rand_u32: u32,
    ) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        self.encode_block_into(&mut out, content, command, long_padding, rand_u32);
        out
    }

    fn encode_block_into(
        &mut self,
        out: &mut Vec<u8>,
        content: &[u8],
        command: VisionCommand,
        long_padding: bool,
        rand_u32: u32,
    ) {
        let content_len = content.len();
        let mut pad_len =
            if content_len < usize::try_from(DEFAULT_TESTSEED[0]).unwrap_or(900) && long_padding {
                let r = usize::try_from(rand_u32.checked_rem(DEFAULT_TESTSEED[1]).unwrap_or(0))
                    .unwrap_or(0);
                let base = usize::try_from(DEFAULT_TESTSEED[2]).unwrap_or(900);
                base.saturating_add(r).saturating_sub(content_len)
            } else {
                usize::try_from(rand_u32.checked_rem(DEFAULT_TESTSEED[3]).unwrap_or(0)).unwrap_or(0)
            };

        let max_pad = MAX_VISION_BLOCK_TOTAL
            .saturating_sub(21)
            .saturating_sub(content_len);
        if pad_len > max_pad {
            pad_len = max_pad;
        }

        let uuid_len = if self.wrote_uuid { 0usize } else { 16usize };
        let block_len = uuid_len
            .saturating_add(5)
            .saturating_add(content_len)
            .saturating_add(pad_len);
        out.reserve(block_len);

        if !self.wrote_uuid {
            out.extend_from_slice(self.user_uuid.as_bytes());
            self.wrote_uuid = true;
        }

        let c_u16 = u16::try_from(content_len).unwrap_or(u16::MAX);
        let p_u16 = u16::try_from(pad_len).unwrap_or(u16::MAX);
        out.push(command.to_u8());
        out.extend_from_slice(&c_u16.to_be_bytes());
        out.extend_from_slice(&p_u16.to_be_bytes());
        out.extend_from_slice(content);
        let new_total = out.len().saturating_add(pad_len);
        out.resize(new_total, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_inner_tls13_server_hello() -> Vec<u8> {
        let mut sh = vec![0x16, 0x03, 0x03, 0x00, 0x55, 0x02, 0x00, 0x00, 0x51];
        sh.resize(43, 0x11);
        sh.push(32); // session_id len
        sh.extend([0x22u8; 32]);
        sh.extend_from_slice(&0x1301u16.to_be_bytes());
        sh.push(0); // compression
        sh.extend_from_slice(&6u16.to_be_bytes());
        sh.extend_from_slice(TLS13_SUPPORTED_VERSIONS_BYTES);
        let sh_total_minus_5 = sh.len().saturating_sub(5);
        if let Some(s) = sh.get_mut(3..5) {
            s.copy_from_slice(&(sh_total_minus_5 as u16).to_be_bytes());
        }
        sh
    }

    #[test]
    fn vision_padder_and_unpadder_roundtrip_and_direct_switch(
    ) -> Result<(), Box<dyn core::error::Error>> {
        let uuid = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00")?;

        let mut padder = VisionPadder::new(uuid.clone());
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut filter = VisionTlsFilter::new();

        let sh = build_inner_tls13_server_hello();
        filter.inspect_downlink(&sh);
        assert!(filter.enable_xtls());

        let blk1 = padder.wrap_outbound(&sh, &filter, 42);
        assert!(padder.is_padding());
        assert!(!padder.direct_copy_active());

        let out1 = unpadder.feed(&blk1)?;
        assert_eq!(&*out1.payload, &sh);
        assert_eq!(out1.mode, UnpadMode::Padding);

        // 2. Inner TLS 1.3 ApplicationData -> triggers CommandPaddingDirect
        let mut app = vec![0x17, 0x03, 0x03, 0x00, 0x05];
        app.extend_from_slice(b"HELLO");
        let mut blk2 = padder.wrap_outbound(&app, &filter, 99);
        assert!(!padder.is_padding());
        assert!(padder.direct_copy_active());

        // Append raw direct bytes right after blk2 to verify direct_trailing extraction!
        blk2.extend_from_slice(b"RAW_DIRECT_DATA");
        let out2 = unpadder.feed(&blk2)?;
        assert_eq!(&*out2.payload, &app);
        assert_eq!(out2.mode, UnpadMode::DirectCopy);
        assert_eq!(&*out2.direct_trailing, b"RAW_DIRECT_DATA");
        Ok(())
    }

    #[test]
    fn vision_non_tls_falls_back_to_padding_end_without_direct_copy(
    ) -> Result<(), Box<dyn core::error::Error>> {
        let uuid = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00")?;
        let mut padder = VisionPadder::new(uuid.clone());
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut filter = VisionTlsFilter::new();

        for i in 0..8 {
            let msg = format!("HTTP_CHUNK_{i}");
            filter.inspect_downlink(msg.as_bytes());
            let mut blk = padder.wrap_outbound(msg.as_bytes(), &filter, 17);
            if i == 7 {
                // Trailing bytes after CommandPaddingEnd MUST appear in payload ONLY, not direct_trailing!
                blk.extend_from_slice(b"TRAILING_HTTP");
            }
            let out = unpadder.feed(&blk)?;
            if i == 7 {
                let mut expected = msg.into_bytes();
                expected.extend_from_slice(b"TRAILING_HTTP");
                assert_eq!(&*out.payload, &expected);
                assert!(out.direct_trailing.is_empty());
            } else {
                assert_eq!(&*out.payload, msg.as_bytes());
            }
        }

        assert!(!padder.is_padding());
        assert!(!padder.direct_copy_active());
        assert_eq!(unpadder.mode(), UnpadMode::Passthrough);
        Ok(())
    }

    #[test]
    fn vision_unpadder_handles_fragmented_initial_uuid_and_header(
    ) -> Result<(), Box<dyn core::error::Error>> {
        let uuid = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00")?;
        let mut padder = VisionPadder::new(uuid.clone());
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut filter = VisionTlsFilter::new();

        let ch = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00";
        filter.inspect_uplink(ch);
        let blk = padder.wrap_outbound(ch, &filter, 123);

        // Feed 1 byte at a time across the 16-byte UUID, 5-byte Vision header, content, and padding!
        let mut collected = Vec::new();
        for byte in &*blk {
            let out = unpadder.feed(core::slice::from_ref(byte))?;
            collected.extend_from_slice(&out.payload);
        }
        assert_eq!(collected, ch);
        assert_eq!(unpadder.mode(), UnpadMode::Padding);
        Ok(())
    }

    #[test]
    fn vision_rejects_unknown_command_and_hrr_and_handles_fragmented_sh(
    ) -> Result<(), Box<dyn core::error::Error>> {
        let uuid = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00")?;
        let mut bad_unpadder = VisionUnpadder::new(uuid);
        let mut bad_blk = Vec::new();
        bad_blk.extend_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ]);
        bad_blk.extend_from_slice(&[0x99, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            bad_unpadder.feed(&bad_blk).err(),
            Some(VisionError::UnknownCommand(0x99))
        );

        // HelloRetryRequest must NOT enable XTLS!
        let mut hrr = build_inner_tls13_server_hello();
        if let Some(rand_slot) = hrr.get_mut(11..43) {
            rand_slot.copy_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        }
        let mut filter = VisionTlsFilter::new();
        filter.inspect_downlink(&hrr);
        assert!(!filter.enable_xtls());

        // Real fragmented ServerHello split across 20-byte chunks must still enable XTLS!
        let sh = build_inner_tls13_server_hello();
        for chunk in sh.chunks(20) {
            filter.inspect_downlink(chunk);
        }
        assert!(filter.enable_xtls());
        Ok(())
    }
}

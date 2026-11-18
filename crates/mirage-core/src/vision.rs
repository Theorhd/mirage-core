//! Sans-I/O XTLS-Vision framing, TLS-in-TLS inner handshake detection,
//! random padding, and direct-copy transition state machine.

use crate::vless::VlessUuid;

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

/// Maximum Vision chunk content size so header (up to 21 bytes) + content + padding fits cleanly.
const MAX_VISION_BLOCK_TOTAL: usize = 8192;

/// Inner TLS 1.3 `supported_versions` extension bytes (`0x002b`, len `2`, `0x0304`).
const TLS13_SUPPORTED_VERSIONS_BYTES: &[u8] = &[0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];

/// Shared TLS inspection state across uplink & downlink for an XTLS-Vision session.
#[derive(Debug, Clone)]
pub struct VisionTlsFilter {
    remaining_packets_to_filter: usize,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher_suite: u16,
    remaining_server_hello: usize,
}

impl Default for VisionTlsFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl VisionTlsFilter {
    /// Creates a new TLS inspection state (inspecting up to 8 initial packets).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            remaining_packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher_suite: 0,
            remaining_server_hello: 0,
        }
    }

    /// Inspects an inner payload chunk (client->upstream or upstream->client) for
    /// inner TLS 1.3 ClientHello / ServerHello markers.
    pub fn inspect(&mut self, data: &[u8]) {
        if self.remaining_packets_to_filter == 0 || data.is_empty() {
            return;
        }
        self.remaining_packets_to_filter = self.remaining_packets_to_filter.saturating_sub(1);

        if data.len() >= 6 {
            let b0 = *data.first().unwrap_or(&0);
            let b1 = *data.get(1).unwrap_or(&0);
            let b2 = *data.get(2).unwrap_or(&0);
            let b3 = *data.get(3).unwrap_or(&0);
            let b4 = *data.get(4).unwrap_or(&0);
            let b5 = *data.get(5).unwrap_or(&0);

            if b0 == 0x16 && b1 == 0x03 && b2 == 0x03 && b5 == 0x02 {
                // Inner TLS ServerHello
                let rec_len = usize::from(u16::from_be_bytes([b3, b4]));
                self.remaining_server_hello = 5usize.saturating_add(rec_len);
                self.is_tls = true;
                self.is_tls12_or_above = true;
                if data.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid_len = usize::from(*data.get(43).unwrap_or(&0));
                    let cs_off = 44usize.saturating_add(sid_len);
                    if let (Some(&c0), Some(&c1)) =
                        (data.get(cs_off), data.get(cs_off.saturating_add(1)))
                    {
                        self.cipher_suite = u16::from_be_bytes([c0, c1]);
                    }
                }
            } else if b0 == 0x16 && b1 == 0x03 && b5 == 0x01 {
                // Inner TLS ClientHello
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let check_len = self.remaining_server_hello.min(data.len());
            self.remaining_server_hello = self.remaining_server_hello.saturating_sub(data.len());
            if let Some(slice) = data.get(..check_len) {
                if slice
                    .windows(TLS13_SUPPORTED_VERSIONS_BYTES.len())
                    .any(|w| w == TLS13_SUPPORTED_VERSIONS_BYTES)
                {
                    if matches!(self.cipher_suite, 0x1301..=0x1304) {
                        self.enable_xtls = true;
                    }
                    self.remaining_packets_to_filter = 0;
                    return;
                }
            }
            if self.remaining_server_hello == 0 {
                // Concluded ServerHello without TLS 1.3 supported_versions -> TLS 1.2
                self.remaining_packets_to_filter = 0;
            }
        }
    }

    /// Returns `true` if inner TLS 1.3 handshake was detected and XTLS direct copy is allowed.
    #[must_use]
    pub const fn enable_xtls(&self) -> bool {
        self.enable_xtls
    }

    /// Returns `true` once the filter has completed inspecting the initial handshake window.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.remaining_packets_to_filter == 0
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

    /// Returns remaining packets before filtering stops.
    #[must_use]
    pub const fn remaining_packets(&self) -> usize {
        self.remaining_packets_to_filter
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
    Initial,
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
    hdr_buf: [u8; 5],
    current_command: VisionCommand,
    content_len: usize,
    padding_len: usize,
}

/// Output produced by [`VisionUnpadder::feed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpaddedOutput {
    /// Unpadded inner payload bytes ready to forward to upstream.
    pub payload: Vec<u8>,
    /// Current unpadder mode after processing this chunk.
    pub mode: UnpadMode,
    /// Any trailing bytes that belong to raw direct-copy mode (after `CommandPaddingDirect`).
    pub direct_trailing: Vec<u8>,
}

impl VisionUnpadder {
    /// Creates a new Vision unpadder bound to the authenticated client UUID.
    #[must_use]
    pub fn new(user_uuid: VlessUuid) -> Self {
        Self {
            user_uuid,
            mode: UnpadMode::Padding,
            step: UnpadStep::Initial,
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
    /// plus updated mode.
    pub fn feed(&mut self, input: &[u8]) -> UnpaddedOutput {
        if self.mode != UnpadMode::Padding {
            return UnpaddedOutput {
                payload: if self.mode == UnpadMode::Passthrough {
                    input.to_vec()
                } else {
                    Vec::new()
                },
                mode: self.mode,
                direct_trailing: if self.mode == UnpadMode::DirectCopy {
                    input.to_vec()
                } else {
                    Vec::new()
                },
            };
        }

        let mut slice = input;
        let mut payload = Vec::with_capacity(input.len());

        if self.step == UnpadStep::Initial {
            if slice.len() >= 21 {
                if let Some(prefix) = slice.get(..16) {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(prefix);
                    if self.user_uuid.ct_eq_bytes(&arr) {
                        slice = slice.get(16..).unwrap_or(&[]);
                        self.step = UnpadStep::Header(0);
                    } else {
                        self.mode = UnpadMode::Passthrough;
                        return UnpaddedOutput {
                            payload: slice.to_vec(),
                            mode: self.mode,
                            direct_trailing: Vec::new(),
                        };
                    }
                }
            } else {
                self.mode = UnpadMode::Passthrough;
                return UnpaddedOutput {
                    payload: slice.to_vec(),
                    mode: self.mode,
                    direct_trailing: Vec::new(),
                };
            }
        }

        let mut idx = 0usize;
        while idx < slice.len() {
            match self.step {
                UnpadStep::Initial => {
                    self.step = UnpadStep::Header(0);
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
                        let cmd_raw = *self.hdr_buf.first().unwrap_or(&1);
                        self.current_command =
                            VisionCommand::from_u8(cmd_raw).unwrap_or(VisionCommand::End);
                        let c0 = *self.hdr_buf.get(1).unwrap_or(&0);
                        let c1 = *self.hdr_buf.get(2).unwrap_or(&0);
                        let p0 = *self.hdr_buf.get(3).unwrap_or(&0);
                        let p1 = *self.hdr_buf.get(4).unwrap_or(&0);
                        self.content_len = usize::from(u16::from_be_bytes([c0, c1]));
                        self.padding_len = usize::from(u16::from_be_bytes([p0, p1]));

                        if self.content_len > 0 {
                            self.step = UnpadStep::Content(self.content_len);
                        } else if self.padding_len > 0 {
                            self.step = UnpadStep::Padding(self.padding_len);
                        } else if self.finish_block(slice.get(idx..).unwrap_or(&[]), &mut payload) {
                            return UnpaddedOutput {
                                payload,
                                mode: self.mode,
                                direct_trailing: slice.get(idx..).unwrap_or(&[]).to_vec(),
                            };
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
                        return UnpaddedOutput {
                            payload,
                            mode: self.mode,
                            direct_trailing: slice.get(idx..).unwrap_or(&[]).to_vec(),
                        };
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
                        return UnpaddedOutput {
                            payload,
                            mode: self.mode,
                            direct_trailing: slice.get(idx..).unwrap_or(&[]).to_vec(),
                        };
                    }
                }
            }
        }

        UnpaddedOutput {
            payload,
            mode: self.mode,
            direct_trailing: Vec::new(),
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
                self.step = UnpadStep::Initial;
                payload.extend_from_slice(trailing);
                true
            }
            VisionCommand::Direct => {
                self.mode = UnpadMode::DirectCopy;
                self.step = UnpadStep::Initial;
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
    ) -> Vec<u8> {
        if !self.is_padding {
            return payload.to_vec();
        }

        // Empty initial packet -> emit long Vision padding to mask VLESS response header.
        if payload.is_empty() {
            return self.encode_block(&[], VisionCommand::Continue, true, rand_u32);
        }

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
        } else if !tls_filter.is_tls12_or_above() && tls_filter.remaining_packets() == 0 {
            self.is_padding = false;
            command = VisionCommand::End;
        }

        let max_content = MAX_VISION_BLOCK_TOTAL.saturating_sub(21);
        if payload.len() <= max_content {
            return self.encode_block(payload, command, long_padding, rand_u32);
        }

        // Split oversized chunks so each Vision block stays <= MAX_VISION_BLOCK_TOTAL
        // without allocating an intermediate `Vec<&[u8]>` or per-chunk `Vec<u8>`.
        let chunks = payload.chunks(max_content);
        let num_chunks = chunks.len();
        let last_idx = num_chunks.saturating_sub(1);
        let mut out =
            Vec::with_capacity(payload.len().saturating_add(num_chunks.saturating_mul(64)));
        let mut step_rand = rand_u32;
        for (idx, chunk) in chunks.enumerate() {
            let chunk_cmd = if idx == last_idx {
                command
            } else {
                VisionCommand::Continue
            };
            let chunk_long = long_padding && idx < last_idx;
            self.encode_block_into(&mut out, chunk, chunk_cmd, chunk_long, step_rand);
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
    ) -> Vec<u8> {
        let mut out = Vec::new();
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

    #[test]
    fn vision_padder_and_unpadder_roundtrip_and_direct_switch() {
        let Ok(uuid) = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00") else {
            return;
        };

        let mut padder = VisionPadder::new(uuid.clone());
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut filter = VisionTlsFilter::new();

        // 1. Simulated inner TLS 1.3 ServerHello (>= 79 bytes with cipher 0x1301 and 0x002b00020304)
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

        filter.inspect(&sh);
        assert!(filter.enable_xtls());

        let blk1 = padder.wrap_outbound(&sh, &filter, 42);
        assert!(padder.is_padding());
        assert!(!padder.direct_copy_active());

        let out1 = unpadder.feed(&blk1);
        assert_eq!(out1.payload, sh);
        assert_eq!(out1.mode, UnpadMode::Padding);

        // 2. Inner TLS 1.3 ApplicationData -> triggers CommandPaddingDirect
        let mut app = vec![0x17, 0x03, 0x03, 0x00, 0x05];
        app.extend_from_slice(b"HELLO");
        let mut blk2 = padder.wrap_outbound(&app, &filter, 99);
        assert!(!padder.is_padding());
        assert!(padder.direct_copy_active());

        // Append raw direct bytes right after blk2 to verify direct_trailing extraction!
        blk2.extend_from_slice(b"RAW_DIRECT_DATA");
        let out2 = unpadder.feed(&blk2);
        assert_eq!(out2.payload, app);
        assert_eq!(out2.mode, UnpadMode::DirectCopy);
        assert_eq!(out2.direct_trailing, b"RAW_DIRECT_DATA");
    }

    #[test]
    fn vision_non_tls_falls_back_to_padding_end_without_direct_copy() {
        let Ok(uuid) = VlessUuid::from_str_hex("11223344-5566-7788-99aa-bbccddeeff00") else {
            return;
        };
        let mut padder = VisionPadder::new(uuid.clone());
        let mut unpadder = VisionUnpadder::new(uuid);
        let mut filter = VisionTlsFilter::new();

        for i in 0..8 {
            let msg = format!("HTTP_CHUNK_{i}");
            filter.inspect(msg.as_bytes());
            let blk = padder.wrap_outbound(msg.as_bytes(), &filter, 17);
            let out = unpadder.feed(&blk);
            assert_eq!(out.payload, msg.as_bytes());
        }

        assert!(!padder.is_padding());
        assert!(!padder.direct_copy_active());
        assert_eq!(unpadder.mode(), UnpadMode::Passthrough);
    }
}

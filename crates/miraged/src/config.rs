//! Zeroizing TOML configuration loader and validator.

use core::fmt;
use core::time::Duration;
use std::net::SocketAddr;
use std::path::Path;

use mirage_core::crypto::{ShortId, StaticPrivateKey};
use mirage_core::tls_parser::DEFAULT_MAX_CLIENT_HELLO_BYTES;
use mirage_core::vless::VlessUuid;
use serde::de::{self, Visitor};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::DaemonError;

const DEFAULT_INITIAL_READ_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_MAX_CONNECTIONS: usize = 4_096;
const DEFAULT_MAX_TIME_DIFF_SECS: u64 = 60;
const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 65_536;
const DEFAULT_TCP_IDLE_TIMEOUT_SECS: u64 = 300;
const DEFAULT_UDP_IDLE_TIMEOUT_SECS: u64 = 120;
const DEFAULT_HALF_CLOSE_TIMEOUT_SECS: u64 = 10;
const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 30;
const DEFAULT_DEST_PROFILE_CACHE_TTL_SECS: u64 = 120;
const DEFAULT_HAPPY_EYEBALLS_DELAY_MS: u64 = 75;
const DEFAULT_LISTEN_BACKLOG: u32 = 1_024;
const MIN_CLIENT_HELLO_BYTES: usize = 64;
const MAX_CLIENT_HELLO_BYTES_CAP: usize = 64 * 1024;
const MIN_READ_TIMEOUT_MS: u64 = 100;
const MAX_READ_TIMEOUT_MS: u64 = 60_000;
const MAX_TIME_DIFF_SECS_CAP: u64 = 3_600;

/// Outbound IP address-family preference for DNS resolution and Happy Eyeballs dialing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpStrategy {
    /// Interleave IPv4 first, then IPv6 (avoids IPv6 latency penalties on IPv4-first VPSes).
    #[default]
    PreferV4,
    /// Interleave IPv6 first, then IPv4 (RFC 8305 IPv6-first preference).
    PreferV6,
    /// Query and dial IPv4 (`A`) records only.
    V4Only,
}

struct DeserializedPrivateKey(StaticPrivateKey);

impl<'de> Deserialize<'de> for DeserializedPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = DeserializedPrivateKey;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 64-character hex or 43-character Base64url X25519 private key")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                StaticPrivateKey::from_encoded(value)
                    .map(DeserializedPrivateKey)
                    .map_err(|_| de::Error::custom("invalid private key"))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let zeroized = Zeroizing::new(value);
                self.visit_str(&zeroized)
            }
        }
        deserializer.deserialize_str(KeyVisitor)
    }
}

struct DeserializedShortId(ShortId);

impl<'de> Deserialize<'de> for DeserializedShortId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SidVisitor;
        impl Visitor<'_> for SidVisitor {
            type Value = DeserializedShortId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a non-empty even-length hex ShortID (2..=16 hex chars)")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ShortId::from_hex(value)
                    .map(DeserializedShortId)
                    .map_err(|_| de::Error::custom("invalid short_id"))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let zeroized = Zeroizing::new(value);
                self.visit_str(&zeroized)
            }
        }
        deserializer.deserialize_str(SidVisitor)
    }
}

struct DeserializedVlessUuid(VlessUuid);

impl<'de> Deserialize<'de> for DeserializedVlessUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UuidVisitor;
        impl Visitor<'_> for UuidVisitor {
            type Value = DeserializedVlessUuid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a standard UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                VlessUuid::from_str_hex(value)
                    .map(DeserializedVlessUuid)
                    .map_err(|_| de::Error::custom("invalid vless uuid"))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let zeroized = Zeroizing::new(value);
                self.visit_str(&zeroized)
            }
        }
        deserializer.deserialize_str(UuidVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVlessConfig {
    uuids: Vec<DeserializedVlessUuid>,
    #[serde(default)]
    allow_private_egress: bool,
    #[serde(default)]
    allow_smtp_port_25: bool,
    #[serde(default)]
    block_quic: bool,
    #[serde(default)]
    ip_strategy: IpStrategy,
    #[serde(default = "default_dns_resolver")]
    dns_resolver: SocketAddr,
    #[serde(default)]
    allow_system_dns: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRealityConfig {
    private_keys: Vec<DeserializedPrivateKey>,
    short_ids: Vec<DeserializedShortId>,
    #[serde(default = "default_max_time_diff_secs")]
    max_time_diff_secs: u64,
    #[serde(default = "default_replay_cache_capacity")]
    replay_cache_capacity: usize,
    #[serde(default)]
    min_client_ver: Option<[u8; 3]>,
    #[serde(default)]
    max_client_ver: Option<[u8; 3]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen_addr: SocketAddr,
    dest_addr: SocketAddr,
    server_names: Vec<String>,
    #[serde(default = "default_max_client_hello_bytes")]
    max_client_hello_bytes: usize,
    #[serde(default = "default_initial_read_timeout_ms")]
    initial_read_timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_tcp_idle_timeout_secs")]
    tcp_idle_timeout_secs: u64,
    #[serde(default = "default_udp_idle_timeout_secs")]
    udp_idle_timeout_secs: u64,
    #[serde(default = "default_half_close_timeout_secs")]
    half_close_timeout_secs: u64,
    #[serde(default = "default_tcp_keepalive_secs")]
    tcp_keepalive_secs: u64,
    #[serde(default = "default_dest_profile_cache_ttl_secs")]
    dest_profile_cache_ttl_secs: u64,
    #[serde(default = "default_happy_eyeballs_delay_ms")]
    happy_eyeballs_delay_ms: u64,
    #[serde(default = "default_listen_backlog")]
    listen_backlog: u32,
    #[serde(default)]
    unsafe_debug_logging: bool,
    #[serde(default)]
    reality: Option<RawRealityConfig>,
    #[serde(default)]
    vless: Option<RawVlessConfig>,
}

const fn default_max_client_hello_bytes() -> usize {
    DEFAULT_MAX_CLIENT_HELLO_BYTES
}

const fn default_initial_read_timeout_ms() -> u64 {
    DEFAULT_INITIAL_READ_TIMEOUT_MS
}

const fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

const fn default_tcp_idle_timeout_secs() -> u64 {
    DEFAULT_TCP_IDLE_TIMEOUT_SECS
}

const fn default_udp_idle_timeout_secs() -> u64 {
    DEFAULT_UDP_IDLE_TIMEOUT_SECS
}

const fn default_half_close_timeout_secs() -> u64 {
    DEFAULT_HALF_CLOSE_TIMEOUT_SECS
}

const fn default_tcp_keepalive_secs() -> u64 {
    DEFAULT_TCP_KEEPALIVE_SECS
}

const fn default_dest_profile_cache_ttl_secs() -> u64 {
    DEFAULT_DEST_PROFILE_CACHE_TTL_SECS
}

const fn default_happy_eyeballs_delay_ms() -> u64 {
    DEFAULT_HAPPY_EYEBALLS_DELAY_MS
}

const fn default_listen_backlog() -> u32 {
    DEFAULT_LISTEN_BACKLOG
}

const fn default_max_time_diff_secs() -> u64 {
    DEFAULT_MAX_TIME_DIFF_SECS
}

const fn default_replay_cache_capacity() -> usize {
    DEFAULT_REPLAY_CACHE_CAPACITY
}

fn default_dns_resolver() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 5353))
}

/// Validated VLESS protocol, egress policy, and private DNS configuration.
#[derive(Clone)]
pub struct VlessConfig {
    uuids: Vec<VlessUuid>,
    allow_private_egress: bool,
    allow_smtp_port_25: bool,
    block_quic: bool,
    ip_strategy: IpStrategy,
    dns_resolver: SocketAddr,
    allow_system_dns: bool,
}

impl VlessConfig {
    /// Constructs and validates a `VlessConfig`.
    pub fn new(
        uuids: Vec<VlessUuid>,
        allow_private_egress: bool,
        allow_smtp_port_25: bool,
        dns_resolver: SocketAddr,
        allow_system_dns: bool,
    ) -> Result<Self, DaemonError> {
        let cfg = Self {
            uuids,
            allow_private_egress,
            allow_smtp_port_25,
            block_quic: false,
            ip_strategy: IpStrategy::default(),
            dns_resolver,
            allow_system_dns,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Configures whether outbound UDP port 443 (QUIC/HTTP3) is blocked.
    #[must_use]
    pub const fn with_block_quic(mut self, block_quic: bool) -> Self {
        self.block_quic = block_quic;
        self
    }

    /// Configures the outbound IP address-family preference.
    #[must_use]
    pub const fn with_ip_strategy(mut self, ip_strategy: IpStrategy) -> Self {
        self.ip_strategy = ip_strategy;
        self
    }

    fn validate(&self) -> Result<(), DaemonError> {
        if self.uuids.is_empty() {
            return Err(DaemonError::ConfigInvalid);
        }
        Ok(())
    }

    /// Returns configured VLESS client UUIDs.
    #[must_use]
    pub fn uuids(&self) -> &[VlessUuid] {
        &self.uuids
    }

    /// Returns whether private/internal egress IPs are permitted (default `false`).
    #[must_use]
    pub const fn allow_private_egress(&self) -> bool {
        self.allow_private_egress
    }

    /// Returns whether outbound TCP port 25 is permitted (default `false`).
    #[must_use]
    pub const fn allow_smtp_port_25(&self) -> bool {
        self.allow_smtp_port_25
    }

    /// Returns whether outbound UDP port 443 (QUIC/HTTP3) is blocked (default `false`).
    #[must_use]
    pub const fn block_quic(&self) -> bool {
        self.block_quic
    }

    /// Returns the configured outbound IP family strategy (default `PreferV6`).
    #[must_use]
    pub const fn ip_strategy(&self) -> IpStrategy {
        self.ip_strategy
    }

    /// Returns the configured private recursive DNS resolver address.
    #[must_use]
    pub const fn dns_resolver(&self) -> SocketAddr {
        self.dns_resolver
    }

    /// Returns whether opt-in system DNS fallback is permitted (default `false`).
    #[must_use]
    pub const fn allow_system_dns(&self) -> bool {
        self.allow_system_dns
    }
}

impl fmt::Debug for VlessConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessConfig")
            .field("uuids_count", &self.uuids.len())
            .field("allow_private_egress", &self.allow_private_egress)
            .field("allow_smtp_port_25", &self.allow_smtp_port_25)
            .field("block_quic", &self.block_quic)
            .field("ip_strategy", &self.ip_strategy)
            .field("allow_system_dns", &self.allow_system_dns)
            .finish()
    }
}

/// Validated Reality authentication & replay-protection configuration.
#[derive(Clone)]
pub struct RealityConfig {
    private_keys: Vec<StaticPrivateKey>,
    short_ids: Vec<ShortId>,
    max_time_diff_secs: u64,
    replay_cache_capacity: usize,
    min_client_ver: Option<[u8; 3]>,
    max_client_ver: Option<[u8; 3]>,
}

impl RealityConfig {
    /// Constructs and validates a `RealityConfig`.
    pub fn new(
        private_keys: Vec<StaticPrivateKey>,
        short_ids: Vec<ShortId>,
        max_time_diff_secs: u64,
        replay_cache_capacity: usize,
        min_client_ver: Option<[u8; 3]>,
        max_client_ver: Option<[u8; 3]>,
    ) -> Result<Self, DaemonError> {
        let cfg = Self {
            private_keys,
            short_ids,
            max_time_diff_secs,
            replay_cache_capacity,
            min_client_ver,
            max_client_ver,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), DaemonError> {
        if self.private_keys.is_empty() || self.short_ids.is_empty() {
            return Err(DaemonError::ConfigInvalid);
        }
        if self.max_time_diff_secs == 0 || self.max_time_diff_secs > MAX_TIME_DIFF_SECS_CAP {
            return Err(DaemonError::ConfigInvalid);
        }
        if self.replay_cache_capacity == 0 {
            return Err(DaemonError::ConfigInvalid);
        }
        if let (Some(min_v), Some(max_v)) = (self.min_client_ver, self.max_client_ver) {
            if min_v > max_v {
                return Err(DaemonError::ConfigInvalid);
            }
        }
        Ok(())
    }

    /// Returns active server X25519 private keys (`[current, previous...]`).
    #[must_use]
    pub fn private_keys(&self) -> &[StaticPrivateKey] {
        &self.private_keys
    }

    /// Returns allowed non-empty ShortIDs.
    #[must_use]
    pub fn short_ids(&self) -> &[ShortId] {
        &self.short_ids
    }

    /// Returns the anti-replay timestamp window in seconds.
    #[must_use]
    pub const fn max_time_diff_secs(&self) -> u64 {
        self.max_time_diff_secs
    }

    /// Returns the maximum capacity of the fail-closed anti-replay cache.
    #[must_use]
    pub const fn replay_cache_capacity(&self) -> usize {
        self.replay_cache_capacity
    }

    /// Returns the optional inclusive minimum client version.
    #[must_use]
    pub const fn min_client_ver(&self) -> Option<[u8; 3]> {
        self.min_client_ver
    }

    /// Returns the optional inclusive maximum client version.
    #[must_use]
    pub const fn max_client_ver(&self) -> Option<[u8; 3]> {
        self.max_client_ver
    }
}

impl fmt::Debug for RealityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityConfig")
            .field("private_keys_count", &self.private_keys.len())
            .field("short_ids_count", &self.short_ids.len())
            .field("max_time_diff_secs", &self.max_time_diff_secs)
            .field("replay_cache_capacity", &self.replay_cache_capacity)
            .finish()
    }
}

/// Validated runtime configuration for `miraged`.
#[derive(Clone)]
pub struct Config {
    listen_addr: SocketAddr,
    dest_addr: SocketAddr,
    server_names: Vec<String>,
    max_client_hello_bytes: usize,
    initial_read_timeout_ms: u64,
    max_connections: usize,
    tcp_idle_timeout_secs: u64,
    udp_idle_timeout_secs: u64,
    half_close_timeout_secs: u64,
    tcp_keepalive_secs: u64,
    dest_profile_cache_ttl_secs: u64,
    happy_eyeballs_delay_ms: u64,
    listen_backlog: u32,
    unsafe_debug_logging: bool,
    reality: Option<RealityConfig>,
    vless: Option<VlessConfig>,
}

impl Config {
    /// Constructs and validates a runtime configuration.
    pub fn new(
        listen_addr: SocketAddr,
        dest_addr: SocketAddr,
        server_names: Vec<String>,
        max_client_hello_bytes: usize,
        initial_read_timeout_ms: u64,
        max_connections: usize,
        unsafe_debug_logging: bool,
    ) -> Result<Self, DaemonError> {
        let cfg = Self {
            listen_addr,
            dest_addr,
            server_names,
            max_client_hello_bytes,
            initial_read_timeout_ms,
            max_connections,
            tcp_idle_timeout_secs: DEFAULT_TCP_IDLE_TIMEOUT_SECS,
            udp_idle_timeout_secs: DEFAULT_UDP_IDLE_TIMEOUT_SECS,
            half_close_timeout_secs: DEFAULT_HALF_CLOSE_TIMEOUT_SECS,
            tcp_keepalive_secs: DEFAULT_TCP_KEEPALIVE_SECS,
            dest_profile_cache_ttl_secs: DEFAULT_DEST_PROFILE_CACHE_TTL_SECS,
            happy_eyeballs_delay_ms: DEFAULT_HAPPY_EYEBALLS_DELAY_MS,
            listen_backlog: DEFAULT_LISTEN_BACKLOG,
            unsafe_debug_logging,
            reality: None,
            vless: None,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Configures the `DestServerProfile` cache TTL in seconds (`0` disables caching).
    pub fn with_dest_profile_cache_ttl_secs(mut self, ttl_secs: u64) -> Result<Self, DaemonError> {
        self.dest_profile_cache_ttl_secs = ttl_secs;
        self.validate()?;
        Ok(self)
    }

    /// Configures the TCP keepalive idle interval in seconds (`0` disables keepalive).
    pub fn with_tcp_keepalive_secs(mut self, secs: u64) -> Result<Self, DaemonError> {
        self.tcp_keepalive_secs = secs;
        self.validate()?;
        Ok(self)
    }

    /// Configures the Happy Eyeballs head-start delay in milliseconds.
    pub fn with_happy_eyeballs_delay_ms(mut self, delay_ms: u64) -> Result<Self, DaemonError> {
        self.happy_eyeballs_delay_ms = delay_ms;
        self.validate()?;
        Ok(self)
    }

    /// Attaches a validated `RealityConfig` to this configuration.
    pub fn with_reality(mut self, reality: RealityConfig) -> Result<Self, DaemonError> {
        reality.validate()?;
        self.reality = Some(reality);
        Ok(self)
    }

    /// Attaches a validated `VlessConfig` to this configuration.
    pub fn with_vless(mut self, vless: VlessConfig) -> Result<Self, DaemonError> {
        vless.validate()?;
        self.vless = Some(vless);
        Ok(self)
    }

    /// Reads and validates configuration from a TOML file on disk.
    ///
    /// Reads raw bytes into a `Zeroizing<String>` buffer so secret fields are
    /// scrubbed from heap memory immediately after deserialization.
    pub fn from_toml_file(path: &Path) -> Result<Self, DaemonError> {
        let raw_text = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|_| DaemonError::ConfigReadFailed)?,
        );
        Self::from_toml_str(&raw_text)
    }

    /// Parses and validates configuration from a TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, DaemonError> {
        let raw: RawConfig = toml::from_str(toml_str).map_err(|_| DaemonError::ConfigInvalid)?;
        let mut cfg = Self::new(
            raw.listen_addr,
            raw.dest_addr,
            raw.server_names,
            raw.max_client_hello_bytes,
            raw.initial_read_timeout_ms,
            raw.max_connections,
            raw.unsafe_debug_logging,
        )?;
        cfg.tcp_idle_timeout_secs = raw.tcp_idle_timeout_secs;
        cfg.udp_idle_timeout_secs = raw.udp_idle_timeout_secs;
        cfg.half_close_timeout_secs = raw.half_close_timeout_secs;
        cfg.tcp_keepalive_secs = raw.tcp_keepalive_secs;
        cfg.dest_profile_cache_ttl_secs = raw.dest_profile_cache_ttl_secs;
        cfg.happy_eyeballs_delay_ms = raw.happy_eyeballs_delay_ms;
        cfg.listen_backlog = raw.listen_backlog;
        cfg.validate()?;

        if let Some(rc) = raw.reality {
            let private_keys = rc.private_keys.into_iter().map(|k| k.0).collect();
            let short_ids = rc.short_ids.into_iter().map(|s| s.0).collect();
            let validated_rc = RealityConfig::new(
                private_keys,
                short_ids,
                rc.max_time_diff_secs,
                rc.replay_cache_capacity,
                rc.min_client_ver,
                rc.max_client_ver,
            )?;
            cfg = cfg.with_reality(validated_rc)?;
        }
        if let Some(vc) = raw.vless {
            let uuids = vc.uuids.into_iter().map(|u| u.0).collect();
            let validated_vc = VlessConfig::new(
                uuids,
                vc.allow_private_egress,
                vc.allow_smtp_port_25,
                vc.dns_resolver,
                vc.allow_system_dns,
            )?
            .with_block_quic(vc.block_quic)
            .with_ip_strategy(vc.ip_strategy);
            cfg = cfg.with_vless(validated_vc)?;
        }
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), DaemonError> {
        if self.server_names.is_empty() {
            return Err(DaemonError::ConfigInvalid);
        }
        for name in &self.server_names {
            if !is_valid_sni_entry(name) {
                return Err(DaemonError::ConfigInvalid);
            }
        }
        if !(MIN_CLIENT_HELLO_BYTES..=MAX_CLIENT_HELLO_BYTES_CAP)
            .contains(&self.max_client_hello_bytes)
        {
            return Err(DaemonError::ConfigInvalid);
        }
        if !(MIN_READ_TIMEOUT_MS..=MAX_READ_TIMEOUT_MS).contains(&self.initial_read_timeout_ms) {
            return Err(DaemonError::ConfigInvalid);
        }
        if self.max_connections == 0 {
            return Err(DaemonError::ConfigInvalid);
        }
        if !(5..=86_400).contains(&self.tcp_idle_timeout_secs) {
            return Err(DaemonError::ConfigInvalid);
        }
        if !(5..=3_600).contains(&self.udp_idle_timeout_secs) {
            return Err(DaemonError::ConfigInvalid);
        }
        if !(1..=300).contains(&self.half_close_timeout_secs) {
            return Err(DaemonError::ConfigInvalid);
        }
        if self.tcp_keepalive_secs > 600 {
            return Err(DaemonError::ConfigInvalid);
        }
        if self.dest_profile_cache_ttl_secs > 3_600 {
            return Err(DaemonError::ConfigInvalid);
        }
        if !(10..=2_000).contains(&self.happy_eyeballs_delay_ms) {
            return Err(DaemonError::ConfigInvalid);
        }
        if !(128..=65_535).contains(&self.listen_backlog) {
            return Err(DaemonError::ConfigInvalid);
        }
        Ok(())
    }

    /// Returns the socket address to bind the public listener on.
    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Returns the pinned fallback destination address (`dest`).
    #[must_use]
    pub const fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }

    /// Returns the exact ASCII case-insensitive SNI allowlist.
    #[must_use]
    pub fn server_names(&self) -> &[String] {
        &self.server_names
    }

    /// Returns the maximum initial bytes inspected for `ClientHello` reassembly.
    #[must_use]
    pub const fn max_client_hello_bytes(&self) -> usize {
        self.max_client_hello_bytes
    }

    /// Returns the initial handshake read timeout in milliseconds.
    #[must_use]
    pub const fn initial_read_timeout_ms(&self) -> u64 {
        self.initial_read_timeout_ms
    }

    /// Returns the initial read timeout as a `Duration`.
    #[must_use]
    pub const fn initial_read_timeout(&self) -> Duration {
        Duration::from_millis(self.initial_read_timeout_ms)
    }

    /// Returns the maximum concurrent connections enforced via accept-side backpressure.
    #[must_use]
    pub const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Returns the idle timeout enforced on active TCP relay streams.
    #[must_use]
    pub const fn tcp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.tcp_idle_timeout_secs)
    }

    /// Returns the idle timeout enforced on UDP / XUDP relay sockets.
    #[must_use]
    pub const fn udp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_idle_timeout_secs)
    }

    /// Returns the shortened drain timeout applied once one side of a TCP relay closes.
    #[must_use]
    pub const fn half_close_timeout(&self) -> Duration {
        Duration::from_secs(self.half_close_timeout_secs)
    }

    /// Returns the TCP keepalive idle interval (`Duration::ZERO` disables keepalive).
    #[must_use]
    pub const fn tcp_keepalive(&self) -> Duration {
        Duration::from_secs(self.tcp_keepalive_secs)
    }

    /// Returns the `DestServerProfile` cache TTL (`Duration::ZERO` disables caching).
    #[must_use]
    pub const fn dest_profile_cache_ttl(&self) -> Duration {
        Duration::from_secs(self.dest_profile_cache_ttl_secs)
    }

    /// Returns the Happy Eyeballs head-start delay between address-family attempts.
    #[must_use]
    pub const fn happy_eyeballs_delay(&self) -> Duration {
        Duration::from_millis(self.happy_eyeballs_delay_ms)
    }

    /// Returns the TCP accept backlog passed to `listen(2)`.
    #[must_use]
    pub const fn listen_backlog(&self) -> i32 {
        #[allow(clippy::cast_possible_wrap)]
        {
            self.listen_backlog as i32
        }
    }

    /// Returns whether opt-in unsafe debug logging is enabled.
    #[must_use]
    pub const fn unsafe_debug_logging(&self) -> bool {
        self.unsafe_debug_logging
    }

    /// Returns the optional Reality configuration.
    #[must_use]
    pub fn reality(&self) -> Option<&RealityConfig> {
        self.reality.as_ref()
    }

    /// Returns the optional VLESS configuration.
    #[must_use]
    pub fn vless(&self) -> Option<&VlessConfig> {
        self.vless.as_ref()
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen_addr", &"[REDACTED]")
            .field("dest_addr", &"[REDACTED]")
            .field("server_names_count", &self.server_names.len())
            .field("max_client_hello_bytes", &self.max_client_hello_bytes)
            .field("initial_read_timeout_ms", &self.initial_read_timeout_ms)
            .field("max_connections", &self.max_connections)
            .field("unsafe_debug_logging", &self.unsafe_debug_logging)
            .field("reality_enabled", &self.reality.is_some())
            .field("vless_enabled", &self.vless.is_some())
            .finish()
    }
}

fn is_valid_sni_entry(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_graphic() && *b != b'*' && *b != b'\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config_with_and_without_reality() {
        let toml = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = ["example.com", "cdn.example.com"]
        "#;
        let cfg = Config::from_toml_str(toml);
        assert!(cfg.is_ok());
        if let Ok(c) = cfg {
            assert_eq!(c.max_client_hello_bytes(), DEFAULT_MAX_CLIENT_HELLO_BYTES);
            assert_eq!(c.initial_read_timeout_ms(), DEFAULT_INITIAL_READ_TIMEOUT_MS);
            assert_eq!(c.max_connections(), DEFAULT_MAX_CONNECTIONS);
            assert!(!c.unsafe_debug_logging());
            assert!(c.reality().is_none());
            let dbg = format!("{c:?}");
            assert!(!dbg.contains("example.com"));
            assert!(!dbg.contains("8443"));
        }

        let toml_reality = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = ["example.com"]

            [reality]
            private_keys = ["1111111111111111111111111111111111111111111111111111111111111111"]
            short_ids = ["0123abcd"]
            max_time_diff_secs = 60
        "#;
        let cfg_r = Config::from_toml_str(toml_reality);
        assert!(cfg_r.is_ok());
        if let Ok(c) = cfg_r {
            assert!(c.reality().is_some());
            let dbg = format!("{c:?}");
            assert!(!dbg.contains("1111"));
            assert!(!dbg.contains("0123abcd"));
        }
    }

    #[test]
    fn rejects_empty_server_names_wildcards_and_empty_short_ids() {
        let empty = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = []
        "#;
        assert_eq!(
            Config::from_toml_str(empty).err(),
            Some(DaemonError::ConfigInvalid)
        );

        let wildcard = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = ["*.example.com"]
        "#;
        assert_eq!(
            Config::from_toml_str(wildcard).err(),
            Some(DaemonError::ConfigInvalid)
        );

        let empty_sid = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = ["example.com"]

            [reality]
            private_keys = ["1111111111111111111111111111111111111111111111111111111111111111"]
            short_ids = [""]
        "#;
        assert_eq!(
            Config::from_toml_str(empty_sid).err(),
            Some(DaemonError::ConfigInvalid)
        );
    }

    #[test]
    fn parses_performance_and_video_tuning_fields() {
        let toml = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = ["example.com"]
            tcp_idle_timeout_secs = 240
            udp_idle_timeout_secs = 90
            half_close_timeout_secs = 8
            tcp_keepalive_secs = 25
            dest_profile_cache_ttl_secs = 180
            happy_eyeballs_delay_ms = 60
            listen_backlog = 2048

            [vless]
            uuids = ["11111111-1111-4111-8111-111111111111"]
            block_quic = true
            ip_strategy = "v4_only"
        "#;
        let parsed = Config::from_toml_str(toml);
        assert!(parsed.is_ok());
        if let Ok(cfg) = parsed {
            assert_eq!(cfg.tcp_idle_timeout(), Duration::from_secs(240));
            assert_eq!(cfg.udp_idle_timeout(), Duration::from_secs(90));
            assert_eq!(cfg.half_close_timeout(), Duration::from_secs(8));
            assert_eq!(cfg.tcp_keepalive(), Duration::from_secs(25));
            assert_eq!(cfg.dest_profile_cache_ttl(), Duration::from_secs(180));
            assert_eq!(cfg.happy_eyeballs_delay(), Duration::from_millis(60));
            assert_eq!(cfg.listen_backlog(), 2048);
            assert!(cfg.vless().is_some_and(VlessConfig::block_quic));
            assert_eq!(
                cfg.vless().map(VlessConfig::ip_strategy),
                Some(IpStrategy::V4Only)
            );
        }

        let bad_backlog = r#"
            listen_addr = "127.0.0.1:8443"
            dest_addr = "127.0.0.1:9443"
            server_names = ["example.com"]
            listen_backlog = 16
        "#;
        assert!(Config::from_toml_str(bad_backlog).is_err());
    }
}

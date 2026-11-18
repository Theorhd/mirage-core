//! Zeroizing TOML configuration loader and validator.

use core::fmt;
use core::time::Duration;
use std::net::SocketAddr;
use std::path::Path;

use mirage_core::tls_parser::DEFAULT_MAX_CLIENT_HELLO_BYTES;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::DaemonError;

const DEFAULT_INITIAL_READ_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_MAX_CONNECTIONS: usize = 4_096;
const MIN_CLIENT_HELLO_BYTES: usize = 64;
const MAX_CLIENT_HELLO_BYTES_CAP: usize = 64 * 1024;
const MIN_READ_TIMEOUT_MS: u64 = 100;
const MAX_READ_TIMEOUT_MS: u64 = 60_000;

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
    #[serde(default)]
    unsafe_debug_logging: bool,
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

/// Validated runtime configuration for `miraged`.
#[derive(Clone)]
pub struct Config {
    listen_addr: SocketAddr,
    dest_addr: SocketAddr,
    server_names: Vec<String>,
    max_client_hello_bytes: usize,
    initial_read_timeout_ms: u64,
    max_connections: usize,
    unsafe_debug_logging: bool,
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
            unsafe_debug_logging,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads and validates configuration from a TOML file on disk.
    ///
    /// Reads raw bytes into a `Zeroizing<String>` buffer so sensitive fields
    /// added in future milestones are scrubbed from heap memory after parsing.
    pub fn from_toml_file(path: &Path) -> Result<Self, DaemonError> {
        let raw_text = Zeroizing::new(
            std::fs::read_to_string(path).map_err(|_| DaemonError::ConfigReadFailed)?,
        );
        Self::from_toml_str(&raw_text)
    }

    /// Parses and validates configuration from a TOML string.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, DaemonError> {
        let raw: RawConfig = toml::from_str(toml_str).map_err(|_| DaemonError::ConfigInvalid)?;
        Self::new(
            raw.listen_addr,
            raw.dest_addr,
            raw.server_names,
            raw.max_client_hello_bytes,
            raw.initial_read_timeout_ms,
            raw.max_connections,
            raw.unsafe_debug_logging,
        )
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

    /// Returns whether opt-in unsafe debug logging is enabled.
    #[must_use]
    pub const fn unsafe_debug_logging(&self) -> bool {
        self.unsafe_debug_logging
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
    fn parses_valid_config() {
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
            let dbg = format!("{c:?}");
            assert!(!dbg.contains("example.com"));
            assert!(!dbg.contains("8443"));
        }
    }

    #[test]
    fn rejects_empty_server_names_and_wildcards() {
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
    }
}

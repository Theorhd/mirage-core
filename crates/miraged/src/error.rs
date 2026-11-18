//! Sanitized static error types for Zero-PII logging.
//!
//! Foreign errors (e.g., `std::io::Error`, TOML parse errors) can embed IPs,
//! hostnames, or file contents. All externally visible errors are mapped into
//! static messages before reaching logs.

use core::fmt;

/// Sanitized operational errors for `miraged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonError {
    /// Invalid CLI arguments.
    InvalidArguments,
    /// Failed to read configuration file.
    ConfigReadFailed,
    /// Configuration failed syntax or schema validation.
    ConfigInvalid,
    /// Failed to disable process core dumps / dumpability.
    HardeningFailed,
    /// Failed to bind listening TCP socket.
    BindFailed,
    /// Failed to register OS shutdown signal handler.
    SignalHandlerFailed,
}

impl DaemonError {
    /// Returns a static, PII-free error description.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArguments => "invalid command-line arguments",
            Self::ConfigReadFailed => "failed to read configuration file",
            Self::ConfigInvalid => "configuration validation failed",
            Self::HardeningFailed => "failed to apply process hardening",
            Self::BindFailed => "failed to bind listening socket",
            Self::SignalHandlerFailed => "failed to register shutdown signal handler",
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for DaemonError {}

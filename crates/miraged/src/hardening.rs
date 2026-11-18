//! Process-level hardening (panic sanitization and dumpability).

use std::io::Write;

use crate::error::DaemonError;

/// Installs a panic hook that emits only a static message, preventing panic
/// payloads (which may contain attacker-controlled bytes or secrets) from
/// reaching logs or stderr.
pub fn install_static_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(b"miraged: fatal internal panic\n");
    }));
}

/// Marks the process non-dumpable (`PR_SET_DUMPABLE = 0`) on Linux to prevent
/// core dumps and same-UID `ptrace` attachment.
pub fn disable_core_dumps() -> Result<(), DaemonError> {
    #[cfg(target_os = "linux")]
    {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| DaemonError::HardeningFailed)?;
    }
    Ok(())
}

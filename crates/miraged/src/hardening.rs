//! Process-level hardening (panic sanitization, `RLIMIT_CORE = 0`, and dumpability).

use crate::error::DaemonError;

/// Installs a panic hook that emits only a static message, preventing panic
/// payloads (which may contain attacker-controlled bytes or secrets) from
/// reaching logs or stderr, and avoiding `std::io::Stderr` mutex deadlocks on Unix.
pub fn install_static_panic_hook() {
    std::panic::set_hook(Box::new(|_| {
        #[cfg(unix)]
        {
            let _ = rustix::io::write(std::io::stderr(), b"miraged: fatal internal panic\n");
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            if let Ok(mut stderr) = std::io::stderr().try_lock() {
                let _ = stderr.write_all(b"miraged: fatal internal panic\n");
            }
        }
    }));
}

/// Disables core dumps (`RLIMIT_CORE = 0` on all Unix) and marks the process
/// non-dumpable (`PR_SET_DUMPABLE = 0`) + `PR_SET_NO_NEW_PRIVS` on Linux.
pub fn disable_core_dumps() -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|_| DaemonError::HardeningFailed)?;
    }
    #[cfg(target_os = "linux")]
    {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .map_err(|_| DaemonError::HardeningFailed)?;
        rustix::thread::set_no_new_privs(true).map_err(|_| DaemonError::HardeningFailed)?;
    }
    Ok(())
}

/// Returns `true` if the current process is running with effective UID 0 (`root`).
#[must_use]
pub fn is_running_as_root() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

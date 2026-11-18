//! `miraged` server binary entrypoint.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use miraged::config::Config;
use miraged::error::DaemonError;
use miraged::hardening;
use miraged::metrics::Metrics;
use miraged::proxy;
use tokio::net::TcpListener;
use tracing::Level;

const DEFAULT_CONFIG_PATH: &str = "/run/secrets/config.toml";

fn parse_config_path() -> Result<PathBuf, DaemonError> {
    let mut args = std::env::args_os();
    let _bin = args.next();

    let Some(first) = args.next() else {
        return Ok(PathBuf::from(DEFAULT_CONFIG_PATH));
    };

    if first == "--config" {
        let Some(path) = args.next() else {
            return Err(DaemonError::InvalidArguments);
        };
        if args.next().is_some() {
            return Err(DaemonError::InvalidArguments);
        }
        return Ok(PathBuf::from(path));
    }

    Err(DaemonError::InvalidArguments)
}

fn init_tracing(unsafe_debug_logging: bool) {
    let max_level = if unsafe_debug_logging {
        Level::DEBUG
    } else {
        Level::WARN
    };

    let _ = tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_target(false)
        .with_ansi(false)
        .try_init();

    if unsafe_debug_logging {
        tracing::warn!("unsafe_debug_logging enabled: this instance is NOT privacy-safe");
    }
}

async fn shutdown_signal() -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| DaemonError::SignalHandlerFailed)?;
        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                res.map_err(|_| DaemonError::SignalHandlerFailed)?;
            }
            _ = sigterm.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|_| DaemonError::SignalHandlerFailed)
    }
}

async fn run(config: Arc<Config>) -> Result<(), DaemonError> {
    let listener = TcpListener::bind(config.listen_addr())
        .await
        .map_err(|_| DaemonError::BindFailed)?;

    let metrics = Arc::new(Metrics::new());

    proxy::run_server(listener, config, metrics, async {
        let _ = shutdown_signal().await;
    })
    .await
}

fn init_sync() -> Result<Arc<Config>, DaemonError> {
    hardening::install_static_panic_hook();
    hardening::disable_core_dumps()?;

    let config_path = parse_config_path()?;
    let config = Arc::new(Config::from_toml_file(&config_path)?);
    init_tracing(config.unsafe_debug_logging());
    Ok(config)
}

fn main() -> ExitCode {
    let config = match init_sync() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("miraged: {}", err.as_str());
            return ExitCode::FAILURE;
        }
    };

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        eprintln!("miraged: failed to initialize async runtime");
        return ExitCode::FAILURE;
    };

    match rt.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("miraged: {}", err.as_str());
            ExitCode::FAILURE
        }
    }
}

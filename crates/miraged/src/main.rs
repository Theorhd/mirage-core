//! `miraged` server binary entrypoint.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use miraged::config::Config;
use miraged::error::DaemonError;
use miraged::hardening;
use miraged::keygen;
use miraged::metrics::Metrics;
use miraged::net_opt::bind_tcp_listener;
use miraged::proxy::{self, SharedRuntime};
use tracing::Level;

const DEFAULT_CONFIG_PATH: &str = "/run/secrets/config.toml";

enum CliAction {
    Serve { config_path: PathBuf },
    CheckConfig { config_path: PathBuf },
    Keygen,
}

fn parse_cli() -> Result<CliAction, DaemonError> {
    let mut args = std::env::args_os();
    let _bin = args.next();

    let Some(first) = args.next() else {
        return Ok(CliAction::Serve {
            config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
        });
    };

    if first == "keygen" {
        if args.next().is_some() {
            return Err(DaemonError::InvalidArguments);
        }
        return Ok(CliAction::Keygen);
    }

    if first == "--check" {
        let config_path = match args.next() {
            None => PathBuf::from(DEFAULT_CONFIG_PATH),
            Some(flag) if flag == "--config" => {
                let Some(path) = args.next() else {
                    return Err(DaemonError::InvalidArguments);
                };
                if args.next().is_some() {
                    return Err(DaemonError::InvalidArguments);
                }
                PathBuf::from(path)
            }
            _ => return Err(DaemonError::InvalidArguments),
        };
        return Ok(CliAction::CheckConfig { config_path });
    }

    if first == "--config" {
        let Some(path) = args.next() else {
            return Err(DaemonError::InvalidArguments);
        };
        match args.next() {
            None => {
                return Ok(CliAction::Serve {
                    config_path: PathBuf::from(path),
                })
            }
            Some(flag) if flag == "--check" && args.next().is_none() => {
                return Ok(CliAction::CheckConfig {
                    config_path: PathBuf::from(path),
                });
            }
            _ => return Err(DaemonError::InvalidArguments),
        }
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

#[cfg(unix)]
fn spawn_sighup_reloader(config_path: PathBuf, runtime: Arc<SharedRuntime>) {
    if let Ok(mut sighup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        tokio::spawn(async move {
            while sighup.recv().await.is_some() {
                let path = config_path.clone();
                let load_res =
                    tokio::task::spawn_blocking(move || Config::from_toml_file(&path)).await;
                match load_res {
                    Ok(Ok(new_cfg)) => {
                        if runtime.reload(new_cfg).is_err() {
                            tracing::warn!("configuration reload rejected");
                        }
                    }
                    _ => {
                        tracing::warn!("configuration reload failed; keeping active config");
                    }
                }
            }
        });
    }
}

async fn run(config_path: PathBuf, config: Config) -> Result<(), DaemonError> {
    let listener = bind_tcp_listener(config.listen_addr(), config.listen_backlog())
        .map_err(|_| DaemonError::BindFailed)?;

    let runtime = SharedRuntime::new(config)?;
    #[cfg(unix)]
    spawn_sighup_reloader(config_path, Arc::clone(&runtime));
    #[cfg(not(unix))]
    let _ = config_path;

    let metrics = Arc::new(Metrics::new());

    proxy::run_server_with_reload(listener, runtime, metrics, async {
        let _ = shutdown_signal().await;
    })
    .await
}

fn main() -> ExitCode {
    hardening::install_static_panic_hook();
    if let Err(err) = hardening::disable_core_dumps() {
        eprintln!("miraged: {}", err.as_str());
        return ExitCode::FAILURE;
    }

    let action = match parse_cli() {
        Ok(act) => act,
        Err(err) => {
            eprintln!("miraged: {}", err.as_str());
            return ExitCode::FAILURE;
        }
    };

    match action {
        CliAction::Keygen => {
            if let Err(err) = keygen::run_keygen() {
                eprintln!("miraged: {}", err.as_str());
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        CliAction::CheckConfig { config_path } => match Config::from_toml_file(&config_path) {
            Ok(_) => {
                println!("miraged: configuration valid");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("miraged: {}", err.as_str());
                ExitCode::FAILURE
            }
        },
        CliAction::Serve { config_path } => {
            let config = match Config::from_toml_file(&config_path) {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("miraged: {}", err.as_str());
                    return ExitCode::FAILURE;
                }
            };
            init_tracing(config.unsafe_debug_logging());

            let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            else {
                eprintln!("miraged: failed to initialize async runtime");
                return ExitCode::FAILURE;
            };

            match rt.block_on(run(config_path, config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("miraged: {}", err.as_str());
                    ExitCode::FAILURE
                }
            }
        }
    }
}

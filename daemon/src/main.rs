//! daemon: thin binary entry. Argv → tokio runtime → library subcommand.
//! All real logic lives in `lib.rs` and its modules so integration tests
//! can drive the same code paths without spawning a separate process.

mod cli;

use std::process::ExitCode;

use cli::{Command, parse};
use tracing::error;
use wake_my_pc_daemon::{Config, admin, pairing_flow, server};

fn main() -> ExitCode {
    init_tracing();
    let args = parse();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("failed to start tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    // service-run / install-service / uninstall-service are sync paths
    // that don't want a Config or a tokio runtime — short-circuit them.
    #[cfg(windows)]
    {
        match &args.command {
            Command::ServiceRun => {
                return match wake_my_pc_daemon::service::service_dispatcher_start() {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        error!("service-run: {e:#}");
                        ExitCode::FAILURE
                    }
                };
            }
            Command::InstallService { binary } => {
                let path = match binary.clone() {
                    Some(p) => p,
                    None => match std::env::current_exe() {
                        Ok(p) => p,
                        Err(e) => {
                            error!("could not resolve current_exe: {e}");
                            return ExitCode::FAILURE;
                        }
                    },
                };
                return match wake_my_pc_daemon::service::install_service(path) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        error!("install-service: {e:#}");
                        ExitCode::FAILURE
                    }
                };
            }
            Command::UninstallService => {
                return match wake_my_pc_daemon::service::uninstall_service() {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        error!("uninstall-service: {e:#}");
                        ExitCode::FAILURE
                    }
                };
            }
            _ => {}
        }
    }

    let cfg = match Config::from_args(args.config) {
        Ok(c) => c,
        Err(e) => {
            error!("config: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(async move {
        match args.command {
            Command::Serve => server::run(cfg).await,
            Command::Pair => pairing_flow::run(cfg).await,
            Command::ListPaired => admin::list_paired(cfg).await,
            Command::Revoke { phone_name } => admin::revoke(cfg, phone_name).await,
            Command::ReauthNow => admin::reauth_now(cfg).await,
            Command::UninstallRevokeBroadcast => admin::uninstall_revoke_broadcast(cfg).await,
            // Windows-only commands handled above before runtime build.
            #[cfg(windows)]
            Command::ServiceRun
            | Command::InstallService { .. }
            | Command::UninstallService => unreachable!(),
        }
    });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("wake_my_pc_daemon=info,warn"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

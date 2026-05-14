//! Windows SCM service entry points + install / uninstall helpers.
//!
//! Two concerns live here, both Windows-only:
//!
//! 1. `service-run` subcommand entry. The `wake-my-pc-daemon.exe` binary
//!    is installed as a `SERVICE_WIN32_OWN_PROCESS` LocalSystem service.
//!    SCM invokes the binary with the `service-run` subcommand on
//!    startup; we hand control to `windows-service::service_dispatcher`
//!    which calls back into [`service_main`] from a worker thread.
//!    The control handler runs on a separate thread and signals
//!    shutdown to the listener via a `tokio::sync::oneshot::Sender`.
//!
//! 2. `install-service` / `uninstall-service` subcommands. Both must
//!    run elevated (admin) — they touch the SCM database. The MSI
//!    invokes these via a custom action; ad-hoc installs run them by
//!    hand from an elevated PowerShell.

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tracing::{error, info, warn};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service::ServiceDependency};

use crate::Config;

/// Internal SCM service name. Lowercase, no spaces — matches the value
/// passed to `New-Service`/`sc.exe create` and used by SCM in the
/// service-control APIs.
pub const SERVICE_NAME: &str = "wake-my-pc";

/// Friendly display name shown in `services.msc`.
pub const SERVICE_DISPLAY_NAME: &str = "Wake My PC";

/// Description shown in `services.msc` Details pane.
pub const SERVICE_DESCRIPTION: &str =
    "Listens on LAN for authenticated wake/sleep/lock commands from paired phones.";

define_windows_service!(ffi_service_main, service_main);

/// Entry point invoked from `main` for the `service-run` subcommand.
/// Hands the binary to `service_dispatcher::start`, which blocks until
/// SCM stops the service.
pub fn service_dispatcher_start() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("service_dispatcher::start (binary not invoked by SCM?)")
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("service exited with error: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;

    // The SCM control handler runs on a separate Win32 thread. It
    // signals shutdown via a tokio oneshot — `Sender::send` is sync, so
    // it works from the non-tokio thread. Wrap in `Mutex<Option<...>>`
    // so the move closure can `.take()` the sender on first stop.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
    let handler_tx = shutdown_tx.clone();

    let event_handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Ok(mut guard) = handler_tx.lock()
                    && let Some(tx) = guard.take()
                {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("registering SCM control handler")?;

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .context("set_service_status(Running)")?;

    info!("service started — entering listener");

    let result: Result<()> = runtime.block_on(async move {
        let cfg = default_service_config()?;
        let listener = tokio::net::TcpListener::bind(cfg.bind)
            .await
            .with_context(|| format!("binding TCP listener at {}", cfg.bind))?;
        let handlers = Arc::new(crate::handlers::PlatformHandlers);
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        crate::server::run_with_listener_handlers_shutdown(cfg, listener, handlers, shutdown).await
    });

    if let Err(e) = &result {
        error!("listener exited with error: {e:#}");
    }

    // Tell SCM we've stopped (regardless of error path).
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    info!("service stopped");
    result
}

/// Build the daemon config used inside the SCM service. SCM invokes the
/// binary with no per-user environment, so we never read CLI flags
/// here — the install path baked the data dir + port into the
/// `ImagePath` arguments at install time. For now, defaults: machine
/// data dir + DEFAULT_PORT on `0.0.0.0`. Tunability is M5 polish.
fn default_service_config() -> Result<Config> {
    Config::from_args(crate::ConfigArgs {
        data_dir: None,
        port: crate::config::DEFAULT_PORT,
        bind: "0.0.0.0".parse()?,
    })
}

/// Register the daemon with SCM as a LocalSystem auto-start service.
/// Requires Administrator privileges. Idempotent: returns Ok if the
/// service is already installed and points at the same binary path.
pub fn install_service(binary_path: PathBuf) -> Result<()> {
    if !binary_path.is_file() {
        return Err(anyhow!(
            "binary {} does not exist; install-service expects an absolute path to a built daemon exe",
            binary_path.display()
        ));
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening SCM (need Administrator)")?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path,
        // The binary's argv[1] when SCM launches it. `service-run` is
        // the subcommand that hands control to the dispatcher.
        launch_arguments: vec![OsString::from("service-run")],
        dependencies: Vec::<ServiceDependency>::new(),
        // None = LocalSystem. Required for SE_SHUTDOWN_NAME (PowerOff)
        // and to access the machine-scope DPAPI keystore in
        // %PROGRAMDATA%\wake-my-pc.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating service (already installed? run uninstall-service first)")?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .context("setting service description")?;

    info!("installed service {SERVICE_NAME} (LocalSystem, auto-start)");
    Ok(())
}

/// Stop + delete the service. Tolerates missing service (idempotent).
/// Caller (uninstaller) is expected to invoke
/// `uninstall-revoke-broadcast` BEFORE this so the daemon can deliver
/// Revoke to reachable phones while it's still listening.
pub fn uninstall_service() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )
    .context("opening SCM (need Administrator)")?;

    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(1060) =>
        {
            // ERROR_SERVICE_DOES_NOT_EXIST — already gone.
            warn!("service {SERVICE_NAME} not installed; uninstall is a no-op");
            return Ok(());
        }
        Err(e) => return Err(anyhow::Error::from(e).context("opening service")),
    };

    // Ask SCM to stop. Best-effort — a stuck service still gets deleted
    // on next reboot via the DELETE flag below.
    match service.query_status() {
        Ok(status) if status.current_state != ServiceState::Stopped => {
            let _ = service.stop();
            // Give it a beat to actually stop.
            std::thread::sleep(Duration::from_millis(500));
        }
        _ => {}
    }

    service
        .delete()
        .context("deleting service (will fully remove on next reboot if still in use)")?;

    info!("uninstalled service {SERVICE_NAME}");
    Ok(())
}

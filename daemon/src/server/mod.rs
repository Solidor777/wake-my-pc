//! Long-running listener. Binds the configured port, performs TLS 1.3
//! mutual auth via [`wake_my_pc_core::crypto::server_config_for_pinned_clients`],
//! then dispatches the per-connection protocol loop.
//!
//! Concurrency shape (locked: tokio):
//! ```text
//!   serve()
//!     ├── load keystore (DPAPI on Windows)
//!     ├── core::crypto::DeviceIdentity::from_bytes
//!     ├── handlers.prepare()  (enable SE_SHUTDOWN_NAME on Windows)
//!     ├── shared SharedState  (Arc<RwLock<KeystoreContents>> + Arc<dyn Handlers>)
//!     ├── ctrl-c task       ──┐
//!     └── accept-loop task  ──┴──▶ drop on shutdown
//!         └── per-connection task: TLS handshake + protocol::run
//! ```

mod connection;
mod listener;
mod state;

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::{info, warn};
use wake_my_pc_core::crypto::DeviceIdentity;

use crate::config::Config;
use crate::handlers::{Handlers, PlatformHandlers};
use crate::keystore;

pub use state::SharedState;

/// Run the daemon listener loop until ctrl-c. Production entry — binds
/// the TCP listener internally to the configured `bind` address.
pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("binding TCP listener at {}", cfg.bind))?;
    run_with_listener(cfg, listener).await
}

/// Run the daemon listener with a pre-bound `TcpListener`. Integration
/// tests use this so they can grab the ephemeral port via
/// `listener.local_addr()` before handing it over. Wires production
/// [`PlatformHandlers`].
pub async fn run_with_listener(cfg: Config, listener: TcpListener) -> anyhow::Result<()> {
    run_with_listener_and_handlers(cfg, listener, Arc::new(PlatformHandlers)).await
}

/// Run with an injected [`Handlers`] impl. Test-only entry; production
/// uses [`run_with_listener`]. Shutdown is ctrl-c.
pub async fn run_with_listener_and_handlers(
    cfg: Config,
    listener: TcpListener,
    handlers: Arc<dyn Handlers>,
) -> anyhow::Result<()> {
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    run_with_listener_handlers_shutdown(cfg, listener, handlers, shutdown).await
}

/// Service-mode entry: caller provides the shutdown future. SCM stops
/// the daemon by signalling `shutdown` from its control-handler thread.
pub async fn run_with_listener_handlers_shutdown<S>(
    cfg: Config,
    listener: TcpListener,
    handlers: Arc<dyn Handlers>,
    shutdown: S,
) -> anyhow::Result<()>
where
    S: std::future::Future<Output = ()>,
{
    keystore::ensure_data_dir(&cfg.data_dir).await?;

    let contents = match keystore::load(&cfg.keystore_path()).await? {
        Some(c) => c,
        None => {
            anyhow::bail!(
                "no keystore at {} — run `wake-my-pc-daemon pair` first to bootstrap",
                cfg.keystore_path().display()
            );
        }
    };

    let identity = DeviceIdentity::from_bytes(&contents.device_identity_bytes())
        .context("loading device identity from keystore")?;

    if let Err(e) = handlers.prepare() {
        // Non-fatal: daemon can still run sleep+lock without shutdown
        // privilege; PowerOff will surface NotPermitted to the peer.
        warn!("handlers.prepare() failed (PowerOff will be unavailable): {e}");
    }

    let state = SharedState::with_handlers(contents, identity, cfg.clone(), handlers);

    info!(
        "wake-my-pc-daemon listening on {} ({} pairings loaded)",
        listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| cfg.bind.to_string()),
        state.snapshot().await.pairings.len()
    );

    listener::accept_loop(state, listener, shutdown).await
}

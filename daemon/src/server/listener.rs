//! TCP accept loop + TLS handshake. After handshake, hands off to
//! [`super::connection::run`] for the protocol-level dispatch.
//!
//! The pinset that authenticates incoming clients is rebuilt from the
//! keystore on each accept (cheap — small set, Arc-shared inside
//! rustls). This is correct rather than performant: any pairing
//! mutation (new pair, revocation) takes effect on the next connection
//! without restarting the listener.

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use wake_my_pc_core::crypto::{PinSet, server_config_for_pinned_clients};

use super::SharedState;
use super::connection;

/// Accept connections forever (or until ctrl-c). The `TcpListener` is
/// pre-bound by the caller — see [`super::run`] for the bind site.
pub async fn accept_loop(state: SharedState, listener: TcpListener) -> anyhow::Result<()> {
    let local_addr = listener.local_addr()?;
    info!("listening on {local_addr}");

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("ctrl-c received; stopping listener");
                return Ok(());
            }
            accept = listener.accept() => {
                let (tcp, peer_addr) = match accept {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("accept failed: {e}");
                        continue;
                    }
                };

                let acceptor = match build_acceptor(&state, provider.clone()).await {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("rustls config build failed: {e:#}");
                        continue;
                    }
                };
                let state = state.clone();

                tokio::spawn(async move {
                    debug!("connection from {peer_addr}");
                    if let Err(e) = handle_connection(acceptor, tcp, state).await {
                        debug!("connection from {peer_addr} ended: {e:#}");
                    }
                });
            }
        }
    }
}

async fn build_acceptor(
    state: &SharedState,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> anyhow::Result<TlsAcceptor> {
    let snap = state.read().await;
    let pins: Vec<_> = snap
        .pairings
        .iter()
        .filter(|p| p.is_active())
        .map(|p| p.client_spki)
        .collect();
    let pinset = Arc::new(PinSet::with_pins(pins));
    let cfg = server_config_for_pinned_clients(pinset, state.identity(), provider)
        .map_err(anyhow::Error::from)?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    state: SharedState,
) -> anyhow::Result<()> {
    let tls = acceptor.accept(tcp).await.context("TLS handshake")?;
    connection::run(tls, state).await
}

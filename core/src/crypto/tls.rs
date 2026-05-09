//! rustls config builders for client + server. PROTOCOL.md §6.
//!
//! Three modes:
//!   - client → daemon: server cert pinned, client presents own cert.
//!   - daemon ← client (running): client cert pinned, daemon presents own cert.
//!   - daemon ← client (pairing window): any TLS-valid client cert; daemon
//!     captures the SPKI at the protocol layer once `Pair{pairing_code}`
//!     succeeds.
//!
//! All three reject TLS < 1.3 at config time (PROTOCOL.md §6, PRINCIPLES.md
//! §1: no plaintext fallback / no downgrade path).
//!
//! TLS resumption is disabled (PROTOCOL.md §5) — every reconnect is a fresh
//! handshake, so per-direction nonce state cleanly resets to `last_seen = 0`.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::{ClientConfig, ServerConfig};

use super::Error;
use super::device::DeviceIdentity;
use super::pin::{PinSet, PinnedClientVerifier, PinnedServerVerifier};

/// Build a `ClientConfig` that authenticates daemons by SPKI pin and
/// presents `client_identity` as the local cert. TLS 1.3 only; resumption
/// disabled.
pub fn client_config_for_pinned_daemon(
    daemon_pins: Arc<PinSet>,
    client_identity: &DeviceIdentity,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ClientConfig, Error> {
    let verifier = Arc::new(PinnedServerVerifier::new(daemon_pins, provider.as_ref()));
    let (cert_chain, private_key) = identity_to_rustls(client_identity);

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| Error::RustlsConfig(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, private_key)
        .map_err(|e| Error::RustlsConfig(e.to_string()))?;

    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Build a `ServerConfig` that authenticates clients by SPKI pin and
/// presents `server_identity`. TLS 1.3 only; resumption / 0-RTT disabled.
pub fn server_config_for_pinned_clients(
    client_pins: Arc<PinSet>,
    server_identity: &DeviceIdentity,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ServerConfig, Error> {
    let verifier = Arc::new(PinnedClientVerifier::pinned(client_pins, provider.as_ref()));
    let (cert_chain, private_key) = identity_to_rustls(server_identity);

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| Error::RustlsConfig(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| Error::RustlsConfig(e.to_string()))?;

    disable_server_resumption(&mut config);
    Ok(config)
}

/// Build a `ServerConfig` for the pairing window — accepts any TLS-valid
/// client cert. The daemon must use this ONLY while [`super::PairingHandshake`]
/// is in `Awaiting` state, and must rebuild the running config (with the new
/// pin) once pairing succeeds.
pub fn server_config_for_pairing(
    server_identity: &DeviceIdentity,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ServerConfig, Error> {
    let verifier = Arc::new(PinnedClientVerifier::pairing_window(provider.as_ref()));
    let (cert_chain, private_key) = identity_to_rustls(server_identity);

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| Error::RustlsConfig(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| Error::RustlsConfig(e.to_string()))?;

    disable_server_resumption(&mut config);
    Ok(config)
}

fn identity_to_rustls(
    identity: &DeviceIdentity,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = CertificateDer::from(identity.cert_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_pkcs8_der().to_vec()));
    (vec![cert], key)
}

fn disable_server_resumption(config: &mut ServerConfig) {
    // No TLS 1.3 session tickets, no stateful session caching, no 0-RTT.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
}

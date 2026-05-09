//! TLS 1.3 + SPKI-pinning + pairing handshake. PROTOCOL.md §6 + §8.
//!
//! M1 scope: cert generation, SPKI pinning verifier (rustls trait impls),
//! pairing handshake state machine, monotonic nonce counter. This module
//! is **pure types and config builders** — no sockets. Transport plumbing
//! lives in `daemon/` (M2) and the mobile shells (M4).

mod device;
mod nonce;
mod pairing;
mod pin;
mod spki;
mod tls;

pub use device::{DeviceIdentity, DeviceIdentityBytes};
pub use nonce::{NonceCounter, NonceError, NonceReceiver, NonceSender};
pub use pairing::{
    PAIRING_WINDOW_DEFAULT_MS, PairingHandshake, PairingRecord, PairingRejection, PairingState,
    PairingTransition,
};
pub use pin::{PinSet, PinnedClientVerifier, PinnedServerVerifier};
pub use spki::{compute_spki_hash, extract_spki_hash};
pub use tls::{
    client_config_for_pinned_daemon, server_config_for_pairing, server_config_for_pinned_clients,
};

pub use crate::protocol::SpkiHash;

use thiserror::Error;

/// Crypto-layer errors. Distinct from [`crate::protocol::Error`] — the
/// protocol layer handles wire framing; this layer handles certs, pins,
/// pairing, and nonces.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Certificate generation via rcgen failed. Surfaced from
    /// [`device::DeviceIdentity::generate`]. Should not happen in normal use;
    /// indicates a system-level RNG / time / dependency-version issue.
    #[error("device cert generation failed: {0}")]
    CertGeneration(String),

    /// Stored device-identity bytes (PKCS#8 DER + cert DER) failed to round-trip.
    /// Indicates keystore corruption or version skew.
    #[error("device identity could not be loaded: {0}")]
    IdentityLoad(String),

    /// X.509 cert could not be parsed when extracting the SPKI hash.
    /// Caller fed invalid DER.
    #[error("x509 parse failed: {0}")]
    X509Parse(String),

    /// rustls config builder rejected the configuration. Indicates a
    /// programmer error here (we built an unsupported combination).
    #[error("rustls config build failed: {0}")]
    RustlsConfig(String),

    /// Strict-monotonic nonce check failed. Maps to wire `NonceReplay`
    /// (PROTOCOL.md §7).
    #[error(transparent)]
    Nonce(#[from] NonceError),

    /// Pairing state machine transition not allowed in current state.
    #[error("pairing state machine: {0}")]
    PairingState(&'static str),

    /// OS RNG failed. Defensive — `getrandom` should never fail on a
    /// well-configured platform.
    #[error("os rng failed: {0}")]
    OsRng(String),
}

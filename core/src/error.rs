//! Top-level crate error. Module-level errors (`protocol::Error`,
//! `crypto::Error`) are the canonical APIs; this enum exists as a convenience
//! for callers (the daemon, desktop-ui, bindings) that want a single handle
//! type. Conversions go one way: module errors `Into` the top-level `Error`,
//! never the reverse — so we never lose detail accidentally.

use thiserror::Error;

/// Crate-wide error. Variants are flat: each module's error becomes one
/// variant here. Adding a new module-level error means adding a variant +
/// `From` impl; the lint posture (`#[non_exhaustive]`) keeps downstream
/// matches honest across minor versions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Wire-protocol encode/decode/framing failure. See [`crate::protocol::Error`].
    #[error(transparent)]
    Protocol(#[from] crate::protocol::Error),

    /// TLS / pinning / pairing / nonce failure. See [`crate::crypto::Error`].
    #[error(transparent)]
    Crypto(#[from] crate::crypto::Error),
}

//! Daemon-specific errors. Most code returns `anyhow::Result<...>` because
//! we're at a binary boundary; this module exists for the few places where
//! a typed error is meaningfully matched (keystore I/O, OS handler return
//! mapping to wire `ProtocolError`).

use thiserror::Error;
use wake_my_pc_core::protocol::ProtocolError;

/// Reasons an OS state-change handler can fail. Mapped to wire codes per
/// PROTOCOL.md §7 with no detail leaked to the peer (Principle 1).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OsHandlerError {
    /// The OS API call returned a failure status. Logged locally with
    /// detail; surfaced to peer as `Internal`.
    #[error("OS handler failed: {detail}")]
    OsApi {
        /// Diagnostic message — local logs only, never on the wire.
        detail: String,
    },

    /// The daemon doesn't have the privilege to perform the action
    /// (e.g. PowerOff without `SE_SHUTDOWN_NAME`). Logged locally;
    /// surfaced to peer as `Internal`. Operationally indicates an install
    /// problem.
    #[error("OS handler not permitted: {detail}")]
    NotPermitted {
        /// Diagnostic message — local logs only.
        detail: String,
    },
}

impl OsHandlerError {
    /// Map to the on-wire `ProtocolError`. All variants collapse to
    /// `Internal` per Principle 1 (no info leak).
    #[must_use]
    pub fn to_wire_code(&self) -> ProtocolError {
        ProtocolError::Internal
    }
}

/// Keystore I/O failures. Daemon startup catches and logs; subcommands
/// surface to the user via `anyhow`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeystoreError {
    /// File-level I/O.
    #[error("keystore I/O: {0}")]
    Io(#[from] std::io::Error),

    /// DPAPI / OS keystore-encryption failure.
    #[error("keystore encryption: {0}")]
    Encryption(String),

    /// Postcard decode of the plaintext layer failed — keystore corruption
    /// or wrong format version.
    #[error("keystore decode: {0}")]
    Decode(String),

    /// Keystore on disk has a format version this daemon doesn't recognize.
    #[error("keystore format v{got} not supported (expected v{expected})")]
    FormatVersion {
        /// Format byte read from the file.
        got: u8,
        /// Format byte this build understands.
        expected: u8,
    },

    /// Core-side parse of the device identity bytes failed.
    #[error("device identity: {0}")]
    Identity(#[from] wake_my_pc_core::crypto::Error),
}

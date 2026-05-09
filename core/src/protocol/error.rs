//! Protocol-layer errors. Two error roles:
//!
//! - **Library errors** (this enum): what the encode/decode functions return
//!   to in-process callers. Carries detail useful to a Rust caller (the bad
//!   length, expected vs. got version, postcard inner cause).
//! - **Wire errors** ([`super::ProtocolError`]): the on-wire enum sent to the
//!   peer in a [`super::DaemonFrame::Error`] frame. Stripped of detail per
//!   Principle 1 (no info leak via error text).
//!
//! `Error::to_wire_code` maps library → wire so the daemon can produce honest
//! error responses without leaking internals.

use thiserror::Error;

use super::message::ProtocolError;

/// Errors returned by `core::protocol` encode and decode APIs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Postcard refused to encode the frame. Should not happen for the
    /// closed set of types in PROTOCOL.md §3 — surfaces as `MalformedFrame`
    /// on the wire if it ever does.
    #[error("postcard encoding failed: {0}")]
    Encoding(postcard::Error),

    /// Postcard refused to decode the payload — caller fed bad bytes.
    #[error("postcard decoding failed: {0}")]
    Decoding(postcard::Error),

    /// Encoder produced (or decoder declared) a frame larger than
    /// [`super::MAX_FRAME_LEN`]. Sender bug, or attacker probing resource limits.
    #[error("frame length {len} exceeds max {max}")]
    OversizedFrame {
        /// Declared envelope length in bytes.
        len: usize,
        /// `MAX_FRAME_LEN`, copied for diagnostic clarity.
        max: usize,
    },

    /// Length prefix declares a frame smaller than [`super::MIN_FRAME_LEN`]
    /// (i.e. cannot fit version + nonce + a single postcard discriminant).
    #[error("frame length {len} below minimum {min}")]
    UndersizedFrame {
        /// Declared envelope length.
        len: usize,
        /// `MIN_FRAME_LEN`.
        min: usize,
    },

    /// Envelope version byte didn't match [`super::PROTOCOL_VERSION`].
    /// Receiver MUST close connection per PROTOCOL.md §2.
    #[error("envelope version {got:#x} not supported (expected {expected:#x})")]
    VersionMismatch {
        /// Version byte read from the wire.
        got: u8,
        /// Version this build understands.
        expected: u8,
    },

    /// Postcard finished decoding the payload but bytes remained inside the
    /// declared envelope length. Indicates length lying about contents —
    /// connection-killing per PROTOCOL.md §4.
    #[error("trailing {trailing} bytes in envelope after payload decode")]
    TrailingBytes {
        /// Number of unparsed bytes after the postcard frame.
        trailing: usize,
    },

    /// `usize` → `u32` length conversion overflowed. Defensive — only
    /// reachable on hypothetical 128-bit `usize` platforms; we still surface
    /// it as a typed error rather than panic per Principle 2.
    #[error("frame length overflowed u32")]
    LengthOverflow,
}

impl Error {
    /// Map a library error to its on-wire `ProtocolError`. Used by the daemon
    /// (M2) when crafting an `Error` frame to send to the offending peer.
    /// Stripped of detail per Principle 1.
    #[must_use]
    pub fn to_wire_code(&self) -> ProtocolError {
        match self {
            Self::VersionMismatch { .. } => ProtocolError::VersionMismatch,
            Self::Encoding(_)
            | Self::Decoding(_)
            | Self::OversizedFrame { .. }
            | Self::UndersizedFrame { .. }
            | Self::TrailingBytes { .. }
            | Self::LengthOverflow => ProtocolError::MalformedFrame,
        }
    }
}

//! Strict-monotonic per-direction nonce counter (PROTOCOL.md §5).
//!
//! Each direction of a TLS session gets independent send + receive counters,
//! both starting at `0` post-handshake. First sent frame's nonce is `1`
//! (pre-increment). Receiver tracks `last_seen`; accepts iff
//! `incoming > last_seen`. TLS record-layer in-order delivery makes strict
//! monotonic safe (no out-of-order accept needed).
//!
//! Wrap-around is not handled — at u64 + 1 frame/ms, exhaustion takes 584
//! million years.

use thiserror::Error;

/// Outbound nonce counter. Caller pre-increments via [`Self::next`] then
/// stamps the returned value into the envelope.
#[derive(Clone, Copy, Debug, Default)]
pub struct NonceSender {
    next: u64,
}

impl NonceSender {
    /// Fresh sender, ready to emit `1` on first call to [`Self::next`].
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Pre-increment and return the new value. First call returns `1`.
    /// Pure arithmetic — no I/O. `checked_add` per Principle 2; overflow
    /// returns `None` and the caller should drop the connection.
    #[must_use]
    pub fn issue(&mut self) -> Option<u64> {
        let v = self.next.checked_add(1)?;
        self.next = v;
        Some(v)
    }

    /// Last-issued nonce. `0` before [`Self::issue`] is called.
    #[must_use]
    pub const fn last_issued(&self) -> u64 {
        self.next
    }
}

/// Inbound nonce checker. Strict-monotonic: rejects equal-or-lower.
#[derive(Clone, Copy, Debug, Default)]
pub struct NonceReceiver {
    last_seen: u64,
}

impl NonceReceiver {
    /// Fresh receiver; `last_seen = 0`, so the first accepted frame's
    /// nonce must be `>= 1`.
    #[must_use]
    pub const fn new() -> Self {
        Self { last_seen: 0 }
    }

    /// Validate `incoming` against the strict-monotonic rule and advance
    /// `last_seen` on accept. Returns `Ok(())` on accept, `Err` on replay.
    pub fn accept(&mut self, incoming: u64) -> Result<(), NonceError> {
        if incoming <= self.last_seen {
            return Err(NonceError::Replay {
                incoming,
                last_seen: self.last_seen,
            });
        }
        self.last_seen = incoming;
        Ok(())
    }

    /// Highest nonce accepted so far. `0` if none yet.
    #[must_use]
    pub const fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

/// Convenience pair: a sender and receiver bundled for one direction-pair.
/// Each TLS session holds two of these (one client→daemon, one daemon→client).
#[derive(Clone, Copy, Debug, Default)]
pub struct NonceCounter {
    /// Outbound counter for this direction.
    pub send: NonceSender,
    /// Inbound checker for this direction.
    pub recv: NonceReceiver,
}

impl NonceCounter {
    /// Fresh counter with both halves zeroed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            send: NonceSender::new(),
            recv: NonceReceiver::new(),
        }
    }
}

/// Nonce-validation failure. Maps to wire [`crate::protocol::ProtocolError::NonceReplay`].
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NonceError {
    /// Incoming nonce was less than or equal to `last_seen`.
    #[error("nonce replay: got {incoming}, last seen {last_seen}")]
    Replay {
        /// Nonce on the offending frame.
        incoming: u64,
        /// Highest accepted before this frame.
        last_seen: u64,
    },
}

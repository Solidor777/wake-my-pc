//! Pairing handshake state machine. PROTOCOL.md §8.
//!
//! Pure state — no I/O, no clock, no RNG-as-side-effect. Caller (the daemon
//! in M2) drives transitions: starts a pairing window when the user runs
//! `daemon-cli pair`, feeds incoming `Pair` frames in, ticks for expiry.
//!
//! Window default: 5 minutes. After one accepted `Pair` OR timeout, the
//! state machine returns to `Idle`; second pairing requires another `start`.
//!
//! Brute-force bound: pairing codes are 6 digits (0..1_000_000). The state
//! machine itself caps wrong-code attempts at [`MAX_PAIRING_ATTEMPTS`] per
//! window — after the bound is reached, state returns to `Idle` and the
//! user must re-run `daemon-cli pair`. Combined with the 5-minute TTL, an
//! online attacker on the LAN gets at most 5 guesses against a 10^6
//! search space (5e-6 per window) — sound for a one-shot home-LAN flow.

use super::Error;
use crate::protocol::SpkiHash;

/// Default pairing window: 5 minutes.
pub const PAIRING_WINDOW_DEFAULT_MS: u64 = 5 * 60 * 1000;

/// Maximum wrong-code attempts before the state machine forces a fresh
/// `daemon-cli pair`. PROTOCOL.md §8 brute-force bound.
pub const MAX_PAIRING_ATTEMPTS: u8 = 5;

/// Upper bound (exclusive) of pairing codes — they fit in 6 decimal digits.
const PAIRING_CODE_MODULUS: u32 = 1_000_000;

/// Stateful pairing handshake. Single-active-window model — the daemon
/// holds one of these and gates all incoming pairing attempts through it.
#[derive(Debug)]
pub struct PairingHandshake {
    state: PairingState,
}

/// Externally-observable state. Daemons inspect `state()` to decide which
/// rustls config to serve (pairing-window vs. running) and to render the
/// 6-digit code in `Awaiting`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingState {
    /// No pairing window open. Daemon serves the running rustls config.
    Idle,
    /// Pairing window open. Daemon serves `server_config_for_pairing` and
    /// shows `code` to the user (canonical 6-digit value, `0..1_000_000`).
    Awaiting {
        /// One-time pairing PIN, 6-digit canonical value (`0..1_000_000`).
        /// Caller renders as zero-padded decimal; QR encodes the same value.
        code: u32,
        /// Wall-clock expiry of this window, unix milliseconds.
        expires_at_unix_ms: u64,
        /// How many wrong-code rejections have occurred this window.
        /// Hits [`MAX_PAIRING_ATTEMPTS`] → state returns to `Idle`.
        failed_attempts: u8,
    },
    /// One pairing succeeded. Held until [`PairingHandshake::reset`] —
    /// caller is expected to take the [`PairingRecord`], persist it, then
    /// reset.
    Paired {
        /// The successful pairing's record.
        record: PairingRecord,
    },
}

/// Output of a state transition. Returned from every public method so the
/// caller knows what changed without re-reading state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingTransition {
    /// Window opened. Caller displays `code`.
    Started {
        /// Same code now in `state.Awaiting.code`.
        code: u32,
    },
    /// Window timed out without a successful pair.
    Expired,
    /// Pair frame accepted. Caller should persist `record` and call
    /// [`PairingHandshake::reset`].
    Succeeded {
        /// Newly-paired client.
        record: PairingRecord,
    },
    /// Pair frame rejected; window remains open until timeout.
    Rejected {
        /// Why the frame was refused.
        reason: PairingRejection,
    },
    /// No state change — already in the target state.
    NoOp,
}

/// Why a `Pair` frame was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRejection {
    /// State machine wasn't in `Awaiting` when the frame arrived.
    NotInWindow,
    /// `pairing_code` didn't match the active window's code, and the
    /// per-window attempt budget is not yet exhausted (window stays open).
    WrongCode,
    /// Window had expired by the time the frame arrived.
    Expired,
    /// Wrong-code attempts hit [`MAX_PAIRING_ATTEMPTS`]. Window forced
    /// closed; user must re-run `daemon-cli pair` to start a new one.
    TooManyAttempts,
    /// `offered_code` was outside the valid 6-digit range
    /// (`0..1_000_000`). Counts against the attempt budget.
    OutOfRange,
}

/// Persisted record of one successful pairing. Daemon stores this in its
/// keystore alongside the per-pairing fields tracked by M2 (`paired_at`,
/// `last_authenticated_at`, `revoked`, etc.).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRecord {
    /// User-visible label (from the `Pair` frame).
    pub phone_name: String,
    /// SHA-256 of the client's SPKI (extracted from its TLS cert by the
    /// caller before invoking [`PairingHandshake::accept_pair`]).
    pub client_spki: SpkiHash,
    /// Unix milliseconds at which the pairing was completed.
    pub paired_at_unix_ms: u64,
}

impl Default for PairingHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingHandshake {
    /// Fresh handshake in `Idle`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: PairingState::Idle,
        }
    }

    /// Current state. Caller may match on this to decide UI / rustls config.
    #[must_use]
    pub fn state(&self) -> &PairingState {
        &self.state
    }

    /// Open a pairing window.
    /// - From `Idle`: generates a fresh code, transitions to `Awaiting`.
    /// - From `Awaiting`: rejected as `NoOp` (caller should reset first).
    /// - From `Paired`: rejected as `NoOp` (caller should reset first).
    ///
    /// `ttl_ms` is the window length; pass [`PAIRING_WINDOW_DEFAULT_MS`]
    /// unless explicitly tightening.
    pub fn start(&mut self, now_unix_ms: u64, ttl_ms: u64) -> Result<PairingTransition, Error> {
        if !matches!(self.state, PairingState::Idle) {
            return Ok(PairingTransition::NoOp);
        }
        let code = random_pairing_code()?;
        let expires_at_unix_ms = now_unix_ms.saturating_add(ttl_ms);
        self.state = PairingState::Awaiting {
            code,
            expires_at_unix_ms,
            failed_attempts: 0,
        };
        Ok(PairingTransition::Started { code })
    }

    /// Process an incoming `Pair` frame. Returns the resulting transition.
    /// On `Succeeded`, state moves to `Paired{record}`. Rejection
    /// transitions:
    /// - `NotInWindow`: state unchanged.
    /// - `Expired`: state → `Idle`.
    /// - `WrongCode`: window stays open, attempt counter incremented.
    /// - `OutOfRange` (`offered_code >= 1_000_000`): same — counts against
    ///   the budget so a fuzzer can't burn through unbounded.
    /// - `TooManyAttempts`: state → `Idle` after the bound is hit.
    pub fn accept_pair(
        &mut self,
        now_unix_ms: u64,
        offered_code: u32,
        phone_name: String,
        client_spki: SpkiHash,
    ) -> PairingTransition {
        let (code, expires_at_unix_ms, prior_failures) = match self.state {
            PairingState::Awaiting {
                code,
                expires_at_unix_ms,
                failed_attempts,
            } => (code, expires_at_unix_ms, failed_attempts),
            PairingState::Idle | PairingState::Paired { .. } => {
                return PairingTransition::Rejected {
                    reason: PairingRejection::NotInWindow,
                };
            }
        };

        if now_unix_ms >= expires_at_unix_ms {
            self.state = PairingState::Idle;
            return PairingTransition::Rejected {
                reason: PairingRejection::Expired,
            };
        }

        // Range check first — a malformed code still costs an attempt so
        // a peer can't spam the window with junk to keep it open.
        let out_of_range = offered_code >= PAIRING_CODE_MODULUS;

        if out_of_range || offered_code != code {
            let new_failures = prior_failures.saturating_add(1);
            if new_failures >= MAX_PAIRING_ATTEMPTS {
                self.state = PairingState::Idle;
                return PairingTransition::Rejected {
                    reason: PairingRejection::TooManyAttempts,
                };
            }
            self.state = PairingState::Awaiting {
                code,
                expires_at_unix_ms,
                failed_attempts: new_failures,
            };
            return PairingTransition::Rejected {
                reason: if out_of_range {
                    PairingRejection::OutOfRange
                } else {
                    PairingRejection::WrongCode
                },
            };
        }

        let record = PairingRecord {
            phone_name,
            client_spki,
            paired_at_unix_ms: now_unix_ms,
        };
        self.state = PairingState::Paired {
            record: record.clone(),
        };
        PairingTransition::Succeeded { record }
    }

    /// Periodic expiry check. Caller invokes from a tick / poll loop.
    /// Returns `Expired` exactly once when a window times out.
    pub fn tick(&mut self, now_unix_ms: u64) -> PairingTransition {
        match self.state {
            PairingState::Awaiting {
                expires_at_unix_ms, ..
            } if now_unix_ms >= expires_at_unix_ms => {
                self.state = PairingState::Idle;
                PairingTransition::Expired
            }
            _ => PairingTransition::NoOp,
        }
    }

    /// Reset to `Idle`. Caller invokes after persisting a `Paired{record}`,
    /// or after handling a `Rejected{Expired}`.
    pub fn reset(&mut self) {
        self.state = PairingState::Idle;
    }
}

/// Generate a 6-digit pairing code in `0..1_000_000`. Rejection-sampled
/// to avoid the modulo-bias of `u32 % 1_000_000` (small bias, ~2^-32, but
/// rejection sampling is barely more code and is the right default for
/// a security-relevant random integer).
fn random_pairing_code() -> Result<u32, Error> {
    // Largest multiple of `PAIRING_CODE_MODULUS` that fits in u32.
    // u32::MAX = 4_294_967_295. 4_294 * 1_000_000 = 4_294_000_000.
    // Values >= this would skew the modulo, so we resample them.
    // Integer truncation is intentional here — that's exactly what gives
    // us the largest-multiple-of-modulus, so the lint is a false positive.
    #[allow(clippy::integer_division)]
    const RESAMPLE_THRESHOLD: u32 = (u32::MAX / PAIRING_CODE_MODULUS) * PAIRING_CODE_MODULUS;
    loop {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).map_err(|e| Error::OsRng(e.to_string()))?;
        let raw = u32::from_le_bytes(buf);
        if raw < RESAMPLE_THRESHOLD {
            return Ok(raw % PAIRING_CODE_MODULUS);
        }
    }
}

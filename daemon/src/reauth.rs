//! Daemon-side re-auth state machine. PLAN.md M2 → "Re-auth state
//! machine".
//!
//! Pure state — no I/O. Daemon code reads `interval_days` and
//! `last_authenticated_at_unix_ms` from the keystore and asks
//! [`evaluate`] whether a state-changing command should be allowed.
//!
//! Off interval ⇒ daemon never enters NeedsReauth. OneDay/SevenDays/
//! ThirtyDays ⇒ NeedsReauth at exactly `last_authenticated_at +
//! interval_days * 86_400_000` ms. `ReauthStatus` always succeeds, even
//! in NeedsReauth, so the phone can render the banner.

use wake_my_pc_core::protocol::{ProtocolError, ReauthInterval};

/// Outcome of an evaluation against the re-auth window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReauthState {
    /// Daemon will accept state-changing commands.
    Active,
    /// Daemon is past the re-auth window; only `ReauthStatus`/`ReauthConfig`
    /// and `RevokeAck` are accepted. Maps to wire `RequiresReauth`.
    NeedsReauth,
}

impl ReauthState {
    /// Map to a wire error if this state would block the command. `None`
    /// means the command is allowed.
    #[must_use]
    pub fn block_state_change(self) -> Option<ProtocolError> {
        match self {
            Self::Active => None,
            Self::NeedsReauth => Some(ProtocolError::RequiresReauth),
        }
    }
}

/// Convert a `u8` interval (as stored in the keystore) to a wire
/// [`ReauthInterval`].
#[must_use]
pub fn interval_from_days(days: u8) -> ReauthInterval {
    match days {
        0 => ReauthInterval::Off,
        1 => ReauthInterval::OneDay,
        7 => ReauthInterval::SevenDays,
        30 => ReauthInterval::ThirtyDays,
        // Any other value persisted defaults back to 7 — the canonical
        // default. Keystore writes are validated, but a future code change
        // could store something unrecognized; degrade gracefully.
        _ => ReauthInterval::SevenDays,
    }
}

/// Convert a wire [`ReauthInterval`] back to its keystore u8.
#[must_use]
pub fn interval_to_days(interval: ReauthInterval) -> u8 {
    match interval {
        ReauthInterval::Off => 0,
        ReauthInterval::OneDay => 1,
        ReauthInterval::SevenDays => 7,
        ReauthInterval::ThirtyDays => 30,
    }
}

/// Compute the expiry timestamp (unix-ms). `0` ⇒ Off (never expires);
/// caller renders as "never".
#[must_use]
pub fn expires_at_unix_ms(last_auth_unix_ms: u64, interval_days: u8) -> u64 {
    if interval_days == 0 {
        return u64::MAX;
    }
    let window_ms = u64::from(interval_days).saturating_mul(86_400_000);
    last_auth_unix_ms.saturating_add(window_ms)
}

/// Decide whether the daemon is currently `Active` or `NeedsReauth`.
#[must_use]
pub fn evaluate(now_unix_ms: u64, last_auth_unix_ms: u64, interval_days: u8) -> ReauthState {
    if interval_days == 0 {
        return ReauthState::Active;
    }
    if now_unix_ms < expires_at_unix_ms(last_auth_unix_ms, interval_days) {
        ReauthState::Active
    } else {
        ReauthState::NeedsReauth
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const ONE_DAY: u64 = 86_400_000;

    #[test]
    fn off_interval_is_always_active() {
        assert_eq!(evaluate(0, 0, 0), ReauthState::Active);
        // Far-future timestamp: Off interval ignores it.
        assert_eq!(evaluate(u64::MAX - 1, 0, 0), ReauthState::Active);
    }

    #[test]
    fn one_day_window_active_at_25h() {
        // Plan exit-criterion shape: hour 0 → succeed, hour 25 → RequiresReauth.
        let last_auth = 0;
        // Hour 0 — well within window.
        assert_eq!(evaluate(0, last_auth, 1), ReauthState::Active);
        // Hour 23 — still within.
        assert_eq!(evaluate(23 * 3_600_000, last_auth, 1), ReauthState::Active);
        // Hour 25 — past expiry.
        assert_eq!(
            evaluate(25 * 3_600_000, last_auth, 1),
            ReauthState::NeedsReauth
        );
    }

    #[test]
    fn manual_extend_recovers_to_active() {
        // Hour 25 with last_auth=0 ⇒ NeedsReauth.
        assert_eq!(evaluate(25 * 3_600_000, 0, 1), ReauthState::NeedsReauth);
        // After running reauth-now at hour 12 (last_auth = 12h), hour 25
        // is within new 36-hour window.
        assert_eq!(
            evaluate(25 * 3_600_000, 12 * 3_600_000, 1),
            ReauthState::Active
        );
    }

    #[test]
    fn boundary_at_exact_expiry_is_needs_reauth() {
        // Strict inequality: now == expires_at counts as NeedsReauth so a
        // command landing exactly on the boundary doesn't sneak through.
        assert_eq!(evaluate(ONE_DAY, 0, 1), ReauthState::NeedsReauth);
    }

    #[test]
    fn intervals_round_trip() {
        for d in [0u8, 1, 7, 30] {
            assert_eq!(interval_to_days(interval_from_days(d)), d);
        }
    }
}

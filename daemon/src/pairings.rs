//! Per-pairing record. Keystore round-trip target for postcard.
//!
//! Mirrors `PLAN.md` M2 → "Persistence: per-pairing keystore record":
//! `phone_name`, `paired_at`, `revoked` (immediate-effect flag),
//! `revoke_pending` (unack'd Revoke push queue), `last_authenticated_at`.

use serde::{Deserialize, Serialize};
use wake_my_pc_core::crypto::SpkiHash;

/// One paired phone's record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRecord {
    /// User-visible label captured at pairing time.
    pub phone_name: String,
    /// SHA-256 of the phone's SPKI. The cryptographic identity.
    pub client_spki: SpkiHash,
    /// Unix-ms when pairing succeeded.
    pub paired_at_unix_ms: u64,
    /// Unix-ms of the most recent successful re-auth credential prompt.
    /// On fresh pairing, equals `paired_at_unix_ms`.
    pub last_authenticated_at_unix_ms: u64,
    /// Immediate-effect revocation flag. `true` means daemon rejects any
    /// command from this pairing as `Revoked` and queues a Revoke push.
    pub revoked: bool,
    /// `true` while a Revoke push is queued and unacknowledged. Cleared
    /// when phone returns `RevokeAck` (at which point the daemon removes
    /// the pairing entry entirely).
    pub revoke_pending: bool,
}

impl PairingRecord {
    /// Build a fresh record from a successful core::crypto pairing.
    #[must_use]
    pub fn from_core(record: wake_my_pc_core::crypto::PairingRecord) -> Self {
        Self {
            phone_name: record.phone_name,
            client_spki: record.client_spki,
            paired_at_unix_ms: record.paired_at_unix_ms,
            last_authenticated_at_unix_ms: record.paired_at_unix_ms,
            revoked: false,
            revoke_pending: false,
        }
    }

    /// `true` if this pairing should currently be in the live PinSet
    /// served to the rustls listener.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.revoked
    }
}

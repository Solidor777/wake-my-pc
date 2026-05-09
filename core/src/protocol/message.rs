//! Wire message types. Postcard variant tags follow source order — see
//! PROTOCOL.md §3 for the canonical tag table. Reordering variants is a wire
//! break; the KAT in `core/tests/kat.rs` (M1 §10) locks this down.

use serde::{Deserialize, Serialize};

use super::error::Error;

/// 256-bit SHA-256 of an X.509 SubjectPublicKeyInfo (DER-encoded). Used as
/// the cryptographic identity of a paired peer (PROTOCOL.md §6).
///
/// Lives in `protocol` rather than `crypto` because it travels on the wire
/// inside [`DaemonFrame::Revoke`]; the `crypto` module re-exports this type
/// and provides the hashing constructor in `crypto::spki`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SpkiHash(pub [u8; 32]);

impl SpkiHash {
    /// Hex-encoded form for logs, QR fallback display, and KAT vectors.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// 5-state PC report (PRINCIPLES.md §3, PROTOCOL.md §3 Daemon→Client table).
/// Ordered for postcard tag stability — DO NOT reorder without bumping
/// protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PcState {
    /// PC is fully off (no power; can only be reached via WoL magic packet).
    Off,
    /// PC is in a sleep/suspend state. Reachable via WoL.
    Sleeping,
    /// PC is on with no user logged in (login screen).
    OnLoggedOut,
    /// PC is on with a user logged in but the session is locked.
    OnLocked,
    /// PC is on with a user logged in and the session is active.
    OnLoggedIn,
}

/// User-selectable re-auth window. Default 7 days per PRINCIPLES.md §3.
/// Off disables re-auth entirely on whichever side configures it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReauthInterval {
    /// Re-auth disabled — daemon never enters `NeedsReauth`.
    Off,
    /// One day.
    OneDay,
    /// Seven days (default).
    SevenDays,
    /// Thirty days.
    ThirtyDays,
}

/// On-wire error code (PROTOCOL.md §7). Distinct from the library
/// [`Error`](super::error::Error) — this enum is what travels in
/// [`DaemonFrame::Error`] and contains no detail per Principle 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolError {
    /// Client SPKI is not pinned in the daemon's pairing set. Connection closes.
    NotPaired,
    /// Pairing is flagged revoked. Connection closes.
    Revoked,
    /// Daemon is in `NeedsReauth`; only `ReauthStatus`/`RevokeAck` succeed.
    /// Connection stays open.
    RequiresReauth,
    /// Envelope version unsupported. Connection closes.
    VersionMismatch,
    /// Frame failed length/encoding/bounds checks. Connection closes.
    MalformedFrame,
    /// Strict-monotonic nonce check failed. Connection closes.
    NonceReplay,
    /// Known version, unknown message tag. Connection stays open.
    Unsupported,
    /// Daemon-side internal failure. No detail leaked. Connection stays open.
    Internal,
}

/// Client → daemon messages. Variant order = postcard tag (PROTOCOL.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFrame {
    /// First-contact pairing message. Sent only inside the daemon's pairing
    /// window (PROTOCOL.md §8). `phone_name` is the user-visible label
    /// shown in `daemon-cli list-paired`; capped to 64 bytes by the daemon
    /// at intake to bound storage. `pairing_code` is the canonical 6-digit
    /// value (`0..1_000_000`); values outside that range are rejected at
    /// the state machine and count against the per-window attempt budget
    /// (`MAX_PAIRING_ATTEMPTS`).
    Pair {
        /// User-visible label for this pairing.
        phone_name: String,
        /// One-time pairing PIN, 6-digit (`0..1_000_000`).
        pairing_code: u32,
    },
    /// Request: put PC to sleep.
    Sleep,
    /// Request: lock the active session. v1 is one-way (no remote unlock).
    Lock,
    /// Request: shut down PC.
    PowerOff,
    /// Request: send a fresh `StateReport`. Idempotent.
    StateProbe,
    /// Query the daemon's re-auth window.
    ReauthStatus,
    /// Set the daemon's `pc_reauth_interval_days`. May trigger an immediate
    /// credential prompt on the daemon if the new interval expires now.
    ReauthConfig {
        /// Desired re-auth interval.
        interval: ReauthInterval,
    },
    /// Acknowledge a `Revoke` push (PROTOCOL.md §3, §5). Phone has wiped
    /// the pairing on its side; daemon may now drop the pairing record.
    RevokeAck,
}

/// Daemon → client messages. Variant order = postcard tag (PROTOCOL.md §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonFrame {
    /// Generic positive ack for state-changing requests. `request_nonce`
    /// echoes the offending frame's nonce so the client can correlate.
    Ack {
        /// Nonce of the request being acknowledged.
        request_nonce: u64,
    },
    /// 5-state report. Sent unsolicited on transition AND in response to
    /// `StateProbe`.
    StateReport(PcState),
    /// Daemon-initiated revocation of this pairing. Phone verifies
    /// `daemon_spki` matches a known pin then wipes the pairing.
    /// `revoke_nonce` is independent of the per-direction stream nonce —
    /// see PROTOCOL.md §5.
    Revoke {
        /// Hash of the daemon's SPKI; phone uses this to confirm the
        /// Revoke originated from the right daemon.
        daemon_spki: SpkiHash,
        /// Single-use revoke nonce.
        revoke_nonce: u64,
    },
    /// Typed error response. `request_nonce = 0` means "uncorrelatable".
    Error {
        /// Nonce of the request that triggered the error, or `0`.
        request_nonce: u64,
        /// Wire error code.
        code: ProtocolError,
    },
    /// Response to `ReauthStatus`.
    ReauthInfo {
        /// Last successful credential prompt, unix milliseconds.
        last_authenticated_at_unix_ms: u64,
        /// Configured interval.
        interval: ReauthInterval,
        /// Computed expiry, unix milliseconds. `interval = Off` ⇒ `u64::MAX`.
        expires_at_unix_ms: u64,
    },
}

/// Encode a `ClientFrame` payload for embedding in an [`super::Envelope`].
/// Use [`super::encode_envelope`] to wrap the result in the framed wire form.
pub fn encode_client_frame(frame: &ClientFrame) -> Result<Vec<u8>, Error> {
    postcard::to_allocvec(frame).map_err(Error::Encoding)
}

/// Encode a `DaemonFrame` payload. See [`encode_client_frame`].
pub fn encode_daemon_frame(frame: &DaemonFrame) -> Result<Vec<u8>, Error> {
    postcard::to_allocvec(frame).map_err(Error::Encoding)
}

/// Decode a payload as a `ClientFrame`. Returns `TrailingBytes` if postcard
/// decodes a frame but extra bytes remain — sign of a length-lying sender.
pub fn decode_client_frame(payload: &[u8]) -> Result<ClientFrame, Error> {
    decode_payload(payload)
}

/// Decode a payload as a `DaemonFrame`. See [`decode_client_frame`].
pub fn decode_daemon_frame(payload: &[u8]) -> Result<DaemonFrame, Error> {
    decode_payload(payload)
}

fn decode_payload<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, Error> {
    let (frame, rest) = postcard::take_from_bytes::<T>(payload).map_err(Error::Decoding)?;
    if !rest.is_empty() {
        return Err(Error::TrailingBytes {
            trailing: rest.len(),
        });
    }
    Ok(frame)
}

//! Wire protocol — message types and length-prefixed envelope. Pure data,
//! serde, postcard; no transport. PROTOCOL.md is the canonical spec; this
//! module is the implementation. **Spec leads, code follows** — any wire
//! change updates `docs/PROTOCOL.md` first.
//!
//! Layering recap (PROTOCOL.md §1): TLS handles handshake/AEAD/KDF; this layer
//! adds a versioned envelope with a strict-monotonic per-direction nonce, and
//! postcard-encoded message enums. Wake-on-LAN is NOT a protocol message
//! (sleeping PC has no daemon); it lives in a future `core::wol` (M3).
//!
//! Postcard variant tags follow source order — the enum order in
//! [`message`](self::message) MUST match PROTOCOL.md §3 exactly. The KAT suite
//! locks this in; any reordering will fail tests.

mod envelope;
mod error;
mod message;

pub use envelope::{
    DecodeOutcome, Envelope, MAX_FRAME_LEN, MIN_FRAME_LEN, PROTOCOL_VERSION, decode_envelope,
    encode_envelope,
};
pub use error::Error;
pub use message::{
    ClientFrame, DaemonFrame, PcState, ProtocolError, ReauthInterval, SpkiHash,
    decode_client_frame, decode_daemon_frame, encode_client_frame, encode_daemon_frame,
};

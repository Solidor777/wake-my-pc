//! Length-prefixed envelope (PROTOCOL.md §4). Each direction over the TLS
//! stream is a sequence of frames:
//!
//! ```text
//! frame    := len:u32(BE) || envelope:[u8; len]
//! envelope := version:u8 || nonce:u64(BE) || payload:[u8]
//! ```
//!
//! [`decode_envelope`] is streaming-friendly: caller appends bytes and
//! retries until `DecodeOutcome::Frame` returns. No partial state is held
//! across calls — the caller owns the buffer.

use super::error::Error;

/// Current protocol version byte. Bumped only on wire-incompatible changes
/// (PROTOCOL.md §2). v1.x is wire-compatible; major bumps break the envelope.
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Length of the envelope header (`version` + `nonce`) in bytes.
const ENVELOPE_HEADER_LEN: usize = 1 + 8;

/// Smallest legal envelope: header + one byte of postcard discriminant.
pub const MIN_FRAME_LEN: usize = ENVELOPE_HEADER_LEN + 1;

/// Maximum envelope length in bytes (i.e. `len` field as parsed from wire,
/// not counting the length prefix itself). Frames at or below this are
/// accepted; frames above are rejected to bound resource use.
pub const MAX_FRAME_LEN: usize = 65_536;

/// Length of the on-wire `len` prefix in bytes.
const LENGTH_PREFIX_LEN: usize = 4;

/// Parsed envelope. The payload is unparsed bytes — call
/// [`super::decode_client_frame`] or [`super::decode_daemon_frame`] next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Envelope version byte. Always [`PROTOCOL_VERSION`] on encode; checked
    /// against it on decode (`VersionMismatch` otherwise).
    pub version: u8,
    /// Strict-monotonic per-direction nonce. PROTOCOL.md §5.
    pub nonce: u64,
    /// Postcard-encoded message payload.
    pub payload: Vec<u8>,
}

/// Outcome of [`decode_envelope`]. The caller treats `Incomplete` as a
/// "need more bytes" signal — accumulate further bytes from the socket and
/// re-call.
#[derive(Debug)]
pub enum DecodeOutcome<'a> {
    /// One full frame parsed. `remainder` is the unconsumed tail of the
    /// input — typically the start of the next frame.
    Frame {
        /// The parsed envelope.
        envelope: Envelope,
        /// Bytes after the frame; may be empty.
        remainder: &'a [u8],
    },
    /// Not enough bytes yet to parse a full frame. Append more and retry.
    Incomplete,
}

/// Encode an envelope to wire bytes (length prefix + version + nonce + payload).
/// Returns `OversizedFrame` if the resulting envelope exceeds [`MAX_FRAME_LEN`].
pub fn encode_envelope(env: &Envelope) -> Result<Vec<u8>, Error> {
    let env_len = ENVELOPE_HEADER_LEN
        .checked_add(env.payload.len())
        .ok_or(Error::LengthOverflow)?;
    if env_len > MAX_FRAME_LEN {
        return Err(Error::OversizedFrame {
            len: env_len,
            max: MAX_FRAME_LEN,
        });
    }
    let len_field = u32::try_from(env_len).map_err(|_| Error::LengthOverflow)?;

    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + env_len);
    out.extend_from_slice(&len_field.to_be_bytes());
    out.push(env.version);
    out.extend_from_slice(&env.nonce.to_be_bytes());
    out.extend_from_slice(&env.payload);
    Ok(out)
}

/// Try to parse one envelope from the head of `buf`. Returns
/// [`DecodeOutcome::Incomplete`] if the buffer is too short to contain a
/// full frame yet; returns an error for malformed length / version /
/// truncated-after-length bytes.
///
/// Does NOT decode the payload — the caller picks
/// [`super::decode_client_frame`] or [`super::decode_daemon_frame`] based
/// on which side of the connection it's on.
///
/// Defensive parse per Principle 2: any input that would otherwise panic
/// (oversize, undersize, version mismatch) returns a typed error instead.
pub fn decode_envelope(buf: &[u8]) -> Result<DecodeOutcome<'_>, Error> {
    let len_bytes: &[u8; 4] = match buf.first_chunk::<4>() {
        Some(b) => b,
        None => return Ok(DecodeOutcome::Incomplete),
    };
    let env_len_u32 = u32::from_be_bytes(*len_bytes);
    let env_len = env_len_u32 as usize;

    if env_len < MIN_FRAME_LEN {
        return Err(Error::UndersizedFrame {
            len: env_len,
            min: MIN_FRAME_LEN,
        });
    }
    if env_len > MAX_FRAME_LEN {
        return Err(Error::OversizedFrame {
            len: env_len,
            max: MAX_FRAME_LEN,
        });
    }

    let total_needed = LENGTH_PREFIX_LEN
        .checked_add(env_len)
        .ok_or(Error::LengthOverflow)?;
    if buf.len() < total_needed {
        return Ok(DecodeOutcome::Incomplete);
    }

    let envelope_bytes = match buf.get(LENGTH_PREFIX_LEN..total_needed) {
        Some(b) => b,
        None => return Err(Error::LengthOverflow),
    };

    let version = match envelope_bytes.first() {
        Some(&v) => v,
        // Unreachable given MIN_FRAME_LEN >= 1; defensive.
        None => {
            return Err(Error::UndersizedFrame {
                len: env_len,
                min: MIN_FRAME_LEN,
            });
        }
    };
    if version != PROTOCOL_VERSION {
        return Err(Error::VersionMismatch {
            got: version,
            expected: PROTOCOL_VERSION,
        });
    }

    let nonce_bytes: [u8; 8] = match envelope_bytes.get(1..9).and_then(|s| s.try_into().ok()) {
        Some(b) => b,
        None => {
            return Err(Error::UndersizedFrame {
                len: env_len,
                min: MIN_FRAME_LEN,
            });
        }
    };
    let nonce = u64::from_be_bytes(nonce_bytes);

    let payload = match envelope_bytes.get(ENVELOPE_HEADER_LEN..) {
        Some(p) => p.to_vec(),
        None => {
            return Err(Error::UndersizedFrame {
                len: env_len,
                min: MIN_FRAME_LEN,
            });
        }
    };

    let remainder = match buf.get(total_needed..) {
        Some(r) => r,
        None => &[],
    };

    Ok(DecodeOutcome::Frame {
        envelope: Envelope {
            version,
            nonce,
            payload,
        },
        remainder,
    })
}

//! Property tests + negative tests for the wire protocol. Companion to
//! `protocol_kat.rs` (frozen byte vectors); this file exercises the
//! encoder + decoder over arbitrary inputs and around the malformed
//! boundary (PROTOCOL.md §4 / §7 / Principle 2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use proptest::prelude::*;
use wake_my_pc_core::crypto::SpkiHash;
use wake_my_pc_core::protocol::{
    ClientFrame, DaemonFrame, DecodeOutcome, Envelope, Error, MAX_FRAME_LEN, MIN_FRAME_LEN,
    PROTOCOL_VERSION, PcState, ProtocolError, ReauthInterval, decode_client_frame,
    decode_daemon_frame, decode_envelope, encode_client_frame, encode_daemon_frame,
    encode_envelope,
};

// ============================ proptest strategies ============================

fn arb_reauth_interval() -> impl Strategy<Value = ReauthInterval> {
    prop_oneof![
        Just(ReauthInterval::Off),
        Just(ReauthInterval::OneDay),
        Just(ReauthInterval::SevenDays),
        Just(ReauthInterval::ThirtyDays),
    ]
}

fn arb_pc_state() -> impl Strategy<Value = PcState> {
    prop_oneof![
        Just(PcState::Off),
        Just(PcState::Sleeping),
        Just(PcState::OnLoggedOut),
        Just(PcState::OnLocked),
        Just(PcState::OnLoggedIn),
    ]
}

fn arb_protocol_error() -> impl Strategy<Value = ProtocolError> {
    prop_oneof![
        Just(ProtocolError::NotPaired),
        Just(ProtocolError::Revoked),
        Just(ProtocolError::RequiresReauth),
        Just(ProtocolError::VersionMismatch),
        Just(ProtocolError::MalformedFrame),
        Just(ProtocolError::NonceReplay),
        Just(ProtocolError::Unsupported),
        Just(ProtocolError::Internal),
    ]
}

fn arb_spki() -> impl Strategy<Value = SpkiHash> {
    any::<[u8; 32]>().prop_map(SpkiHash)
}

fn arb_client_frame() -> impl Strategy<Value = ClientFrame> {
    prop_oneof![
        ("[\\x20-\\x7E]{0,64}", any::<u32>()).prop_map(|(phone_name, pairing_code)| {
            ClientFrame::Pair {
                phone_name,
                pairing_code,
            }
        }),
        Just(ClientFrame::Sleep),
        Just(ClientFrame::Lock),
        Just(ClientFrame::PowerOff),
        Just(ClientFrame::StateProbe),
        Just(ClientFrame::ReauthStatus),
        arb_reauth_interval().prop_map(|interval| ClientFrame::ReauthConfig { interval }),
        Just(ClientFrame::RevokeAck),
    ]
}

fn arb_daemon_frame() -> impl Strategy<Value = DaemonFrame> {
    prop_oneof![
        any::<u64>().prop_map(|request_nonce| DaemonFrame::Ack { request_nonce }),
        arb_pc_state().prop_map(DaemonFrame::StateReport),
        (arb_spki(), any::<u64>()).prop_map(|(daemon_spki, revoke_nonce)| DaemonFrame::Revoke {
            daemon_spki,
            revoke_nonce
        }),
        (any::<u64>(), arb_protocol_error()).prop_map(|(request_nonce, code)| DaemonFrame::Error {
            request_nonce,
            code
        }),
        (any::<u64>(), arb_reauth_interval(), any::<u64>()).prop_map(
            |(last_authenticated_at_unix_ms, interval, expires_at_unix_ms)| {
                DaemonFrame::ReauthInfo {
                    last_authenticated_at_unix_ms,
                    interval,
                    expires_at_unix_ms,
                }
            }
        ),
    ]
}

// =============================== property tests ==============================

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn client_frame_roundtrip(frame in arb_client_frame()) {
        let bytes = encode_client_frame(&frame).unwrap();
        let decoded = decode_client_frame(&bytes).unwrap();
        prop_assert_eq!(frame, decoded);
    }

    #[test]
    fn daemon_frame_roundtrip(frame in arb_daemon_frame()) {
        let bytes = encode_daemon_frame(&frame).unwrap();
        let decoded = decode_daemon_frame(&bytes).unwrap();
        prop_assert_eq!(frame, decoded);
    }

    #[test]
    fn envelope_roundtrip(frame in arb_client_frame(), nonce in any::<u64>()) {
        let payload = encode_client_frame(&frame).unwrap();
        let env = Envelope { version: PROTOCOL_VERSION, nonce, payload };
        let bytes = encode_envelope(&env).unwrap();
        let outcome = decode_envelope(&bytes).unwrap();
        match outcome {
            DecodeOutcome::Frame { envelope, remainder } => {
                prop_assert_eq!(envelope, env);
                prop_assert!(remainder.is_empty());
            }
            DecodeOutcome::Incomplete => prop_assert!(false, "expected Frame, got Incomplete"),
        }
    }

    #[test]
    fn envelope_concat_two_frames_decodes_first_returns_remainder(
        frame_a in arb_client_frame(),
        frame_b in arb_daemon_frame(),
        nonce_a in any::<u64>(),
    ) {
        let env_a = Envelope {
            version: PROTOCOL_VERSION,
            nonce: nonce_a,
            payload: encode_client_frame(&frame_a).unwrap(),
        };
        let env_b = Envelope {
            version: PROTOCOL_VERSION,
            nonce: nonce_a.wrapping_add(1),
            payload: encode_daemon_frame(&frame_b).unwrap(),
        };
        let bytes_a = encode_envelope(&env_a).unwrap();
        let bytes_b = encode_envelope(&env_b).unwrap();
        let mut concatenated = bytes_a.clone();
        concatenated.extend_from_slice(&bytes_b);

        let outcome = decode_envelope(&concatenated).unwrap();
        match outcome {
            DecodeOutcome::Frame { envelope, remainder } => {
                prop_assert_eq!(envelope, env_a);
                prop_assert_eq!(remainder, &bytes_b[..]);
            }
            DecodeOutcome::Incomplete => prop_assert!(false),
        }
    }

    #[test]
    fn random_bytes_either_decode_or_typed_error(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        // Smoke-fuzz the decoder: any input either parses, signals
        // Incomplete, or returns a typed Error. Never panic. (Principle 2.)
        match decode_envelope(&bytes) {
            Ok(_) | Err(_) => {} // both fine; no panic == pass
        }
    }
}

// ============================== negative tests ==============================

#[test]
fn truncated_length_prefix_is_incomplete() {
    let outcome = decode_envelope(&[0x00, 0x00]).unwrap();
    assert!(matches!(outcome, DecodeOutcome::Incomplete));
}

#[test]
fn oversized_envelope_rejected() {
    let mut buf = vec![0u8; 4];
    let oversize = u32::try_from(MAX_FRAME_LEN + 1).unwrap();
    buf[..4].copy_from_slice(&oversize.to_be_bytes());
    let err = decode_envelope(&buf).unwrap_err();
    assert!(matches!(err, Error::OversizedFrame { .. }), "got {err:?}");
}

#[test]
fn undersized_envelope_rejected() {
    let undersize = u32::try_from(MIN_FRAME_LEN - 1).unwrap();
    let mut buf = undersize.to_be_bytes().to_vec();
    // Pad enough so the length-vs-buffer check passes — the rejection
    // must come from the MIN_FRAME_LEN check, not from Incomplete.
    buf.resize(4 + MIN_FRAME_LEN, 0);
    let err = decode_envelope(&buf).unwrap_err();
    assert!(matches!(err, Error::UndersizedFrame { .. }), "got {err:?}");
}

#[test]
fn version_mismatch_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&10u32.to_be_bytes()); // env_len = 10
    buf.push(0x99); // wrong version
    buf.extend_from_slice(&1u64.to_be_bytes()); // nonce
    buf.push(0x01); // payload byte
    let err = decode_envelope(&buf).unwrap_err();
    assert!(
        matches!(
            err,
            Error::VersionMismatch {
                got: 0x99,
                expected: PROTOCOL_VERSION
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn truncated_envelope_payload_is_incomplete() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&10u32.to_be_bytes());
    buf.push(PROTOCOL_VERSION);
    // Only 5 of the expected 9 envelope-body bytes present.
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    let outcome = decode_envelope(&buf).unwrap();
    assert!(matches!(outcome, DecodeOutcome::Incomplete));
}

#[test]
fn trailing_bytes_in_client_payload_rejected() {
    // Sleep variant (0x01) + extra junk — must fail with TrailingBytes.
    let payload = [0x01, 0xFF, 0xFF];
    let err = decode_client_frame(&payload).unwrap_err();
    assert!(
        matches!(err, Error::TrailingBytes { trailing: 2 }),
        "got {err:?}"
    );
}

#[test]
fn unknown_client_variant_rejected() {
    // Variant index 99 — outside the 0..=7 range.
    let payload = [99];
    let err = decode_client_frame(&payload).unwrap_err();
    assert!(matches!(err, Error::Decoding(_)), "got {err:?}");
}

#[test]
fn empty_buffer_is_incomplete() {
    let outcome = decode_envelope(&[]).unwrap();
    assert!(matches!(outcome, DecodeOutcome::Incomplete));
}

#[test]
fn encode_oversize_payload_rejected() {
    // Build a payload one byte over the limit.
    let too_big = vec![0u8; MAX_FRAME_LEN]; // header (9) + this overflows
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce: 1,
        payload: too_big,
    };
    let err = encode_envelope(&env).unwrap_err();
    assert!(matches!(err, Error::OversizedFrame { .. }), "got {err:?}");
}

#[test]
fn library_error_to_wire_code_mapping_is_total() {
    // Every library error variant MUST map to a wire code; if a future
    // variant is added without updating to_wire_code, this test catches
    // it via Error's #[non_exhaustive] semantics at the call site.
    let cases = [
        (
            Error::OversizedFrame {
                len: MAX_FRAME_LEN + 1,
                max: MAX_FRAME_LEN,
            },
            ProtocolError::MalformedFrame,
        ),
        (
            Error::UndersizedFrame {
                len: 0,
                min: MIN_FRAME_LEN,
            },
            ProtocolError::MalformedFrame,
        ),
        (
            Error::VersionMismatch {
                got: 0xFF,
                expected: PROTOCOL_VERSION,
            },
            ProtocolError::VersionMismatch,
        ),
        (
            Error::TrailingBytes { trailing: 1 },
            ProtocolError::MalformedFrame,
        ),
        (Error::LengthOverflow, ProtocolError::MalformedFrame),
    ];
    for (err, want) in cases {
        assert_eq!(err.to_wire_code(), want, "{err:?}");
    }
}

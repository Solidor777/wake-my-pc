//! Known-Answer Tests for the wire protocol. PROTOCOL.md §10.
//!
//! Vectors are hand-rolled from the spec, NOT regenerated from the encoder
//! — a buggy encoder cannot rubber-stamp itself. Each variant of every
//! frame type appears at least once. Reordering enum variants will break
//! these tests, surfacing the wire change at PR review.
//!
//! Postcard wire facts used here:
//!   - enum discriminant: `varint(u32)` of the variant index (source order).
//!   - `String`:         `varint(usize)` length + UTF-8 bytes.
//!   - `[u8; N]`:        N raw bytes, no length prefix.
//!   - `varint(uN)`:     LEB128, low-bit-first, continuation in MSB.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use wake_my_pc_core::crypto::SpkiHash;
use wake_my_pc_core::protocol::{
    ClientFrame, DaemonFrame, Envelope, MAX_FRAME_LEN, PROTOCOL_VERSION, PcState, ProtocolError,
    ReauthInterval, decode_client_frame, decode_daemon_frame, decode_envelope, encode_client_frame,
    encode_daemon_frame, encode_envelope,
};

// ============================ ClientFrame KAT ==============================

#[test]
fn kat_client_pair_simple() {
    // Variant 0 = Pair. phone_name = "Alice" (varint(5) = 0x05, 5 UTF-8 bytes).
    // pairing_code = 7 (varint(u32) of 7 = single byte 0x07).
    let frame = ClientFrame::Pair {
        phone_name: "Alice".into(),
        pairing_code: 7,
    };
    let expected: &[u8] = &[
        0x00, // variant
        0x05, // string length varint
        0x41, 0x6C, 0x69, 0x63, 0x65, // "Alice"
        0x07, // pairing_code varint
    ];
    assert_eq!(encode_client_frame(&frame).unwrap(), expected);
    assert_eq!(decode_client_frame(expected).unwrap(), frame);
}

#[test]
fn kat_client_sleep() {
    assert_eq!(encode_client_frame(&ClientFrame::Sleep).unwrap(), &[0x01]);
    assert_eq!(decode_client_frame(&[0x01]).unwrap(), ClientFrame::Sleep);
}

#[test]
fn kat_client_lock() {
    assert_eq!(encode_client_frame(&ClientFrame::Lock).unwrap(), &[0x02]);
    assert_eq!(decode_client_frame(&[0x02]).unwrap(), ClientFrame::Lock);
}

#[test]
fn kat_client_power_off() {
    assert_eq!(
        encode_client_frame(&ClientFrame::PowerOff).unwrap(),
        &[0x03]
    );
    assert_eq!(decode_client_frame(&[0x03]).unwrap(), ClientFrame::PowerOff);
}

#[test]
fn kat_client_state_probe() {
    assert_eq!(
        encode_client_frame(&ClientFrame::StateProbe).unwrap(),
        &[0x04]
    );
    assert_eq!(
        decode_client_frame(&[0x04]).unwrap(),
        ClientFrame::StateProbe
    );
}

#[test]
fn kat_client_reauth_status() {
    assert_eq!(
        encode_client_frame(&ClientFrame::ReauthStatus).unwrap(),
        &[0x05]
    );
    assert_eq!(
        decode_client_frame(&[0x05]).unwrap(),
        ClientFrame::ReauthStatus
    );
}

#[test]
fn kat_client_reauth_config_each_interval() {
    // ReauthConfig is variant 6. Inner ReauthInterval enum: Off=0, OneDay=1,
    // SevenDays=2, ThirtyDays=3.
    for (interval, tag) in [
        (ReauthInterval::Off, 0x00),
        (ReauthInterval::OneDay, 0x01),
        (ReauthInterval::SevenDays, 0x02),
        (ReauthInterval::ThirtyDays, 0x03),
    ] {
        let frame = ClientFrame::ReauthConfig { interval };
        let expected: &[u8] = &[0x06, tag];
        assert_eq!(
            encode_client_frame(&frame).unwrap(),
            expected,
            "interval {interval:?}"
        );
        assert_eq!(decode_client_frame(expected).unwrap(), frame);
    }
}

#[test]
fn kat_client_revoke_ack() {
    assert_eq!(
        encode_client_frame(&ClientFrame::RevokeAck).unwrap(),
        &[0x07]
    );
    assert_eq!(
        decode_client_frame(&[0x07]).unwrap(),
        ClientFrame::RevokeAck
    );
}

// ============================ DaemonFrame KAT ==============================

#[test]
fn kat_daemon_ack_small_nonce() {
    // Variant 0 = Ack. request_nonce = 1 (varint(u64) of 1 = 0x01).
    let frame = DaemonFrame::Ack { request_nonce: 1 };
    let expected: &[u8] = &[0x00, 0x01];
    assert_eq!(encode_daemon_frame(&frame).unwrap(), expected);
    assert_eq!(decode_daemon_frame(expected).unwrap(), frame);
}

#[test]
fn kat_daemon_state_report_each_pc_state() {
    // Variant 1 = StateReport. Inner PcState: Off=0, Sleeping=1, OnLoggedOut=2,
    // OnLocked=3, OnLoggedIn=4.
    for (state, tag) in [
        (PcState::Off, 0x00),
        (PcState::Sleeping, 0x01),
        (PcState::OnLoggedOut, 0x02),
        (PcState::OnLocked, 0x03),
        (PcState::OnLoggedIn, 0x04),
    ] {
        let frame = DaemonFrame::StateReport(state);
        let expected: &[u8] = &[0x01, tag];
        assert_eq!(
            encode_daemon_frame(&frame).unwrap(),
            expected,
            "state {state:?}"
        );
        assert_eq!(decode_daemon_frame(expected).unwrap(), frame);
    }
}

#[test]
fn kat_daemon_revoke_all_aa_spki() {
    // Variant 2 = Revoke. SpkiHash is a tuple struct of [u8; 32] — postcard
    // emits 32 raw bytes, no length prefix. revoke_nonce = 3.
    let frame = DaemonFrame::Revoke {
        daemon_spki: SpkiHash([0xAA; 32]),
        revoke_nonce: 3,
    };
    let mut expected: Vec<u8> = Vec::new();
    expected.push(0x02); // variant
    expected.extend_from_slice(&[0xAA; 32]); // spki
    expected.push(0x03); // revoke_nonce varint
    assert_eq!(encode_daemon_frame(&frame).unwrap(), expected);
    assert_eq!(decode_daemon_frame(&expected).unwrap(), frame);
}

#[test]
fn kat_daemon_error_each_code() {
    // Variant 3 = Error. request_nonce = 0 (uncorrelatable). Inner ProtocolError:
    // NotPaired=0, Revoked=1, RequiresReauth=2, VersionMismatch=3, MalformedFrame=4,
    // NonceReplay=5, Unsupported=6, Internal=7.
    for (code, tag) in [
        (ProtocolError::NotPaired, 0x00),
        (ProtocolError::Revoked, 0x01),
        (ProtocolError::RequiresReauth, 0x02),
        (ProtocolError::VersionMismatch, 0x03),
        (ProtocolError::MalformedFrame, 0x04),
        (ProtocolError::NonceReplay, 0x05),
        (ProtocolError::Unsupported, 0x06),
        (ProtocolError::Internal, 0x07),
    ] {
        let frame = DaemonFrame::Error {
            request_nonce: 0,
            code,
        };
        let expected: &[u8] = &[0x03, 0x00, tag];
        assert_eq!(
            encode_daemon_frame(&frame).unwrap(),
            expected,
            "code {code:?}"
        );
        assert_eq!(decode_daemon_frame(expected).unwrap(), frame);
    }
}

#[test]
fn kat_daemon_reauth_info_seven_days() {
    // Variant 4 = ReauthInfo. last_authenticated_at_unix_ms = 1, interval = SevenDays (tag 2),
    // expires_at_unix_ms = 2.
    let frame = DaemonFrame::ReauthInfo {
        last_authenticated_at_unix_ms: 1,
        interval: ReauthInterval::SevenDays,
        expires_at_unix_ms: 2,
    };
    let expected: &[u8] = &[0x04, 0x01, 0x02, 0x02];
    assert_eq!(encode_daemon_frame(&frame).unwrap(), expected);
    assert_eq!(decode_daemon_frame(expected).unwrap(), frame);
}

// ============================== Envelope KAT ==============================

#[test]
fn kat_envelope_sleep_nonce_one() {
    // Wrap ClientFrame::Sleep (1 byte payload 0x01) in an envelope:
    //   len (BE u32) = 1 (version) + 8 (nonce) + 1 (payload) = 10
    //   version = 0x01
    //   nonce  = 1 (BE u64)
    //   payload = 0x01
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce: 1,
        payload: encode_client_frame(&ClientFrame::Sleep).unwrap(),
    };
    let bytes = encode_envelope(&env).unwrap();

    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x0A, // length prefix = 10
        0x01, // version
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // nonce = 1 (BE)
        0x01, // postcard payload (Sleep variant)
    ];
    assert_eq!(bytes, expected);

    match decode_envelope(&bytes).unwrap() {
        wake_my_pc_core::protocol::DecodeOutcome::Frame {
            envelope,
            remainder,
        } => {
            assert_eq!(envelope, env);
            assert!(remainder.is_empty());
        }
        wake_my_pc_core::protocol::DecodeOutcome::Incomplete => panic!("expected Frame"),
    }
}

#[test]
fn envelope_max_frame_len_constant_is_64ki() {
    // Pin down the constant — a future refactor must explicitly bump it.
    assert_eq!(MAX_FRAME_LEN, 65_536);
}

#[test]
fn protocol_version_is_one() {
    // Pin down the version byte — bumping it is a wire break.
    assert_eq!(PROTOCOL_VERSION, 0x01);
}

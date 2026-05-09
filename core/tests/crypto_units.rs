//! Unit-level crypto tests: pin verifier, nonce counter, pairing handshake.
//! TLS handshake-level tests live in `crypto_tls.rs` (slower; full rustls).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use wake_my_pc_core::crypto::{
    DeviceIdentity, MAX_PAIRING_ATTEMPTS, NonceReceiver, NonceSender, PAIRING_WINDOW_DEFAULT_MS,
    PairingHandshake, PairingRecord, PairingRejection, PairingState, PairingTransition, PinSet,
    PinnedClientVerifier, PinnedServerVerifier, SpkiHash, compute_spki_hash, extract_spki_hash,
};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// =============================== SPKI tests ================================

#[test]
fn compute_spki_hash_is_sha256_of_input() {
    // Hand-rolled fact: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924
    //                                    27ae41e4649b934ca495991b7852b855
    let h = compute_spki_hash(b"");
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(h.0.as_slice(), expected.as_slice());
}

#[test]
fn extract_spki_hash_matches_device_identity_cache() {
    // Round-trip: a fresh DeviceIdentity caches its SPKI hash; extracting it
    // from the cert DER must produce the same value.
    let id = DeviceIdentity::generate().unwrap();
    let recomputed = extract_spki_hash(id.cert_der()).unwrap();
    assert_eq!(recomputed, id.spki_hash());
}

#[test]
fn extract_spki_hash_rejects_garbage() {
    let err = extract_spki_hash(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap_err();
    assert!(
        format!("{err:?}").to_lowercase().contains("x509"),
        "got {err:?}"
    );
}

#[test]
fn distinct_devices_get_distinct_pins() {
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    assert_ne!(a.spki_hash(), b.spki_hash());
}

#[test]
fn device_identity_roundtrips_through_bytes() {
    let id = DeviceIdentity::generate().unwrap();
    let restored = DeviceIdentity::from_bytes(&id.to_bytes()).unwrap();
    assert_eq!(id.spki_hash(), restored.spki_hash());
    assert_eq!(id.cert_der(), restored.cert_der());
    assert_eq!(id.key_pkcs8_der(), restored.key_pkcs8_der());
}

#[test]
fn corrupted_cert_bytes_fail_to_load() {
    let id = DeviceIdentity::generate().unwrap();
    let mut corrupted = id.to_bytes();
    corrupted.cert_der[0] ^= 0xFF;
    let err = DeviceIdentity::from_bytes(&corrupted).unwrap_err();
    let msg = format!("{err:?}").to_lowercase();
    assert!(msg.contains("x509") || msg.contains("parse"), "got {err:?}");
}

// ========================== Pin verifier tests =============================

#[test]
fn pinned_server_verifier_accepts_pinned_cert() {
    let id = DeviceIdentity::generate().unwrap();
    let pinset = Arc::new(PinSet::with_pins([id.spki_hash()]));
    let verifier = PinnedServerVerifier::new(pinset, provider().as_ref());

    let cert = CertificateDer::from(id.cert_der().to_vec());
    let server_name = ServerName::try_from("anything.invalid").unwrap();
    let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], UnixTime::now());
    assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn pinned_server_verifier_rejects_unpinned_cert() {
    let pinned = DeviceIdentity::generate().unwrap();
    let imposter = DeviceIdentity::generate().unwrap();
    let pinset = Arc::new(PinSet::with_pins([pinned.spki_hash()]));
    let verifier = PinnedServerVerifier::new(pinset, provider().as_ref());

    let imposter_cert = CertificateDer::from(imposter.cert_der().to_vec());
    let server_name = ServerName::try_from("anything.invalid").unwrap();
    let result =
        verifier.verify_server_cert(&imposter_cert, &[], &server_name, &[], UnixTime::now());
    assert!(result.is_err());
}

#[test]
fn pinned_client_verifier_accepts_pinned_cert() {
    let id = DeviceIdentity::generate().unwrap();
    let pinset = Arc::new(PinSet::with_pins([id.spki_hash()]));
    let verifier = PinnedClientVerifier::pinned(pinset, provider().as_ref());

    let cert = CertificateDer::from(id.cert_der().to_vec());
    let result = verifier.verify_client_cert(&cert, &[], UnixTime::now());
    assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn pinned_client_verifier_rejects_unpinned_cert() {
    let pinned = DeviceIdentity::generate().unwrap();
    let imposter = DeviceIdentity::generate().unwrap();
    let pinset = Arc::new(PinSet::with_pins([pinned.spki_hash()]));
    let verifier = PinnedClientVerifier::pinned(pinset, provider().as_ref());

    let imposter_cert = CertificateDer::from(imposter.cert_der().to_vec());
    let result = verifier.verify_client_cert(&imposter_cert, &[], UnixTime::now());
    assert!(result.is_err());
}

#[test]
fn pairing_window_verifier_accepts_any_well_formed_cert() {
    // Pairing-window mode: ANY cert that parses as X.509 passes the rustls
    // gate. The protocol layer's pairing_code check is what gates pairing.
    let imposter = DeviceIdentity::generate().unwrap();
    let verifier = PinnedClientVerifier::pairing_window(provider().as_ref());

    let cert = CertificateDer::from(imposter.cert_der().to_vec());
    let result = verifier.verify_client_cert(&cert, &[], UnixTime::now());
    assert!(result.is_ok());
}

#[test]
fn pairing_window_verifier_still_rejects_malformed_cert() {
    let verifier = PinnedClientVerifier::pairing_window(provider().as_ref());
    let bogus = CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let result = verifier.verify_client_cert(&bogus, &[], UnixTime::now());
    assert!(result.is_err());
}

#[test]
fn pinset_membership_is_sorted_iter() {
    let a = SpkiHash([0x01; 32]);
    let b = SpkiHash([0x02; 32]);
    let c = SpkiHash([0x03; 32]);
    let pinset = PinSet::with_pins([c, a, b]);
    let collected: Vec<_> = pinset.iter().copied().collect();
    assert_eq!(collected, vec![a, b, c]);
    assert_eq!(pinset.len(), 3);
    assert!(!pinset.is_empty());
}

// ============================== Nonce tests ================================

#[test]
fn nonce_sender_starts_at_one() {
    let mut s = NonceSender::new();
    assert_eq!(s.last_issued(), 0);
    assert_eq!(s.issue(), Some(1));
    assert_eq!(s.issue(), Some(2));
    assert_eq!(s.last_issued(), 2);
}

#[test]
fn nonce_receiver_strict_monotonic() {
    let mut r = NonceReceiver::new();
    assert!(r.accept(1).is_ok());
    assert!(r.accept(2).is_ok());
    // Replay rejected.
    assert!(r.accept(2).is_err());
    // Backward rejected.
    assert!(r.accept(1).is_err());
    // Forward jump accepted.
    assert!(r.accept(100).is_ok());
    // Backward (even within prior accepted range) rejected.
    assert!(r.accept(50).is_err());
    assert_eq!(r.last_seen(), 100);
}

#[test]
fn nonce_receiver_zero_rejected() {
    let mut r = NonceReceiver::new();
    // 0 <= last_seen (0) — rejected. First valid frame's nonce must be >= 1.
    assert!(r.accept(0).is_err());
}

// ============================ Pairing tests ================================

#[test]
fn pairing_starts_from_idle() {
    let mut h = PairingHandshake::new();
    assert!(matches!(h.state(), PairingState::Idle));
    let t = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    assert!(matches!(t, PairingTransition::Started { .. }));
    assert!(matches!(h.state(), PairingState::Awaiting { .. }));
}

#[test]
fn pairing_start_when_already_awaiting_is_noop() {
    let mut h = PairingHandshake::new();
    h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    let t = h.start(1, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    assert!(matches!(t, PairingTransition::NoOp));
}

#[test]
fn pairing_accepts_correct_code() {
    let mut h = PairingHandshake::new();
    let started = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    let code = match started {
        PairingTransition::Started { code } => code,
        _ => panic!("expected Started"),
    };

    let spki = SpkiHash([0xAB; 32]);
    let result = h.accept_pair(100, code, "Phone".into(), spki);
    let record = match result {
        PairingTransition::Succeeded { record } => record,
        other => panic!("expected Succeeded, got {other:?}"),
    };
    assert_eq!(record.phone_name, "Phone");
    assert_eq!(record.client_spki, spki);
    assert_eq!(record.paired_at_unix_ms, 100);

    assert!(matches!(
        h.state(),
        PairingState::Paired { record: PairingRecord { phone_name, .. } } if phone_name == "Phone"
    ));
}

#[test]
fn pairing_rejects_wrong_code_window_stays_open() {
    let mut h = PairingHandshake::new();
    let started = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    let code = match started {
        PairingTransition::Started { code } => code,
        _ => panic!(),
    };
    let bad = code.wrapping_add(1);

    let result = h.accept_pair(100, bad, "Phone".into(), SpkiHash([0; 32]));
    assert!(matches!(
        result,
        PairingTransition::Rejected {
            reason: PairingRejection::WrongCode
        }
    ));
    assert!(matches!(h.state(), PairingState::Awaiting { .. }));
}

#[test]
fn pairing_rejects_pair_in_idle() {
    let mut h = PairingHandshake::new();
    let result = h.accept_pair(0, 12345, "Phone".into(), SpkiHash([0; 32]));
    assert!(matches!(
        result,
        PairingTransition::Rejected {
            reason: PairingRejection::NotInWindow
        }
    ));
}

#[test]
fn pairing_window_expires_via_tick() {
    let mut h = PairingHandshake::new();
    h.start(0, 1_000).unwrap();
    let early = h.tick(500);
    assert!(matches!(early, PairingTransition::NoOp));
    assert!(matches!(h.state(), PairingState::Awaiting { .. }));
    let late = h.tick(1_000);
    assert!(matches!(late, PairingTransition::Expired));
    assert!(matches!(h.state(), PairingState::Idle));
    // Second tick after expiry returns NoOp (already Idle).
    let again = h.tick(2_000);
    assert!(matches!(again, PairingTransition::NoOp));
}

#[test]
fn pairing_pair_after_expiry_rejected() {
    let mut h = PairingHandshake::new();
    let started = h.start(0, 1_000).unwrap();
    let code = match started {
        PairingTransition::Started { code } => code,
        _ => panic!(),
    };
    // Past expiry without explicit tick — accept_pair detects.
    let result = h.accept_pair(2_000, code, "Phone".into(), SpkiHash([0; 32]));
    assert!(matches!(
        result,
        PairingTransition::Rejected {
            reason: PairingRejection::Expired
        }
    ));
    assert!(matches!(h.state(), PairingState::Idle));
}

#[test]
fn pairing_too_many_wrong_codes_locks_window() {
    let mut h = PairingHandshake::new();
    let started = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    let code = match started {
        PairingTransition::Started { code } => code,
        _ => panic!(),
    };
    let bad = (code + 1) % 1_000_000;

    // First MAX-1 wrong attempts: window stays open.
    for i in 0..(MAX_PAIRING_ATTEMPTS - 1) {
        let result = h.accept_pair(100, bad, "Phone".into(), SpkiHash([0; 32]));
        assert!(
            matches!(
                result,
                PairingTransition::Rejected {
                    reason: PairingRejection::WrongCode
                }
            ),
            "attempt {i} unexpected: {result:?}"
        );
        assert!(matches!(h.state(), PairingState::Awaiting { .. }));
    }
    // Final attempt trips the bound.
    let result = h.accept_pair(100, bad, "Phone".into(), SpkiHash([0; 32]));
    assert!(
        matches!(
            result,
            PairingTransition::Rejected {
                reason: PairingRejection::TooManyAttempts
            }
        ),
        "got {result:?}"
    );
    assert!(matches!(h.state(), PairingState::Idle));
}

#[test]
fn pairing_correct_code_after_some_failures_still_succeeds() {
    let mut h = PairingHandshake::new();
    let started = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    let code = match started {
        PairingTransition::Started { code } => code,
        _ => panic!(),
    };
    let bad = (code + 1) % 1_000_000;

    // Burn 2 of MAX_PAIRING_ATTEMPTS failures (must stay below the cap).
    const { assert!(MAX_PAIRING_ATTEMPTS > 2) };
    for _ in 0..2 {
        h.accept_pair(50, bad, "Phone".into(), SpkiHash([0; 32]));
    }
    let ok = h.accept_pair(100, code, "Phone".into(), SpkiHash([0xAB; 32]));
    assert!(matches!(ok, PairingTransition::Succeeded { .. }));
}

#[test]
fn pairing_out_of_range_code_rejected_and_counted() {
    let mut h = PairingHandshake::new();
    h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();

    // Any value >= 1_000_000 is out of range; counts against budget.
    let result = h.accept_pair(50, 1_000_000, "Phone".into(), SpkiHash([0; 32]));
    assert!(
        matches!(
            result,
            PairingTransition::Rejected {
                reason: PairingRejection::OutOfRange
            }
        ),
        "got {result:?}"
    );
    // Window stays open after one out-of-range attempt.
    assert!(matches!(h.state(), PairingState::Awaiting { .. }));

    // Hammer until lockout (we already burned 1).
    for _ in 1..MAX_PAIRING_ATTEMPTS {
        h.accept_pair(50, u32::MAX, "Phone".into(), SpkiHash([0; 32]));
    }
    assert!(matches!(h.state(), PairingState::Idle));
}

#[test]
fn pairing_codes_are_in_valid_range() {
    // Generate many to confirm the rejection-sample path always yields
    // values in 0..1_000_000. (Fast — start() is pure CPU + getrandom.)
    for _ in 0..1024 {
        let mut h = PairingHandshake::new();
        let started = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
        match started {
            PairingTransition::Started { code } => {
                assert!(code < 1_000_000, "got out-of-range code {code}");
            }
            other => panic!("expected Started, got {other:?}"),
        }
    }
}

#[test]
fn pairing_reset_clears_paired_state() {
    let mut h = PairingHandshake::new();
    let started = h.start(0, PAIRING_WINDOW_DEFAULT_MS).unwrap();
    let code = match started {
        PairingTransition::Started { code } => code,
        _ => panic!(),
    };
    h.accept_pair(100, code, "Phone".into(), SpkiHash([0; 32]));
    assert!(matches!(h.state(), PairingState::Paired { .. }));
    h.reset();
    assert!(matches!(h.state(), PairingState::Idle));
}

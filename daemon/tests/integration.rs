//! End-to-end daemon tests.
//!
//! Strategy: bypass the interactive `pair` subcommand and bootstrap the
//! keystore directly with predefined pairings. Then spawn the listener
//! and connect with a `core::crypto`-built client config. This exercises
//! the full TLS + protocol path without the print-and-wait pairing loop.
//!
//! Tests use only non-destructive commands (StateProbe, ReauthStatus,
//! ReauthConfig, RevokeAck) so they don't actually sleep / lock the
//! host. Sleep / Lock / PowerOff dispatch tests need a mockable
//! `Handlers` trait — tracked in TODO.md as an M2 follow-up.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use wake_my_pc_core::crypto::{
    DeviceIdentity, NonceCounter, PinSet, SpkiHash, client_config_for_pinned_daemon,
};
use wake_my_pc_core::protocol::{
    ClientFrame, DaemonFrame, DecodeOutcome, Envelope, PROTOCOL_VERSION, PcState, ProtocolError,
    ReauthInterval, decode_daemon_frame, decode_envelope, encode_client_frame, encode_envelope,
};

mod harness {
    //! Shared helpers for integration tests.

    use std::path::Path;

    use tempfile::TempDir;
    use wake_my_pc_core::crypto::DeviceIdentity;

    pub struct TestKeystore {
        pub dir: TempDir,
        pub daemon_identity: DeviceIdentity,
        pub clients: Vec<DeviceIdentity>,
    }

    /// Build a keystore on disk with `n_clients` pre-paired clients.
    /// Returns the daemon + client identities so tests can build their
    /// own TLS configs. Saves the keystore through the production path
    /// (DPAPI on Windows) so the daemon-under-test loads it normally.
    pub async fn build_keystore(n_clients: usize) -> TestKeystore {
        use wake_my_pc_daemon::{KeystoreContents, PairingRecord};

        let dir = tempfile::tempdir().unwrap();
        let daemon_identity = DeviceIdentity::generate().unwrap();

        let mut clients = Vec::with_capacity(n_clients);
        let mut pairings = Vec::with_capacity(n_clients);
        for i in 0..n_clients {
            let client = DeviceIdentity::generate().unwrap();
            pairings.push(PairingRecord {
                phone_name: format!("device-{i}"),
                client_spki: client.spki_hash(),
                paired_at_unix_ms: 1_000,
                last_authenticated_at_unix_ms: 1_000,
                revoked: false,
                revoke_pending: false,
            });
            clients.push(client);
        }

        let mut contents = KeystoreContents::from_identity(&daemon_identity.to_bytes());
        contents.pairings = pairings;
        contents.reauth_interval_days = 0; // Off for tests — reauth gating is its own test.
        contents.last_authenticated_at_unix_ms = 0;

        let path = keystore_path(dir.path());
        wake_my_pc_daemon::keystore_save(&path, &contents)
            .await
            .unwrap();

        TestKeystore {
            dir,
            daemon_identity,
            clients,
        }
    }

    pub fn keystore_path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("keystore.bin")
    }
}

/// Run a single-shot client request against the daemon: connect, send
/// `frame`, read one response envelope, disconnect.
async fn rpc_one(
    daemon_addr: SocketAddr,
    daemon_pin: SpkiHash,
    client: &DeviceIdentity,
    frame: &ClientFrame,
) -> DaemonFrame {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = client_config_for_pinned_daemon(
        Arc::new(PinSet::with_pins([daemon_pin])),
        client,
        provider,
    )
    .unwrap();

    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(daemon_addr).await.unwrap();
    let server_name = ServerName::try_from("any.invalid").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let mut nonces = NonceCounter::new();
    let nonce = nonces.send.issue().unwrap();
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce,
        payload: encode_client_frame(frame).unwrap(),
    };
    let bytes = encode_envelope(&env).unwrap();
    tls.write_all(&bytes).await.unwrap();

    // Read one response envelope.
    let mut buf = Vec::with_capacity(256);
    loop {
        let parsed: Option<(Envelope, usize)> = match decode_envelope(&buf) {
            Ok(DecodeOutcome::Frame {
                envelope,
                remainder,
            }) => {
                let consumed = buf.len() - remainder.len();
                Some((envelope, consumed))
            }
            Ok(DecodeOutcome::Incomplete) => None,
            Err(e) => panic!("decode envelope: {e}"),
        };
        if let Some((env, _consumed)) = parsed {
            return decode_daemon_frame(&env.payload).unwrap();
        }
        let mut chunk = [0u8; 1024];
        let n = tls.read(&mut chunk).await.unwrap();
        if n == 0 {
            panic!("server closed before responding");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Spawn the daemon listener on a random localhost port. Returns the
/// bound address + a join handle for the listener task.
async fn spawn_daemon(
    data_dir: std::path::PathBuf,
) -> (SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    use std::net::{IpAddr, Ipv4Addr};

    // Configure for ephemeral localhost port.
    let cfg = wake_my_pc_daemon::Config {
        data_dir,
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    };

    // We can't easily get the bound port back from the existing
    // server::run because it binds inside accept_loop. Bind here
    // first, then hand the listener over.
    let listener = tokio::net::TcpListener::bind(cfg.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle =
        tokio::spawn(
            async move { wake_my_pc_daemon::run_server_with_listener(cfg, listener).await },
        );

    // Give the listener a moment to settle before tests connect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, handle)
}

#[tokio::test]
async fn state_probe_returns_5_state() {
    let ks = harness::build_keystore(1).await;
    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[0],
        &ClientFrame::StateProbe,
    )
    .await;
    match resp {
        DaemonFrame::StateReport(state) => {
            // On Windows, expect OnLoggedIn; on stub platforms also OnLoggedIn.
            assert!(
                matches!(state, PcState::OnLoggedIn | PcState::OnLoggedOut),
                "got {state:?}"
            );
        }
        other => panic!("expected StateReport, got {other:?}"),
    }
}

#[tokio::test]
async fn reauth_status_reports_interval() {
    let ks = harness::build_keystore(1).await;
    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[0],
        &ClientFrame::ReauthStatus,
    )
    .await;
    match resp {
        DaemonFrame::ReauthInfo { interval, .. } => {
            // Test harness initializes interval to Off.
            assert_eq!(interval, ReauthInterval::Off);
        }
        other => panic!("expected ReauthInfo, got {other:?}"),
    }
}

#[tokio::test]
async fn reauth_config_persists_across_calls() {
    let ks = harness::build_keystore(1).await;
    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    // Set to SevenDays, expect Ack.
    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[0],
        &ClientFrame::ReauthConfig {
            interval: ReauthInterval::SevenDays,
        },
    )
    .await;
    assert!(matches!(resp, DaemonFrame::Ack { .. }), "got {resp:?}");

    // Read it back.
    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[0],
        &ClientFrame::ReauthStatus,
    )
    .await;
    match resp {
        DaemonFrame::ReauthInfo { interval, .. } => {
            assert_eq!(interval, ReauthInterval::SevenDays);
        }
        other => panic!("expected ReauthInfo, got {other:?}"),
    }
}

#[tokio::test]
async fn multi_device_pairing_both_authenticate() {
    let ks = harness::build_keystore(2).await;
    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    // Phone (clients[0]) probes — accepted.
    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[0],
        &ClientFrame::StateProbe,
    )
    .await;
    assert!(matches!(resp, DaemonFrame::StateReport(_)), "got {resp:?}");

    // Tablet (clients[1]) probes — also accepted, independent identity.
    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[1],
        &ClientFrame::StateProbe,
    )
    .await;
    assert!(matches!(resp, DaemonFrame::StateReport(_)), "got {resp:?}");
}

#[tokio::test]
async fn unpaired_client_rejected_at_tls() {
    let ks = harness::build_keystore(1).await;
    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    // A fresh (un-pinned) identity. Daemon's PinSet doesn't include it.
    let imposter = DeviceIdentity::generate().unwrap();
    let outcome = try_send_state_probe(addr, ks.daemon_identity.spki_hash(), &imposter).await;
    assert!(
        matches!(outcome, ProbeOutcome::TlsRejected),
        "expected TLS rejection, got {outcome:?}"
    );
}

#[tokio::test]
async fn revocation_blocks_revoked_client_keeps_others_working() {
    use wake_my_pc_daemon::{KeystoreContents, keystore_load, keystore_save};

    let ks = harness::build_keystore(2).await;
    let path = harness::keystore_path(ks.dir.path());

    // Mutate the keystore on disk to revoke clients[0].
    let mut contents: KeystoreContents = keystore_load(&path).await.unwrap().unwrap();
    let revoke_target = ks.clients[0].spki_hash();
    for p in &mut contents.pairings {
        if p.client_spki == revoke_target {
            p.revoked = true;
            p.revoke_pending = true;
        }
    }
    keystore_save(&path, &contents).await.unwrap();

    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    // Revoked client: not in the live PinSet (rebuilt per accept from
    // non-revoked pairings). Server rejects via TLS alert (visible to the
    // client only on first read/write attempt — TLS 1.3 client-side
    // handshake completes optimistically before the server validates).
    let outcome = try_send_state_probe(addr, ks.daemon_identity.spki_hash(), &ks.clients[0]).await;
    assert!(
        matches!(outcome, ProbeOutcome::TlsRejected),
        "revoked client should fail TLS, got {outcome:?}"
    );

    // Other client still works.
    let resp = rpc_one(
        addr,
        ks.daemon_identity.spki_hash(),
        &ks.clients[1],
        &ClientFrame::StateProbe,
    )
    .await;
    assert!(matches!(resp, DaemonFrame::StateReport(_)), "got {resp:?}");
}

#[tokio::test]
async fn nonce_replay_rejected() {
    let ks = harness::build_keystore(1).await;
    let (addr, _server) = spawn_daemon(ks.dir.path().to_path_buf()).await;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = client_config_for_pinned_daemon(
        Arc::new(PinSet::with_pins([ks.daemon_identity.spki_hash()])),
        &ks.clients[0],
        provider,
    )
    .unwrap();
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("any.invalid").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // Send the SAME nonce twice. Daemon must reject the second with NonceReplay.
    let payload = encode_client_frame(&ClientFrame::StateProbe).unwrap();
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce: 1,
        payload: payload.clone(),
    };
    tls.write_all(&encode_envelope(&env).unwrap())
        .await
        .unwrap();

    // Drain the first response.
    let mut buf = Vec::with_capacity(256);
    let _first = drain_one_envelope(&mut tls, &mut buf).await;

    // Second copy with same nonce.
    let env_replay = Envelope {
        version: PROTOCOL_VERSION,
        nonce: 1,
        payload,
    };
    tls.write_all(&encode_envelope(&env_replay).unwrap())
        .await
        .unwrap();

    let second = drain_one_envelope(&mut tls, &mut buf).await;
    let resp = decode_daemon_frame(&second.payload).unwrap();
    match resp {
        DaemonFrame::Error {
            code: ProtocolError::NonceReplay,
            ..
        } => {}
        other => panic!("expected Error{{NonceReplay}}, got {other:?}"),
    }
}

/// Outcome of an end-to-end probe attempt against the daemon.
#[derive(Debug)]
#[allow(dead_code)] // variants captured for assertions; fields read in match arms
enum ProbeOutcome {
    /// Server accepted and responded with a frame.
    Reply(DaemonFrame),
    /// TLS layer rejected — TCP or rustls error before any frame.
    /// Includes the case where TLS 1.3 client-side handshake completes
    /// optimistically and the server's reject arrives only when the
    /// client tries to write or read application bytes.
    TlsRejected,
}

/// Connect, attempt to send a `StateProbe`, and read one response. If the
/// server rejected the client via the SPKI verifier (post-handshake on
/// TLS 1.3), the write or the read fails — categorize as `TlsRejected`.
async fn try_send_state_probe(
    daemon_addr: SocketAddr,
    daemon_pin: SpkiHash,
    client: &DeviceIdentity,
) -> ProbeOutcome {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = match client_config_for_pinned_daemon(
        Arc::new(PinSet::with_pins([daemon_pin])),
        client,
        provider,
    ) {
        Ok(c) => c,
        Err(_) => return ProbeOutcome::TlsRejected,
    };

    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = match TcpStream::connect(daemon_addr).await {
        Ok(t) => t,
        Err(_) => return ProbeOutcome::TlsRejected,
    };
    let server_name = ServerName::try_from("any.invalid").unwrap();
    let mut tls = match connector.connect(server_name, tcp).await {
        Ok(t) => t,
        Err(_) => return ProbeOutcome::TlsRejected, // server rejected before handshake completes
    };

    // Send a probe — server may have already closed.
    let mut nonces = NonceCounter::new();
    let nonce = nonces.send.issue().unwrap();
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce,
        payload: encode_client_frame(&ClientFrame::StateProbe).unwrap(),
    };
    let bytes = encode_envelope(&env).unwrap();
    if tls.write_all(&bytes).await.is_err() {
        return ProbeOutcome::TlsRejected;
    }

    let mut buf = Vec::with_capacity(256);
    loop {
        let parsed: Option<(Envelope, usize)> = match decode_envelope(&buf) {
            Ok(DecodeOutcome::Frame {
                envelope,
                remainder,
            }) => {
                let consumed = buf.len() - remainder.len();
                Some((envelope, consumed))
            }
            Ok(DecodeOutcome::Incomplete) => None,
            Err(_) => return ProbeOutcome::TlsRejected,
        };
        if let Some((env, _)) = parsed {
            return match decode_daemon_frame(&env.payload) {
                Ok(f) => ProbeOutcome::Reply(f),
                Err(_) => ProbeOutcome::TlsRejected,
            };
        }
        let mut chunk = [0u8; 1024];
        let n = match tls.read(&mut chunk).await {
            Ok(n) => n,
            Err(_) => return ProbeOutcome::TlsRejected,
        };
        if n == 0 {
            return ProbeOutcome::TlsRejected;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn drain_one_envelope(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
) -> Envelope {
    loop {
        let parsed: Option<(Envelope, usize)> = match decode_envelope(buf) {
            Ok(DecodeOutcome::Frame {
                envelope,
                remainder,
            }) => {
                let consumed = buf.len() - remainder.len();
                Some((envelope, consumed))
            }
            Ok(DecodeOutcome::Incomplete) => None,
            Err(e) => panic!("decode envelope: {e}"),
        };
        if let Some((env, consumed)) = parsed {
            buf.drain(..consumed);
            return env;
        }
        let mut chunk = [0u8; 1024];
        let n = tls.read(&mut chunk).await.unwrap();
        if n == 0 {
            panic!("peer closed mid-frame");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

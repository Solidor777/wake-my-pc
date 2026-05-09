//! Real in-memory TLS 1.3 handshake test. Confirms the rustls config
//! builders + SPKI verifiers compose into a working session, and that the
//! pin enforcement is real end-to-end (not just the verifier shim).
//!
//! Three scenarios:
//!   - Pinned both ways → handshake completes.
//!   - Server pins wrong client SPKI → handshake fails.
//!   - Client pins wrong daemon SPKI → handshake fails.
//!
//! Plus a structural check that the negotiated version is TLS 1.3.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, ServerConfig, ServerConnection};
use wake_my_pc_core::crypto::{
    DeviceIdentity, PinSet, client_config_for_pinned_daemon, server_config_for_pinned_clients,
};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Pump bytes between an in-memory client and server until the handshake
/// completes or stalls. `Ok(())` means handshake completed; the caller
/// then inspects the connections for negotiated parameters.
fn drive_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    let mut steps = 0;
    while client.is_handshaking() || server.is_handshaking() {
        steps += 1;
        if steps > 32 {
            panic!("handshake exceeded 32 round trips — stalled");
        }

        // Drain client → server.
        if client.wants_write() {
            let mut buf = Vec::new();
            while client.wants_write() {
                client
                    .write_tls(&mut buf)
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            let mut cursor = Cursor::new(buf);
            while (cursor.position() as usize) < cursor.get_ref().len() {
                server
                    .read_tls(&mut cursor)
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            server.process_new_packets()?;
        }

        // Drain server → client.
        if server.wants_write() {
            let mut buf = Vec::new();
            while server.wants_write() {
                server
                    .write_tls(&mut buf)
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            let mut cursor = Cursor::new(buf);
            while (cursor.position() as usize) < cursor.get_ref().len() {
                client
                    .read_tls(&mut cursor)
                    .map_err(|e| rustls::Error::General(e.to_string()))?;
            }
            client.process_new_packets()?;
        }
    }
    Ok(())
}

fn build_pair(
    client_cfg: ClientConfig,
    server_cfg: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    let server_name = ServerName::try_from("any.invalid").unwrap();
    let client = ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
    let server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    (client, server)
}

#[test]
fn pinned_both_ways_handshake_succeeds_and_negotiates_tls13() {
    let server_id = DeviceIdentity::generate().unwrap();
    let client_id = DeviceIdentity::generate().unwrap();

    let server_cfg = server_config_for_pinned_clients(
        Arc::new(PinSet::with_pins([client_id.spki_hash()])),
        &server_id,
        provider(),
    )
    .unwrap();
    let client_cfg = client_config_for_pinned_daemon(
        Arc::new(PinSet::with_pins([server_id.spki_hash()])),
        &client_id,
        provider(),
    )
    .unwrap();

    let (mut client, mut server) = build_pair(client_cfg, server_cfg);
    drive_handshake(&mut client, &mut server).expect("handshake should complete");

    // PROTOCOL.md §6: TLS 1.3 only.
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
}

#[test]
fn server_rejects_unpinned_client_cert() {
    let server_id = DeviceIdentity::generate().unwrap();
    let pinned_client = DeviceIdentity::generate().unwrap();
    let imposter_client = DeviceIdentity::generate().unwrap();

    let server_cfg = server_config_for_pinned_clients(
        Arc::new(PinSet::with_pins([pinned_client.spki_hash()])),
        &server_id,
        provider(),
    )
    .unwrap();
    // Imposter client trusts the right server but presents the wrong
    // client cert — daemon side must reject at handshake.
    let client_cfg = client_config_for_pinned_daemon(
        Arc::new(PinSet::with_pins([server_id.spki_hash()])),
        &imposter_client,
        provider(),
    )
    .unwrap();

    let (mut client, mut server) = build_pair(client_cfg, server_cfg);
    let result = drive_handshake(&mut client, &mut server);
    assert!(result.is_err(), "handshake should fail; got {result:?}");
}

#[test]
fn client_rejects_unpinned_server_cert() {
    let pinned_server = DeviceIdentity::generate().unwrap();
    let imposter_server = DeviceIdentity::generate().unwrap();
    let client_id = DeviceIdentity::generate().unwrap();

    // Imposter server runs with valid auth-on-its-side but is NOT in the
    // client's pinset — client rejects in `verify_server_cert`.
    let server_cfg = server_config_for_pinned_clients(
        Arc::new(PinSet::with_pins([client_id.spki_hash()])),
        &imposter_server,
        provider(),
    )
    .unwrap();
    let client_cfg = client_config_for_pinned_daemon(
        Arc::new(PinSet::with_pins([pinned_server.spki_hash()])),
        &client_id,
        provider(),
    )
    .unwrap();

    let (mut client, mut server) = build_pair(client_cfg, server_cfg);
    let result = drive_handshake(&mut client, &mut server);
    assert!(result.is_err(), "handshake should fail; got {result:?}");
}

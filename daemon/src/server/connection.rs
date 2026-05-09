//! Per-connection protocol loop. Runs after `tokio_rustls` completes the
//! handshake (and the `ServerCertVerifier` has confirmed the peer SPKI is
//! pinned). Maps the verified peer back to a pairing record, then enters
//! the read/dispatch/write loop.
//!
//! Strict ordering per PROTOCOL.md §5: nonce check happens BEFORE the
//! payload is dispatched to a handler. Truncated / malformed input
//! produces a typed error and closes the connection.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};
use wake_my_pc_core::crypto::{NonceCounter, SpkiHash, extract_spki_hash};
use wake_my_pc_core::protocol::{
    ClientFrame, DaemonFrame, DecodeOutcome, Envelope, PROTOCOL_VERSION, ProtocolError,
    decode_client_frame, decode_envelope, encode_daemon_frame, encode_envelope,
};

use super::SharedState;
use crate::error::OsHandlerError;
use crate::platform;
use crate::reauth;

const READ_CHUNK: usize = 4096;

/// Run the per-connection protocol loop until the peer disconnects or
/// an unrecoverable error occurs.
pub async fn run(mut tls: TlsStream<TcpStream>, state: SharedState) -> Result<()> {
    let peer_spki = peer_spki_from_tls(&tls).context("extracting peer SPKI from TLS session")?;

    // Pre-flight: confirm the SPKI maps to a non-revoked pairing. The
    // rustls verifier already accepted the cert by SPKI pin, but the
    // revocation flag is at the application layer (rustls only sees the
    // current PinSet built at accept time).
    {
        let snap = state.read().await;
        match snap.active_pairing(&peer_spki) {
            Some(_) => {}
            None => {
                // Either revoked between accept and protocol-start, or
                // (defensively) the rustls config + keystore got out of
                // sync. Send a typed error and close.
                send_error_and_close(&mut tls, 0, ProtocolError::Revoked).await?;
                return Ok(());
            }
        }
    }

    let mut nonces = NonceCounter::new();
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK);

    loop {
        let envelope = match read_envelope(&mut tls, &mut buf).await? {
            Some(env) => env,
            None => {
                debug!("peer closed cleanly");
                return Ok(());
            }
        };

        if let Err(e) = nonces.recv.accept(envelope.nonce) {
            warn!("peer {} replayed nonce: {e}", peer_spki.to_hex());
            send_error_and_close(&mut tls, envelope.nonce, ProtocolError::NonceReplay).await?;
            return Ok(());
        }

        let frame = match decode_client_frame(&envelope.payload) {
            Ok(f) => f,
            Err(e) => {
                let code = e.to_wire_code();
                debug!("decode failure: {e}");
                send_error_and_close(&mut tls, envelope.nonce, code).await?;
                return Ok(());
            }
        };

        let response = dispatch(&state, &peer_spki, &frame, envelope.nonce).await;

        if !write_frame(&mut tls, &mut nonces, &response).await? {
            return Ok(());
        }

        if response_closes_connection(&response) {
            // Send completed; flush + drop.
            let _ = tls.shutdown().await;
            return Ok(());
        }
    }
}

fn peer_spki_from_tls(tls: &TlsStream<TcpStream>) -> Result<SpkiHash> {
    let (_, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("peer presented no certificates"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("peer cert chain empty"))?;
    extract_spki_hash(leaf.as_ref()).map_err(anyhow::Error::from)
}

/// Read one envelope from the TLS stream, growing `buf` as bytes arrive.
/// Returns `Ok(None)` on clean EOF before any frame begins.
async fn read_envelope(
    tls: &mut TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
) -> Result<Option<Envelope>> {
    loop {
        // Try to parse what we have. The match scope confines the
        // immutable borrow of `buf` so we can drain afterwards.
        let parsed: Option<(Envelope, usize)> = match decode_envelope(buf) {
            Ok(DecodeOutcome::Frame {
                envelope,
                remainder,
            }) => {
                let consumed = buf.len() - remainder.len();
                Some((envelope, consumed))
            }
            Ok(DecodeOutcome::Incomplete) => None,
            Err(e) => return Err(anyhow!("malformed framing from peer: {e}")),
        };
        if let Some((env, consumed)) = parsed {
            buf.drain(..consumed);
            return Ok(Some(env));
        }

        let mut chunk = [0u8; READ_CHUNK];
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None); // clean EOF between frames
            }
            return Err(anyhow!("peer closed mid-frame"));
        }
        if let Some(slice) = chunk.get(..n) {
            buf.extend_from_slice(slice);
        }
    }
}

async fn write_frame(
    tls: &mut TlsStream<TcpStream>,
    nonces: &mut NonceCounter,
    frame: &DaemonFrame,
) -> Result<bool> {
    let nonce = nonces
        .send
        .issue()
        .ok_or_else(|| anyhow!("send nonce overflowed (impossible — 584M years)"))?;
    let payload = encode_daemon_frame(frame)?;
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce,
        payload,
    };
    let bytes = encode_envelope(&env)?;
    tls.write_all(&bytes).await?;
    Ok(true)
}

/// Some response variants close the connection per PROTOCOL.md §7.
fn response_closes_connection(frame: &DaemonFrame) -> bool {
    match frame {
        DaemonFrame::Error { code, .. } => matches!(
            code,
            ProtocolError::NotPaired
                | ProtocolError::Revoked
                | ProtocolError::VersionMismatch
                | ProtocolError::MalformedFrame
                | ProtocolError::NonceReplay
        ),
        _ => false,
    }
}

async fn send_error_and_close(
    tls: &mut TlsStream<TcpStream>,
    request_nonce: u64,
    code: ProtocolError,
) -> Result<()> {
    // We don't have a NonceCounter here, but the peer is about to be
    // dropped — strict ordering matters less. Still send a valid frame
    // with nonce=1 so a phone-side parse doesn't fail.
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce: 1,
        payload: encode_daemon_frame(&DaemonFrame::Error {
            request_nonce,
            code,
        })?,
    };
    let bytes = encode_envelope(&env)?;
    let _ = tls.write_all(&bytes).await;
    let _ = tls.shutdown().await;
    Ok(())
}

async fn dispatch(
    state: &SharedState,
    peer_spki: &SpkiHash,
    frame: &ClientFrame,
    request_nonce: u64,
) -> DaemonFrame {
    let now_ms = unix_ms_now();

    // Re-auth gate: state-changing commands fail with RequiresReauth past
    // the window. Status / config / revoke-ack always succeed.
    let snap = state.snapshot().await;
    let reauth_state = reauth::evaluate(
        now_ms,
        snap.last_authenticated_at_unix_ms,
        snap.reauth_interval_days,
    );

    match frame {
        ClientFrame::Pair { .. } => {
            // Pair frames are only valid inside a pairing window served
            // by the `pair` subcommand, NOT by the running listener.
            DaemonFrame::Error {
                request_nonce,
                code: ProtocolError::NotPaired,
            }
        }

        ClientFrame::Sleep => {
            if let Some(blocked) = reauth_state.block_state_change() {
                return DaemonFrame::Error {
                    request_nonce,
                    code: blocked,
                };
            }
            handler_to_response(platform::sleep(), request_nonce)
        }
        ClientFrame::Lock => {
            if let Some(blocked) = reauth_state.block_state_change() {
                return DaemonFrame::Error {
                    request_nonce,
                    code: blocked,
                };
            }
            handler_to_response(platform::lock(), request_nonce)
        }
        ClientFrame::PowerOff => {
            if let Some(blocked) = reauth_state.block_state_change() {
                return DaemonFrame::Error {
                    request_nonce,
                    code: blocked,
                };
            }
            handler_to_response(platform::power_off(), request_nonce)
        }

        ClientFrame::StateProbe => match platform::current_session_state() {
            Ok(s) => DaemonFrame::StateReport(s),
            Err(_) => DaemonFrame::Error {
                request_nonce,
                code: ProtocolError::Internal,
            },
        },

        ClientFrame::ReauthStatus => DaemonFrame::ReauthInfo {
            last_authenticated_at_unix_ms: snap.last_authenticated_at_unix_ms,
            interval: reauth::interval_from_days(snap.reauth_interval_days),
            expires_at_unix_ms: reauth::expires_at_unix_ms(
                snap.last_authenticated_at_unix_ms,
                snap.reauth_interval_days,
            ),
        },

        ClientFrame::ReauthConfig { interval } => {
            let new_days = reauth::interval_to_days(*interval);
            let mut w = state.write().await;
            w.reauth_interval_days = new_days;
            drop(w);
            if let Err(e) = state.save().await {
                warn!("keystore save (ReauthConfig) failed: {e}");
                return DaemonFrame::Error {
                    request_nonce,
                    code: ProtocolError::Internal,
                };
            }
            DaemonFrame::Ack { request_nonce }
        }

        ClientFrame::RevokeAck => {
            // The peer is acknowledging a daemon-initiated Revoke. Look
            // up the matching pairing and remove it entirely.
            let mut w = state.write().await;
            let before = w.pairings.len();
            w.pairings
                .retain(|p| !(p.client_spki == *peer_spki && p.revoked));
            let removed = before - w.pairings.len();
            drop(w);
            if removed > 0
                && let Err(e) = state.save().await
            {
                warn!("keystore save (RevokeAck) failed: {e}");
            }
            DaemonFrame::Ack { request_nonce }
        }
    }
}

fn handler_to_response(result: Result<(), OsHandlerError>, request_nonce: u64) -> DaemonFrame {
    match result {
        Ok(()) => DaemonFrame::Ack { request_nonce },
        Err(e) => {
            warn!("OS handler failure (peer sees Internal): {e}");
            DaemonFrame::Error {
                request_nonce,
                code: e.to_wire_code(),
            }
        }
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

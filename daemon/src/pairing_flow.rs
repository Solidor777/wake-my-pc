//! `wake-my-pc-daemon pair` — one-shot pairing window.
//!
//! Bootstraps a daemon identity if none exists yet, opens a 5-minute
//! pairing window via [`wake_my_pc_core::crypto::PairingHandshake`],
//! prints the 6-digit code + SPKI hex (and a future QR rendering — for
//! now stdout-only), accepts ONE TLS connection from the phone, decodes
//! a single `Pair` frame, validates it, and either:
//!
//! - persists the new pairing record + replies `Ack` + closes; or
//! - rejects with the appropriate wire error and stays open until the
//!   attempt budget or TTL is exhausted.
//!
//! Pairing connections use [`wake_my_pc_core::crypto::server_config_for_pairing`]
//! — accepts any TLS-valid client cert. The pairing-code check at the
//! protocol layer is what gates the flow.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{info, warn};
use wake_my_pc_core::crypto::{
    DeviceIdentity, NonceCounter, PAIRING_WINDOW_DEFAULT_MS, PairingHandshake, PairingState,
    PairingTransition, SpkiHash, extract_spki_hash, server_config_for_pairing,
};
use wake_my_pc_core::protocol::{
    ClientFrame, DaemonFrame, DecodeOutcome, Envelope, PROTOCOL_VERSION, ProtocolError,
    decode_client_frame, decode_envelope, encode_daemon_frame, encode_envelope,
};

use crate::config::Config;
use crate::keystore::{self, KeystoreContents};
use crate::pairings::PairingRecord as DaemonPairingRecord;

/// Run the `pair` subcommand.
pub async fn run(cfg: Config) -> Result<()> {
    keystore::ensure_data_dir(&cfg.data_dir).await?;

    // Load existing keystore or bootstrap a fresh identity.
    let mut contents = match keystore::load(&cfg.keystore_path()).await? {
        Some(c) => {
            info!("existing keystore at {}", cfg.keystore_path().display());
            c
        }
        None => {
            info!("no keystore found — generating fresh device identity");
            let id = DeviceIdentity::generate().context("generating device identity")?;
            KeystoreContents::from_identity(&id.to_bytes())
        }
    };

    let identity = DeviceIdentity::from_bytes(&contents.device_identity_bytes())
        .context("parsing daemon device identity")?;

    // Open the pairing window.
    let mut handshake = PairingHandshake::new();
    let now = unix_ms_now();
    let started = handshake.start(now, PAIRING_WINDOW_DEFAULT_MS)?;
    let code = match started {
        PairingTransition::Started { code } => code,
        other => return Err(anyhow!("unexpected pairing transition: {other:?}")),
    };

    println!("====================================");
    println!("wake-my-pc-daemon pairing");
    println!("Code: {code:06}");
    println!("SPKI: {}", identity.spki_hash().to_hex());
    println!("This window is valid for 5 minutes or until 5 wrong attempts.");
    println!("====================================");

    // Bind the pairing-window listener.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let pair_cfg = server_config_for_pairing(&identity, provider)?;
    let acceptor = TlsAcceptor::from(Arc::new(pair_cfg));
    let listener = TcpListener::bind(cfg.bind)
        .await
        .with_context(|| format!("binding pairing listener at {}", cfg.bind))?;
    info!("pairing listener bound to {}", listener.local_addr()?);

    // Accept loop with TTL deadline.
    let deadline = tokio::time::sleep(std::time::Duration::from_millis(PAIRING_WINDOW_DEFAULT_MS));
    tokio::pin!(deadline);

    loop {
        // Tick the state machine for expiry — also catches TTL-exhausted
        // case if accept happens to land exactly at the deadline.
        if matches!(handshake.tick(unix_ms_now()), PairingTransition::Expired) {
            return Err(anyhow!("pairing window expired"));
        }

        tokio::select! {
            _ = &mut deadline => {
                return Err(anyhow!("pairing window expired"));
            }
            accept = listener.accept() => {
                let (tcp, peer) = accept.context("pairing accept")?;
                info!("pairing connection from {peer}");

                let tls = match acceptor.clone().accept(tcp).await {
                    Ok(t) => t,
                    Err(e) => { warn!("TLS handshake failed: {e}"); continue; }
                };

                match handle_pair_attempt(&mut handshake, &mut contents, &cfg, tls).await {
                    Ok(true) => return Ok(()),                  // paired
                    Ok(false) => {}                              // rejection within budget; loop
                    Err(e) => warn!("pairing attempt error: {e:#}"),
                }
                if matches!(handshake.state(), PairingState::Idle) {
                    return Err(anyhow!("pairing window closed (timeout or attempt budget)"));
                }
            }
        }
    }
}

/// Returns Ok(true) if the pair succeeded (and was persisted),
/// Ok(false) if rejected within budget (window stays open),
/// Err on connection-level failure (window stays open per Idle check).
async fn handle_pair_attempt(
    handshake: &mut PairingHandshake,
    contents: &mut KeystoreContents,
    cfg: &Config,
    mut tls: TlsStream<TcpStream>,
) -> Result<bool> {
    let peer_spki = peer_spki_from_tls(&tls)?;

    let mut buf = Vec::with_capacity(256);
    let envelope = read_one_envelope(&mut tls, &mut buf).await?;

    let mut send_nonces = NonceCounter::new();

    // No nonce-replay state for pairing (single message, single session).
    let frame = match decode_client_frame(&envelope.payload) {
        Ok(f) => f,
        Err(e) => {
            send_error(&mut tls, &mut send_nonces, envelope.nonce, e.to_wire_code()).await?;
            return Ok(false);
        }
    };

    let (phone_name, pairing_code) = match frame {
        ClientFrame::Pair {
            phone_name,
            pairing_code,
        } => (phone_name, pairing_code),
        _ => {
            send_error(
                &mut tls,
                &mut send_nonces,
                envelope.nonce,
                ProtocolError::Unsupported,
            )
            .await?;
            return Ok(false);
        }
    };

    let now = unix_ms_now();
    let transition = handshake.accept_pair(now, pairing_code, phone_name.clone(), peer_spki);

    match transition {
        PairingTransition::Succeeded { record } => {
            let new_pairing = DaemonPairingRecord::from_core(record);
            // Multi-device support: keystore holds one Vec<PairingRecord>,
            // one entry per paired phone/tablet. Re-pairing the same SPKI
            // (typically phone wipe + re-pair) replaces the prior record
            // rather than accumulating duplicates. Different SPKIs simply
            // add new records — owner can pair phone + tablet + ...
            contents
                .pairings
                .retain(|p| p.client_spki != new_pairing.client_spki);
            contents.pairings.push(new_pairing);
            // Persist before acking — if save fails, peer must NOT think
            // they're paired.
            keystore::save(&cfg.keystore_path(), contents).await?;

            send_ack(&mut tls, &mut send_nonces, envelope.nonce).await?;
            let _ = tls.shutdown().await;
            info!("paired: {phone_name}");
            Ok(true)
        }
        PairingTransition::Rejected { reason } => {
            warn!("pair attempt rejected: {reason:?}");
            // Map all rejection reasons to NotPaired on the wire — we
            // don't tell the peer which specific check failed (Principle 1).
            send_error(
                &mut tls,
                &mut send_nonces,
                envelope.nonce,
                ProtocolError::NotPaired,
            )
            .await?;
            let _ = tls.shutdown().await;
            Ok(false)
        }
        other => Err(anyhow!("unexpected pairing transition: {other:?}")),
    }
}

fn peer_spki_from_tls(tls: &TlsStream<TcpStream>) -> Result<SpkiHash> {
    let (_, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("no peer cert"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("empty peer cert chain"))?;
    extract_spki_hash(leaf.as_ref()).map_err(anyhow::Error::from)
}

async fn read_one_envelope(tls: &mut TlsStream<TcpStream>, buf: &mut Vec<u8>) -> Result<Envelope> {
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
            Err(e) => return Err(anyhow!("malformed framing: {e}")),
        };
        if let Some((env, consumed)) = parsed {
            buf.drain(..consumed);
            return Ok(env);
        }
        let mut chunk = [0u8; 4096];
        let n = tls.read(&mut chunk).await?;
        if n == 0 {
            return Err(anyhow!("peer closed mid-frame"));
        }
        if let Some(slice) = chunk.get(..n) {
            buf.extend_from_slice(slice);
        }
    }
}

async fn send_ack(
    tls: &mut TlsStream<TcpStream>,
    nonces: &mut NonceCounter,
    request_nonce: u64,
) -> Result<()> {
    let nonce = nonces
        .send
        .issue()
        .ok_or_else(|| anyhow!("send nonce overflow"))?;
    let frame = DaemonFrame::Ack { request_nonce };
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce,
        payload: encode_daemon_frame(&frame)?,
    };
    let bytes = encode_envelope(&env)?;
    tls.write_all(&bytes).await?;
    Ok(())
}

async fn send_error(
    tls: &mut TlsStream<TcpStream>,
    nonces: &mut NonceCounter,
    request_nonce: u64,
    code: ProtocolError,
) -> Result<()> {
    let nonce = nonces
        .send
        .issue()
        .ok_or_else(|| anyhow!("send nonce overflow"))?;
    let frame = DaemonFrame::Error {
        request_nonce,
        code,
    };
    let env = Envelope {
        version: PROTOCOL_VERSION,
        nonce,
        payload: encode_daemon_frame(&frame)?,
    };
    let bytes = encode_envelope(&env)?;
    tls.write_all(&bytes).await?;
    Ok(())
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

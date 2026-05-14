//! `list-paired`, `revoke`, `reauth-now` subcommands. Pure local
//! keystore mutations — no network. The running listener picks up
//! changes on the next accept (rebuilds PinSet per accept).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use tracing::info;

use crate::config::Config;
use crate::keystore::{self, KeystoreContents};
use crate::reauth;

/// Print one row per pairing.
pub async fn list_paired(cfg: Config) -> Result<()> {
    let contents = require_keystore(&cfg).await?;

    if contents.pairings.is_empty() {
        println!("No pairings. Run `wake-my-pc-daemon pair` to add one.");
        return Ok(());
    }

    println!(
        "{:<24} {:<24} {:<24} {:<8} SPKI",
        "phone_name", "paired_at_unix_ms", "last_auth_unix_ms", "revoked",
    );
    for p in &contents.pairings {
        println!(
            "{:<24} {:<24} {:<24} {:<8} {}",
            p.phone_name,
            p.paired_at_unix_ms,
            p.last_authenticated_at_unix_ms,
            p.revoked,
            p.client_spki.to_hex(),
        );
    }
    Ok(())
}

/// Set `revoked = true` on the named pairing. Queues a Revoke push for
/// the listener / future retry-loop to deliver opportunistically.
pub async fn revoke(cfg: Config, phone_name: String) -> Result<()> {
    let mut contents = require_keystore(&cfg).await?;
    let mut found = false;
    for p in &mut contents.pairings {
        if p.phone_name == phone_name {
            p.revoked = true;
            p.revoke_pending = true;
            found = true;
        }
    }
    if !found {
        return Err(anyhow!("no pairing named {phone_name:?}"));
    }
    keystore::save(&cfg.keystore_path(), &contents).await?;
    info!("revoked pairing: {phone_name}");
    println!("revoked: {phone_name}");
    Ok(())
}

/// Run a credential prompt, then reset `last_authenticated_at_unix_ms`
/// to now. M2 baseline: no prompt — always succeeds. Production-ready
/// Windows Hello / Touch ID / polkit deferred (see TODO.md).
pub async fn reauth_now(cfg: Config) -> Result<()> {
    let mut contents = require_keystore(&cfg).await?;

    if !run_credential_prompt_stub() {
        return Err(anyhow!("credential prompt cancelled"));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    contents.last_authenticated_at_unix_ms = now;
    keystore::save(&cfg.keystore_path(), &contents).await?;

    let interval = reauth::interval_from_days(contents.reauth_interval_days);
    println!(
        "re-authenticated at {now} unix-ms; interval {interval:?}; next due {} unix-ms",
        reauth::expires_at_unix_ms(now, contents.reauth_interval_days)
    );
    Ok(())
}

/// Mark every pairing as revoked and try to deliver a Revoke push to
/// each phone's last-known address. Invoked by the MSI uninstaller as a
/// pre-keystore-wipe custom action so reachable phones get a clean
/// "this pairing was removed" UX hint before the daemon goes away.
///
/// Best-effort by design (Principle 1: layered revocation): the
/// cryptographic guarantee comes from the keystore wipe that the MSI
/// performs after this. M2 baseline cannot actually deliver the Revoke
/// frames because the phone-side mDNS listener is M4 — every
/// connection attempt will fail with `connection refused`. The
/// keystore mutation (revoked + revoke_pending flags) still lands so
/// any phone that reconnects between this call and the keystore wipe
/// is rejected immediately.
pub async fn uninstall_revoke_broadcast(cfg: Config) -> Result<()> {
    let mut contents = require_keystore(&cfg).await?;

    let mut targets: Vec<(String, Option<std::net::SocketAddr>)> = Vec::new();
    for p in &mut contents.pairings {
        targets.push((p.phone_name.clone(), p.last_known_address));
        p.revoked = true;
        p.revoke_pending = true;
    }
    keystore::save(&cfg.keystore_path(), &contents).await?;

    if targets.is_empty() {
        println!("no pairings to broadcast Revoke to");
        return Ok(());
    }

    println!(
        "marked {} pairing(s) revoked; attempting best-effort Revoke push:",
        targets.len()
    );
    let delivered = 0usize;
    let mut unreachable = 0usize;
    let mut no_address = 0usize;

    for (name, maybe_addr) in &targets {
        match maybe_addr {
            None => {
                println!("  {name}: NO ADDRESS (phone never connected post-pair)");
                no_address += 1;
            }
            Some(addr) => {
                // M2 placeholder: phone-side listener doesn't exist
                // until M4 mDNS lands. Try a TCP connect with a 1s
                // budget and report the (expected-)failure honestly.
                match tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        // We could connect, but the daemon-as-client
                        // mTLS + Revoke-frame path lands with M4. For
                        // now treat as undeliverable.
                        println!(
                            "  {name} @ {addr}: REACHABLE but daemon-initiated Revoke channel \
                             not implemented yet (M4)"
                        );
                        unreachable += 1;
                    }
                    Ok(Err(e)) => {
                        println!("  {name} @ {addr}: UNREACHABLE ({e})");
                        unreachable += 1;
                    }
                    Err(_) => {
                        println!("  {name} @ {addr}: UNREACHABLE (timeout)");
                        unreachable += 1;
                    }
                }
            }
        }
    }

    println!(
        "summary: delivered={delivered} unreachable={unreachable} no_address={no_address} of {}",
        targets.len()
    );
    println!(
        "note: cryptographic revocation comes from the keystore wipe the MSI performs next; \
         this push is best-effort UX only."
    );
    Ok(())
}

async fn require_keystore(cfg: &Config) -> Result<KeystoreContents> {
    keystore::load(&cfg.keystore_path())
        .await
        .with_context(|| format!("loading keystore at {}", cfg.keystore_path().display()))?
        .ok_or_else(|| {
            anyhow!(
                "no keystore at {} — run `wake-my-pc-daemon pair` first",
                cfg.keystore_path().display()
            )
        })
}

/// M2 baseline credential-prompt stub: no platform integration. Always
/// returns true. Replaced in M2 follow-up with Windows Hello (WebAuthn),
/// Touch ID (`LocalAuthentication`), polkit on Linux. See TODO.md.
fn run_credential_prompt_stub() -> bool {
    info!("credential prompt: stub (M2 baseline) — always-ok");
    true
}

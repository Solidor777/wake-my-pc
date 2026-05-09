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

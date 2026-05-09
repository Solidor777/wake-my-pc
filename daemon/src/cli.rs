//! Clap-derived CLI surface. Subcommands:
//!
//! - `serve` — main daemon. Long-running listener.
//! - `pair` — open a one-shot pairing window.
//! - `list-paired` — show pairings.
//! - `revoke <phone_name>` — revoke a pairing.
//! - `reauth-now` — manually reset re-auth window.
//!
//! Config flags (`--data-dir`, `--port`) are global. `--data-dir` overrides
//! the OS-appropriate default ([`crate::config::Config::from_args`]).

use clap::{Parser, Subcommand};
use wake_my_pc_daemon::ConfigArgs;

/// Parsed CLI arguments — produced by [`parse`] and consumed by `main`.
#[derive(Debug, Parser)]
#[command(name = "wake-my-pc-daemon", version, about, long_about = None)]
pub struct Args {
    /// Global config flags. See [`ConfigArgs`].
    #[command(flatten)]
    pub config: ConfigArgs,

    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the long-running listener (default daemon behavior).
    Serve,
    /// Open a one-shot pairing window. Prints a 6-digit code + SPKI hex
    /// (and a QR payload to stdout) and accepts one client `Pair`.
    Pair,
    /// List paired phones with `phone_name`, `paired_at`, and
    /// `last_authenticated_at`.
    ListPaired,
    /// Revoke a paired phone. Sets `revoked = true` immediately; queues a
    /// Revoke push so the phone wipes its pin next time it's reachable.
    Revoke {
        /// `phone_name` from `list-paired`.
        phone_name: String,
    },
    /// Manually re-authenticate; resets `last_authenticated_at` to now.
    /// (Production: triggers Windows Hello / Touch ID / polkit. M2 baseline:
    /// no-op stub — see TODO.md re-auth credential prompt deferral.)
    ReauthNow,
}

/// Parse argv. Exits with clap's standard help/version on `--help`/`--version`.
#[must_use]
pub fn parse() -> Args {
    Args::parse()
}

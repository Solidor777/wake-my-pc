//! Daemon configuration. Two layers:
//!
//! - [`ConfigArgs`] — CLI-shaped clap struct. Lives at this layer because
//!   `cli.rs` `#[command(flatten)]`s it.
//! - [`Config`] — resolved runtime config. Built once in `main` from
//!   [`ConfigArgs`] and the OS data-dir defaults.
//!
//! Default port is `51820` (placeholder). Production: install-time
//! choice (PLAN.md M2 "port chosen at install"). For M2 development we
//! expose `--port` so integration tests can use ephemeral ports.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use directories::ProjectDirs;

/// Default listener port. Settled at install time in production.
pub const DEFAULT_PORT: u16 = 51_820;

/// CLI-shaped config args. Flattened into [`crate::cli::Args`] by clap.
#[derive(Debug, Args, Clone)]
pub struct ConfigArgs {
    /// Override the OS-appropriate data directory. Useful for tests and
    /// portable installs.
    #[arg(long, value_name = "PATH", global = true)]
    pub data_dir: Option<PathBuf>,

    /// TCP port for the LAN listener. Default 51820. Production: chosen
    /// at install time and stored in the keystore record.
    #[arg(long, default_value_t = DEFAULT_PORT, global = true)]
    pub port: u16,

    /// Bind address. Default `0.0.0.0` (LAN). Tests use `127.0.0.1`.
    #[arg(long, default_value = "0.0.0.0", global = true)]
    pub bind: IpAddr,
}

/// Resolved runtime config.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory holding the keystore + any future state.
    pub data_dir: PathBuf,
    /// Listener bind socket.
    pub bind: SocketAddr,
}

impl Config {
    /// Resolve [`ConfigArgs`] to a runtime config. Uses platform-appropriate
    /// data-directory defaults (`%APPDATA%\wake-my-pc` on Windows,
    /// `~/Library/Application Support/io.wake-my-pc.wake-my-pc` on macOS,
    /// `$XDG_DATA_HOME/wake-my-pc` on Linux) when `--data-dir` is unset.
    pub fn from_args(args: ConfigArgs) -> Result<Self> {
        let data_dir = match args.data_dir {
            Some(p) => p,
            None => {
                let dirs = ProjectDirs::from("io", "wake-my-pc", "wake-my-pc")
                    .context("could not resolve OS data directory")?;
                dirs.data_dir().to_path_buf()
            }
        };
        let bind = SocketAddr::new(args.bind, args.port);
        Ok(Self { data_dir, bind })
    }

    /// Path to the encrypted keystore file.
    #[must_use]
    pub fn keystore_path(&self) -> PathBuf {
        self.data_dir.join("keystore.bin")
    }

    /// Test helper: build a config rooted at a temp path with a localhost
    /// ephemeral-port bind. Integration tests construct this directly
    /// rather than parsing argv.
    #[must_use]
    pub fn for_test(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            bind: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
        }
    }
}

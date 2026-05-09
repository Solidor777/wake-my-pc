//! daemon: library surface used by `main.rs` (the binary entry point) and
//! by integration tests in `tests/`.
//!
//! Modules are public so tests can build a keystore + spawn a listener
//! without going through the interactive `pair` flow. The binary calls
//! these same functions; there is no behavior split between bin and lib.
//!
//! Principle 2 lints: `unsafe` is allowed here (FFI to OS APIs) but
//! every block carries a `// SAFETY:` comment per POST_WORK_FINDINGS.

#![allow(unsafe_code)]

pub mod admin;
pub mod config;
pub mod error;
pub mod keystore;
pub mod pairing_flow;
pub mod pairings;
pub mod platform;
pub mod reauth;
pub mod server;

// Top-level convenience re-exports for the integration-test surface.
pub use config::{Config, ConfigArgs};
pub use error::{KeystoreError, OsHandlerError};
pub use keystore::{KEYSTORE_FORMAT_VERSION, KeystoreContents};
pub use pairings::PairingRecord;

/// Test/integration alias for [`keystore::load`].
pub use keystore::load as keystore_load;
/// Test/integration alias for [`keystore::save`].
pub use keystore::save as keystore_save;

/// Run the listener with a pre-bound TCP listener. Integration tests use
/// this to get an ephemeral port via `local_addr()` before handing the
/// listener over.
///
/// Production callers use [`server::run`] which binds internally.
pub async fn run_server_with_listener(
    cfg: Config,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    server::run_with_listener(cfg, listener).await
}

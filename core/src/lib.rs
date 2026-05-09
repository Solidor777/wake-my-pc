//! core: M1 surface — wire protocol + crypto. Pure Rust, no I/O, no platform deps.
//!
//! Principle 2: `forbid(unsafe_code)` is mandatory here. unwrap/expect lints are
//! `deny` workspace-wide; this crate raises that to a hard architectural rule.
//!
//! Module map:
//! - [`protocol`] — wire format (PROTOCOL.md §3–§5, §7). Encodes/decodes
//!   `ClientFrame`, `DaemonFrame`, and the length-prefixed envelope; no transport.
//! - [`crypto`] — TLS 1.3 + Ed25519 device cert generation, SPKI pinning,
//!   pairing handshake state machine, monotonic nonce counter.
//! - [`error`] — top-level [`Error`] enum re-exported at crate root for
//!   callers that want one type to handle.
//!
//! Anything that does I/O — sockets, files, OS APIs — lives in `daemon/`,
//! `desktop-ui/`, or `bindings/` per Principle 4 layering.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod error;
pub mod protocol;

pub use error::Error;

/// Smoke-test surface kept for M0 dep-graph proofs. Retired when daemon and
/// desktop-ui adopt real protocol calls in M2.
#[must_use]
pub fn hello() -> &'static str {
    "core: hello"
}

#[cfg(test)]
mod tests {
    use super::hello;

    #[test]
    fn hello_is_stable() {
        assert_eq!(hello(), "core: hello");
    }
}

//! Per-OS sleep / lock / power-off / session-state handlers.
//!
//! The trait-shape is implicit: every platform module exposes the same
//! free-functions (`sleep`, `lock`, `power_off`, `current_session_state`,
//! `prepare`). Daemon code calls them via `crate::platform::*`; cfg flags
//! pick the impl. Honest non-impl on non-Windows in the M2 baseline:
//! these return [`crate::error::OsHandlerError`] so the daemon doesn't
//! pretend to do anything.

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
mod stub;

#[cfg(not(windows))]
pub use stub::*;

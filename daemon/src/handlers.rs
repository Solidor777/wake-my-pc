//! OS-handler capability surface, expressed as an injectable trait.
//!
//! Why a trait: `dispatch` runs Sleep / Lock / PowerOff against the host
//! OS. Calling those for real inside `cargo test` would actually suspend
//! the developer's machine. The trait lets production wire the real
//! Win32 / IOKit / DBus calls while integration tests inject a mock that
//! records what was invoked and returns canned results.
//!
//! Production impl is [`PlatformHandlers`] — a unit struct that delegates
//! to the free functions in [`crate::platform`]. The free functions
//! remain the canonical OS-call site (see `daemon/src/platform/mod.rs`);
//! this module is a thin trait wrapper, not a parallel implementation.

use wake_my_pc_core::protocol::PcState;

use crate::error::OsHandlerError;
use crate::platform;

/// Daemon-wide OS-action capability. Carried by `SharedState` so the
/// per-connection dispatch loop can call into it without knowing whether
/// it's hitting real OS APIs or a test mock.
///
/// Dyn-compatible: every method takes `&self`, returns a concrete type,
/// and is non-generic.
pub trait Handlers: Send + Sync + 'static {
    /// One-time daemon-startup setup. On Windows this enables
    /// `SE_SHUTDOWN_NAME`; on stub platforms it's a no-op. Production
    /// callers tolerate a non-fatal `Err` (only PowerOff depends on it).
    fn prepare(&self) -> Result<(), OsHandlerError>;

    /// Suspend the host. Returns immediately; the OS schedules the suspend.
    fn sleep(&self) -> Result<(), OsHandlerError>;

    /// Lock the active session.
    fn lock(&self) -> Result<(), OsHandlerError>;

    /// Power off the host. May return `NotPermitted` if the daemon's
    /// process token never had `SE_SHUTDOWN_NAME` enabled (Windows) or
    /// the equivalent capability on other OSes.
    fn power_off(&self) -> Result<(), OsHandlerError>;

    /// Probe the current session and map to a 5-state. Cheap; called
    /// per `StateProbe` request.
    fn current_session_state(&self) -> Result<PcState, OsHandlerError>;
}

/// Production handlers — delegates to the per-OS free functions in
/// `crate::platform`. Zero-sized; cloneable via `Arc`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformHandlers;

impl Handlers for PlatformHandlers {
    fn prepare(&self) -> Result<(), OsHandlerError> {
        platform::prepare()
    }

    fn sleep(&self) -> Result<(), OsHandlerError> {
        platform::sleep()
    }

    fn lock(&self) -> Result<(), OsHandlerError> {
        platform::lock()
    }

    fn power_off(&self) -> Result<(), OsHandlerError> {
        platform::power_off()
    }

    fn current_session_state(&self) -> Result<PcState, OsHandlerError> {
        platform::current_session_state()
    }
}

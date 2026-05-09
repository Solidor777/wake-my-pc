//! macOS + Linux placeholder. These OSes get their own sessions per PLAN.md
//! M2 multi-platform note. Until then, every handler returns `OsApi` so
//! the daemon honestly reports failure rather than silently no-op'ing.

use wake_my_pc_core::protocol::PcState;

use crate::error::OsHandlerError;

const NOT_IMPLEMENTED: &str = "OS handler not implemented on this platform yet (M2 Win-only)";

/// One-time setup at daemon startup. On Windows this enables
/// `SE_SHUTDOWN_NAME`; here it's a no-op.
pub fn prepare() -> Result<(), OsHandlerError> {
    Ok(())
}

/// Put the PC to sleep. Stub.
pub fn sleep() -> Result<(), OsHandlerError> {
    Err(OsHandlerError::OsApi {
        detail: NOT_IMPLEMENTED.into(),
    })
}

/// Lock the active session. Stub.
pub fn lock() -> Result<(), OsHandlerError> {
    Err(OsHandlerError::OsApi {
        detail: NOT_IMPLEMENTED.into(),
    })
}

/// Shut down the PC. Stub.
pub fn power_off() -> Result<(), OsHandlerError> {
    Err(OsHandlerError::OsApi {
        detail: NOT_IMPLEMENTED.into(),
    })
}

/// Probe the current 5-state. Stub returns OnLoggedIn so unit tests on
/// non-Windows can still construct a meaningful StateReport.
pub fn current_session_state() -> Result<PcState, OsHandlerError> {
    Ok(PcState::OnLoggedIn)
}

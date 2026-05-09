//! Windows OS handlers. PLAN.md M2 → "OS state-change APIs per platform".
//!
//! All `unsafe` blocks here wrap Win32 FFI; each carries a `// SAFETY:`
//! comment per Principle 2. The blast radius of these calls is high
//! (sleep/lock/shutdown the host); errors convert to typed
//! [`OsHandlerError`] and never panic.
//!
//! Privilege model: PowerOff requires `SE_SHUTDOWN_NAME` enabled on the
//! daemon process token. [`prepare`] enables it once at startup;
//! attempting PowerOff without prepare succeeded surfaces as `NotPermitted`.
//!
//! Session state: M2 baseline returns a coarse `OnLoggedIn`/`OnLoggedOut`
//! by checking for an active console session. Full `OnLocked` distinction
//! via `WTSSessionInfoEx` lock flags is tracked in TODO.md as an M2
//! follow-up — the protocol has the variant; the daemon just doesn't
//! emit it yet.

use std::ptr::null_mut;
use std::sync::OnceLock;

use wake_my_pc_core::protocol::PcState;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Power::SetSuspendState;
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Shutdown::{
    EWX_FORCE, EWX_POWEROFF, ExitWindowsEx, LockWorkStation, SHTDN_REASON_FLAG_PLANNED,
    SHTDN_REASON_MAJOR_OTHER, SHTDN_REASON_MINOR_OTHER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::OsHandlerError;

/// Tracks whether [`prepare`] has run successfully. PowerOff refuses to
/// proceed otherwise.
static SHUTDOWN_PRIVILEGE_READY: OnceLock<bool> = OnceLock::new();

/// One-time daemon-startup setup. Enables `SE_SHUTDOWN_NAME` on the
/// process token so [`power_off`] can later call `ExitWindowsEx`.
pub fn prepare() -> Result<(), OsHandlerError> {
    if SHUTDOWN_PRIVILEGE_READY.get().copied().unwrap_or(false) {
        return Ok(());
    }
    enable_shutdown_privilege()?;
    let _ = SHUTDOWN_PRIVILEGE_READY.set(true);
    Ok(())
}

/// Put the PC to sleep via `SetSuspendState(FALSE, FALSE, FALSE)`.
/// Returns immediately; OS schedules the suspend.
pub fn sleep() -> Result<(), OsHandlerError> {
    // SAFETY: SetSuspendState takes 3 BOOLEAN values; no pointers, no
    // out-params. Cannot violate memory safety.
    let ok = unsafe { SetSuspendState(0, 0, 0) };
    if ok == 0 {
        return Err(OsHandlerError::OsApi {
            detail: format!("SetSuspendState failed: error {}", last_err()),
        });
    }
    Ok(())
}

/// Lock the active session via `LockWorkStation`.
pub fn lock() -> Result<(), OsHandlerError> {
    // SAFETY: LockWorkStation takes no arguments and returns a BOOL.
    // No memory safety surface.
    let ok = unsafe { LockWorkStation() };
    if ok == 0 {
        return Err(OsHandlerError::OsApi {
            detail: format!("LockWorkStation failed: error {}", last_err()),
        });
    }
    Ok(())
}

/// Power off the PC via `ExitWindowsEx(EWX_POWEROFF | EWX_FORCE, ...)`.
/// Requires [`prepare`] to have enabled the shutdown privilege; without
/// it returns `NotPermitted`.
pub fn power_off() -> Result<(), OsHandlerError> {
    if !SHUTDOWN_PRIVILEGE_READY.get().copied().unwrap_or(false) {
        return Err(OsHandlerError::NotPermitted {
            detail: "SE_SHUTDOWN_NAME not enabled — call prepare() at startup".into(),
        });
    }
    // SAFETY: ExitWindowsEx takes two u32 flags; no pointers. The flags
    // EWX_POWEROFF | EWX_FORCE are documented constants from windows-sys.
    let ok = unsafe {
        ExitWindowsEx(
            EWX_POWEROFF | EWX_FORCE,
            SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED,
        )
    };
    if ok == 0 {
        return Err(OsHandlerError::OsApi {
            detail: format!("ExitWindowsEx failed: error {}", last_err()),
        });
    }
    Ok(())
}

/// Probe the current console session and map to a coarse 5-state.
///
/// M2 baseline: `OnLoggedIn` if there's an active console session
/// (`WTSGetActiveConsoleSessionId` returns a valid id), `OnLoggedOut`
/// otherwise. Locked-vs-unlocked discrimination is M2 follow-up via
/// `WTSSessionInfoEx` — see TODO.md.
pub fn current_session_state() -> Result<PcState, OsHandlerError> {
    // SAFETY: WTSGetActiveConsoleSessionId takes no args and returns a u32.
    // 0xFFFFFFFF means no session is currently attached to the console.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFF_FFFF {
        return Ok(PcState::OnLoggedOut);
    }
    Ok(PcState::OnLoggedIn)
}

fn enable_shutdown_privilege() -> Result<(), OsHandlerError> {
    // SE_SHUTDOWN_NAME = "SeShutdownPrivilege" as a wide string.
    let name: Vec<u16> = "SeShutdownPrivilege\0".encode_utf16().collect();

    let mut token: HANDLE = null_mut::<core::ffi::c_void>().cast();

    // SAFETY: GetCurrentProcess returns a pseudo-handle that doesn't need
    // closing; OpenProcessToken writes to `token` only on success. We pass
    // valid pointers with correct sizes.
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    };
    if ok == 0 {
        return Err(OsHandlerError::OsApi {
            detail: format!("OpenProcessToken failed: error {}", last_err()),
        });
    }

    // SAFETY: name is a null-terminated UTF-16 buffer; LookupPrivilegeValueW
    // writes to `luid` only on success. Returned token is owned by us and
    // closed below.
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = unsafe { LookupPrivilegeValueW(null_mut(), name.as_ptr(), &mut luid) };
    if ok == 0 {
        // SAFETY: token is a valid handle from OpenProcessToken above.
        unsafe { CloseHandle(token) };
        return Err(OsHandlerError::OsApi {
            detail: format!("LookupPrivilegeValueW failed: error {}", last_err()),
        });
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: tp is on the stack with a valid layout. Other pointer args
    // are documented as optional and accept null. AdjustTokenPrivileges
    // returns BOOL but ALSO sets ERROR_NOT_ALL_ASSIGNED via GetLastError
    // even on a non-zero return — we check both.
    let ok = unsafe { AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut()) };
    let err = last_err();

    // SAFETY: token is a valid handle from OpenProcessToken.
    unsafe { CloseHandle(token) };

    if ok == 0 {
        return Err(OsHandlerError::OsApi {
            detail: format!("AdjustTokenPrivileges failed: error {err}"),
        });
    }
    // ERROR_NOT_ALL_ASSIGNED = 1300. Means the user-mode daemon process
    // doesn't have SeShutdownPrivilege available to enable — typically
    // because the install was as a low-rights user without the rights
    // assigned. Surface as NotPermitted so the caller can log + tell user.
    if err == 1300 {
        return Err(OsHandlerError::NotPermitted {
            detail: "process token does not hold SeShutdownPrivilege".into(),
        });
    }
    Ok(())
}

fn last_err() -> u32 {
    // SAFETY: GetLastError takes no args and returns a u32 from TLS.
    unsafe { GetLastError() }
}

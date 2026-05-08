// uniffi-generated FFI shims live in the proc-macro expansion below;
// we never write raw `unsafe extern "C"` here. Principle 2.
#![forbid(unsafe_code)]

uniffi::setup_scaffolding!();

/// Smoke-test FFI surface. Mobile shells call this on launch to prove the
/// `core` crate is linked through bindings. Replaced with real protocol API
/// in M1.
#[uniffi::export]
#[must_use]
pub fn hello() -> String {
    wake_my_pc_core::hello().to_string()
}

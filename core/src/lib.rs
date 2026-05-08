// Principle 2: core forbids unsafe entirely. FFI lives in `bindings/`,
// platform syscalls live in `daemon/` and `desktop-ui/`.
#![forbid(unsafe_code)]

/// Smoke-test surface used by every consumer (`daemon`, `desktop-ui`,
/// `bindings`, and the mobile shells via uniffi) to prove the dep graph
/// links. Replaced with real protocol API in M1.
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

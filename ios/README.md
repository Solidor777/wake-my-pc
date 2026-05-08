# iOS shell — placeholder

Status (2026-05-08): **scaffold not yet created.** This directory exists so the M0 layout matches PLAN.md. The real Xcode project + Swift Package + SwiftUI app must be created on macOS — that work was deferred from M0 because the development machine is Windows and Xcode isn't available.

## What an agent on macOS should do next

1. **Generate Swift bindings from uniffi.** From the workspace root:
   ```
   cargo run --bin uniffi-bindgen -- generate \
     --library target/debug/libwake_my_pc_bindings.dylib \
     --language swift \
     --out-dir ios/Generated
   ```
   This produces `wake_my_pc_bindings.swift` + a modulemap. Add both to the Xcode project as a Swift Package or directly to the target.

2. **Build the static lib for iOS targets** (Simulator + device). Add the iOS triples to rustup:
   ```
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   ```
   Then build per-target with `--release` and lipo the results into a single `.a` linked from the Xcode target.

3. **Create the SwiftUI app.** Single view, calls `hello()` from the bindings, displays the result. M0 smoke test only — the one-button UX comes in M4 per `docs/PLAN.md`.

4. **CI integration.** Update `.github/workflows/pre-release.yml` to run the iOS build on a `macos-latest` runner. Per-PR mobile CI is gated to a `mobile-ci` label per Principle 4 (softened CI clause).

## Constraints to preserve

- **Principle 1 (security):** the Swift side never stores private keys outside iOS Keychain. uniffi bindings expose only the safe surface; raw key material stays in `core`.
- **Principle 2 (memory & execution safety):** uniffi catches Rust panics at the FFI boundary by default. Verify this by adding a deliberate-panic test before declaring this milestone done. Swift code itself: no force-unwraps (`!`) in production paths.
- **Principle 3 (simplicity):** pairing flow is QR scan + 6-digit numeric fallback (locked decision). No additional setup screens.
- **Principle 4 (multiplatform):** ships in lockstep with Android. Don't merge an iOS-only feature.

## Why no skeleton files yet

Writing a `Package.swift` + Xcode project on Windows that we can't compile or open would be theater — it'd ship broken, get edited blind, and waste a Mac-side agent's time fixing it. An honest empty directory plus this README is the correct M0 state.

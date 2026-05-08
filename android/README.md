# Android shell — placeholder

Status (2026-05-08): **scaffold not yet created.** This directory exists so the M0 layout matches PLAN.md. The real Gradle project + Compose app must be created with the Android SDK + NDK installed — deferred from M0 because the development machine doesn't have those installed and validating without them would ship broken config.

## What an agent with Android SDK + NDK should do next

1. **Generate Kotlin bindings from uniffi.** From the workspace root:
   ```
   cargo run --bin uniffi-bindgen -- generate \
     --library target/debug/libwake_my_pc_bindings.so \
     --language kotlin \
     --out-dir android/app/src/main/java
   ```

2. **Build the shared lib for Android ABIs.** Add NDK triples:
   ```
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```
   Use `cargo-ndk` (or build per-triple manually) to produce `.so` files. Drop them in `android/app/src/main/jniLibs/<abi>/`.

3. **Create the Compose app.** Single Activity, calls `hello()` from the bindings on first composition, displays the result. M0 smoke test only — the one-button UX comes in M4 per `docs/PLAN.md`.

4. **CI integration.** Update `.github/workflows/pre-release.yml` to build Android on `ubuntu-latest` with the SDK + NDK provisioned. Per-PR mobile CI is gated to a `mobile-ci` label per Principle 4 (softened CI clause).

## Constraints to preserve

- **Principle 1 (security):** the Kotlin side never stores private keys outside Android Keystore. Use `MasterKey` + `EncryptedSharedPreferences` or direct Keystore APIs. uniffi exposes only the safe surface; raw key material stays in `core`.
- **Principle 2 (memory & execution safety):** uniffi catches Rust panics at the JNI boundary by default. Verify with a deliberate-panic test. Kotlin code: no `!!` in production paths; prefer `?:`/`?.let` over force-unwraps.
- **Principle 3 (simplicity):** pairing is QR + 6-digit numeric fallback (locked decision). No additional config screens.
- **Principle 4 (multiplatform):** ships in lockstep with iOS.

## Why no skeleton files yet

A `build.gradle.kts` + manifest + Compose stub written on a machine without the Android SDK would not actually parse against a real toolchain — version mismatches in the Gradle plugin, the NDK, the Kotlin compiler, and Compose are routine. Rather than ship config that "looks right" and breaks on first `./gradlew build`, this directory is empty and an SDK-equipped agent fills it in.

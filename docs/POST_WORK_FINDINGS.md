# Post-work findings

Living record per CLAUDE.md rules 6 + 10. Each entry: short title, 1–2 sentence summary, status. Status values: `open`, `accepted`, `resolved`, `superseded`.

For canonical decisions see `PRINCIPLES.md` and `PLAN.md` — entries here just flag what's notable to a future agent reading cold.

---

## Open

### M0 mobile scaffolding deferred
`ios/` and `android/` have READMEs only — no Xcode/Gradle project files. Windows machine M0 was built on lacks Xcode + Android SDK/NDK. Next pass on macOS (iOS) and any env with Android SDK + NDK (Android) fills in projects per the per-platform README. Until then, M0's "Simulator/emulator runs show 'core: hello'" exit criterion is unmet. **Status: open.**

### CI workflows unverified until first push
`per-pr.yml` and `pre-release.yml` are syntactically reasonable but neither has run against GitHub Actions. iOS/Android jobs in `pre-release.yml` will fail until mobile scaffolds exist — intentional. First push reveals any YAML mistakes. **Status: open.**

---

## Accepted (load-bearing — future agents should not "fix" these)

### `unsafe` is forbidden only in `core` and `bindings`, not the whole workspace
`desktop-ui` (eframe → winit/glow/wgpu) and `daemon` (Win32 / IOKit / DBus FFI) need `unsafe` for OS interop. Workspace lints set `unsafe_code = "warn"`, then `core` and `bindings` upgrade to `forbid` via crate-level attribute. Each `unsafe` block in `daemon`/`desktop-ui` requires `// SAFETY:` comment per Principle 2. The alternative — re-implementing windowing/GPU/OS sleep APIs in pure Rust — is dramatically worse for safety. **Status: accepted.**

### `cargo-audit` in per-PR CI as a Principle 1 supply-chain gate
Failing advisories block merge until dep is bumped or advisory is reviewed and ignored with justification. Heavier supply-chain hardening (`cargo-deny`, lock-file pinning policy) deferred to M1 when crypto deps land. **Status: accepted.**

### Auth gate is client-side, not server-side
Per-action biometric (M4 opt-in) gates on the *phone* (LocalAuthentication / BiometricPrompt) before the command goes over mTLS. Daemon doesn't see auth events — receives mTLS-authed commands as before. Phone biometric is a UX/anti-theft gate, not an additional cryptographic factor. **Status: accepted.**

### Re-auth and per-action biometric gate are independent layers
Per-action gate (default off) prompts on every command. Re-auth (default on, 7d) prompts every N days. Compose without conflict — both / neither / one. Default v1 state: re-auth ON (7d), per-action gate OFF. Don't conflate them. **Status: accepted.**

### WoL revocation: four-layer plan
Sleep/Lock/PowerOff are revoked cleanly by uninstall (daemon + keystore gone). Wake via WoL is BIOS/NIC-level and unauthenticated by spec — phone retaining the MAC can still wake post-uninstall. Defense in depth, all four ship in v1:
- **(d) Daemon-side revoke + persistent retry queue (most automatic).** `wake-my-pc-daemon revoke <phone>` flags revoked immediately, queues Revoke push; mDNS-driven retry; same routine fires from uninstaller (best-effort, no retry afterward). CLI-only for v1; tray-icon GUI deferred. PLAN.md M2 + M4.
- **(a) Phone-side Unpair (most reliable).** Settings → Unpair removes cert pin + stored MAC. User's primary cleanup path; works regardless of daemon state. PLAN.md M4.
- **(b) BIOS WoL-disable for air-gap revocation.** Documented in install docs + M5 onboarding. App can't enforce; we point at the BIOS setting.
- **(c) No daemon-layer WoL filter, by design.** Anything at daemon layer is moot post-uninstall; anything below is firmware. Explicit non-goal — future agents should not build a shim.

**Status: accepted.**

### resolver = "3" pinned at workspace level
Required for edition 2024 (introduced Cargo 1.84). **Status: accepted.**

---

## Superseded

### Remote-unlock — moved from "never" to M11 (2026-05-08)
Original stance: remote Unlock too risky to support. Superseded same day after user clarified the unlock button "should still work" given biometric gating and credential storage on phone. v1 stays one-way Lock; no `Unlock` opcode in v1.0 freeze. M11 (post-v1) ships Unlock with the locked design (Keychain/Keystore + mandatory biometric + per-OS feasibility caveats including macOS likely-infeasible). **Status: superseded — see PLAN.md M11 for canonical record.**

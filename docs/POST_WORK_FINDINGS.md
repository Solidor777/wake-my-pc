# Post-work findings

Living record per CLAUDE.md rules 6 + 10. Each entry: short title, 1–2 sentence summary, status. Status values: `open`, `accepted`, `resolved`, `superseded`.

For canonical decisions see `PRINCIPLES.md` and `PLAN.md` — entries here just flag what's notable to a future agent reading cold.

---

## Open

### M0 mobile scaffolding deferred
`ios/` and `android/` have READMEs only — no Xcode/Gradle project files. Windows machine M0 was built on lacks Xcode + Android SDK/NDK. Next pass on macOS (iOS) and any env with Android SDK + NDK (Android) fills in projects per the per-platform README. Until then, M0's "Simulator/emulator runs show 'core: hello'" exit criterion is unmet. **Status: open.**

### CI workflows unverified until first push
`per-pr.yml` and `pre-release.yml` are syntactically reasonable but neither has run against GitHub Actions. iOS/Android jobs in `pre-release.yml` will fail until mobile scaffolds exist — intentional. First push reveals any YAML mistakes. **Status: open.**

### Unmaintained transitive deps from postcard + uniffi
`cargo audit` reports three unmaintained-warnings (no vulnerabilities; exit 0): `atomic-polyfill 1.0.3` via heapless via postcard, `bincode 1.3.3` via uniffi_macros, `paste 1.0.15` via uniffi. Tracked in `TODO.md` as a watch item — bump becomes blocking only if any flips to a vulnerability advisory. M1 uses `cargo audit` (default) which fails on vulnerabilities only; `--deny warnings` is intentionally NOT used per Principle 1 supply-chain note (block on advisories that are real, not on maintainer-life-event noise). **Status: open.**

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

### M1 stack refinement: ed25519-dalek dropped, rcgen-via-ring is sufficient
Locked decision (2026-05-08, M1 kickoff): "rustls + ed25519-dalek + rcgen". Implementation refinement during M1: rcgen with the `ring` provider already manages Ed25519 keypair generation + PKCS#8 serialization end-to-end, so a direct `ed25519-dalek` dep is duplicate machinery. The Ed25519 algorithm is unchanged; only the crate that exposes it shifted. Drop is documented inline in `core/Cargo.toml`. **Status: accepted.**

### M1: TLS resumption disabled by configuration
PROTOCOL.md §5 specifies fresh handshake per session; rustls config disables session tickets, server session storage, and 0-RTT (`max_early_data_size = 0`). One extra handshake per reconnect is acceptable on a one-button-LAN-app, and the tradeoff buys clean per-session nonce reset and removes a class of cross-session replay risk. **Status: accepted.**

### M1: 6-digit fallback requires SPKI hash entry alongside the code
PROTOCOL.md §8 codifies that the 6-digit pairing code is a one-time PIN, NOT a hash commitment. Without the SPKI hash typed in alongside the code, an active LAN MITM at pairing time could substitute their own cert. The home-LAN threat model accepts this (pairing is a deliberate one-shot in a known location); QR path is the strong default; users on headless installs are the rare case. Future agents should not "fix" this by treating the 6-digit as a SAS commitment without bumping the protocol version. **Status: accepted.**

### M1: SPKI pinset is Arc-immutable; pairing changes rebuild rustls config
`PinSet` is shared via `Arc` and immutable per TLS-config build. To hot-add a pairing the daemon (M2) must rebuild its `ServerConfig` and either restart the listener or use rustls's `Acceptor`-with-config-callback path. The pairing path is rare enough that a config rebuild is cheap; the alternative (interior mutability across an Arc-shared verifier) is harder to reason about. **Status: accepted.**

### M1: MSRV bumped 1.85 → 1.88 for time-crate advisory
RUSTSEC-2026-0009 (medium-severity DoS via stack exhaustion in `time`) has its fix in `time 0.3.47`, which requires Rust 1.88. Workspace MSRV bumped to 1.88; CI uses `dtolnay/rust-toolchain@stable` so no infra impact. Principle 1's supply-chain gate trumps an MSRV preference; future advisory-driven bumps follow the same rule. Documented inline in workspace `Cargo.toml`. **Status: accepted.**

### M1 post-review fix: pairing brute-force bound enforced in state machine
Security review surfaced that `PairingHandshake::accept_pair` left the window open after wrong-code rejections, deferring rate-limit policy to the M2 daemon caller — a silent deferral. Fixed inline (CLAUDE.md rule 7): `PairingState::Awaiting` now carries `failed_attempts: u8`; after `MAX_PAIRING_ATTEMPTS = 5` wrong-or-out-of-range codes the state machine returns to `Idle` and forces a fresh `daemon-cli pair`. Combined with the 6-digit canonical form (next entry), gives ≤5×10⁻⁶ success per window — sound out of the box without daemon-side lockout. New `PairingRejection` variants: `TooManyAttempts`, `OutOfRange`. Tests cover both. **Status: accepted.**

### M1 post-review fix: `pairing_code` canonical 6-digit form
Pre-fix mismatch: `random_pairing_code` produced a full `u32` from `getrandom`; PROTOCOL.md §8 said the user-visible code was `pairing_code % 1_000_000`. Headless-path manual entry could only carry the 6 digits, so the daemon's `offered_code != stored_code` compare matched only ~1/4296 of the time (when the daemon happened to roll a value `< 1_000_000`). Fixed: `random_pairing_code` now rejection-samples to produce a value in `0..1_000_000`; the wire `pairing_code` field IS the 6-digit value (no separate "internal" representation). PROTOCOL.md §8 updated to drop the modulo-display fiction. The KAT vector for `Pair` (`pairing_code: 7`) is unaffected — 7 is a valid 6-digit value and the wire bytes are identical. **Status: accepted.**

### M1: PROTOCOL.md not embedded as crate doc via `include_str!`
Initial M1 attempt added `#![doc = include_str!("../../docs/PROTOCOL.md")]` to `core/src/lib.rs` so rustdoc would render the spec. rustdoc tries to compile fenced code blocks as doctests, and the spec contains illustrative-not-compilable Rust (`struct QrPayload { lan_hint: SocketAddrV4, ... }` with no imports) plus EBNF-style schema (`frame := len:u32 || ...`) — both fail the doctest pass. Pulled. The spec lives at `docs/PROTOCOL.md`; module-level docs link to it by file path, which is sufficient for the agent-cold-read use case. **Status: resolved.**

---

## Superseded

### Remote-unlock — moved from "never" to M11 (2026-05-08)
Original stance: remote Unlock too risky to support. Superseded same day after user clarified the unlock button "should still work" given biometric gating and credential storage on phone. v1 stays one-way Lock; no `Unlock` opcode in v1.0 freeze. M11 (post-v1) ships Unlock with the locked design (Keychain/Keystore + mandatory biometric + per-OS feasibility caveats including macOS likely-infeasible). **Status: superseded — see PLAN.md M11 for canonical record.**

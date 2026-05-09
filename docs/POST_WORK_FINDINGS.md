# Post-work findings

Living record per CLAUDE.md rules 6 + 10. Each entry: short title, 1–2 sentence summary, status. Status values: `open`, `accepted`, `resolved`, `superseded`.

For canonical decisions see `PRINCIPLES.md` and `PLAN.md` — entries here just flag what's notable to a future agent reading cold.

---

## Open

- **M0 mobile scaffolding deferred.** `ios/` and `android/` have READMEs only (no Xcode/Gradle projects). Blocked on Mac + Android SDK/NDK host. M0 mobile exit criterion ("Simulator/emulator runs show 'core: hello'") unmet.
- **CI workflows verified by first push 2026-05-08.** `per-pr.yml` + `pre-release.yml` first ran on the M1 push. Status check on Actions tab is the user's call (gh CLI unauthenticated locally). iOS/Android jobs in `pre-release.yml` will fail until mobile scaffolds land — intentional.
- **TLS 1.3 client-side handshake completes optimistically (M2 finding).** TLS 1.3 client `connect()` returns `Ok` after sending Finished, BEFORE the server runs `verify_client_cert`. Server reject arrives later as a TLS alert on next `read`/`write`. Tests exchange a real frame (`try_send_state_probe` in `daemon/tests/integration.rs`) to observe rejection. Future TLS-mTLS tests must follow the same pattern.
- **`pair`/`serve` port contention (M2).** Both subcommands bind the configured port; user must stop `serve` before `pair`. Multi-device pairing itself works (re-pair re-uses the keystore identity). Unification ⇒ `TODO.md` "pair while serve is running".
- **Unmaintained transitive deps (postcard + uniffi).** `cargo audit` exit 0 with 3 warnings (atomic-polyfill, bincode, paste). Watch item in `TODO.md`; not blocking. `--deny warnings` is NOT used — Principle 1 gates on real advisories, not maintainer-life-event noise.

---

## Accepted (load-bearing — future agents should not "fix" these)

- **M2 dispatch goes through `daemon::Handlers` trait, not free functions.** `server::connection::dispatch` calls `state.handlers().sleep()` etc.; the trait sits on `SharedState`. `PlatformHandlers` is the production impl — a thin wrapper over `crate::platform::*` free functions, which remain the canonical OS-call site. Tests inject a recording mock via `run_server_with_listener_and_handlers`. Don't reintroduce direct `platform::sleep()` calls in dispatch — that re-breaks the integration-test surface.
- **Windows lock-state semantics: SessionFlags 0=locked, 1=unlocked (post-KB2533690).** `daemon::platform::windows::current_session_state` queries `WTSSessionInfoEx` and reads `WTSINFOEX_LEVEL1_W::SessionFlags`. Pre-Win7-SP1 / pre-KB2533690 systems had the senses inverted; we don't support those. Only `SessionState == WTSActive` qualifies as a logged-in user; other connect states (Connected/Disconnected/Init) collapse to `OnLoggedOut`. API failure falls back to `OnLoggedIn` rather than risk a false `OnLocked`.
- **`unsafe` forbidden in `core` + `bindings` only.** `daemon` and `desktop-ui` need OS-FFI `unsafe` (Win32 / IOKit / DBus / winit-glow). Workspace lint `unsafe_code = "warn"`; `core` + `bindings` upgrade to `forbid` via crate-level attribute. Each block requires `// SAFETY:` comment.
- **`cargo audit` is the per-PR supply-chain gate.** Failing advisories block merge. Heavier hardening (`cargo-deny`, pinning policy) deferred until at least M5.
- **Auth gate is client-side, not server-side.** M4 per-action biometric prompts the *phone* (LocalAuthentication / BiometricPrompt) before the command crosses mTLS. Daemon receives mTLS-authed commands as before — biometric is a UX/anti-theft gate, not a cryptographic factor.
- **Re-auth and per-action biometric are independent layers.** Re-auth = every-N-days re-prompt (default ON, 7d). Per-action gate = every-command re-prompt (default OFF). Both compose without conflict — don't conflate them.
- **WoL revocation: four-layer plan.** Canonical record in `PRINCIPLES.md` §1 ("Revocation is layered"). Future agents must not build a daemon-layer WoL filter — explicit non-goal.
- **`resolver = "3"`** at workspace level — required for edition 2024.
- **M1: ed25519-dalek dropped; rcgen-via-ring is sufficient.** Locked stack ("rustls + ed25519-dalek + rcgen") refined during M1 — rcgen with `ring` provider manages Ed25519 keypair + PKCS#8 end-to-end. Algorithm unchanged; one less crate.
- **M1: TLS resumption disabled.** rustls config zeros session tickets, server session storage, and 0-RTT (`max_early_data_size = 0`) per PROTOCOL.md §5. One extra handshake per reconnect; clean per-session nonce reset; removes cross-session replay risk.
- **M1: 6-digit fallback requires SPKI-hash co-entry.** PROTOCOL.md §8 — code is a one-time PIN, NOT a hash commitment. Without the SPKI typed alongside, an active LAN MITM at pairing time could substitute a cert. Home-LAN threat model accepts this; QR path is the strong default. Don't "fix" this by treating the 6-digit as a SAS commitment without bumping protocol version.
- **M1: `PinSet` is Arc-immutable.** Hot-add a pairing ⇒ daemon rebuilds its `ServerConfig`. Listener does this per accept (cheap; pairing path is rare).
- **M1: MSRV 1.85 → 1.88 for `time` advisory.** RUSTSEC-2026-0009 fix ships in `time 0.3.47`, requires 1.88. CI uses stable so no infra impact. Future advisory-driven bumps follow the same precedent.
- **M1 post-review: pairing brute-force bound in state machine.** `PairingState::Awaiting` carries `failed_attempts: u8`; after `MAX_PAIRING_ATTEMPTS = 5` wrong/out-of-range codes the state machine forces back to `Idle`. Bound is in core, not deferred to the daemon caller. New `PairingRejection` variants: `TooManyAttempts`, `OutOfRange`.
- **M1 post-review: `pairing_code` is canonically 6-digit (`0..1_000_000`).** No separate "internal full-u32" form — the wire field IS the 6-digit value. `random_pairing_code` rejection-samples. PROTOCOL.md §8 has the canonical spec.
- **M1: PROTOCOL.md not embedded via `include_str!`.** rustdoc compiles fenced code blocks; the spec contains illustrative-not-compilable Rust + EBNF. Module docs link by file path instead. **Status: resolved.**

---

## Superseded

- **Remote-unlock: "never" → M11 (2026-05-08).** Original stance was no-Unlock-ever. Same-day reversal after user accepted the biometric-gated, credential-on-phone tradeoff. v1.0 ships one-way Lock (no `Unlock` opcode); M11 ships Unlock per its locked design. Canonical record: PLAN.md M11.

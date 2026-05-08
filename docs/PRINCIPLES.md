# Principles

Engine-wide invariants. Source of truth — `PLAN.md` schedules work against these; `POST_WORK_FINDINGS.md` records violations surfaced during review. Conflicts with these principles block merge until resolved or principle is explicitly amended here.

---

## 1. Security — owner-only, encrypted end-to-end

**Invariant:** only the human who installed the server on a given PC can wake or sleep that PC. No other actor — including Anthropic, the network operator, an attacker on the LAN, a stolen phone without the owner's unlock, or a future maintainer of this repo — can issue a wake or sleep command.

**Why:** the app remotely toggles a personal computer. A compromised auth path means an attacker can keep your PC awake to mine, exfiltrate, or join a botnet — or sleep it during a critical task. Wake-on-LAN's magic packet is itself unauthenticated, so all authentication and authorization must live at the orchestration layer above WoL. There is no "low-stakes" failure mode; security regressions ship as P0 bugs.

**How to apply:**
- **Mutual authentication.** Every wake/sleep command is cryptographically bound to a specific (client device, server install) pair established at pairing time. Pre-shared symmetric secrets or device-bound asymmetric keypairs — never username/password, never a shared cloud account.
- **Encrypted in transit.** All client↔server traffic uses authenticated encryption (TLS 1.3 or equivalent AEAD). No plaintext fallback, no downgrade path.
- **Encrypted at rest.** Any persisted credential (private keys, paired-device records, server tokens) is stored in the platform's strongest available keystore. iOS Keychain, Android Keystore, Windows DPAPI/TPM, macOS Keychain are all hardware-backed where the device supports it — these are mandatory. Linux is uneven: Secret Service requires a session bus (no good answer for headless servers), kernel keyring is volatile across reboots — see TODO.md for the open design question. The minimum bar everywhere is: never plaintext on disk, never in config we serialize ourselves.
- **Replay-protected.** Every command carries a nonce or monotonic counter; the server rejects reused or out-of-order commands. A captured packet must not be replayable.
- **No identifying info in git.** Hostnames, MAC addresses, public keys, paired device IDs, server URLs, screenshots showing them — none of these get committed. CLAUDE.md rule 0 enforces this; PRINCIPLES.md elevates it. CI must fail if a candidate identifier slips into a tracked file.
- **No telemetry by default.** No analytics, no crash reporters phoning home, no third-party SDKs that observe usage. If we ever add opt-in telemetry, it ships off by default and is documented in PLAN.md before merge.
- **Defense in depth at the WoL packet too.** The magic packet itself is unauthenticated by spec, so we treat the LAN as untrusted: the *trigger* to send a magic packet must be authenticated upstream of the LAN broadcast.
- **Uninstall is clean revocation.** Removing the daemon from a PC must remove the keystore (private keys + paired-device records), the service registration, and the binary itself. After uninstall, no previously-paired phone can issue Sleep / Lock / PowerOff commands against that PC — the daemon isn't there to receive them, and the key material to authenticate them is gone. Reinstalling generates fresh device keys, so every previously-paired phone must re-pair from scratch; old pins do not survive the reinstall. **Revocation is layered** (locked plan; all four ship in v1):
  - **Daemon-side revoke with persistent retry queue.** A daemon CLI (`wake-my-pc-daemon revoke <phone>`) flags a pairing as revoked **immediately** — daemon stops authenticating that phone instantly, regardless of whether the phone ever receives a notification. The daemon then queues a Revoke push to the phone; whenever it sees the phone on LAN it retries until ack'd, at which point the phone wipes its stored MAC and the daemon removes the pairing entry entirely. The uninstaller invokes the same routine to broadcast Revoke to every paired phone before wiping the keystore — best-effort with no retry afterward, since the daemon is going away. Reachable phones get cleaned up automatically; unreachable phones at uninstall time fall through to the next layers. (PLAN.md M2 for the daemon side, M4 for the phone receiver.)
  - **Phone-side Unpair revokes WoL too.** Settings → Unpair on the phone removes the stored MAC alongside the cert pin. The user's primary cleanup path — works regardless of whether the daemon is alive, online, or even installed. An unpaired phone has nothing left to send — no auth'd command, no magic packet. (PLAN.md M4.)
  - **BIOS WoL-disable for full air-gap revocation.** Documented in install docs and M5 onboarding for users who want certainty that a previously-paired phone with a retained MAC still cannot wake the PC. The app cannot enforce this — WoL is firmware-level — but we tell users where to find it.
  - **No daemon-layer WoL filter.** We do not engineer a magic-packet-blocking shim. Anything at the daemon layer is moot post-uninstall (daemon's gone), and anything below is firmware. The architectural non-decision is intentional — future agents should not try to build it.

**Aspirational framing.** "100% safe" is not a literal claim — it's the standard we measure against. We state an attack and prove our design refuses it; if we can't, the design changes.

---

## 2. Memory & execution safety — never crash

**Invariant:** the app does not crash. Not on the phone, not on the PC daemon, not at FFI boundaries. Memory-safety bugs are forbidden; logic errors that would otherwise panic must convert to user-visible `Result`s the UI can render gracefully.

**Why:** a phone app that crashes is uninstalled. A daemon that crashes is silently failing — the user discovers the regression by walking to their PC. Both undermine trust in a single-button app where the trust budget is already zero. Rust's memory model gives us a head start on memory safety, but it doesn't prevent panics, unwraps in code paths we forgot, integer overflow at boundaries, or unhandled OS API failures. Discipline is required.

**How to apply:**
- **No `.unwrap()` / `.expect()` in non-test code.** Enforced via `clippy::unwrap_used` and `clippy::expect_used` lints set to deny in `core/`, `daemon/`, `desktop-ui/`, `bindings/`. Tests are exempt — panicking *is* the test failure.
- **No `panic!()` in production paths.** Acceptable only at startup-time invariant checks (e.g., binary built without an expected feature flag) where exiting is the correct behavior anyway.
- **All errors are `Result` types with exhaustive enums.** A function that can fail returns `Result<T, E>` where `E` is a defined error enum. No `Box<dyn Error>` in `core` (binary boundaries may use it for human-facing diagnostics).
- **FFI boundaries catch panics.** Rust → Swift/Kotlin via uniffi: any panic that escapes user code is caught at the FFI boundary and converted to a binding-layer error, never aborting the host process.
- **Daemon supervises itself.** If the daemon process does die for unrecoverable reasons (OOM, segfault from a transitive C dep, OS API misuse we couldn't predict), the OS service manager (systemd / launchd / SCM) restarts it. Documented and proven in M2 integration tests.
- **Untrusted inputs are validated at the boundary.** Network bytes, filesystem reads, environment variables, command-line arguments — parsed defensively. Malformed input produces a typed error, never a panic.
- **Integer arithmetic is `checked_*` / `saturating_*` where it matters.** Default Rust wrapping is acceptable for protocol counters that semantically require wrap. For lengths, indices, durations, and any arithmetic on untrusted input: explicit checked or saturating ops.
- **`unsafe` is forbidden outside justified, audited blocks.** `#![forbid(unsafe_code)]` in `core` and `bindings`. `daemon` and `desktop-ui` may use `unsafe` only with a `// SAFETY:` comment documenting the invariants (typically FFI to OS APIs like Win32 `SetSuspendState`).
- **Crash-test the binaries.** Fuzz the protocol parser (`cargo-fuzz` in CI). Property-test the state machine. M5 acceptance includes a "throw garbage at every input" pass.

**Aspirational framing.** "Never crash" is the standard. A bug that panics in production is a P0 fix the same way a security regression is.

---

## 3. Simplicity — state-aware dashboard, one default action

**Invariant:** the steady-state user experience is a state-aware dashboard with **one default action button** (sleep toggle). The dashboard shows the current PC state — one of `Off`, `Sleeping`, `On / Logged Out`, `On / Locked`, `On / Logged In`. The default action button toggles sleep: tap when `On / *` to sleep; tap when `Sleeping` or `Off` to wake (WoL packet). Sleep ↔ wake transitions emit notifications by default. **Re-authentication is required every 7 days by default** on both phone and PC sides — biometric on phone (Face/Touch ID, with passcode fallback); platform credential on PC (Hello, Touch ID, polkit). Pre-expiry notifications at -3 days, -1 day, day-of; user can extend manually at any time. That is the entire happy-path surface.

**Why:** the value proposition is "I don't want to walk to my PC to press the power button." The moment we ask the user to remember a hostname, pick a server from a list, interpret a status code, or hunt through a menu for the right action, we've lost. Simplicity is not a polish phase — it's a constraint that shapes what features can exist at all. State display is not a feature add — it's part of the action surface (the button is meaningless without state context).

**How to apply:**
- **One default action button on the dashboard.** No mode switcher, no separate wake/sleep buttons in the default view, no menu. The button's affordance changes with PC state (different label, color, or icon — TBD in `ui-egui` design pass), but it is one button.
- **Default-on notifications are limited to sleep ↔ wake and re-auth pre-expiry.** Sleep/wake notifications close the loop on the default button's action. Re-auth pre-expiry notifications (-3d / -1d / day-of) prevent silent lockout — the user always gets warned before the PC stops accepting commands. No other state transitions notify by default.
- **Pairing happens once.** Initial setup (scan QR / enter 6-digit code) is a one-time flow. After that the user never sees configuration in normal use.
- **No settings the happy path needs.** A settings screen exists for unpair / re-pair / multiple PCs / opt-in features below, but the default user with one paired PC never opens it.
- **Optional features are opt-in and default off.** Specifically:
  - Toggle button for `Power Off` (daemon-mediated shutdown). Power-on is via WoL — already covered by the default sleep-toggle button when state is `Off`, since "wake from off" and "wake from sleep" both send a WoL packet.
  - Toggle button for `Lock` (v1: one-way; locks when unlocked). Remote unlock arrives post-v1 in M11 as an opt-in with mandatory biometric gate and explicit security disclosure — see `PLAN.md` M11. Until then, unlocking requires walking to the PC.
  - Per-action platform-auth gate — require a biometric on the phone (Face ID / Touch ID / Windows Hello on the client side, depending on phone OS) before sending any state-change command. Default off; user enables per-action.
  - Per-state-change notifications beyond sleep/wake (notify on `Off`, `On / Locked`, `On / Logged In` transitions). Default off.
- **Multiple paired PCs is a secondary surface.** If the user pairs more than one, they pick from a short list — but the per-PC view is still the dashboard. Picking a PC scales with how many PCs you own, not with the complexity of the action.
- **Errors are one line.** "Can't reach PC" / "Paired device not authorized" — short, in plain language, never a stack trace or error code as the primary content.
- **New features default to "no" — including new optional features.** The opt-ins listed above are the v1 boundary; any feature beyond them gets challenged against this principle in review. The bar is: would removing this make the app worse for the median user? If unclear, defer to TODO.md.

---

## 4. Multiplatform — all platforms, day 1

**Invariant:** every release ships simultaneously on all five target platforms. Client: Android + iOS. Server: Windows + macOS + Linux. No "Android-first then iOS later," no "Windows is primary, others are best-effort." Feature parity is a release blocker.

**Why:** a "wake my PC" app that doesn't work on the user's specific phone or PC is useless to that user — there's no graceful degradation, no partial value. Picking a primary platform creates a maintenance gradient where the others rot. Forcing parity from day 1 keeps the architecture honest: any feature must be expressible on every platform before it can ship anywhere.

**How to apply:**
- **Day-1 platforms (release blockers):** iOS, Android, Windows, macOS, Linux. A feature that works on four of five does not ship until the fifth is done or the feature is cut.
- **Shared core where feasible.** Implementation strategy (single Rust core + thin platform shells, cross-platform UI framework, or separate native apps with a shared protocol spec) is an architectural decision deferred to PLAN.md and explicit confirmation per CLAUDE.md rule 5. PRINCIPLES.md only mandates the *outcome* (parity), not the *mechanism*.
- **Protocol versioned, stable before second consumer.** The wire protocol between client and server is platform-neutral. The first consumer (typically the PC daemon) may evolve the protocol freely while it's the only consumer — but the moment a second platform begins consuming it, the protocol freezes at a versioned `v1.0` and any further change goes through a normal versioning bump. This catches the failure mode where the protocol accidentally shapes itself around one platform's idioms, without paying the cost of locking it in before any consumer exists.
- **CI gates all five at release.** Every release tag must pass build + test on all five targets — that is the hard gate. Per-PR CI runs the cheap subset (core crate + desktop targets on Linux/macOS/Windows runners); mobile builds (iOS Simulator, Android emulator) run on a pre-release workflow and on-demand via a `mobile-ci` label. Rationale: macOS/iOS runners are expensive enough that per-PR five-platform CI was projected to dominate cost without catching enough regressions to justify it. The release gate keeps the parity invariant honest; the per-PR subset keeps fast feedback affordable.
- **No platform-specific features in the core flow.** Push notifications, widgets, Siri / Google Assistant integration, Linux systemd unit files — these are platform-specific *delivery* of the same core capability. The capability itself must exist on all platforms.
- **Sixth platform is a deferred-by-default decision.** Adding (e.g.) a web client or a smartwatch app is a new principle-level commitment, not a casual addition. It goes through the same "parity from day 1" bar or is explicitly carved out in this doc.

---

## Conflicts between principles

When two principles conflict, the order above is the priority order: **security > memory/execution safety > simplicity > multiplatform.**

- **Security beats safety:** if the only way to avoid a panic is to ship code that violates the security model, panic instead. (In practice this should never come up — the design must refuse such states statically.)
- **Safety beats simplicity:** a one-line user-facing error is "less simple" than a crash dialog, but the error is required.
- **Simplicity beats multiplatform:** a feature that's awkward on one platform is cut everywhere rather than shipped only on the four that handle it cleanly.

These conflicts should be rare; when they arise, surface them in the PR description and update this section if the resolution generalizes.

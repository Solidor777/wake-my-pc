# Plan

Milestone roadmap. Update on completion per CLAUDE.md rule 10. Deferrals → `TODO.md`; mid-flight findings → `POST_WORK_FINDINGS.md`.

---

## Locked architectural decisions (2026-05-08)

Not up for re-litigation without a principle-level revisit.

- **Stack:** Rust core crate + thin native shells. iOS = SwiftUI via `uniffi`; Android = Compose via `uniffi`/JNI; Win/Mac/Linux = Rust binary with **egui** UI.
- **Connectivity (v1):** LAN-only. Internet-capable wake = M7+.
- **Wake/sleep split:** Sleep via daemon (auth'd command). Wake via WoL magic packet from client. Two paths because a sleeping PC has no daemon listening.
- **Auth + transport:** mutual TLS 1.3 over TCP via `rustls`. Each device generates a self-signed Ed25519 cert at pairing; daemon and client store each other's SPKI pin. TLS handles handshake/AEAD/KDF; per-command nonces add app-layer replay protection.
- **Linux keystore:** hybrid — libsecret/Secret Service when a session bus is available; fallback to encrypted file with key derived from `/etc/machine-id` + per-install salt for headless. Headless Linux is the weakest at-rest tier (TODO.md).
- **Pairing UX:** QR + 6-digit numeric fallback. Daemon prints code to stdout/log so headless installs work without rendering a QR.
- **Daemon paired-phone management UI (v1):** CLI-only. Tray-icon GUI deferred post-v1.

---

## Completed

- **Docs scaffolding (2026-05-08).** `PRINCIPLES.md` (4 principles: security > memory/exec safety > simplicity > multiplatform), `PLAN.md`, `TODO.md`, `POST_WORK_FINDINGS.md`, `.gitignore`.
- **M0 desktop + CI (2026-05-08).** Cargo workspace (`core`, `daemon`, `desktop-ui`, `bindings`), edition 2024, MSRV 1.85. Workspace lints enforce Principle 2 (`unwrap_used`/`expect_used` denied; `forbid(unsafe_code)` in `core` + `bindings`). `core::hello()` smoke test wired through daemon, desktop-ui (egui), bindings (uniffi). Local `cargo build/test/clippy/fmt` green on Windows. CI workflows: `per-pr.yml` (Linux/Mac/Windows desktop + cargo-audit) and `pre-release.yml` (full five-platform; mobile gated to `mobile-ci` label / release tags). README.md.

## In-progress

- **M0 mobile portion** (deferred — needs macOS + Android SDK env). `ios/` and `android/` exist with detailed READMEs but no project files. Honest empty-with-instructions over scaffold-without-validation.

---

## M0: Repo & CI foundations

**Goal:** every later milestone can assume the repo builds + tests on all five targets.

**Deliverables:**
- Workspace `Cargo.toml` with `core`, `daemon`, `desktop-ui`, `bindings` crates.
- Mobile project skeletons: `ios/` (SwiftUI), `android/` (Gradle + Compose). Each links `core` via uniffi, prints "core: hello" on launch.
- CI in two tiers (Principle 4 CI clause):
  - **Per-PR (cheap):** core + daemon + desktop-ui build + test on x86_64 Linux/Mac/Windows.
  - **Pre-release (full):** all five targets including iOS Simulator + Android emulator. Triggered on release tags or `mobile-ci` PR label.
- README.md.

**Exit criteria:**
- `cargo build --workspace` green on Linux/Mac/Windows.
- iOS Simulator + Android emulator runs show "core: hello" via pre-release workflow.
- Per-PR CI runs the three desktop paths in <10 minutes.

---

## M1: Wire protocol & crypto

**Goal:** the protocol between client and daemon is fully specified, implemented in `core`, unit-tested. No transport, no UI — just the bytes.

**Deliverables:**
- `docs/PROTOCOL.md` documenting wire format running *over* the mTLS channel: command types, framing, per-command nonces, error codes, versioning.
- **Message types** (canonical list):
  - **Client → daemon:** `Pair` (carries `phone_name` so user can identify pairings later), `Sleep`, `Lock`, `PowerOff`, `StateProbe`, `ReauthStatus`, `ReauthConfig`.
  - **Daemon → client:** `StateReport` (5-state enum: `Off`, `Sleeping`, `On_LoggedOut`, `On_Locked`, `On_LoggedIn`), `Revoke` (carries daemon SPKI hash + nonce), error responses including `RequiresReauth`.
  - **Client → daemon ack:** `RevokeAck`.
  - **Wake is NOT a daemon command.** WoL magic packet handled in M3 — daemon is dead when PC is off/sleeping.
  - **Unlock is NOT in v1.0.** Lands at v1.1 in post-v1 M11. Reserve versioning room — no opcode squatting that blocks future addition.
- **Crypto: TLS 1.3 + Ed25519 device certs.** No separate AEAD/KEX choice (subsumed under mTLS). `core::crypto` wraps `rustls`: cert generation, SPKI pinning, pairing-handshake state machine, command-nonce validation.
- `core::protocol`: encode/decode all message types, no I/O.
- KAT + property + negative tests: wrong cert / unpinned cert / replayed nonce / truncated message / TLS downgrade all rejected.
- Pairing UX flow specced (QR + 6-digit numeric fallback).
- **Protocol freezes at v1.0 at start of M4** (mobile = second consumer).

**Exit criteria:**
- 100% of message types covered by KAT + property + negative tests.
- `cargo audit` clean for `core`.
- Independent crypto-design review (security-review skill or human reviewer) signs off.

---

## M2: PC daemon — Win + Mac + Linux together

**Goal:** daemon binary on all three desktop OSes accepts auth'd Sleep/Lock/PowerOff commands, reports 5-state, advertises on LAN.

**Deliverables:**
- `daemon/` binary using `core::protocol` + `core::crypto`.
- LAN listener: TCP + TLS 1.3 mutual auth via `rustls`, port chosen at install. mDNS/Bonjour service advertisement.
- **OS state-change APIs per platform:**
  - **Windows.** Sleep: `SetSuspendState` (powrprof.dll). Lock: `LockWorkStation()` (user32.dll). PowerOff: `ExitWindowsEx(EWX_POWEROFF | EWX_FORCE)` — daemon enables `SE_SHUTDOWN_NAME` privilege at startup.
  - **macOS.** Sleep: `pmset sleepnow` shell-out OR `IOPMSleepSystem` via IOKit. Lock: `loginwindow` distributed-notification OR `pmset displaysleepnow` + screensaver. PowerOff: `shutdown -h now` (sudoers exception).
  - **Linux.** Sleep: DBus → `org.freedesktop.login1.Manager.Suspend`. Lock: `loginctl lock-session`. PowerOff: DBus → `org.freedesktop.login1.Manager.PowerOff`. Avoid shell-out where possible.
- **Session-state detection** (powers 5-state `StateReport`):
  - Windows: WTS API (`WTSQuerySessionInformation`).
  - macOS: `CGSessionCopyCurrentDictionary`.
  - Linux: `loginctl show-session`.
- **Service installation** (Windows: SCM service. macOS: launchd LaunchAgent plist. Linux: systemd user unit; non-systemd fallback documented in TODO.md).
- **Uninstaller per platform — clean revocation per Principle 1.** Removes binary + service registration + keystore (paired-device records + private keys). Reinstalling generates fresh keys; phones must re-pair.
  - Windows: MSI/MSIX uninstall hits service stop+dereg, files, registry, DPAPI keystore.
  - macOS: signed `.pkg` ships uninstall script that unloads launchd plist + removes binary + deletes Keychain items.
  - Linux: `apt purge` / `dnf remove` + postrm hook wipes libsecret + encrypted-file fallback. Manual install ships `uninstall.sh`.
  - **Uninstaller invokes revoke broadcast** pre-keystore-wipe — best-effort, no retry afterward (daemon's gone). Prints summary of reached/unreached phones.
- **Persistence: per-pairing keystore record:** `phone_name` (captured at Pair), `paired_at`, `revoked` (immediate-effect flag), `revoke_pending` (unack'd Revoke push queue), `last_authenticated_at`.
- **Daemon CLI:**
  - `wake-my-pc-daemon list-paired` — phone name, pair date, last-auth date for each pairing.
  - `wake-my-pc-daemon revoke <phone-name>` — sets `revoked=true` immediately; queues Revoke push. mDNS browser retries delivery whenever phone appears on LAN; on `RevokeAck`, pairing is fully removed.
  - `wake-my-pc-daemon reauth-now` — manual re-auth before expiry. Triggers credential prompt; on success resets `last_authenticated_at` and adds `reauth_interval_days`.
- **Re-auth state machine.** `pc_reauth_interval_days` default 7 (options: 1 / 7 / 30 / Off). State: `Active` ↔ `NeedsReauth` past expiry. In `NeedsReauth`, daemon rejects state-change commands with `RequiresReauth`; only `ReauthStatus` queries succeed. Returning to `Active` requires platform credential prompt:
  - Windows: Windows Hello via WebAuthn API (PIN / biometric / FIDO2 — whichever user has).
  - macOS: Touch ID via `LocalAuthentication.LAContext` with password fallback.
  - Linux: polkit pkexec or PAM-driven prompt fallback.
- **Re-auth notifications.** OS-native notifications fire at `expiry - 3d`, `expiry - 1d`, day-of, but only for offsets that fit the configured interval — for `interval=1`: only day-of; for `interval=7` or `30`: all three. Notification action = "Authenticate now" → opens credential prompt. Same hook as `reauth-now` CLI.
- Pairing acceptance flow: daemon shows QR (terminal output for v1; tray-icon UI deferred). Client scans; daemon writes pairing record on success.

**Exit criteria:**
- All three OS daemons execute Sleep / Lock / PowerOff on auth'd command (per-OS, per-command integration test).
- All three emit accurate 5-state `StateReport` as session state changes (lock screen → daemon flips to `On_Locked` within heartbeat interval).
- All three reject unauth'd / replayed / wrong-key commands (negative integration test).
- Service install + uninstall scripts work end-to-end on each OS.
- **Revocation invariant verified.** Pair P → Sleep succeeds → uninstall → reinstall → Sleep from same P fails with `Paired device not authorized`.
- **Daemon-side revoke + retry verified.** Pair P1 + P2 → `daemon revoke P1` → P1 immediately rejected → P1 offline → P2 still works → P1 rejoins LAN → daemon pushes Revoke → P1 wipes pairing → daemon removes pairing entry.
- **Re-auth state machine verified.** With `pc_reauth_interval_days = 1`: command at hour 0 succeeds; hour 25 returns `RequiresReauth`; credential prompt completes; hour 26 succeeds. Manual `reauth-now` at hour 12 extends to hour 36.
- No platform is "best-effort" — feature parity per Principle 4.

---

## M3: WoL trigger & state detection

**Goal:** client (any platform) can wake a paired PC and tell whether it's currently awake.

**Deliverables:**
- `core::wol`: build magic packet for stored MAC, send via UDP broadcast to port 9. Same packet wakes `Sleeping` and `Off` (NIC handles both).
- `core::state`: probe daemon's heartbeat port; if unreachable, infer `Off | Sleeping` (indistinguishable from network alone). When daemon reachable, expose its 5-state report. Transition rules:
  - `Off → On_*` (after WoL + boot)
  - `Sleeping → On_*` (after WoL + resume)
  - `On_* → Sleeping` (after Sleep command)
  - `On_* → Off` (after PowerOff command)
  - `On_LoggedIn ↔ On_Locked` (after Lock command, or user manually unlocks at PC)
  - `On_LoggedOut → On_LoggedIn` (only via user logging in at PC — not remote)
- MAC discovery during pairing (daemon reports its NIC MACs; client picks the one matching the pairing LAN).
- Integration test: paired PC asleep → client triggers wake → boot → daemon online → state flips to `On_*`. Real PC pair per OS.

**Exit criteria:**
- Wake works on all three desktop OSes (BIOS WoL prerequisite documented + linked from onboarding).
- State detection latency < 2s from PC actually-awake to client showing `On_*`.
- "BIOS WoL disabled" and "wrong network" failure modes have tested one-line user errors.

---

## M4: Mobile clients — iOS + Android together

**Goal:** state-aware dashboard end-to-end on both phones. Default happy path: dashboard + sleep button + sleep/wake notifications + 7-day re-auth (Principle 3). Optional features wired but default-off in Settings. **Protocol freezes at v1.0 at start of this milestone.**

**Deliverables:**
- **Pairing flow.** Settings → "Pair new PC" → camera → scan QR (or enter 6-digit fallback) → mutual key derivation → success.
- **Default dashboard** (Principle 3 happy path):
  - Renders current 5-state via `core::state`.
  - One default action button. State `Off | Sleeping` → "Wake" (sends WoL). State `On_*` → "Sleep" (sends `Sleep`). Affordance reflects state (TBD ui-egui design pass).
  - **Default-on notifications:** local push when PC transitions `Off|Sleeping → On_*` (wake confirmed) or `On_* → Sleeping` (sleep confirmed).
- **Optional features (default off; Settings):**
  - **Power Off button.** Visible only when state is `On_*`. Sends `PowerOff`.
  - **Lock button.** Visible only when state is `On_LoggedIn`. Sends `Lock`. v1 is one-way; remote unlock = post-v1 M11.
  - **Per-action platform-auth gate.** Phone-side biometric before sending state-change command. iOS: `LocalAuthentication.LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`. Android: `BiometricPrompt`. Per-action — user can require auth for `PowerOff` only or for all four.
  - **Per-state-change notifications.** Default off for everything except sleep ↔ wake. User enables `Off` / `On_LoggedOut` / `On_Locked` / `On_LoggedIn` independently.
- **Multiple-PC handling.** If >1 paired, list view → tap PC → its dashboard. Single-PC users never see the list.
- **Unpair from phone wipes stored MAC + cert pin** (revokes mTLS auth AND WoL — phone can no longer construct a magic packet). Confirmation prompt per Principle 3.
- **Receive `Revoke` from daemon.** Phone advertises `_wake-my-pc-client._tcp` on LAN via mDNS while app foreground (Local Network permission). On Revoke, verify SPKI matches a known pairing → wipe cert pin + stored MAC → `RevokeAck` → local notification ("[PC name] removed this pairing"). Background reception = best-effort; honest behavior is "phone gets the Revoke when it next opens on same LAN as daemon."
- **Per-pairing re-auth tracking.** Each pairing carries `phone_reauth_interval_days` (default 7; options 1 / 7 / 30 / Off) + `last_authenticated_at`. App refuses state-change commands when expired; biometric resolves and resets timer. Pre-expiry notifications fire at `-3d / -1d / day-of`, only the offsets that fit the configured interval (1-day → day-of only). Dashboard banner "Re-auth in 2 days · tap to extend" inside last 3 days.
- **Settings → Re-authentication:**
  - "Re-authenticate this phone every: [1/7/30/Off]" (default 7).
  - "Re-authenticate this PC every: [1/7/30/Off]" (default 7; sends `ReauthConfig`).
  - "Re-authenticate now" button — runs biometric immediately, resets phone-side timer, sends `reauth-now` to daemon if PC re-auth enabled.
- iOS biometric: `LocalAuthentication.LAContext.evaluatePolicy(.deviceOwnerAuthentication)` (biometric or passcode auto-fallback).
- Android biometric: `BiometricPrompt` with `setAllowedAuthenticators(BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`.
- Errors: one-line per Principle 3.
- iOS: SwiftUI, iOS 16+ (TBD). Android: Compose, Android 10+ (TBD).
- Both ship in lockstep.

**Exit criteria:**
- Pairing works on both phones × all three desktop OSes (6 combos green) for both QR and 6-digit paths.
- Default-action button correctly sleeps awake PCs and wakes Sleeping/Off PCs across all combos.
- Each opt-in feature works when enabled and stays invisible when disabled.
- Sleep ↔ wake + re-auth pre-expiry notifications fire by default; no other notifications fire without explicit opt-in.
- Re-auth defaults verified (7 days each side); user can change to 1/30/Off independently. Manual extend works mid-window.
- Lock works; remote-unlock is verified absent (negative test: no `Unlock` opcode exists in v1.0).
- Accessibility: dashboard passes VoiceOver + TalkBack basic checks; biometric prompts use platform accessibility flows.
- Self-review against PRINCIPLES.md → POST_WORK_FINDINGS.md.
- Protocol v1.0 tagged in PROTOCOL.md.

---

## M5: Beta hardening

**Goal:** good enough to give to non-technical friends.

**Deliverables:**
- Onboarding copy review — every screen reads cleanly to a user who hasn't heard of WoL. Includes BIOS WoL-disable callout for users who want full revocation post-uninstall (Principle 1 residual-risk).
- Error path coverage — every failure mode has a tested one-line user-facing error.
- **Uninstall discoverability test.** Beta user with no docs must fully uninstall in <60s. P1 against Principle 3 if not.
- Store assets: icon, screenshots, descriptions, privacy nutrition labels (iOS) / data safety (Android). Privacy stance: "no data collected" (Principle 1's no-telemetry rule).
- Signed desktop installers: `.msi` (Win), `.pkg`/`.dmg` (Mac), `.deb` + `.rpm` + tarball (Linux). Code-signing certs acquired.
- 5–10 beta testers across both phone OSes and ideally all three desktop OSes.
- Bug bash on every supported pair.

**Exit criteria:**
- Beta testers complete a wake + sleep cycle without help.
- No P0/P1 bugs from beta.
- All five platforms ship from the same commit hash.

---

## M6: v1 release

**Deliverables:**
- App Store submission (iOS, ~1–7 day review).
- Play Store submission (Android, ~1–3 day review).
- Desktop installers on GitHub Releases with checksums + signatures.
- Landing page (scope of marketing site is its own decision — flag).
- Release notes per CLAUDE.md rule 12.

**Exit criteria:**
- All five platforms downloadable by an unrelated user without our help.
- First non-tester user successfully wakes + sleeps a PC.

---

## Post-v1 deferred milestones

Each is milestone-sized.

- **M7 — Internet-capable wake.** Three sub-options: cloud relay we operate; router-side WoL exposure; always-on home device. Different security models. Re-open Principle 1 review when this lands.
- **M8 — Widgets / quick actions.** iOS home-screen widget + Android quick-settings tile. Preserve one-tap; failures stay one-line.
- **M9 — Multiple-user / shared PCs.** PC paired with multiple phones, separate or shared authority. Adds authorization model on top of M1's authentication.
- **M10 — Apple Watch / Wear OS.** New platforms = new principle-level commitment per Principle 4's "sixth platform" carve-out.
- **M11 — Remote unlock.** Tap Unlock → biometric on phone → PC unlocks. Default-off opt-in. Locked design (2026-05-08):
  - User enters PC unlock credential during opt-in flow. Phone stores in iOS Keychain (`kSecClassGenericPassword` with biometric-protected access) or Android Keystore (`MasterKey` + `setUserAuthenticationRequired(true)`). Mandatory biometric per action — not opt-in. Daemon receives credential over mTLS, types into lock screen, never persists.
  - **Per-OS feasibility.** Windows: messy but doable (custom Credential Provider DLL is the clean path; UAC-elevated, separate security review). Linux: best-effort by display manager (GDM works via DBus; SDDM/KDE vary; ship at least GDM). **macOS: likely infeasible** — Apple's loginwindow + SecurityAgent block programmatic credential injection by design. Settings shows "not available on macOS" with docs link. The only planned Principle-4 carve-out, accepted only because Apple actively prevents the feature.
  - Onboarding security disclosure on opt-in: "Storing your PC password on your phone is a tradeoff..." User must acknowledge.
  - PROTOCOL.md + PRINCIPLES.md threat-model update lands as part of M11.

---

## Open architectural questions

None blocking M0–M4. Per-PR mobile CI economics (TODO.md) doesn't block any milestone; revisit end of M4 with cost + regression-frequency data.

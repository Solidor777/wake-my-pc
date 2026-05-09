# TODO

Deferred work. Per CLAUDE.md rule 7, items here are deferred only when redundant with a planned milestone or in conflict with the active goal — not as a stash for routine cleanup.

For decisions made, see `PLAN.md` → "Locked architectural decisions".

---

## Open design questions

### Per-PR mobile CI economics
Principle 4 CI clause was softened 2026-05-08 to gate full five-platform CI at release rather than per-PR. Per-PR runs core + desktop only. **Question:** is "release-only" too coarse — do we miss enough mobile regressions that we should re-add per-PR mobile CI on a sampling basis (e.g., 1-in-N PRs, or PRs touching `bindings/` or `core::ffi`)?

**Why deferred:** can't answer until M0 ships and we have actual cost data + regression frequency.

**When to revisit:** end of M4. If mobile regressions are landing on `main` and only being caught at release, tighten. Otherwise the softened gate stays.

---

## Known limitations to surface at v1

Accepted tradeoffs from locked decisions. Each must surface clearly in v1 onboarding or install docs.

- **WoL must be enabled in BIOS/UEFI.** First-launch onboarding shows platform-specific instructions. Failing to wake with a clear "WoL not enabled in BIOS" error is acceptable; failing silently is not.
- **Phone and PC must share a LAN.** Internet-capable wake = M7+. Pairing assumes shared subnet; post-pair wake assumes phone on same LAN.
- **Linux non-systemd distros.** Service install assumes systemd. Alpine/Void/Gentoo-OpenRC users get manual install path; no auto-install for v1.
- **Headless Linux at-rest crypto is weaker** (machine-id-derived encrypted file vs hardware-backed keystores on the four other OSes). Document honestly.
- **Linux libsecret install dependency** for the better keystore tier. Document in install prerequisites.

---

## M2 follow-up work (deferred from 2026-05-08 Windows baseline)

Each lands in its own session on the right environment / behind the right risk gate.

### macOS + Linux platform code
**What:** `daemon/src/platform/{macos,linux}.rs` implementations of `sleep`/`lock`/`power_off`/`current_session_state`/`prepare`. Currently stubbed with `OsApi("not implemented")`. macOS: `pmset` + `loginwindow` + `shutdown -h now` per PLAN.md M2. Linux: DBus `login1.Manager.{Suspend,PowerOff}` + `loginctl lock-session`.
**When to revisit:** next session on a Mac (iOS env) and/or a Linux box. M2 close-out blocked until both ship.

### Per-OS keystore encryption (Mac + Linux)
**What:** `daemon/src/keystore/platform.rs` non-Windows path currently returns `Err("not implemented")`. Mac: Keychain `SecItemAdd` / `SecItemCopyMatching`. Linux: libsecret + machine-id-derived AEAD fallback per PLAN.md "Locked architectural decisions".
**When:** lands with the platform code above; same session.

### mDNS / Bonjour service advertisement
**What:** Daemon broadcasts `_wake-my-pc._tcp.local` on the LAN so the phone's pairing flow can resolve the daemon without manual IP entry. PLAN.md M2 requires this for the QR + 6-digit pairing UX.
**When:** post-platform-parity session. `mdns-sd` (pure Rust, async) is the leading candidate; revisit after the spike.

### Service installation + uninstaller
**What:** Windows MSI/MSIX + SCM service registration; macOS signed `.pkg` + launchd plist; Linux `.deb`/`.rpm` + systemd unit. Uninstaller invokes Revoke broadcast pre-keystore-wipe (best-effort).
**When:** beta hardening (M5) timeline. Until then, manual install via copying the binary + `wake-my-pc-daemon serve` works.

### Re-auth credential prompts
**What:** `admin::reauth_now` currently runs an always-ok stub. Production: Windows Hello via WebAuthn API; macOS Touch ID via `LocalAuthentication.LAContext`; Linux polkit `pkexec` or PAM. Deep platform integration; deserves a dedicated session per OS.
**When:** before v1 ships. Tracked separately because each prompt is its own platform spike.

### Re-auth pre-expiry notifications
**What:** OS-native notifications at `expiry - 3d`, `expiry - 1d`, day-of (only the offsets that fit the configured interval). Notification action opens the credential prompt (same code path as `reauth-now`).
**When:** after credential prompts land — they share a UI surface.

### Lock-state discrimination (`WTSSessionInfoEx`)
**What:** Daemon currently returns `OnLoggedIn` whenever a console session exists. Full 5-state needs the `WTS_SESSIONFLAG_LOCK` (which is documented-inverted on Win 7+) to distinguish `OnLocked` from `OnLoggedIn`. M2 baseline emits `OnLoggedIn` for both — protocol has the variant; daemon just doesn't fire it yet.
**When:** before M4 ships. The phone-side default-action button keys off this distinction.

### Revoke retry queue
**What:** When `daemon-cli revoke <phone>` is invoked while the phone is offline, the daemon should queue a Revoke push and deliver it opportunistically (mDNS browser detects phone returns to LAN, daemon connects, sends Revoke, waits for `RevokeAck`, then drops the pairing entry). Current baseline marks `revoked = true` and `revoke_pending = true` in the keystore — phone won't get the push until it reconnects to a daemon serving with the new pinset (which excludes it, so the connection fails and the phone never receives Revoke).
**When:** with mDNS responder. They share the LAN-discovery code.

### Mockable `Handlers` trait for destructive-command tests
**What:** Sleep / Lock / PowerOff dispatch is currently untested at the integration level because it would actually sleep/lock/power-off the host. Refactor `dispatch` to accept a `Handlers: Send + Sync` trait so tests inject a recording mock. M2 baseline tests cover StateProbe + ReauthStatus + ReauthConfig + RevokeAck round-trips; the destructive trio is verified only by direct unit tests of `platform::*` (which themselves don't run in CI).
**When:** alongside any further M2 protocol work — the refactor surface is small but worth doing once.

### `pair` while `serve` is running
**What:** The current model requires stopping `serve` before running `pair` (both bind the same port). UX would prefer one persistent daemon process where the user signals "enter pairing window" via a control channel (file flag, named pipe, signal). Multi-device pairing already works (`pair` re-uses the existing keystore identity); this is purely about not having to restart.
**When:** before beta. Probably during M5 polish.

---

## Routine follow-ups

### Unmaintained transitive deps (M1, 2026-05-08)
`cargo audit` reports three unmaintained-but-not-vulnerable warnings:
- `atomic-polyfill 1.0.3` (RUSTSEC-2023-0089) via `heapless` via `postcard 1.1`. Resolved if/when postcard bumps to a heapless past 0.7.
- `bincode 1.3.3` (RUSTSEC-2025-0141) via `uniffi_macros 0.28`. Resolved if/when uniffi bumps to bincode 2.x.
- `paste 1.0.15` (RUSTSEC-2024-0436) via `uniffi_core` + `uniffi_bindgen 0.28`. Same: gated on uniffi.

**Why deferred:** none are vulnerabilities (audit exits 0); upgrading would mean swapping postcard or uniffi outright, which is a much larger blast radius than the risk warrants. Watch list — re-check at M5 (beta hardening) and any time a new advisory lands against any of these crates.

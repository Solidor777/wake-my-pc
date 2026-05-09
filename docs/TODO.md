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

Each lands in its own session on the right host / behind the right gate. PLAN.md M2 carries the canonical OS-API + behaviour spec.

- **macOS + Linux platform code** — `daemon/src/platform/{macos,linux}.rs` currently stubbed `OsApi("not implemented")`. Revisit on Mac (also iOS env) and a Linux box. M2 close-out blocked until both ship.
- **Per-OS keystore encryption (Mac + Linux)** — `daemon/src/keystore/platform.rs` non-Windows path returns `Err`. Same session as platform code.
- **mDNS / Bonjour advertisement** — `_wake-my-pc._tcp.local` so the phone's pairing flow resolves without manual IP entry. Leading candidate `mdns-sd`. After platform parity.
- **Service install + uninstaller** — MSI / signed `.pkg` + launchd plist / `.deb`+`.rpm` + systemd unit. Uninstaller invokes Revoke pre-keystore-wipe. M5 timeline; manual `wake-my-pc-daemon serve` works until then.
- **Re-auth credential prompts** — `admin::reauth_now` is an always-ok stub. Production needs Windows Hello (WebAuthn) / Touch ID (`LocalAuthentication`) / polkit. Per-OS spike; before v1 ships.
- **Re-auth pre-expiry notifications** — OS-native at `-3d / -1d / day-of` (only offsets fitting the interval). After credential prompts; shares the UI surface.
- **Revoke retry queue** — offline phones never receive Revoke today (handshake fails because they're already out of the live PinSet). Lands with mDNS; shares LAN-discovery code.
- **`pair` while `serve` is running** — both bind the same port today; pair-while-serving needs a control channel (signal / named pipe / file flag). Multi-device pairing itself already works. M5 polish.

---

## Routine follow-ups

### Unmaintained transitive deps (M1, 2026-05-08)
`cargo audit` reports three unmaintained-but-not-vulnerable warnings:
- `atomic-polyfill 1.0.3` (RUSTSEC-2023-0089) via `heapless` via `postcard 1.1`. Resolved if/when postcard bumps to a heapless past 0.7.
- `bincode 1.3.3` (RUSTSEC-2025-0141) via `uniffi_macros 0.28`. Resolved if/when uniffi bumps to bincode 2.x.
- `paste 1.0.15` (RUSTSEC-2024-0436) via `uniffi_core` + `uniffi_bindgen 0.28`. Same: gated on uniffi.

**Why deferred:** none are vulnerabilities (audit exits 0); upgrading would mean swapping postcard or uniffi outright, which is a much larger blast radius than the risk warrants. Watch list — re-check at M5 (beta hardening) and any time a new advisory lands against any of these crates.

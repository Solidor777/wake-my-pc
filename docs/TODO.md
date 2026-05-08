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

## Routine follow-ups

_(none — this section is for the rare exception that can't be fixed inline per CLAUDE.md rule 7.)_

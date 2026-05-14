# wake-my-pc

Toggle a PC awake or asleep from your phone. One button. Works on any of {Windows, macOS, Linux} from any of {iOS, Android}, on the same LAN.

**Status:** pre-v1, M0 in progress. See `docs/PLAN.md` for the milestone roadmap.

## Repository layout

```
core/         Rust crate. Protocol, crypto, state. Pure logic, no I/O. forbid(unsafe_code).
daemon/       Rust binary. PC-side service. Receives auth'd Sleep commands; calls OS sleep API.
desktop-ui/   Rust binary. Win/Mac/Linux client UI (egui).
bindings/     Rust crate. uniffi UDL exposing core to Swift (iOS) + Kotlin (Android).
ios/          SwiftUI app shell. Scaffold pending — see ios/README.md.
android/      Compose app shell. Scaffold pending — see android/README.md.
docs/         PRINCIPLES.md, PLAN.md, TODO.md, POST_WORK_FINDINGS.md. Read these first.
.github/      CI workflows. per-pr.yml (cheap subset) and pre-release.yml (full five-platform gate).
```

## Build

### Desktop (Windows / macOS / Linux)

```
cargo build --workspace
cargo run -p wake-my-pc-desktop    # opens the egui smoke-test window
cargo run -p wake-my-pc-daemon     # M0 stub — prints "core: hello" and exits
```

Linux requires GUI build deps:

```
sudo apt install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev \
                    libxkbcommon-dev libgtk-3-dev libssl-dev
```

### iOS / Android

Mobile shells are scaffold-pending as of 2026-05-08 — the desktop machine these were initialized on doesn't have Xcode or the Android SDK, and shipping unvalidated mobile config would just create work for the next agent. See `ios/README.md` and `android/README.md` for the next steps.

### Windows installer (MSI)

The daemon ships as a LocalSystem SCM service installed via MSI. Build it with [cargo-wix](https://github.com/volks73/cargo-wix) — requires the WiX 3.x SDK (`candle.exe` + `light.exe`) on PATH:

```
cargo install cargo-wix
cargo build --release -p wake-my-pc-daemon
cargo wix --package wake-my-pc-daemon -p wake-my-pc-daemon --no-build
```

The MSI installs `wake-my-pc-daemon.exe` to `%ProgramFiles%\wake-my-pc\`, creates `%ProgramData%\wake-my-pc\` with ACLs locked to SYSTEM + Administrators, and registers the SCM service auto-starting as LocalSystem. Uninstall best-effort-broadcasts a Revoke to every paired phone before the keystore wipe (per Principle 1's layered revocation).

WiX source lives at `daemon/wix/main.wxs`; the locked decisions baked into it are documented in the file header.

## Tests + lints

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Lint posture comes from Principle 2 (memory & execution safety): `unwrap_used` and `expect_used` are denied workspace-wide; `unsafe_code` is forbidden in `core/` and `bindings/`. Tests are exempt — panicking *is* the test failure.

## Architecture

Three load-bearing decisions live in `docs/PLAN.md` → "Locked architectural decisions". The short version:

- **Rust core + thin native shells** for five-platform parity from a single codebase.
- **LAN-only for v1.** Internet-capable wake is a post-v1 milestone.
- **Mutual TLS 1.3 over TCP** between client and daemon, with Ed25519 device certs pinned at pairing time. WoL magic packet handles wake (PC is asleep, daemon isn't running); daemon handles sleep when PC is awake.

For the why, read `docs/PRINCIPLES.md` first, then `docs/PLAN.md`.

## Contributing

This repo follows the rules in `CLAUDE.md`. Highlights:

- Plan against principles + plan before non-trivial work.
- Architectural decisions need explicit confirmation — don't pick file layout, dep, or naming unilaterally.
- All five platforms ship together at release. Per-PR CI runs the cheap subset (Linux/macOS/Windows desktop); mobile builds gate to a `mobile-ci` label or release tags.
- Never compromise security. The Wake-on-LAN magic packet is unauthenticated by spec; all command authority lives at the orchestration layer above WoL.

## License

Dual-licensed under Apache-2.0 OR MIT.

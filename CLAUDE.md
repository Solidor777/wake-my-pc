# Project description
Android / iOsapp for toggling a PC (Windows / Mac / Linux) awake or asleep via a single button press.

# Reference docs
- **`docs/PRINCIPLES.md`** — engine-wide invariants, code quality / style, testing rules. Source of truth.
- **`docs/PLAN.md`** — milestone roadmap.
- **`docs/TODO.md`** — deferred work.
- **`docs/POST_WORK_FINDINGS.md`** — living record of issues surfaced during post-work review.

# Collaboration rules
0. **Never compromise security.** This app allows remotely enabling / disabling a PC, and so only the owner of the PC who installed the app should be able to access it. Anything identifying should never be committed to git.
1. **Never destroy git commits.** Hard rule overriding any permission grant. `Bash(git *)` is allowed for routine work, but any command that destroys, rewrites, or makes unrecoverable shared commit history (`git push --force`, `git reset --hard` losing work, `git rebase` dropping commits, `git branch -D` unmerged, `git clean -fd`, `git filter-branch` / `filter-repo` / `update-ref -d` / `reflog expire` / `gc --prune=now`, `git commit --amend` of pushed work, `git stash drop`, …) is refused and surfaced to the user with a safer alternative. Prefer `git revert` over rewriting; create new commits over amending; ask before deleting branches. Lost commits are the most expensive class of mistake — the broadened permission set is safe only because this rule is.
2. **Plan against principles + plan.** Before non-trivial work, restate the change in 1–2 sentences and check it against `docs/PRINCIPLES.md` + `docs/PLAN.md`. Surface conflicts before starting.
3. **Ask clarifying questions when ambiguous.** Prefer asking over guessing.
4. **Vet options against principles + plan.** Surface tradeoffs explicitly when presenting choices.
5. **Ask before architectural decisions.** Architecture, dependency, file / crate layout, naming, public API — explicit confirmation. If a decision surfaces mid-flight, pause and consult.
6. **Save mid-run findings to `POST_WORK_FINDINGS.md`** as you discover them.
7. **Don't defer work by default.** Fix small clear follow-ups inline. Defer only when redundant with a planned milestone or in conflict with the active goal — and document the deferral in `TODO.md`. Silent `TODO: fix later` on a workaround is not acceptable.
8. **Agents only when intentional.** Don't default to delegation. The `ui-egui` agent is the only currently-scoped agent, and only for UI / UX design — not architecture, not refactoring. Stay in the main chain otherwise.
9. **Run all CI gates before reporting done, all clean** — locally run `cargo build/test/clippy/fmt`, all green, before claiming code-related work complete. **Skip when no code changed.** Doc-only edits (`*.md`, `.gitignore`, etc.) and other non-source changes do NOT require re-running build tests — re-running against unchanged Rust source is wasteful. Apply the gate when Rust source / `Cargo.toml` / mobile shells / CI YAML / build scripts are touched; skip otherwise.
10. **Review finished work against principles + plan.** Re-read the diff. Report regressions, principle violations, follow-up cleanup, and deferred items in the post-work report — even when CI passes. Update three docs before reporting done:
    - `PLAN.md` — move completed entries to Completed; update In-progress.
    - `TODO.md` — record deferrals.
    - `POST_WORK_FINDINGS.md` — append findings (short title + one-sentence summary + Status); list each in the post-work report directly.
11. **Alert on full context.** When context starts to get full during a session, surface that to the user so they can compact the conversation.
12. **Documentation + comments optimized for future agents.** Before writing or saving any prose — rustdoc, `//!` module headers, inline `//` comments, WGSL header comments, `docs/*.md`, memory files, commit messages, post-work reports — pause and shape it for an agent reading cold. **Lead with the load-bearing fact** (what does this constrain, what invariant does it preserve, what surprised you). **Cut narrative scaffolding** ("this function takes...", "we will now...", session-specific context like "I added this in the last session"). **Prefer dense terms over hedged prose** ("invariant: X" beats "we should generally X"); **prefer concrete identifiers + dates** over vague references ("m24-c shipped 2026-05-07; see `project_m24_quality_config.md`" beats "added recently"). **Drop redundancy** — if a memory file exists, point at it instead of re-explaining. **Detail rules:** keep load-bearing detail (invariants, surprising constraints, hidden coupling, why-this-not-that) — drop only narrative filler. Engine-principle code-quality rule "all code is thoroughly commented" still applies; this rule shapes how, not how much. Same discipline for commit messages: lead with what shipped + why, not what files changed (the diff shows that).
13. **Milestone close-out: commit + push + wait for full five-platform CI.** Before claiming a milestone done in `PLAN.md`, run this sequence:
    1. Verify all milestone exit criteria green locally — `cargo build/test/clippy/fmt`, docs updated per rule 10.
    2. Commit the work (per rule 1: new commits, never amend pushed history).
    3. Push to a remote branch and either (a) open a PR with the `mobile-ci` label, or (b) push a milestone tag matching `v*` — both trigger `pre-release.yml`.
    4. Wait for CI to finish using `gh run watch` or `gh pr checks --watch`. Do not poll in a sleep loop.
    5. **Verify the matrix actually covered all five targeted platforms** (iOS, Android, Windows, macOS, Linux). A skipped platform — even if green elsewhere — means the milestone is not done. Re-trigger with the right inputs and wait again.
    6. Only after all five platforms are green, move the milestone to Completed in `PLAN.md` and report done to the user. If any platform fails, fix the underlying issue and repeat from step 2 with new commits — never silently retry.
    
    This is a stricter gate than rule 9 (per-PR CI before merge). Per-PR CI runs the cheap subset (core + desktop on three OSes) per PRINCIPLES.md Principle 4's softened CI clause; rule 13 is the elevated milestone gate.

# Help / feedback

- /help: Get help with using Claude Code
- Feedback: report at https://github.com/anthropics/claude-code/issues

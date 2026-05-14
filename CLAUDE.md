# Project description
Android / iOS app for toggling a PC (Windows / Mac / Linux) awake or asleep via a single button press.

## Reference docs
- **`docs/PRINCIPLES.md`** — engine-wide invariants, code quality / style, testing rules. Source of truth.
- **`docs/PLAN.md`** — milestone roadmap.
- **`docs/TODO.md`** — deferred work.
- **`docs/POST_WORK_FINDINGS.md`** — living record of issues surfaced during post-work review.

## Collaboration rules
* **Preserve Git History:** NEVER destroy, rewrite, or drop commits (no `push --force`, `reset --hard`, `rebase` dropping commits, etc.). Prefer `revert` or new commits. Ask before branch deletion.
* **Context Management:** Alert the user when the context window nears capacity to allow for compaction and clearing. Advise on compaction vs clearing when this occurs.
* **Objective and to the point:** Lead with load-bearing facts. Strip narrative scaffolding and redundant explanations. Be objective, not sycophantic. Evaluate thoroughly before coming to a recommendation. Surface concerns to the user if given bad or conflicting instructions.

## Planning & Architecture
* **Align and Vet Plans:** Before non-trivial work, restate the change in 1–2 sentences and check it against `engine_principles.md` + `PLAN.md`. Surface conflicts for review before starting.
* **Vet options:** Check options against `engine_principles.md` + `PLAN.md`. Surface tradeoffs explicitly when presenting choices.
* **Consent Required:** Pause and ask before making decisions on architecture, dependencies, file/crate layout, naming, or public APIs. Prefer asking over guessing.
* **Do the work now:** Fix small, clear follow-ups inline. Defer to `TODO.md` only if work conflicts with the active goal or if context / remaining rate is reaching its limits. No silent `TODO: fix later` workarounds.

## Runtime Semantics Change Validation (Excludes docs, comments, and `crates/third_party/` vendored crates.)
* **Local CI Gates:** locally run `cargo build/test/clippy/fmt`, all green, before claiming code-related work complete. 

## Tracking & Documentation
* **Post-Work Review:** Review diffs against `engine_principles.md` + `PLAN.md`. Update docs before reporting done:
* `PLAN.md`: Trim completed items to 1-liners pointing to memory files, then move them to completed items.
* `TODO.md`: Trim and optimize new deferrals before adding. Remove completed and no-longer-relevant items.
* `POST_WORK_FINDINGS.md`: Append mid-run findings (Title + 1-sentence summary + Status). List doc updates in the post-work report.
* **Agent-Optimized Writing:** Applies to code comments, `//!` headers, commit messages, and docs. Lead with load-bearing facts (invariants, constraints, hidden coupling). Strip narrative scaffolding and redundant explanations. Use concrete identifiers over hedged prose.

## Commits & Pushes
* **Auto-Commit:** Commit logical work-units immediately once local CI passes. Do not pause to ask. Do not batch unrelated concerns.
* **Auto-Push per Milestone:** Push only when a full milestone (not sub or partial milestone) closes. Do not pause to ask.
* **CI Monitoring:** Watch pipeline (`gh run watch`) post-push. Fix-forward layer-by-layer (topmost first) if red. Do not declare done until pushed CI is green.n.

# haru-pack issue board — conventions

**This file is the canonical, living description of how the board works.** Update it as the
process evolves and add a changelog entry below. The [META issue #3](https://github.com/ShyftXero/haru-pack/issues/3)
carries the full changelog; this file is the source of truth for the conventions themselves.

Onboarding: (1) read this file; (2) a project Claude-memory pointer to issue #3 already exists
(added 2026-09-11) — don't re-add it.

## Working norms (read first)

- **Don't waste tokens.** Be **terse by default** — state, not chatter; expand into detail only when
  the human asks. **Check a thing isn't already done before doing it** (this file, the board, the
  project memory). Read the board / this doc **when you need work**, not on a timer, and never
  message or wake another session.

## How the board works (v1)

Adopted from lotek's `docs/ISSUE_BOARD.md` + `docs/agents/issue-tracker.md`, **simplified for a
single repo under the owner's own `gh` auth**, and improved where noted.

- **Board, not a message bus.** Read the board **when you need work** — never message, wake, or
  poll another session, never broadcast status. Assigning an issue to yourself is a *lock*, not a
  notification.
- **Claim = lock, then act.** `gh issue edit <n> --add-assignee @me` **and** post a `### CLAIM`
  comment carrying your **session handle + branch + UTC time**. All sessions share one GitHub
  account, so the assignee is only a coarse "someone's on it"; the **handle** disambiguates *which*
  session holds it. *(Improvement over lotek, whose bot token cannot set an assignee at all.)*
  Un-assign + `### HANDOFF` when you stop mid-work. A claim silent **> 4h** is reclaimable — say so
  in a comment.
- **Columns = exactly one `status:` label.** `status:todo` (available) → `status:doing` (claimed) →
  `status:review` (PR open) → **closed = Done**. `status:blocked` + a `blocked by #N` note when
  stuck. Move the label **in the same step** as the work; **remove the stale `status:` label on
  close** (a closed issue still wearing `status:review` is board litter).
- **Comment headers, for the human reading later:** `### CLAIM` / `### PROGRESS` / `### HANDOFF` /
  `### BLOCKED` / `### DONE`. State, not chatter.
- **PR implements the issue.** `Fixes #N` on the PR so merge closes it. **Issue comments = work-item
  state; PR comments = code-review of that diff only.**
- **A session merges its own PR.** Green CI is the gate, not a human. Land it, let the branch
  delete itself (`deleteBranchOnMerge` is on for this repo as of 2026-09-11), and close the
  issue. Waiting on a review that nobody was asked for is how a finished diff sits for a day.
  Prefer `--rebase` when the commits are individually meaningful and `--squash` when they are
  not; either way the commit messages carry the reasoning, because that is what survives.
- **The one thing that requires the owner: cutting a release.** Versioning, tagging and
  publishing are his call and stay his call — see `docs/RELEASING.md` and
  `docs/PUBLISHING.md`. Everything short of that, a session finishes on its own.
- **Base off `main`, and record the base ref on the issue.** Branches here have drifted far from
  `main` (a session once sat 55 commits behind); starting from a stale worktree is a real trap.
  *(Improvement: base-ref discipline written onto every work issue.)*
- **Done is invariant-linked, not prose.** A work issue's Definition-of-Done cites a declared
  `INV-…` id, requires a **walked Red-path**, and green `pytest -m invariant`. This repo's
  documented AI failure mode is over-claiming verification (`THREAT_MODEL.md`, `INV-DOC-01/02`) — a
  citation beats a confident sentence. *(Improvement: board tied to the invariant scheme.)*
- **Auth.** Single repo, driven with the **owner's own `gh`** — no GitHub-App bot token, no
  cross-repo `Fixes` caveat, no push-attribution dance. *(Simplification over lotek's bot-token
  machinery.)*

## Labels

| Label | Meaning |
|---|---|
| `status:todo` | available, unclaimed — pick from here |
| `status:doing` | claimed + in progress (assignee set + `### CLAIM` handle/branch) |
| `status:blocked` | waiting — see `blocked by #N` |
| `status:review` | PR open, CI not yet green — the session merges it once it is |
| `proposal` | design that needs a dedicated session to pick up |
| `meta` | standing reference / process doc — not a work item |
| `enhancement` / `bug` / `documentation` | type (GitHub defaults) |

## Finding work

```sh
gh issue list --state open --search "no:assignee" --label "status:todo"
gh issue view <n> --comments      # read in full before claiming
gh issue edit <n> --add-assignee @me   # the lock; then ### CLAIM with handle+branch+UTC
```

## What lotek has that we deliberately don't (yet)

- `scripts/issue_flow.py` — a tool that *executes* the board doc (claim/progress/ready/release/land/
  sweep) because the silently-skipped steps get missed by hand. **Candidate to port** once the board
  sees enough traffic to make the hand-driven steps error-prone.
- A hermetic test pinning the doc's vocabulary to the tooling. Port alongside the tool.

## Changelog

- **v1 — 2026-09-11.** Board established. Created labels `status:todo|doing|blocked|review`,
  `proposal`, `meta`. Conventions adopted from lotek and simplified for single-repo/owner-auth;
  added session-handle claim identity, invariant-linked DoD, and base-ref discipline. First tracked
  work item: **#2** (`--ephemeral` rename + `--overwrite` shred-on-reap).
- **v1.1 — 2026-09-11.** Added the project Claude-memory pointer to this issue (so sessions stop
  re-deriving the board). Added the "don't waste tokens / terse by default" working norm.
- **v1.2 — 2026-09-11.** **A session now merges its own PR** once CI is green, rather than
  parking it in `status:review` for a human. `status:review` re-scoped to mean "PR open, CI
  not yet green". Enabled `deleteBranchOnMerge` on the repo, so a merged branch stops
  lingering on origin. Recorded the single remaining human gate: **cutting a release**.
- **v1.3 — 2026-11-03.** Graduated conventions from issue #3 body to `docs/ISSUE_BOARD.md`
  on `main`. Issue #3 now points here; this file is the source of truth going forward.

#!/usr/bin/env python3
"""Two mechanical gates on `Bash`, and deliberately only two.

Adopted from lotek, which runs thirteen. Most of lotek's encode a JUDGEMENT — "is this the
right moment to refactor", "should this be a separate PR" — and roughly 65% of their blocks
are overridden in practice, which is the number that tells you a gate is really a reminder
wearing a refusal's clothes. A gate that is usually wrong teaches everyone to reach for the
override, including on the occasions it was right.

These two are the ones that have never been overridden across 1,601 recorded events over
there, and the reason is structural rather than lucky: each encodes a MECHANICAL rule, not
an opinion. There is no case where `git add -A` is what you meant, and no case where a
release tag on untested bytes is fine. Nothing else from that system is worth having here
yet; if a third rule is ever added, the bar is "can it be wrong?" and the answer has to be
no.

Exit 0 = allow. Exit 2 = block, with the reason on stderr.

FAILING OPEN IS DELIBERATE. `settings.json` locates this file by trying `$CLAUDE_PROJECT_DIR`
and then `$PWD`, and exits 0 if neither has it. That is not laziness about enforcement — it is
the only safe shape for a hook that runs before EVERY Bash call. When the path did not resolve
(a worktree session whose `$CLAUDE_PROJECT_DIR` pointed at a main checkout that had not pulled
these files yet), the hook errored and every single Bash call in that session was refused,
including the ones needed to fix it. A gate that can brick a session is worse than the
behaviour it prevents, and neither of these two rules is a security control: bulk staging is
hygiene, and the real release gate is `cut-release.sh` plus CI on the tag.

KNOWN LIMITATION, stated rather than papered over: these match the command TEXT, so
`grep -n "git add -A" README.md` is blocked even though it stages nothing. That is the
correct trade for a gate that must never be wrong in the permissive direction — the failure
mode is an inconvenient refusal you can rephrase, not a silent miss. Parsing shell properly
to avoid it would mean a parser, and a parser is a thing that can disagree with the shell.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# ── gate 1: bulk staging ──────────────────────────────────────────────────────────────
# `git add -A`, `git add .` and `git commit -a` repeatedly swept unrelated work into a
# commit — a stray debug print, another session's scratch file, a whole untracked directory
# nobody looked at. The damage is not the mess: it is that the commit message then describes
# something other than the diff, and the diff is what a reviewer trusts.
#
# Matched on the command text rather than on intent, because intent is exactly the thing a
# mechanical gate must not try to read.
BULK_STAGE = [
    (re.compile(r"\bgit\s+add\s+(-A\b|--all\b)"), "git add -A"),
    (re.compile(r"\bgit\s+add\s+(-[A-Za-z]*u[A-Za-z]*\b|--update\b)"), "git add -u"),
    (re.compile(r"\bgit\s+add\s+\.(\s|$)"), "git add ."),
    (re.compile(r"\bgit\s+add\s+:/(\s|$)"), "git add :/"),
    (re.compile(r"\bgit\s+commit\b[^|;&]*\s(-[A-Za-z]*a[A-Za-z]*\b|--all\b)"), "git commit -a"),
]

BULK_MESSAGE = """\
Refusing {what}: bulk staging.

Stage the files you actually changed, by name:

    git add path/one path/two

This is not a style preference. Bulk staging has repeatedly swept unrelated work into a
commit here — another session's scratch file, a debug print, a whole untracked directory —
and the cost is not the mess, it is that the commit message then describes something other
than the diff. The diff is what a reviewer trusts.

`git status --short` first if you are not sure what is dirty. If you genuinely want
everything, name everything; the typing is the point."""

# ── gate 2: a release tag on unacked bytes ────────────────────────────────────────────
# A version tag is the one action in this repo that cannot be taken back: pushing it
# triggers `.github/workflows/publish.yml`, and once PyPI has accepted an upload that
# version is spent (docs/RELEASING.md). So the tag must be pinned to bytes whose gate was
# observed to pass — not to a branch, not to "tests were green earlier", but to the exact
# commit sha being tagged.
#
# `./scripts/cut-release.sh` already runs that gate. This refuses the ways AROUND it.
TAG_PATTERNS = [
    (re.compile(r"\bgit\s+tag\b(?![^|;&]*\s-d\b)[^|;&]*\bv?\d+\.\d+"), "a version tag"),
    (re.compile(r"\bgit\s+push\b[^|;&]*(--tags|--follow-tags)\b"), "a tag push"),
    (re.compile(r"\bgit\s+push\b[^|;&]*\srefs/tags/"), "a tag push"),
    (re.compile(r"\bgh\s+release\s+create\b"), "a GitHub release"),
]

ACK = ".claude/release-ack.json"

TAG_MESSAGE = """\
Refusing {what}: {why}

A version tag is the only irreversible action in this repo. Pushing it triggers
.github/workflows/publish.yml, and once PyPI accepts an upload that version is spent —
yanking is not unpublishing (docs/RELEASING.md).

Use the script, which runs the whole gate and tags for you:

    ./scripts/cut-release.sh --check      # run the gate, tag nothing
    ./scripts/cut-release.sh X.Y.Z        # verify, stamp, tag

If you are doing something the script does not cover, record the evidence against the exact
sha first:

    ./scripts/ack-release.sh

That runs ruff, the self-build and `pytest -m invariant`, and writes {ack} naming the sha it
ran against. The ack is pinned to the sha on purpose: "the tests passed" is a claim about
bytes, and a claim about a branch is not the same claim.

Cutting a release is also the one thing in this project that stays the owner's call."""


def _head() -> str:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                           timeout=15)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _ack_problem() -> str:
    """Why the ack does not cover HEAD, or "" if it does."""
    p = Path(ACK)
    if not p.is_file():
        return f"no {ACK}, so nothing says the tests passed on these bytes."
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"{ACK} is unreadable ({e})."
    if not data.get("ok"):
        return f"{ACK} records a FAILING gate run."
    head = _head()
    if not head:
        return "this is not a git checkout, so the ack cannot be pinned to anything."
    if data.get("sha") != head:
        return (f"{ACK} is pinned to {str(data.get('sha'))[:12]}, but HEAD is {head[:12]}. "
                f"The gate was run on different bytes than the ones being tagged.")
    return ""


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0                      # never block because the hook itself is confused
    if event.get("tool_name") != "Bash":
        return 0
    command = (event.get("tool_input") or {}).get("command") or ""

    for pattern, what in BULK_STAGE:
        if pattern.search(command):
            print(BULK_MESSAGE.format(what=what), file=sys.stderr)
            return 2

    for pattern, what in TAG_PATTERNS:
        if pattern.search(command):
            if problem := _ack_problem():
                print(TAG_MESSAGE.format(what=what, why=problem, ack=ACK), file=sys.stderr)
                return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

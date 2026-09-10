# busybody — chaos testing for haru-pack binaries

```sh
python tools/busybody.py                      # every persona
python tools/busybody.py --persona forger     # one persona
python tools/busybody.py --list               # every case and why it exists
python tools/busybody.py --keep               # leave the wreckage to inspect
```

Output per run: `busybody/out/runs/<run-id>/` containing `report.txt` (written to be read on
its own), `journal.jsonl`, `results.json`, and preserved artifacts for any finding.

```sh
python tools/busybody.py --history     # every run; interrupted ones say so
python tools/busybody.py --triage      # findings grouped by fingerprint, across all runs
```

Exit codes are a contract: `0` clean, `1` findings, `130` interrupted. **An interrupt beats
findings** — a run you killed did not finish, and reporting its partial findings as a
completed verdict is the same lie facing the other way.

## The point is not "does it break"

Anything breaks if you hit it hard enough. What matters is **how**.

A launcher that refuses a tampered payload with one clear line is working correctly. A
launcher that prints a Nim traceback full of build-machine paths, or hangs, or — worst —
exits 0 having quietly done the wrong thing, is not. Every case declares which of those it
expects, and three outcomes are findings no matter what any case expected.

| Outcome | Meaning | Verdict |
|---|---|---|
| `RAN` | exit 0, app's marker in stdout | depends on the case |
| `REFUSED` | non-zero, haru-pack diagnostic — a guard fired | usually good |
| `CRASHED` | a raw language-level traceback reached the user | **always a finding** |
| `HUNG` | no exit within the timeout | **always a finding** |
| `SILENT` | exit 0, but the app never ran | **always a finding, the worst kind** |

`SILENT` is worst because it is the one a human does not notice. A crash gets reported; a
binary that exits 0 having run someone else's code does not.

## The personas

Each persona is a *mindset* that generates a family of faults, not a single test. Adding a
case means asking "what else would this person do?", which is a more productive question
than "what else could go wrong?".

### butterfingers — not malicious, just unlucky

The user whose download died at 60%, who hit Ctrl-C during a slow first run, whose file
manager dropped the executable bit. No adversary, no cleverness. This persona exists because
most real failures are accidents, and a tool that only handles attacks is unfinished.

Cases: truncated binary · payload lopped off · killed mid-stage then re-run · executable bit
removed.

The interesting one is **killed mid-stage**: the next run must recover. A cache that
poisons itself the first time someone is impatient is worse than no cache.

### squatter — got there first

Arrived before you did and left something behind. Pre-created the cache directory with a
plausible `.ready` token, dropped a `uv` earlier on `PATH`, made the cache world-writable.
Not necessarily the same user; possibly just a shared machine.

Cases: pre-created stage with a fake `.ready` · `uv` planted on `PATH` · world-writable cache.

Tests trust-on-first-use. The original staging code short-circuited on a bare `.ready` file,
which meant anyone who could create that path chose what the signed binary executed.

### forger — edits the artifact

Has the binary and a hex editor. Flips payload bytes, rewrites footer fields, appends a
second footer, rebuilds the payload zip with valid CRCs, points `HARUPACK_DEV_STAGE` at
their own tree.

Cases: payload byte flipped · payload reforged with valid CRCs · nonsense footer extent ·
second footer appended · dev-stage redirect.

This persona is where expectations get honest. **`payload_reforged_with_valid_crcs` is
expected to SUCCEED** — the footer digest is not a MAC, `INV-LAUNCH-01` says so in its own
Note, and this case is what that sentence means in practice. A first draft of it merely
flipped a byte and got `REFUSED`, which looked like tamper-detection but was the zip's own
CRC32 refusing a corrupt archive — an incidental check a real attacker would never trip.

If that case ever starts refusing, something gained genuine authentication and the
invariant needs updating. That is a finding in the good direction.

### vandal — waits until it works, then wrecks it

Lets the first run succeed, then modifies a staged file, deletes one, opens the tree to the
world, replaces the stage directory with a symlink. Everything this persona does happens
*after* haru-pack was satisfied.

Cases: staged file modified after success · staged file deleted · stage opened to the world ·
stage replaced with a symlink.

Tests reuse-time verification specifically. A stage checked once and trusted forever is a
stage anyone can edit between runs.

### landlord — owns the building, sets hostile terms

The environment nobody designs for. Read-only cache directory, no `HOME` at all, empty
`PATH`, a paranoid `umask`. Not an attack — a locked-down build agent, a container with a
minimal environment, a shared host with strange defaults.

Cases: read-only cache · no HOME · empty PATH · umask 077.

The standard here is low but absolute: whatever it decides to do, it must not crash deciding.
Every one of these is a plausible CI environment.

### twin — two of them, at once

Two first runs racing on one cold cache. Staging is meant to be atomic — build in a
per-process temporary directory, then move into place — so both processes should end up
working and neither should observe a half-built tree.

Cases: two cold starts simultaneously.

### timetraveller — moves the clock, lies about location

Spoofs `HARUPACK_GEO`, sets licence variables that should not apply.

This persona is unusual: **it is expected to get through.** The docs say expiry and geo are
advisory — geo reads an environment variable supplied by the person being restricted, and
expiry reads their clock. A refusal here would mean the documentation *understates* what
those checks do, which is its own kind of finding.

A persona whose passing result confirms a documented weakness is worth having. It keeps the
docs honest in the direction they are most likely to drift.

## What busybody found on its first real run

Two bugs in busybody itself, and one in haru-pack.

**In busybody:** a case that mis-declared its expectation (`dev_stage_redirect` expected
`REFUSED`, but ignoring an environment variable and running normally is the *correct*
behaviour — `RAN` is right and `SILENT` is the failure), and a case that treated the OS
refusing to `exec` a non-executable file as a harness error rather than a refusal.

**In haru-pack — the real one:** a packed script binary run from inside any directory
containing a `pyproject.toml` caused `uv` to discover that project and rebuild **its**
`.venv` against the staged interpreter. cwd is the user's launch directory by design
(run-in-place), and uv walks up from cwd.

It was found destructively: a chaos case whose work directory sat inside this checkout left
haru-pack's own `.venv/bin/python` a dangling symlink into a staged tree that was then
deleted. Running a tool inside your own repository is the *normal* case, so this would have
hit real users.

Fixed with `uv run --no-project` on the script path (`INV-LAUNCH-07`), verified both
directions by hand, and busybody's own work directories moved outside the repository so the
harness cannot damage the tree it is testing.

## The journal, the heartbeat and the ledger

Adopted from lotek's BusyBody, which had already solved this.

**Every result is written the moment it happens**, line-buffered and fsynced, not serialised
at the end. A long run that gets Ctrl-C'd, times out, or has the machine taken away keeps
everything up to the case in flight. lotek's reasoning: a wedged or SIGKILLed process must
leave its journal readable up to the last thing it did.

**A heartbeat file** is rewritten as the run proceeds. That is what lets `--history`
distinguish three states which otherwise look identical:

| state | meaning |
|---|---|
| `complete` | wrote a `finished` record |
| `live` | heartbeat is fresh; still going |
| `INTERRUPTED` | started, no finish record, heartbeat stale |

An interrupted run showing up **as interrupted** is the point. "No results file" and "the run
died halfway through" are very different facts, and only one of them is interesting.

**The findings ledger lives outside the repository** — beside the checkout, or wherever
`HARUPACK_BUSYBODY_LEDGER` points. lotek keeps its ledger outside the tree because a file
inside is caught by `git stash`, worktree switches and branch changes, losing history exactly
when you are hopping branches to investigate. haru-pack is developed in worktrees, so this
applies here too.

**Findings are fingerprinted.** Paths, timestamps, hex, ports and bare numbers are normalised
out before hashing, so several cases failing for one reason collapse into one group with a
count and a first-seen date. `--triage` prints those groups largest-first with the remedy
attached. Without normalisation every run produces a fresh set of apparently-unrelated
failures and any trend is invisible.

**Severity is a closed vocabulary**: `critical` / `warning` / `note`. Not "error", not
"info" — three words, learned once. A `CASE-ERROR` (busybody's own bug) is always a `note`,
never a finding about haru-pack. Two of those turned up on the first real run; keeping them
separate from product defects is the whole reason the split exists.

**Artifacts for a finding are preserved unconditionally** under the run's `findings/`
directory — the mutated binary and the cache it produced — whether or not `--keep` was
passed. `--keep` is a flag people remember only after the interesting run.

## Reading the report without any help

`busybody/out/report.txt` is written to stand alone. Each finding carries:

- **OUTCOME** and what that outcome means
- **EXPECTED** — what the case would have accepted
- **INVARIANT** — the `INVARIANTS.md` entry that governs it
- **WHAT THIS CASE SIMULATES** — why anyone wrote it
- **WHAT TO DO** — the concrete next step, named in advance
- the last lines of stderr/stdout

If you are holding that file and nothing else, that is meant to be enough.

## Adding a case

Cases are plain Python functions in `tools/busybody.py`, not data. They mutate binaries and
environments, so code is the honest representation.

```python
@case("vandal", ("REFUSED",),
      "What this simulates, and why it matters.",
      inv="INV-STAGE-01",
      remedy="What to do when this fails.")
def my_case(exe: Path, work: Path) -> dict:
    ...
    return run_exe(victim, work, env=clean_env(work / "c"))
```

`work` is a temporary directory outside the repository. Use `clean_env()` for the
environment — it scrubs `VIRTUAL_ENV`, `PYTHONPATH` and friends, without which a case can
reach back out and modify the environment busybody itself runs from.

A clean run means the faults somebody thought of did not break anything. It is evidence, not
proof. **Adding a case that fails is worth more than re-running the ones that pass.**

## The top-25 sweep, and what it did not tell us — 2026-09-10

```sh
python tools/busybody.py --fixtures top25 --tier thick
```

**575 runs (23 cases × 25 packages), 575 as expected, 35 minutes.** Every top-25 fixture
built; 69.8 GB of work directories reaped afterwards.

And the useful result is a negative one: **no case changed its outcome depending on the
payload.** The ledger quantifies it — 575 runs produced exactly **23 distinct
fingerprints**, one per case. Each case gave an identical answer 25 times.

That is not a surprise in hindsight. These cases exercise the *launcher*, and the launcher
is byte-identical in all 25 binaries. Sweeping it across packages re-confirms the same 23
facts at 25× the cost.

An attempt to fix that is instructive. `native_library_modified_after_success` was added
believing it would be payload-sensitive: pure-Python packages have no `.so` to modify, so
the case would skip on some and fire on others. **Wrong** — at the thick tier every payload
bundles an interpreter and therefore ships `.so` files, and `iniconfig` (pure Python) caught
a flipped byte in the bundled `libpython` itself. Same fingerprint as `cryptography`.

The case stayed, because what it *does* prove is worth having: the staging digest manifest
covers compiled artifacts, including `libpython`, not just `.py` files. A naive "verify the
Python files" implementation would pass every other vandal case and fail this one.

### What this means for how to run it

- **The synthetic fixture is the right default.** It answers the same 23 questions in 100
  seconds instead of 35 minutes.
- **Sweeping the top 25 is worth it after a change to staging or overlay handling**, where
  payload shape plausibly matters and the cost buys reassurance.
- **Cases that would genuinely vary by package** have to exercise the *application*, not the
  launcher: an app that writes files next to itself, one that spawns subprocesses, one that
  needs a display, one whose import has side effects. None of the current cases do, and
  writing them means a different kind of persona than the seven here.

Recording the negative result rather than the run count, because "575/575 passed" reads like
25× the assurance and is not.

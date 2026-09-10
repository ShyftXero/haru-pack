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
python tools/busybody.py --analyze     # did the last sweep buy anything? what diverged?
python tools/busybody.py --calibrate --fixtures top25    # find a discriminating threshold
```

## Analysis is a tool, not a reading exercise

Every analysis in this document was first done by hand, with throwaway one-liners over
`journal.jsonl`. That works exactly once. It does not survive the person who wrote the
one-liner, it cannot be re-run later to compare, and it burns whoever repeats it — a human
scrolling a 900-line JSONL file, or a model ingesting it as tokens — for an answer the
machine computes in a millisecond.

So the questions are the tool:

**`--analyze [RUN]`** prints the fingerprint census, the divergence matrix, the outcome and
blame distributions, and the slowest cases. The census is the one that matters: *N case runs
produced M distinct results*. A 25-fixture sweep with a 25:1 ratio confirmed the same facts
once per fixture — which is not 25× the assurance, and the report says so in those words.

**`--calibrate`** measures the resource band between fixtures and prints a threshold to
paste, along with the per-fixture requirements to paste beside it. It stages each fixture
unrestricted first, so what gets measured is the *application's* requirement rather than
staging's — the latter being identical for every package and not the question. It also says
plainly that the number is machine-specific and does not transfer.

Neither needs a model. Neither needs you to open the raw records.

## wedge — the persona that attacks the config

The other twelve personas abuse a binary that was already built. `wedge` attacks the
**declaration**, and it is a different class of bug: a config contradiction that builds
cleanly ships an artifact whose behaviour nobody predicted from reading the config, and the
build is the last point at which the person who can fix it is still watching.

A *wedge* is a configuration where two directives cannot both be honoured. Four outcomes:

| outcome | meaning |
|---|---|
| `REFUSED` | the build stopped and named at least one side of the conflict. Best case. |
| `WARNED` | it built and said which side it overrode. Fine when precedence is documented. |
| `RAN` | it built and the predicted damage did not occur — the wedge was not a real contradiction. The **case** is wrong, not the tool. |
| `SILENT-WEDGE` | it built, said nothing, and the artifact carries the damage. **A finding.** |

`SILENT-WEDGE` is in `FATAL`. `WARNED` deliberately is not: resolving a conflict and saying
which side lost is the behaviour this persona is asking for.

Each case names the artifact property it expects to be damaged and then checks it, so a
finding is never "the config was weird" — it is "the config was weird **and** here is the
resulting binary's specific defect."

### Three defects on the first run

**`app_subdir` containing `..`** — the payload builder copies the project to
`payload/<app_subdir>`, so the application landed *outside* the payload. The zip is
assembled from the payload root, the app was not under it, and the launcher staged a binary
with no entrypoint: `can't open file '.../escaped/app.py'`. Same class as a zip-slip — a
path from config escaping the root it is resolved against.

**`expires` in the past** — `cryptbox.nim` compares the policy date to now and quits with
`license expired`, so the artifact was dead on arrival and the failure read as a licensing
problem rather than the typo it was.

**An unrecognised `cwd_policy`** — `main.nim` compares it against `"exe"` and treats
everything else as `"launch"`, so a typo and a deliberate choice produced identical binaries.
The difference surfaced only as a relative path resolving from the wrong directory on someone
else's machine.

All three are now refused at build time by `validate_manifest` / `validate_encryption`, with
messages that name both sides. `tests/test_config_wedges.py` claims them, including a check
that `CWD_POLICIES` only lists values `main.nim` actually branches on — so the validator
cannot drift into validating against a fiction.

### It also caught two of its own cases cheating

`licence_expires_before_it_is_built` and `three_names_for_one_artifact` both *passed* at
first, and both were wrong. They refused — but for an unrelated guard that fired earlier: no
secret supplied, and an ambiguous entrypoint. Neither had reached the wedge it claimed to
test.

That is the same mistake `payload_edited_and_footer_recomputed` made when it took a CRC32
rejection as proof of tamper detection. `REFUSED-UNRELATED` now names it: *the build refused
without mentioning either side of the conflict, so the case missed its target.* It is a note
against busybody, not a pass for haru-pack. Fixing the two cases to isolate their wedges is
what exposed the expiry defect.

**A case must isolate its wedge, or it measures whichever guard happens to fire first.**

### Wedge cases run once

They are registered `per_fixture=False`. They build their own artifact and say nothing about
the packed package, so running them once per fixture would repeat one answer 25 times and
inflate exactly the census INV-CHAOS-04 exists to keep honest.

## Running it wide

```sh
python tools/busybody.py --fixtures top25 --tier thick --jobs 8
```

Measured on a 20-core box, top-25 at tier=thick, 37 cases:

| jobs | wall clock | result |
|---|---|---|
| 1 | 389.9 s | 37/37 behaved as expected |
| 4 | 142.1 s | 37/37 behaved as expected |
| 8 | 70.5 s | 37/37 behaved as expected |

**Identical outcomes at all three widths is the point; the speedup is only the reason to
bother.** A harness whose results depend on how many workers it used has no results — every
finding becomes "is that real, or was the box just busy?"

Default is 4, cap is 8. The cap is not a shrug: each worker stages a real interpreter (peak
452 MB measured) and spawns processes with their own rlimits, and past 8 the timing-sensitive
cases start reporting the load rather than the product.

### Four cases never share the machine

`killed_mid_stage`, `two_cold_starts_at_once`, `interrupted_while_the_app_runs` and
`terminated_mid_run` are marked `serial=True` and run in their own pass afterwards. Each
sleeps for a fixed interval and then signals — they are asking *where had the process got to
after 0.7 seconds?*, and the answer changes when seven other cases are competing for CPU.

Marking a case serial costs wall clock. Not marking one that needs it costs a flaky result
that reads as a regression, which is worse.

### One code path

`run_one()` executes a case. The parallel pass hands work items to a pool; the serial pass
calls the same function inline. Two implementations would drift, and the drift shows up as
"it only fails under `--jobs 8`" — the least debuggable shape available.

The journal and the findings ledger have exactly one writer: the parent. Workers return
records and never touch shared state, which keeps the fsync-per-line contract that makes an
interrupted run readable. Results come back through ordered `imap`, not `imap_unordered`, so
two runs of the same sweep produce comparable journals — that comparability is what makes the
fingerprint census reproducible rather than merely repeatable.

`--keep` forces one worker: it retains every work directory, 131 GB for a top-25 sweep, and
running wide only makes that peak arrive sooner. mpire is a dev-group dependency; without it
the sweep runs serially and says so.

## When the box fails, not the product

A 925-run sweep on 2026-09-10 reported **470 findings**. All of them were one disk quota.

The harness wrote work directories into `/tmp`, which on this machine carries `usrquota`
with a 24 GiB per-user ceiling. At case 168 the launcher started failing with
`errno: 122 Disk quota exceeded`, and every case after that — across all twenty remaining
fixtures — recorded that failure under whichever persona happened to be running. Three
distinct defects, all in one event:

1. **Work dirs were freed only at the end of the run.** The reaper tracked all 925 and
   removed them in the run-level `finally`. That was itself the fix for an earlier
   leak-on-raise bug, and it traded a small leak for a large one: 925 thick-tier work dirs
   at ~145 MB each needs about 100 GB. 168 x 145 MB is 24 GiB — exactly where it died.
2. **The failure was scored per case.** One environment failure became thirty different
   "findings" per fixture, and 470 rows went into the findings ledger.
3. **`--analyze` called it divergence.** It reported *30 of 37 cases diverged by fixture*.
   None had.

What made it readable in seconds was the divergence matrix itself: the same five fixtures
passed every single case, and no property of a Python package produces that. Those five were
the five built before the quota ran out. The tool found its own run invalid — which is the
point of having it, and it should not have needed to.

### What changed

| | |
|---|---|
| `reaper.release(work)` | frees each case's scratch immediately; `reap()` stays as the backstop for a raise or Ctrl-C |
| `infra_failure_reason()` | errno 122/28 aborts the sweep instead of scoring it |
| ledger | an aborted run writes **nothing** — a ledger full of one failure in thirty costumes is worse than an empty one |
| `--work-root DIR` | put scratch on a filesystem with room |
| `--scratch-cap-gb N` | abort on a leak at a number you chose, default 8 |
| `--analyze` | an aborted run prints `THE BOX FAILED, NOT THE PRODUCT` and labels the fake divergence |

### `df` is not the ceiling

This is the part worth remembering. `df` said 31 GiB free on `/tmp`, and the next write
failed at 24 GiB, because a **per-user quota is invisible to `statvfs`**. A preflight that
only checked free space would have reported plenty of room and been wrong.

So the harness prints the scratch mount's quota options at the start of every sweep:

```
scratch    : /tmp  (31.2 GiB free per statvfs)
             /tmp has a quota (usrquota). The number above is NOT the ceiling —
             a per-user quota is invisible to statvfs. Use --work-root to move scratch
             somewhere unquota'd if a long sweep dies with errno 122.
```

Recovering an already-poisoned run: `--analyze <RUN>` now labels it, and the ledger rows can
be dropped by `run` id. The run's journal is append-only, so the honest repair is to *append*
an `infra_failure` annotation rather than edit the original records.

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

## App-level personas — the ones that vary by package

The seven personas above attack the **launcher**, which is byte-identical in every binary
haru-pack produces. That is why sweeping them across 25 packages produced 575 runs and only
23 fingerprints. These five attack the **packaged application** instead.

### cartographer — messes with *where*

Awkward cwd (spaces, quotes, unicode), invocation through a symlink, a read-only working
directory, hostile argv. Tests the run-in-place contract: haru-pack promises a binary behaves
like a compiled program in the folder it was launched from, and passes args through "like
python" with no injected `--`.

### polyglot — locale and encoding

The C locale with no `LANG` and legacy codecs forced on; unicode in the cache path. Packages
that decode text diverge sharply here; ones that do not, do not.

### mute — I/O shape

Closed stdin, and stdout slammed shut mid-write (the `| head -1` case). The stdin case also
covers the licence prompt, which is guarded on `isatty` — a hang there would be the serious
outcome.

### impatient — signals to the *app*

Ctrl-C and SIGTERM after staging, so the signal lands on the application rather than on
staging. `main.nim` installs a custom SIGINT handler specifically so the child owns Ctrl-C;
a comment said so and nothing tested it until now.

### hoarder — resource ceilings

Few file descriptors, a tight address space, a read-only `TMPDIR`. The most
package-dependent of the lot, and the one that required real work to make so.

## Two things this taught, both worth keeping

**A threshold only discriminates if it sits between the packages.** The first
`tight_address_space` used 256 MB — below what a bare interpreter needs — so every package
failed identically and the case discriminated nothing while looking thorough. Calibrated on
this box:

| package | 512 MB | 768 MB | 1024 MB |
|---|---|---|---|
| iniconfig | ok | ok | ok |
| numpy | fail | fail | ok |

768 MB separates them, and that number is in the source with the measurement beside it. If it
stops diverging, recalibrate — do not nudge it.

**"The launcher crashed" and "the app crashed" are different findings.** Once calibrated, the
case diverged and then reported the divergence as `CRASHED` — a haru-pack defect — because the
classifier could not tell a numpy `MemoryError` from a Nim traceback. There is now an
`APP-CRASHED` outcome and a `blame` field (`launcher` / `app` / `os` / `harness`), split cheaply on
the fact that the launcher prefixes every diagnostic with `haru-pack:`. `APP-CRASHED` is
deliberately **not** fatal: an application declining a limit a persona imposed on purpose is
behaving correctly, and a case has to opt into accepting it.

### Measured divergence

Across `iniconfig` (pure Python, 60 MB) and `numpy` (native BLAS, 77 MB):

| level | cases | diverged by package |
|---|---|---|
| launcher (7 personas) | 24 | **0** |
| app (5 personas) | 13 | **2** |

The two: `tight_address_space` (RAN vs APP-CRASHED — a real, stable property) and
`interrupted_while_the_app_runs` (RAN vs REFUSED — but that one turns on *import speed*, so
it is a fact about this machine, and the case says so).

2 of 13 is a modest result and worth stating plainly: the bundled interpreter absorbs most
environmental hostility, so most app-level cases still answer identically regardless of what
was packed. Cases that discriminate have to target something the package genuinely changes —
its resource envelope, its native libraries, its startup cost.

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

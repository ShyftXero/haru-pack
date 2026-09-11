# busybody — chaos testing for haru-pack binaries

```sh
python tools/busybody.py                      # every persona
python tools/busybody.py --persona forger     # one persona
python tools/busybody.py --list               # every case and why it exists
python tools/busybody.py --keep               # leave the wreckage to inspect
python tools/busybody.py --seed 7             # same seed, same seeded faults
```

Output per run: `busybody/out/runs/<run-id>/` containing `report.txt` (written to be read on
its own), `journal.jsonl`, `results.json`, and preserved artifacts for any finding.

```sh
python tools/busybody.py --history     # every run; interrupted ones say so
python tools/busybody.py --triage      # findings grouped by fingerprint, across all runs
```

Three knobs change what happens rather than what gets reported:

| flag | default | effect |
|---|---|---|
| `--timeout N` | 180 | the default wait for a case that does not name its own |
| `--seed N` | 0 | the stream for cases that pick a moment or a victim |
| `--herd-n N` | 16 | children per `herd` case; floored at 2, since nothing below that races |

`--timeout` is newly honest rather than new: it was parsed and never read, `run_exe`
hardcoding 120 while the help advertised 180. Cases that name their own wait still keep it.
`--seed` reproduces a choice exactly — same seed, same case, same fixture, same moment.

Exit codes are a contract: `0` clean, `1` findings, `130` interrupted. **An interrupt beats
findings** — a run you killed did not finish, and reporting its partial findings as a
completed verdict is the same lie facing the other way.

## The point is not "does it break"

Anything breaks if you hit it hard enough. What matters is **how**.

A launcher that refuses a tampered payload with one clear line is working correctly. A
launcher that prints a Nim traceback full of build-machine paths, or hangs, or — worst —
exits 0 having quietly done the wrong thing, is not. Every case declares which of those it
expects, and four outcomes are findings no matter what any case expected.

| Outcome | Meaning | Verdict |
|---|---|---|
| `RAN` | exit 0, app's marker in stdout | depends on the case |
| `REFUSED` | non-zero, haru-pack diagnostic — a guard fired | usually good |
| `CRASHED` | a raw language-level traceback reached the user | **always a finding** |
| `HUNG` | no exit within the timeout | **always a finding** |
| `SILENT` | exit 0, but the app never ran | **always a finding, the worst kind** |
| `WEDGED` | nothing was progressing; declared from outside | **always a finding** |

`SILENT` is worst because it is the one a human does not notice. A crash gets reported; a
binary that exits 0 having run someone else's code does not. It carries a second reading for
a build-kind case: exit 0, and the directive the operator wrote was ignored.

`WEDGED` is the odd one out: it is the only outcome no process can report about itself,
which is why it arrives from a watchdog and has a section of its own below.

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

### herd — sixteen of them, at once

The same race at the scale a CI job actually has: one binary per worker, all starting
against one cold cache key at the same instant, watched from outside by a thread that owns
none of them. `twin` proves two processes can share a stage; this asks whether sixteen can.

Cases: sixteen cold starts · sixteen cold starts with one child killed mid-stage at a
seeded moment · sixteen starts against a stage directory whose owner is dead and never
wrote `.ready`.

The failure this persona exists for is the one no child can report — everybody alive,
nobody burning CPU, nothing being written — so read the wedge section below before reading
a result from it. All three cases are registered `light=True`: the work directory holds one
shared stage plus up to N transient staging trees, and preserving sixteen near-identical
copies of the same payload is a slow way to learn nothing.

`--herd-n` sets N. The three cases are three cases and not 3×N, because `--triage` ranks
groups by count and sixteen registered cases per fault would rank one bug sixteen times.

### timetraveller — moves the clock, lies about location

Spoofs `HARUPACK_GEO`, sets licence variables that should not apply.

This persona is unusual: **it is expected to get through.** The docs say expiry and geo are
advisory — geo reads an environment variable supplied by the person being restricted, and
expiry reads their clock. A refusal here would mean the documentation *understates* what
those checks do, which is its own kind of finding.

A persona whose passing result confirms a documented weakness is worth having. It keeps the
docs honest in the direction they are most likely to drift.

## App-level personas — the ones that vary by package

The eight personas above attack the **launcher**, which is byte-identical in every binary
haru-pack produces. That is why sweeping the seven that existed on 2026-09-10 across 25
packages produced 575 runs and only 23 fingerprints. These five attack the **packaged
application** instead.

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

A third case runs one binary twice on one cache: once with stdout on a real pty
(`pty.openpty`, so `isatty` is genuinely true) and once on a pipe. The marker has to
survive both. That is the shape `INV-UI-01` was written about — rich reads `[...]` as a
style tag and drops an unrecognised one *silently*, so a message is eaten rather than
mangled, and the piped path is the one nobody is watching. Escape sequences are stripped
from **both** sides before classifying: a marker wearing a colour code would otherwise read
as `SILENT` and this case would file ANSI as a launcher defect, and comparing a stripped tty
against an unstripped pipe would call every run a divergence instead. Formatting may
legitimately differ — a tty gets width-dependent wrapping — so the record reports whether
the two texts agree without failing the case on a terminal width.

This case is the transferable half of an idea that was otherwise declined; see
[`BRAINSTORM.md`](BRAINSTORM.md) §1b.

### impatient — signals to the *app*

Ctrl-C and SIGTERM after staging, so the signal lands on the application rather than on
staging. `main.nim` installs a custom SIGINT handler specifically so the child owns Ctrl-C;
a comment said so and nothing tested it until now.

### hoarder — resource ceilings

Few file descriptors, a tight address space, a read-only `TMPDIR`. The most
package-dependent of the lot, and the one that required real work to make so.

## A build-time persona — the one that attacks the build, not the binary

The thirteen personas above all need a finished artifact. This one attacks the build that
produces it, which is where the human fumbling that matters for haru-pack actually happens:
a wrong flag, a stale sidecar, a typo'd directive.

### tinkerer — lives in configuration

The eager operator who keeps editing the table until something desyncs. Directives arrive
from four places, lowest precedence first: discovery < `[tool.haru-pack]` in
`pyproject.toml` < `haru_pack.toml` < CLI flags. `build._declarations` merges the middle two
with `dict.update`, per top-level key and not deep; `build._resolve` then consumes the
merged dict with plain `decl.get()` calls. Nothing in that ladder validates a key.

Cases: an underscored `[tool.haru_pack]` table · a directive key misspelled by one
character (`entry-point`) · the two homes disagreeing · a directive contradicted by the CLI
flag that duplicates it · `--thin --thick` together · an entrypoint naming a file outside
the project, in two spellings · a `[[bundle]]` list in both homes.

The oracle was already written down before the persona existed. `INV-BUILD-07`'s Assets
paragraph says *"a config table read by nobody is worse than a missing one, because the
operator believes it took effect"* — which is `SILENT`, the outcome this harness already
calls the worst kind. A build that exits 0 having ignored a directive is the packaging form
of a Save that returns 200 and never persists.

The discriminator here is three-way, not two, because haru-pack ships refusals that hand
over the fix: refuse **with the fix** is correct, refuse uselessly is a docs defect, ignore
silently is the finding. Only the third is a `SILENT`.

## Two kinds of case, and why one of them runs once

Every case is registered with a `kind`, and the driver dispatches on that field.

| kind | receives | how often |
|---|---|---|
| `exe` | a prebuilt binary, plus a fresh work directory | once per fixture |
| `build` | the `haru-pack` CLI, plus a fresh work directory | once per **run** |

An `exe`-kind case attacks a finished artifact, and the artifact is exactly what
`--fixtures` varies, so it runs once for each. A `build`-kind case writes its own throwaway
project into its work directory, runs `haru-pack build` itself, and reads the exit code, the
merged log and the resulting artifact's manifest as evidence. The fixtures are not an input
to any of that.

Running it once per fixture anyway is not merely wasteful, it is a measured mistake. The
2026-09-10 sweep priced it: 575 runs across 25 packages produced **23 distinct
fingerprints**, one per case, each answered identically 25 times, because those cases
exercise the launcher and the launcher is byte-identical in all 25 binaries. A build-time
case is payload-invariant for the same reason one step earlier, and the sweep is what 25×
re-confirmation costs — 35 minutes against 100 seconds.

Build records say so rather than leaving it to be worked out: `fixture` reads `none
(build-time case)`, and `kind` travels all the way to `results.json`, the journal and the
ledger.

**Dispatch is on the registry field, never on the function's arity.** The two signatures
differ — `fn(exe, work)` against `fn(haru, work)` — and calling one with the other's target
raises `TypeError`, which the driver's deliberately-broad `except` swallows into a
`CASE-ERROR`. A case registered under the wrong kind would then read as a harness bug in
the report instead of as one wrong word in one decorator.

## The seed, and journalling before acting

Every fault busybody injected before `--seed` existed landed at a **fixed** point:
`killed_mid_stage` kills mid-stage, `impatient` signals after staging. Those are one point
each on an axis that is continuous, and a SIGKILL 40 ms after the `.tmp-` directory appears
is a different fault from one 4 s in.

A case that wants a moment or a victim asks `Ctx.rng(salt)` for it. The stream is determined
by `(seed, case name, fixture, salt)` and nothing else, hashed with `hashlib` rather than the
`hash()` builtin: `hash()` is salted per process, so the same `--seed` would draw a different
stream every run and the one thing a seed exists for would silently not work.

**Journal the perturbation before performing it, never after.** `Ctx.perturb(action,
**fields)` writes a `perturb` record, flushes and fsyncs; the case acts after that returns.
The ordering is the whole discipline. A fault whose moment came out of a seed is
unattributable if it is recorded afterwards — one case name, two outcomes, and a journal that
cannot say which moment it chose — and the harness's own jitter then reads as a haru-pack
defect. That is the confusion the `CASE-ERROR` split exists to prevent, arriving by a
different door.

Three rules those records obey, each of which is a way to get this wrong:

- **The seed is a field you read, not an identity.** It is deliberately absent from the
  fingerprint basis, and `normalize()` collapses bare numbers anyway, so seeded variants of
  one fault group together at `--triage` instead of arriving as a fresh bug per run.
- **An observation is not a perturbation.** The watchdog writes a `wedge` record directly and
  not through `perturb`, because filing something the harness *saw* as something it *did*
  would make the seeded-kill record — the one record a seed exists to make reproducible —
  untrustworthy.
- **A case that can outlast the heartbeat must beat from inside itself**, via `Ctx.beat()`.
  `busybody_ledger.HEARTBEAT_STALE_S` is 120 s, shorter than several in-case waits, and the
  driver beats only *between* cases. A stale heartbeat is precisely how `reap_orphans` and
  `prune_runs` decide a run is dead and delete its work directories, so a live herd case
  going quiet would have its own evidence reaped out from under it.

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
`APP-CRASHED` outcome and a `blame` field (`launcher` / `app` / `unknown`), split cheaply on
the fact that the launcher prefixes every diagnostic with `haru-pack:`. `APP-CRASHED` is
deliberately **not** fatal: an application declining a limit a persona imposed on purpose is
behaving correctly, and a case has to opt into accepting it.

### Measured divergence

Across `iniconfig` (pure Python, 60 MB) and `numpy` (native BLAS, 77 MB). The persona and
case counts are the ones that existed on the day, not today's:

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
count and a first-seen date. Without normalisation every run produces a fresh set of
apparently-unrelated failures and any trend is invisible.

`--triage` prints those groups largest-first with the remedy attached — **cascades last,
whatever their count**, which is the one exception and is explained under the wedge below.

**Severity is a closed vocabulary**: `critical` / `warning` / `note`. Not "error", not
"info" — three words, learned once. A `CASE-ERROR` (busybody's own bug) is always a `note`,
never a finding about haru-pack. Two of those turned up on the first real run; keeping them
separate from product defects is the whole reason the split exists.

**Artifacts for a finding are preserved unconditionally** under the run's `findings/`
directory — the mutated binary and the cache it produced — whether or not `--keep` was
passed. `--keep` is a flag people remember only after the interesting run.

## The wedge — the failure nothing can report about itself

Every other outcome is a verdict about one process, reached by the parent that started it,
and `HUNG` is where that runs out. `communicate(timeout=...)` can say "this child did not
exit in time". It cannot tell *slow because sixteen processes are contending for one cache
key* from *stopped, permanently* — the two are identical from inside any one of them, and a
process that is not running cannot notice that it is not running.

So `WEDGED` is declared from outside, by a watchdog thread that owns none of the children
and is not one of the things it judges. It samples three signals once a second and requires
all three, AND-ed, held **continuously**:

- every child is still alive — an exit is progress, and the collector classifies it
- no child's CPU time advanced — `utime+stime` from `/proc/<pid>/stat`, for all of them, not
  for one
- the staged byte total under the cache base did not grow — the tree is not being built

The conjunction is what makes three individually unreliable signals safe together. The byte
walk can miss growth under churn and `/proc` is a clock tick coarse, but neither can declare
a wedge on its own: sixteen processes burning CPU are never quiet, whatever the walk says.

Blame follows the same rule the `launcher` / `app` split already follows: `launcher` only on
launcher-side evidence, and there is exactly one piece of it — a `<key>.tmp-<pid>` staging
directory whose byte count is static and whose **owner pid is dead**. `stage.nim` names that
directory after its author, so an orphan identifies itself, and "the survivors are waiting on
a tree nobody is building" becomes a claim about haru-pack's state rather than about the box.
Everything else is `unknown`, including — checked first, before anything else — the sampler
not having been scheduled on time. A watchdog that files its own starvation as a product
wedge is `tight_address_space` at 256 MB again: it fires, it looks thorough, it discriminates
nothing.

### The threshold is provisional, and the source says so

`WEDGE_QUIET_S = 40.0`. What that number wants is the longest genuine no-progress stretch of
a *healthy* sixteen-way cold start of a thick binary, and that has **not been measured** — no
thick fixture existed in this worktree and building one is tens of minutes.

What was measured, 2026-09-11 on this box (20 cores, 62 GB, NVMe), is a proxy with the same
phases: sixteen concurrent processes, each copying a 47 MB zip into its own
`<key>.tmp-<pid>` under one shared base, extracting it (4516 files), sha256-ing every
extracted file and renaming the tree into place — `stageZip` minus the interpreter start, uv
and the network, watched by this same watchdog. Two runs, cold and warm page cache: **30 s
and 11 s wall, 10 and 6 samples, longest quiet stretch 0.0 s in both.** No two consecutive
samples were ever quiet, on either run.

Which means the proxy does not measure the healthy quiet period. It *bounds* it below the
sampling interval — 1.3-1.7 s, the byte walk alone costing 345-662 ms at 16 × 4516 files —
and since the proxy is missing a real cold start's two slowest phases, even that bound is a
lower one. Hence 40 s: an order of magnitude above anything observed, not 2×. The source
carries the replacement measurement as a TODO rather than a hope — run `--persona herd
--herd-n 16` against a thick fixture three times and read the "longest quiet stretch" figure
the verdict record already prints.

Erring high costs detection latency. Erring low costs the case its meaning, which is the
more expensive mistake and the one already written down here: a threshold under the real
quiet period of a healthy cold start cries wedge on a working run, and a case that always
fires is a case nobody reads.

A limit of the method, measured while validating it: **an application that deliberately
idles is indistinguishable from a stall** by these three signals. A fixture that only slept
produced 6 s of continuous quiet on a healthy four-way herd. So the herd cases hold for
fixtures that stage, print and exit — which every busybody fixture does — and a packaged app
that waits on a socket or a prompt for longer than the threshold does not belong in this
persona at any threshold.

### post_wedge — one stall is one finding

Once a wedge is declared, everything that resolves at or after that instant is tagged
`post_wedge` and carries the wedge's `wedge_id`. The tagging is the cheap half of this whole
feature and the half easiest to skip.

Here is the arithmetic it prevents. Sixteen children waiting on one dead stager all time out.
Untagged, that single stall enters the ledger as sixteen `HUNG` records which fingerprint
into a group of sixteen, and `--triage` — which ranks groups by count — then puts one bug
above every genuine finding, sixteen times over. That is the same error as reading "575/575
passed" as 25× the assurance, with the sign flipped.

So a cascade is de-emphasised, not hidden:

- A cascade is **not** marked `ok`. Marking it so would erase it from the findings section and
  from the exit code, and a suppressed consequence is not the same claim as a passing case.
- Cascades **do** reach the ledger, because the shape of a cascade is the primary evidence for
  the wedge that caused it. Suppressing is triage's job, not the ledger's.
- `ledger_rollup` groups on `(fingerprint, cascade)` and sorts cascades last, so no cascade
  group outranks a fresh finding however many children fell. The flag is part of the grouping
  key and deliberately *not* part of the fingerprint basis, so the same fault seen cleanly
  does not merge into its own cascade group.
- `--history` counts `findings` and `cascades` in separate columns for the same reason: one
  stall that produced sixteen consequences should read `1` and `16`, not `17`.

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

A `build`-kind case takes the CLI instead of a binary, and declares that in its
registration rather than by its signature:

```python
@case("tinkerer", ("REFUSED",),
      "What this simulates, and why it matters.",
      inv="INV-BUILD-07",
      remedy="What to do when this fails.",
      kind="build")
def my_build_case(haru: Path, work: Path) -> dict:
    proj = tinker_project(work, pyproject=PYPROJECT + '[tool.haru-pack]\nkey = "v"\n')
    b = run_build(haru, proj, work, "--thin")
    honoured = manifest_entrypoint(b["exe"]) == ["expected.py"]
    return build_verdict(b, classify_build(b, honoured=honoured),
                         "what was read, and from where", "the detail for the report")
```

`haru` is the `haru-pack` CLI, resolved the way `build_fixture` resolves it. The throwaway
project lives in `work` alongside the artifact, so a build case needs no fixture and is
given none. `honoured` is the case's own oracle — whether the directive took effect — and
`classify_build` turns exit 0 with `honoured=False` into `SILENT`. That single mapping is
what makes an ignored directive a finding instead of a pass. Pass `honoured=None` for a case
that expects a refusal and has nothing to read back: exit 0 is then `SILENT` by definition,
because the build accepted what it was supposed to turn down.

`light=True` is the other registration flag worth knowing. It tells `preserve` to copy the
work directory's top-level files and merely *name* the subdirectories it skipped — for a case
whose wreckage is N near-identical staging trees, like every herd case.

A clean run means the faults somebody thought of did not break anything. It is evidence, not
proof. **Adding a case that fails is worth more than re-running the ones that pass.**

## What the two new personas assert — and what they are expected to report

No full run of `herd` or `tinkerer` is recorded here, so this section states what the cases
*assert* rather than what a run returned. Three of the seven `tinkerer` cases are written
expecting a refusal that today's haru-pack does not give, and it matters that those read as
product findings rather than as miscalibrated cases: the harness's own mistakes are
`CASE-ERROR` at severity `note` by construction, and never findings about haru-pack.

**What "the directive took effect" is read from**, because `RAN` here does not mean "it ran".
Not the build log — the receipt prints out, tier, target, payload length and sha, and names
no directive. Not the artifact's behaviour either: a thin binary fetches uv and a Python on
first run, so executing one needs the network and measures the *launcher*, which twelve other
personas already do to death. The oracle is `manifest.toml` at the payload zip root, the same
bytes the launcher parses at stage time, read back out of the artifact without running it. So
`RAN` in this persona means "exit 0 **and** the shipped artifact records the directive as
honoured", and each case names the field it read. The remaining gap — *and the launcher then
obeys the manifest* — is what the other personas are for.

The three, with the code that makes each one expected:

1. **An unknown directive key, ignored silently.** `[tool.haru-pack] entry-point = "cli.py"`
   is the one-character typo of `entrypoint`. There is no unknown-key validation anywhere in
   the ladder: `_declarations` merges the table wholesale with `dict.update`, and `_resolve`
   reads the names it knows with plain `decl.get()` calls. A key nobody reads is
   indistinguishable from a key nobody wrote, so the build has nothing to refuse and
   discovery's answer ships. `INV-BUILD-07`'s Statement covers the underscored *table* and
   says nothing about an unknown *key* inside a correctly-named one — yet its Assets
   paragraph is the oracle for both. The remedy names the fix: validate the merged top-level
   keys against the set actually read, suggest the nearest match, and widen the Statement
   with a claiming test per spelling.
2. **Containment defeated by spelling.** Two probes over the same file outside the tree.
   `../shared/cli.py` is refused, because `entrypoints._PLAIN_NAME` does not admit a leading
   `..`. `sub/../../shared/cli.py` reaches the same file through a directory that does exist,
   and `verify_script_file` builds `Path(project) / spec` and asks `is_file()` — so an
   interior `..` landing on a real file passes a check that is not about resolution at all.
   The remedy is not a better regex: resolve the candidate and require it under `decl_dir`,
   which is the containment check `archives._is_within` already applies to archive members.
3. **Contradictory tier flags, resolved without a word.** `cli._run_build` holds two
   unguarded assignments, `if thin: tier = "thin"` and `if thick or chonky: tier = "thick"`,
   so the second wins whatever order the flags were typed in and nothing is printed either
   way. No invariant covers this today. The case reads the tier back out of the artifact's
   manifest so the record names which one won, and counts exit 0 as the finding whichever it
   was — the contradiction was settled in silence, which is the bug `--shake` exists to
   avoid, asked for small and silently got fat. On a box where the thick path cannot complete
   the case may instead report `CRASHED`, and that is a second defect rather than noise:
   `archives.UnpinnedArtifact` subclasses `RuntimeError` while `cli.py` catches only
   `BuildError`, `EntryPointError`, `AmbiguousProject` and `TargetError`, so a missing
   interpreter pin reaches the operator as a rich traceback full of build-machine paths.
   A non-zero exit that is *not* about the contradiction degrades to `CASE-ERROR`, never to
   a `REFUSED` the case did not earn.

None of the three is fixed. They are written down so that a `SILENT` from this persona reads
as the known shape of a known defect, and so a *refusal* turning up there is recognised as
the good kind of finding — the role `payload_reforged_with_valid_crcs` already plays for
`forger`.

The other four `tinkerer` cases are the calibration, and a persona needs them: one whose
every case fails discriminates nothing, which is `tight_address_space` at 256 MB pointing
the other way. They are the underscored `[tool.haru_pack]` table, which `_declarations`
refuses by name; the sidecar overriding `[tool.haru-pack]`; a CLI flag overriding both; and a
`[[bundle]]` list present in both homes, where the sidecar's list replaces rather than
appends.

For `herd`, the pass is every judged child `RAN` with no wedge declared, and the record
carries what a reader needs whether or not one was: how many children were judged and their
outcomes, any child this case killed on purpose, and the longest quiet stretch measured
against the threshold a wedge would have needed. `REFUSED` is inside the orphaned-stage
case's `expect` set on purpose — refusing a stage tree that carries no `.ready` is what
`INV-STAGE-01` already requires — so the interesting failure there is sixteen processes
*waiting* on a tree whose owner is dead, not one of them declining it.

**The invariant these cases point at does not fully cover them, and they say so.**
`INV-STAGE-01` governs what a stage must satisfy before it is executed — a real directory,
the right owner, not group- or world-writable, a `.ready` naming this payload's digest, every
`.stage-files` entry still hashing — which is exactly what the survivors' verdict asserts.
Neither it nor `INV-STAGE-02` mentions concurrency or atomicity; that claim lives only in
`twin`'s remedy prose. Each herd case's remedy names the missing invariant as a thing to
write rather than a footnote to bolt on.

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

**What came of that last bullet.** Three persona groups were written against it. The five
app-level ones diverged on 2 of 13 cases, recorded above — a modest result, kept as it
measured. `herd` and `tinkerer` took the other route the bullet implies: discriminate on
haru-pack's own state rather than on the payload — concurrent staging in one case, the build
itself in the other — so both answer against the synthetic fixture and neither has any reason
to be swept across 25 packages.

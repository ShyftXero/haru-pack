# haru-pack — invariants

Properties this codebase has decided must never regress. Adopted from the lotek
`INVARIANTS.md` pattern; the ID scheme, the mandatory **Red-path**, and the
machine-checked linkage contract are the same.

## Why this file exists

haru-pack's first full adversarial review (2026-09-09) found five security claims
that were documented, dated, and marked "Verified" — and unimplemented. The failure
mode is not carelessness; it is that **prose evidence is satisfiable by a claim**.
A paragraph saying "the launcher verifies its payload sha256" costs the same to write
whether or not the code does it. `pytest -m invariant` does not.

The design constraint, borrowed from lotek's process retrospective:

> Any new control must produce evidence a human can check in under a minute,
> or it will be satisfied with a claim.

## Entry format

| Field | Meaning |
|---|---|
| `Status` | `active` — **must** have ≥1 test marked `@pytest.mark.invariant("<id>")`. `proposed` — **must** have zero. A `proposed` entry is a known gap, honestly labelled, not a promise. |
| `Statement` | One falsifiable sentence. |
| `Actors` | Who is on the other side of it. |
| `Assets` | What is lost if it breaks. |
| `Red-path` | **Mandatory.** What you would break to watch the claiming test go red. If you cannot write this, you do not have an invariant — you have a wish. |
| `Source` | The commit, audit, or incident it was mined from. |
| `Territory` | Repo-relative paths where the behavior lives. Required once `active`. |

## What this file does and does not prove

The linkage contract (`tests/test_invariants_enforced.py`) proves that every `active`
invariant is **claimed** by at least one test. It **cannot prove efficacy** — it has no
way to distinguish a test that would go red along the red-path from one that could not.
That is why the Red-path field is mandatory and why neutralize-then-observe-red is the
expected workflow before marking an invariant `active`.

Fourteen entries are deliberately `proposed` as of 2026-09-15 — `INV-LAUNCH-03`,
`INV-SUPPLY-02`, the whole `INV-TRUST-*` family and others; `grep '^Status: proposed'` for the
current list, which this paragraph will otherwise fall behind. The behavior is **not
implemented**, or is only partly implemented and the entry says which part. They are written
down so the gap is legible, not so it looks covered.

**Each `active` entry records in its own Red-path field how it was promoted.** The entries dated
2026-09-09 were promoted by walking it — neutralize the guard, observe the claiming test go red,
restore. Later entries give their own date, and some say plainly what was NOT walked:
`INV-SANDBOX-01` and `INV-SANDBOX-02` were walked against the argv builder only, not against the
call site that decides which mode the builder is handed. Where an adversarial verifier
subsequently proved a claiming test *vacuous* (green with the guard removed), the entry was not
promoted until the test was fixed; two were. Several entries have had their **Statement
narrowed** because verification showed the original wording claimed more than the code does —
most recently `INV-SUPPLY-01`, `INV-SANDBOX-01` and `INV-SANDBOX-02` on 2026-09-15. Those
narrowings are recorded in the entries themselves rather than quietly applied.

---

## TIER — a tier's description is a promise about run time

### INV-TIER-01
Status: active
Statement: A `--thick` build carries everything it needs to run, including a PEP 723
script's inline dependencies; the resulting binary runs with no network access on a machine
that has never seen it before.
Actors: not an attacker — an operator shipping to an air-gapped machine, a locked-down
enterprise host, or anywhere the first run happens without a network.
Assets: the tier's meaning. `docs/TIERS.md` describes thick as "download NOTHING, fully
offline"; a build that quietly needs the network makes every other statement about the tiers
suspect.
Red-path: Replace the `warm_cache_for_script(...)` call in `assemble_payload` with `pass`,
build a thick binary from a PEP 723 script with a dependency, and run it with a pristine
`XDG_CACHE_HOME` and `UV_OFFLINE=1`. Walked 2026-09-09: it failed with uv's *"Packages were
unavailable because the network was disabled"*, and the payload was 1.7 MB smaller — the
missing wheel.
Source: Found 2026-09-09 while building the flex harness's offline check.
`assemble_payload` warmed the dependency cache only under `if manifest.get("kind") ==
"project" or steps`, so scripts got uv and an interpreter but not their dependencies. The
build reported success; the tier's own description said the opposite.
Note: **The pristine cache is the load-bearing part of any test of this.** With a warm
`~/.cache/haru-pack` the staged tree is reused and an offline run succeeds regardless of what
the payload contains — a vacuous green. `tools/flex-run.py --tier thick --offline-check`
creates a fresh cache directory per package for exactly this reason.
Note: Staging is automatic at thick rather than opt-in, because thick's contract already
promises it; leaving it opt-in would mean the documented behaviour is wrong by default. It is
announced on stdout, since it changes both what ships and how large the binary is.
Note: What the offline check proves is bounded. It forces uv offline and points the proxy
variables at a dead port, which blocks the dependency-fetch path. It is not a network
namespace — this build host cannot create one — so it does not stop a package from opening a
socket of its own. Do not read a green offline check as "this binary makes no network calls".
Note: Cross-compiled thick builds take the `warm_cache_windows` path, which resolves wheels
for the target platform without executing them. Script staging runs the target interpreter,
so it is host-target only.
Note: Verified 2026-09-10 by busybody's `examiner` persona, which runs a packaged library's
OWN test suite from inside the thick binary with the network denied at the process level:

    numpy     2175 passed, 3 skipped, 2 xfailed in 26.33s   (100.8 MB binary)
    certifi      3 passed in 0.03s                          ( 63.7 MB binary)

This is a stronger statement than a hello-world fixture can make. `import numpy` succeeds
long before numpy is usable — the failure modes of a bundled native package live in the
parts an import never touches: a lazily-loaded `.so`, an f2py-generated extension, a
packaged data file. The figures above are the WHEEL-path measurement: checked across all 25
top-PyPI packages, only numpy and certifi ship a runnable suite in the wheel. As of
2026-09-16 the examiner sources each package's suite from its SDIST instead (INV-CHAOS-15),
reusing the flex exam's `tools/exam_fetch`, so it now covers any top-N package rather than
that pair — and numpy and certifi, whose suites ride only in the wheel, are themselves
recorded honestly as "no test suite in sdist".
Note: A vacuous pass is prevented twice over. The generated script verifies the test paths
exist and exits 2 with `PAYLOAD INCOMPLETE` if they do not, and pytest itself returns 5
rather than 0 when it collects nothing. The success marker is printed only on rc == 0.
Territory: src/haru_pack/build/, src/haru_pack/bundle.py, src/haru_pack/discovery.py,
tests/test_tiers_offline.py, tests/test_examiner_fixtures.py, tools/flex-run.py

### INV-TIER-03
Status: active
Statement: A payload built for a foreign target contains only objects for that target. No
host ELF object reaches a Windows payload; no x86-64 object reaches an aarch64 payload.
Actors: whoever runs `--target linux-aarch64` and deploys the result to a Raspberry Pi, and
whoever runs `--target windows` and emails the exe to a customer.
Assets: the meaning of `--target`. A cross-built binary that carries host objects fails on
first run on the machine it was explicitly built for — after the build reported success, and
after the artifact has been signed and shipped. The operator has no reason to suspect it and
no way to see it without unpacking the binary.
Red-path: A payload whose members include `\x7fELF` objects under `--target windows`, or ELF
objects with `e_machine` 0x3E (x86-64) under `--target linux-aarch64`. Both are checked
statically by busybody's `crosseyed` cases, which read the payload rather than running it —
a Windows payload cannot be executed on Linux, but it can be inspected, and that is what
makes the check possible without a second machine. `tests/test_compose.py` pins the
`e_machine` decoding, because getting 0x3E and 0xB7 the wrong way round would make the
aarch64 check pass on an x86 payload.
Source: 2026-09-10, from the persona brainstorm. Cross-target correctness had four tests in
`tests/test_targets.py` covering target PARSING and none covering payload CONTENTS, so
nothing anywhere verified that a foreign payload held foreign objects. uv's
`--python-platform` resolves wheels for the target without executing them, which is the
right mechanism; the risk is any path that stages with the host interpreter instead.
Note: The Raspberry Pi is a stated deployment target for this project, which is why the
aarch64 case is not hypothetical. ARM Linux is a target, not a build host.
Note: `tourist` covers the adjacent question — what happens when a foreign artifact IS
executed here — and its honest scope is "fails cleanly". A real foreign run needs a real
foreign machine; `openclaw` is the ARM one on hand.
Territory: src/haru_pack/targets.py, src/haru_pack/bundle.py, tools/busybody*.py,
tests/test_compose.py, tests/test_targets.py

---

### INV-TIER-04
Status: proposed
Statement: A build declared free-threaded runs on a free-threaded interpreter on the target, at
every tier — not only `thick`.
Actors: an operator who passed `--free-threaded`, got exit 0, and shipped it.
Assets: the flag's meaning. A flag that is silently a no-op at two of three tiers is worse than
an unimplemented one, because it is believed.
Red-path: Remove the `python_request` key from the manifest, build a `default`-tier binary with
`--free-threaded`, run it, and assert `sys._is_gil_enabled()` is `False`. It will be `True`.
Source: docs/FREE_THREADED.md, 2026-09-10 — found by reading `launcher/main.nim:175` and
noticing `manifest.python` is a path, not a version, so no tier without a staged interpreter
carries the variant to the target at all.
Territory: not yet — nothing is implemented. Planned:
src/haru_pack/build/, src/haru_pack/launcher/manifest.nim, src/haru_pack/launcher/main.nim

---

## CHAOS — the harness remembers what happened
### INV-TIER-02
Status: active
Statement: A build that combines `post_install` steps with `--thick` says so loudly, because
the two are contradictory: `post_install` means "fetch and set up on the target, on first
run", and thick sets `UV_OFFLINE=1` and promises to download nothing.
Actors: an operator following haru-pack's own advice. `scaffold.KNOWN` tells you to declare a
`post_install` step for spacy, nltk, transformers and tiktoken; nothing warned that doing so
and then building thick produces a binary that fails on the target.
Assets: the operator's time, and their trust in the tool's advice. The failure lands on first
run, on the target machine, after the build reported success.
Red-path: Delete the `tier == "thick" and manifest.get("post_install")` warning from
`assemble_payload`. The claiming test builds a thick project with a post_install step and
requires the warning; it goes red.
Source: Measured 2026-09-09 by the flex hard-target run — the first time these were built.
`spacy` FAILED on the first run of its thick binary: its documented post_install step is
`python -m spacy download en_core_web_sm`, and uv refused the download the tier had disabled.
`nltk` passed with a network and then FAILED the offline check. Both were configured exactly
as `scaffold.KNOWN` recommends.
Note: A warning, not a refusal. haru-pack cannot tell whether a given step needs the network —
`flask db upgrade` does not, `spacy download` does — and refusing would block the legitimate
cases. The fix for a downloading step is a `[[bundle]]` step, which runs at build time and
ships its output in the payload; that is what playwright does, and playwright passed thick +
offline at 225 MB with firefox bundled.
Territory: src/haru_pack/build/, src/haru_pack/cli/, tests/test_tiers_offline.py

---

## CHAOS — the harness remembers what happened

### INV-CHAOS-01
Status: active
Statement: A busybody run's results survive the run being killed, an interrupted run is
reported AS interrupted, and repeated findings group under one fingerprint.
Actors: whoever reads the output — days later, on a run they did not start, with no AI to
summarise it for them.
Assets: the ability to act on a chaos run at all. A harness whose long run loses everything
on Ctrl-C, or that cannot tell a new crash from one that has been there for weeks, produces
noise rather than evidence.
Red-path: Buffer the journal and write it at the end — an interrupted run then loses every
completed case. Or drop the `finished` record and the heartbeat, and a run that died halfway
becomes indistinguishable from one with no results. Or remove the volatile-token
normalisation from `fingerprint()`, and one root cause splits into a fresh group per run.
Each has a claiming test.
Source: Adopted from lotek's BusyBody (`tests/busybody/journal.py`, `ledger.py`) on
2026-09-09, after this harness was built without any of it and the gap was pointed out.
lotek's journals are line-buffered and flushed per record specifically so "a wedged or
SIGKILLed process must leave its journal readable up to the last thing it did".
Note: The exit-code contract is lotek's and encodes a judgement worth keeping — 0 clean, 1
findings, 130 interrupted, and **an interrupt beats findings**: a run the operator killed did
not finish, and reporting its partial findings as a completed verdict is the same lie facing
the other way.
Note: The findings ledger lives OUTSIDE the repository. lotek's reasoning applies with force
here: a file inside the tree is caught by `git stash`, worktree switches and branch changes,
losing history exactly when you are moving between branches to investigate. haru-pack is
developed in worktrees. Override with `HARUPACK_BUSYBODY_LEDGER`.
Note: Severity is a closed three-value vocabulary — critical / warning / note — also lotek's.
A `CASE-ERROR` (busybody's own bug) is a `note`, never a finding about haru-pack. Two of
those turned up on the first real run, and conflating them with product defects is precisely
what the split prevents.
Territory: tools/busybody_ledger.py, tools/busybody*.py, tests/test_busybody_ledger.py

### INV-CHAOS-02
Status: active
Statement: Every working directory a chaos run creates is removed when the run ends, however
it ends — success, a raising case, or an interrupt — except artifacts deliberately held for a
finding, which are reported with their size.
Actors: not an attacker — whoever owns the disk. Also the next person to run the suite on a
box that has been quietly filling up.
Assets: the machine. At the thick tier each work directory holds a staged interpreter;
measured, three cases leaked 489.7 MB. A harness nobody can afford to run is a harness
nobody runs.
Red-path: Move `reaper.reap()` out of `main()`'s `finally` block onto the success path.
Interrupt a run, or let a case raise, and the directories survive. One claiming test parses
`main()`'s AST and fails if the reap call is not reachable from a `finally`, because "we put
it back on the happy path" is the regression worth catching, not the absence of the call.
Source: A correctness bug in the first version of busybody, found on 2026-09-09 while adding
the ledger. Work dirs were removed only when a case succeeded — and a chaos harness is the
program most likely to be interrupted, so best-effort cleanup was exactly the wrong shape.
Note: `Reaper.reap()` never raises. It runs in a `finally`, so an exception there would mask
the original failure — the one actually worth reading.
Note: Orphan reaping and run pruning follow lotek's `cleanup.py` heartbeat rule: if any run
has a fresh heartbeat, something may still be using its directories and nothing is touched. A
missing or unreadable heartbeat means not live, and both are safe to reap, because a live run
always has a fresh one.
Territory: tools/busybody_ledger.py, tools/busybody*.py, tests/test_busybody_ledger.py

### INV-CHAOS-03
Status: active
Statement: A chaos finding distinguishes the launcher failing from the packaged application
failing, and any resource threshold used to tell packages apart is calibrated to sit between
their actual requirements rather than chosen by eye.
Actors: whoever triages the report. Also the next person to add an app-level case.
Assets: whether a chaos run means anything. A harness that calls "numpy will not start in
768 MB" a product defect trains people to ignore its findings; one whose thresholds sit below
every package discriminates nothing while looking thorough.
Red-path: Add `APP-CRASHED` to `FATAL`, and every resource-limit case reports a finding on
any heavy package — the exact outcome those cases exist to produce. Or set
`ADDRESS_SPACE_MB` outside the measured band (512 < n < 1024) and the case stops telling
`iniconfig` and `numpy` apart. Each has a claiming test.
Source: Both learned on 2026-09-10 while building the app-level personas. The first
`tight_address_space` used 256 MB, which is below what a bare interpreter needs — so every
package failed identically and the case discriminated nothing. Once calibrated to 768 MB it
diverged, and then reported the fixture-divergence as `CRASHED`, i.e. as a haru-pack bug, because the
classifier could not tell a numpy `MemoryError` from a Nim traceback.
Note: The split is cheap because the launcher prefixes every diagnostic with `haru-pack:`.
That convention is now load-bearing for triage, not only for readability.
Note: `interrupted_while_the_app_runs` also diverges by package, but on IMPORT SPEED — the
signal goes 0.7 s in, and numpy is still importing while iniconfig has finished. That is a
fact about this machine, not a stable property of either package, and the case says so. Do
not read a change there as a regression without checking the box it ran on.
Note: Launcher-level personas are payload-invariant by construction and no threshold will
change that. Measured 2026-09-10: 575 runs across 25 packages produced 23 fingerprints, one
per case. App-level personas are the only ones for which `--fixtures top25` buys anything,
and even then only 2 of 13 diverged — the bundled interpreter absorbs most environmental
difference.
Territory: tools/busybody*.py, tests/test_busybody_ledger.py

---

### INV-CHAOS-04
Status: active
Statement: Every question asked of a chaos run is answerable by a tool that reads the run's
own records, and the report states how many distinct results the run produced — not only how
many runs it performed.
Actors: whoever reads a sweep six months from now, with no model available and no memory of
how the numbers were computed.
Assets: whether the harness's output means anything to a human. A sweep that reports
"925/925 passed" and nothing else reads like 925x the assurance of a single run. It is not,
if every case answered identically 925 times, and the difference is not visible without
computing it.
Red-path: Delete the fixture-divergence computation from `analyze_run`, or the FINGERPRINT CENSUS
from `format_analysis`, and a 25-fixture sweep reports a large run count with no way to see
that it confirmed the same handful of facts once per fixture. Two claiming tests feed
`analyze_run` synthetic journals — one where every fixture agrees, one where they do not —
and assert the report says which happened.
Source: 2026-09-10. Every analysis in docs/BUSYBODY.md was first produced by hand with
throwaway one-liners over `journal.jsonl`. That works exactly once: it does not survive the
person who wrote it, cannot be re-run to compare, and costs whoever repeats it — a human
scrolling 900 lines of JSONL, or a model ingesting them as tokens — for an answer the machine
computes in a millisecond.
Note: `--calibrate` is the same principle applied to thresholds. It measures the band and
prints a number to paste, with the per-fixture measurements to paste beside it, so the next
person recalibrates instead of nudging. It also states that the number is machine-specific.
Note: This invariant is why `tools/busybody.py --calibrate` exists at all. A comment in the
source already promised it ("re-run tools/busybody.py --calibrate rather than nudging the
number") while no such flag existed — a dangling claim of exactly the kind INV-DOC-02 exists
to catch, found in our own code.
Territory: tools/busybody_analyze.py, tools/busybody*.py, tests/test_busybody_ledger.py

---

### INV-CHAOS-05
Status: active
Statement: The harness's own environment failing is never reported as a product finding. A
run that exhausts scratch space aborts, says the box failed, and writes nothing to the
findings ledger. And scratch is freed per case, so a long sweep's live footprint stays at
one case's worth rather than the whole sweep's.
Actors: whoever reads the ledger. Also whoever runs a 900-case sweep on a machine with a
quota they have never had reason to think about.
Assets: the credibility of every finding. A ledger holding 470 rows that are all one disk
quota wearing thirty persona costumes is worse than an empty ledger — it cannot be triaged,
and it teaches the reader that busybody findings are noise.
Red-path: Delete the `infra_failure_reason` check from the case loop and a sweep that runs
out of room scores the box's failure as chaos findings across every remaining fixture.
Delete the `reaper.release(work)` call and the sweep holds every work directory until the
end — about 100 GB for 37 cases x 25 fixtures at the thick tier. Change `if bad and not
aborted` back to `if bad` and a poisoned run pollutes the ledger permanently. Each has a
claiming test.
Source: 2026-09-10, from a real 925-run sweep. It died at case 168 with `errno 122 Disk
quota exceeded` and reported 470 findings. Three separate defects in one event:

  1. Work dirs were tracked and reaped only in the run-level `finally`. That was itself a
     fix for an earlier leak-on-raise bug, and it traded a small leak for a large one:
     168 cases x ~145 MB is 24 GiB, which is exactly the user quota on this box's /tmp.
  2. The quota failure was classified per case, so one environment failure became thirty
     different "findings" per fixture.
  3. `--analyze` reported 30 of 37 cases as having DIVERGED by fixture. They had not. The
     five fixtures that passed everything were the five built before the quota ran out.

Note: The fixture-divergence report was what made the run readable at all — the same five fixtures
passing every single case is not a pattern any package property produces. The tool found its
own run invalid, which is the point of having it. It should not have needed to.
Note: `df` is not the ceiling. This box reported 31 GiB free on /tmp and refused the next
write at 24 GiB, because the mount carries `usrquota` and a per-user quota is invisible to
`statvfs`. The harness now prints the mount's quota options at the start of a sweep, and
`--work-root` moves scratch elsewhere.
Note: `--scratch-cap-gb` (default 8) aborts on a leak at a number the operator chose rather
than at whatever the filesystem happens to allow.
Territory: tools/busybody*.py, tools/busybody_ledger.py, tools/busybody_analyze.py,
tests/test_busybody_ledger.py

---

### INV-CHAOS-06
Status: active
Statement: Running the harness in parallel changes how long a sweep takes and nothing else.
A case that measures elapsed time runs in a serial pass; a case run is executed by one
function whether it runs in a worker or inline; and the journal has exactly one writer.
Actors: whoever runs `--jobs 8` to get an answer before lunch, and whoever later has to
explain why a case only fails at `--jobs 8`.
Assets: the meaning of an outcome. A harness whose results depend on how many workers it
used has no results — every finding becomes "is that real, or was the box just busy?"
Red-path: Drop `serial=True` from `interrupted_while_the_app_runs` (it sleeps 0.7 s and then
signals, so under load the signal arrives at a different point in startup) and the case
begins flipping between RAN and REFUSED with no code change. Give the parallel and serial
passes separate implementations and they drift, surfacing as "only fails under --jobs 8".
Let a worker call `jr.write` and the journal interleaves partial lines, breaking the
fsync-per-line contract INV-CHAOS-01 depends on. Each has a claiming test.
Source: 2026-09-10. Measured on this 20-core box, top-25 tier=thick, 37 cases:

    jobs=1   389.9s    37/37 behaved as expected
    jobs=4   142.1s    37/37 behaved as expected
    jobs=8    70.5s    37/37 behaved as expected

Identical outcomes at all three widths is the evidence that matters; the speedup is only
the reason to bother.
Note: `JOBS_MAX = 8` is a cap, not a default. Each worker stages a real interpreter — peak
452 MB measured — and spawns processes with their own rlimits. The ceiling exists because
past it the timing-sensitive cases start reporting the load rather than the product.
Note: `--keep` forces one worker. It retains every work directory, which is 131 GB for a
top-25 sweep, and running wide only makes that peak arrive sooner.
Note: mpire is a dev-group dependency. Nothing haru-pack ships uses it, and a sweep runs
serially and says so when it is absent — a missing convenience must not stop the work.
Note: ordered `imap`, not `imap_unordered`. An unordered journal is not byte-comparable
between two runs of the same sweep, and that comparability is what makes the fingerprint
census reproducible rather than merely repeatable.
Territory: tools/busybody*.py, tests/test_busybody_ledger.py

---

### INV-CHAOS-07
Status: active
Statement: A declaration that cannot be honoured as written is refused at build time, with a
message naming both sides of the contradiction — for the conflicts the build-time validators
cover (`build/validate.py`, `build/declare.py`, `build/geo.py`). Within that scope haru-pack
does not resolve a config conflict silently and hand back an artifact whose damage is
discovered on the target. The scope is a list of named checks, not a universal property: a
conflict nobody wrote a check for still resolves silently, and one such case is known and
unfixed — see the Note on `--thin --thick`.
Actors: whoever edits `haru_pack.toml` — often by copying a block from another project — and
whoever receives the binary that edit produced.
Assets: the operator's ability to predict an artifact from its config. Every other guard in
this file protects the binary at runtime; this one protects the meaning of the build. A
config wedge that builds cleanly is the worst shape available, because the build is the last
point at which the person who can fix it is still watching.
Red-path: Remove the `validate_manifest` call from `_resolve` and `app_subdir = "../x"`
builds a binary whose entrypoint is outside the payload — measured as
`can't open file '.../escaped/app.py'` on first run. Remove `validate_encryption` and
`expires = "2001-01-01"` builds a binary that refuses every run forever. Add a value to
`CWD_POLICIES` that `main.nim` does not implement and the config accepts a policy the
launcher silently treats as `launch`. Each has a claiming test, plus a live case in
busybody's `wedge` persona.
Source: 2026-09-10. The `wedge` persona was built to attack declarations rather than
binaries, and found three defects on its first run:

  1. `app_subdir` containing `..` — the payload builder copies the project to
     `payload/<app_subdir>`, so the application landed OUTSIDE the payload. The zip is
     assembled from the payload root, the app was not under it, and the launcher staged a
     binary with no entrypoint. Same class as a zip-slip: a path from config escaping the
     root it is resolved against.
  2. `expires` in the past. `cryptbox.nim` compares the policy date to now and quits with
     "license expired", so the artifact was dead on arrival and the failure read as a
     licensing problem rather than a typo.
  3. An unrecognised `cwd_policy`. `main.nim` compares it against `"exe"` and treats
     everything else as `"launch"`, so a typo and a deliberate choice produced identical
     binaries, and the difference only surfaced as a relative path resolving from the wrong
     directory on someone else's machine.

Note: The persona also caught two of its OWN cases passing for the wrong reason. Both
refused, but for an unrelated guard that fired first — no secret supplied, and an ambiguous
entrypoint — so neither had reached the wedge it claimed to test. That is the same mistake
`payload_edited_and_footer_recomputed` made when it took a CRC32 rejection as proof of
tamper detection. `REFUSED-UNRELATED` now names it: the build refused without mentioning
either side of the conflict, so the case missed its target and is a note against busybody
rather than a pass for haru-pack.
Note: **Known uncovered instance — contradictory CLI tier flags.** `--thin --thick` builds a
thick binary and says nothing. `cli/builddriver._resolve_tier` runs `if thin: tier = "thin"`
and then `if thick or chonky: tier = "thick"` — two unguarded ifs, so whichever is written
second wins. Nothing in the tree states that thick beats thin, so that is an accident of
ordering rather than a documented precedence (unlike the config ladder, which states its
order). Measured by busybody's `contradictory_tier_flags` case in
`tools/busybody_cases_directives.py`; reported in docs/BUSYBODY.md and not yet fixed. It is
outside the Statement because the validators above see a DECLARATION, and flag-vs-flag
conflicts have already collapsed into a single `tier` value before `build()` is called —
there is nothing left for them to contradict. That is an explanation of why the check is
missing, not a reason it should be: the honest wording is the narrowed Statement plus this
note, not a "never" the tier flags falsify.
Note: `SILENT-WEDGE` is in `FATAL`. `WARNED` deliberately is not — resolving a conflict and
saying which side lost is the behaviour this invariant asks for, not a defect.
Note: Wedge cases are `per_fixture=False`. They build their own artifact and say nothing
about the packed package, so running them once per fixture would repeat one answer 25 times
and inflate the census that INV-CHAOS-04 exists to keep honest.
Territory: src/haru_pack/build/, tools/busybody*.py, tests/test_config_wedges.py

---

### INV-CHAOS-08
Status: active
Statement: Under any stack of hostile conditions, haru-pack either works or refuses
intelligibly. It never produces a language-level traceback, never hangs, and never exits
zero without running the application. Composed runs are selected and realised from a
recorded seed, so any finding can be reproduced by one printed command.
Actors: whoever hits the combination nobody reasoned about. That is every user eventually,
because a stack of individually-ordinary conditions is what a real machine is.
Assets: the difference between chaos engineering and integration testing. A persona that
runs alone asks a closed question — "does staging cope with umask 077?" has the same answer
forever. The open question is which COMBINATION of individually-survivable conditions is not
survivable, and running them one at a time cannot answer it.
Red-path: The composed pass asserts only the FATAL floor, so removing a guard anywhere in
staging or the launcher shows up here as a CRASHED stack rather than as a specific failed
case. Concretely: delete the payload-digest check and the stacks containing
`revenant_stage_from_an_older_layout` start reporting CRASHED instead of REFUSED. Remove
`realize()`'s determinism (seed the draw from time instead of the triple) and
`--compose-only` stops reproducing a finding, which is caught by a claiming test.
Source: 2026-09-10. Built after the observation that the twelve existing personas each ran
in isolation, which makes them integration tests wearing costumes. 42 traits across 11
personas, combining to 845 conflict-free pairs and over 11,000 triples.
Note: The pass condition is deliberately weak and must stay weak. `RAN`, `REFUSED` and
`APP-CRASHED` are all acceptable for a stack, because nobody has reasoned about combination
7,431. Asserting anything stronger — "haru-pack always works under any three of these" —
would be an overclaim of exactly the kind this file exists to prevent. The floor is the
claim: it refuses intelligibly, or it works.
Note: PER-ACTION PERTURBATION PROBABILITY (cf. human error probability; FoundationDB calls
the same mechanism buggification). Each trait has a probability of acting, so a persona is a person rather
than a fixture. If greenhorn always fumbles, then "greenhorn fumbled AND auditor left a .env
behind" is the only thing ever tested, and "greenhorn got it right, auditor still left the
.env" — a different code path — never runs. A run's identity is the set that FIRED, not the
set that was selected, and both are journalled.
Note: The probability is forced to 1 for two passes, and only two. The k=1 pass IS the attribution
baseline — "does trait A fail alone?" cannot be answered by a run where A did not fire, and a
baseline with holes makes every composed finding unattributable. `--compose-only` is forced
because someone asked for a specific stack, and handing them a control run answers a
different question than the one they typed.
Note: A run where nothing fired is a control, and it is kept rather than resampled. A control
arriving naturally through the same machinery is worth more than one bolted on beside it: if
the baseline is broken, that is where it shows.
Note: `realize()` draws from sha256 of (seed, run_index, trait_name), not from a sequential
RNG and not from `random.Random(triple)` — the latter raises on Python 3.14, and even where
it works the seed-to-stream mapping is an implementation detail. A digest is stable across
Python versions and machines, which is the property a printed reproduction line actually
needs. Per-trait rather than sequential so that adding a trait to the catalogue does not
reshuffle every other trait's firing decisions in every other run.
Note: Conflicts are declared for pairs where one trait CANCELS another, not for pairs that
break together. A stack whose members cancel tests less than either member alone; a stack
that breaks together is the finding.
Territory: tools/busybody_compose.py, tools/busybody_traits.py, tools/busybody*.py,
tests/test_compose.py

---

## FLEX — the harness that decides what haru-pack is tested against

### INV-CHAOS-09
Status: active
Statement: `STALLED` is declared only by an observer outside every process being judged — never
derived from a child's exit status or from one process's own timeout — and once declared it is
a finding whatever the case said it expected.
Actors: not an attacker — whoever reads the report of a sixteen-way herd case, and the next
person to add a case that starts more than one process at a time.
Assets: the one failure class no child can report. "Everybody alive, nobody burning CPU,
nothing being written" is invisible from inside each of the processes it is happening to, and
if a single process's timeout could say `STALLED` then every slow case on a loaded box would say
it too and the class would mean nothing. A stall outside `FATAL` is worse: it is a stall a case
can declare acceptable, and a harness that exits 0 after watching nothing happen for forty
seconds.
Red-path: Two, each with a claiming test. (1) Return `"STALLED"` from `classify()` when
`timed_out` — one process's own wait then declares a system-wide stall, and the classify grid
goes red. (2) Remove `"STALLED"` from `FATAL` — the case whose `expect` set names STALLED passes,
the run exits 0, `severity_for` grades the stall `warning`, and the report's always-a-finding
legend stops naming it. Walked 2026-09-11, both red then green again — and neither test moves
along the other's branch (the classify grid is green with STALLED out of `FATAL`; the end-to-end
case is green when `classify` hands back STALLED), which is why the entry needs both.
Source: lotek's BusyBody sent back what to steal; triaged in docs/BRAINSTORM.md section 1b on
2026-09-11. The stall is the part this harness could not already see — twelve personas watched
one process at a time, and a stall is a property of several at once.
Note: HUNG and STALLED are not the same claim, and the split is the whole entry. HUNG is one
process failing to exit inside its timeout, which is all a single wait can observe. STALLED is no
process progressing, which needs several watched together: `StallWatch` AND-s three signals
(every child still alive, no child's CPU time advanced, the staged byte total did not grow) and
requires them continuously, because not one of the three is trustworthy alone.
Note: A declaration is journalled as `kind="stall"` and deliberately NOT through `Ctx.perturb`.
A perturb record means a fault the harness INJECTED; filing an observation there would make the
seeded-kill record — the one thing a seed exists to make reproducible — untrustworthy.
INV-CHAOS-11 is that record.
Note: `STALL_QUIET_S = 40` is provisional and `tools/busybody.py` says so beside the number,
with both measurements it stands on — a proxy, and then all three herd cases against a real
default-tier fixture on 2026-09-11, longest quiet stretch 0.0s over 9 to 13 ticks each — plus a
TODO naming the thick-tier measurement that has not been taken, because a thick fixture cannot
be built on that box at all (no pinned sha256 for the CPython it wants). The threshold is not
what this entry claims. Who is allowed to declare the outcome is.
Territory: tools/busybody*.py, tests/test_busybody_faults.py, tests/test_busybody_ledger.py

### INV-CHAOS-10
Status: active
Statement: A result that resolves at or after a declared stall is recorded as a cascade of that
stall, and no cascade group can outrank a fresh finding in the triage roll-up, however many
results fell into it.
Actors: whoever reads `--triage` to decide what to fix first — days later, on a run they did
not start, with nothing but the ledger.
Assets: the ranking, which is the only thing in the ledger that says what to do next. A stalled
herd is one stall and then N children failing because of it; those N share a fingerprint, so
ordering on count alone put a sixteen-count group above the single-count record of the fault
that caused it. One bug presented as the top sixteen problems, with its cause ranked
seventeenth — an arithmetic error wearing the clothes of a priority.
Red-path: Restore the count-only ordering key in `ledger_rollup` —
`sorted(out, key=lambda g: (-g["count"], g["fingerprint"]))`. The claiming test lays down one
stall plus N cascades and parametrises N over 2, 16 and 64: it goes red at every N, because the
defect is arithmetic and is already wrong at two. Walked 2026-09-11. The second claiming test,
over `--triage`'s own output, stays GREEN under it — `print_triage` splits on the `post_stall`
field rather than trusting the sort order — so the roll-up test is the one that carries this
claim, and the triage test carries the counting ("1 finding, plus 16 cascades").
Source: lotek's BusyBody sent back what to steal; triaged in docs/BRAINSTORM.md section 1b on
2026-09-11. Then measured here: `--history` and `--triage` disagreed sixteen-to-one about how
much one run had found, which is what exposed the ranking rather than any reasoning about it.
Note: `post_stall` is part of the GROUPING key and deliberately not of the fingerprint basis.
Every fingerprint already on the ledger was computed without it and has to keep matching, and
putting it in the basis would not have helped anyway — N cascades would still form one N-count
group under a different name. Rows written before the field existed carry no `post_stall`, and
`bool(None)` is False, so they group and rank exactly as they always did.
Note: A cascade is de-emphasised, never hidden. It keeps `ok=False`, it reaches the ledger, and
it prints under its own heading with the numbering running on — because the shape of a cascade
is the primary evidence for the stall that caused it. Suppressing it is triage's job, not the
ledger's.
Territory: tools/busybody_ledger.py, tools/busybody*.py, tests/test_busybody_faults.py,
tests/test_busybody_ledger.py

### INV-CHAOS-11
Status: active
Statement: A perturbation whose moment or victim was drawn from the run seed is journalled
BEFORE it is performed, so its record survives the fault it announces.
Actors: whoever tries to reproduce a finding from the journal, holding the seed and nothing
else. Also the next person to add a seeded case.
Assets: the seed's only purpose. A fault landed at a moment drawn from a seed is worth having
because it can be landed again deliberately, and that requires the moment and the victim to be
on disk — recorded afterwards, they are lost to exactly the faults worth reproducing, and the
harness's own timing jitter then reads as a product defect.
Red-path: Two, each with a claiming test. (1) Move the `Ctx.perturb(...)` call in
`sixteen_cold_starts_one_killed_mid_stage` below `target.send_signal(signal.SIGKILL)` — the
source-order test goes red. (2) Record the fault on the case record instead of before the
action (drop the write from `Ctx.perturb`, fold its fields into the record `run_one` builds) —
a case that SIGKILLs the harness then leaves a journal with no trace of what it did, and the
survival test goes red. Walked 2026-09-11, both red then green again.
Source: lotek's BusyBody sent back what to steal; triaged in docs/BRAINSTORM.md section 1b on
2026-09-11, where the `--seed` and "faults that land at a seeded moment" item is taken.
Note: The two claiming tests are deliberately different in kind, because each one stays GREEN
along the other's Red-path — measured, both ways, on 2026-09-11. Under (1) the journal's ORDER
is unchanged, since the driver writes the case record after the case returns either way: a test
that only asserts "the perturb record precedes the result record" passes while the fault is now
recorded after it landed, so the source-order test is the one that catches it. Under (2) the two
statements are still in the right order and the source-shape check passes, while a fault that
stops the recorder leaves no record at all — the journal reads `['started', 'case']`. Either
test alone would therefore be satisfiable by a claim; the source-shape half is also blind to a
fault performed inside a helper the case calls, and says so.
Note: `Journal.write` flushes and fsyncs per record for this reason, which is the same property
INV-CHAOS-01 needs for an interrupted run.
Territory: tools/busybody*.py, tools/busybody_ledger.py, tests/test_busybody_faults.py

### INV-CHAOS-12
Status: active
Statement: A `--persona` / `--case` selection whose name matches nothing is a SETUP FAILURE
(exit 2), never a silent drop. `--persona forger,typo` (one good name masking a typo) must refuse
and name the typo, not quietly run only forger and print a clean verdict — a run that silently
skipped what you asked for reads exactly like a healthy one.
Actors: whoever narrows a sweep to a persona/case and trusts the exit code — a typo that silently
runs a shorter matrix (or nothing) and exits 0/clean is the false-green this forbids.
Assets: the property that the verdict describes the run you asked for; an unmatched selection can
never masquerade as a clean pass of it.
Red-path: In `busybody.main` replace the `--case` unknown-name check with `if False and ...`,
rebuild nothing, and run `busybody.py --case truncated_binary,tyop`: the typo is dropped,
truncated_binary runs alone, the process exits 0, and
`test_a_typo_mixed_with_a_real_name_still_fails_loud` goes red. Walked 2026-09-12 on this Linux
host (observed the typo silently swallowed and rc 0).
Source: adopted from lotek BusyBody #558 (`_corpus_scripts` — an unmatched selection is fatal,
not dropped). docs/BUSYBODY.md "Selection is fail-loud".
Territory: tools/busybody*.py, tests/test_busybody_runcontrol.py

### INV-CHAOS-13
Status: active
Statement: A busybody sweep registers itself under a project-tagged registry and REFUSES to start
(exit 3) while another sweep is genuinely LIVE — its pid is alive AND its heartbeat (or, before
its first beat, its birth time) is fresh (< `BB_STALE_S`). A registry left by a DEAD or WEDGED run
(pid gone, or heartbeat older than `BB_STALE_S`) is REAPED, never trusted, so one crashed run
cannot wedge the harness forever. `HARUPACK_BUSYBODY_FORCE=1` overrides the refusal (a logged,
deliberate override), and the marker is released on exit. The registry is project-tagged and never
reads or writes another project's. The registry path is FIXED (`/tmp/harupack-busybody`, override
`$HARUPACK_BUSYBODY_REGISTRY`) and NOT `tempfile.gettempdir()` — a sweep isolates its scratch with
its own `$TMPDIR`, so a gettempdir-derived registry would move with the scratch dir and two sweeps
would never see each other.
Actors: an operator (or a second agent session) who launches a sweep while one is already running.
Two sweeps each stage a real interpreter per worker and thrash the box into the OOM killer — the
failure observed 2026-09-12, when a concurrent thick top-50 sweep was killed at every concurrency.
Assets: the property that only one interpreter-staging sweep runs at a time unless forced, so a
sweep's resource use is bounded and its results are not polluted by a co-runner's contention; and
that a dead run's leftover marker degrades to reapable, not to a permanent block.
Red-path: In `guard_single_instance` replace `raise SystemExit(3)` on the live branch with `pass`,
and `test_a_live_sweep_blocks_a_second_one` goes red (DID NOT RAISE — a second sweep starts beside
a live one). Separately, make `_bb_live` ignore the heartbeat/birth freshness (return True on a
live pid alone) and `test_a_stale_heartbeat_makes_even_a_live_pid_reapable` goes red. Separately,
set `BB_REGISTRY = Path(tempfile.gettempdir()) / "harupack-busybody"` and, under a `$TMPDIR`
pointing at a real writable dir, `test_registry_is_a_fixed_path_not_tmpdir_derived` goes red (the
registry follows the scratch dir). Walked 2026-09-12 on this Linux host (all three observed).
Source: adopted from lotek BusyBody #738 (single-instance reaper, graceful stop, project-tagged
registry — lotek explicitly reserves its own tag so haru-pack gets its own). docs/BUSYBODY.md "Run control".
Checks pids directly with `os.kill(pid, 0)`, so there is no ps-grep self-match trap (CLAUDE.md).
Territory: tools/busybody*.py, tests/test_busybody_runcontrol.py

### INV-CHAOS-14
Status: active
Statement: `--analyze` is a GATE, not just a reader: it exits non-zero whenever the run it
re-reads is not a clean, completed pass. `analyze_exit_code` returns 2 when no verdict was
possible (a SETUP FAILURE or an environment ABORT — 'zero findings' there is an absence of data,
not a pass), 1 when a human must look (findings present, OR the run did not finish), and 0 only
when the run COMPLETED with nothing to report. main()'s `--analyze` branch returns that code.
Actors: whoever wires `busybody.py --analyze` into CI (or a script) and trusts its exit status —
a run full of findings, a setup failure, or an environment abort that exits 0 is a false pass, the
exact false-clean this forbids.
Assets: the property that a post-hoc verdict cannot read cleaner than the run it describes; the
sweep's own exit-code contract (0/1/2/130) and this one agree on what a pass is.
Red-path: In main()'s `--analyze` branch replace `return analyze_exit_code(analysis)` with
`return 0`, and `test_analyze_exit_code_is_wired_into_the_cli` goes red (the gate is decorative);
`analyze_exit_code` on a findings/setup/abort journal then returns 0. Separately, make
`analyze_exit_code` return 0 unconditionally and `test_analyze_is_a_gate_not_just_a_reader` goes
red on every non-clean journal. Walked 2026-09-12 on this Linux host.
Source: adopted from lotek BusyBody #418/#682 (analyze doubles as a gate; refuse a false-clean).
docs/BUSYBODY.md. Found by auditing haru-pack's `--analyze` against lotek's false-clean hardening.
Territory: tools/busybody*.py, tools/busybody_analyze.py, tests/test_busybody_ledger.py

### INV-CHAOS-15
Status: active
Statement: The examiner sources each package's real test suite from its SDIST — reusing
`tools/exam_fetch` (`pypi_meta`/`fetch_sdist`/`locate_suite`/`test_deps`/`make_project`), never a
forked copy — so it covers ANY top-N package rather than a hardcoded pair, and records "no test
suite in sdist" rather than reporting a pass it did not run. A package whose sdist carries no test
tree yields NO-SUITE, and one whose suite errors is a real result, not a skip.
Actors: an operator (or a reviewer) who reads a green examiner run as "a thick payload carried a
WORKING library". A wheel-only examiner that silently covers 2 of N — or one that fakes a pass for
a package it never actually ran a suite for — is the false assurance this forbids.
Assets: the honesty of the examiner's coverage. The exam persona is the strongest statement the
harness makes about a packed library (it runs the library's OWN suite, offline); a claim that
tests a hardcoded pair while reading as "any package", or that reports a pass with no suite behind
it, makes every other exam result suspect.
Red-path: In `busybody_cases_exam.exam_project_from_root` replace the `if kind == "none": return
None, NO_SUITE` branch with `return proj, "faked"`, so a suiteless sdist yields a project instead
of the honest no-suite verdict; `test_a_sdist_with_no_test_tree_is_no_suite_not_a_pass` goes red
(a project was written for a package that ships no suite). Separately, re-freeze the pair with
`EXAM_PACKAGES = ("numpy", "certifi")` and `test_the_examiner_is_not_frozen_to_numpy_and_certifi`
goes red. Separately, paste `locate_suite`'s body in as a local def and
`test_the_examiner_reuses_exam_fetch_and_does_not_fork_it` goes red (identity broken, fork named).
Walked 2026-09-16 on this Linux host — all three observed green->red, then restored.
Source: 2026-09-16, issue #28. The examiner hardcoded numpy+certifi — the only two top-25 packages
whose suite ships in the WHEEL — so it covered 2 of N. The flex exam (PR #29) had already factored
the sdist->thick-project->offline-pytest machinery into `tools/exam_fetch`; the examiner just did
not use it.
Territory: tools/busybody.py, tools/busybody_cases_exam.py, tools/busybody_report.py,
tests/test_examiner_fixtures.py

### INV-FLEX-01
Status: active
Statement: `flex/packages.toml` is a pure function of two committed files —
`flex/sources.toml` and `flex/curation.toml` — regenerable offline and byte-identical every
time; the raw upstream snapshot it derives from is not required to reproduce it.
Actors: a maintainer six months from now asking "why is this package in the list"; anyone
auditing what the tool was actually tested against.
Assets: the meaning of a green flex run. A matrix nobody can reproduce is a matrix nobody
can reason about, and "we test the top 25" becomes a claim rather than a fact.
Red-path: Make `tools/gen-package-manifest.py` fetch the ranking itself instead of reading
the committed extract, or hand-edit `flex/packages.toml`. `--check` regenerates from the
inputs and compares; the claiming tests go red. An import-level AST check also fails if the
generator grows a dependency on the network or the clock.
Source: Added 2026-09-09 with the flex harness. The constraint came first: artifacts must
carry their provenance and regenerate deterministically, on the assumption that whoever
maintains this later has no AI and possibly no network.
Note: Fetching is deliberately a SEPARATE tool (`tools/fetch-top-pypi.py`). The ranking
changes monthly, so a generator that fetched would produce a different file from the same
command — reproducible-with-provenance, not deterministic-from-nothing. Refreshing produces
a reviewable diff instead of silent drift.
Note: The raw snapshot is gitignored; the committed extract is names in rank order, without
download counts, because counts change daily and would churn the file without changing which
packages are tested. The snapshot's sha256 is recorded so a refetch can be compared.
Territory: flex/, tools/fetch-top-pypi.py, tools/gen-package-manifest.py, tests/test_flex.py

### INV-FLEX-02
Status: active
Statement: Every package `scaffold.KNOWN` claims to handle specially appears as a flex hard
target, and every hard target names a real `KNOWN` entry; each states the packaging corner it
exercises.
Actors: a maintainer adding support for a package with an awkward install shape.
Assets: the honesty of haru-pack's "we handle this" list. `KNOWN` is what the tool advertises
it can special-case; the hard targets are what proves it. Two copies of the same knowledge
that drift apart is how a tool ends up claiming support it no longer has.
Red-path: Add an entry to `scaffold.KNOWN` without adding a matching hard target (or the
reverse). The set-comparison test names the offender in both directions.
Source: Added 2026-09-09. The top-25 list is a breadth check and mostly pure-Python wheels;
the hard targets — browser binaries, post-install downloads, giant native wheels, system
libraries — are where a packaging tool earns its keep.
Note: `weasyprint` is marked `expect_failure`: it needs pango and cairo, which pip cannot
bundle. Failing is the correct result and is recorded as such, so a known limitation does not
read as a regression — and so an unexpected PASS becomes visible, which is the interesting
direction.
Note: These tests do not build anything. `tools/flex-run.py` does that, and it needs a
toolchain and several minutes; the invariants here are about the LIST, not the builds.
Territory: flex/curation.toml, src/haru_pack/scaffold.py, tests/test_flex.py

### INV-FLEX-03
Status: active
Statement: The import name the flex harness exercises is one the INSTALLED distribution
actually provides, discovered from its metadata rather than derived from its name. A curated
`import_name` in `flex/curation.toml` is an assertion checked against that discovery, never an
input to it, and the probe reports which of its three resolution routes produced the answer so
a guess can never read as a fact.
Actors: whoever adds a package to the matrix and has to decide what it imports as; the
maintainer six months later reading a green run and concluding the package imports; any
distribution that renames, splits or merges its top-level modules between releases.
Assets: the meaning of a flex pass. "The payload carries an importable library" is the whole
claim of the `importable` style, and it is worth nothing if the harness imported a module name
it invented rather than the one the distribution ships.
Red-path: Three, each walked 2026-09-14. (1) Point a curated `import_name` at a module the
distribution does not provide — `test_a_stale_curated_import_name_is_a_failure_that_blames_the_manifest`
goes red, and the message must blame the MANIFEST rather than the package. (2) Generate the
probe body from `pkg["import_name"]` —
`test_the_probe_does_not_consult_the_curated_import_name` goes red, because a curated value
that can steer the probe makes checking the probe against it a tautology. (3) Return the
last-resort guess without labelling it —
`test_the_last_resort_guess_is_labelled_as_a_guess` goes red.
Source: 2026-09-14, issue #33. `flex/curation.toml` carried eight hand-written `import_name`
entries — `pyyaml` -> `yaml`, `python-dateutil` -> `dateutil`, and six more. Every one was a
human guess that could go stale silently, and `pillow` -> `PIL` is the shape that makes
guessing structurally wrong: nothing recovers `PIL` from `pillow`. The exact answer already
exists in the installed metadata, and the probe runs inside the binary where that metadata is.
Note: Normalisation is PEP 503 — `typing-extensions`, `typing_extensions` and
`Typing.Extensions` are one distribution. Comparing raw names silently resolves nothing for
every distribution whose name contains `-` or `.`, which is most of them, and the failure mode
is a silent fall-through to the guess rather than an error.
Note: Three routes, best first: `packages_distributions()` (exact, 3.10+), `top_level.txt`
(the wheel said so, works back to 3.8, absent from some wheels), then
`name.replace("-", "_")`. The route is RETURNED and recorded in `flex/out/results.json`. That
is the whole defence against this becoming curation again by another name.
Note: This governs the `importable` style only. The `smoke` style still honours
`import_name`, because a hand-written smoke body is hand-written throughout and the curated
name is part of it — conflating the two would either break the existing bodies or make this
check vacuous.
Territory: tools/flex_probes.py, tools/flex-run.py, flex/curation.toml,
tests/test_flex_probes.py

---

## BUILD — the build pipeline reports what it actually did

### INV-BUILD-01
Status: active
Statement: `build()` reports `encrypted=True` only if the bytes actually attached to the
launcher are an encrypted container; a build never claims a protection it did not apply.
Actors: the operator running the build; anyone downstream reading the build receipt.
Assets: the operator's belief about whether the shipped artifact is protected.
Red-path: Hardcode `encrypted=True` in the `info.update(...)` call in `build.build`, or
detach it from the branch that actually calls `crypto.encrypt`. The claiming test inspects
the produced payload for the container magic and goes red.
Source: CRIT C1 — `--encrypt` accepted a secret, printed success, and shipped plaintext.
Territory: src/haru_pack/build/, src/haru_pack/cli/

### INV-BUILD-02
Status: active
Statement: A build that requests encryption on the command line either produces an
encrypted payload or fails with a non-zero exit; there is no path that silently downgrades.
Actors: the operator; the licensee the encryption was meant to constrain.
Assets: the payload's confidentiality; the entire licensing story built on it.
Red-path: Remove `encrypt` from the parameters threaded into `build.build()` and restore
the `any([expires, geo, machine, user, embed_secret])` enablement rule. `--encrypt --secret X`
with no policy flag then exits 0 with a plaintext payload and the claiming test goes red.
Source: CRIT C1, adversarial review 2026-09-09. The bug shipped in a documented example.
Territory: src/haru_pack/cli/, src/haru_pack/build/

### INV-BUILD-03
Status: active
Statement: When more than one entrypoint is defensible, haru-pack refuses and names the
candidates; it never picks one silently.
Actors: an operator pointing haru-pack at a project they did not write, or one that grew a
second console script since the last build.
Assets: correctness of the shipped artifact. A wrong guess is the worst outcome available here
— it builds cleanly, exits 0, and runs the wrong program, so the failure surfaces at the
customer rather than at the build.
Red-path: Restore `entrypoint = [next(iter(scripts))] if scripts else [...]` in
`discovery.discover`. `test_multiple_console_scripts_refuse_and_list_candidates` goes red,
because that expression returns an arbitrary dict key instead of raising.
Source: Found 2026-09-09 while designing the "just point it at a script" UX. `discover` picked
the first key of `[project.scripts]`. lotek happens to declare exactly one, so it was right by
luck; a project with `serve` and `migrate` got a coin flip and no warning.
Note: Root-level `.py` files stop being candidates once `[project.scripts]` exists. In a real
tree they are helpers, plugins, and one-off utilities that the console script invokes or takes
as arguments — lotek's root has a dozen, and the only correct answer is the declared `lotek`.
Note: `python -m <package>` is only offered when that package is actually **executable** —
i.e. `<pkg>/__main__.py` exists. Otherwise it is a guess dressed as a default. This checked
only `__init__.py` until 2026-09-10, so a library-shaped package (importable, nothing to
execute) yielded the entrypoint `python -m <pkg>`, which builds cleanly and then fails on the
target with "'<pkg>' is a package and cannot be directly executed". Verified against a
synthetic package that day. Red-path for that half: change the `__main__.py` test in
`discovery.discover` back to `__init__.py` and
`test_an_importable_but_unexecutable_package_is_refused` goes red.
Territory: src/haru_pack/discovery.py, src/haru_pack/cli/, tests/test_entrypoints.py

### INV-BUILD-04
Status: active
Statement: An entrypoint may be given as a script filename, a console-script name, or a
`module:callable` object reference. A malformed one is rejected at build time — and so is a
well-formed one whose module is present in the project tree but does not define the named
attribute. Neither is ever deferred to a runtime "command not found" or `ImportError` on a
customer machine.
Actors: an operator typing `--entry-point`, or editing `entrypoint` in haru_pack.toml or
`[tool.haru-pack]`.
Assets: build-time feedback. Every spelling accepted here is resolved to plain argv before it
reaches the payload.
Red-path: Delete the `if ":" in spec: raise` branch in `entrypoints.resolve_entrypoint`. Four
parametrizations of `test_malformed_entry_points_are_rejected` go red — `mod:`, `:func`,
`mod::func` and `not a ref!` all fall through to being treated as console-script names.
Separately, delete the `verify_object_ref(...)` call from `build._resolve`:
`test_a_reference_to_a_missing_callable_is_refused` goes red, and `-e app:mian` builds
cleanly again and dies on the target.
Note: The reference check is STATIC — the module is parsed, never imported. Importing would
execute the project's code on the build host and could not work at all for a cross-compiled
target. The cost is that dynamically-created attributes are invisible, so the rule is to
refuse only when certain: module not found in the tree (it may come from a dependency),
unparseable, or providing the name via `import *` all pass silently. Added 2026-09-10 after
`app:main` was found to build cleanly against a module whose logic lived in an
`if __name__ == "__main__":` block — the guard is not importable, and the error message now
says so specifically, because that is the misconception that produces the mistake.
Source: Added 2026-09-09 with `--entry-point`. The first implementation had exactly that bug:
anything failing the object-reference pattern was silently treated as a command name, so a
typo'd `app.cli:` became a search for a console script of that literal name.
Note: Resolution happens at BUILD time, so the launcher never parses entry-point syntax. That
is one less place for the Python and Nim sides to disagree (compare INV-CRYPTO-02, where they
did). The generated argv sets `sys.argv[0]` and re-raises the callable's return value as
`SystemExit`, matching what an installed console script does — without which a non-zero exit
code would be reported as success.
Territory: src/haru_pack/entrypoints.py, src/haru_pack/build/, tests/test_entrypoints.py

### INV-BUILD-05
Status: active
Statement: Every artifact a build bundles — the `uv` binary, the standalone interpreter, and
the compiled launcher itself — is built for the target's architecture, and a target with no
pinned artifact for its architecture is refused rather than silently served an x86_64 one.
Actors: not an attacker — an operator building for a Raspberry Pi, and their customers.
Assets: whether the shipped binary runs at all. The **default** tier bundles a `uv`
executable, so an arch mismatch does not degrade gracefully: the target cannot execute it,
and the failure appears on the customer's machine as "cannot execute binary file".
Red-path: Hardcode a single asset name in `targets._UV_ASSETS` for two architectures, or drop
`--all-arches` from `bundle._find_python_url`, or hardcode x86_64 in `uvfetch.nim`'s
`uvAsset()`. Each has its own claiming test; the asset-uniqueness one goes red immediately.
Source: Added 2026-09-09. `--target` meant an OS and x86_64 was implied everywhere:
`_UV_ASSET` had one entry per OS, `_find_python_url` defaulted `arch="x86_64"`, and
`uvfetch.nim` hardcoded three x86_64 asset names. A Raspberry Pi is an ordinary target here.
Note: `--all-arches` is load-bearing and easy to lose. Without it `uv python list` returns
only x86_64 and armv7 — checked against uv 0.10.4 — so an aarch64 lookup finds nothing and
the target looks *unsupported* rather than *unpinned*, which sends you debugging the wrong
thing entirely.
Note: python-build-standalone ships gnu and musl builds for the same (os, arch) and they are
not interchangeable, so the resolver filters on libc.
Note: Verified end to end on 2026-09-09 — `bundle_uv` and `bundle_python` for
`linux-aarch64` both downloaded, verified against their pinned digests, and `file(1)`
reported "ELF 64-bit LSB, ARM aarch64" for each.
Territory: src/haru_pack/targets.py, src/haru_pack/bundle.py, src/haru_pack/bootstrap.py,
src/haru_pack/launcher/uvfetch.nim, tests/test_targets.py

### INV-BUILD-06
Status: active
Statement: `haru-pack <path>` is a shortcut for `haru-pack build <path>`, and it never
shadows a registered subcommand.
Actors: anyone typing the obvious thing.
Assets: the CLI's predictability. A shortcut that swallows `version` or `doctor` is worse
than no shortcut.
Red-path: Reimplement the shortcut as a `@app.callback(invoke_without_command=True)` with a
positional argument. Click then binds the first token to it and `haru-pack version` is parsed
as "build the project named 'version'"; the claiming test invokes `version` and goes red.
Source: Added 2026-09-09 for the "point it at a script and a binary appears" UX. The callback
approach was tried first and did exactly the above — it also left every unpassed option as a
Typer `OptionInfo` sentinel, so a plain `haru-pack hello.py` printed "🦣 chonky mode" and then
crashed on `OptionInfo.encode()`.
Note: Both entry points call one plain `_run_build()` with ordinary keyword defaults, rather
than `ctx.invoke`, which is what produced the sentinel bug. One implementation, two doors.
Territory: src/haru_pack/cli/, tests/test_targets.py

### INV-BUILD-07
Status: active
Statement: Build directives are read from `[tool.haru-pack]` in `pyproject.toml` as well as
from `haru_pack.toml`, in that order of increasing precedence; a table haru-pack does not
read is never silently ignored.
Actors: a developer who wants their project to declare how it is bundled, in the file that
already declares everything else about it; and the same developer three months later
wondering why a directive did nothing.
Assets: whether configuration means what it appears to mean. A config table read by nobody is
worse than a missing one, because the operator believes it took effect — the same failure
shape as the five documented-but-unimplemented security claims this file exists because of.
Red-path: Delete the `[tool.haru_pack]` (underscore) refusal in `build._declarations` and
`test_an_underscored_tool_table_is_refused_not_ignored` goes red. Delete the pyproject read
entirely and `test_directives_can_live_in_pyproject` goes red.
Source: Asked for 2026-09-10 — "the developer could choose how to bundle the tool and define
it inside of their own project". `haru_pack.toml` stays: it is the only option for a tree with
no pyproject.toml (a bare script, a folder of `.py` files) and the local override for one that
has it. The precedence ladder is the one `discovery`'s docstring already described, with the
new table slotted at the pyproject level.
Note: The merge is per top-level key, not deep. A `[[bundle]]` list in `haru_pack.toml`
replaces rather than extends the one in `pyproject.toml`; concatenating would let an operator
add steps but never remove an inherited one.
Note: PEP 723 permits `[tool]` tables inside a script's inline metadata block. That is NOT
read yet — a script's directives still go in `haru_pack.toml` beside it.
Territory: src/haru_pack/build/, tests/test_entrypoints.py

---

## CRYPTO — the container is what both implementations think it is

### INV-CRYPTO-01
Status: active
Statement: The license policy never appears in cleartext anywhere in a built artifact;
expiry, geo, machine and user are recoverable only after successful authenticated decryption.
Actors: a licensee reverse-engineering the binary they were shipped.
Assets: the policy itself (knowing the expiry date is the first step to editing it).
Red-path: Move the policy from inside the AES-GCM plaintext to the container header (which
is what `docs/ENCRYPTION_LICENSING.md` incorrectly described for months). The claiming test
scans the whole container for the policy's field values and goes red.
Source: Adversarial review 2026-09-09, finding N17 — three contradictory descriptions of
this container, two of them wrong about the mechanism that provides this property.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim

### INV-CRYPTO-02
Status: active
Statement: The container's byte layout is fixed and identical on the writer (Python) and
reader (Nim) sides; a change to one without the other is caught before release.
Actors: a maintainer editing either side; an AI agent editing one file in isolation.
Assets: every encrypted build ever shipped — a silent offset drift bricks them at runtime
with a message that reads as "wrong secret".
Red-path: Change any offset constant in `crypto.encrypt`'s header packing, or in
`cryptbox.parseBox`'s slice bounds, without changing the other. The claiming test asserts
the Python-produced offsets against the offsets parsed out of the Nim source and goes red.
Source: Adversarial review 2026-09-09. `docs/ENCRYPTION_LICENSING.md` asserted byte-for-byte
interop under a dated "Verified" heading with no test behind it.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim

### INV-CRYPTO-03
Status: active
Statement: Tampering with any byte of an encrypted container causes authenticated decryption
to fail; the container is never partially trusted.
Actors: a licensee editing the shipped binary to extend or remove their license.
Assets: the payload; the enforceability of every policy field.
Red-path: Pass `None` as the AAD in `AESGCM.encrypt`, or ignore the returned tag when
assembling the container. The claiming test flips a bit in each container region and asserts
authentication failure on every one; it goes red for the region that stopped being covered.
Source: Adversarial review 2026-09-09.
Territory: src/haru_pack/crypto.py

### INV-CRYPTO-04
Status: active
Statement: The container header — version, flags, KDF iteration count, salt, nonce and
embedded-secret length — is covered by the AEAD, so tampering with it is *detected* rather
than merely unproductive.
Actors: a licensee editing the header of a binary they were shipped.
Assets: the distinction between "cannot be changed" and "gains nothing by changing".
Red-path: In `crypto.encrypt`, replace `aad = container_aad(...)` with `aad = MAGIC` (the v1
form). Walked 2026-09-09: 5 red, including both tests that run the compiled Nim decryptor
against a Python-written container.
Source: Found by `test_header_is_unauthenticated_but_fail_closed` while writing the
INV-CRYPTO-03 suite on 2026-09-09. The AAD was the fixed magic `HPAKENC1`, leaving 62 bytes
of header outside it — fail-closed (a header edit changed key derivation) but not
tamper-evident. Container version bumped 1 -> 2; `cryptbox.nim` rejects v1 by version before
prompting for a secret.
Note: The writer MUST go through `crypto.container_aad()` rather than assembling the AAD
itself. When it did not, an adversarial verifier reverted the writer to the bare magic and
five of the six tests claiming this invariant stayed green — they exercised `container_aad()`
while the cipher saw something else. `test_every_header_field_is_inside_the_aad` constrains
the AAD *definition*; the Nim interop tests constrain that the writer *uses* it. Neither
alone is sufficient.
Note: A one-sided change to `crypto.py` or `cryptbox.nim` bricks every encrypted build with an
error that reads as "wrong secret". Do not touch either without compiling and running the Nim.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim

### INV-CRYPTO-05
Status: active
Statement: The GCM tag comparison in the launcher examines all 16 bytes with no early exit,
so the time it takes does not depend on how many leading tag bytes were correct.
Actors: a licensee who can run the shipped binary repeatedly against containers they mutate.
Assets: the tag, and with it the cost of forging a container — a byte-at-a-time timing oracle
turns a 2^128 problem into a 16 x 256 one.
Red-path: Restore the early-exit form in `openContainer`
(`for i in 0 ..< 16: if tag[i] != box.tag[i]: quit(...)`). The claiming test parses the
comparison loop out of cryptbox.nim and goes red on the `quit` inside it.
Source: Adversarial review 2026-09-09, finding W10.
Note: The first claiming test checks the SHAPE of the comparison in the source, not its
timing. That is deliberate and it is a real limitation: a timing measurement taken in a pytest
subprocess measures the scheduler, and a green noise-test is worse than an honest source check.
The second claimant runs the compiled decryptor and proves a corrupted tag is still rejected,
so "constant-time" cannot be satisfied by not comparing at all.
Territory: src/haru_pack/launcher/cryptbox.nim, tests/test_crypto_hardening.py

### INV-CRYPTO-06
Status: active
Statement: After authenticated decryption the launcher validates the policy length prefix
against the actual plaintext length before slicing it; an out-of-range length produces a
diagnostic exit rather than a crash or a negative-length allocation.
Actors: a secret-holder feeding the launcher a container they assembled themselves; a
corrupted or truncated download.
Assets: the launcher's ability to fail with an explanation. This is robustness, not a bypass —
the check sits behind the AEAD, so only a secret-holder can reach it.
Red-path: Delete the `pt.len < 4` and `plen > pt.len - 4` guards in `openContainer`. The
claiming test forges a correctly-authenticated container whose plaintext claims a policy length
of 0xFFFFFFFF and requires exit code 5 with a diagnostic; without the guards the process dies
with an unhandled Nim IndexDefect (`fatal.nim(53) sysFatal`, rc 1).
Source: Adversarial review 2026-09-09. `let plen = rdU32(pt, 0)` was followed directly by
`pt[4 ..< 4+plen]` and `newString(pt.len - 4 - plen)`.
Note: **Statement narrowed on promotion.** The original said "never a crash". An adversarial
verifier showed that is false: the guards only reject a `plen` OUTSIDE `[0, pt.len-4]`, and an
in-range `plen` whose bytes are not valid JSON still raises out of `parseJson` in `checkPolicy`.
That path is caught by INV-LAUNCH-06's top-level handler and exits cleanly, but this invariant
does not claim it.
Territory: src/haru_pack/launcher/cryptbox.nim, tests/test_crypto_hardening.py

---

## BIND — machine/user binding resolves the same value on both sides, or it bricks the right host

### INV-BIND-01
Status: active
Statement: The machine value bound by `--machine` is the OS **hostname** and the user value
bound by `--user` is the OS **login username** (NOT `$USER`/`$USERNAME`); the hostname is
canonicalized IDENTICALLY on the Python writer and the Nim reader — ASCII-lowercase, then a
single trailing dot stripped — before the `0x1f` KDF fold, so a binary bound to a host
decrypts on that host regardless of case/trailing-dot and fails closed on any other.
Actors: a packager binding a licence to a customer's machine; the customer running it; a
maintainer who edits the canonicalization on one side and not the other.
Assets: every machine/user-bound build. The KDF is EXACT-MATCH: one differing byte between
what the packager bound and what the launcher resolves derives a wrong key, and the payload
that was *meant* to decrypt on that host never does — a licence that bricks the right machine
is as bad as one that opens on the wrong one.
Red-path: (1) SOURCE — change `cryptbox.loginUser` back to `getEnv("USER")`, or
`cryptbox.hostnameCanon` back to reading `/etc/machine-id`; the source-assertion claimants in
`tests/test_binding.py` go red. (2) CANON DRIFT — remove the `toLowerAscii` (or the trailing-dot
strip) from `crypto.canon_hostname` OR from `cryptbox.canonHostname` but not both; the
cross-implementation vector test (`ws1.corp`, `WS1.CORP.`, `WS1.CORP` → `ws1.corp`) compiles the
Nim canonicalizer and compares it byte-for-byte to the Python one, and goes red. (3) EXECUTION —
the parity matrix builds workstation1.corp-bound and notforworkstation1.corp-bound containers,
runs the compiled Nim decryptor with the runtime hostname pinned to `workstation1.corp`, and
requires the matching binary to open (rc 0) and the mismatched one to fail closed (rc 5).
Walked 2026-09-22: on Linux (gethostname pinned via an `LD_PRELOAD` shim, because this host
forbids writing `uid_map` so a UTS namespace is unavailable) auth→rc0, deny→rc5, `WS1.CORP.`
runtime against a `ws1.corp` binding→rc0 (canon collapse through the real reader), and a
`ws1.corp` (FQDN) binding on a short `ws1` host→rc5 (the documented exact-match footgun); and
on the cross-compiled Windows `.exe` under WINE (computer name driven through the same
`gethostname` shim, one fresh `WINEPREFIX` per hostname because wineserver caches it) auth→rc0,
deny→rc5.
Source: Issue #59. Machine binding previously read `/etc/machine-id` (Linux) / `reg`+`ioreg`
(Win/mac) and user binding read `$USER`/`$USERNAME`; #59 made both cross-platform host values
(hostname + login username) folded into the same KDF, and the machine-binding row in
`docs/ENCRYPTION_LICENSING.md` had said it "names a test rather than an invariant id" — this is
that invariant.
Note: **HONEST LIMIT.** This is not an identity check. The hostname is a value the target
*reports* (a writable string on a machine the licensee controls), and the login username is a
login on that same machine — a second passphrase component, not proof of *who* is running it.
The KDF makes a wrong value a hard authentication failure rather than a skippable check, but
what it binds *to* is not a hardware root of trust. See THREAT_MODEL.md and
ENCRYPTION_LICENSING.md, which are kept deliberately un-upgraded on this point.
Note: **FQDN footgun, tested.** The reader prefers the FQDN (Windows
`GetComputerNameExW(DnsFullyQualified)`; POSIX `getHostname`) and falls back to the short name
where no DNS suffix exists. Because the match is exact after canon, a binary bound to the FQDN
fails closed on a host that reports only the short name. `test_binding.py` pins this as KNOWN
behaviour rather than leaving it a surprise.
Note: **NETWORK SERVICE.** On Windows, `GetUserNameW` under the NETWORK SERVICE account returns
`<HOSTNAME>$` rather than a human login. Desktop-irrelevant, noted so a service-account binding
is not a mystery.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim,
src/haru_pack/cli/inspectcmd.py, tests/test_binding.py

---

## PAYLOAD — only what the operator meant to ship gets shipped

### INV-PAYLOAD-01
Status: active
Statement: No file matching a credential-material pattern (`.env`, `*.pem`, `*.key`,
`id_rsa*`, `.ssh/`, `.aws/`, `credentials*`, `*.p12`, `*.pfx`) is copied into a payload,
regardless of where it sits in the source tree.
Actors: an operator who runs `haru-pack build .` in a project directory that also holds
their working `.env`; every recipient of the resulting binary.
Assets: the operator's API keys, signing keys, and cloud credentials — published inside a
binary that is, by design, distributed widely and often signed.
Red-path: Delete the credential patterns from `build._IGNORE`. The claiming test builds a
payload from a fixture tree containing `.env` and `id_rsa` and asserts they are absent from
the zip; it goes red immediately.
Source: CRIT C4, adversarial review 2026-09-09. `_IGNORE` excluded `.git` and `__pycache__`
but nothing secret-shaped.
Territory: src/haru_pack/build/

### INV-PAYLOAD-02
Status: active
Statement: `overlay.verify()` reports `sha_ok=False` for any modification to the attached
payload; the build-time integrity check is not decorative.
Actors: anyone tampering with a distributed binary; the operator running `haru-pack verify`.
Assets: the integrity signal haru-pack offers to someone holding an unsigned (ELF) binary
who wants to check it WITHOUT running it. (The launcher checks the same digest at startup
under `INV-LAUNCH-01`; that one only helps you if you already trust the binary enough to
execute it.)
Red-path: Make `verify()` return `sha_ok=True` unconditionally, or compare the digest against
itself. The claiming test mutates one payload byte and goes red.
Source: Adversarial review 2026-09-09, findings C2/C3.
Note: This invariant covers the **build-time** check only — `overlay.verify()`, which is what
`haru-pack verify` runs on a binary you already have. The runtime check is a separate promise
under `INV-LAUNCH-01`, which is now `active`: `main.launch` calls `verifyPayloadDigest` before
staging (main.nim:251). Neither one is tamper-evidence. Both compare the payload against a
digest that lives in the same attacker-writable footer, so whoever rewrites the payload can
recompute the digest beside it; read `INV-LAUNCH-01`'s Note before citing either as an
anti-tamper claim.
Territory: src/haru_pack/overlay.py

### INV-PAYLOAD-03
Status: active
Statement: A payload's bundled dependency cache contains only the project's **runtime**
resolution. The dev dependency group — its test runner, linters and build backend — is
never downloaded into the payload, on either the host or the cross path.
Actors: not an attacker; the operator, who pays for it in bytes, and the auditor of a
signed artifact, who has to explain why a customer-facing binary contains a test framework.
Assets: the size of every thick binary, and the accuracy of the claim that a payload
contains what the program needs. `uv sync` installs the *default* dependency groups and
`dev` is one of them, so `warm_cache_and_lock` warmed the bundled cache with the project's
own tooling and shipped it. Measured on `examples/shake-demo` (2026-09-10): 11 dists and
6.5 MB of unpacked wheel trees — pytest, pluggy, iniconfig, pygments, hatchling, editables,
pathspec, tomlkit, trove-classifiers, packaging — none of which a launcher can reach,
because it runs the project's entrypoint and never its suite.
Note: the tools themselves are still needed at *build* time — a `[[bundle]]` step or a
`--shake` observation run executes them — so `install_dev_tools` puts them in the throwaway
build env from the BUILD HOST's cache. The build environment is unchanged; only the payload
got smaller. That split is the invariant: `UV_CACHE_DIR` points into the payload for the
runtime sync and nowhere near it for the dev install.
Red-path: Drop `--no-dev` from the `uv sync` in `bundle.warm_cache_and_lock`, or let
`warm_cache_windows` call `_export_reqs(app_dir)` with the default `dev=True`. The claiming
test asserts on the argv of both and goes red.
Source: Found 2026-09-10 while building `--shake` — the tree-shaker's "dists outside the
`--no-dev` resolution" rule was dropping eleven trees that had no business being in the
payload in the first place. Fixed on its own rather than left as a `--shake` side effect,
since a plain `--thick` build should not ship a test framework either.
Territory: src/haru_pack/bundle.py, src/haru_pack/build/

---

## LAUNCH — what the shipped binary does on a machine you do not control

### INV-LAUNCH-01
Status: active
Statement: The launcher refuses to stage or execute a payload whose SHA-256 does not match
the digest recorded in its own footer.
Actors: anyone who can write to a distributed binary — a mirror, a shared fileserver, malware
already resident on the target.
Assets: code execution under the vendor's identity and (on Windows) their EV signature. The
payload contains `pre_install`/`post_install` argv that the launcher runs.
Red-path: Replace the `verifyPayloadDigest(...)` call in `main.launch` with `discard`,
rebuild, and run the fixture's tampered exe. Walked 2026-09-09: 5 red — without the guard the
modified binary ran to completion (rc 0) and printed its payload's marker.
Source: CRIT C2, adversarial review 2026-09-09. `main.nim` reads `ft.payloadSha`, hex-encodes
it, and uses the first 16 characters as a **cache directory name**. It never compares it to
anything. `docs/SIGNING.md` claimed under a dated "Validated (2026-09-09)" heading that this
check had been observed working.
Note: **This is not tamper-evidence and must not be described as such.** The digest is
self-referential — both the payload and the digest it is checked against come from the same
attacker-writable footer, so anyone who edits the payload can recompute the 32 footer bytes and
still execute. The verifier walked exactly that attack and confirmed it. What this invariant
buys is detection of corruption, truncation, and naive edits, plus a precondition for the real
fix. Real tamper-evidence on Windows comes from Authenticode over the overlay; Linux ELF output
has no equivalent. `INV-LAUNCH-03` is the real fix and stays `proposed`.
Note: The digest covers the **ciphertext container**, not the decrypted zip, so it is checked
before `openContainer`. Getting that order backwards makes every encrypted build fail to
launch. A tampered encrypted payload is caught here (rc 6), not by the AEAD (rc 5).
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/launcher/overlay.nim

### INV-LAUNCH-02
Status: active
Statement: The `HARUPACK_DEV_STAGE` staging bypass is absent from release builds; a
distributed launcher cannot be redirected to an arbitrary payload tree by an environment
variable.
Actors: anyone who can set an environment variable for the victim's process.
Assets: the vendor's code-signing identity. A signed launcher that runs attacker-chosen code
on demand is a signed proxy for arbitrary execution, and it skips decryption and every
license check on that path.
Red-path: Change the `when defined(haruDev)` guard around the `getEnv("HARUPACK_DEV_STAGE")`
read to `when true`, rebuild. Walked 2026-09-09: 2 red — the release binary staged from the
attacker-named directory and the string reappeared in the ELF.
Source: CRIT C5, adversarial review 2026-09-09.
Note: Verified by `strings` on a release build: zero occurrences of `HARUPACK_DEV_STAGE`. The
variable is still honoured under `-d:haruDev`, which is how the dev workflow keeps working.
Territory: src/haru_pack/launcher/main.nim

### INV-LAUNCH-03
Status: proposed
Statement: The launcher verifies a signature over the payload — not merely a digest — before
executing anything it contains, on every platform including ELF targets.
Actors: as INV-LAUNCH-01, plus an attacker who can rewrite the footer.
Assets: as INV-LAUNCH-01.
Red-path: Once implemented — sign a payload with the wrong key and observe refusal. Note
that `INV-LAUNCH-01` is its precondition, not a substitute: a digest the attacker can recompute
is not a signature.
Source: Adversarial review 2026-09-09, finding C3. Directly analogous to lotek's runner
self-upgrade gate, where a SHA-256 manifest match only *proposes* an upgrade and a valid
Ed25519 signature is required to act on it.
Note: **`--self-signed` (INV-SIGN-01, `active`) does NOT satisfy this and is not claimed to.**
It verifies an Ed25519 signature over the footer digests, but under a public key embedded in
the same file, so an editor who re-keys the binary re-signs it (walked, case iii). That is
edit-detection, not the out-of-band-anchored verification this invariant requires. The real
fix on Windows is Authenticode (`--cert-file`, deferred to docs/SIGNING.md's HSM/cloud flow);
on ELF/macOS it would need a key anchored outside the artifact (a pinned fingerprint, a
distribution-signature, or notarization) — none of which this entry yet claims, so it stays
`proposed`.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/overlay.py

### INV-LAUNCH-04
Status: active
Statement: A launcher built at the `thick` tier executes only binaries staged from its own
payload; it never resolves `uv` or an interpreter from `PATH` or the working directory.
Actors: anyone who can drop a file named `uv` into the target's PATH or cwd.
Assets: execution under the application's identity, defeating the tier's offline/hermetic claim.
Red-path: Disable the `if m.tier == "thick": die(...)` guard in `findUv` and the matching
interpreter guard, rebuild. Walked 2026-09-09: 2 red — a `uv` planted earlier in PATH ran, and
a thick build with no staged interpreter resolved python off the host.
Source: Adversarial review 2026-09-09, finding W14. `main.findUv` consulted `findExe("uv")`
before falling back to fetching.
Note: Scoped to the `thick` tier deliberately. `thin` and `default` may still resolve `uv` from
PATH, which is the documented behaviour of those tiers, not an oversight — but it does mean a
PATH-planted `uv` runs for them. Only `thick` claims to be hermetic.
Territory: src/haru_pack/launcher/main.nim

### INV-LAUNCH-05
Status: active
Statement: The launcher refuses a footer whose declared payload extent does not lie wholly
inside its own file and ahead of the footer; attacker-supplied offsets are validated by size,
never discovered by allocating.
Actors: anyone who can write to a distributed binary; a truncated or partially-copied download.
Assets: the end user's first impression of a shipped product, and the launcher's ability to
report a corrupt binary as corrupt. `payloadOff`/`payloadLen` are attacker-controlled u64s read
off disk.
Red-path: Replace the `footerFault(...)` call in `main.launch` AND the one inside
`overlay.readPayload` with `""`. Rewrite `payloadOff` in a built exe to 2**63 and run it:
observed `fatal.nim(53) sysFatal / Error: unhandled exception: value out of range [RangeDefect]`,
exit 1. Walked 2026-09-09: 6 red.
Source: Adversarial review 2026-09-09, finding W9. `overlay.nim` cast both fields straight to
`int` and fed them to `setPosition`/`readStr`. `-d:release` keeps Nim's bounds and range checks,
so the effect was a crash or an OOM rather than memory corruption.
Note: A `RangeDefect` is a Defect, not a `CatchableError`, so INV-LAUNCH-06's top-level handler
cannot clean it up. That is why this has to be validated up front rather than caught.
Territory: src/haru_pack/launcher/overlay.nim, src/haru_pack/launcher/main.nim

### INV-LAUNCH-06
Status: active
Statement: A shipped launcher never shows an end user a raw Nim traceback; every failure path
produces a one-line diagnostic and a documented exit code, and no manifest field is indexed
without a length check.
Actors: not an attacker — an end user with a corrupt download, and anyone reading the
build-machine paths a Nim traceback prints.
Assets: the product's credibility, and the build host's directory layout.
Red-path: Delete the `try/except CatchableError` around `quit(launch())` in `main.nim`. Ship a
payload whose `manifest.toml` is not valid TOML and run it: observed `parsetoml.nim(1066)
parseKeyValuePair / Error: unhandled exception: ... [TomlError]`, exit 1. Walked 2026-09-09:
2 red.
Source: Adversarial review 2026-09-09, finding W16. `parseManifest`, `parseJson` and the expiry
`parse` all raise, and `main.nim` did `m.entrypoint[0]` with no length check, so a manifest with
an empty entrypoint crashed.
Note: Narrowing the handler to `except ValueError` is NOT a valid neutralization — parsetoml's
`TomlError` derives from `ValueError`, so the test stays green. Use the deletion above.
Territory: src/haru_pack/launcher/main.nim

### INV-LAUNCH-07
Status: active
Statement: A packed binary never modifies the Python environment of the directory it is run
from; `uv` is prevented from discovering and adopting an enclosing project.
Actors: not an attacker — an ordinary user running a packed tool inside their own repository,
which is the normal way people use tools.
Assets: the user's project. Adopting their project means rebuilding their `.venv` against our
staged interpreter, leaving their environment broken in a way that has nothing to do with
what they ran.
Red-path: Delete `a.add "--no-project"` from the `akScript` branch of `main.nim`. Build any
script binary, run it from inside a directory containing a `pyproject.toml`, and watch that
project's `.venv/bin/python` get repointed at the staged interpreter. Walked both directions
by hand on 2026-09-09: broken without the flag, byte-identical with it.
Source: Found by busybody, destructively. A chaos case whose working directory happened to
sit inside this checkout left haru-pack's own `.venv/bin/python` a dangling symlink into a
staged tree that was then deleted. The harness broke the repository it was testing, which is
the only reason the launcher bug was noticed.
Note: This is a direct consequence of the run-in-place design. cwd is deliberately the user's
launch directory, and uv walks UP from cwd looking for a project — so the feature and the bug
come from the same decision. The project path was already safe because it passes `--project`
explicitly; only the script path was exposed.
Note: busybody's own work directories now live outside the repository for the same reason. A
chaos harness that can damage the tree it is testing is worse than no harness.
Territory: src/haru_pack/launcher/main.nim, tools/busybody*.py, tests/test_launcher_isolation.py

### INV-LAUNCH-08
Status: active
Statement: The launcher's footer reader loads both the v1 (68B, payload only) and the v2
(116B, payload + stub-config) footer format, dispatching on `format_ver`, and validates the
v2 stub-config extent by size exactly as it validates the payload extent.
Actors: anyone who can write to a distributed binary; a truncated or partially-copied
download. `stubOff`/`stubLen` are attacker-controlled u64s read off disk.
Assets: the launcher's ability to keep loading today's single-payload binaries AND to load a
new stub-carrying one, and to refuse a hostile stub locator by size rather than by crashing
inside `setPosition`/`readStr`.
Red-path: In `overlay.footerSizeFor` return `FooterV1Size` for version 2 (ignore the
version), rebuild — a v2 binary's TAIL check lands on the stub-offset field, the footer is
not found, and the exe reports "no payload appended" while a v1 binary still loads. Walked
2026-09-10: v1 green, v2 red. Separately, guard out the `if ft.hasStub:` extent block in
`footerFault` and set `stub_off` to 2**63 in a built v2 exe — observed `fatal.nim(53)
sysFatal` / RangeDefect, exit 1; the guard turns that into a clean `ExitBadFooter`. Walked
2026-09-10: 4 red.
Source: docs/adr/0003-stub-config-and-canary.md §1.5/§1.6. Extends INV-LAUNCH-05 territory to
the stub-config locator; the version dispatch is what keeps v1 binaries loading.
Territory: src/haru_pack/launcher/overlay.nim, src/haru_pack/launcher/main.nim, src/haru_pack/overlay.py

### INV-LAUNCH-09
Status: active
Statement: The launcher sets every manifest `inject` (env-append) KEY=VALUE pair in the child
environment before invoking uv or the app, so both inherit them; the launcher's own reserved
variables are set afterward and win on any collision.
Actors: not an attacker — the packager choosing licensing/API-key env for the app. The
security edge (an inject must not repoint a reserved var such as `UV_PYTHON` off the host,
INV-LAUNCH-04) is defence in depth alongside the build-time refusal of reserved keys.
Assets: the app's declared configuration actually reaching it, and the thick tier's
hermeticity.
Red-path: Delete the `for (k, v) in m.inject: putEnv(k, v)` loop in `main.launch`, rebuild —
a fake uv that echoes an injected var sees it empty. Walked 2026-09-10: 1 red. Separately,
move the loop AFTER the reserved `putEnv` block — an inject of `HARUPACK_STAGE` then wins and
the collision assertion goes red. Walked 2026-09-10: 1 red.
Source: docs/adr/0003-stub-config-and-canary.md §4.2. The pairs live in the PAYLOAD manifest
(post-decrypt), so an encrypted build hides them; the launcher splits each entry on the first
`=` only.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/launcher/manifest.nim

---

## SIGN — --self-signed detects a post-build edit (and says exactly what it does not)

### INV-SIGN-01
Status: active
Statement: On a `--self-signed` (v3-footer) binary the launcher verifies an Ed25519 signature
over the footer's structural + digest fields (formatVer, flags, payloadOff, payloadLen,
payloadSha, stubOff, stubLen, stubSha) under the public key embedded in the footer tail, AFTER
it has verified the payload and stub digests against the real bytes — so an edit that recomputes
the footer digest but does not re-sign is refused (exit 13), and an edit re-signed by a
different key without also swapping the embedded key is refused; an edit re-signed AND with the
embedded key swapped is accepted, which is the documented honest limit and is asserted so it
cannot be over-claimed.
Actors: anyone who can write to a distributed binary — a mirror, a shared fileserver, malware
resident on the target. NOT an attacker who is trusted to re-key the binary out of band; that is
the limit, not a defended case.
Assets: detection of a post-build payload/stub edit, and — crucially — an HONEST boundary on
what that detection is worth. Over-claiming here (calling it tamper-evidence) is the failure
this entry exists to prevent (INV-DOC-02).
Red-path: Neutralize `verifyPayloadSignature` in `main.launch` (replace its body with
`discard`, or make `ed25519.ed25519Verify` return `true`), rebuild, and run
`tests/test_self_signed.py`. Walked 2026-09-22: with the check neutralized, cases (i) and (ii)
(`test_case_i_...`, `test_case_ii_...`) go RED — the launcher ran to `PAYLOAD_UV_RAN` on a
digest-repacked and on an other-key-re-signed binary — while case (iii) and the v2-still-loads
regression stay green. Restored: 10 green. Separately, the vendored verifier itself is walked
against the RFC 8032 §7.1 vectors (`tests/launcher_ed25519_test.nim`, run by
`test_launcher_ed25519_matches_rfc8032`): flip one signature byte and the vector goes red.
Source: Issue #61. Builds on INV-LAUNCH-01 (payload digest) and INV-STUB-01 (stub digest): those
bind the digests to the bytes, and this binds a signature to the digests. The signing key lives
on the Python side (`cryptography`); the launcher only verifies, with a vendored Ed25519
(`launcher/ed25519.nim`) because nimcrypto ships no public-key primitive.
Note: **This is NOT tamper-evidence and must not be described as such.** The public key is
embedded in the same file, OUTSIDE the signed region (a signature cannot authenticate itself),
so anyone who edits the payload can re-sign with their own key and swap the embedded key — case
(iii), which PASSES on purpose. It becomes meaningful only when the key FINGERPRINT
(`pubkey_sha256`, emitted on the build receipt and by `build/signing.py`) is pinned OUT OF BAND
by the recipient. What it buys with no out-of-band pin is edit-detection: it turns a silent
digest-repack into a refusal. It deliberately does **not** claim INV-LAUNCH-03, which requires
out-of-band-anchored verification and stays `proposed`.
Note: Determinism. Ed25519 is deterministic (RFC 8032), so signing adds no per-build randomness
and a `--self-signed` build stays byte-identical on rebuild (the reproducible-build property
`tools/busybody_cases_repro.py` depends on). No salt was added.
Territory: src/haru_pack/overlay.py, src/haru_pack/launcher/main.nim,
src/haru_pack/launcher/overlay.nim, src/haru_pack/launcher/ed25519.nim,
src/haru_pack/build/signing.py, tests/test_self_signed.py

---

### INV-SIGN-02
Status: active
Statement: `haru-pack verify --pin <spec>` fetches a published set of Ed25519 public keys over
TLS — `github:<user>` from `https://github.com/<user>.keys`, or `keys-url:<https-url>` — and
succeeds (exit 0) ONLY if the build's EMBEDDED signing public key (`overlay.verify(exe)['pubkey']`,
the same key INV-SIGN-01 verifies the signature under) is byte-for-byte one of those keys, in
addition to the existing `sha_ok` gate. A match upgrades the build from edit-detection to
identity-anchored provenance: the embedded key is now tied to an out-of-band identity the editor
does not control. Every other outcome — a network error, an empty body, a body with no
ssh-ed25519 key, a malformed embedded key, or no match — fails closed (nonzero exit); a malformed
line in an otherwise-valid `.keys` is ignored rather than allowed to match. `--sign-key` accepting
an OpenSSH Ed25519 key is what makes the embedded key equal a dev's published GitHub SSH key, so
this anchor is reachable without a separate publish step.
Actors: a recipient who runs haru-pack and wants provenance, not just edit-detection; against a
mirror/fileserver/malware editor who re-signs and swaps the embedded key (the case INV-SIGN-01
PASSES on purpose). NOT defended: an attacker who takes over the pinned GitHub account or presents
a mis-issued TLS certificate for the anchor host — that forges the anchor and is the documented
limit, not a covered case.
Assets: identity-anchored provenance of a `--self-signed` binary, and an HONEST boundary on it —
the anchor's trust reduces exactly to GitHub-account + TLS trust (INV-DOC-02). This is a real
reduction of trust, not an elimination; over-claiming it as unforgeable is the failure this entry
guards against.
Red-path: Neutralize the anchor check in `src/haru_pack/anchor.py` — make `check_embedded_pubkey`
return `AnchorResult(matched=True, ...)` unconditionally, or make `parse_authorized_keys` return
the embedded key regardless of input — and run `tests/test_anchor.py`. The mandatory case
`test_rekeyed_binary_not_in_keys_is_refused` (a build signed by key A, then re-keyed to key B and
re-signed so INV-SIGN-01 accepts it, pinned to a `.keys` that lists A but not B) must go from
refused (nonzero exit) to accepted when the check is neutralized. Restore and it refuses again.
Source: Issue #71. Builds on INV-SIGN-01: that binds a signature to the embedded key inside the
file; this binds the embedded key to an identity OUTSIDE the file. INV-SIGN-01 is unchanged — the
launcher still pins nothing, so a bare exe on a recipient WITHOUT haru-pack auto-verifies nothing;
the new guarantee lives only in the `verify` tool.
Note: The published-key channel is trusted for account + TLS only. `github.com/<user>.keys` is
served over GitHub's TLS and tied to the account, so an editor who tampers a binary cannot also
change what that URL returns — but an account takeover or mis-issued cert can. `keys-url:` exists
for GitHub-less orgs and carries the same TLS-trust caveat. Deferred (not built): a vendor-published
signed-statement variant, and GPG/OpenPGP anchors.
Territory: src/haru_pack/anchor.py, src/haru_pack/cli/inspectcmd.py, src/haru_pack/build/signing.py,
tests/test_anchor.py

---

## SUPPLY — what we execute that we did not write

### INV-SUPPLY-01
Status: active
Statement: Every artifact haru-pack itself fetches over the network — the `choosenim`
installer, the `zig` toolchain archive, the `uv` release asset, and the python-build-standalone
interpreter — is verified against a digest pinned in this repository before it is extracted or
executed, and an artifact with no pin is refused rather than fetched. The Nim compiler is **not**
in that list. haru-pack pins the choosenim INSTALLER; the Nim toolchain choosenim then downloads
from nim-lang.org is verified by choosenim, not by this repository. See the gap Note below.
Actors: anyone who can serve or tamper with a release asset; a compromised upstream account.
Assets: the build host's toolchain, and every binary it subsequently produces. The staged
interpreter ends up inside a signed customer deliverable.
Red-path: Point `fetch_verified` at a fixture archive whose bytes do not match its registered
digest and require `DigestMismatch`; then remove the pin entirely and require `UnpinnedArtifact`
*before* any network call. Walked 2026-09-09.
Source: Adversarial review 2026-09-09, finding W6. Four download sites, zero checks:
`bootstrap.install_nim`, `bundle.bundle_uv`, `bundle.bundle_python`, `uvfetch.ensureUv`.
**Correction:** an earlier revision of this entry said `uv python list --output-format json`
returns a `sha256` per entry that `_find_python_url` "read past and discarded". That is false —
checked against uv 0.10.4, the entry keys are exactly {arch, implementation, key, libc, os, path,
symlink, url, variant, version, version_parts} and there is no digest field. The pins come from
the release instead: the `<asset>.sha256` sidecar where one is published, and the release API's
per-asset digest where it is not. One pin was spot-checked against the live artifact on
2026-09-09 and matched.
Note: **Statement narrowed on promotion, from "every artifact haru-pack downloads and then
executes" to "downloads directly".** The original wording was false and an adversarial verifier
proved it. The two gaps it found — `bundle_python(target="host")` shelling out to
`uv python install`, and `warm_cache_windows` discarding the lockfile's hashes — have since been
closed by `INV-SUPPLY-07` and `INV-SUPPLY-08`, and `bundle_uv`'s PATH shortcut by
`INV-SUPPLY-06`. The narrow scope is kept anyway: it says what THIS entry proves, and the
distinction between a direct download and a delegated one is exactly what went unnoticed the
first time. **Reworded again 2026-09-15**, because "directly" had become a word doing hidden
work: it excluded the Nim toolchain while the same sentence listed the Nim toolchain as its
first example, so the Statement contradicted itself and read as a stronger promise than the code
makes. The list is now literal and the delegated fetch is named below instead of implied by an
adverb.
Note: **Residual gap, named rather than covered: the Nim compiler on a host build.**
`install_nim` verifies the choosenim installer against `pins.toml`
(`src/haru_pack/toolchain.py:433`) and then executes it (`:440`); choosenim downloads the whole
Nim toolchain from nim-lang.org over its own TLS, and nothing in this repository hashes what it
wrote. The pin chain stops at the installer. This is the widest blast radius of any unpinned
input in the project, because that compiler builds the launcher embedded in every binary
haru-pack ships to a customer — a substituted Nim is a substituted launcher in every artifact
built afterwards. `toolchain.py`'s module docstring says the same thing at the code. Closing it
means installing pinned Nim releases ourselves rather than delegating to choosenim; that is not
done, and no test claims it is.
Note: The aarch64 docker image is the one Nim acquisition path WITHOUT that gap:
`docker/install-nim-source.py` and `docker/install-nim-binary.py` fetch a Nim pinned in
`pins.toml` (`kind = "nim"`, digest from the publisher's own `.sha256` file) and refuse an
unpinned one. It exists because choosenim publishes no `linux_arm64` binary at all, so
`install_nim` refuses on that platform rather than inventing a fallback: `choosenim_asset`
returns None and the error names the supported hosts. No digest was invented to make a check
pass.
Territory: src/haru_pack/archives.py, src/haru_pack/bootstrap.py, src/haru_pack/bundle.py,
src/haru_pack/toolchain.py, src/haru_pack/pins.toml

### INV-SUPPLY-02
Status: proposed
Statement: The Nim libraries linked into a shipped launcher are version-pinned, so the same
commit produces the same cryptographic implementation.
Actors: not an attacker — entropy. Also anyone who compromises a nimble package.
Assets: reproducibility, and the meaning of any statement about the launcher's crypto.
Red-path: Once genuinely pinned — install two versions of a dependency side by side, compile
twice, and observe the same version linked both times.
Source: Adversarial review 2026-09-09, finding W7. `nimble install -y zippy puppy parsetoml
nimcrypto` was unpinned, eleven lines below `NIM_VERSION = "2.2.6"  # pinned; bump deliberately`.
Note: **Deliberately still `proposed` even though the `nimble install` argv is now pinned.**
An adversarial verifier showed the pin does not achieve the Statement: `build.compile_launcher`
runs a bare `nim c` with no `--nimblePath`, no lockfile and no project `.nimble`, so Nim resolves
each import to the HIGHEST version present in the multi-version package directory regardless of
what was installed. Pinning the installer only controls which versions arrive, not which one the
compiler picks. Marking this active would be exactly the over-claim this file exists to prevent.
The fix is a project `.nimble` or an explicit `--nimblePath` at compile time.
Note: **The launcher's Ed25519 verifier is the one crypto primitive NOT exposed to this gap,
because it is not a nimble dependency at all.** `nimcrypto` (the launcher's crypto library)
ships no public-key primitive — SHA-2, HMAC, PBKDF2 and AES only — so `--self-signed`'s
verification (INV-SIGN-01) is VENDORED in-repo as `src/haru_pack/launcher/ed25519.nim` (a
TweetNaCl port, public domain). Being in-tree, its exact bytes are fixed by the commit rather
than resolved by `nim c` from the multi-version package dir, so it does not inherit the
highest-version-wins ambiguity this entry describes. SHA-512 for it still comes from nimcrypto
and is subject to the gap. This narrows the surface but does not close the entry.
Territory: src/haru_pack/bootstrap.py, src/haru_pack/build/, src/haru_pack/launcher/ed25519.nim

### INV-SUPPLY-04
Status: active
Statement: The `uv_version` string from the payload manifest is interpolated into the runtime
download URL only if it is a bare version number (optional `v`, one to four dot-separated
numeric components); anything else aborts the fetch.
Actors: anyone who can edit the manifest inside a payload; an operator socially engineered into
a hostile `uv_version`.
Assets: the URL from which the thin tier downloads and then executes a binary on the customer's
machine.
Red-path: Make `uvfetch.isValidUvVersion` return true — 12 red (hostile strings including
`../../../../evil/releases/download/1.0`, `@evil.example`, a CRLF header injection, `latest`).
Separately, delete the guard's CALL from `ensureUv` — `tests/test_stage_callsites.py` goes red.
Source: Adversarial review 2026-09-09, boundary B6. `ensureUv` built its URL as
`base & uvVersion & "/" & asset` with no validation whatsoever.
Territory: src/haru_pack/launcher/uvfetch.nim

### INV-SUPPLY-05
Status: active
Statement: The runtime uv download is refused before it is written to disk or extracted if it is
empty, exceeds the hard size cap, or fails to match the `uv_sha256` digest recorded in the
payload manifest — and a malformed pin is a refusal, never a skipped check.
Actors: anyone who can serve or tamper with the release asset on the customer's network; a
compromised upstream account.
Assets: arbitrary code execution on the customer's machine — the downloaded uv is executed
immediately, with the application's identity.
Red-path: Make `uvfetch.checkUvArchive` return "" — 6 red (digest mismatch, three malformed
pins, empty download, over-cap archive). Separately, delete its CALL from `ensureUv` —
`tests/test_stage_callsites.py` goes red.
Source: Adversarial review 2026-09-09, boundary B6 / finding W6. `writeFile(arc, fetch(url))`
had no digest, no cap and no timeout.
Note: **`uv_sha256` IS populated, as of 2026-09-11.** `_stage_uv` writes the pinned digest of
the target's uv release asset into the payload manifest for the `thin` tier — the only tier that
fetches uv on the customer's machine — and refuses the build outright when no pin exists
(`src/haru_pack/build/assemble.py:108`, INV-SUPPLY-01). Until 2026-09-15 this Note said the
opposite in bold: that nothing populated the field and the pin check was "vacuous in
production". That was written when the mechanism landed in the launcher ahead of the build side,
and it was never updated when the build side landed a day later — a stale Note claiming a
weakness the code no longer has, which is the same class of drift INV-DOC-02 exists for, pointed
the other way.
Note: The unverified path is still REACHABLE, for one case only: a payload built by an older
haru-pack carries no `uv_sha256`, and for those `ensureUv` warns on stderr that the uv it is
about to download and execute is unverified and then proceeds. It does not refuse. A binary
built by this version of haru-pack cannot reach that branch, because the build fails before
producing one.
Note: Further limits — puppy exposes no streaming API, so the cap is enforced from a HEAD
content-length pre-flight and then on the body once it is already in memory; the cap is on the
compressed archive, so a zip bomb under it is not caught; TLS is the OS's, unpinned.
Territory: src/haru_pack/launcher/uvfetch.nim

### INV-SUPPLY-06
Status: active
Statement: The `uv` binary placed into a payload is always the pinned, digest-verified release
asset; no build ships whatever `uv` happened to be first on the build host's PATH.
Actors: anyone who can write a file named `uv` earlier in the build operator's PATH; a
compromised developer workstation.
Assets: the customer deliverable. The copied binary is zipped into the payload and signed, and
it is the first thing the launcher executes.
Red-path: Restore the `local = shutil.which("uv")` copy shortcut at the top of `bundle_uv`.
`tests/test_sources.py::test_bundle_uv_never_ships_a_binary_off_the_build_hosts_path` goes red.
Source: Noticed 2026-09-09 while implementing INV-SUPPLY-01. `bundle_uv` returned the copied
local binary before any digest logic was reached, so INV-SUPPLY-01 did not cover it — nothing
was downloaded.
Note: The earlier plan was to keep the PATH copy "for local iteration only". That was dropped:
a second code path is a second thing to get wrong, and it was the unverified one that ran by
default. Host and cross now share one path. The cost is a download on a host build that
previously reused a local binary; the artifact cache makes that a one-off per version.
Note: This also makes host builds reproducible. Two machines with different local uv versions
used to produce different payloads from the same commit.
Territory: src/haru_pack/bundle.py, tests/test_sources.py

### INV-SUPPLY-07
Status: active
Statement: The standalone interpreter staged into a payload is downloaded and digest-verified by
haru-pack itself on every target, host included; no interpreter reaches a payload via a
subprocess whose bytes haru-pack never inspected.
Actors: anyone who can serve or tamper with an upstream artifact; a compromised upstream account.
Assets: the customer deliverable. The staged interpreter is signed with the vendor's certificate
and executed on every customer machine.
Red-path: Restore the `if target == "host": subprocess.run(["uv", "python", "install", ...])`
branch in `bundle_python`. Two tests go red: the shape test that forbids a host-specific branch,
and `test_bundle_python_verifies_on_the_host_target`, which requires a `DigestMismatch` when the
fetched interpreter is not the pinned one.
Source: Found by the adversarial verifier for INV-SUPPLY-01 on 2026-09-09, which is why that
invariant's Statement had to be narrowed to *direct* downloads. `bundle_python(target="host")`
was the DEFAULT path and it forwarded the operator's whole environment to `uv python install`.
Note: Host and cross now share one code path, differing only in the `(os, arch)` they resolve.
That is the point: the old fork meant one of the two was unverified, and it was the one almost
everybody used. `_host_arch()` maps the machine so a host build is no longer x86_64-only.
Territory: src/haru_pack/bundle.py, tests/test_sources.py

### INV-SUPPLY-08
Status: active
Statement: The application's own dependency wheels are installed into a bundled payload with
hash verification, so a compromised index cannot substitute a wheel.
Actors: a compromised or hostile package index; an attacker with a network position during a
cross-build.
Assets: the customer deliverable — these wheels ARE the application.
Red-path: Put `--no-hashes` back into `_export_reqs`, or drop `--require-hashes` from
`warm_cache_windows`. One test goes red for each.
Source: Found by the adversarial verifier for INV-SUPPLY-01 on 2026-09-09. `warm_cache_windows`
ran `uv export --no-hashes` and fed the hashless requirements file to
`uv pip install --only-binary :all:` with no `--require-hashes`. The lockfile had the hashes;
they were explicitly discarded.
Note: uv emits hashes by DEFAULT — `--no-hashes` was an opt-out. Because a hashed requirement
spans multiple lines (`    --hash=sha256:...` continuations), `_export_reqs` must not strip
indentation; a third test covers that, since silently dropping continuations would produce a
hashless file and `--require-hashes` would then reject everything.
Note: The `warm_cache_and_lock` path (host thick builds) resolves from `uv.lock`, whose per-wheel
hashes uv verifies itself. That is delegated verification, not our check.
Territory: src/haru_pack/bundle.py, tests/test_sources.py

### INV-SUPPLY-09
Status: active
Statement: `bootstrap.ensure_nim_deps` invokes nimble with an exact version for every package it
installs; no dependency is requested as a bare name.
Actors: entropy, mostly. Also anyone who publishes a malicious new release of a package we
install unpinned.
Assets: which versions of the launcher's libraries — including its AES-GCM implementation —
arrive on a build host.
Red-path: Replace the pinned specs in `NIM_DEPS` with bare package names. The claiming tests
assert every spec carries an exact version and that the argv nimble actually receives is the
pinned one; they go red.
Source: Adversarial review 2026-09-09, finding W7.
Note: **This is deliberately narrower than `INV-SUPPLY-02`, which stays `proposed`.** Pinning
the installer controls which versions *arrive*; it does not control which one the *compiler
links*. `build.compile_launcher` runs a bare `nim c` with no `--nimblePath` and no project
`.nimble`, so Nim resolves each import to the highest version present in a multi-version package
directory. Do not read a green suite here as reproducibility.
Note: `test_every_third_party_nim_import_is_pinned` scans only direct `import` lines in
`launcher/*.nim`. Transitive dependencies — `webby` and `libcurl`, pulled in by puppy — are not
covered and are not claimed.
Territory: src/haru_pack/bootstrap.py

### INV-SUPPLY-10
Status: active
Statement: A configured mirror changes only *where* an artifact is fetched from, never *whether*
it is verified: the pinned digest is selected by the artifact's upstream identity, so a hostile
mirror produces a `DigestMismatch` rather than a compromised build.
Actors: whoever operates the mirror; anyone who can point a build at one (an env var is enough).
Assets: everything INV-SUPPLY-01/06/07 protect. A mirror that could choose its own pin would
silently undo all of them.
Red-path: In `bundle_python`, move the `PBS_SHA256.get(...)` lookup below the
`sources.python_url(...)` rewrite so the pin is keyed by the mirrored URL. The source-order test
goes red; so does `test_a_hostile_mirror_cannot_substitute_an_artifact`, which serves different
bytes from a mirror and requires the build to fail.
Source: Added 2026-09-09 alongside mirror support. Environments that cannot reach github.com need
an alternate origin; the risk is that "configurable origin" quietly becomes "configurable trust".
Note: The refusal in `Sources.python_url` to rewrite a URL that does not start with the known
upstream base is part of this. Guessing a mirror path for an unrecognised host would fetch an
unrelated file, and the digest check would then be the only thing standing between that and the
payload — a check should not be the last line of defence when refusing is available.
Note: Mirrors are for availability and policy. If a mismatch appears after pointing at a mirror,
the mirror is wrong or stale. Do not edit the pin to make it pass.
Territory: src/haru_pack/sources.py, src/haru_pack/bundle.py, tests/test_sources.py

### INV-SUPPLY-11
Status: active
Statement: A python-build-standalone pin is keyed by the artifact's canonical GitHub release
URL, not by whatever mirror uv currently reports. A uv upgrade that changes its download host
never invalidates a pin, and haru-pack prefers a version that is already pinned over whatever
patch uv's catalog has advanced to.
Actors: whoever upgrades uv (the user did, mid-session); whoever later runs a thick build and
expects the pins to still mean something.
Assets: the stability of the pin set. haru-pack resolves python URLs live from uv's catalog, so
if the pin key tracked uv's mirror, every uv release would silently invalidate every python pin
and turn thick builds into a re-pinning treadmill.
Red-path: Remove `_canonical_pbs_url` from `_find_python_url` so the pin is keyed by uv's raw
URL. After a uv upgrade that moved the host (0.10 github.com → 0.12 releases.astral.sh), every
python pin misses and thick builds fail with `UnpinnedArtifact`. Or delete the prefer-pinned
branch so `_find_python_url` returns uv's newest patch even when an older pinned build is still
in the catalog; a thick build then chases an unpinned version it did not need to. Both have
claiming tests.
Source: 2026-09-10. `uv self update` 0.10.4 → 0.12.12 moved the catalog host to
releases.astral.sh and advanced the newest builds, which broke every thick python pin at once.
The canonical-URL keying plus prefer-pinned restored 3 of 5 targets with no re-pinning; the two
x86_64 targets were re-pinned to the 3.13.9 build the others already used, so all five now stage
one uniform, verified interpreter.
Note: This composes with INV-SUPPLY-10. Canonicalisation decides the pin KEY (publisher
identity); `Sources.python_url` decides the download POINT (mirror). A mirror still cannot dodge
the pin, because the key is the publisher URL regardless of where the bytes come from.
Note: Prefer-pinned falls back to uv's newest only when NO pinned build for the minor is in the
catalog — and then the pin check refuses it, loudly, which is the signal to run add-pin. It
never silently stages an unverified interpreter.
Territory: src/haru_pack/bundle.py, tests/test_supply_chain.py

### INV-SUPPLY-12
Status: proposed
Statement: A free-threaded interpreter is staged through the same pinned, digest-verified,
member-sanitized path as a GIL one; the zstd archive does not get a second extraction route.
Actors: anyone who can influence what the build host downloads.
Assets: INV-SUPPLY-01 and INV-SUPPLY-03, which a parallel `.tar.zst` path would quietly exempt
half the interpreters from.
Red-path: Point the free-threaded extraction at an archive containing `../` and a member outside
the destination; `_reject_unsafe_members` must refuse it, exactly as for `.tar.gz`. Then drop the
pin for a free-threaded URL and confirm the build refuses rather than downloading.
Source: docs/FREE_THREADED.md, 2026-09-10. Free-threaded builds publish no `install_only`
archive (0 of 141 assets in python-build-standalone release 20260211), only `-full.tar.zst`, so
a second extraction path is the obvious implementation — and INV-SUPPLY-07 was mined from
exactly that shape: two staging paths where only one was verified, and the unverified one was
the default.
Territory: not yet — nothing is implemented. Planned:
src/haru_pack/archives.py, src/haru_pack/bundle.py

### INV-SUPPLY-13
Status: active
Statement: The launcher's HTTP(S) (thin-tier uv fetch, remote payload fetch, and the online geo/ip
gate) uses puppy's DEFAULT OS-native TLS backend on every target — WinHTTP on Windows, AppKit/
NSURLSession on macOS, libcurl on Linux. haru-pack NEVER compiles the launcher with
`-d:puppyLibcurl`, so a Windows/macOS binary needs no bundled `cacert.pem` and no OpenSSL: TLS
trust is the system store (WinHTTP ROOT / Keychain / `/etc/ssl`), and only the Linux/libcurl path
honors `SSL_CERT_FILE` / `SSL_CERT_DIR` / `http(s)_proxy`.
Actors: a future implementer who "adds a cert bundle" or flips puppy to libcurl for uniformity, and
in doing so reintroduces a real cacert dependency the packed binary does not ship — turning every
Windows launch into a fail-closed TLS error, or (worse) prompting a shipped cert that breaks the
no-OpenSSL contract (docs/TIERS.md, docs/adr/0005-remote-fetch.md).
Assets: the "no curl/wget/OpenSSL on the target, no cert file beside the binary" contract the thin
tier and the geo gate both rest on. If puppy silently switched to libcurl on Windows, HTTPS would
need a cacert.pem that nothing produces.
Red-path: Add `"-d:puppyLibcurl"` to the args list in `emit/nimflags.nim_target_flags` (the single
source of truth used by both the real build and the emitted kit). `test_launcher_never_uses_puppy_libcurl`
in tests/test_packaging.py goes red: the flag set for a Windows/macOS target now carries a define
that forces libcurl, which on Windows needs the cacert this build never ships. Walked 2026-09-23 on
this Linux host (the guard flags the injected define across all KNOWN_TARGETS and both cc providers).
Source: Issue #67. The issue was filed on the FALSE premise that Windows puppy needs a bundled
cacert.pem; the grill established puppy's defaults (WinHTTP/AppKit/libcurl) and that cacert only
matters under `-d:puppyLibcurl`, which haru-pack never sets. This guard freezes that fact so the
assumption cannot silently flip. Sources: treeform/puppy README/source, forum.nim-lang.org/t/7581.
Note: This is a flag-set guard, not a live-TLS test. It asserts the launcher is built for the
OS-native backend; it does not prove a live public-CA HTTPS handshake succeeds on real Windows/macOS
(that needs those OSes — the geo parity leg exercises WinHTTP transport under wine against a LOCAL
plain-HTTP resolver, see tests/test_geo_gate_wine.py).
Territory: src/haru_pack/emit/nimflags.py, src/haru_pack/build/compiler.py, tests/test_packaging.py

---

## STAGE — the tree on the target that we actually execute
### INV-SUPPLY-03
Status: active
Statement: No archive is extracted with a call that permits writes outside the destination
directory. Every `tarfile` extraction in the source goes through `archives.safe_extract_tar`,
which uses `filter="data"` on interpreters that have it and otherwise screens every member
itself before extracting.
Actors: whoever controls an archive we fetched over unverified TLS (see INV-SUPPLY-01).
Assets: the build host's filesystem.
Red-path: Delete the `_reject_unsafe_members(tf, dest)` call from `safe_extract_tar`'s fallback
branch (archives.py:128) — `test_traversing_member_is_rejected` builds a tar whose member is
`../victim.txt` and goes red on any interpreter without `data_filter` — see the Note for which
ones those are, and for why CI is not currently one of them. Or call
`tarfile.open(...).extractall(dest)` directly from any module under `src/` other than
`archives.py`: `test_no_unfiltered_tar_extraction_in_the_source` scans for that call shape and
goes red on every interpreter.
Source: Adversarial review 2026-09-09, finding W8. `requires-python = ">=3.9"`, where the
tarfile default is the pre-CVE-2007-4559 behavior.
Note — the two paths, because the statement used to say `filter="data"` full stop and that was
not true of every supported interpreter. `safe_extract_tar` takes the `filter="data"` branch
only when `hasattr(tarfile, "data_filter")`: 3.12+, plus the backports in 3.9.17, 3.10.12 and
3.11.4. On 3.9.0-3.9.16, 3.10.0-3.10.11 and 3.11.0-3.11.3 — all inside `requires-python =
">=3.9"` — it falls back to `_reject_unsafe_members` (archives.py:108) and then a bare
`extractall`. That fallback rejects members whose path escapes the destination, symlinks and
hardlinks whose target escapes it, and device nodes. It is deliberately narrower than
`data_filter`: it does not clear setuid/setgid or other high mode bits, and does not normalize
permissions. The escape property the statement claims holds on both paths; the mode-sanitizing
extras of `data_filter` do not.
Note — the fallback is not covered by CI today. The matrix pins `3.9` and `uv python install
3.9` resolves to the newest 3.9 patch, which is past the 3.9.17 backport, so both CI jobs take
the `filter="data"` branch. Walking the fallback red-path means asking for a pre-backport patch
release by hand — `uv venv --python 3.9.16` (also 3.10.11, 3.11.3; all three are downloadable
python-build-standalone builds). Closing this properly is a ci.yml change, not an INVARIANTS.md
one.
Territory: src/haru_pack/bootstrap.py, src/haru_pack/bundle.py

---

## STAGE — the tree on the target that we actually execute

### INV-STAGE-01
Status: active
Statement: The launcher never executes a staged tree it cannot account for: a stage directory
is reused only if it is a real directory owned by the calling user, not group- or
world-writable, carrying a `.ready` token that names this exact payload digest, and every file
recorded in `.stage-files` still hashes to its recorded sha256. The ONE relaxation (#4): a member
the build DECLARED writable (`--writable <glob>`, resolved to exact stage-relative paths and
carried in the signature-covered stub-config) is recorded as a `mutable:` line instead of a
sha256; on reuse it is checked for presence, regular-file kind, and non-symlink-ness — its BYTES
are deliberately not pinned, so a bundled data file the app rewrites in place no longer fails
verification — while it STILL counts in the file count and the `.stage-files` digest the `.ready`
token binds, so the tree stays fully accounted for. The BUILD refuses to declare writable any
importable/executable file (`.py`/`.pyc`/`.so`/`.pth`/…, `sitecustomize`/`usercustomize`, the
interpreter tree, `uv`, the entrypoint, pre/post-install targets, or ANY `+x` file) — a writable
code path would be a same-uid RCE primitive — and a `mutable:` member may never be a symlink or a
`.haru-links` alias target. A verify mismatch stays FATAL and is never auto-healed; the deliberate
recovery is the operator-only `--<canary>-reinstall` arg (#3), which WIPES the launcher's own
computed subtree — through the same shredGuard the reaper uses, never a path from arg/env — and
re-extracts.
Actors: any process on the target that can write into the user's cache directory before the
launcher does — a same-user attacker, a shared or misconfigured cache, resident malware.
Assets: code execution under the vendor's identity and (on Windows) behind their signature. The
launcher runs `pre_install`/`post_install` argv and the entrypoint straight out of this tree.
Red-path: Restore the trust-on-first-use short circuit — `if dirExists(final): return final` in
`stage.stageZip`. The claiming tests pre-create a hostile stage directory (with and without the
old one-byte `.ready`), modify and delete a staged file, chmod the tree 0777, and replace it
with a symlink. Walked 2026-09-09: 6 red, 49 passed. The #4/#3 additions to the walked set
(tests/test_writable_reinstall.py, nim host): (a) declare `data/app.db` writable, stage, rewrite
it between runs -> 2nd run rc 0 — neutralised by dropping the `mutable:` branch in
recordTree/verifyTree, which turns the app's own write into a fatal tamper; (b) rewrite a
NON-declared bundled file (`bin/python`) -> still rc != 0 (verifyTree "modified"); (c) try to
declare `plugins/hook.pth`, a `+x` file, a `.py`/`.so`, a shell/Windows executable
(`.sh`/`.bat`/`.ps1`/`.exe`), a NON-`.py` pre/post-install `run` target of ANY extension
(including extensionless), or a file whose CONTENT is executable magic (shebang/ELF/PE/Mach-O) even
with no exec bit or code suffix, plus the interpreter tree or `uv` -> the BUILD refuses
(build.resolve_writable backstop, pure-Python, runs on any host); (d) replace
the declared `data/app.db` with a symlink -> verifyTree refuses ("now a symlink"). Also walked:
the error-message fix names the changed file + `--<canary>-reinstall`, and reinstall wipes only
its own subtree (a sentinel beside it survives, INV-REAP-01).
Source: THREAT_MODEL.md boundary B10, adversarial review 2026-09-09. The old code
short-circuited on a bare `.ready` existence check under a directory named after 64 bits of the
footer digest, and its `if not dirExists(final): moveDir` also handed back a pre-existing
directory with no `.ready` at all.
Note: The exemption list is load-bearing and was wrong twice. An adversarial verifier found that
`vendor/uv` was exempt from `.stage-files` while `main.findUv` executes exactly that path first —
handing a same-uid attacker the one file guaranteed to run — and that `*.pyc`/`__pycache__` were
exempt, which is executable code outside the manifest because CPython validates timestamp-mode
bytecode only against the source's mtime and size, both forgeable. Both exemptions are gone;
`main.nim` sets `PYTHONPYCACHEPREFIX` outside the stage so nothing writes bytecode into it.
`tests/test_stage_callsites.py` fails if either exemption returns.
Note: This does NOT exclude an attacker already running as the same user. Every input to the
`.ready` token is readable from the binary being attacked, so they can rewrite the tree and
regenerate the token together; closing that needs an OS boundary (a separate service account or
a root-owned read-only stage), not a checksum. Ownership and mode are checked on POSIX only —
there is no Windows ACL equivalent here. Verification re-hashes recorded files on every launch,
so startup cost scales with payload size.
Note (#4 relaxation / #3 reinstall, 2026-09-23): the `--writable` relaxation deliberately widens
what a same-uid attacker can change — a declared data file's BYTES are no longer pinned. That is
acceptable ONLY because the build's backstop makes the declared set incapable of holding code
(no importable/executable file, no `+x` file, never an alias target), so the relaxation can turn a
data file mutable but can never turn a code path mutable. The declared set rides the
signature-covered stub-config (INV-STUB-01 / INV-SIGN-01), so it is integrity-anchored, not a side
channel. `#3` and `#4` CONFLICT on data loss: `--<canary>-reinstall` re-extracts from the payload
and so discards ALL stage state, declared-writable files included — writable app state should live
OUTSIDE the stage (a data dir; docs/SHARP_CORNERS.md section E), with the bundle carrying only a
seed copied out on first run.
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim,
src/haru_pack/launcher/stubconfig.nim, src/haru_pack/build/writable.py

### INV-STAGE-02
Status: active
Statement: No payload archive entry can write outside the stage directory; an entry path that is
absolute, drive-relative, contains a `..` component, or contains a NUL is refused before
anything is extracted.
Actors: whoever can supply or edit the payload zip — a tampered distributed binary, or a
build-side compromise.
Assets: every file the launching user can write, including their shell startup files and
anything on their PATH.
Red-path: Make `stage.unsafeEntryPath` return false — 8 red. Separately, delete the
`assertArchiveEntriesSafe(zipPath)` CALL from `stageZip` — `tests/test_stage_callsites.py`
goes red. Both are required: the first proves the predicate works, the second proves it runs.
Source: Adversarial review 2026-09-09, boundary B7 — "target relies on zippy, unverified here".
Note: The reliance was measured, not assumed: zippy 0.10.12's `verifyPathIsSafeToExtract` does
reject `../escape.txt`, so the end-to-end staging test stays green even with `unsafeEntryPath`
neutralized. Our check is defence in depth for shapes zippy's substring tests miss (a bare `..`,
`C:evil`, NUL) and so the defence is ours to keep across a dependency bump.
Note: An adversarial verifier proved the original suite vacuous at the call site — deleting the
`assertArchiveEntriesSafe` line left 55/55 green, because every test called the predicate
directly. `tests/test_stage_callsites.py` exists for that reason and is honest about being a
source-shape check rather than an end-to-end one.
Territory: src/haru_pack/launcher/stage.nim

---

## SECRET — key material does not leak sideways

### INV-STAGE-03
Status: proposed
Statement: N first runs of one binary that race to stage the same payload into one cache key
all end up executing a complete, verified stage, and a process that loses the race never
observes a partial tree.
Actors: not an attacker — a CI job that starts one binary per worker, a login script on a
shared box, a fleet rollout. Anything that fans out a first run, which is the only moment this
is contended.
Assets: the first-run promise under contention. Every other STAGE claim is about one process
meeting a tree; this is about N of them building the same tree at once, and the failure modes
are the ones a single process cannot produce — a half-extracted tree becoming reachable, or a
process waiting forever on a claim whose owner is dead.
Red-path: Neutralise the atomicity in `stage.nim` — extract in place under `final` instead of
building `<key>.tmp-<pid>` and moving it in one `moveDir` — rebuild the launcher, and run
`tools/busybody.py --persona herd --herd-n 16` against a thick fixture. **Deliberately not
walked in this change**: it needs a launcher rebuild, and an invariant promoted without walking
its red path is the exact defect this file exists because of.
Source: The claim already existed as prose — it lives today only in the `twin` case's remedy
("every process builds in its own `.tmp-<pid>` and races an atomic move") and in the three
`herd` cases added on 2026-09-11. Neither INV-STAGE-01's nor INV-STAGE-02's Statement mentions
atomicity or concurrency: INV-STAGE-01 governs what a stage must satisfy BEFORE it is executed
and INV-STAGE-02 governs archive entry paths, so the herd cases cite INV-STAGE-01 for the half
it legitimately covers (a tree with no `.ready` is refused, not run) and say in their remedy
that the atomicity half is unwritten. This entry is that gap, labelled.
Note: `proposed` here means the CLAIM is unclaimed, not that the code is absent — the atomic
move is in `stageZip` today. What is missing is a test that goes red when it is removed, and
the only honest one costs a Nim rebuild plus a sixteen-way herd run against a thick fixture.
Promoting it on the strength of the herd cases passing would be linkage without efficacy:
`--persona herd` is green on a launcher that never had the move, right up until the race lands.
Note: The no-waiting half is a separate promise from the atomicity half, and worth writing
separately when this is promoted. Today's staging takes no lock, so a dead owner's
`<key>.tmp-<pid>` is ignored by construction; the moment a lock or a wait-for-the-winner
appears, waiting forever on a dead claim arrives with it, and that is what
`sixteen_starts_against_an_orphaned_stage` is standing guard over.
Territory: not yet claimed. The behaviour lives in src/haru_pack/launcher/stage.nim
(`stageZip`'s `<key>.tmp-<pid>` plus the atomic `moveDir`); the harness that probes it is the
`herd` persona in tools/busybody*.py.

### INV-STAGE-04
Status: active
Statement: On POSIX the launcher stages a `.haru-links` alias as a relative **symlink** to its
in-stage target, not a copy — so a staged thick tree stops carrying its duplicate interpreter
bytes (~90 MB). That stays inside INV-STAGE-01 because `recordTree` now yields `pcLinkToFile`
and records each alias as a `symlink:<target> <rel>` line, and `verifyTree`, on every reuse,
checks that the path is **still a symlink** **still resolving to that same in-stage target** —
whose own bytes are hash-verified by its regular-file line — rather than following the link and
hashing whatever it reaches. A recorded regular file that is later a symlink, an alias replaced
by a regular file, and an alias repointed (inside the stage or out) are all refused. On Windows,
where creating a symlink is privileged, the alias stays a copy and is recorded as an ordinary
file; the two platforms' staged trees differ in size, not in what each is verified against.
Actors: for the saving, not an attacker — an operator staging thick payloads on a small disk,
each staged tree ~90 MB lighter. For the checks, anyone who can write into a staged tree between
runs, to whom a symlink is a redirect primitive: repoint `bin/python` at `/etc` or a file whose
bytes they can swap after verification (a TOCTOU the copy never exposed), or swap a verified
regular file for a link to matching content.
Assets: ~90 MB of duplicate on-disk bytes per staged thick payload, and INV-STAGE-01's integrity
chain extended over the alias — the launcher must never execute a `bin/python` that now points
somewhere it did not record. The target is required to be a present, non-symlink regular file that
is **not `isRuntimeMutable`** — recordTree records exactly those, so the alias can only resolve to a
member the manifest itself hash-verifies. Both recordTree and verifyTree enforce it, so neither a
crafted payload nor a hand-edited `.stage-files` can name a runtime-mutable (unrecorded) target.
Red-path: three, all walked 2026-09-16 on this linux host:
(0) drop the `got != tgtRel` target-equality check in `verifyTree`'s symlink branch — rebuild,
stage, then repoint `vendor/alias.bin` at `/etc/hostname` and at another in-stage member. Both
`test_an_alias_repointed_outside_the_stage_is_refused` and
`test_an_alias_repointed_at_a_different_member_is_refused` went green-to-red: the launcher reused
the tampered stage (exit 0 instead of 3);
(1) force `materialiseLinks` back to `copyFileWithPermissions` on POSIX (`when false and ...`) —
`test_a_deduped_alias_is_staged_as_a_symlink_and_reused` went red (`is_symlink()` false) and the
on-disk saving disappeared;
(2) neuter both `isRuntimeMutable(tgtRel)` guards (recordTree + verifyTree) — a payload aliasing
`bin/python` at `uv.lock` then staged clean (exit 0) and
`test_an_alias_to_a_runtime_mutable_target_is_refused` went green-to-red, i.e. an interpreter whose
bytes no `.stage-files` line hashes was accepted. All three reverted before commit. Finding from
Acid_Burn's adversarial review of this change.
Source: INV-PAYLOAD-06 took the *shipped-binary* saving 2026-09-15 and left the ~186 MB *staged*
footprint as "a separate question [that] would have to solve the recording problem first" — a
symlink was absent from `.stage-files` and so unverified. Issue #42 is that follow-up: recordTree
records symlinks and verifyTree gained the kind + target rules that let the staged tree hold them
without a hole. Deliberately not casual, per the issue: it touches the one file whose whole job is
making the staged tree accountable.
Territory: src/haru_pack/launcher/stage.nim, tests/test_stage_hardening.py

---

## SECRET — key material does not leak sideways
### INV-SECRET-01
Status: active
Statement: A license secret typed at the runtime prompt is never echoed to the terminal.
Actors: shoulder-surfers; anyone reading a recorded terminal session or CI log.
Assets: the license secret, which is the entire trust anchor — there is no PKI behind it.
Red-path: Change `readPasswordFromStdin("")` back to `stdin.readLine()` in
`cryptbox.resolveSecret` (cryptbox.nim:103). Two tests go red.
`test_typed_secret_is_not_echoed_to_the_terminal` drives the real decryptor over a kernel pty
with ECHO left ON, types the secret, and fails when those bytes come back down the master; it
also asserts the container actually opens, so a no-echo read that mangled the secret would not
pass for the wrong reason. `test_the_secret_prompt_uses_a_no_echo_read` pins the mechanism by
grepping the proc body, so the refactor is caught even on a box with no pty. The pty test has
its own guard-of-guards, `test_the_echo_check_can_see_an_echo`: it types a WRONG secret at the
same prompt and requires both that the open fails (rc 5) and that the wrong secret was not
echoed either — proof the bytes really reach the child, so a misconfigured pty cannot make the
first test pass vacuously.
Source: Adversarial review 2026-09-09, finding W11, and fixed since: `resolveSecret` read the
secret with `stdin.readLine()` while `std/terminal` was already imported and
`readPasswordFromStdin` went unused. It now writes the prompt to stderr — so it never pollutes
the app's stdout — and reads with no echo.
Territory: src/haru_pack/launcher/cryptbox.nim


### INV-SECRET-02
Status: active
Statement: A secret embedded in an encrypted build is not present in plaintext in the
distributed binary at rest. But the launcher stages the payload to disk in plaintext to run
it, so any user who can EXECUTE the binary can recover the staged source from their own
cache. haru-pack never claims otherwise, and obfuscation raises the cost of reading that
staged source without making it a confidentiality boundary.
Actors: the developer who has to embed an API key and ship it, and the reverse engineer who
receives the binary and rummages.
Assets: the developer's correct understanding of what they are protecting. The dangerous
failure is not a weak cipher; it is a developer who believes "encrypted binary" means the
embedded key is safe from someone running it, ships a key that must never leak, and is wrong.
Red-path: busybody's `reverse_engineer` persona plants a known secret and proves each edge:
  * ENCRYPTED build, no embed — the secret literal is ABSENT from the binary's payload
    (decompressed), because the payload is ciphertext. This is what encryption buys.
  * PLAIN build — the secret is PRESENT in the staged tree under the run's cache after the
    binary runs. This is the soft spot, and it is inherent: a plaintext interpreter must be
    handed plaintext to run.
  * OBFUSCATED build — the plaintext literal is GONE from the staged source, replaced by a
    pyarmor bootstrap. Measurable, and the whole value of `--obfuscate`; not a guarantee.
  * `--embed-secret` — the decryption key is in the binary, so the payload is recoverable
    from the binary ALONE. This is the documented weakest mode: encryption reduced to
    obfuscation.
Each is a claiming case, and the persona reports what it actually recovered rather than
asserting a boundary.
Source: 2026-09-10, from the reverse_engineer/obfuscation work. The staging path
(`stage.nim`) writes the decrypted payload to `XDG_CACHE_HOME/haru-pack/<key>-<digest>/root/`
in plaintext and leaves it there — it is the regenerable cache, not a temp dir — so the
window is not "while running" but "until the cache is cleared".
Note: The staged tree is hardened to owner-only, and the protection is REACHABILITY, not
per-file bits. `hardenDir` sets the cache base (`<cache>/haru-pack`) and the staged root to
0700; the inner files stay 0644, but the 0700 gate means another user cannot traverse in to
reach them. Measured 2026-09-10. The persona's first version checked raw inner bits and
reported a FALSE LEAKED on every 0644 file — corrected to walk the ancestor chain and flag a
file only if it is other-readable AND every directory up to the cache base is
other-traversable. A finding that cannot survive that check is not a finding; verifying it
before believing it is the discipline, and it applied to the harness's own output here.
That protection does nothing against the user who RUNS the binary, because that user is the
owner — which is INV-SECRET-02's whole point.
Note: A secret that must never be recovered must never be shipped to the client. The correct
architecture for a must-not-leak key is a server the client authenticates to, not a key in an
artifact the client holds. haru-pack's job is to be honest that packing is not that.
Note: `--emit-nim` widens what sits on the packager's OWN disk, not what the customer gets: the
kit's `payload.bin` is the exact bytes the binary already carries (ciphertext under `--encrypt`,
plaintext otherwise), so it exposes nothing new. The build SECRET/key is derived-from, not
stored, and is never written to any kit file — that half is INV-SECRET-03's claim, proved by
`test_emit_kit_never_contains_the_build_secret` grepping every emitted file. It is named here
because the kit is what widens the packager-side exposure, not because this entry proves it.
Note: This entry and INV-SECRET-03 carried the SAME id until 2026-09-15, and only the other one
was loaded (see its first Note). They are neighbours because they are easy to conflate and must
not be: this one is about what a customer who RUNS the binary can recover from their own cache,
INV-SECRET-03 is about what the build writes to disk on the packager's machine. Neither implies
the other — a build that leaks nothing still ships a payload the runner can stage and read.
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/crypto.py, src/haru_pack/emit/,
tools/busybody*.py, tests/test_reverse_engineer.py, tests/test_emit_nim.py

### INV-SECRET-03
Status: active
Statement: A build secret is never written into a manifest, a build receipt, an `--emit-nim`
kit, or any other artifact the build produces, and it is not present in the value `build.build`
returns to its caller.
Actors: anyone who reads the project repo or the shipped binary.
Assets: the license secret.
Red-path: Add the secret to the `info` dict returned by `build.build`, or to the manifest
written by `assemble_payload`. `test_secret_never_lands_in_a_produced_artifact` builds with a
known secret and asserts it appears in no produced file or return value, and
`test_emit_kit_never_contains_the_build_secret` greps every file of an emitted kit; both go red.
Source: Adversarial review 2026-09-09. `docs/CONFIG.md` states the secret is never stored in
config — asserted in prose only.
Note: **This entry was a second `### INV-SECRET-02` until 2026-09-15**, declared under the OBF
section with a Statement unrelated to the INV-SECRET-02 above. `load_invariants` keys entries by
id and keeps the last one it parses, so while both existed this Statement was the only one the
machinery loaded, the one above was unvalidated prose, and all ten markers naming
`INV-SECRET-02` were credited here — including the seven in `tests/test_reverse_engineer.py`,
which prove the other claim. Renumbered rather than merged, because the two say different
things: this one is about what the BUILD emits, INV-SECRET-02 is about what a shipped binary
yields to someone who runs it. A commit, report or marker dated before 2026-09-15 that cites
`INV-SECRET-02` and talks about manifests, receipts or kits means this entry.
Note: This does **not** cover `--secret <literal>`, which puts key material in shell history
and `ps` output. That is a documented sharp edge, not a defended one.
Territory: src/haru_pack/build/, src/haru_pack/cli/, src/haru_pack/emit/,
tests/test_build_encryption.py, tests/test_emit_nim.py

---

## OBF — source obfuscation, and the honesty around it

### INV-OBF-01
Status: active
Statement: `--obfuscate` either applies the requested engine or fails the build. It never
silently ships unobfuscated source when obfuscation was asked for. The result is recorded in
the manifest, so the artifact states truthfully what was done to it.
Actors: the developer who runs `--obfuscate pyarmor` in CI and does not watch the log, and
the person who later has to trust that a shipped binary is what its build command claimed.
Assets: the truthfulness of the build. "I asked for obfuscation and got a plain binary and
was not told" is the worst outcome, because it produces false confidence in a shipped
artifact — the exact class INV-DOC-02 exists to prevent, here at build time.
Red-path: request `--obfuscate pyarmor` with uv absent, or with a pyarmor that errors, and
the build must exit non-zero rather than produce an unobfuscated binary. A claiming test
drives `get_engine` with an unavailable engine and asserts the build refuses. The `none`
engine is the explicit default and the honest name for "not obfuscated" — never implied by
omission.
Source: 2026-09-10. pyarmor is run as `uv run --python <ver> --with pyarmor -- pyarmor gen`,
so haru-pack needs no pyarmor dependency and — crucially — obfuscates under the SAME
interpreter version the binary will stage.
Note: Obfuscation binds the payload to an EXACT Python minor version. Measured 2026-09-10: a
payload obfuscated for 3.12 imports only under 3.12 — 3.11 fails on `_PyThreadState_GetCurrent`,
3.13/3.14 on `_PyErr_GetTopmostException`, because pyarmor's runtime .so references
version-private symbols. This is not a lock TO 3.12: pyarmor obfuscates for standard CPython
3.7 through 3.14 (verified 3.11/3.12/3.13/3.14 each build and run when targeted), and
haru-pack obfuscates under whatever `--python` selects. 3.12 is only the default. Only
`--thick` bundles the exact interpreter and guarantees the run-time match; thin/default
resolve a Python on the target and may not land on the same minor, so a non-thick obfuscated
build warns loudly that the binary will fail to start unless the target has exactly that
version.
Note: pyarmor does NOT support free-threaded (GIL-less) CPython — the `+freethreaded` /
`python3.14t` builds. A bare "3.14" can resolve to a free-threaded interpreter via uv, so the
engine catches pyarmor's free-threading error and re-raises it naming the real constraint and
the fix (pin a standard interpreter, or drop --obfuscate for a free-threaded target). This is
the single hard ceiling; standard 3.14 obfuscates fine.
Note: The engine is modular (an `ObfuscationEngine` interface with a registry) because
pyarmor is commercial, versioned, and may be unavailable — offline, a lapsed licence, or a
future where it is abandoned. This project exists to outlive its tools, so pyarmor is one
implementation, not a hard dependency.
Note: pyarmor's unlicensed/trial runtime is size-limited and not for redistribution. haru-pack
detects the trial banner and says so in the build log; it does not decide licensing for the
user, but it will not let them ship a trial artifact believing it is licensed.
Note: Obfuscation and encryption are INDEPENDENT axes. Neither implies the other: you can
obfuscate a plaintext-payload binary, encrypt an unobfuscated one, do both, or neither. They
protect different things (INV-SECRET-02), and the code wires them separately so a change to
one cannot silently alter the other.
Territory: src/haru_pack/obfuscate.py, src/haru_pack/build/, src/haru_pack/cli/,
tests/test_obfuscate.py

---

## DOC — claims are traceable to evidence

### INV-DOC-01
Status: active
Statement: Every `INV-` identifier cited anywhere in `src/`, `docs/`, `tests/`, `tools/` or a
root markdown file resolves to a real entry in this file. In addition, every `inv=` value on a
registered busybody case or trait either names declared invariants or is empty — a non-empty
value that cites no id at all is a case that reads as governed and is not.
Actors: a future maintainer or AI agent citing an invariant that was never declared.
Assets: the credibility of the whole scheme. lotek added this scanner after discovering
`INV-MODULARITY-01` cited across seven source files and five plans docs without ever
being declared. The `inv=` half protects the same credibility one layer down: that field is
printed under INVARIANT in every busybody report and rolled up into the findings ledger, so an
unresolvable value sends whoever is triaging a finding to an entry that does not exist.
Red-path: Write `INV-NONSENSE-99` in any tracked file. The claiming test goes red. For the
second half, set `inv="INV-NONSENSE-99"` on any case in `tools/busybody_cases_*.py`, or set it
to a string with no id in it at all; `test_every_case_inv_citation_resolves` goes red naming
the case and the value. Walked 2026-09-13 — the check found `inv="see THREAT_MODEL.md"` on
`geo_spoofed`, which had shipped, and which is what the second clause was written for.
Source: Adopted from lotek `tests/test_invariants_enforced.py`. The `tools/` root and the
`inv=` resolution check were added 2026-09-13: the 2026-09-13 modularity split moved busybody's
cases out of one file into twelve, and `tools/` was scanned by nothing, so the `inv=` strings
on 80 cases were validated by nothing either.
Territory: INVARIANTS.md, tests/_invariants.py, tests/test_invariants_enforced.py, tools/

### INV-DOC-02
Status: active
Statement: A dated "Verified" or "Validated" claim in the docs names the invariant or test
that backs it; verification is never asserted in prose alone.
Actors: an AI agent writing a plausible-sounding validation record for work it did not do.
Assets: the reader's ability to tell a checked claim from an imagined one. Both existing
"Verified (2026-09-09)" footers in this repo predated any test; the one in `docs/SIGNING.md`
described a runtime SHA-256 check that has never existed in the code.
Red-path: Add a `## Verified (2026-01-01)` heading to any doc with no `INV-` reference in
its body. The claiming test goes red.
Source: CRIT C2, adversarial review 2026-09-09. This is the control aimed squarely at the
hallucinated-security-feature failure mode.
Territory: docs/, tests/test_invariants_enforced.py

---

## SHAKE — a file is only deleted from a payload on evidence, and only shipped on proof

`--shake` prunes a `--thick` payload down to the files the project's own test suite was
observed to touch. It is the one feature in haru-pack that makes a signed artifact *smaller
by deleting things*, which means its failure mode is unique: an `ImportError` on a customer
machine, on first run, for a file nobody remembers removing. Everything below exists to
keep that from being possible to reach by accident.

The honest limit, stated once so no entry below has to over-claim: **a passing test suite is
evidence about the suite, not about the program.** A code path the suite never exercises is
invisible to observation. `--shake` is therefore opt-in, refuses to run without a declared
test command, keeps the static closure of every lazy import inside a kept module, and writes
down every file it removed. It does not claim that a shaken payload is safe; it claims that
a shaken payload was *observed running and re-proven afterwards*, and that the operator can
see exactly what changed.

### INV-SHAKE-01
Status: active
Statement: A shaken payload is never emitted unless, after pruning, the project's declared
test command passes against a fresh environment installed offline from the pruned payload;
if it does not, the build fails rather than falling back to an unshaken binary.
Actors: not an attacker — the operator who asked for a small binary, and their customer, who
runs it first on a machine with no network and no Python.
Assets: the meaning of a build that exits 0. haru-pack's stated design rule is that a wrong
guess "compiles cleanly, exits 0, and fails on the customer's machine — which is the worst
place to find out". Pruning on an unverified trace is that failure with the file already
deleted, and the *other* tempting fallback — warn and ship the unshaken payload — hands back
a binary many times the requested size, which the operator learns from `ls -l` or not at all.
Red-path: Wrap the `_verify(...)` call in `shake.shake()` in `try/except ShakeError: pass`,
or change `build()`'s `except ShakeError` to log a warning and continue. Either makes
`test_a_failed_verification_raises_instead_of_returning_a_report` or
`test_a_shake_error_fails_the_build_rather_than_shipping_unshaken` go red.
Source: Written with the feature, 2026-09-10, from the tier's own precedent: INV-TIER-01
exists because `--thick` once quietly needed the network. `--shake` can quietly need a file.
Territory: src/haru_pack/shake/, src/haru_pack/build/, tests/test_shake.py

### INV-SHAKE-02
Status: active
Statement: The verification runs against a tree that is genuinely missing the pruned files;
if any pruned path reappears in the verification environment, the build fails instead of
reporting a pass.
Actors: a dev-group dependency that pins a different version of a runtime dist, so `uv`
reinstalls that dist whole — un-pruned — into the environment the suite is about to run in.
Assets: the difference between "we checked and it was fine" and "we did not check". A false
green here is worse than no verification at all, because it is the thing an operator would
point to when the field failure arrives.
Red-path: Delete the `_resurrected(...)` check from `shake._verify`, or move it after the
suite loop. `test_verification_checks_the_pruned_files_are_still_absent` goes red. To watch
it fail for real: add a dev dependency pinning an older version of a runtime dist, shake, and
observe the suite pass against files the payload no longer contains.
Source: Found while designing the verification step, 2026-09-10 — the first draft installed
the dev group into the verification env and would have verified the wrong tree.
Territory: src/haru_pack/shake/, tests/test_shake.py

### INV-SHAKE-03
Status: active
Statement: `--shake` deletes nothing without an observation to justify it: no declared or
discoverable test command is a hard refusal, and an observation run that exits non-zero
prunes nothing.
Actors: an operator reaching for `--shake` because the binary is too big, on a project with
no suite; and an AI agent "fixing" the refusal by adding a default rulepack.
Assets: the evidence requirement itself. A red suite is the worst possible input — every
test after the first failure went unexecuted, so the files it would have exercised look
prunable — and it is exactly the state in which a build would appear to save the most.
Red-path: Give `shake.resolve_config` a fallback (`test = test or ["pytest"]`), or drop the
non-zero-exit check in `shake._observe`. `test_shake_refuses_a_project_with_no_test_command`
or `test_a_failing_observation_run_prunes_nothing` goes red.
Source: Written with the feature, 2026-09-10. The repo's standing rule — "it refuses instead
of guessing" — applied to deletion, where guessing is least recoverable.
Territory: src/haru_pack/shake/, tests/test_shake.py

### INV-SHAKE-04
Status: proposed
Statement: A binary built with `--shake` fails at *startup* with a message naming the shake
receipt when an import resolves to a file the shake removed, rather than surfacing a bare
`ModuleNotFoundError` from wherever the program happened to reach for it.
Actors: the customer hitting the residual risk this feature cannot design away, and the
support engineer reading their screenshot.
Assets: diagnosability of the one failure mode `--shake` adds. The sidecar
`<out>.shake.json` receipt makes this answerable *if the operator still has the build*;
nothing in the shipped binary points at it.
Red-path: Not yet implemented — there is no launcher-side hook, so there is no test to go
red. Would require the stager to install an import hook that consults a pruned-path list
shipped in the manifest.
Source: Named as a known gap when `--shake` landed, 2026-09-10, rather than left implicit.

### INV-SHAKE-05
Status: active
Statement: `--slim-python` prunes only AFTER the bundled interpreter has been digest-verified
(`INV-SUPPLY-01`) and records every removed path on the build receipt; a default build (no
flag) prunes nothing, so the staged interpreter is byte-for-byte the pinned published
artifact.
Actors: not an attacker — the operator who wants the ~9.5 MB of interpreter furniture off a
`--thick` binary, and the auditor who repeats `INV-SUPPLY-01`'s digest check against the
publisher's release. Shipping PBS unmodified is what makes that check repeatable; pruning
before verification, or without recording what was cut, breaks it.
Assets: the provenance chain of the staged interpreter. `--slim-python` is the one path that
deliberately deletes from a verified upstream artifact, so its value depends entirely on the
order (verify, then prune — never the reverse) and on the receipt naming every file removed,
so the chain reads "verified PBS artifact, then these N files removed by haru-pack" rather
than "some tree we assembled". A default build must not touch the interpreter at all, or the
byte-for-byte property `INV-SUPPLY-01` rests on is silently lost.
Red-path: In `thick.stage`, move the `slim_mod.maybe_slim(...)` call ABOVE the
`bundle_python(...)` line — `test_slim_prunes_only_after_the_interpreter_is_verified` goes
red because the prune now precedes the fetch-and-verify. Separately, drop the
`info["slim_python"] = {...}` block in `receipt.finish` —
`test_the_receipt_lists_every_removed_path` goes red because the removed set is no longer
recorded. Walked both 2026-09-16: 1 red each, restored to green.
Source: Issue #43, 2026-09-16. Follow-up to #40. `--shake` prunes on evidence and requires a
traced suite; `--slim-python` is the distinct capability — drop a FIXED known-unused set with
no test suite — kept separate on purpose so the size trade never voids provenance by default.
Territory: src/haru_pack/build/slim.py, src/haru_pack/build/thick.py,
src/haru_pack/build/receipt.py, tests/test_slim.py

---

## The uv binary is compressed in the payload and byte-identical in the stage

### INV-PAYLOAD-04
Status: active
Statement: When `uv` is bundled it is stored XZ-compressed in the payload, and at stage time
the launcher expands it, **checks the result against the sha256 of the original bytes that
the build recorded beside it**, and refuses the tree if they differ — all before the stage
manifest is recorded, so the file the launcher executes is covered by stage verification
exactly as an uncompressed one was. The build side guarantees the recorded digest is the
publisher's: `bundle_uv` verifies the release against `pins.toml` (`INV-SUPPLY-01`) and
`compress_uv` hashes exactly those bytes.
Scope of the runtime check — read this before citing the invariant: it detects **corruption**
(a truncated or bit-rotted member, a mismatched `.size`, a decoder bug), NOT tampering. The
digest sidecar sits next to the member, so an attacker who can rewrite `uv.xz` can rewrite
`uv.xz.sha256` with it. Nor does `INV-LAUNCH-01` (`active`) close that gap for the payload as a
whole: it is the same shape of check — payload against a digest in the same attacker-writable
footer — so it too detects corruption rather than tampering. Authenticity of the whole artifact
comes from a signature over the whole binary: Authenticode on Windows, nothing equivalent on
Linux ELF output. See `INV-LAUNCH-01`'s Note, and `INV-LAUNCH-03`, which is the real fix and is
still `proposed`. The original wording of this entry said the expansion is "byte-identical to
the publisher's release" full stop, with nothing at runtime behind it — flagged by the
adversarial review of 2026-09-11 as a claim the code did not back, which is the exact failure
mode this file exists to prevent.
Actors: the operator shipping over a metered or slow link; the recipient's AV and
application-allowlisting stack; the auditor asking what `uv` is inside a signed artifact.
Assets: ~8 MB of every non-thin binary, and the integrity chain around the one file the
launcher runs first. Measured on uv 0.10.4 linux-x86_64 (2026-09-10): 55.59 MB raw,
22.25 MB as the payload's DEFLATE, **14.17 MB** as XZ/LZMA2. A default-tier `hello`
went 23 MB to 15.0 MB.
Note — why not UPX, which was the original proposal: packing *modifies the executable*.
That destroys uv's own Authenticode signature, makes the payload bytes match no publisher
digest (so `INV-SUPPLY-01`'s verification becomes unrepeatable by a third party), trips the
packer heuristics that AV engines apply to UPX above all others — on exactly the enterprise
Windows targets this project exists to serve — and pays decompression on *every* launch
rather than once. Compressing the payload *member* instead gets the same bytes back:
verified 2026-09-10, staged `vendor/uv` sha256 `ae65ed04fee535f3ab8d31da7c2f9fde156dc5afdd6b5b5125e535ccc49bba34`,
identical to the release tarball's, and present in `.stage-files` under that digest.
Red-path: five, and every one was a real failure caught by running it:
(0) drop the `.sha256` write from `bundle.compress_uv` — the launcher's check silently
becomes a no-op, because it skips when the sidecar is absent;
(0b) change one character of a built binary's `uv.xz.sha256` and run it. Walked 2026-09-11:
refused with "expanded vendor/uv.xz does not match its recorded digest", exit 7;
(1) move the `expandCompressedMembers(root)` call in `stage.stageZip` to after
`recordTree(root)` — the executed binary drops out of the recorded set;
(2) add a BCJ filter (`lzma.FILTER_X86`) to `bundle.compress_uv`'s chain — Python still
round-trips it, but `xz_dec_bcj.c` is deliberately not vendored, so the *launcher* rejects
the stream on the target;
(3) build `xzdec.nim`'s include path with `parentDir()` and `/` instead of explicit forward
slashes — those use the TARGET's separator, so `--target windows-x86_64` emits
`-I\home\...` and mingw cannot find `xz.h`. Walked all three 2026-09-10.
Source: Eli asked whether haru-pack could UPX the uv binary before storing it, 2026-09-10.
The answer was that the size win is real but belongs to LZMA rather than to packing, and is
obtainable without modifying a signed third-party executable.
Note — architecture coverage, because "the C is portable" is a claim like any other:
the decoder is compiled and round-trips the real `uv.xz` to the same digest on
linux-x86_64, on windows-x86_64 cross-compiled from Linux (under wine), and — as of
2026-09-11 — on **linux-aarch64 natively on real hardware** (gcc 14.2, `-Wall -Wextra`, no
warnings). macOS is still neither compiled nor run and `docs/TIERS.md` says so. Building the
whole launcher for aarch64 needs the real `aarch64-linux-gnu-gcc`; `zig cc` handles the
vendored C but not `nimcrypto`'s `-march=armv8-a+crypto` NEON path.
Territory: src/haru_pack/bundle.py, src/haru_pack/launcher/xzdec.nim,
src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/xz/

### INV-PAYLOAD-05
Status: active
Statement: The vendored XZ decoder in `src/haru_pack/launcher/xz/` matches, file for file,
the SHA-256 digests recorded in its own `PROVENANCE.md`, and no undeclared C or header file
sits alongside it.
Actors: whoever updates the vendored decoder; whoever audits third-party C that is compiled
into a binary they Authenticode-sign.
Assets: the audit trail for ~3 400 lines of third-party C in every launcher. This repo pins
every *binary* it executes (`INV-SUPPLY-01`); vendored source that nothing checks would be
the same trust gap with a friendlier appearance.
Red-path: change one byte of `xz/xz_dec_lzma2.c`, or drop a new `.c` into `xz/`, without
updating `PROVENANCE.md`. The claiming test goes red.
Source: Written with `INV-PAYLOAD-04`, 2026-09-10 — the decoder was vendored rather than
fetched precisely so it would be reviewable in a diff, which is only true if drift is
detectable.
Territory: src/haru_pack/launcher/xz/, tests/test_uv_compression.py

### INV-PAYLOAD-06
Status: active
Statement: A file symlink inside the payload is stored **once**, with its aliases listed in
`.haru-links`, and the launcher re-creates each alias between `extractAll` and `recordTree` —
as a **symlink** on POSIX (the on-disk dedup, INV-STAGE-04) or a **copy** on Windows — so
every alias is inside the sealed `.stage-files` manifest. Both halves of every entry are
treated as untrusted: a link or target path that could reach outside the stage
(`unsafeEntryPath`), a target the payload does not contain, a collision with a real member,
a malformed line, or more than `MaxLinkEntries` entries all refuse the payload. Only the
shape the launcher can reproduce exactly is deduplicated — a directory symlink, a dangling
one, and one escaping the payload keep the old copy-the-bytes behaviour.
Actors: the operator shipping over a metered link; anyone who can rewrite the payload of a
binary they hold, for whom a link table is the obvious arbitrary-file-write primitive.
Scale, measured rather than assumed: a thick linux-x86_64 payload carries **1047** link
entries — the four interpreter aliases plus `idle3`, `pydoc3`, the pkgconfig pair, a man
page, and about a thousand terminfo aliases. That is why the saving (34.98 MB) came out
above the 34.3 MB the five big duplicates alone predicted, and why `MaxLinkEntries` is
16384 rather than the few hundred a first guess would have set it to.
Assets: 34.98 MB of every thick binary, and the integrity chain around the interpreter the
launcher executes. Measured 2026-09-15 on `hello.py`, thick, linux-x86_64, Python 3.13:
python-build-standalone ships `bin/python` and `bin/python3` as symlinks to `python3.13` and
`libpython3.13.so` as one to `libpython3.13.so.1.0`; `Path.is_file()` follows symlinks and
`ZipFile.write` reads through them, so five names stored five full copies of two files.
DEFLATE compresses each member independently, so the duplication survived compression:
2 x 12,074,129 + 10,107,799 = **34.3 MB of an 84.5 MB payload**. After the fix the same
binary is **85,405,022 -> 50,425,885 bytes**, a 41% cut, and it still runs.
Note — this is the *shipped-binary* saving; the *on-disk* staged tree once kept the aliases
as copies because `recordTree` walked `walkDirRec` with its default `{pcFile}` filter and so
skipped `pcLinkToFile` — a symlink would have been absent from `.stage-files` and gone
unverified. `INV-STAGE-04` closed that: `recordTree` now records symlinks (as `symlink:<target>`
lines) and `verifyTree` re-checks them, so on POSIX the alias is a symlink and the ~186 MB
staged footprint drops by the duplicate bytes too, without punching a hole in `INV-STAGE-01`.
Red-path: four, all walked 2026-09-15:
(0) replace the `unsafeEntryPath` guard in `stage.materialiseLinks` with `if false:` — a
table naming `../escape.bin` or `/etc/cron.d/x` is then materialised outside the stage.
Walked: two of the four parametrised cases went green-to-red, exit 0 instead of 3, with the
file written outside the cache;
(1) move the `materialiseLinks(root)` call in `stage.stageZip` to after `recordTree(root)` —
the aliases drop out of the recorded set, exactly as `INV-PAYLOAD-04`'s red-path (1);
(2) make `payload._dedupe_target` return a target for a symlink that escapes the payload —
the launcher then cannot reproduce it and staging refuses with "does not contain";
(3) drop the `fileExists(linkPath)` collision check — a payload carrying both a real member
and a link entry for that path silently gets one of them.
Source: Eli asked why a hello-world thick binary is 85 MB when PyInstaller manages under 20,
2026-09-15. Most of the answer is deliberate (an unmodified, digest-verified CPython plus
uv); this part was not, and had been invisible because `docs/TIERS.md` recorded the missing
symlinks only as a *correctness* note the launcher tolerates, never as a size.
Territory: src/haru_pack/payload.py, src/haru_pack/launcher/stage.nim,
tests/test_payload_symlinks.py, tests/test_stage_hardening.py

### INV-PAYLOAD-07
Status: active
Statement: Every payload declares its format. `assemble_payload` stamps `payload_format` (an
integer, current value **1**) into `manifest.toml`, and the launcher REFUSES a payload whose
declared format exceeds `MaxSupportedPayloadFormat` (also 1) — exit `ExitPayloadFormat` (12),
with "this payload's format (N) is newer than this launcher understands (1); rebuild with a
matching haru-pack". A payload with NO `payload_format` key reads back as 0 (legacy) and is
ACCEPTED, so every payload built before this field existed keeps launching. This mirrors the
instinct already in `overlay.footerSizeFor` (an unknown footer version is refused, not guessed)
and `stage.expandCompressedMembers` (a member with no `.size` sidecar is refused as "not produced
by a matching haru-pack") — but points it at the OTHER skew: not a malformed payload, an older
launcher handed a newer one.
Actors: whoever caches, vendors, or `--launcher <path>`s a prebuilt launcher instead of the one
this repo compiles during every build — the moment the "always build both at once" coincidence
that makes the skew unreachable today stops holding; the recipient who would otherwise run a
silently broken staged tree.
Assets: the guarantee that a launcher matches the payload it stages. The concrete failure is
`.haru-links` (#40, `INV-PAYLOAD-06`): a launcher predating `materialiseLinks` stages the ~1000-
entry link table as an ordinary ~60 KB text file, so `bin/python` and every other alias silently
never appear and the app runs against a tree missing its interpreter — a confusing runtime error
or a silent misbehaviour depending on which alias something reaches for. A one-integer version
gate gives every FUTURE payload member the same protection at once, instead of re-litigating it
per feature the first time a prebuilt-launcher path exists — which is the wrong time.
Note — where the check sits, stated plainly: the format lives inside the payload's own
`manifest.toml`, so the launcher can only read it after `stageZip` has extracted the tree. The
refusal therefore fires just after `parseManifest`, BEFORE `findUv` and any execution — it
prevents RUNNING a mis-staged tree, which is the harm, not the staging into the private cache
(which `--reap` cleans). A corrupt/non-integer `payload_format` degrades to 0/legacy via
`getInt`'s default, matching the "no key is accepted" rule rather than faulting.
Red-path: two, both walked 2026-09-16:
(0) bump `MaxSupportedPayloadFormat` in `launcher/main.nim` from 1 to 999 (neutralise the gate)
and rebuild. Observed: `test_payload_format_newer_than_supported_is_refused` and
`test_a_far_future_format_is_also_refused` flipped green-to-red — the format-2 and format-99
payloads ran all the way to their bundled uv (`PAYLOAD_UV_RAN` on stdout, exit **0** instead of
12), while the legacy and current-format accept tests stayed green. Restored to 1;
(1) comment out `manifest["payload_format"] = PAYLOAD_FORMAT` in `build/assemble.py` (drop the
stamp). Observed: `test_build_stamps_the_current_payload_format` flipped green-to-red — the
written manifest carried no `payload_format` at all (`None == 1`), i.e. the launcher's gate would
have nothing to check and the guarantee would rest entirely on "always build both at once".
Restored.
Source: filed by Eli as #44 while landing #40 — noticed that the thing making the old-launcher/
new-payload skew unreachable is a coincidence (haru-pack compiles the launcher from source every
build), not a check, and that `manifest.toml` carried no format version while the footer's
`format_ver` describes only the footer layout, not the payload's contents.
Territory: src/haru_pack/payload.py, src/haru_pack/build/assemble.py,
src/haru_pack/launcher/manifest.nim, src/haru_pack/launcher/main.nim,
tests/test_payload_format.py

### INV-BUILD-08
Status: active
Statement: A bare console-script entrypoint is checked as far as the tier allows: refused
when an environment exists and neither the project nor any dependency provides it, warned
about when there is no environment to check against, and silent when the project declares
it. A `.py` entrypoint that is not in the project tree is always refused.
Actors: an operator passing `--entry-point serve` for a script that was renamed, or typing
`--entry-point app.py` for a file that lives in a subdirectory.
Assets: `docs/PRINCIPLES.md`'s third user — the recipient of the executable, who sees only
"it worked" or "it didn't". An unresolvable console script fails as a `command not found`
from uv on *their* machine, after a build that exited 0.
Red-path: Delete the `verify_console_script(...)` call from `assemble_payload` and
`test_a_console_script_nothing_provides_is_refused_at_thick` goes red. Delete the
`verify_script_file(...)` call in `build._resolve` and
`test_a_missing_script_file_is_refused` goes red.
Note: The graded response is the point, not timidity. The launcher runs `uv run <name>`,
which resolves console scripts from the project environment — so `gunicorn`, `flask`,
`celery` and `uvicorn` are correct answers that appear nowhere in `[project.scripts]`.
Refusing on absence from that table would reject working builds, which is its own
ergonomic failure. Certainty comes from an environment, and only `--thick` has one at build
time; at thin/default the honest output is a warning that names what could not be checked
and says `--thick` would check it.
Note: A script declared in `[project.scripts]` is trusted without looking in the
environment, because a `[tool.uv] package = false` project does not install its own scripts
and would otherwise be refused wrongly.
Source: Asked for 2026-09-10 — "fix both of those issues. user ergonomics is paramount" —
after `-e serve` with no such script was found to build cleanly.
Territory: src/haru_pack/entrypoints.py, src/haru_pack/build/, tests/test_entrypoints.py

### INV-BUILD-09
Status: active
Statement: When haru-pack refuses to choose an entrypoint, it names concrete candidates and
prints a command the operator can copy — it never refuses without saying what to do next.
Actors: a developer meeting the tool for the first time, on a project it cannot read a
single obvious answer out of.
Assets: whether "it refuses instead of guessing" is a feature or an obstacle. Refusing is
correct (INV-BUILD-03); refusing with a wall of prose and no next step converts a good
decision into a bad experience, and `docs/PRINCIPLES.md` ranks that as a failure.
Red-path: Make `discovery.discover` raise `AmbiguousProject` with an empty candidate list
for an importable-but-not-executable package — i.e. drop the `suggest_object_refs` call.
`test_a_non_executable_package_suggests_its_own_callables` goes red, and the operator is
back to reading a paragraph and guessing.
Note: Suggesting is not picking. The candidates are ordered by `PREFERRED_CALLABLES` so the
first one printed is usually right, and the build still refuses until a human chooses.
Verified 2026-09-10 against a package defining `main` and `helper`: the refusal listed
`demo:main` and `demo:helper` and printed
`haru-pack build <path> --entry-point demo:main`.
Source: Asked for 2026-09-10 with INV-BUILD-08.
Territory: src/haru_pack/discovery.py, src/haru_pack/entrypoints.py, src/haru_pack/cli/,
tests/test_entrypoints.py

---

## UI — what haru-pack prints is what it meant to print

### INV-BUILD-10
Status: proposed
Statement: `ft-probe` cannot report a pass unless it observed the GIL actually disabled in the
process that ran the tests.
Actors: not an attacker — a developer deciding whether to ship a free-threaded build.
Assets: the probe's only claim. A probe that passes with the GIL on is a green light bolted to
nothing, and its whole purpose is to be believed by someone who will not re-derive it.
Red-path: Run `ft-probe` with `PYTHON_GIL=1` in the environment on a project whose suite passes.
`PYTHON_GIL=1` re-enables the GIL on a free-threaded build, so the run proves nothing; the probe
must refuse to report `no-blocker-found`. If it still reports a pass, the check is absent.
Source: docs/FREE_THREADED.md, 2026-09-10.
Territory: not yet — nothing is implemented. Planned: src/haru_pack/ (probe module), tools/

---

## UI — what haru-pack prints is what it meant to print
### INV-UI-01
Status: active
Statement: No text haru-pack prints is lost to terminal markup. Rich markup is opt-in per
call, never the default, and the `name: value` shape of `haru-pack verify`'s output is
preserved so it stays machine-readable.
Actors: `docs/PRINCIPLES.md`'s second user — the developer reading a refusal — and a CI job
grepping `haru-pack verify`.
Assets: the actionable half of every error message. Measured 2026-09-10 with rich 15.0.0:
`from rich import print` renders `[project.scripts]` as **nothing at all** and `[[bundle]]`
as `[]`, because rich reads `[...]` as a style tag and drops unrecognised ones silently
rather than raising. Those exact strings are what the entrypoint and config refusals exist
to tell the operator — `[project.scripts]`, `[tool.haru-pack]`, `[shake]`, `[sources]`,
`[[bundle]]`, `[[post_install]]`. A refusal that names no fix is worse than the bug it
reports.
Red-path: Change `ui.print`'s `markup` default to `True`, or `from rich import print`
directly in `cli/`. Ten parametrizations of
`test_bracketed_text_survives_printing` go red. Separately, render `ui.fields` as a
`rich.Table` again — it drops the `:` separator and
`test_fields_keeps_the_colon_separator` goes red, which is what would have broken
`haru-pack verify app | grep 'sha_ok: True'`.
Source: Asked for 2026-09-10 — "haru should use rich to print things nicely… `from rich
import print` to make the change as small as possible". The change is that small at every
call site; it just routes through `haru_pack.ui` so the brackets survive. The first draft
of `ui.fields` did render a table and did drop the colon, which is why that half is an
invariant too.
Note: `NO_COLOR=1` and a non-tty stdout are honoured by rich, so piped output is plain —
verified. Colour is never the carrier of meaning: every state that is coloured is also
stated in words (`payload integrity: OK`, `nim deps: FAILED`), because a colour is invisible
to anyone reading a log file.
Territory: src/haru_pack/ui.py, src/haru_pack/cli/, tests/test_ui.py

---

## PKG — the thing on PyPI is the thing that works

### INV-PKG-01
Status: active
Statement: `haru` and `haru-pack` are both installed console scripts pointing at the same
callable, and every command haru-pack prints back for the operator to run uses the name they
actually invoked.
Actors: a downstream user who typed `haru` because it is shorter, then read a refusal telling
them to run `haru-pack`.
Assets: `docs/PRINCIPLES.md`'s second user. Copy-pasteable output is the entire point of the
entrypoint refusals (INV-BUILD-09); printing a command the operator did not type makes them
translate it, and translating is where the typo goes.
Red-path: Remove either entry from `[project.scripts]` —
`test_both_commands_are_declared` goes red. Or hardcode `"haru-pack"` in `cli.prog()` and
`test_the_copy_pasteable_command_uses_the_invoked_name` goes red.
Note: Two real console scripts, not a shell alias, so the short name works on a Windows
install with no shell profile to alias in. `version` deliberately still prints `haru-pack`
whichever way it was invoked, because it reports the installed *distribution*.
Note: The distribution name `haru` is NOT available on PyPI — it is an unrelated web
framework (`haru 0.0.1a4`). Script names are per-environment so the command is fine, but
`pip install haru` will never be this project.
Note: A consequence, verified 2026-09-10: haru-pack's own `pyproject.toml` now declares two
console scripts, so `haru-pack .` on this repository correctly refuses as ambiguous and
lists both. Packing haru-pack with haru-pack needs `-e haru-pack`.
Source: Asked for 2026-09-10 — "i want to have haru-pack and haru as equivalent commands".
Territory: pyproject.toml, src/haru_pack/cli/, tests/test_packaging.py

### INV-PKG-02
Status: active
Statement: Every file the launcher is compiled from — the Nim sources, the vendored XZ
decoder's `.c`/`.h`, and `pins.toml` — is shipped in the wheel, and no launcher file on disk
falls outside the include list.
Actors: anyone who installs from PyPI rather than from a git checkout.
Assets: whether the published package works at all. `[tool.hatch.build] include` is a
hand-written allowlist, so a new launcher file is omitted *silently* — and the resulting
haru-pack builds nothing, failing on the user's machine at their first build with
`xz.h: No such file or directory`. The dev machine never sees it, because there the sources
are simply present in the tree.
Red-path: Drop `src/haru_pack/launcher/xz/*.c` from the include list.
`test_the_launcher_sources_are_declared_for_the_wheel` goes red. Add a new file under
`src/haru_pack/launcher/` matching no pattern and
`test_every_launcher_source_on_disk_is_covered_by_an_include_pattern` goes red.
Note: Verified end to end 2026-09-10 — `uv build`, install the wheel into a clean venv, and
`launcher_src_dir()` resolves with `main.nim`, `xzdec.nim` and three `xz/*.c` present. The
suite checks the declaration rather than repeating that, because building a wheel needs a
network.
Source: Added 2026-09-10 while getting the project ready for PyPI. The vendored C had just
been added and was one forgotten line away from shipping broken.
Territory: pyproject.toml, tests/test_packaging.py

---

## CI — the checks that gate a release actually run, and run the same thing everywhere

### INV-CI-01
Status: active
Statement: The linter is pinned to one exact version, declared in exactly one place, and
both CI and `scripts/cut-release.sh` use that pin rather than whatever `ruff` is on PATH.
Actors: nobody adversarial — ruff's own release cadence.
Assets: every other check in this repository. `ci.yml` runs `lint` before the invariant
contract and the full suite, so a lint failure means **neither of them runs**; and
`publish.yml` has `needs: ci`, so it also means nothing can be released. Measured
2026-09-11: CI had failed on eight consecutive runs, every one of them a lint failure on
unchanged code, because `uvx ruff check .` downloads the newest ruff and ruff's DEFAULT rule
set grows between versions. On this tree, ruff 0.15.19 is clean and ruff 0.16.6 reports 143
errors (`I001`, `PLW1510`, `RUF100`). The machine-checked half of this very file had not
executed in CI for days.
Red-path: Change `ci.yml`'s lint step back to `uvx ruff check .`, or loosen the dev-group pin
to `ruff>=…`. `test_the_linter_is_pinned_to_one_version` goes red. To watch the original
failure: run `uvx ruff@0.16.6 check .`.
Note: There were **three** different ruff versions on the maintainer's machine when this was
diagnosed — `~/.local/bin/ruff` 0.15.19, `.venv/bin/ruff` 0.16.6, `uvx ruff` 0.15.19 — which
is why the release gate reported success on the exact commit CI rejected. The gate no longer
falls back to an unpinned `ruff`; it fails if `uv` is missing instead, because a skipped
check that prints a note is the thing that let this run for a week.
Note: Pinning is not an opinion about the new rules. Adopting them is a separate, deliberate
change — `I001` in particular fights the compact grouped-import style `[tool.ruff.lint]`
documents on purpose.
Source: Found 2026-09-11 while answering "what do we need to publish to PyPI": the answer
was "nothing, except that CI has been red for days and gates the publish workflow".
Territory: .github/workflows/ci.yml, pyproject.toml, scripts/cut-release.sh,
tests/test_packaging.py

### INV-CI-02
Status: active
Statement: A release built by `scripts/cut-release.sh` packs haru-pack with haru-pack for
linux-x86_64 and windows-x86_64, verifies each artifact's payload, and refuses to tag if
that fails; skipping it requires saying `--no-self-build` out loud.
Actors: the user who downloads a binary because they have no Python — and every reader of
the claim "point it at a Python project and get a binary".
Assets: whether the pitch is true. haru-pack is a Python project with a native dependency
(`cryptography`), a console-script entrypoint, and package data that has to survive into the
payload, so packing itself exercises the parts most likely to break. Verified 2026-09-11:
both targets build, both pass `haru-pack verify`, the Linux artifact runs and reports its own
version, and the Windows artifact stages and executes its bundled uv under wine.
Red-path: Remove the `./scripts/self-build.sh` call from the gate in `cut-release.sh`, or
make its failure non-fatal. `test_the_release_gate_self_builds` goes red. Separately, remove
the `${#BUILT[@]}` guard or the target-name validation from `self-build.sh` and
`test_the_self_build_refuses_to_succeed_with_no_artifacts` goes red.
Note: it DID succeed having built nothing. `--targets ""` printed "self-build ok: 0
artifact(s)", exited 0, and `sha256sum` with an empty argument list hashed STDIN into
SHA256SUMS — so the gate would have passed and published a release whose only asset described
an empty set. Found by the adversarial review of 2026-09-11; both cases now exit 1 before any
work is done.
Note: Default tier, not `--thick`, so each artifact is ~15 MB and fetches Python on first
run. Thick self-builds would need Windows `cryptography` wheels resolved from Linux — a
different question from "does the tool work on itself".
Note: The Windows artifact cannot be fully smoke-tested here. wine cannot create the
junctions uv wants for a Python install (`os error 50`), so the script accepts reaching that
error as success and says why. A full Windows first-run check needs real Windows, and this
invariant does not claim otherwise.
Source: Asked for 2026-09-11 — "wire the self build to demonstrate it via releases (linux
and windows as part of the release script)".
Territory: scripts/self-build.sh, scripts/cut-release.sh, tests/test_packaging.py

---

## STUB — the cleartext, signature-covered stub-config section

### INV-STUB-01
Status: active
Statement: The launcher verifies the v2 stub-config's SHA-256 against the `stub_sha256` in
its own footer BEFORE parsing the canary map, and refuses a mismatch with `ExitBadStub`.
Actors: anyone who can write to a distributed binary. The stub bytes and the digest they are
checked against both live in the same attacker-writable region.
Assets: the per-knob canary map — which env var the launcher reads for the decryption key
and (in later phases) for the other knobs. A silently-altered map is a silently-altered
launcher input.
Red-path: Replace `verifyStubDigest(stubBytes, ft.stubSha)` in `main.launch` with `discard`,
rebuild, then change one canary letter inside the stub-config region of a built UNENCRYPTED
v2 exe (`HARU` -> `XARU`, still a valid prefix). Without the guard the altered-but-valid map
parses and the build runs (rc 0); with it, `ExitBadStub`. Walked 2026-09-10: 1 red.
Source: docs/adr/0003-stub-config-and-canary.md §1.7. Analog of INV-LAUNCH-01 with the same
self-referential caveat.
Note: Like the payload digest (INV-LAUNCH-01) this is NOT tamper-evidence — both the stub
bytes and `stub_sha256` come from the same footer, so an editor can recompute it. It detects
corruption/truncation/naive edits and is the precondition for a real signature
(INV-LAUNCH-03, still proposed). It must not be described as tamper-proof.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/launcher/overlay.nim

---

## CANARY — per-knob env-name resolution

### INV-CANARY-01
Status: active
Statement: The SECRET knob's decryption key is read from the single env var
`<canary.secret>_SECRET` named by the stub-config (default `HARU_SECRET`); the retired
`HARUPACK_SECRET` is not read, and no other knob's prefix resolves the secret.
Actors: not an attacker — the packager choosing a per-build canary, plus the property that a
stale or guessed env name (legacy `HARUPACK_SECRET`, or the wrong knob's prefix) does not
decrypt.
Assets: correct resolution of the decryption key's env name. A launcher that still honoured
`HARUPACK_SECRET` would silently accept a secret set under the retired name, defeating the
canary's purpose.
Red-path: Hardcode `cryptbox.resolveSecret` back to `getEnv("HARUPACK_SECRET")` (ignore
`secretEnv`), rebuild. A default build run with `HARU_SECRET` set then fails to decrypt (rc 4
"no secret"); a build whose stub sets the secret canary to `MARK`, run with `MARK_SECRET`
set, also fails. Walked 2026-09-10: 2 red.
Source: docs/adr/0003-stub-config-and-canary.md §3.2/§3.3. One resolution rule,
`stubconfig.envForKnob`, serves all four knobs; only SECRET is consumed in Phase 1.
Territory: src/haru_pack/launcher/cryptbox.nim, src/haru_pack/launcher/stubconfig.nim, src/haru_pack/launcher/main.nim

### INV-CANARY-02
Status: active
Statement: The build resolves the per-knob canary map with the precedence
`--stub-env-<knob>-canary` > `--env-canary`/`--env-canary-random` > built-in `HARU`, refuses
two conflicting all-knobs defaults and any resolved token that is not a valid env-name prefix
(`^[A-Za-z_][A-Za-z0-9_]*$`), emits the map as the cleartext stub-config section of a v2
binary, and records it in the build receipt. The map is not secret; the secret VALUE never
appears in it (INV-SECRET-02).
Actors: the packager choosing a per-build canary — not an attacker. The dangerous outcome is
a build that silently ships a stub the launcher then reads a different env name for than the
packager was told, or a receipt/auditor that cannot see which env names a binary watches.
Assets: agreement between what the packager asked for, what the binary carries, and what the
receipt reports; and the property that every NEW binary carries the section at all.
Red-path: In `build.resolve_canary`, delete the `if env_canary and env_canary_random: raise`
and `test_conflicting_all_knob_defaults_refused` goes red; delete the
`if not _CANARY_RE.fullmatch(tok): raise` and `test_invalid_canary_token_refused` goes red.
Drop `stub_config=` from the `build.build` `attach()` call (emit a v1 footer) and
`test_build_emits_a_v2_binary_carrying_the_canary_map` goes red (`format_ver == 1`); drop
`canary=canary` from the receipt `info.update` and both the emit test and
`test_receipt_records_the_canary_map_but_not_the_secret` go red. Walked 2026-09-10.
Source: docs/adr/0003-stub-config-and-canary.md §2.1/§5. The build half of the one resolution
rule INV-CANARY-01 defends at runtime; every new binary is v2 (carries the section).
Territory: src/haru_pack/build/, src/haru_pack/cli/, src/haru_pack/overlay.py

### INV-CANARY-03
Status: active
Statement: Every haru-named runtime INPUT the launcher reads from the environment resolves ONLY
through the canary model (`stubconfig.envForKnob`, a dynamic `<canary>_<KNOB>` name) — the launcher
source contains no `getEnv("HARU…")` / `getEnv("HARUPACK…")` string LITERAL used as input, except
the dev-only `HARUPACK_DEV_STAGE` (guarded by `-d:haruDev`, never in a release binary). Env vars the
launcher SETS for the child (`UV_*`, `PYTHONPATH`, the `HARUPACK_*` injects/reserved) are outputs
via `putEnv`, not inputs, and are out of scope. This closes the honor-system bypass class — e.g. the
removed `getEnv("HARUPACK_GEO")` geo bypass, which an end user could set to an allowed value to pass
a security gate (CONTEXT.md "geo / ip"; the geo gate now fails closed offline).
Actors: an end user on the target trying to influence the stub with a guessed/known plain env name;
the property is that there is no such name — every input hides behind the per-build canary.
Assets: the integrity of the canary model itself. One plain `getEnv("HARUPACK_X")` input reintroduces
the bypass class the canary exists to remove, and nothing but a scanner would catch it drifting back.
Red-path: A machine-checked scan (`tests/test_canary.py::test_no_plain_haru_named_input_env_read`)
reads every `src/haru_pack/launcher/*.nim` and fails on any `getEnv("HARU…")` literal not in the
whitelist. Add `getEnv("HARUPACK_FOO")` to any launcher source and the scan goes red; restore the
`getEnv("HARUPACK_GEO")` read and it goes red naming that var. Walked 2026-09-12.
Source: adversarial review 2026-09-12 (Phantom_Phreak) — found `cryptbox.nim` still reading
`HARUPACK_GEO` though CONTEXT.md said the bypass was removed. All runtime inputs routed through the
canary model; the geo gate made env-non-overridable (fail-closed offline).
Territory: src/haru_pack/launcher/cryptbox.nim, src/haru_pack/launcher/main.nim, src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/stubconfig.nim, tests/test_canary.py

---

## INJECT — env-append lives in the payload, and the build is honest about it

### INV-INJECT-01
Status: active
Statement: The build validates each `--env-append KEY=VALUE` into the payload manifest `inject`
list — refusing a malformed entry (no `=`, empty KEY) or a reserved KEY (`HARUPACK_*`, the
launcher-managed `UV_*`, `PYTHONPYCACHEPREFIX`, `PYTHONPATH`) — and, on an UNENCRYPTED build
only, warns loudly when a value is secret-shaped. An encrypted build hides the payload and so
warns nothing.
Actors: the packager injecting licensing/API-key env — plus the honesty edge from
INV-SECRET-02: a plaintext payload ships the value recoverable, and the operator must not
assume otherwise. A reserved KEY is the silently-ineffective-config class INV-BUILD-01/02 forbid.
Assets: the operator's correct understanding of what an unencrypted inject exposes, and the
guarantee that an inject the launcher would silently drop is refused at build time, not shipped.
Red-path: In `build.resolve_injects`, remove the
`if not encrypted and _looks_secret_shaped(...)` warning branch and
`test_secret_shaped_inject_warns_on_unencrypted_build` goes red; remove the reserved-key
`raise` and `test_reserved_inject_key_refused` goes red; in `build.build`, remove
`manifest["inject"] = injects` and `test_build_writes_inject_into_the_payload_manifest` goes
red. Walked 2026-09-10.
Source: docs/adr/0003-stub-config-and-canary.md §4.3. The pairs live post-decrypt; the
launcher applies them before uv + the app and its own reserved vars win on a collision
(INV-LAUNCH-09). Called "inject", never "project".
Territory: src/haru_pack/build/, src/haru_pack/cli/

---

## STAGING-2 — reap, ram-only, and base-path relocate staging without becoming a delete primitive

Phase 2 of the launcher rework (docs/adr/0004-reap-ram-staging.md) lets a build bake three
staging choices into the cleartext stub-config: an on-exit detached cleanup (`--reap`), a
best-effort RAM-backed staging root (`--ram-only`), and a relocated staging root
(`--base-path`, consuming the Phase-1 `BASE_PATH` knob). The danger is that `--reap` is a
delete primitive fed by a relocatable root, one input to which (`BASE_PATH` env) is
attacker-settable. The invariants below keep the delete target pinned to a subtree the
launcher itself created, and keep an unsafe root out at both build and run time. None of the
three changes any security decision by its ABSENCE, which is why neither the footer version nor
`stub_config_version` moves — the corpus and the absence-is-today's-behaviour default are held
by the CANARY/STUB invariants above and by docs/adr/0004 §2.

### INV-BASE-01
Status: active
Statement: The launcher resolves the staging root by the precedence `BASE_PATH` env
(canary-resolved) > stub-config `base_path` > (`ram_only` ? RAM-backed root : the per-user
cache), computed BEFORE staging; it stages and reaps only a `<root>/<key>-<digest>` subtree it
creates, and it REFUSES a root that is empty, `/`, a filesystem/drive/UNC root, or the
home-directory root — at build time for `--base-path` and defensively at runtime for both the
baked `base_path` and the `BASE_PATH` env.
Actors: anyone who can set the `BASE_PATH` env on the target (the value is not baked through
the build), plus a packager who fat-fingers `--base-path /`. The reaper (INV-REAP-01) deletes
what staging created, so a root that resolves to `/` or `$HOME` would be catastrophic.
Assets: the property that relocating staging can never become arbitrary-create or (via reap)
arbitrary-delete; a hostile `BASE_PATH` can move where the subtree lives but not what is
deleted, and can never name a bare root.
Red-path: In `stage.refuseUnsafeRoot` return `""` always, rebuild, run a binary whose
stub-config sets `base_path = "/"` (or run any binary with `HARU_BASE_PATH=/`): without the
guard the launcher tries to stage under `/` and the "refusing to stage under an unsafe base
path" `ExitBadStub` never fires. Separately, in `build.resolve_base_path` drop the
`_is_root_like` raise and `test_build_refuses_root_base_path` goes red. Separately, reorder
`main.resolveStagingRoot` to consult `sc.basePath` before the env and
`test_env_base_path_overrides_stub_base_path` goes red.
Source: docs/adr/0004-reap-ram-staging.md §3/§6. Consumes the `BASE_PATH` knob ADR 0003 §3.4
left wired-but-unconsumed; the per-knob env-name rule is INV-CANARY-01.
Note: The refusal resolves SYMLINKS, not just `.`/`..`. A lexical-only check was proven
bypassable 2026-09-11: `refuseUnsafeRoot("/tmp/x")` where `/tmp/x -> $HOME` returned ACCEPTED,
so a symlinked `BASE_PATH` staged (and, with `--reap`, reaped) a subtree at the forbidden real
location — blast radius bounded to the own subtree, but the guard's intent defeated and a
TOCTOU window opened. On POSIX, `physicalPrefix` resolves the longest existing ancestor via `expandFilename`
(realpath) before the root/drive/home checks. On WINDOWS, `getFullPathNameW` (what
`expandFilename` uses there) does NOT follow reparse points and untested
`GetFinalPathNameByHandleW` FFI has no place in a delete-primitive guard, so Windows FAILS
CLOSED: it refuses a staging root whose existing prefix passes through any reparse point
(symlink OR junction; both set FILE_ATTRIBUTE_REPARSE_POINT, which `symlinkExists` tests).
`reapDetached` refuses a target that has since become a symlink/reparse point on both platforms
(defence-in-depth against a swap between create and the detached delete).
Red-path: delete the `physicalPrefix` block in `refuseUnsafeRoot` and
`test_symlinked_env_base_path_to_a_refused_root_is_refused` goes red (the launcher stages under
`$HOME` / `/`). See CHANGELOG.md 2026-09-11.
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/stubconfig.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build/, src/haru_pack/cli/

### INV-RAM-01
Status: active
Statement: With `ram_only` baked and no base-path override, the launcher stages under a
RAM-backed root — `/dev/shm/haru-pack` on Linux when `/dev/shm` exists and is writable — and
otherwise falls back to the persistent per-user cache with an honest stderr note; an explicit
base_path always wins over ram-only.
Actors: not an attacker — a packager who does not want the staged payload tree written to
persistent disk, and who must not be given a false guarantee when no RAM filesystem exists.
Assets: an honest mechanism (real tmpfs paths the interpreter can import from; memfd is
unusable for a path-based import tree) and an honest fallback, so ram-only never silently
promises RAM it did not get. It governs only where the STUB stages, never the app's own writes.
Red-path: In `stage.ramBackedRoot` return `baseDir()` unconditionally, rebuild, run a binary
whose stub-config sets `ram_only = true`: staging then lands in the per-user cache and
`test_ram_only_stages_under_dev_shm` (which asserts `HARUPACK_STAGE` is under `/dev/shm`) goes
red. Walked on this Linux host, where `/dev/shm` exists.
Source: docs/adr/0004-reap-ram-staging.md §4. CONTEXT.md "RAM-backed staging (ephemeral)".
Note: Phase 3 (INV-EPHEMERAL-01, docs/adr/0007) adds a second "otherwise falls back" condition
to the auto path: even when `/dev/shm` is available, the launcher stages to RAM only when the
baked `unpacked_bytes` provably fits free memory. A real `ram_only` build always bakes that size,
so this narrows nothing an operator sees; a hand-crafted stub with `ram_only` and no
`unpacked_bytes` now fails safe to disk rather than gambling RAM.
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build/

### INV-REAP-01
Status: active
Statement: With `reap` baked, after the app exits the launcher spawns a DETACHED,
fire-and-forget process that deletes ONLY the `<root>/<key>-<digest>` subtree it created this
run, then returns the child's exit code without waiting; the base path itself and anything
beside the subtree are left intact, and a `HARUPACK_DEV_STAGE` tree is never reaped.
Actors: not an attacker — a packager who wants staged bytes cleaned up on exit; the safety edge
is that the delete target must be the launcher's own subtree, never a raw base_path or env value
(shared with INV-BASE-01).
Assets: cleanup of the staged subtree that keeps running after the stub dies (many GB), without
ever deleting the root it lives under or a developer's dev-stage tree.
Red-path: Comment out the `if reapWanted and reapTarget.len > 0: reapDetached(reapTarget)` call
in `main.launch`, rebuild, run a binary whose stub-config sets `reap = true` and a base_path
under a temp dir: the staged subtree is still present after exit and
`test_reap_deletes_only_its_own_subtree` (which polls for the subtree to vanish while asserting
the base dir and a sentinel survive) goes red. Walked 2026-09-10 on Linux.
Source: docs/adr/0004-reap-ram-staging.md §5/§6. CONTEXT.md "detached reap" / "reap
(build-time)".
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build/

### INV-SHRED-01
Status: active
Statement: With `overwrite` baked (which requires `reap`), the detached reaper SHREDS before it
unlinks: for every staged regular file it opens the file WITHOUT truncation, seeks to 0, writes
`getFileSize(file)` bytes from a reused non-crypto PRNG buffer covering the whole logical extent,
and `fsync`/`FlushFileBuffers` BEFORE the file is unlinked; `overwriteFile` returns true only when
bytes-written == file length. It is native Nim on both platforms — a POSIX inline shred in the
double-forked reaper, and a Windows re-exec of the launcher as a guarded `--haru-shred <subtree>`
worker — with no shell, no PowerShell, and no shipped secure-erase binary. The shred target is
always the launcher's own `<root>/<key>-<digest>` subtree; the `--haru-shred` surface is guarded
(stage-shaped name, safe root, non-symlink, never a `HARUPACK_DEV_STAGE` tree).
Actors: not an attacker — a packager shipping an unencrypted model blob that unavoidably touches
disk on Windows/macOS, who wants it to resist SIMPLE file-undelete after the app exits. The safety
edge is shared with INV-REAP-01/INV-BASE-01: the shred/delete target must be the launcher's own
subtree, and the new `--haru-shred` re-exec must never become arbitrary-delete.
Assets: the property that a matching-length in-place overwrite covers the full LOGICAL extent and
is durable (fsync) before the unlink, so a logical file-undelete tool (Recuva/PhotoRec/TestDisk)
on a non-CoW filesystem finds overwritten bytes, not the plaintext. This is an HONEST, BOUNDED
control, NOT a secure erase: SSD FTL/wear-leveling (LBA != PBA), copy-on-write filesystems,
snapshots/VSS, journals, and swap can all retain the original — documented in THREAT_MODEL.md, with
`--encrypt` + `--ephemeral` named as the durable defense (nothing plaintext ever reaches disk).
Red-path: In `stage.overwriteFile` add `return true` before the write loop (claim success without
writing), rebuild the tests/test_shred.py harness, run `harness overwrite <file>`: the file still
holds its original bytes and `test_overwrite_covers_extent_and_changes_content` goes red with
CONTENT_UNCHANGED. Separately, delete the `fsync`/`flushFileBuffers` line and
`test_overwritefile_fsyncs_before_it_closes` goes red. Separately, drop the `overwrite and not
reap` raise in `build.build` and `test_overwrite_requires_reap` goes red. Walked 2026-09-11 on
this Linux host.
Source: docs/adr/0004-reap-ram-staging.md §5b. Asked for in issue #2 — an honest anti-recovery
ceiling, native-only (no PowerShell on hardened targets), belt-and-suspenders to encrypt-at-rest.
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build/, src/haru_pack/cli/

---

## REMOTE — the payload can arrive over the wire, and the wire is not trusted

### INV-REMOTE-01
Status: active
Statement: A remote-fetch build (`--source-url`, footer remote flag) embeds NO payload bytes; it
fetches the payload over HTTP at runtime and runs it through the SAME pipeline as an appended
build — the build-baked footer digest (`ft.payloadSha`) is verified against the fetched bytes
BEFORE decrypt/license/stage, so only bytes matching the digest ever run. The byte SOURCE is the
only difference between appended and remote delivery: no pipeline step is skippable by choosing a
mode. Delivery mode is fixed at build time by the footer flag; the `SOURCE_URL` knob (env
`<canary>_SOURCE_URL` over the baked value) only relocates WHERE to fetch (mirror/failover) — an
APPENDED build never flips to a network fetch because of an env var, and any fetch/transport
failure is fail-closed (`ExitRemoteFetch`), never a fallback to running something else.
Actors: an attacker on the network path (or a hostile/compromised mirror) who can substitute the
fetched bytes, and a local user who can set `<canary>_SOURCE_URL` to repoint the fetch. Neither can
cause unverified bytes to execute: substituted bytes fail the digest check, a repointed URL is
still digest-anchored.
Assets: the property that where the payload comes from is untrusted input and the build-time digest
is the sole trust anchor — so remote delivery is exactly as safe as appended delivery, and a
down/lying host degrades to a refusal, not to arbitrary code.
Red-path: Remove the `verifyPayloadDigest(payload, ft.payloadSha)` call after the fetch/read split
in `main.launch`, rebuild, and run a remote binary whose server returns tampered bytes: the app
RUNS on the tampered payload (returncode 0, no "integrity check FAILED"), and
`test_remote_tampered_bytes_fail_closed` goes red. Separately, make `main.launch` swallow the
`fetchPayload` error instead of `die(..., ExitRemoteFetch)` and `test_remote_server_down_fail_closed`
goes red. Walked 2026-09-12 on this Linux host (the digest neutralization was observed to run
tampered bytes — zippy tolerates the trailing junk, so the digest check is exactly what stops it).
Source: docs/adr/0005-remote-fetch.md. CONTEXT.md "remote-fetch" / "payload pipeline". Issue #10.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/launcher/uvfetch.nim, src/haru_pack/launcher/overlay.nim, src/haru_pack/launcher/stubconfig.nim, src/haru_pack/overlay.py, src/haru_pack/build/, src/haru_pack/cli/, tests/test_remote_fetch.py

---

## GATE — a pre-run condition is resolved, matched, and failed closed

### INV-GATE-01
Status: active
Statement: Every rule-checked execution gate has ONE shape — resolve a current value, match it
against an allow-policy, FAIL CLOSED — and all gates live inside the encrypted policy (checked
post-decrypt, invisible to a reverse-engineer). The online geo/ip gate resolves the caller's
IP+geo from a consensus of N resolver endpoints and returns normally ONLY when at least
`consensus` endpoints resolve AND at least `consensus` of them agree the caller is allowed;
anything less — too few reachable, too few agreeing, an unparseable body, `success != true` — is
a refusal (`quit 3`), never a pass. `date` (expiry) is the same shape; `machine`/`user` are
strictly stronger (cryptographically bound via the key). Designing one gate is designing them all.
Actors: an operator on a down or lying network (a resolver that times out, 500s, or returns junk)
who would benefit if "cannot check" silently became "allowed"; and the packager who must trust
that a location restriction actually restricts.
Assets: the fail-closed property — an execution gate that cannot resolve its input denies rather
than admits, so a DoS'd or partitioned resolver stops the app instead of waving it through.
Red-path: In `execgate.checkGeoGate` disable the two guards (`if resolved < gp.consensus: quit`
and `if allowed < gp.consensus: quit`), rebuild, and run an encrypted binary whose resolver
reports a denied location (and, separately, one whose resolver is unreachable): the app RUNS
(returncode 0), and `test_geo_denied_location_fails_closed` /
`test_geo_resolver_unreachable_fails_closed` go red. Walked 2026-09-12 on this Linux host.
Source: docs/adr/0006-execution-gates.md. CONTEXT.md "execution gate" / "geo / ip". Issue #11.
Territory: src/haru_pack/launcher/execgate.nim, src/haru_pack/launcher/cryptbox.nim, src/haru_pack/crypto.py, src/haru_pack/build/, src/haru_pack/cli/, tests/test_geo_gate.py

### INV-GEO-01
Status: active
Statement: The geo/ip gate is decided by the online resolver consensus against the encrypted
allow-policy, and haru-pack reads NO environment variable to decide it — no haru-pack knob or env
can satisfy or bypass it. The retired `HARUPACK_GEO` bypass (a user-settable var that used to pass
the geo check outright) is removed; `cryptbox.checkPolicy` reads no env for location, a pre-Phase-4
array-form geo policy (which depended on that bypass) is refused rather than silently ignored, and
a declared-but-unparseable allow-list fails closed. Allow-rules are `field=value` assertions
against the resolver JSON — AND within a rule, OR across rules — so the same mechanism gates geo
(`country_code=US`) and ip (`ip=1.2.3.4`).
Actors: a licensed user outside the allowed region who sets `HARUPACK_GEO` (or any other var
haru-pack might read) to an allowed value to run anyway — exactly the bypass that made the old geo
check theatre. This invariant closes THAT bypass; it does not (cannot) close the transport itself —
see the Limit.
Assets: the property that the location decision is not local state that haru-pack itself trusts;
setting an env var that haru-pack reads cannot turn a denied location into an allowed one.
Red-path: Re-add `if getEnv("HARUPACK_GEO").len > 0: return` to `cryptbox.checkPolicy` before the
gate, rebuild, and run an encrypted binary whose resolver denies (FR) with `HARUPACK_GEO=US` in
the environment: the app RUNS and `test_env_cannot_bypass_the_geo_gate` goes red. Walked
2026-09-12 on this Linux host (observed the app run under the reintroduced bypass).
Note: HONEST LIMIT (load-bearing — do not read the Statement wider than this). The gate is an
HTTP(S) call made ON THE END USER'S OWN MACHINE, and a user with local privilege controls the trust
that call depends on: DNS/`/etc/hosts`, the proxy, and the CA store — so they can MITM the resolver
and forge `country_code=US`. The exact knob is platform-specific (do not overclaim the env-var
route cross-platform): on Linux, puppy uses libcurl, which honors `SSL_CERT_FILE`/`SSL_CERT_DIR` and
`http(s)_proxy`; on Windows (WinHTTP) and macOS (AppKit/Keychain) those env vars are IGNORED, but a
local admin owns the OS trust store and proxy config just the same, so the MITM caveat holds on all
three — only the mechanism differs. N-endpoint consensus does NOT help, because one
on-path position intercepts every endpoint identically (and the shipped default K=1 trusts a single
response). So this gate is REAL against a casual user and honest network faults (fail-closed
offline), but it is ADVISORY against a determined local adversary; consensus defends only against a
minority of compromised/lying EXTERNAL resolvers. The durable control against a hostile HOST is not
client-side geo — it is not shipping to them. Documented in docs/adr/0006 §"Honest limits".
Source: docs/adr/0006-execution-gates.md §3. CONTEXT.md "geo / ip (execution gates)". Issue #11 —
the security gap this phase was asked to close.
Territory: src/haru_pack/launcher/cryptbox.nim, src/haru_pack/launcher/execgate.nim, src/haru_pack/crypto.py, src/haru_pack/build/, src/haru_pack/cli/, tests/test_geo_gate.py

---

## STAGING-3 — ephemeral is safe on a small machine and controllable at runtime

Phase 3 of the staging rework (docs/adr/0007-ephemeral-safe.md) makes `--ephemeral` safe to
default and honest on the target. A 512 MB CI runner or a small VPS cannot hold a staged
interpreter + payload in a tmpfs, so the launcher now SIZES the RAM-backed choice before it
commits to it and falls back to the persistent cache rather than filling RAM and dying
mid-extract. `--ephemeral` also implies `--reap` ("not permanent" cleans up), and the target
gets the last word through a fifth canary knob, `EPHEMERAL`. The knob is ADDITIVE: its
`[canary]` key is emitted only when non-default, so the pinned v1 stub-config corpus is
byte-identical and neither the footer version nor `stub_config_version` moves — the launcher and
its stub-config are always emitted by the same build, so a version-skew read never happens.

### INV-EPHEMERAL-01
Status: active
Statement: When ephemeral staging is in effect and the target does not force it
(`<canary>_EPHEMERAL` unset), the launcher stages to the RAM-backed root ONLY when the payload
provably fits — `stage.ramWouldFit` requires the `/dev/shm` tmpfs free bytes, `/proc/meminfo`
MemAvailable, AND (when a finite cgroup memory limit exists) the cgroup budget to each be at least
`unpacked_bytes × 1.2` — and otherwise falls back to the persistent cache with an honest stderr
note. `unpacked_bytes` is the EXPANDED staged-tree size: the build sums expanded sizes (reading each
`.xz` member's `.xz.size` sidecar, not its compressed size), bakes it into the cleartext stub-config
only alongside `ram_only`, and records it in the receipt. An unknown size (`unpacked_bytes`
absent/0), an unmeasurable host, or an over-large size whose ×1.2 would overflow int64 (guarded by
a pre-multiply DIVISION test, so `-d:release` cannot turn it into a crash) all resolve to "does not
fit". This removes the PREDICTABLE OOM — a tree with no room in the knowable memory budget — it is a
size check, not a reservation, and does not promise "never OOM" against a race or a budget the
launcher cannot read (docs/adr/0007 §5).
Actors: not an attacker — a packager who ships `--ephemeral` and a target (a 512 MB CI runner, a
small VPS) that cannot fit the staged tree in RAM. The failure this prevents is an out-of-memory
or ENOSPC death on the target after the build reported success.
Assets: the property that `--ephemeral` degrades to disk instead of failing when RAM is short;
and the honesty of the sizing (fail-safe on anything it cannot measure, never an optimistic
gamble).
Red-path: (1) In `stage.ramWouldFit` add `return true` before the checks (or make
`main.autoEphemeralRoot` return `ramBackedRoot()` unconditionally), rebuild, run a binary whose
stub sets `ram_only = true` and `unpacked_bytes` far larger than the host's RAM:
`test_ephemeral_oversized_payload_falls_back_to_disk` (asserts staging is NOT under `/dev/shm`)
goes red. (2) C1: make `build._staged_tree_bytes` sum `p.stat().st_size` for every file (the
compressed size) instead of the `.xz.size` expanded value; `test_staged_tree_bytes_counts_uv_expansion`
(baked size must reflect the expansion, not the ~14 MB compressed uv) goes red. (3) W2: replace the
division overflow guard with the `need = x + x div 5; if need < x` form and rebuild;
`test_overflow_unpacked_bytes_fails_safe` (an int64-range `unpacked_bytes` must fall back to disk,
not crash) goes red. All walked 2026-09-12 on this Linux host.
Source: docs/adr/0007-ephemeral-safe.md §detection. Asked for by Eli: "a machine with only 512mb
ram might not be able to extract and run the program it packs … need a way to detect the
environment prior to launch." C1/W2/W3 from the Phantom_Phreak adversarial review 2026-09-12.
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim, src/haru_pack/launcher/stubconfig.nim, src/haru_pack/build/, src/haru_pack/bundle.py, tests/test_ephemeral_safe.py

### INV-EPHEMERAL-02
Status: active
Statement: `--ephemeral` bakes BOTH `ram_only = true` and `reap = true`; `--no-reap` opts out of
only the implied reap; `--reap` together with `--no-reap` is refused; and the build receipt's
`staging.reap` reports the EFFECTIVE value, so the receipt never claims a cleanup the binary will
not perform (INV-BUILD-01). Because the coupling runs before the `overwrite requires reap` check,
`--ephemeral --overwrite` is accepted without a separate `--reap`.
Actors: not an attacker — a packager who reasons "ephemeral means not permanent" and expects the
staged tree gone after the app exits, and one running a restart-heavy service who needs `--no-reap`
to reuse the RAM stage across restarts.
Assets: agreement between the flag's meaning, the baked behaviour, and the receipt; and the
escape hatch that keeps the reuse case possible.
Red-path: In `build.build` remove `if ram_only and not no_reap and not reap: reap = True`;
`test_ephemeral_implies_reap` (build `ram_only` → receipt `staging.reap` True) goes red. Remove
`if no_reap and reap: raise` and `test_reap_and_no_reap_conflict` goes red. Walked 2026-09-12.
Source: docs/adr/0007-ephemeral-safe.md §coupling. Asked for by Eli: "ephemeral should imply
reap. maybe fold in reap to ephemeral."
Territory: src/haru_pack/build/, src/haru_pack/cli/, tests/test_ephemeral_safe.py

### INV-EPHEMERAL-03
Status: active
Statement: The launcher reads the runtime staging toggle from `<canary.ephemeral>_EPHEMERAL`
(default `HARU_EPHEMERAL`) and nothing else, at a precedence above the baked choice but below an
explicit `BASE_PATH` path. It is 2-STATE: `1` forces the RAM-backed root AND skips the fit-check
(target-autonomy enable — RAM even on a binary NOT built `--ephemeral`); any other value, INCLUDING
`0`, is treated as unset/auto. There is deliberately NO force-DISK value — a target must not be able
to downgrade an `--encrypt --ephemeral` payload onto disk via an env var. The `EPHEMERAL` knob is the
fifth of the closed canary catalogue and is ADDITIVE: its `[canary]` key defaults to `HARU` when
absent and is emitted only when non-default, so a four-key v1 stub-config parses and runs unchanged.
Actors: not an attacker — an operator on a big box enabling RAM on a binary the packager did not
build ephemeral; and the SECURITY property that no env value (a stale one, a wrong-canary one, or a
literal `0`) can push an encrypted ephemeral payload onto disk.
Assets: correct, canary-guarded resolution of the runtime enable; the no-downgrade property; and
back-compatible parsing of every stub-config the previous format could produce.
Red-path: In `main.forceRamRequested` `return false` unconditionally (ignore the env), rebuild, run
a NON-ephemeral binary with `HARU_EPHEMERAL=1`: staging stays on disk and
`test_env_1_forces_ram_on_nonephemeral_binary` goes red. Separately, make `forceRamRequested` also
accept `"0"` (return the value == "0" or "1") and `test_env_0_is_ignored_not_a_downgrade` (a fitting
ephemeral binary must stay in RAM under `EPHEMERAL=0`, never be forced to disk) goes red. Separately,
in `stubconfig.parseStubConfig` drop the `if k == kEphemeral: continue` and a four-key v1 stub-config
fails to parse — `test_v1_four_key_stub_still_parses` goes red. Walked 2026-09-12.
Source: docs/adr/0007-ephemeral-safe.md §override. Asked for by Eli: "allow overriding with an
env var at the haru stub layer", chosen as a new canary knob.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/launcher/stubconfig.nim, src/haru_pack/build/, tests/test_ephemeral_safe.py

---

## TOOL — the kitchen sink is the default, and all of it is declinable

### INV-TOOL-01
Status: active
Statement: `haru-pack bootstrap` installs every optional build capability this host knows how
to install — every cross toolchain with a known package, plus wine — and every one of them
can be declined individually or all at once, in one sudo prompt, with the package command
shown before it runs.
Actors: the developer setting haru-pack up for the first time, and the one who deliberately
does not want ARM cross-compilers or a wine install on their machine.
Assets: `docs/PRINCIPLES.md`'s second user, from both directions. Discovering a missing
cross-compiler three commands into a release is the failure the default prevents; being made
to install several hundred megabytes of wine to build for your own laptop is the failure the
flags prevent. A default that cannot be declined is not a default, it is a requirement.
Red-path: Make `toolchain.select_capabilities()` return `()` when called with no arguments —
`test_the_default_is_everything` goes red and the kitchen sink silently becomes opt-in.
Remove the unknown-name reporting and `test_an_unknown_name_is_reported_rather_than_ignored`
goes red, at which point `--without wein` installs wine and says nothing.
Note: The precedence is deliberately boring, because guessing wrong installs the wrong
hundreds of megabytes: `--minimal` wins and selects nothing; naming any `--target`/`--with`
makes the selection EXACT; otherwise it is everything minus `--without`.
Note: Capabilities are derived from `Target.cross_cc()`, not a second hand-kept list, so a
new target with a known package becomes selectable for free and cannot drift from what
`build` actually needs. The host C compiler and Nim are deliberately NOT capabilities — a
haru-pack that cannot build for its own machine is not a working install, so offering to
decline them would be a lie.
Note: `bootstrap --list` reports weight as a PACKAGE COUNT resolved with `apt-get -s`, not a
size. The first version read `apt-cache show`'s `Installed-Size`, which is the metapackage
alone, and reported `wine` as "194 kB" when wine's real cost is its dependency closure — a
number that makes the kitchen sink look free is worse than no number. When there is no apt
to ask, the column is blank rather than guessed.
Note: `doctor` separates targets from tools, because wine is not something you build *for*
and the flag to add it differs (`--with` vs `--target`).
Source: Asked for 2026-09-11 — "be mindful that I do want the default to be the 'kitchen
sink' model, but I want people to be able to selectively choose what they get". The
per-target mechanism already existed via `--target`; what changed is that the default is now
everything and the parts are nameable.
Territory: src/haru_pack/toolchain.py, src/haru_pack/cli/, tests/test_toolchain_select.py

### INV-TOOL-02
Status: active
Statement: The launcher's C compiler is `zig` by default — one digest-pinned download into
haru-pack's own directory, needing no sudo and no package manager — and `--cc system` (or
`HARUPACK_CC`) selects the system cross toolchains instead. A zig with no pin for this build
host is refused, not downloaded.
Actors: someone who just ran `uv tool install haru-pack` and wants a binary, on a machine
where they may not have sudo at all.
Assets: whether the tool works without a system-administration step. Before this, building
for everything meant four system packages (`build-essential`, `mingw-w64`,
`gcc-aarch64-linux-gnu`, `gcc-arm-linux-gnueabihf`) and a sudo prompt; zig covers every
target haru-pack builds for from a single artifact. It is the same shape the project already
uses for Nim (choosenim, own directory) and `uv` (downloaded, digest-pinned), so it makes
the toolchain story consistent rather than adding a new kind of thing.
Red-path: Change `build.resolve_cc`'s default from `"zig"` to `"system"` and
`test_zig_is_the_default_compiler` goes red. Remove the pin lookup from
`toolchain.install_zig` and `test_an_unpinned_zig_is_refused` goes red — at which point
haru-pack downloads and then EXECUTES an unverified compiler, which is exactly what
`INV-SUPPLY-01` exists to forbid.
Note: Verified end to end with the PINNED zig 0.16.0 (not the maintainer's dev build) on
2026-09-11: the launcher builds for linux-x86_64, windows-x86_64, linux-aarch64 and
linux-armv7, and a SHA-256 known-answer test built through haru-pack's own shim passes on
real arm64 hardware and under wine, with digests byte-identical to a GCC build. That check
matters because the launcher's whole stage-verification story is SHA-256, so "it compiled"
would not have been evidence.
Note: A macOS target falls back to `system` automatically and says so, because zig's bundled
macOS headers lack `fstore_t`, which Nim's posix module needs. Refusing outright would be
worse: the operator asked for a Mac build, not a lecture about compilers.
Note: The shim is generated, not checked in, because Nim wants ONE executable for
`--<cpu>.<os>.gcc.exe` — and note those per-target keys, not the generic `--gcc.exe`, which
Nim ignores for a cross build. The shim also translates `nimcrypto`'s
`-march=armv8-a+crypto`, which zig's clang rejects as a CPU name. Measured consequence:
SHA-256 stays correct but the NEON path is not enabled, so ARM hashing falls back to the
reference implementation. A speed regression, not a correctness one; recorded in
docs/ZIG_TOOLCHAIN.md.
Note: The build receipt records which provider compiled the launcher, so an artifact can be
traced to its compiler. zig is clang-based, so binaries are NOT byte-identical to GCC-built
ones.
Source: Asked for 2026-09-11. The maintainer's reasoning overrode mine: I had suggested
system-GCC-by-default to avoid changing existing setups, which is inertia rather than a
benefit, against a real ergonomic win of one less post-install step and no sudo.
Territory: src/haru_pack/toolchain.py, src/haru_pack/build/, src/haru_pack/targets.py,
src/haru_pack/pins.toml, tests/test_zig_provider.py

### INV-TOOL-03
Status: active
Statement: Installing Nim is ONE code path with two host-selected implementations, chosen by
`choosenim_asset()`, not by a flag: where choosenim publishes a binary it is used (digest-pinned);
where it does not — notably linux aarch64, a Raspberry Pi you build ON — `install_nim` BUILDS Nim
from source with haru-pack's own managed `zig cc` (a `cc`/`gcc` shim that execs the managed zig,
so no host gcc, no apt, no sudo). It never dead-ends on "unsupported host" for a host haru-pack can
actually build for. The source build is pinned to the `v<NIM_VERSION>` git tag (Nim itself is not
haru-digest-pinned on either path — see the toolchain module docstring).
Actors: someone who ran `uv tool install haru-pack` on an arm64 board (a Pi) and wants to build
there. Before this they hit a wall — choosenim has no arm64 binary — and had to install Nim by
hand; now the tool provisions itself.
Assets: whether an arm64 Linux box is a first-class BUILD host with nothing to set up. zig already
covers every C-compiler need without sudo (INV-TOOL-02); this extends the same one-artifact,
no-sudo story to the Nim compiler itself, so the Pi needs neither a system gcc nor a hand-built Nim.
Red-path: Restore the `raise ToolchainError(... build on a supported host ...)` in the `if not
asset` branch of `install_nim` and `test_no_choosenim_binary_builds_nim_from_source` goes red —
install_nim raises instead of building, and the Pi has no way to get Nim. Separately, make
`_host_zig_cc_shim` exec a bare `cc` instead of the managed zig and
`test_source_build_shim_runs_the_managed_zig` goes red (the build would need a system compiler).
Note: Verified end to end on an arm64 Pi 2026-09-14 — `install_nim`/`build_nim_from_source` cloned
Nim v2.2.6 and built csources + `koch boot` + `koch tools` entirely through the managed zig cc,
producing a working `nim`. (First proven by hand the same day: 6321 zig-cc invocations, zero system
gcc.)
Source: Asked for 2026-09-14 — make zig the way to compile Nim on a Pi, one code path, automatic
where choosenim has no binary. docs/ZIG_TOOLCHAIN.md.
Territory: src/haru_pack/toolchain.py, src/haru_pack/nim_source.py, tests/test_zig_provider.py

## TRUST — the project being packaged is an input, not an author

Every other section here treats the operator's project as trusted and asks what happens to
the artifact. This one asks the opposite question: **what can a source tree do to the
machine that packages it, and to the binary that comes out?**

The distinction is not theoretical. `haru-pack build .` is run against repositories cloned
from the internet, against branches that arrive in CI, and against applications an agent
wrote that nobody read line by line. In each of those the build host executes code the
operator did not write, and the artifact is signed with the operator's identity.

Mined from the `trojan` busybody persona, 2026-09-11. **All seven are `proposed`** — they
are written down because six of them were demonstrated on the first real run, not because
anything defends them yet. See `docs/BUSYBODY.md` for the run, and `THREAT_MODEL.md` for
the actor these entries were derived from.

### INV-TRUST-01
Status: proposed
Statement: Every command supplied by the packed project — each `[[bundle]]` step's argv —
is printed to the build log before it is executed, so the operator sees what is about to run
on their machine while there is still time to stop it.
Actors: the author of a repository the operator cloned and packed; a contributor whose pull
request added a `haru_pack.toml`; the operator, who typed `haru-pack build .` and expected a
packaging tool rather than a script runner.
Assets: the build host, its PATH, its credentials, and every artifact built on it
afterwards — including ones signed with the vendor's key.
Red-path: `build/thick.py` runs `for step in steps: run_bundle_step(...)` with no log line. Add
the print, then delete it again: a claiming test asserts the argv appears in the build's
stdout, and goes red the moment the line is removed.
Source: busybody `trojan` persona, case `a_bundle_step_runs_unannounced_on_the_build_host`,
2026-09-11. The capability is documented in `docs/CONFIG.md`; that it is reachable from a
file inside the packed tree, silently, is not.
Note: The invariant deliberately asks for **visibility**, not refusal. Bundle steps are a
feature and the operator's own project needs them. What is missing is the sentence that lets
an operator distinguish their step from someone else's.

### INV-TRUST-02
Status: proposed
Statement: `haru-pack build` does not execute code supplied by the packed project during
dependency staging, or — if it must — says so before it does, and the docs state plainly
that packing an untrusted tree is running that tree.
Actors: the author of any repository with a `pyproject.toml`; the maintainer of any sdist
in its dependency list.
Assets: the build host and its toolchain — `INV-SUPPLY-01` through `-11` protect everything
haru-pack *downloads*, and none of them cover the thing the operator handed it.
Red-path: The case plants a project whose `[build-system]` names an in-tree backend via
`backend-path`. At `--thick`, `bundle.warm_cache_and_lock` runs `uv sync --project`, which
imports and calls that backend. A claiming test asserts the marker the backend would write
does not appear; it goes red as soon as project installation is re-enabled unsandboxed.
Source: busybody `trojan` persona, case `a_build_backend_owns_the_build_host`, 2026-09-11.
This is the standard sdist supply-chain vector, pointed at a host that believes it is only
copying files. There is no `haru_pack.toml` in the hostile project at all, so no amount of
auditing haru-pack's own config format would see it.

### INV-TRUST-03
Status: proposed
Statement: A `[[post_install]]` step is named in the build log at **every** tier that ships
it, in a sentence that says it will run on the customer's machine.
Actors: the operator who signs the binary; every customer who runs it.
Assets: the vendor's code-signing identity, and the customer's machine — this is
`THREAT_MODEL.md`'s worst case expressed as a configuration key.
Red-path: `build/assemble.py` warns only on the `thick` path (`if tier == "thick" and
manifest.get("post_install")`). Move the warning outside that condition; a claiming test
builds at `default` and asserts the argv is in stdout, and goes red when the condition is
put back.
Source: busybody `trojan` persona, case `a_post_install_step_ships_code_to_the_customer`,
2026-09-11.
Note: **Measured, and better than assumed.** At the `default` tier the build named the step
and the case reported `SANCTIONED`, not `SMUGGLED` — the capability, exercised visibly. The
entry stays `proposed` for two reasons: nothing asserts the behaviour, so it can regress
silently; and `thin` has not been measured. A narrower entry than the one first drafted,
because the run said so.

### INV-TRUST-04
Status: proposed
Statement: No file from the packed project can occupy a payload path the launcher treats as
control data — `manifest.toml`, `vendor/`, or any other path read to decide what to execute.
Actors: the author of a packed repository.
Assets: the launcher's own instructions. A project that can write `manifest.toml` is not
being packaged by haru-pack; it is configuring it.
Red-path: `validate_manifest` rejects an `app_subdir` containing `..`, an absolute path or a
drive letter, and accepts `"."` — which resolves the application tree onto the payload root.
Reject a subdir that resolves to the root; a claiming test builds with `app_subdir = "."`
and a project-supplied `vendor/uv`, and asserts the payload member is haru-pack's.
Source: busybody `trojan` persona, case `the_project_supplies_the_payloads_control_files`,
2026-09-11. **Demonstrated**: the project's own `vendor/uv` was the one in the payload.
Note: A sibling of the `wedge` persona's first finding. That one found `..`; the validator
was then written against the string `..` rather than against the property "stays strictly
below the payload root", so the next spelling walked straight through it.

### INV-TRUST-05
Status: proposed
Statement: The index a payload's wheels are downloaded from is the one the **operator**
configured. A file inside the packed project cannot change it.
Actors: the author of a packed repository; anyone who can land a `uv.toml` or a
`[tool.uv]` table in a branch that CI packs.
Assets: every dependency inside the signed artifact. `INV-SUPPLY-08` hash-checks wheels
against `uv.lock`; a lock file resolved from an attacker's index is internally consistent
and entirely wrong.
Red-path: pass the operator's resolved index configuration explicitly on every `uv`
invocation (`--index-url` / `--no-config`). A claiming test plants `[tool.uv] index-url` in
the packed project pointing at a discard port and asserts the build still resolves; it goes
red when the explicit flags are removed.
Source: busybody `trojan` persona, case
`the_project_chooses_where_its_dependencies_come_from`, 2026-09-11.
Note: **The redirect is not confirmed.** `uv sync` exited 2 with the planted `index-url` in
place, which is consistent with uv honouring it and failing to reach the discard port — and
also consistent with several other failures. `bundle.warm_cache_and_lock` raises
`CalledProcessError` with uv's stderr captured and discarded, so the build log cannot tell
the difference. The case reports what it can prove (`CRASHED`: the build unwound with no
diagnostic) and the index question stays open until uv's output is surfaced. Recorded rather
than assumed, because assuming is how this entry would become a claim with nothing behind it.

### INV-TRUST-06
Status: proposed
Statement: A path that leaves the source tree is not dereferenced into the payload. A
symlink pointing outside the project is refused, skipped, or stored as a link — never
followed and copied as content.
Actors: the author of a packed repository; a contributor who added one file to it.
Assets: everything `INV-PAYLOAD-01` protects — the operator's keys, `.env`, cloud
credentials — published inside a binary that is distributed and often signed.
Red-path: `build/tree.py` calls `shutil.copytree(source, app, ignore=_IGNORE)`, whose default
`symlinks=False` dereferences, and whose `ignore` callable is given the **name of the entry
being copied**, never the target of a link. A claiming test plants `assets/logo.png` as a
symlink to an out-of-tree key file and asserts the key's bytes are absent from every payload
member; it goes red the moment the copy follows links again.
Source: busybody `trojan` persona, case
`a_symlink_walks_a_private_key_into_the_payload`, 2026-09-11. **Demonstrated**: three
credential files outside the project reached the payload as `app/assets/logo.png`,
`app/assets/theme.css` and `app/README.md`.
Note: `INV-PAYLOAD-01` is satisfied throughout. Its Statement is about files *matching a
credential pattern*, and the link names do not match one. That is a narrow invariant doing
exactly what it says, which is why this entry exists beside it rather than as an amendment
to it.
Note: **Not addressed by the `INV-BASE-01` symlink fixes** (`0d804ed`, `ffa2dbc`, both on
main). Those resolve symlinks in the launcher's *staging-root* refusal — run time, on the
customer's machine, against whoever sets `HARU_BASE_PATH`. This entry is build time, on the
operator's machine, against whoever wrote the packed tree. Re-run 2026-09-11 against main
with both fixes in place: all nine `trojan` findings unchanged, and `build/tree.py` still calls
`shutil.copytree(source, app, ignore=_IGNORE)` untouched.

### INV-TRUST-07
Status: proposed
Statement: A source tree the payload copy cannot handle produces a haru-pack diagnostic
naming the offending path, not a language-level traceback.
Actors: anyone who packs a repository containing a broken symlink, a symlink loop, a fifo or
a device node — malice optional, and mostly absent.
Assets: the operator's ability to act on the failure, and the build host's disk.
Red-path: wrap the payload copy and convert `shutil.Error`/`OSError` into a `BuildError` that
names the path. A claiming test packs a tree with a dangling symlink and asserts the output
contains no traceback frame; it goes red when the handler is removed.
Source: busybody `trojan` persona, cases `a_broken_symlink_stops_the_build`,
`a_symlink_loop_makes_the_payload_infinite` and
`a_character_device_feeds_the_payload_forever`, 2026-09-11. **Demonstrated**: all three
print a rich-rendered `shutil.py` traceback with absolute build-host paths. The device-node
case additionally reads `/dev/zero` into the payload until a resource limit stops it; only
busybody imposed that limit, not haru-pack.

---

## EMIT — the reproduction kit rebuilds what haru shipped, or it is a lie

`--emit-nim` / `--emit-c` hand the operator the stub source (as Nim, or as the Nim C backend's
own C output) plus this build's payload and config, so they can inspect, modify, and recompile
it themselves — the packed binary is still produced either way. A kit is only worth shipping
if it actually reproduces the binary: a plausible-looking `compile.sh` that does not rebuild
the stub, or an assembler that emits different bytes, is the same over-claim `INV-BUILD-01`
forbids — one layer out. Both kits share ONE `assemble.py` / `kit.json` pair
(`emit._write_kit_common`, `emit._ASSEMBLE_PY`) — the reassembly logic lives in exactly one
place, so the two flags cannot silently diverge on what "reassemble" means.

### INV-EMIT-01
Status: active
Statement: A `--emit-nim` kit faithfully reproduces the build it came from, to the extent a
recompile allows. The stub source in the kit is byte-identical to `launcher_src_dir()`; the
emitted `assemble.py` reproduces `overlay.attach`'s footer, offsets and digests for the same
stub (appended and remote-fetch); the `nim c` flag set the kit's `compile.sh` uses is the same
`build.compile_launcher` uses (`emit.nim_target_flags`, one source), so the recipe cannot
drift; and a real recompile of the emitted stub with the emitted `compile.sh` yields a WORKING
binary — its overlay verifies and its payload and stub-config bytes are the exact bytes this
build shipped. Byte-for-byte identity of the launcher is NOT claimed: a Nim/C recompile is not
reproducible in general.
Actors: a packager who wants to audit or modify the stub and still ship a genuine equivalent;
anyone who later trusts a binary compiled from an emitted kit.
Assets: the meaning of the kit. If the emitted parts do not reconstitute a working equivalent
of the shipped binary, "here is what I built" is a lie, and every modification made against the
kit diverges from what runs on a customer's machine.
Red-path: (a) make `emit.emit_nim_kit` copy a stale or partial Nim tree (skip `xz/`, mutate a
file) and `test_kit_source_is_byte_identical_to_what_haru_compiles` goes red; (b) change
`assemble.py`'s footer packing (wrong struct order, drop the remote branch, re-OR the flags)
and `test_assemble_reproduces_overlay_attach` goes red; (c) add a `nim c` flag directly in
`build.compile_launcher` instead of `emit.nim_target_flags` and
`test_nim_target_flags_are_the_same_object_compile_launcher_uses` goes red; (d) break the
emitted `compile.sh` (wrong flag, bad path) and `test_a_real_recompile_yields_a_working_
equivalent` goes red. All walked 2026-09-12; (c) demonstrated by injecting `--opt:size` into
`compile_launcher` and observing the lockstep test fail.
Source: 2026-09-12, from the `--emit-nim` design (and adversarial review the same day, which
BLOCKED an earlier version whose only "recompile" test re-appended bytes it had just carved
back out of the shipped binary). The stub is a single generic binary whose per-build config is
DATA (payload + stub-config), not compiled-in branches, so a faithful kit is source + those
blobs + a reassembler; the risk the whole time was a kit that looks right and rebuilds
something subtly different.
Note: The kit exposes exactly what the shipped binary already exposes — an unencrypted
`payload.bin` is the same recoverable source the binary carries, and an encrypted one stays
encrypted. For a remote-fetch build the appended binary carries no payload, so the exposure is
the binary plus its hosted payload sidecar, which is what a remote build already ships (the
shared `assemble.py` writes that same `<out>.haru-payload` sidecar for a remote kit — see
INV-EMIT-02, which pins it). The build secret/key is never written to the kit (INV-SECRET-02).
Note: The kit is refused rather than written when the destination is unsafe — a symlinked
target dir or `stub/`, or a non-empty `stub/` that is not a prior haru kit — matching the
INV-BASE-01 posture. A kit failure is a warning, never a build failure: the binary is already
written before the kit is attempted.
Territory: src/haru_pack/emit/, src/haru_pack/build/, src/haru_pack/cli/,
tests/test_emit_nim.py

### INV-EMIT-02
Status: active
Statement: The `--emit-c` kit is faithful. Its `compile.sh` invokes the zig compiler
haru-pack itself uses (the emitted `./zig-cc` shim), never a fabricated or hand-written
command, and preserves Nim's per-file compile flags; its `assemble.py` — the SAME static,
stdlib-only reassembler `--emit-nim` ships (INV-EMIT-01) — reproduces `overlay.attach`'s bytes
exactly, appended and remote-fetch alike, and writes the `<out>.haru-payload` sidecar for a
remote build. So the emitted C compiles with zig alone — no Nim — and reassembles a binary
whose payload and stub-config verify.
Actors: not an attacker — an operator who wants to read the stub, patch it, and recompile,
or an auditor reproducing a shipped artifact from its parts.
Assets: the meaning of the feature. A kit that does not rebuild the stub, or rebuilds it and
then assembles the wrong bytes, is worse than no kit: it looks like a faithful reproduction
and is not, and the operator finds out only when the artifact behaves differently.
Red-path: all four halves are red-able WITHOUT a toolchain, so the invariant is defended on a
bare CI box. (1) Compiler token — make `emit._rewrite_compile` emit a literal `gcc` (or any
token that is not the passed shim); `test_transform_uses_the_zig_shim_and_keeps_per_file_flags`
goes red. (2) Vendoring/self-containment — drop the `nimbase.h` (or an xz-header) copy in
`emit_c_sources`, or let an absolute `-I` survive; `test_emit_c_sources_vendors_headers_without_toolchain`
goes red (it runs against a fixture launcher.json, no Nim/zig needed). (3) Overlay fidelity —
corrupt `assemble.py`'s footer packing (wrong offset/flags/layout); the
`test_assemble_reproduces_overlay_*` tests go red. (4) Injection safety — every per-build value
`assemble.py` needs, including a hostile `--out` name, is DATA in `kit.json` (`json.dumps` in,
`json.loads` out), never spliced into `assemble.py`'s own source text — there is no format
placeholder for a hostile string to reach into. `test_assemble_py_is_not_injectable_via_out_name`
and `test_finish_kit_survives_braces_in_out_name` pin this. The nim+zig-gated
`test_emitted_c_compiles_with_zig_and_reassembles` adds the end-to-end proof where the
toolchain is present.
Source: Added 2026-09-12 with `--emit-c`, hardened after an adversarial review, then unified
with `--emit-nim`'s reassembler when #16 and #17 merged: both had independently built a
payload/stub-config/footer reassembler, so `emit._write_kit_common` / `emit._ASSEMBLE_PY` is
now the one implementation both kits call, replacing `--emit-c`'s original per-build
`str.format()`-templated `assemble.py`. Verified during development: the Nim C backend assigns
per-file flags (`-mssse3`/`-mavx2` for nimcrypto's SHA-2 paths) that a blanket `zig cc *.c`
drops — proving the recipe must come from Nim's own build manifest, not a hand-written command
— and the mangled `@…`-prefixed C filenames are read as response files unless `./`-prefixed.
The original adversarial review also caught a command-injection sink (a hostile `--out` name
interpolated raw into a per-build `assemble.py`); moving the value into `kit.json` removes the
injection surface entirely rather than merely escaping it.
Note: The emitted kit is NOT fully self-contained — it needs a `zig` on `PATH` (or `HARU_ZIG`).
The shim is relocatable (`${HARU_ZIG:-zig}`, written by `toolchain.zig_cc_shim` — the same
helper `--emit-nim`'s kit uses), so no build-host absolute path is baked in. The `--emit-c`
directory is refused up front if it is a symlink or a non-empty directory, and a kit failure is
a WARNING that never reports an already-written binary as failed.
Territory: src/haru_pack/emit/, src/haru_pack/build/, src/haru_pack/cli/,
tests/test_emit_c.py

---

## MODULARITY — no module becomes the place everything goes

A "god module" is not merely a long file. It is a long file that everything must be routed
through: the one simultaneously widest and heaviest thing in the tree, which no change can
go around and no reader can hold in their head. haru-pack grew four of them before anyone
counted — `build.py` at 735 statements importing 16 of the package's 22 modules,
`tools/busybody.py` at 3393, `shake.py` at 536, `cli.py` at 483 — and the cost lands on the
audience `docs/PRINCIPLES.md` puts first: whoever is working on haru-pack.

The three entries below are one claim split by what makes a module unreadable, because the
three have different remedies. Together they are the definition: **a module may be the hub
or it may hold the work, but not both.**

The budgets count STATEMENTS, not physical lines. Blank lines, comments and docstrings are
free, deliberately: this repo's comments are the audit trail for why a refusal exists and
several of them are cited from this file, so a physical-line cap would tax exactly the
thing the repo wants more of, and the cheapest way to pass it would be to delete an
explanation. Write as much prose as the decision deserves.

`tests/` is outside these budgets and the exclusion is reasoned, not squeamish: the
pathology is CENTRALITY, and a test module is a leaf nothing imports. Splitting a long test
file moves lines between files and improves nothing. A test file that ever gets imported by
another stops being a leaf and belongs under the cap.

### INV-MODULARITY-01
Status: active
Statement: No module under `src/haru_pack/` or `tools/` holds more than 300 statement
lines.
Actors: not an attacker — us, six months from now, and every agent asked to change one
thing in a file that does forty.
Assets: the ability to review a change. A diff inside a 1177-line module is read against a
context nobody has loaded, so the reviewer checks the lines that changed and not what they
changed *about*. Three of the four god modules this invariant was written against had
already grown a second responsibility nobody had named.
Red-path: concatenate any module in `src/haru_pack/build/` with itself. The claiming test
goes red naming that file, its statement count and the budget. Walked 2026-09-13 by writing
the check BEFORE the splits: it named exactly eight files — build, cli, emit, shake,
busybody, busybody_hostile, busybody_traits, exam — which is the same list a reader asked
"which files are too big" produces unprompted.
Source: 2026-09-13. The budget is calibrated against this tree rather than picked from the
air: at 300 it cleared `toolchain.py` (256) and `bundle.py` (251), which are dense but each
do one job, and named every file a reader would point at.
Note: There is no allowlist and adding one would defeat this. An allowlist is how a size
budget becomes a formality — the first exception is always justified, the tenth is never
questioned, and the module it excuses is the one that got too big precisely because nobody
was counting.
Territory: tests/_modularity.py, tests/test_modularity.py, src/haru_pack/, tools/

### INV-MODULARITY-02
Status: active
Statement: No function in those trees has a body of more than 80 statement lines.
Actors: the same reader, one screen further down.
Assets: visible control flow. `build()` was 209 statements and `busybody.main()` was 286;
in both, the sequence of phases a run has — the thing you actually want to know — was
invisible underneath the phases themselves.
Red-path: paste any function body in `src/haru_pack/build/orchestrate.py` into itself. The
claiming test goes red naming the function, its line and its statement count. Walked
2026-09-13: before the splits it named ten functions across six files, including the two
above.
Source: 2026-09-13, with INV-MODULARITY-01. 80 statements is roughly 120 physical lines in
this repo's comment style — about two screens.
Note: The fix is almost never "shorten it". A long build/dispatch function is a sequence of
named steps that were never given names; extracting each one makes the caller the readable
summary of what happens. That is what `orchestrate.build()` and `busybody_cli.main()` are
now.
Territory: tests/_modularity.py, tests/test_modularity.py, src/haru_pack/, tools/

### INV-MODULARITY-03
Status: active
Statement: A module that imports more than 8 first-party modules holds no more than 150
statement lines.
Actors: anyone trying to change one subsystem without reading another.
Assets: the ability to work on a part of haru-pack in isolation. This is the entry that
actually says "no god modules"; the other two are about length. Either half alone is fine
and normal — `cli` must import most of the package to dispatch to it, `shake` is 500 lines
importing almost nothing — and what must not exist is the module that is both.
Red-path: move `orchestrate.build()`'s body into `src/haru_pack/build/__init__.py`, which
already imports most of the package. The claiming test goes red naming the module, its
import list and its statement count. Walked 2026-09-13: before the splits it named `build`
(16 imports, 735 statements) and `cli` (12, 483), and no others — the metric does not fire
on modules that are merely large.
Source: 2026-09-13. Found by asking what distinguishes a god module from a long one, since
a pure line cap would have called `shake.py` and `busybody.py` the same problem as
`build.py` when only the last was a hub.
Note: A hub is allowed and is often right. `build/__init__.py` imports fifteen siblings and
is a facade holding no logic; `cli/__init__.py` imports every command module because that is
what REGISTERS them. Both pass, because both are thin.
Territory: tests/_modularity.py, tests/test_modularity.py, src/haru_pack/, tools/

### INV-MODULARITY-04
Status: active
Statement: No module in busybody's ENGINE imports a module in busybody's CATALOGUE. The
engine is what runs a sweep, classifies an outcome, journals it and reports it; the
catalogue is the declared faults and the fixtures they are thrown at. The dependency runs
one way only — catalogue on engine — and the partition is declared explicitly in
`tests/_modularity.py`, not inferred from filenames.
Actors: not an attacker. Whoever needs the sweep machinery without haru-pack's specific
list of ways to break haru-pack — a second project, or this one after an extraction — and
the ordinary afternoon in which an engine module grows one convenient import and nobody
notices that the seam closed.
Assets: the separation the 2026-09-13 split created. It landed on roughly the seam an
extraction would want, and nothing held it open: `tools/` is a flat directory of siblings on
`sys.path`, there is no package, and no budget can express direction. `busybody_run`
importing `busybody_fixtures` broke no budget — both files are small, neither is central —
and still meant the sweep driver held a hard reference into the catalogue. A size budget
measures how much a module holds; only this one says which way it points.
Red-path: add `import busybody_cases_stage` to `tools/busybody_runner.py` and run
`pytest tests/test_modularity.py`. `test_the_engine_does_not_import_the_catalogue` goes red
naming the pair. Walked 2026-09-13, and walked the other way too: before the registry below
existed the check named `busybody_run -> busybody_fixtures` unprompted, which is the
violation that was actually there.
Source: 2026-09-13, from the alignment pass against lotek's independent busybody. Declaring
it required one real fix: `busybody_run` imported `build_fixture` / `build_top25_fixtures` /
`calibrate` by name. Those are now registered — `busybody_config.FIXTURE_SOURCES` and
`CALIBRATOR`, filled by `busybody_fixtures` at import and read by name from the engine —
which is the same inversion `CASES` has always used.
Note: The fix for a violation is never "move the import inside a function". That hides the
edge from an AST scan without removing it, and the engine stays unextractable. Invert the
dependency instead: the catalogue registers what it offers, the engine looks it up.
Note: The partition must stay TOTAL. `test_every_busybody_module_is_on_one_side_or_the_other`
fails on any `busybody_*.py` in neither set, because a rule that silently stops covering new
modules is worse than no rule — it reads as enforcement while enforcing less every month.
`busybody.py` itself is the single exemption: it is the composition root, whose entire job is
to import the catalogue for its decorators' side effects and hand off to the engine.
Note: This deliberately stops short of making `tools/` a package. The import-direction rule is
the valuable half and it is cheap; packaging is a bigger change and belongs with an extraction
decision that has not been made (docs/BUSYBODY-PROTOCOLS.md is the input to it).
Territory: tests/_modularity.py, tests/test_modularity.py, tools/


## SANDBOX — the harnesses run stranger code in a box, not on the maintainer's workstation

haru-pack's own test harnesses download code written by strangers — chosen by PyPI download
rank, not by audit — and execute it. flex builds a project that depends on each package and
runs the resulting binary; exam goes further and runs the package's **own test suite**. Both
of those sit downstream of `uv sync`, which builds sdists, which executes arbitrary PEP 517
backends.

Until 2026-09-14 all of that ran on the maintainer's workstation, as the maintainer. This
section is the containment, and `docs/adr/0005-sandboxed-flex-and-exam-harnesses.md` is the
design. It is deliberately about **haru-pack's harnesses**, not about `haru-pack build` in an
operator's hands — that is `INV-TRUST-02`, which is still `proposed`.

### INV-SANDBOX-01
Status: active
Statement: `tools/flex-run.py` and `tools/exam.py` contain no path that executes a built
artifact outside the sandbox runner — the `subprocess.run([str(exe)], …)` shape appears only
inside `HostRunner` — and the container argv the runner builds never mounts the docker socket,
mounts this repository read-only or not at all, gives stranger code no writable host path but
the per-package work directory, and never mounts the shared cache into a phase where package
code runs. The host path is opt-in behind an explicit flag: `sandbox.preflight` raises when
docker is unavailable, naming `--no-docker`, rather than returning a host fallback, and
`sandbox.host_warning` names `$HOME`, SSH keys and credentials rather than the word "sandbox".
Actors: the maintainer running `tools/flex-run.py` on their own machine; the author of any
package in `flex/packages.toml`, and of every transitive dependency of it; the author of any
sdist whose build backend runs under `uv sync`.
Assets: the maintainer's workstation — `$HOME`, SSH keys, cloud credentials, browser
profiles — and this repository's working tree, which is where the signing story starts. Also
the meaning of a flex result: one package poisoning the next package's environment makes the
whole matrix unreadable.
Red-path: Three, each walked 2026-09-14. (1) Mount the docker socket, or drop `:ro` from the
repository mount — `test_the_docker_socket_is_never_mounted` /
`test_the_repository_is_mounted_read_only_or_not_at_all` /
`test_the_only_writable_host_path_is_the_per_package_work_directory` go red. (2) Mount the
shared cache into the run phase at all — `test_the_shared_cache_is_never_mounted_while_stranger_code_runs`
goes red. (3) Move `subprocess.run([str(exe)], ...)` out of `HostRunner` and back into
`run_one`, where it would run whichever runner was selected —
`test_no_harness_executes_a_built_binary_except_through_the_sandbox` names the offending
scope. That last check has its own guard-of-guards,
`test_the_bypass_check_would_actually_catch_a_bypass`, because its first version was a regex
that flagged the legitimate host path and would have been "fixed" by loosening it into
something that matched nothing.
Source: 2026-09-14, issue #30. Not from a discovered compromise — from noticing that the
harness's entire job is to download and run strangers' code, and that nothing was standing
between that and the maintainer's `$HOME`. The threat is ordinary: a compromised release of
any top-25 package, or of anything one of them depends on.
Note: The **build** phase needs the uv cache read-write, and that cache is shared across
packages so a 25-package run does not fetch a toolchain 25 times. A malicious sdist build
backend can therefore write into a cache a later package's BUILD reads. That is a real
residual risk, stated rather than papered over; it is confined to a docker volume and never
touches the host filesystem. The **run** phase does not share it: it gets an anonymous volume
that docker creates empty and `--rm` destroys, so package code never sees the shared cache in
either direction.
Note: The first implementation gave the run phase the shared volume mounted `:ro`, which is
unimplementable — a thick binary stages into `$XDG_CACHE_HOME` before it can execute, and the
first real end-to-end run died with `OSError: Read-only file system`. There is now no
read-only cache mode at all and a test asserts its absence, because "mount the shared cache
read-only" reads as the cautious choice and would be reached for again.
Note: **What is checked here is the argv and the absence of a second execution path. The
CALL SITES are not covered.** Each claiming test reads a function's own output — `docker_argv`'s
argv, `host_warning`'s banner, `preflight`'s AST — or the AST shape of a direct execution.
Nothing asserts that the harness calls `preflight` before it picks a runner, that the banner is
actually printed before the first build rather than after it, or that `DockerRunner` is what
gets selected by default. The earlier Statement said the harnesses "execute third-party package
code only inside a container" and that the warning prints "before anything is built or run";
both were ordinary code reading presented as machine-checked fact, and are narrowed above to
what a red path would catch.
Note: `test_the_harness_imports_the_sandbox_at_all` is `assert "sandbox" in path.read_text()`,
which the word in a comment satisfies. Read it as a typo-catcher for the day someone deletes the
import, not as evidence the runner is wired in. It is the weakest claimant this entry has, and
it is listed so nobody counts it twice.
Note: `_direct_artifact_executions` matches one shape — a `subprocess.run` whose first argument
is a one-element list built with `str(...)`. `os.execv`, a shell string, or an argv assembled
into a variable first would all walk past it. The shape covers how the bypass would most
plausibly be reintroduced (by moving the existing line), not every way one could be written.
Note: A container is not a VM. A kernel exploit leaves the box. Rootless docker narrows the
gap and does not close it, which is why `rootless()` warns loudly rather than claiming the
problem is solved — and why `--require-rootless` exists for anyone who wants the stronger
line enforced.
Territory: tools/sandbox.py, docker/, tools/flex-run.py, tools/exam.py, tests/test_sandbox.py

### INV-SANDBOX-02
Status: active
Statement: Asked for a run with no network and a cold cache, `sandbox.docker_argv` produces an
argv that gives the container `--network none` — no interface at all, not a blocked one — and a
fresh anonymous cache volume rather than the warm shared one; asked for a networked run it
produces `--network bridge`, never `--network host`. "The dependencies came out of the payload"
is a claim about the absence of a fetch, so wherever this argv is used for a thick verification
run the fetch is impossible rather than merely discouraged.
Actors: whoever reads `flex/out/results.json` or `top_n_pypi_stats.md` and concludes that the
thick tier carries what it says it carries; the author of any packaged dependency, who is not
obliged to route their network access through uv.
Assets: the evidentiary value of the `offline` column and of the exam page. Both are
published claims about what haru-pack's payloads contain.
Red-path: Change the run phase's `network=False` to `True` for the thick tier, or reuse the
warm named cache instead of a cold anonymous volume. `test_a_thick_verification_run_has_no_network_interface`
and `test_the_offline_check_runs_against_a_cache_that_has_never_been_used` read the argv
`docker_argv` produces and go red. Walked 2026-09-14 by replacing the network expression with
a constant `"bridge"` **in `docker_argv`** — the argv builder, not the call site (next Note).
Source: 2026-09-14, issue #30. `tools/flex-run.py` already documented its own weakness: the
old check forced `UV_OFFLINE` and pointed the proxy variables at a dead port, and said in its
docstring that this "does not stop a package from opening a raw socket of its own". The
container path is what makes that sentence unnecessary. The honesty came first; this
invariant is the fix catching up to it.
Note: **The call site is not covered.** Which runs are the offline ones is decided in
`tools/flex-run.py` at `network=not offline` (:225) and `cache=sandbox.CACHE_COLD` (:230), and
no test reads either line. The claiming tests pass `network=False, cache=sandbox.CACHE_COLD` in
as their own fixture input and assert those values came back out of the argv, so what is proved
is that `docker_argv` is faithful to the mode it is given — not that the harness ever gives it
the offline mode for a thick run. Change `not offline` to `True` in flex-run.py and every test
here stays green while `results.json` keeps printing `carried`. The earlier Statement said "a
thick binary's offline verification run IS executed with no network interface", which is the
half that is not checked. Closing this needs a test that reads the call site — as
`test_no_harness_executes_a_built_binary_except_through_the_sandbox` already does for a
different rule — or an end-to-end run that watches a thick binary fail to reach the network.
Note: This is deliberately NOT "every run has no network". At the `default` and `thin` tiers
the dependency is *supposed* to be fetched on first run, so denying the network there would
fail every package for the wrong reason. `test_the_default_tier_run_keeps_its_network` pins
that distinction so a later "harden everything" pass cannot quietly break the harness.
Note: The host path (`--no-docker`) cannot create a network namespace, so it keeps the old
approximation and every result it produces is marked `carried*` in the summary rather than
`carried`. A weaker check reported in the same column as a stronger one is how evidence gets
overstated.
Territory: tools/sandbox.py, tools/flex-run.py, tools/exam.py, tests/test_sandbox.py

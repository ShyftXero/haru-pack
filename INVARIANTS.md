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

`INV-LAUNCH-03` and `INV-SUPPLY-02` are deliberately `proposed`. The behavior is **not implemented**, or is only
partly implemented and the entry says which part. They are written down so the gap is
legible, not so it looks covered.

**Every `active` entry below was promoted by walking its Red-path** — neutralize the guard,
observe the claiming test go red, restore — on 2026-09-09. Where an adversarial verifier
subsequently proved a claiming test *vacuous* (green with the guard removed), the entry was
not promoted until the test was fixed; two were. Two further entries had their **Statement
narrowed** because verification showed the original wording claimed more than the code does.
Those narrowings are recorded in the entries themselves rather than quietly applied.

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
packaged data file. Checked across all 25 top-PyPI packages, only these two ship a runnable
suite in the wheel; the other 23 would need sdists, which is a second acquisition path for
no extra assurance.
Note: A vacuous pass is prevented twice over. The generated script verifies the test paths
exist and exits 2 with `PAYLOAD INCOMPLETE` if they do not, and pytest itself returns 5
rather than 0 when it collects nothing. The success marker is printed only on rc == 0.
Territory: src/haru_pack/build.py, src/haru_pack/bundle.py, src/haru_pack/discovery.py,
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
Territory: src/haru_pack/targets.py, src/haru_pack/bundle.py, tools/busybody.py,
tests/test_compose.py, tests/test_targets.py

---

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
Territory: src/haru_pack/build.py, src/haru_pack/cli.py, tests/test_tiers_offline.py

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
Territory: tools/busybody_ledger.py, tools/busybody.py, tests/test_busybody_ledger.py

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
Territory: tools/busybody_ledger.py, tools/busybody.py, tests/test_busybody_ledger.py

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
diverged, and then reported the divergence as `CRASHED`, i.e. as a haru-pack bug, because the
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
Territory: tools/busybody.py, tests/test_busybody_ledger.py

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
Red-path: Delete the divergence computation from `analyze_run`, or the FINGERPRINT CENSUS
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
Territory: tools/busybody_analyze.py, tools/busybody.py, tests/test_busybody_ledger.py

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

Note: The divergence report was what made the run readable at all — the same five fixtures
passing every single case is not a pattern any package property produces. The tool found its
own run invalid, which is the point of having it. It should not have needed to.
Note: `df` is not the ceiling. This box reported 31 GiB free on /tmp and refused the next
write at 24 GiB, because the mount carries `usrquota` and a per-user quota is invisible to
`statvfs`. The harness now prints the mount's quota options at the start of a sweep, and
`--work-root` moves scratch elsewhere.
Note: `--scratch-cap-gb` (default 8) aborts on a leak at a number the operator chose rather
than at whatever the filesystem happens to allow.
Territory: tools/busybody.py, tools/busybody_ledger.py, tools/busybody_analyze.py,
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
Territory: tools/busybody.py, tests/test_busybody_ledger.py

---

### INV-CHAOS-07
Status: active
Statement: A declaration that cannot be honoured as written is refused at build time, with a
message naming both sides of the contradiction. haru-pack never resolves a config conflict
silently and hands back an artifact whose damage is discovered on the target.
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
Note: `SILENT-WEDGE` is in `FATAL`. `WARNED` deliberately is not — resolving a conflict and
saying which side lost is the behaviour this invariant asks for, not a defect.
Note: Wedge cases are `per_fixture=False`. They build their own artifact and say nothing
about the packed package, so running them once per fixture would repeat one answer 25 times
and inflate the census that INV-CHAOS-04 exists to keep honest.
Territory: src/haru_pack/build.py, tools/busybody.py, tests/test_config_wedges.py

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
Note: FALLIBILITY. Each trait has a probability of acting, so a persona is a person rather
than a fixture. If greenhorn always fumbles, then "greenhorn fumbled AND auditor left a .env
behind" is the only thing ever tested, and "greenhorn got it right, auditor still left the
.env" — a different code path — never runs. A run's identity is the set that FIRED, not the
set that was selected, and both are journalled.
Note: Fallibility is forced OFF for two passes, and only two. The k=1 pass IS the attribution
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
Territory: tools/busybody_compose.py, tools/busybody_traits.py, tools/busybody.py,
tests/test_compose.py

---

## FLEX — the harness that decides what haru-pack is tested against

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
Territory: src/haru_pack/build.py, src/haru_pack/cli.py

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
Territory: src/haru_pack/cli.py, src/haru_pack/build.py

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
Territory: src/haru_pack/discovery.py, src/haru_pack/cli.py, tests/test_entrypoints.py

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
Territory: src/haru_pack/entrypoints.py, src/haru_pack/build.py, tests/test_entrypoints.py

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
Territory: src/haru_pack/cli.py, tests/test_targets.py

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
Territory: src/haru_pack/build.py, tests/test_entrypoints.py

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
Territory: src/haru_pack/build.py

### INV-PAYLOAD-02
Status: active
Statement: `overlay.verify()` reports `sha_ok=False` for any modification to the attached
payload; the build-time integrity check is not decorative.
Actors: anyone tampering with a distributed binary; the operator running `haru-pack verify`.
Assets: the only integrity signal haru-pack offers on unsigned (ELF) output.
Red-path: Make `verify()` return `sha_ok=True` unconditionally, or compare the digest against
itself. The claiming test mutates one payload byte and goes red.
Source: Adversarial review 2026-09-09, findings C2/C3.
Note: This invariant covers the **build-time** check only. The **runtime** launcher does not
perform it at all — see `INV-LAUNCH-01`, which is `proposed` for exactly that reason. Do not
read this entry as evidence that shipped binaries self-verify. They do not.
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
Territory: src/haru_pack/bundle.py, src/haru_pack/build.py

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
Territory: src/haru_pack/launcher/main.nim, tools/busybody.py, tests/test_launcher_isolation.py

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

## SUPPLY — what we execute that we did not write

### INV-SUPPLY-01
Status: active
Statement: Every artifact haru-pack downloads **directly** — the Nim toolchain, the `uv`
release asset, and the python-build-standalone interpreter — is verified against a digest
pinned in this repository before it is extracted or executed, and an artifact with no pin is
refused rather than fetched.
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
`INV-SUPPLY-06`. The narrow wording is kept anyway: it says what THIS entry proves, and the
distinction between a direct download and a delegated one is exactly what went unnoticed the
first time.
Note: No digest is pinned for Nim `linux_arm64` — upstream publishes no such artifact for 2.2.6.
The table entry is deliberately absent and `install_nim` raises `UnpinnedArtifact` on that
platform. No value was invented to make the check pass.
Territory: src/haru_pack/archives.py, src/haru_pack/bootstrap.py, src/haru_pack/bundle.py

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
Territory: src/haru_pack/bootstrap.py, src/haru_pack/build.py

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
Note: **Read this narrowly. Nothing populates `uv_sha256` yet.** Writing it at build time is
Python-side work in `build.py`/`tiers.py`, outside the launcher. Until that lands the field is
absent in every real payload, the pin check is vacuous in production, and the launcher prints a
warning on stderr that the uv it is about to execute is unverified. The mechanism is proven; the
deployment is not.
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

### INV-SUPPLY-03
Status: active
Statement: No archive is extracted with a call that permits writes outside the destination
directory; every `tarfile` extraction passes `filter="data"`.
Actors: whoever controls an archive we fetched over unverified TLS (see INV-SUPPLY-01).
Assets: the build host's filesystem.
Red-path: Drop the `filter=` argument from any `extractall` call in `bootstrap.py` or
`bundle.py`. The claiming test scans the source for unfiltered `extractall` and goes red.
Source: Adversarial review 2026-09-09, finding W8. `requires-python = ">=3.9"`, where the
tarfile default is the pre-CVE-2007-4559 behavior.
Territory: src/haru_pack/bootstrap.py, src/haru_pack/bundle.py

---

## STAGE — the tree on the target that we actually execute

### INV-STAGE-01
Status: active
Statement: The launcher never executes a staged tree it cannot account for: a stage directory
is reused only if it is a real directory owned by the calling user, not group- or
world-writable, carrying a `.ready` token that names this exact payload digest, and every file
recorded in `.stage-files` still hashes to its recorded sha256.
Actors: any process on the target that can write into the user's cache directory before the
launcher does — a same-user attacker, a shared or misconfigured cache, resident malware.
Assets: code execution under the vendor's identity and (on Windows) behind their signature. The
launcher runs `pre_install`/`post_install` argv and the entrypoint straight out of this tree.
Red-path: Restore the trust-on-first-use short circuit — `if dirExists(final): return final` in
`stage.stageZip`. The claiming tests pre-create a hostile stage directory (with and without the
old one-byte `.ready`), modify and delete a staged file, chmod the tree 0777, and replace it
with a symlink. Walked 2026-09-09: 6 red, 49 passed.
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
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim

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

### INV-SECRET-01
Status: active
Statement: A license secret typed at the runtime prompt is never echoed to the terminal.
Actors: shoulder-surfers; anyone reading a recorded terminal session or CI log.
Assets: the license secret, which is the entire trust anchor — there is no PKI behind it.
Red-path: Once implemented — run an encrypted build interactively and observe no echo.
Source: Adversarial review 2026-09-09, finding W11. `cryptbox.resolveSecret` uses
`stdin.readLine()`; `std/terminal` is already imported but `readPasswordFromStdin` is not used.
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
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/crypto.py, tools/busybody.py,
tests/test_reverse_engineer.py

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
Territory: src/haru_pack/obfuscate.py, src/haru_pack/build.py, src/haru_pack/cli.py,
tests/test_obfuscate.py

### INV-SECRET-02
Status: active
Statement: A build secret is never written into a manifest, a build receipt, or any other
artifact the build produces.
Actors: anyone who reads the project repo or the shipped binary.
Assets: the license secret.
Red-path: Add the secret to the `info` dict returned by `build.build`, or to the manifest
written by `assemble_payload`. The claiming test builds with a known secret and asserts it
appears in no produced file or return value; it goes red.
Source: Adversarial review 2026-09-09. `docs/CONFIG.md` states the secret is never stored in
config — asserted in prose only.
Note: This does **not** cover `--secret <literal>`, which puts key material in shell history
and `ps` output. That is a documented sharp edge, not a defended one.
Territory: src/haru_pack/build.py, src/haru_pack/cli.py

---

## DOC — claims are traceable to evidence

### INV-DOC-01
Status: active
Statement: Every `INV-` identifier cited anywhere in `src/`, `docs/`, `tests/` or a root
markdown file resolves to a real entry in this file.
Actors: a future maintainer or AI agent citing an invariant that was never declared.
Assets: the credibility of the whole scheme. lotek added this scanner after discovering
`INV-MODULARITY-01` cited across seven source files and five plans docs without ever
being declared.
Red-path: Write `INV-NONSENSE-99` in any tracked file. The claiming test goes red.
Source: Adopted from lotek `tests/test_invariants_enforced.py`.
Territory: INVARIANTS.md, tests/test_invariants_enforced.py

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
Territory: src/haru_pack/shake.py, src/haru_pack/build.py, tests/test_shake.py

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
Territory: src/haru_pack/shake.py, tests/test_shake.py

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
Territory: src/haru_pack/shake.py, tests/test_shake.py

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
`uv.xz.sha256` with it. Authenticity of the payload as a whole is `INV-LAUNCH-01`, which is
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
Territory: src/haru_pack/entrypoints.py, src/haru_pack/build.py, tests/test_entrypoints.py

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
Territory: src/haru_pack/discovery.py, src/haru_pack/entrypoints.py, src/haru_pack/cli.py,
tests/test_entrypoints.py

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
directly in `cli.py`. Ten parametrizations of
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
Territory: src/haru_pack/ui.py, src/haru_pack/cli.py, tests/test_ui.py

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
Territory: pyproject.toml, src/haru_pack/cli.py, tests/test_packaging.py

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
Territory: src/haru_pack/build.py, src/haru_pack/cli.py, src/haru_pack/overlay.py

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
Territory: src/haru_pack/build.py, src/haru_pack/cli.py

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
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/stubconfig.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build.py, src/haru_pack/cli.py

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
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build.py

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
Territory: src/haru_pack/launcher/stage.nim, src/haru_pack/launcher/main.nim, src/haru_pack/build.py

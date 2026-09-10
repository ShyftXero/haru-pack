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
Territory: src/haru_pack/build.py, src/haru_pack/bundle.py, src/haru_pack/discovery.py,
tests/test_tiers_offline.py, tools/flex-run.py

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

### INV-TIER-03
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
src/haru_pack/build.py, src/haru_pack/launcher/manifest.nim, src/haru_pack/launcher/main.nim

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

### INV-SUPPLY-11
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
Statement: When `uv` is bundled it is stored XZ-compressed in the payload and expanded
during staging to a binary **byte-identical to the publisher's release**, before the stage
manifest is recorded — so the file the launcher executes is covered by stage verification
exactly as an uncompressed one was.
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
Red-path: three, and each was a real failure caught while building this:
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

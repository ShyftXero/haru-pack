# busybody — chaos testing for haru-pack binaries

```sh
python tools/busybody.py                      # every persona
python tools/busybody.py --persona forger     # one persona
python tools/busybody.py --list               # every case and why it exists
python tools/busybody.py --keep               # leave the wreckage to inspect
```

Output per run: `busybody/out/runs/<run-id>/` containing `report.txt` (written to be read on
its own), `journal.jsonl`, `results.json`, and preserved artifacts for any finding.

## Run control — one sweep at a time (INV-CHAOS-13)

Each worker stages a real interpreter (tens of MB at the thick tier), so two sweeps on one box
thrash disk and memory — a thick top-50 sweep was killed by the OOM guard every time a second
sweep ran alongside it. So a sweep registers itself under `/tmp/harupack-busybody/` and **refuses
to start while another is genuinely live** (its pid is alive and its heartbeat is fresh):

```sh
python tools/busybody.py --fixtures top25 --tier thick     # exits 3 if another sweep is live
HARUPACK_BUSYBODY_FORCE=1 python tools/busybody.py ...      # run anyway (you accept the contention)
```

A registry left by a **dead or wedged** run (pid gone, or heartbeat older than 15 min) is reaped,
not trusted, so a crashed run never wedges the harness. The registry is project-tagged — it never
touches another project's BusyBody. Pids are checked with `os.kill(pid, 0)`, so the guard cannot
match its own process.

## Selection is fail-loud (INV-CHAOS-12)

An unknown `--persona`/`--case` name is a setup failure (exit 2) that names the typo, rather than a
silent drop: `--persona forger,typo` refuses instead of quietly running only forger and printing a
clean verdict. A run that silently skipped what you asked for reads exactly like a healthy one.

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

`--analyze` is also a **gate**, not just a reader (INV-CHAOS-14): it exits **2** on a setup
failure or an environment abort (zero findings there is an absence of data, not a pass), **1**
when the run produced findings or did not finish, and **0** only for a completed run with nothing
to report. So a CI step can trust `busybody.py --analyze <run>` and never read a false pass.

**`--calibrate`** measures the resource band between fixtures and prints a threshold to
paste, along with the per-fixture requirements to paste beside it. It stages each fixture
unrestricted first, so what gets measured is the *application's* requirement rather than
staging's — the latter being identical for every package and not the question. It also says
plainly that the number is machine-specific and does not transfer.

Neither needs a model. Neither needs you to open the raw records.

## wedge — the persona that attacks the config

The other thirteen personas abuse a binary that was already built. `wedge` attacks the
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

### Seven more, further up the ladder — 2026-09-11

The eight cases above feed contradictions through `haru_pack.toml`. Seven more attack the
rest of the ladder — `discovery < [tool.haru-pack] in pyproject.toml < haru_pack.toml < CLI
flags` — which is where an operator actually edits, because `pyproject.toml` is the file
that already declares everything else about their project.

Each reads its answer out of `manifest.toml` at the payload zip root rather than out of the
build log. The log names no directive at all, so "it built and said nothing" cannot be told
apart from "it built and honoured me" without opening the artifact. Those are the same bytes
the launcher parses at stage time.

Three of the seven are calibration — they pass, and if they ever stop passing nothing else
here can be trusted: an underscored `[tool.haru_pack]` table is refused (`INV-BUILD-07`
guards it); the sidecar outranks the pyproject table when both name an entrypoint; a `-e`
flag outranks a declaration; and a `[[bundle]]` list in both homes is replaced rather than
concatenated, which is what the per-top-level-key merge documents.

**The other three reported `SILENT-WEDGE` on their first run, and all three are real.**

1. **An unknown directive key is silently ignored.** `entry-point` for `entrypoint`, inside
   a correctly-named table: exit 0, and the artifact records discovery's answer. Nothing in
   the ladder validates keys — `_declarations` merges the table wholesale and `_resolve`
   reads the names it knows with `decl.get()`. `INV-BUILD-07`'s Statement covers the
   underscored *table* and says nothing about an unknown *key* inside a correct one, while
   its Assets paragraph — "a config table read by nobody is worse than a missing one,
   because the operator believes it took effect" — is the oracle for both.
2. **Containment is defeated by spelling.** `../shared/cli.py` is refused by `_PLAIN_NAME`,
   but `sub/../../shared/cli.py` builds cleanly and the manifest records it.
   `verify_script_file` resolves `Path(project) / spec` and asks `is_file()`, so an interior
   `..` landing on a real file outside the tree passes. This is the same class as
   `app_subdir_escapes_the_payload` in a different field — that one is guarded by
   `validate_manifest`, and this one is not.
3. **Contradictory tier flags resolve silently.** `--thin --thick` yields thick because
   `cli._run_build` has two unguarded ifs and thick is second. Nothing states that thick
   beats thin, so last-write-wins here is an accident of ordering rather than a documented
   precedence — unlike the config ladder.

Each case's `remedy` names the fix. None of them is fixed yet: these are findings the
harness is reporting, not work it has done.

### Wedge cases run once

They are registered `per_fixture=False`. They build their own artifact and say nothing about
the packed package, so running them once per fixture would repeat one answer 25 times and
inflate exactly the census INV-CHAOS-04 exists to keep honest.

## reverse_engineer — the honest limit of packing a secret

A developer has to embed an API key and ship a binary. haru-pack can encrypt the payload, so
the key is not sitting in the distributed exe as a string. But the launcher **stages the
payload to disk in plaintext** so the interpreter can run it — that is not a bug, it is how
running Python works — and it stages to the regenerable cache (`~/.cache/haru-pack/...`), not
a temp dir, so the plaintext persists. Any user who can *run* the binary can read its source
out of their own cache.

The `reverse_engineer` persona plants a known secret and **proves each edge of that
boundary** rather than asserting it (INV-SECRET-02):

| what it checks | outcome |
|---|---|
| encrypted binary, at rest | secret must be **absent** from the exe bytes — `RAN`, else `LEAKED` |
| plain build, after running | secret **is** recoverable from the stage — `EXPOSED` (documented reality, kept visible) |
| `--obfuscate` vs plain | literal present in the plain stage, **gone** from the obfuscated stage — `RAN`, else `LEAKED` |
| staged tree permissions | must be owner-only, not group/other-readable — `RAN`, else `LEAKED` |

Two new outcomes, both closed-vocabulary:

- **`EXPOSED`** — a secret recovered from a surface haru-pack *documents* as recoverable
  (the staged plaintext on the running user's disk). **Not a defect.** The persona keeps it
  visible so that if it ever stops being true, the staging model changed and the docs must
  too.
- **`LEAKED`** — a secret recovered from a surface that is *supposed* to protect it: the
  encrypted binary at rest, or a tree readable by other users. **A defect** (`critical`).

The obfuscation case proves the value **both ways**: the plain control stage must contain the
literal, or the case is vacuous — a no-op obfuscator cannot pass by making both sides clean.

**The honest bottom line, stated everywhere it matters:** a secret that must never be
recovered must never be shipped in an artifact the client holds. The right architecture for a
must-not-leak key is a server the client authenticates to. Packing is not that, and haru-pack
does not pretend it is.

## --obfuscate — raise the cost, honestly

```sh
haru-pack build app.py --thick --obfuscate pyarmor
haru-pack build app.py --thick --obfuscate pyarmor --obfuscate-args "--mix-str"
```

Obfuscation is a modular engine (`ObfuscationEngine` + a registry) with **pyarmor** as the
default. It runs as `uv run --python <target-version> --with pyarmor -- pyarmor gen`, which
means two things:

- haru-pack needs **no pyarmor dependency of its own** — uv provisions it on demand, and uv
  is already the whole staging mechanism.
- pyarmor runs under the **exact interpreter version the binary will stage**, which it must:
  pyarmor's runtime `.so` references version-private CPython symbols, so a payload obfuscated
  for 3.12 fails to import under 3.11 (`_PyThreadState_GetCurrent`) or 3.13/3.14
  (`_PyErr_GetTopmostException`). This is *not* a lock to 3.12 — pyarmor obfuscates for
  **standard CPython 3.7–3.14** (verified 3.11/3.12/3.13/3.14 each build and run when
  targeted); 3.13 is just haru-pack's default `--python`. The one hard ceiling is
  **free-threaded** (GIL-less) CPython, which pyarmor does not support; a bare `3.14` can
  resolve to a `+freethreaded` build via uv, so haru-pack catches that and names the fix.
  Measured 2026-09-10.

Because of that binding, **obfuscation wants `--thick`**: only thick bundles the exact
interpreter and guarantees the match. A non-thick obfuscated build warns loudly that the
target must have exactly that Python or the binary will fail to start.

Three hard rules (INV-OBF-01):

1. **Apply or fail.** `--obfuscate pyarmor` with no uv, or a pyarmor that errors, **fails the
   build**. It never silently ships plaintext when you asked for obfuscation — that false
   confidence is the exact thing being guarded against.
2. **`none` is the honest default.** Not obfuscated is a named engine, recorded in the
   manifest, never implied by omission.
3. **Independent of encryption.** Obfuscate a plaintext-payload binary, encrypt an
   unobfuscated one, do both, or neither. They protect different things and are wired on
   separate axes.

pyarmor's unlicensed/trial runtime is size-limited and not for redistribution; haru-pack
detects the trial banner and says so in the build log. It will not decide licensing for you,
but it will not let you ship a trial artifact believing it is licensed.

## trojan — the project you were asked to package

Every other persona attacks a finished binary or the environment around a build. This one
attacks from inside: it **is** the source tree handed to `haru-pack build`.

`THREAT_MODEL.md` did not have that actor. Its table listed the operator as "not hostile —
busy", which is true, and then assumed the operator wrote what they were packing, which is
not. `haru-pack build` gets run against repositories cloned from the internet, against
branches that arrive in CI, and against applications an agent wrote that nobody read line by
line. In all three the build host executes code the operator did not write, and the artifact
is signed with the operator's identity. The threat model's own worst case says haru-pack's
failure mode is "our tool becomes a distribution channel" — this persona is the half of that
sentence nothing was testing.

```sh
python tools/busybody.py --persona trojan
python tools/busybody.py --case a_symlink_walks_a_private_key_into_the_payload
```

### Hostile, and inert

These cases write attack source. That is a thing to be careful with, so the rules are
absolute and stated in `tools/busybody_hostile.py` at the top of the file:

- **Capability is proven by touching a marker, never by causing harm.** A program that could
  run `rm -rf` writes one empty file and exits. The finding is identical; the blast radius
  is not.
- **`TMPDIR` is redirected into the case's work directory**, which is where every marker
  lands — the realistic drop location, and one the hostile program finds through
  `tempfile.gettempdir()` rather than through cooperation from the harness.
- **No network.** The index-redirection case points at `127.0.0.1:9`, the discard port.
- **Every planted string carries the `busybody_trojan_` prefix**, so one that ever escapes
  is greppable on sight and obviously synthetic.
- **The credentials are strings**, in a directory under `work/`, not keys.

`$HOME` is deliberately **not** redirected, and that is a scar. The first shakedown run did
redirect it, and all four cases came back `REFUSED` — by choosenim, which could not find
`~/.choosenim` and failed long before the payload copy. Four clean passes, zero attacks
reached. A sandbox that hides the compiler tests nothing.

### Four outcomes, two of them fatal

| outcome | meaning |
|---|---|
| `CONTAINED` | the hostile construct was neutralised and no marker fired. Good. |
| `REFUSED` | the build stopped and **named** the construct. Best case. |
| `SANCTIONED` | project-controlled code ran through a path haru-pack *documents* as executing project-controlled code, **and the build log named it first**. Not a defect. |
| `ESCAPED` | project-controlled code ran on the build host through a path documented as executing nothing, or without the log naming it. **A finding.** |
| `SMUGGLED` | bytes never in the project reached the distributed artifact. **A finding.** |

`ESCAPED` and `SMUGGLED` are in `FATAL`. `SANCTIONED` exists for the same reason `EXPOSED`
does in `reverse_engineer`: a documented capability, honestly reported, is not a bug, and
collapsing it into `ESCAPED` would train the reader to skip the one outcome that separates
"we chose this" from "nobody knew".

The verdict on a bundle step therefore turns on **naming**, not on execution. Bundle steps
are a feature and the operator's own project needs them. What was missing is the sentence
that lets an operator tell their step from someone else's.

### What it found on its first run — 2026-09-11

```
10 cases, 1 behaved as expected, 9 findings — all critical.
  SMUGGLED x3   bytes that were never in the project reached the artifact
  CRASHED  x4   the build unwound at the operator instead of refusing
  ESCAPED  x2   the packed project executed code on the build host
  SANCTIONED    post_install, named in the log before it shipped
```

Three were confirmed by hand before the harness existed.

**A symlink walks a private key into the payload** — `SMUGGLED`, and the cleanest of the
set. `_IGNORE` is `shutil.ignore_patterns`, which matches *the name of the entry being
copied*, never the target of a link; `copytree`'s default `symlinks=False` dereferences.
So `assets/logo.png` pointing at an out-of-tree `.ssh/id_rsa` is copied as a regular file
containing the key. Three planted credentials arrived as `app/assets/logo.png`,
`app/assets/theme.css` and `app/README.md`.

`INV-PAYLOAD-01` is satisfied throughout — no file *matching a credential pattern* was
copied — and defeated in substance. That is what a narrow invariant looks like from the
outside, and why `INV-TRUST-06` is a new entry beside it rather than an amendment to it.

**Three tree shapes make the build unwind instead of refusing** — `CRASHED`. A dangling
symlink, a symlink loop and a symlink to `/dev/zero` each produce a rich-rendered `shutil.py`
traceback with absolute build-host paths. The device-node case reads `/dev/zero` into the
payload until a resource limit stops it — a limit **busybody** imposed, not haru-pack.
`INV-TRUST-07`.

**A filename escapes on the target, not here** — `SMUGGLED`. `..\..\..\Startup\evil.bat`
is one legal POSIX filename and three levels of escape on Windows, and
`build_payload_zip` stores names with `as_posix()`. Two such members went into the payload.
`THREAT_MODEL` B7 records target-side extraction as `[R]`, relayed and unverified; this is
the half of B7 that can be checked on this machine, because a payload can be read without
being run.

**The project supplies the payload's control files** — `SMUGGLED`. `validate_manifest`
rejects an `app_subdir` containing `..`, an absolute path or a drive letter — the `wedge`
persona's first finding — and `.` is none of those. It resolves the application tree onto
the payload root, and the project's own `vendor/uv` was the one in the payload.

The pattern there is worth naming: the validator was written against **the string `..`**
rather than against the property *stays strictly below the payload root*, so the next
spelling walked through it. `INV-TRUST-04`.

**The packed project executes code on the build host, twice over** — `ESCAPED`, and the two
that matter most.

A `[[bundle]]` step's argv comes from a `haru_pack.toml` inside the packed tree and runs at
build time with the operator's environment. `build/thick.py` runs the steps in a bare
`for step in steps: run_bundle_step(...)` with nothing printed first, so cloning a repository
and running `haru-pack build .` is code execution by that repository's author, silently.
`INV-TRUST-01`. The fix asked for is **visibility, not refusal**: bundle steps are a feature
and the operator's own project needs them. What is missing is the line that lets an operator
tell their step from someone else's.

The second has **no `haru_pack.toml` in it at all**. A `pyproject.toml` whose `[build-system]`
names an in-tree backend via `backend-path` is enough: at `--thick`,
`bundle.warm_cache_and_lock` runs `uv sync --project`, which installs the project, which
imports and calls that backend. Auditing haru-pack's own config format would never have seen
it. `INV-TRUST-02`.

**And one case could not finish its sentence.** `the_project_chooses_where_its_dependencies_
come_from` plants `[tool.uv] index-url` pointing at the discard port. `uv sync` exits 2 — but
haru-pack raises `CalledProcessError` with uv's stderr captured and thrown away, so the log
cannot say *whether uv honoured the project's index or failed for some other reason*. The
case reports what it can prove: the build unwound with a traceback and no diagnostic. The
redirect itself stays unconfirmed until uv's output is surfaced, and that is recorded in
`INV-TRUST-05` rather than guessed at.

### Two bugs in busybody, found the same way as always

Both were caught by the results looking too clean, which is the only reliable tell.

**A single-script project never reaches `copytree`.** `discover()` returns
`source=<the .py file>` for a directory holding one script, and `build/tree.py` then takes the
`source.is_file()` branch — a `copy2` of that one file. The rest of the tree is never
copied, so a symlink, a device node and a backslash filename are all invisible. Six cases
reported `CONTAINED` for attacks that had not been attempted. Every plant is a project now,
with a `pyproject.toml` and an executable package, because that is what puts the payload
copy on the path at all.

**Grepping the finished binary does not see the payload.** Payload members are DEFLATE'd, so
a secret inside a packed file is simply not present in the exe's bytes. The symlink case
reported `CONTAINED` for a key a hand test had already proved was in the payload.

That one is not only this persona's problem: `auditor`'s
`no_planted_secret_survives_into_the_binary` had the same blind spot, and this doc claimed
the raw-bytes grep was "stronger than scanning zip members". It is stronger for a leak via
the manifest, a Nim literal or a warmed uv cache, and blind to a leak through a packed file
— which is the most likely one. Both cases now use one scanner that does both surfaces and
says which one each hit came from.

**And a refusal that unwinds is not a refusal.** `classify()` matches its traceback markers
against raw text, which is right for a packed binary and wrong for `haru-pack build`: the
CLI renders exceptions through rich, which writes the header as bold even under `NO_COLOR`,
so `Traceback (most recent call last)` is never contiguous. Three cases were scored
`REFUSED` while printing forty lines of stdlib frames at the operator. The strip is local to
`trojan` on purpose — changing the shared classifier would silently re-score every other
persona's history, and that is a decision with a before-and-after to measure, not a
drive-by.

### `names`, borrowed whole from `wedge`

Each attack declares substrings a refusal must mention for the case to have reached what it
meant to test. A build that refuses without naming any of them is `REFUSED-UNRELATED` — a
note against busybody, never a pass for haru-pack. The first shakedown produced four, all
choosenim, and without the check they would have read as four clean passes.

**A case must isolate its attack, or it measures whichever guard happens to fire first.**
That sentence has now been paid for twice.

### Re-run against the symlink fixes — 2026-09-11, and nothing moved

Two `INV-BASE-01` commits landed on main between this persona being written and being
re-run: `0d804ed` resolves symlinks in the staging-root refusal, `ffa2dbc` makes that
refusal cross-platform. Both are real fixes to a real bypass. Neither changes a single
outcome here.

```
10 cases, 1 behaved as expected, 9 findings — identical to the first run.
```

They are a **different boundary**, and the distinction is worth holding onto because the
word "symlink" hides it:

| | `INV-BASE-01` | `INV-TRUST-06` |
|---|---|---|
| when | run time, on the customer's machine | build time, on the operator's machine |
| who | whoever sets `HARU_BASE_PATH` | whoever wrote the packed tree |
| what | a staging root that resolves to `/` or `$HOME` | `assets/logo.png` that resolves to `~/.ssh/id_rsa` |
| where | `stage.nim`, `refuseUnsafeRoot` | `build/tree.py`, `shutil.copytree(..., ignore=_IGNORE)` |

Checked rather than assumed: `build/tree.py` on `origin/main` still reads
`shutil.copytree(source, app, ignore=_IGNORE)` with no symlink handling, and
`payload.py` still selects members with `p.is_file()`, which is true for a symlink to a
file. Every branch in the repo was searched for a payload-copy change; there is none.

**"We fixed symlinks" is not a property a codebase has.** It is a property of one call site.

### What to fix first

Ranked by what an operator loses, not by effort:

1. **`INV-TRUST-02`** — a packed project's build backend runs on the build host. Everything
   built on that host afterwards is suspect, including signed artifacts. Either resolve
   wheel-only, sandbox the install, or say plainly in the docs that packing a tree is
   running it.
2. **`INV-TRUST-06`** — a symlink walks credentials out of the operator's machine and into a
   binary they are about to distribute and sign. One decision: refuse, skip, or store as a
   link.
3. **`INV-TRUST-01`** — print every project-supplied argv before executing it. Cheap, and it
   converts a silent capability into a consensual one.
4. **`INV-TRUST-07`** — wrap the payload copy so a hostile tree shape produces a diagnostic
   rather than forty lines of `shutil.py`. Also the fix for the ordinary case: a repository
   with a broken symlink in it.
5. **`INV-TRUST-04`** — validate `app_subdir` against the property, not the spelling.
6. **`INV-TRUST-05`** — surface uv's stderr, then re-run the case that could not finish its
   sentence, and pass the operator's index configuration explicitly.

Nothing above is implemented. The entries are `proposed` because that is what `proposed`
means here.

### What it does not prove

Ten cases are ten ideas someone had on one afternoon. The persona says nothing about the
attacks nobody thought of, and `CONTAINED` means *this attack did not land*, not *the tree
is trusted*. The honest summary of the current state is the one in `THREAT_MODEL.md`: there
is no boundary between the packed project and the build host, and `INV-TRUST-01` through
`-07` are all `proposed` because nothing defends them yet.

## Composition — why the personas stack

A persona that runs alone asks a closed question. *Does staging cope with umask 077?* has the
same answer forever, and answering it is integration testing with a costume on. The open
question is the other one:

> **Which combination of individually-survivable conditions is not survivable?**

A read-only cwd is fine. No `HOME` is fine. `CI=true` with no TTY is fine. One of the ways of
stacking three of those is where the traceback lives, and no amount of running them
separately will find it. That is the difference between this and a test suite.

So hostility is expressed as **traits** — small, orthogonal, declared mutations — and the
runner combines them:

```sh
python tools/busybody.py --list-traits              # the catalogue
python tools/busybody.py --compose 1                # every trait alone: the baseline
python tools/busybody.py --compose 2                # pairs
python tools/busybody.py --compose 3 --compose-runs 300
python tools/busybody.py --compose-only greenhorn_output_over_the_input,foreman_no_home
```

42 traits across 11 personas. 845 conflict-free pairs, over 11,000 triples.

### The pass condition is deliberately weak

| outcome | verdict |
|---|---|
| `RAN` | fine |
| `REFUSED` | fine — a guard fired and said so |
| `APP-CRASHED` | fine — the app declined the box these traits built for it |
| `CRASHED` | **never** — a language-level traceback reached the user |
| `HUNG` | **never** |
| `SILENT` | **never** — exit 0 and the app never ran |

That is the existing `FATAL` set, which is the point: composition needs no new vocabulary,
only a weaker expectation. Nobody has reasoned about combination 7,431 of 11,000, so
asserting *"haru-pack works under any three of these"* would be an overclaim of exactly the
kind `INVARIANTS.md` exists to prevent. **The floor is the claim: it works, or it refuses
intelligibly.**

### Fallibility — the persona is a person, not a fixture

A trait has a *probability* of acting. Some days the new developer reads the flag correctly.

This matters more than it sounds. If `greenhorn` always fumbles, then *"greenhorn fumbled
AND auditor left a `.env` behind"* is the only thing ever tested — and *"greenhorn got it
right, auditor still left the `.env`"* is a **different code path** that never runs at all.

```
run 0   auditor_plants_credentials+foreman_ci_true          (greenhorn got it right today)
run 1   foreman_ci_true                                     (nobody misbehaved but CI)
run 3   greenhorn_output_over_the_input+auditor+foreman_ci   (everything at once)
```

`fires` is set below 1.0 only where real-world presence is genuinely intermittent — a
developer's mistake, a stale cache that may or may not be there. A CI runner's missing TTY is
not a coin flip, so `foreman`'s traits always fire.

**A run's identity is the set that FIRED**, not the set that was selected. Both are
journalled. A run where nothing fired is a *control*, and it is kept rather than resampled —
a control arriving through the same machinery is worth more than one bolted on beside it,
because if the baseline is broken that is where it shows.

Fallibility is forced **off** for exactly two passes: `--compose 1`, which *is* the
attribution baseline (a baseline with holes makes every composed finding unattributable), and
`--compose-only`, where someone asked for a specific stack and a control run would answer a
different question than the one they typed.

### Attribution, and why the baseline comes first

A composed failure is only interesting if the parts are individually fine. `A+B` failing while
`A` and `B` each pass alone is an **interaction** — the finding worth having. `A+B` failing
because `A` was already broken is just `A`. Running `--compose 1` first is what makes that
distinction free rather than another guess.

### Determinism

Selection and firing both come from a recorded seed, and every finding prints the command that
reproduces it:

```
[critical] CRASHED  greenhorn_output_over_the_input+revenant_manifest_from_the_future
    Reproduce with: python tools/busybody.py --compose-only greenhorn_output_over_the_input,revenant_manifest_from_the_future --compose-seed 1757505639
```

Firing is drawn from `sha256(seed:run_index:trait_name)` rather than a sequential RNG.
Per-trait, so adding a trait to the catalogue does not reshuffle every other trait's decisions
in every other run — a recorded seed has to keep meaning what it meant when the finding was
filed. And a digest rather than `random.Random(triple)`, which raises on Python 3.14 and whose
seed-to-stream mapping is an implementation detail either way.

### Conflicts are cancellations, not breakages

A declared conflict means one trait **cancels** the other — a read-only cache and an absent
`HOME` cannot both be the thing under test, and a stack whose members cancel tests *less* than
either member alone while looking like coverage. Pairs that **break** together are not
conflicts. Those are the findings.

## The eleven personas

| persona | attacks | phase |
|---|---|---|
| `greenhorn` | wrong invocation — bad paths, bad flags, output in silly places | build |
| `foreman` | the environment CI actually provides | build + run |
| `crosseyed` | a foreign `--target`; the payload must not carry host objects | build |
| `babel` | filenames legal here and illegal, colliding or unencodable there | build |
| `understudy` | the packaged application misbehaving | build |
| `revenant` | an on-disk stage left by an older, different haru-pack | run |
| `quotamaster` | target storage hostility — noexec, full, read-only, cgroup | run |
| `packrat` | payload extremes — enormous files, fifos, absurd file counts | build |
| `tourist` | the artifact on a platform that is not its own | run |
| `auditor` | credential-shaped files where the payload builder will see them | build |
| `archivist` | a build that must be byte-reproducible | build |

Three of them also own **explicit cases**, because their value is a property of an artifact
rather than a condition to survive — *"these two builds are identical"* and *"no ELF object in
a Windows payload"* are things to check, not things to endure:

- **`archivist`** builds the same input twice and compares payload bytes, naming the first
  differing member and why (`date_time`, `external_attr`, or content).
- **`auditor`** plants every credential shape the ignore list claims to cover and then **greps
  the finished binary** for each planted value. Stronger than scanning zip members, which
  cannot see a leak via the manifest, a Nim literal, or a warmed uv cache.
- **`crosseyed`** reads the payload of a foreign-target build and checks ELF `e_machine` and
  wheel tags. A Windows payload cannot be *run* here, but it can be *read* — which is what
  makes the check possible without a second machine.

### quotamaster needs docker, and says so

Some target hostility cannot be faked in-process. A **noexec mount** is the clearest case:
staging writes an interpreter and then execs it, so a cache on a noexec filesystem fails at
`exec` with `EACCES`. `/tmp` is noexec on any hardened host and CIS benchmarks recommend it —
and `mount(2)` needs privileges this harness should never ask for.

So those four cases run the artifact inside a container where docker chooses the mount options:
`--tmpfs /cache:noexec`, a 24 MB cache filesystem, `--read-only` rootfs, and a 512 MB cgroup
cap. The image is a stock glibc base (`debian:12-slim`), which keeps the case honest about what
the binary actually requires of a host. A missing docker or image is reported as a **skip**,
not a pass.

The cgroup case is worth its own note: a cgroup limit kills on the OOM path rather than failing
an allocation, so the process takes `SIGKILL` with no traceback and no message. That is a
genuinely different failure from the `RLIMIT_AS` case, and `rc 137` with empty output must not
be classified as a silent success.

## Where the ledger lives

```
/home/you/code/haru-pack-busybody-findings.jsonl     <- beside the MAIN checkout
```

Beside the checkout, never inside it — a file in the repo is caught by `git stash`, by
worktree switches and by branch changes, which loses history exactly when you are hopping
branches to investigate. That is lotek's reasoning and it holds here.

"Beside the checkout" has to mean the **main** one. Resolving it relative to `__file__` put
the ledger at `.claude/worktrees/<name>-busybody-findings.jsonl` when run from a worktree —
inside the directory that gets deleted when the worktree is removed, which defeats the whole
point. A week of findings would vanish with whichever branch happened to be last.

`git rev-parse --git-common-dir` is the authoritative answer: it reports the main
repository's `.git` from a linked worktree and its own from a normal checkout, so one call
covers both. The path fallback (`<main>/.claude/worktrees/<name>` to `<main>`) exists only
for a source tree that is not a git checkout, and it matches `.claude/worktrees` as a *pair*
scanned right-to-left — a checkout can itself live under some other `.claude`, and taking
the first match resolves to the wrong tree entirely.

Override with `HARUPACK_BUSYBODY_LEDGER` — a fixed location is right for the default and
wrong as the only option, not least because the tests need somewhere disposable.

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
expects, and five outcomes are findings no matter what any case expected.

| Outcome | Meaning | Verdict |
|---|---|---|
| `RAN` | exit 0, app's marker in stdout | depends on the case |
| `REFUSED` | non-zero, haru-pack diagnostic — a guard fired | usually good |
| `WARNED` | a contradictory config built, and the build said which side lost | acceptable |
| `CRASHED` | a raw language-level traceback reached the user | **always a finding** |
| `HUNG` | no exit within the timeout | **always a finding** |
| `SILENT` | exit 0, but the app never ran | **always a finding, the worst kind** |
| `SILENT-WEDGE` | a contradictory config built quietly and the artifact carries the damage | **always a finding** |
| `STALLED` | several processes alive, none of them progressing | **always a finding** |

`SILENT` is worst because it is the one a human does not notice. A crash gets reported; a
binary that exits 0 having run someone else's code does not. `SILENT-WEDGE` is the same
shape one step earlier, at the build. `STALLED` is the one no process can report about
itself — see below.

The report prints this list from `FATAL` rather than from a literal, because it went stale
once already: `SILENT-WEDGE` was fatal for a day before the legend said so.

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

`twin` races two. This races `--herd-n` of them, default 16, on one cold cache, and adds
the only thing that can see what two cannot: an observer outside every child.

The stage cache is haru-pack's one shared mutable resource — `$XDG_CACHE_HOME/haru-pack`,
keyed by payload digest — and staging takes no lock, so each process extracts into its own
`<key>.tmp-<pid>` and races an atomic move. What N makes reachable and two does not: a
stampede where sixteen processes each extract the same tree independently, a convoy on the
move, and sixteen processes waiting on a claim whose owner died without ever writing
`.ready`.

Cases: sixteen cold starts at once · sixteen where one is killed mid-stage at a **seeded**
moment (butterfingers composed with twin, which no single-persona case does) · sixteen
against a stage whose owner is already dead.

Three cases, **not** three times N. `--triage` ranks fingerprint groups by count, so
sixteen cases failing on one stall would outrank a genuine unique finding sixteen to one.
Each case reduces over its own children and returns exactly one record; which children
were cascades is evidence inside that record, not sixteen more records.

All three are marked `light=True`: their work directory holds one shared stage plus N
transient copies of it, and `preserve()` copies directories whole, so a finding would
otherwise archive hundreds of megabytes of the same bytes.

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

`herd` is the exception among the eight: it is payload-invariant like the rest, but what it
varies is haru-pack's own concurrent state rather than the package, so it discriminates
without needing the sweep at all.

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

A third case runs the same binary twice, once under a real pty and once through a pipe, and
compares what survives. The rich output wrapper renders differently when stdout is not a
terminal (`INV-UI-01`), and the failure worth catching is not "the colours differ" but "the
*message* differs" — a wrapper that eats a diagnostic when piped is a diagnostic nobody in
CI will ever read. Both sides are stripped of escape sequences before comparison, so the
case asserts the text and not the formatting.

### impatient — signals to the *app*

Ctrl-C and SIGTERM after staging, so the signal lands on the application rather than on
staging. `main.nim` installs a custom SIGINT handler specifically so the child owns Ctrl-C;
a comment said so and nothing tested it until now.

### hoarder — resource ceilings

Few file descriptors, a tight address space, a read-only `TMPDIR`. The most
package-dependent of the lot, and the one that required real work to make so.

## The stall — the failure nothing can report about itself

Every other outcome is a statement one process makes about itself by exiting. `HUNG` is
"this process did not exit inside its timeout", which is all a single wait can ever see.

"Everybody is alive, nobody is burning CPU, nothing is being written" is invisible from
inside each of the processes it is happening to. Each one is fine. None of them has an exit
status yet. So `classify()` cannot produce `STALLED` and deliberately does not: if one
process's timeout could declare it, every slow case on a loaded box would declare it too
and the class would mean nothing.

**The watchdog.** A thread in the harness process, sampling about once a second: whether
each child is alive, its CPU time from `/proc/<pid>/stat`, and the total byte count under
the staging area. A stall is declared only when all three hold **continuously** — every
child alive, no child's CPU advanced, the tree did not grow. It is a thread rather than a
subprocess because the parent is sitting in a wait that releases the GIL, it is already
outside every child (the only property that matters), and a subprocess would read the same
`/proc` and then need IPC to hand the verdict back.

It calls `Ctx.beat()` every tick, because `HEARTBEAT_STALE_S` is 120 seconds, these cases
outlive that, and a stale heartbeat is exactly how `reap_orphans` and `prune_runs` decide a
run is dead and delete its work directories.

**Blame, honestly.** `launcher` only on launcher-side evidence — a `.tmp-<pid>` directory
whose byte count is static while its owner is dead. If the sampler itself was late, the
verdict is `unknown` and says so. A watchdog that reports its own scheduling starvation as
a product defect is the `tight_address_space` mistake again, and this one would be worse:
that case merely discriminated nothing, this one would invent a finding.

**The threshold is provisional, and the source says so.** `STALL_QUIET_S = 40` carries its
measurements beside it. Measured 2026-09-11 against a real default-tier fixture, all three
cases, 16-way from a cold cache: longest quiet stretch **0.0s**, over 9 to 13 ticks each.
The thick tier is strictly slower and has **not** been measured, because a thick fixture
cannot be built on that box at all — there is no pinned sha256 for the CPython it wants and
haru-pack correctly refuses to stage an unverified interpreter. So 40 is an order of
magnitude above everything observed rather than a calibrated number, and the TODO beside it
names the measurement that replaces it.

A limit of the method, recorded because it does not go away with a better threshold: an
application that deliberately idles is indistinguishable from a stall by these three
signals. A fixture that only slept produced 6s of continuous quiet on a healthy 4-way herd.
These cases hold for fixtures that stage, print and exit — which is every busybody fixture
— and a packaged app that waits on a network or a prompt does not belong in this persona at
any threshold.

### post_stall — one stall is one finding

Once a stall is declared, every child that resolves afterwards fails too, and it fails *for
the stall* rather than for itself. Those results are tagged `post_stall` with a shared
`stall_id`.

Without that tag the arithmetic goes wrong in a specific way. Sixteen cascading children
share a persona, a case and an outcome, so they normalise to one fingerprint — and
`ledger_rollup` used to rank groups by count alone, which put that sixteen-count group
**above** the single-count record of the fault that caused it. One bug presented as the top
sixteen problems, with its cause ranked seventeenth. It is the same error as reading
"575/575 passed" as 25× the assurance, pointing the other way.

So `post_stall` joins the grouping key, and the ordering key sinks every cascade group below
every fresh one whatever the counts. `--triage` prints them under their own `CASCADES`
heading with the numbering running on, and `--history` counts them in a separate column —
because if only one of those two views were fixed they would disagree sixteen to one about
one stall and neither number could be trusted.

The cascades are **kept**, not dropped. The shape of a cascade — how many processes went
down with one stall, and which — is the primary evidence that there was a stall. Dropping
them at append time would be one line and would throw that away forever; and marking them
`ok=True` would erase them from the report and from the exit code, which hides the cascade
instead of attributing it. It stays out of the *fingerprint* basis for a separate reason: a
cascade of a real fault would fingerprint differently from the same fault seen cleanly, so
that fault's history would split in two, and every fingerprint already on disk would be
orphaned.

## The seed, and announcing a fault before performing it

Faults used to land at fixed moments — mid-stage, after staging. That is one point on a
continuous axis, and a SIGKILL 40 ms after the staging directory appears is a different
fault from one 4 seconds in. `--seed` draws the moment and the victim instead, from a stream
keyed on `(seed, case, fixture, salt)` through sha256 — not the `hash()` builtin, which is
salted per process, so the same seed would draw a different stream every run and the one
thing a seed is for would silently not work. It also has to hold across a process boundary,
because under `--jobs` the case runs in a worker.

`--seed` is separate from `--compose-seed`: that one selects which traits stack, this one
decides when a chosen fault fires.

**The rule that makes it usable: the fault is announced BEFORE it is performed.** Recorded
afterwards, a kill at 0.4s and a kill at 4.0s leave the same case name with different
outcomes and nothing says which moment was chosen — so the harness's own timing jitter
starts reading as a product defect, which is the confusion the `CASE-ERROR` split exists to
prevent.

A case announces through a file in its own work directory, fsynced before the action, rather
than through the journal. Two reasons, and the second is the real one: under `--jobs` the
parent is the only journal writer, which is what keeps the append order deterministic; and a
record that has to survive the fault it announces cannot live in the process the fault
kills. The parent folds those lines into the journal ahead of the result they explain, so
a reader sees the kill at 2.54s and then the outcome it produced. A record the harness
merely *observed* — a stall — goes through the same durable channel under its own record
type, never as a perturbation, so a reader can always tell which entries the harness caused.

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

Two flags worth knowing before you write one. `per_fixture=False` means the case says
nothing about the packed package — it builds its own artifact, or attacks the harness's own
bookkeeping — so it runs once per run instead of once per fixture. `light=True` means
`preserve()` should copy only the top-level files of the work directory, for a case whose
directory holds a stage tree rather than diagnostics.

A case that injects a fault whose *moment* it chose must draw it from `Ctx.rng()` and
announce it with `Ctx.perturb()` **before** acting. A case that merely observes something
uses `Ctx.observe()`; the two are different record types on purpose.


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

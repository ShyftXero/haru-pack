# Changelog

Stuff worth knowing about, newest first. Dates are when it landed on `main`. The precise
version of any security claim lives in `INVARIANTS.md`; this file is the human-readable trail.

## 2026-09-23

### `--writable`: bundled app data files may change on reuse (INV-STAGE-01 relaxation, fail-closed)

By default the launcher re-hashes every staged file on every run and refuses any mismatch, which
is right for code and wrong for a bundled data file the app opens read-write (a seed `app.db` the
app mutates would fail verification on the second run). `--writable <glob>` (repeatable; also
`writable = [...]` in `haru_pack.toml`) DECLARES such files. The build resolves the glob against
the assembled tree to exact stage-relative paths, carries them in the SIGNATURE-COVERED
stub-config, and the launcher records them as `mutable:` lines — checked for presence, regular-file
kind, and non-symlink-ness on reuse, but with their BYTES deliberately not pinned. The tree stays
fully accounted for: a `mutable:` member still counts in the file count and the `.stage-files`
digest the `.ready` token binds, and it may never be a symlink or a `.haru-links` alias target.

The load-bearing safety is a BUILD-TIME backstop that fails the build (never the customer): it
REFUSES to declare writable any importable/executable file — `.py`/`.pyc`/`.so`/`.pth`/… ,
`sitecustomize`/`usercustomize`, the interpreter tree, `uv`, the entrypoint, pre/post-install
targets, or ANY file carrying the POSIX executable bit. A writable code path would be a same-uid
RCE primitive that re-cuts the holes `stage.nim`'s "NOT exempt, deliberately" block documents;
`.pth` is a hard refuse because `site` executes its `import` lines at interpreter startup.

### `--<canary>-reinstall`: a deliberate wipe-and-re-extract (reserved arg, not an env knob)

A verify mismatch now surfaces the SPECIFIC file that changed and points at the remedy instead of
a generic "corrupt cache": *"the bundled file `…` inside the stage changed since it was unpacked …
use a data dir … re-run with `--<canary>-reinstall`."* A mismatch is still FATAL and never
auto-healed (tamper-evidence). The operator-only `--<canary>-reinstall` arg (default
`--haru-reinstall`; prefix tracks the build canary for white-label consistency, and the existing
`--haru-shred` worker arg is canary-fied the same way) WIPES the launcher's OWN computed subtree —
through the same `shredGuard` the reaper uses, never a path from arg/env (INV-REAP-01 /
INV-BASE-01) — and re-extracts, shredding the wipe on an `--overwrite` build. It is consumed before
the packaged app sees its argv. NOTE the `#3`/`#4` conflict: reinstall re-extracts from the
payload and so discards ALL stage state, declared-writable files included — keep writable app
state OUTSIDE the stage (a data dir; docs/SHARP_CORNERS.md section E).

## 2026-09-16

### `--thick` offline was only accidentally offline: the cache is now warmed with the pinned uv

A `--thick` build warms `vendor/cache` so the binary resolves its deps offline. It warmed with
the build host's `uv` on PATH — but the binary RUNS the pinned/bundled uv, and uv keys its cache
buckets by its own schema version (`simple-vNN`, `wheels-vNN`). So a cache warmed by a newer host
uv (e.g. 0.12.12, writing `simple-v24`) is unreadable to the bundled 0.10.4 uv (which reads
`simple-v20`): every wheel is present, but the "offline" run fails to resolve them and reports
"wasn't found in the cache". The thick offline guarantee therefore held only when the build host's
uv happened to equal the pinned uv — it broke on any box with a newer uv (found packing the flex
top-50 on an aarch64 box). `warm_cache_and_lock`/`warm_cache_for_script` now warm with the pinned
uv (`bundle_uv`), so the buckets match what the binary reads at run time on any build host (#53).

Every build stages to a new `<staging-root>/<key>-<payload-sha>` dir, so every rebuild left
another tree behind and nothing removed the old ones (23 MB default tier, 90 MB+ thick, per
version). On every launch the launcher now touches `.lastrun` in its own stage dir, then
deletes stage dirs that are **both** older than `keep_days` **and** outside the `keep_max`
most-recently-used. Defaults `keep_days = 30`, `keep_max = 3`; `keep_days = 0` disables it. Set
them in `haru_pack.toml` — manifest-only, **no env override** (reading a haru-named env input
outside the canary model would violate `INV-CANARY`, and eviction tuning is not worth a
canary-protected knob).

Retention is LRU by last *use*, not creation, so a build still run daily is never collected.
The sweep is scoped to the siblings of the live stage dir — whatever root was staged into — so
an `--ephemeral` / `BASE_PATH` build GCs only its own trees and never reaches the persistent
cache; only dirs carrying a `.ready` token are candidates (the sibling `uv-cache` tree and
half-written `<key>.tmp-<pid>` dirs are skipped); and removal unlinks the `INV-STAGE-04` in-tree
symlink aliases rather than following them. Residual limit, documented in `docs/TIERS.md`:
`.lastrun` is touched at launch, not periodically, so an instance running longer than
`keep_days` can have its tree evicted by a different launch — raise `keep_days` for long-lived
services.

### The supported-Python floor is now 3.12 (was 3.9)

`requires-python` is `>=3.12`. The tooling already depended on stdlib `tomllib` (3.11+) behind
`tomli` shims, and the CI floor leg kept catching 3.9/3.10 breakage that no longer reflects a
version anyone should package *with* — the launcher targets a bundled 3.13, and the flex exam
projects declare `>=3.12`. So: drop the `tomli` fallback dependency, `import tomllib` directly
(`haru_pack.tomlio`, `tools/exam_fetch`), and move the CI matrix's pure-Python floor leg from
3.9 to 3.12 (3.13 stays the toolchain/ceiling leg). Nothing about the packed *output's*
interpreter changes — this is the floor for running haru-pack itself.

### The vendored XZ decoder is now provenance-CHECKED, not just recorded

`src/haru_pack/launcher/xz/PROVENANCE.md` has always said where the ~3 400 lines of vendored C
came from; nothing ever checked that the record was true. `tools/verify-vendored-xz.py` closes
that: it fetches the pinned upstream tag, checks the archive against the recorded SHA-256, and
compares every vendored file byte-for-byte with the upstream file it claims to be — refusing
any vendored `.c`/`.h` with no upstream mapping. `INV-PAYLOAD-05` already compared vendored
files against per-file digests recorded in this same repo; both halves of that check lived
here, so an edited `.c` with its digest updated to match passed cleanly regardless. The
tarball's SHA-256 was the only link to something outside the repo, and it lived nowhere but
prose.

Run: the tarball hashes to the recorded `ee12fa8c…8977d` and all eight files are
byte-identical to upstream `v2024-12-30`, no local modifications. `.github/workflows/vendored-xz.yml`
runs it Mondays, on dispatch, and on any push touching the vendored tree — not in `ci.yml`,
because it needs the network and the gate on every push must not depend on GitHub being up.
The case worth the weekly run is a **moved tag**: `v2024-12-30` resolving to different bytes
than it did when vendored would be a supply-chain event in someone else's repository, invisible
from here any other way.

`PROVENANCE.md` also gains the upstream path for each vendored file and answers the question
every security reader will ask: this is **xz-embedded**, not xz-utils. CVE-2024-3094 was
injected into xz-utils release tarballs via `build-to-host.m4` and was absent from that
project's git tree; xz-embedded is a separate decoder-only codebase with no autotools, no
build scripts and no compressor, and the vendored tag postdates that discovery by nine months.
Shared authorship is why the question comes up — the answer offered is the verification
command, not the name.

### A staged thick tree stops carrying ~90 MB of duplicate interpreter bytes

On POSIX the launcher now stages a `.haru-links` alias (`bin/python`, `libpython…`, the ~1000
terminfo aliases) as a **symlink** to the one stored copy instead of a full copy, so the staged
tree on disk drops the duplicate bytes the shipped binary already stopped carrying (#41). That
stays inside `INV-STAGE-01`: `recordTree` now records each alias as a `symlink:<target>` line and
`verifyTree` re-checks, on every reuse, that it is still a symlink still resolving to that same
in-stage target (a hash-verified regular file) — a link swapped for a file, a file swapped for a
link, or an alias repointed inside the stage or out are all refused, never silently followed. On
Windows the alias stays a copy (symlink creation is privileged). See `INV-STAGE-04`. Closes #42.

### busybody's examiner now sits ANY top-N package's suite, from the sdist (#28)

The `examiner` persona was hardcoded to numpy and certifi — the only two top-25 packages whose
test suite ships in the WHEEL. Every other package's tests ride in the sdist, so the examiner
silently covered 2 of N.

It now sources each package's suite from its SDIST, reusing the flex exam's `tools/exam_fetch`
(`pypi_meta` → `fetch_sdist` → `locate_suite` → `make_project` with `test_deps`) rather than a
forked copy — the same sdist→thick-project→offline-pytest mechanism `tools/exam.py` proves the
flex top-N with. The defaults are now `iniconfig` and `six` (small, fast, real sdist suites);
`sit_exam(pkg, work)` sits any caller-supplied package, and `top_n_packages()` is the whole list.

Kept honest: a package whose sdist carries no test tree yields `NO-SUITE` carrying "no test
suite in sdist" — never a faked pass. Under the sdist mechanism numpy and certifi land there
themselves, because their suites ship only in the wheel; that is the honest face of the
coverage the wheel path hid. Governed by `INV-CHAOS-15` (Red-path walked 2026-09-16).

### `--slim-python`: drop the ~9.5 MB of interpreter furniture a packed app never touches

A `--thick` binary bundles python-build-standalone unmodified, and ~9.5 MB zipped of it is
furniture most packed apps never reach: tcl/tk + tkinter, pip in the interpreter's
site-packages, ensurepip's bundled wheels, `share/man`, the C headers under `include/`,
idlelib, pydoc_data. The new **opt-in** `--thick --slim-python` removes that fixed set.

- **Never the default.** A build without the flag prunes nothing, so the staged interpreter
  stays byte-for-byte the pinned published artifact — which is what makes `INV-SUPPLY-01`'s
  digest check repeatable by a third party.
- **Prune only after verification, and record it.** The prune runs *after* `bundle_python`
  fetches and digest-verifies the interpreter, and every removed path (and size) lands on the
  build receipt, so the provenance reads "verified PBS artifact, then these N files removed by
  haru-pack" (`INV-SHAKE-05`).
- **Distinct from `--shake`, not folded into it.** `--shake` prunes on a traced test run and
  refuses without a suite; `--slim-python` drops a known-unused set with no suite required.
- **The tkinter trap:** a project that imports `tkinter`, or shells out to pip/ensurepip at
  runtime, must NOT use `--slim-python` — it is opt-in because that safety cannot be proven
  statically. See `docs/SLIM.md`. Closes #43.

### The payload now declares its format, and the launcher refuses one it is too old to read

`manifest.toml` carries a new integer, `payload_format` (current value **1**), and the Nim
launcher refuses any payload whose declared format exceeds `MaxSupportedPayloadFormat` — exit 12,
"this payload's format (N) is newer than this launcher understands (1); rebuild with a matching
haru-pack". A payload with *no* key is treated as legacy/0 and still accepted, so nothing built
before this changes.

The skew this closes (#44): the footer's `format_ver` describes the footer's *layout*, not the
payload's *contents*, so before this an OLD launcher handed a NEW payload had nothing to check.
A launcher predating `.haru-links` (#40) stages that member as a plain text file and the ~1000
aliases it lists silently never appear — `bin/python` goes missing with no error. haru-pack
compiles the launcher from source on every build, so no supported path pairs the two today; the
gate closes the class before a cached, vendored, or `--launcher <path>` prebuilt launcher makes
it reachable. Mirrors `overlay.footerSizeFor` and `expandCompressedMembers`, which already refuse
an unknown version rather than guess. See `INV-PAYLOAD-07`.

### Four README claims checked against the code; four were wrong

Eli asked whether two paragraphs of the "Decisions" section were accurate. Reading every
paragraph against the source turned up four that were not. None of the code changed — these
were all cases of prose drifting past what the code does, which is the exact failure
`INVARIANTS.md` exists to catch and which prose about prose does not.

- **The pinning list left out `zig`.** It named uv, the Python interpreter and the choosenim
  installer. `install_zig` verifies against `pins.toml` exactly like the others, and zig is
  the *default* C compiler in every bootstrap — so the README was understating its own
  guarantee, and contradicting its Install section three paragraphs earlier.

- **The nimble gap was described too gently.** "Pinned to exact versions but never
  digest-checked" implies the pinned version is what ships. `bootstrap.ensure_nim_deps`
  installs `zippy`/`puppy`/`parsetoml`/`nimcrypto` at exact versions, but `compile_launcher`
  runs a bare `nim c` with no lockfile, no project `.nimble` and no `--nimblePath`, so Nim
  links the *highest* version present in the package directory regardless. The code comment
  said so already (`INV-SUPPLY-02`, `proposed`); the README did not.

- **"a ~500-line stub" was out by about 5x.** `main.nim` is 392 lines, but the launcher is
  ~2 400 lines of Nim across seven modules, most of it staging and verification, plus ~3 400
  lines of vendored C. The figure was doing argumentative work — it is the answer to "why is
  a packaging tool written in Nim" — so it is now the real one. Also fixed in
  `docs/COMMON_CRITIQUES.md`, which repeated it.

- **"five active invariants defended by nothing that ran" was fourteen.** Re-measured by
  pointing `XDG_DATA_HOME` at an empty directory and stripping `PATH` so no Nim is
  resolvable, then running the claimants: `INV-CANARY-01`, `CRYPTO-06`, `EPHEMERAL-03`,
  `GATE-01`, `GEO-01`, `LAUNCH-01`, `-02`, `-04`, `-05`, `-06`, `-08`, `-09`, `REMOTE-01`,
  `STUB-01`. The *other* five in that sentence is right — the 2026-09-09 review did find five
  documented, dated "Verified" claims that were unimplemented — and the two numbers had been
  collapsed into one.

Also corrected, in `toolchain.py`'s own module docstring: "The system's Nim is ignored" is
true of installing and false of resolving. `bootstrap.find_nim` prefers the managed Nim and
then falls back to `PATH`, which is precisely what makes the README's "bring your own Nim"
promise work on an arm64 host.

Verified accurate and left alone: the three-users principle, uv-does-the-Python-part,
encryption-at-rest, one-code-path, the ARM-Linux paragraph in full, mirrors (the digest is
looked up by upstream URL before the rewrite), the uv compression figures, `--shake`, and
refuses-instead-of-guessing.

### A thick binary was 40% duplicate bytes: 85.4 MB -> 50.4 MB

`hello.py` at `--thick` is now **50,425,885 bytes**, down from **85,405,022**. Nothing was
removed from it — the same unmodified, digest-verified CPython and uv are still in there, and
the staged tree on disk is byte-identical to what it was before.

python-build-standalone ships `bin/python` and `bin/python3` as symlinks to `python3.13`,
`libpython3.13.so` as one to `.so.1.0`, and — the part nobody had counted — about a thousand
terminfo aliases. `Path.is_file()` follows symlinks and `ZipFile.write` reads through them, so
`build_payload_zip` stored a full copy per name. A zip has no cross-member dedup, so the
duplication survived compression intact: the three big ones alone were 34.3 MB of an 84.5 MB
payload.

The payload now stores each file once and lists the **1047** aliases in `.haru-links`;
`stage.materialiseLinks` re-creates them between `extractAll` and `recordTree`.

**They are re-created as copies, not symlinks, and that is the whole design.** `recordTree`
walks with `walkDirRec`, whose default yield filter is `{pcFile}` and therefore skips
`pcLinkToFile`. A symlink would have been absent from `.stage-files`, and `verifyTree` only
checks what was recorded — so `bin/python`, the interpreter itself, would have gone unverified
on every reuse. That is a hole in `INV-STAGE-01` traded for disk space. The saving is taken in
the shipped binary, where it was wanted; the ~186 MB staged footprint is unchanged, and
shrinking *that* would have to solve the recording problem first.

The link table is untrusted input — the payload digest is not a MAC — so both halves of every
entry go through `unsafeEntryPath`, a target the payload does not contain is refused, a
collision with a real member is refused rather than resolved, malformed lines are refused, and
`MaxLinkEntries` (16384, against a measured 1047) bounds how much disk a rewritten table can
make the launcher write. Red path walked: replacing the guard with `if false:` makes a table
naming `../escape.bin` or `/etc/cron.d/x` materialise outside the stage, exit 0 instead of 3.
`INV-PAYLOAD-06`.

Found by asking why a hello-world thick binary is 85 MB when PyInstaller manages under 20. The
rest of that answer stands and is deliberate: ~9.5 MB is python-build-standalone material a
hello world never touches (tcl/tk, pip, ensurepip, `share/`, headers, idlelib), and the
remainder is the price of an unmodified interpreter plus uv. Only this 35 MB was a defect.
`docs/TIERS.md`'s note that the zip "doesn't preserve symlinks" had been there all along, as a
correctness remark about the launcher tolerating their absence. Nobody had costed it.

## 2026-09-15

### CI tests the happy path fast; the fallback is tested where it does not cost every push

Giving CI a Nim toolchain (so the invariant gate stops being green on tests that never ran)
took the job from ~30 s to ~10 min. Most of that was avoidable.

Measured on the 3.13 job: installing Nim took **24 s**. The other nine and a half minutes were
launcher compiles inside the tests — and they happened **twice**, because a `pytest -m invariant`
step ran the claiming tests and then the full suite ran the same tests again (4m06 + 5m20).
That step is gone. The skip-detector does not need it and is stronger in a full run, where
every claimant is selected rather than just the marked ones.

The toolchain now goes on **one** Python version. x86_64 Ubuntu on 3.13 is the target
demographic and gets the full treatment; 3.9 stays a real floor check for the pure-Python half
and sets `HARUPACK_INVARIANT_SKIPS_OK` explicitly, because launcher tests skipping there is by
design rather than an accident to be caught.

**The compile-from-source route is still fully tested** — in `nim-source-route.yml`, weekly and
on demand, not on every push. It builds the image with `NIM_FROM=source`, asserts the compiler
it produced is the version `pins.toml` names (so the two architectures cannot drift apart),
and packs a real binary with it. It also asserts the escape hatch fails closed: with no
`variant = "binary"` pin, `NIM_FROM=binary` must refuse rather than quietly compile for an hour.

It runs on x86_64 rather than arm64 on purpose, and the workflow says so: what is under test is
the *logic* — which route `acquire-nim.sh` picks, whether `install-nim-source.py` verifies the
pinned tarball, whether `build.sh` bootstraps without reaching for git — none of which is
architecture-specific. A green run there says the route works, not that arm64 works; arm64 was
verified by hand on a Raspberry Pi.

Nothing changed about *when* Nim gets compiled: `NIM_FROM=auto` on x86_64 has always taken the
choosenim binary, and the source build only runs where choosenim publishes nothing.

### the flex sandbox image builds for arm64, and getting a compiler is now a choice

`docker/flex.Dockerfile` supported linux/amd64 only, because choosenim publishes binaries for
linux x86_64, macOS x86_64/arm64 and Windows and **nothing for linux aarch64**. That left the
arm64 box unable to run flex sandboxed at all — it could only use `--no-docker`, which is
precisely the unprotected path the sandbox exists to stop being the default.

Both architectures now work, and both land on the same Nim version, so an arm64 result and an
amd64 result are comparable rather than merely both green.

**Compiling is the fallback, not the plan.** Bootstrapping Nim means compiling roughly eleven
thousand C files — about 25 minutes on a 4-core Raspberry Pi. Nobody on the platforms
choosenim covers pays that, and there is no reason an arm64 user should either. So
`.github/workflows/nim-aarch64.yml` builds one from the source tarball pinned in `pins.toml`.

The pinning half is not done yet, so arm64 still compiles under `auto`: the workflow uploads
the tarball and prints its sha256 with an instruction to add the pin by hand — it never writes
`pins.toml` — and `pins.toml` has a comment where a `variant = "binary"` entry goes rather
than the entry. While this repository is private an unauthenticated fetch of a release asset
cannot work, so a pin would point at something nobody could download. When it lands its
`provenance` must be the workflow run URL, and a test is already waiting to enforce that.

**`NIM_FROM` is the escape hatch**, and two of its modes exist for opposite reasons:

| `NIM_FROM` | what it does |
|---|---|
| `auto` (default) | choosenim where upstream publishes for it; else our pinned prebuilt binary; else compile from the pinned source |
| `binary` | a pinned binary only — fails rather than quietly compiling for an hour |
| `source` | compile from the pinned source; never run a Nim binary this project published |
| `system` | use the Nim already present; fetch and compile nothing |

Someone on a slow arm64 box wants `binary` and would rather fail than wait. Someone who
declines to execute a compiler this project built wants `source` and would rather wait than
trust it. A single "no-download" switch would have served only one of them.

**A gap and a mismatch are different answers.** "No pin for this platform" exits 3 and the
caller may fall back to a source build. "There is a pin and the bytes do not match it" exits 1
and nothing falls back — quietly recompiling instead would erase exactly the supply-chain
signal worth keeping.

**Provenance for an artifact we publish is held to a different standard.** Pinning a
third-party artifact asserts "this is what the publisher published". Pinning our own asserts
"this is what *we* built" — weaker, and worth very little if the only evidence is that someone
ran a command on hardware nobody else can see. So a `variant = "binary"` pin's `provenance`
must be the workflow run URL, and a test enforces it. Building it on a maintainer's Pi would
have been faster and is specifically what this rules out.

Verified on the arm64 box: image built, `Nim Compiler Version 2.2.6 [Linux: arm64]`, and
`certifi` packed and ran inside the sandbox (13.3 MB, build 44.4 s, run 10.8 s).

Two small things found on the way, both of which produced failures that named nothing useful:
nim-lang.org answers urllib's default User-Agent with **HTTP 403**, and the installer scripts
were printing progress to stdout when stdout *is* their return value — so a captured path came
back as `install-nim-source: nim 2.2.6 from https://...` and the build died on `cd`.

## 2026-09-14

### flex: two things the first top25 run taught us

Both found by running the matrix for real rather than by reading the diff.

**`--max-cache-gb` treated a toolchain cache as reclaimable bulk.** The sandbox volume is
13.5 MB, which reads like nothing worth keeping — but it holds haru-pack's XZ-compressed uv
(55.6 MB → 14.2 MB at preset 9), recomputed from scratch if it is gone. Measured across a
top25 run: builds took **207–213 s with a cold volume and 70–83 s with a warm one**, about
140 s per build, paid by every build that starts before the first one repopulates it. To
reclaim 13.5 MB.

That was not hypothetical — the volume had been emptied by testing the budget with
`--max-cache-gb 0.001`, which is why the first four builds of that run were three times
slower than the other twenty-one. Budgets under 1 GB are now refused, with the measurement in
the message. `--flush-cache sandbox` still empties it and now prints the same cost, because
that flag is someone saying they meant it.

**Progress was invisible when stdout was redirected.** Python block-buffers stdout when it is
not a terminal, so `flex-run.py > log` showed nothing at all for an 18-minute top25 run and
then everything at once. A harness whose output only arrives after it finishes is
indistinguishable from a hung one, and the first thing anyone does about a hung harness is
kill it. stdout and stderr are now line-buffered — one setting, rather than a `flush=True`
that the next `print` forgets.

### flex: an `importable` probe style, import names that are found rather than guessed

Three rungs now, cheapest first — `importable` (flex default), `smoke`
(`--style smoke`), `suite` (`tools/exam.py`).

**Why the default moved.** The smoke bodies are hand-written, one per package, in
`flex/curation.toml`. That made each one a second thing that could break for reasons with
nothing to do with packaging — an API moved, a keyword was removed, the package wanted a
display — and when it did, the run said "flex failed" and somebody had to read a traceback to
find out whether haru-pack had done anything wrong at all. `importable` has exactly one
failure mode, and it is the one the harness exists to detect. It is a narrowing, and it costs
something real: a default run no longer exercises the library. The stronger rungs are still
there, and the style is recorded in `results.json` and printed in the summary header so an
`importable` pass and a `smoke` pass are never silently compared.

Each module is attempted in its own `try`/`except`/`finally`. The `except` prints the **full
traceback** — that output is the only artefact left once the container is gone — and doing it
per module means a package with several top-level modules says *which* one broke.

**Import names are now discovered, not guessed** ([`INV-FLEX-03`](INVARIANTS.md)).
`pip install pillow` gives you `import PIL`, and no rule recovers that from the name; it is
why `flex/curation.toml` carried eight hand-written `import_name` entries, each a guess that
could go stale silently. The probe inverts `importlib.metadata.packages_distributions()` from
*inside* the binary, where the distribution actually exists, with PEP 503 normalisation so
`typing-extensions` and `typing_extensions` are one dist. Two fallbacks behind that
(`top_level.txt`, then the guess), and **the route is reported**, so a guess never reads as a
fact. The curated entries become assertions the harness checks and can no longer steer the
probe — if they could, checking the probe against them would be a tautology.

**Cache control**, because a matrix run grows several caches:
`--cache-info`, `--flush-cache sandbox|host`, `--max-cache-gb N`.

Measuring first moved the design. The assumption was that the sandbox volume was the problem;
it is not.

| what | size | may the harness delete it? |
|---|---|---|
| `~/.cache/uv` | **18.9 GB** | no — shared with every project on the machine |
| `haru-flex-cache` | 13.5 MB | yes — the harness's own, rebuildable |
| `~/.cache/haru-pack` | 273 MB | no |
| anonymous run volumes | 0 | `--rm` already reaps them |

The volume stays small because `warm_cache_and_lock` points `UV_CACHE_DIR` at the payload's
own bundled cache inside the build tree, not at ours. So `--max-cache-gb` only ever touches
the volume; the host caches are reported, and only *pruned*, and only when you ask.

One bug worth naming because of its shape: `uv cache dir` writes a **coloured** path, the
escape codes went into the `Path`, and `du` then reported `0 B` for an 18.9 GB cache. Nothing
raised — the number was simply wrong and looked exactly like a right one, which is the worst
thing that can happen in a tool whose entire output is numbers. There is a regression test.

### flex and exam now run strangers' code in a container, not on your workstation

The flex matrix is a list of packages picked by PyPI download rank, and running their code is
the entire point of the harness. That code executed in three places — sdist build backends
under `uv sync`, the binary the build produces, and any `[[bundle]]`/`[[post_install]]` step —
and all three ran on the maintainer's machine, as the maintainer, with `$HOME`, SSH keys,
cloud credentials and this repository's working tree in scope. `tools/exam.py` was the sharp
end: it runs each package's **own test suite**.

Both harnesses now give every package its own throwaway containers, by default. The build
phase gets the network and the shared cache; the run phase gets a throwaway cache of its own
and never sees the shared one, so nothing a package writes into the cache can reach the next
package's **run**. Its next package's *build* is another matter: the build cache is shared
read-write across packages on purpose, so a 25-package run does not fetch the same toolchain
25 times, and a malicious sdist build backend can therefore write into a cache a later build
reads. That residual risk is stated rather than papered over — it lives in a docker volume,
never on your filesystem, and `docker volume rm haru-flex-cache` resets it. The
repository is bind-mounted **read-only**, so flex still tests your working tree rather than a
stale copy baked into an image. `--no-docker` still runs on the host, after printing what that
puts at risk; docker being missing is an error, never a silent fallback
([`INV-SANDBOX-01`](INVARIANTS.md), [ADR 0005](docs/adr/0005-sandboxed-flex-and-exam-harnesses.md)).

**This made an existing result stronger, not just safer.** `--offline-check` is how the thick
tier's "the payload carries its dependencies" claim gets tested, and `tools/flex-run.py` was
honest in its own docstring about how weak the mechanism was: it forced `UV_OFFLINE` and
pointed the proxy variables at a dead port, which "does not stop a package from opening a raw
socket of its own". The run phase now gets `--network none` and a cache volume that has never
been used — a real network namespace, with no interface to open a socket on
([`INV-SANDBOX-02`](INVARIANTS.md)). The `--no-docker` path keeps the old approximation and
prints its results as `carried*`, because a weaker check reported in the same column as a
stronger one is how evidence gets overstated.

**The containment is checked offline.** `docker_argv()` is a pure function — it reads no
environment, no filesystem and no clock — so `tests/test_sandbox.py` asserts the properties
that matter (no network at thick, the shared cache unmounted during the run, the docker socket never
mounted, the repo never mounted writable) by reading the argv, on a box with no docker
installed. A guarantee that can only be checked by running docker is one that gets checked
when somebody remembers.

**Rootless docker is preferred, detected, and warned about rather than required.** The gap is
real — on a rootful daemon the socket is a root-equivalent handle — and
[`docs/ROOTLESS_DOCKER.md`](docs/ROOTLESS_DOCKER.md) is the switch-over. It warns instead of
refusing on purpose: refusing would send people to `--no-docker`, and a rootful container
beats no container. `--require-rootless` makes it fatal for anyone who wants the stronger line.

Stated and not papered over: the build phase needs the uv cache read-write and shares it
across packages, so a malicious build backend can still write into a cache a later package's
*build* reads. It is confined to a docker volume and never touches the host filesystem;
`docker volume rm haru-flex-cache` resets it. And a container is not a VM.

Two things the first implementation got wrong, both found by running it rather than by
reading it, and both now recorded in the ADR rather than quietly amended. The run phase was
given the shared cache mounted `:ro` — unimplementable, because a thick binary stages into
`$XDG_CACHE_HOME` before it can execute, so it died with `OSError: Read-only file system`.
And the image's `chmod -R` sat in its own layer after unpacking zig and the Nim toolchain;
on overlayfs a chmod is a write, so it copied the whole tree up and added ~1.08 GB to the
image for a permission bit.

### busybody — an alignment pass against lotek's independent implementation

haru-pack's busybody was a deliberate reimplementation of lotek's, from lessons learned. This
brings the two closer together **without extracting a shared library**, and puts a process
under the cross-project transfer that had been happening by hand.

**The contracts are written down.** [`docs/BUSYBODY-SCHEMA.md`](docs/BUSYBODY-SCHEMA.md) is
the on-disk contract for the three record types — journal line, finding record, ledger rollup
— field by field, and every record now carries a `schema_version` (1; a record without the key
predates the document and is version 1 by definition, so nothing needed migrating). Writing it
down was a documentation pass: six things it could not describe cleanly are recorded under
`## Smells` rather than quietly fixed, including two undeclared contracts — the ledger's field
list is duplicated in two places that already disagree, and `expect` is a list of outcomes
everywhere except on a composed stack, where it is a string describing a negation.

**One word collided and had to be resolved.** Both projects used *divergence* for unrelated
mechanisms. lotek's is a UI surface disagreeing with an API surface; ours is one case
answering differently across fixtures, and is now **fixture-divergence** in identifiers and in
prose. Neither keeps the bare word.

**Standard vocabulary, where we had invented our own.** Described rather than renamed, because
the identifiers are for the people who work on this daily and the vocabulary is for whoever is
placing the tool against the literature: *nemesis* (Jepsen) for deliberate fault injection and
*buggification* (FoundationDB) for the probabilistic kind; *bucketing by signature* and
*signature normalization* for what `fingerprint` does; *per-action perturbation probability*
for what `fires` is; *external watchdog* detecting violation of a *liveness (progress)
property* for the stall detector; *first-failure attribution* for cascade suppression. Two
names are kept deliberately against the field, and the schema doc says why.

### busybody — three additions the field expects

- **A golden run.** Every composed campaign now runs one un-perturbed control first, through
  the same code path as everything it is the baseline for. Not a flag: a baseline somebody can
  forget is missing on the run where it mattered. A campaign whose control is itself a finding
  says so above everything else — it has not measured fault tolerance, it has measured a broken
  product N times with faults on top. A stack where the firing draw happened to fire nothing is
  **not** a golden run and is named differently; an accident is not a control.
- **"Did the fault land?"** A deliberately injected fault that gets swallowed before reaching
  the target produces silence, and silence reads identically to the system absorbing it
  correctly. Every trait acts by mutating the context it is handed, so busybody snapshots that
  context around each one; a trait that fires and changes nothing is a **test-infrastructure
  finding**, journalled under its own kind and deliberately never written to the findings
  ledger.
- **`INDETERMINATE`**, Jepsen's `:info`. The outcome that is *not a verdict*: the harness
  stopped observing before the action resolved. Never a pass, never a finding — it comes out of
  the denominator, because "14/15 behaved as expected" with one indeterminate is two different
  lies depending on which way you round. It had a producer already, mislabelled: the herd gives
  sixteen children one shared deadline and called whatever missed it `HUNG`, which is a claim
  one process with its own timeout can support and sixteen racing children cannot.

### busybody — what lotek had that we did not

- **`report.md` beside `report.txt`**, byte-identical across regenerations so it can be diffed
  and committed without noise. No generation timestamp, every section sorted by an explicit
  key, findings ordered by severity rather than by run order (run order changes with `--jobs`).
- **`--replay SIGNATURE`** reconstructs the invocation behind a finding from the ledger, which
  is the only place it survives once run directories are pruned. It reconstructs the
  invocation, never the outcome, and a row it cannot reproduce says so instead of emitting a
  plausible command.
- **`--author`** writes a corpus script covering what no recorded run has exercised — cases
  that never ran, traits that never *fired*, layer pairs never stacked. It proposes and never
  runs.
- **Forensic bundles.** `preserve()` copies what a case left behind; this collects what was
  going on, from the living system, at the moment of the finding — process tree, open
  descriptors, the staged tree with any half-staged `.tmp-` directory called out, scratch
  including the quota `df` cannot see, load average. The important one is taken the instant a
  stall is declared, while every child is still up.

### busybody — shrinking, costed and declined

`ddmin` over the fired trait stack was spiked and **rejected for that axis**
([`docs/BUSYBODY-SHRINKING-SPIKE.md`](docs/BUSYBODY-SHRINKING-SPIKE.md)). At the stack sizes
this project runs it costs more than exhaustive search and returns the same answer — 10 calls
against 4 at k=3. The small search space that made haru-pack look like the better place to try
it is exactly why it does not pay. Two findings outlived the verdict: ddmin never
under-approximates under a flaky oracle (it inflates, which is the safe direction), and
`--compose-only` already forces every trait to fire, so an oracle built on it runs at p=1.

### Internal

- **INV-MODULARITY-04: the engine may not import the catalogue.** The 2026-09-13 split
  separated busybody's engine from its catalogue of faults and nothing held that separation
  open — `tools/` is a flat directory of siblings and no size budget can express *direction*.
  Declaring it turned up one real violation: `busybody_run` imported the fixture builders by
  name. Fixed by inversion (`busybody_config.FIXTURE_SOURCES`, the same shape `CASES` has
  always had), not by exception.
- **`INV-DOC-01` now covers the harness.** `CITATION_ROOTS` did not include `tools/`, so the
  `inv=` strings on 80 cases were validated by nothing — a hole the split widened from one file
  to twelve. Plus a check neither repo had: every `inv=` on a case or trait must resolve to a
  declared invariant, and a non-empty value citing no id at all is a failure too
  (`inv="see THREAT_MODEL.md"` had shipped).
- **A frozen `Paths`**, built once at startup and passed down through the whole sweep
  lifecycle, replacing module-level `REPO`/`OUT`/`RUNS` reads in the engine. The module-level
  names remain as a deprecated shim.
- **Two mechanical gates** in a now-tracked `.claude/`: bulk staging (`git add -A` and
  friends) is refused, and a version tag needs `.claude/release-ack.json` pinned to the exact
  sha (`scripts/ack-release.sh` produces it). Two, not thirteen — these are the two that encode
  a mechanical rule rather than a judgement.
- **[`docs/BUSYBODY-TRANSFER.md`](docs/BUSYBODY-TRANSFER.md)**, an append-only log replacing
  the hand-curated prose list, backfilled with 22 rows including the declined ones. Its
  uncomfortable section: as of today fourteen of the first fifteen rows run lotek→haru, and the
  return trip is evidenced nowhere in lotek.
- **[`docs/BUSYBODY-PROTOCOLS.md`](docs/BUSYBODY-PROTOCOLS.md)** — what this harness would need
  from a shared core, written independently of lotek's sketch so the two can be diffed. Its
  headline is not comfortable: haru-pack's cases do not decompose into steps, so a step-wise
  `TargetDriver` would make this harness worse.

## 2026-09-13

### Fixes — the build refuses degenerate inputs instead of crashing with a traceback

- A project directory with **no `pyproject.toml` and no `.py` files** (e.g. only compiled
  `.pyc` files, or an empty directory) now refuses cleanly with an actionable message
  (`discovery.EmptyProject`) instead of a bare `ValueError` traceback. Unlike an *ambiguous*
  project, `--entry-point` cannot rescue one with no source, so it refuses outright.
- An **`-o` path whose parent directory does not exist** now has that directory created (or,
  if it cannot be, a clean `BuildError`) instead of dying with a raw `FileNotFoundError` when
  the final binary is written.
- Both were surfaced by busybody's composed `greenhorn` cases (`greenhorn_source_is_a_pyc`,
  `greenhorn_output_into_missing_dir`), which graded them `CRASHED` — the FATAL class — because
  the compose contract is "refuse intelligibly under any stack of hostile conditions". They are
  build-side (upstream of Nim), so they reproduced identically on x86 and aarch64
  (INV-BUILD-01 / INV-BUILD-03).

### Internal — no god modules, and a check that says so (INV-MODULARITY-01/02/03)

Nothing here changes what haru-pack does. It changes how much of it you have to read to
change one thing.

- **Four god modules are gone.** `build.py` (735 statements, importing 16 of the package's
  22 modules), `tools/busybody.py` (3393), `shake.py` (536) and `cli.py` (483) are now
  packages and flat sibling modules named for what they are FOR — `build/orchestrate` reads
  as the list of phases a build has, `shake/` is its three phases plus the one function that
  runs them in order, `cli/` is one module per command. Four more files that were merely too
  long (`emit.py`, `exam.py`, `busybody_traits.py`, `busybody_hostile.py`) went the same way.
- **The public surface did not move.** `from haru_pack.build import X`, `from haru_pack
  import cli`, `python tools/busybody.py`, `python tools/exam.py` — all unchanged. Every name
  that was importable still is, including the underscored helpers tests reach for.
- **Three budgets, machine-checked, no allowlist.** 300 statements per module, 80 per
  function, and 150 for a module that imports more than eight first-party modules — that last
  one is the actual definition of a god module: a module may be the hub, or hold the work, not
  both. Comments and docstrings are free; see `docs/PRINCIPLES.md`.
- **Behaviour preservation was measured, not asserted.** `tools/gen-package-manifest.py`
  regenerates `flex/packages.toml` byte-identically; `exam.py emit` reproduces
  `top_n_pypi_stats.md` unchanged; `busybody_analyze.format_analysis` and
  `busybody_report.write_report` were diffed against their pre-split selves across fifteen
  constructed inputs and match exactly; busybody still registers the same 80 cases across the
  same 21 personas, and the trait catalogue still holds 42.

Four things the split exposed or introduced. Each has a guard now, because a refactor
that only fixes its own breakage teaches nobody anything:

- **`build/` in `.gitignore`** — and in a very common global `core.excludesFile` — matched
  `src/haru_pack/build/`, so `git add` reported nothing at all while keeping the entire new
  package untracked. This one was a real trap waiting rather than something the split
  caused: any future `build/` package would have hit it. The root artifacts are now anchored
  (`/build/`) and the package is re-included explicitly.
- **Seven relative imports across three files broke silently**, because moving a file into
  a subpackage changes what `from . import x` means. None raised at import time — the ones
  that hurt were late-bound inside a function, so nothing ran them until someone ran that
  exact command. One landed inside a `try/except Exception`, where an ImportError is
  indistinguishable from a malformed pyproject and made every project look unnamed;
  `from . import scaffold` inside `haru-pack init` was covered by nothing at all.
  `tests/test_imports_resolve.py` now statically resolves every relative import in the
  package, so a function-local one is no harder to see than a top-level one.
- **A command module imported only so its decorators run looks like an unused import**, and
  deleting one removes a subcommand with no error anywhere. That hazard is new — it did not
  exist while `cli` was one file. `tests/test_cli_surface.py` asserts the full subcommand set
  and renders `--help` for each, which is what caught two NameErrors during the move.
- `test_the_cli_does_not_import_richs_print_directly` was reading `inspect.getsource(cli)`,
  which on a package returns only `__init__.py`. It now parses the imports of every module in
  the package — and the parsing, rather than substring matching, is what made it see
  `from ..ui import fields, print`.

## 2026-09-12

### Features — `--emit-nim` and `--emit-c`: reproduction kits for the launcher stub

- **`haru-pack build … --emit-nim DIR`** writes a kit alongside the finished binary so you can
  inspect, modify, and manually recompile the launcher stub. The packed binary is still
  produced; `DIR` gets the launcher's Nim source (byte-identical to what haru-pack compiles),
  this build's `payload.bin` and `stubconfig.bin`, a portable `zig-cc` shim, a stdlib-only
  `assemble.py`, and a `compile.sh` that recompiles the stub and reassembles the binary.
- **`haru-pack build … --emit-c DIR`** writes the same kind of kit built instead from the Nim C
  backend's own output for your `--target`: the stub as plain `.c`/`.h` files, `nimbase.h` +
  the xz headers vendored so it needs **no Nim toolchain** — only a `zig` (on `PATH`, or via
  `HARU_ZIG`). `compile.sh` is derived from Nim's own build manifest (per-file flags and all),
  never a hand-written approximation, so nimcrypto's SHA-2 fast paths (`-mssse3`/`-mavx2`)
  survive the translation to zig.
- **The stub is generic; the config is data**, for both kits. Encryption, licence policy,
  reap/ephemeral, remote-fetch and injects are not compiled into the Nim/C — they live in
  `payload.bin` (policy inside it) and `stubconfig.bin`, which the always-present stub
  functions read at runtime. So each kit is source + those two blobs + a reassembler.
  `--emit-nim` and `--emit-c` share the SAME reassembler (`assemble.py` + `kit.json`) — one
  implementation, so the two flags cannot drift on what "reassemble" means.
- **Faithful, and honest about the limit (INV-EMIT-01 / INV-EMIT-02).** A real recompile of the
  emitted stub/C yields a WORKING binary — its overlay verifies and its payload + stub-config
  are this build's exact bytes — proven by actually running the emitted `compile.sh` with
  nim(+zig) in the tests. Byte-for-byte identity of the launcher is **not** claimed (a Nim/C
  recompile is not reproducible in general). The `nim c` flag set is defined once
  (`emit.nim_target_flags`) and shared with the real build, so `--emit-nim`'s recipe cannot
  silently drift; `--emit-c`'s recipe comes from Nim's own build manifest for the same reason.
  Emitting `payload.bin` exposes exactly what the binary already exposes (encrypted stays
  encrypted, and a remote build's kit gets the same `<out>.haru-payload` sidecar the real build
  ships); the build secret is never written to any kit file (INV-SECRET-02).
- **Assumes zig, no build-host paths baked in.** Both kits' `compile.sh` drive
  `${HARU_ZIG:-zig} cc` through a relocatable shim (`toolchain.zig_cc_shim`); `--emit-nim`
  additionally resolves Nim via `${HARU_NIM:-nim}`. No absolute home/username paths, so a kit
  is shareable. An unsafe emit target (symlink, or a non-empty/foreign directory) is refused up
  front (INV-BASE-01 posture), and a kit failure is a warning, never a build failure.

### Tooling — BusyBody run-control hardening (adopted from lotek)

- **Single-instance run control (INV-CHAOS-13).** Two busybody sweeps each stage a real
  interpreter per worker and thrash the box into the OOM killer (seen while running a thick
  top-50 sweep next to another). A sweep now registers itself under a project-tagged
  `/tmp/harupack-busybody/` and **refuses to start (exit 3) while another is genuinely live**
  (pid alive + fresh heartbeat), reaping a dead/wedged run's stale marker rather than trusting
  it. `HARUPACK_BUSYBODY_FORCE=1` overrides. Ported from lotek's BusyBody #738; pids are checked
  with `os.kill(pid, 0)`, so there's no ps-grep self-match trap. **Fix (same day):** the registry
  path was `tempfile.gettempdir()`-derived, so a sweep with its own `$TMPDIR` scratch registered
  somewhere private and the guard couldn't see across sweeps — found live on a top-100 run. Now a
  fixed `/tmp/harupack-busybody` (override `$HARUPACK_BUSYBODY_REGISTRY`).
- **Fail-loud selection (INV-CHAOS-12).** An unknown `--persona`/`--case` name is now a setup
  failure (exit 2) that names the typo — `--persona forger,typo` no longer quietly runs only
  forger and prints a clean verdict. Ported from lotek's BusyBody #558 (an unmatched selection
  is fatal, not dropped). *A run that silently skipped what you asked for reads exactly like a
  healthy one* — the whole reason both guards exist.
- **`--analyze` is a gate now (INV-CHAOS-14).** It used to always exit 0 — a reader, not a
  verdict — so a CI step that trusted it read a false pass on a run full of findings. It now
  exits 2 on a setup failure / environment abort, 1 on findings or an unfinished run, and 0 only
  for a clean completed run. From an audit of `--analyze` against lotek's false-clean hardening
  (#418/#682); the audit also confirmed under docker that the broad `No space left on device`
  infra marker does NOT false-abort the FS-inducing personas (the launcher wraps the OS error),
  so that stayed as-is with a documenting note rather than a needless change.

### Security

- **Launcher: the `HARUPACK_GEO` env bypass is gone (INV-GEO-01).** The old geo "check"
  compared a licence's allowed list against the `HARUPACK_GEO` *environment variable* — so
  anyone outside the region just set `HARUPACK_GEO=US` and ran. That's theatre, and it's
  removed. Location is now decided by an online resolver the user does not control (below),
  and `cryptbox.checkPolicy` reads no env for it at all. A binary built by an older haru-pack
  that still carries the array-form geo policy is *refused*, not silently waved through — a
  dropped location restriction is a breach, not a no-op.

### Added

- **Launcher Phase 4: online execution gates — geo/ip via consensus (INV-GATE-01 /
  INV-GEO-01, ADR 0006).** Every rule-checked gate now has one shape: resolve a current value,
  match an allow-policy, **fail closed**. Geo/ip resolves the caller's IP and location from a
  consensus of online resolvers (default `https://ipwho.is/` — one bare TLS request returns
  both). List N *distinct* endpoints with `--geo-restrict-api-url` and require
  `--geo-restrict-consensus=K` to resolve *and* agree, so (at K≥2) a minority of down or lying
  external resolvers doesn't decide the gate. Rules are `field=value`
  (`--geo-restrict "country_code=US,region=Texas"`, or the `--geo US,CA` shorthand) — AND within
  a rule, OR across them, and because any resolver field works, `ip=1.2.3.4` is an ip gate
  through the same code. It all lives inside the encrypted policy (needs `--encrypt`), hidden
  from a reverse-engineer. **Honest limits:** this is an IP check, not a presence check (a VPN
  exit in an allowed country passes); network-down means the app doesn't run; and because the
  check runs on the user's own machine, a determined local user can MITM their own resolver
  traffic (proxy/CA/DNS) — so it's real against casual use and honest faults, advisory against a
  determined local adversary (the shipped default K=1 trusts a single response). The durable
  control against a hostile host is not shipping to them. See INV-GEO-01 / ADR 0006.
- **Launcher Phase 3: remote-fetch delivery — `--source-url` (INV-REMOTE-01, ADR 0005).** The
  payload can be fetched over HTTP at launch instead of appended to the binary (fetched each
  run — a remote build needs network every launch, not just the first). Same
  pipeline either way — verify → decrypt → licence → stage — so the build-baked footer digest
  is the one thing trusted, no matter where the bytes came from. Tamper with the fetched bytes
  and it fails closed; point the (env-overridable) `SOURCE_URL` at a mirror and it still only
  runs bytes matching the digest. The build writes a `.haru-payload` sidecar to host, and the
  binary carries none of it. An appended build never flips to a network fetch because someone
  set an env var. Proxy-aware through the OS HTTP stack (libcurl `*_proxy` on Linux; system
  proxy on Windows/macOS).
- **`--ephemeral` is now safe on small machines and controllable at runtime (docs/adr/0007).**
  Three changes, one theme — RAM-backed staging shouldn't hurt you on a box that can't afford it,
  and the target gets the final say:
  - **`--ephemeral` implies `--reap`** (opt out with `--no-reap`). "Ephemeral" means "not
    permanent", so the stage cleans itself up after the app exits by default; `--no-reap` keeps it
    for a restart-heavy service that wants to reuse the RAM tree. The build receipt reports the
    effective `reap` (INV-EPHEMERAL-02).
  - **RAM-fit detection (INV-EPHEMERAL-01).** Before auto-staging to `/dev/shm` the launcher checks
    that the payload (`unpacked_bytes × 1.2`, baked into the stub-config) fits BOTH the tmpfs free
    space and `/proc/meminfo` MemAvailable; if not, it falls back to the persistent cache with an
    honest note instead of filling RAM and dying mid-extract on a 512 MB CI runner or small VPS.
    Fail-safe: an unknown or unmeasurable size stays on disk rather than gambling RAM.
  - **Runtime override via a fifth canary knob, `EPHEMERAL` (INV-EPHEMERAL-03).** The target reads
    `<canary>_EPHEMERAL`. It is 2-state, not 3: `1` forces RAM and skips the fit-check (and turns
    RAM on even for a binary not built `--ephemeral` — target autonomy); unset, or any other value
    including `0`, is auto. There is deliberately no value that forces disk — that would let an
    env var downgrade an `--encrypt --ephemeral` payload onto disk. The knob is additive: its
    `[canary]` key is emitted only when non-default, so the v1 stub-config corpus is byte-identical
    and neither the footer nor `stub_config_version` moves. This RAM-fit check also covers a
    remotely-fetched payload (`--source-url`): the fetched bytes are staged through the same
    `resolveStagingRoot`/fit-check pipeline as an appended payload, so remote-fetch and
    `--ephemeral` compose safely together.

## 2026-09-11

### Security

- **Launcher: symlink bypass of the staging-root refusal — fixed (INV-BASE-01).**
  `--reap` / `--base-path` refuse a staging root that is `/`, a drive/UNC root, or `$HOME`, so
  the on-exit reaper can never be pointed at somewhere catastrophic. Trouble is, that refusal
  was *lexical* — it compared strings. So a `BASE_PATH` that pointed at a forbidden root
  *through a symlink* (`/tmp/x -> $HOME`, say) presented a benign-looking string, sailed past
  every check, and staged — and with `--reap`, reaped — a subtree at the forbidden location.
  The blast radius was bounded (it only ever creates/deletes its own `<key>-<digest>` subtree,
  never `rm -rf $HOME` wholesale), but it defeated the guard's whole point and left a TOCTOU
  window on the detached delete. `refuseUnsafeRoot` now resolves the existing part of the path
  now hardens both platforms with the right primitive: **POSIX** resolves the existing prefix to
  its physical location (`physicalPrefix` → `realpath`) before the root/drive/home checks — a
  benign symlink is allowed, one resolving to `/` or `$HOME` is refused; **Windows** fails
  *closed*, refusing a staging root whose existing prefix passes through **any** reparse point
  (symlink *or* junction), because `getFullPathNameW` (what `expandFilename` uses there) does
  not follow reparse points and untested `GetFinalPathNameByHandleW` FFI has no place inside a
  delete-primitive guard. The reaper also refuses a target that has since become a symlink /
  reparse point — cross-platform. Found by a "what about smuggling in path traversals or
  symlinks?" question during review; proven bypassable on POSIX (`/tmp/link -> $HOME` returned
  ACCEPTED), fixed with a claiming test whose red-path was walked. Compiles on release / haruDev
  / `nim check --os:windows`.

### Added

- **Launcher Phase 2: `--reap` + `--ram-only` + `--base-path`** (INV-REAP-01 / INV-RAM-01 /
  INV-BASE-01, ADR 0004). `--reap` bakes a detached, fire-and-forget cleanup of the staged
  subtree on exit; `--ram-only` best-effort stages under `/dev/shm` on Linux (honest fallback +
  the disclaimer that we can't govern the packed app's own disk writes); `--base-path`
  relocates staging. Two orthogonal flags. The reaper only ever removes the stub-created
  subtree.
- **Launcher Phase 1: stub-config section + per-knob env canary + `--env-append`** (INV-STUB-01
  / INV-CANARY-01/02 / INV-LAUNCH-08/09, ADR 0003). A cleartext, signature-covered config the
  stub reads before it decrypts; per-knob env prefixes (`HARU_SECRET`, …, default `HARU`,
  overridable / randomizable); `--env-append K=V` injected into the child env, plaintext unless
  `--encrypt` with a loud warning otherwise.

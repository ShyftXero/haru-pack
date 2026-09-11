# haru-pack — brainstorm

Unfiltered idea dump. Nothing here is committed scope.

## 1. "BusyBody, applied to packaging" — the build fuzzer
Modeled on lotek's BusyBody (persona-driven chaos + differential + reproducible seed +
`analyze`→verdict + cross-run `ledger`). Here the "operators" are **real Python projects**
and the target is our build→stage→run pipeline. Goal: mechanically discover sharp corners
before users do.

### Corpus (what to throw at it)
- **Top-N PyPI packages** → generate a trivial "hello-world" that imports each and calls
  one obvious entrypoint (import + `print(pkg.__version__)` at minimum). Top 100/1000 by
  downloads. Instantly exercises native wheels (numpy/pandas/pillow/cryptography), lazy
  imports, and packages with post-install needs.
- **Real GitHub projects** — clone repos that already have `pyproject.toml`/PEP723,
  filter to ones uv can resolve, try to build+run their console entrypoint.
- **Archetype generators** (deterministic, seeded) — synthesize projects that stress one
  axis each: flask+templates, playwright, a Cython ext, a data-file reader, a
  reads-config-adjacent-to-exe app, a long-running server, a project with `[project.scripts]`
  entry points, one that spawns subprocesses, one that writes to cwd.
- **Adversarial/mutation corpus** — path traversal in the zip, reserved Windows names,
  huge assets, deps that need network at import, a project that `chdir`s, one that reads
  `__file__` for user data (must FAIL the run-in-place assertion → caught, not shipped).

### Personas / axes
- `offline-airgap` — build with warmed cache, run with network physically off; anything
  that phones home is a finding.
- `run-in-place` — drop a config next to the exe, run from a *different* cwd, assert the
  app sees both correctly (this is our core contract; auto-check it).
- `cold-vs-warm` — first run (stage + post-install) vs second run (cache hit) timing +
  correctness; assert 2nd run does no extraction/network.
- `cross-arch` — build Windows bundle on Linux, run under wine (or a Windows runner);
  differential against a native build of the same project.
- `signed-vs-unsigned` — attach → sign → assert launcher still finds payload + runs
  (already proven once; make it continuous).
- `moved-exe` — rename/move the exe, run again; assert stage still resolves.

### Harness shape (steal from BusyBody)
- Reproducible `--seed`; each run in a throwaway dir; artifacts in `.haru-pack-fuzz/runs/<id>/`
  (gitignored): `timeline.jsonl`, per-project journal, the built exe, stdout/stderr.
- `validate` (corpus loads + manifests parse, offline/instant) · `run --minutes N` ·
  `analyze <run>` (verdict: real corner vs artifact of our test) · `ledger` (corners
  rolled up across all runs, deduped) · `coverage` (which axes/wheels/py-versions hit).
- Exit codes: 0 clean · 1 findings · 2 broken corpus/seed.
- Verdict discipline: a build failure that's the *project's* fault (bad deps) is an
  artifact; one that's *our* fault (we mangle cwd, break native wheels, leak to user dirs)
  is a real finding. Keep them separate or the ledger becomes noise.

### Cheap first version
`fuzz/hello_from_top_pypi.py`: pull the top-100 list, for each emit a PEP723 script that
imports it, `haru-pack build` it, run it in an airgapped subdir, record pass/fail + reason.
One afternoon; immediately finds the "needs post-install" and "native wheel per-platform"
classes.


## 1b. Second round from lotek's BusyBody — what transfers, what doesn't (2026-09-11)

lotek sent back a list of what to steal next, having seen us take its journal / heartbeat /
ledger / severity machinery. Its headline: our cases run standalone, deterministic, one-each,
so the failure mode we structurally cannot reach is a **whole-system stall that no single case
observes because it is emergent from concurrency**. Triaged four ways, cheapest first.

### Take: a `--seed`, and faults that land at a seeded moment
Every fault we inject lands at a **fixed** point — `killed_mid_stage` kills mid-stage,
`impatient` signals *after* staging. Those are one point each on an axis that is continuous,
and the axis is where the interesting bugs live: a SIGKILL 40 ms after the `.tmp-` directory
is created is a different fault from one 4 s in, and today we only ever fire the second.

busybody has no `--seed` at all. Adding one is small and it is the prerequisite for anything
nondeterministic, the herd below included. The part worth copying verbatim is lotek's
discipline: **journal the perturbation before performing it.** Without that, a seeded kill
produces one case name with two outcomes and the journal cannot say which moment it chose —
and our own jitter starts masquerading as a haru-pack defect, which is the exact confusion
the `CASE-ERROR` split exists to prevent.

lotek's framing of this ("a persona that executes its script perfectly was *too competent* —
the one thing no real operator is") applies to us only halfway. Our runtime operator is a
shell invoking `./myapp`; the perfect executor really is the realistic case there. The human
fumbling that matters for haru-pack happens at **build** time — wrong flag, stale lockfile,
typo'd directive — which is the persona below.

### Take, and it's the best of the four: `settings-tinkerer` — but it needs a new case kind
The eager admin who lives in Settings flipping toggles until something desyncs. We grew the
surface for exactly this on 2026-09-10 (`[tool.haru-pack]` directives, `INV-BUILD-07`) and
nobody attacks it. Better, the oracle is already written down — INV-BUILD-07's own Assets
paragraph says *"a config table read by nobody is worse than a missing one, because the
operator believes it took effect"*, and `SILENT` is already a first-class outcome we call the
worst kind. A build that exits 0 having ignored a directive is the packaging translation of
lotek's Save that 200s and never persists.

The blocker is structural and worth naming before anyone calls this cheap: **all twelve
personas have the signature `(exe: Path, work: Path)`, and the exe is built once, before any
case runs.** No current case can express a build-time fault. This persona needs a second case
kind that receives a *project directory*, runs `haru-pack build` itself, and treats the build's
exit code, its stderr and the resulting exe as evidence. Cases are cheap; the hook is not.

Cases once it exists: two directives that contradict each other · a directive that contradicts
the CLI flag duplicating it · an unknown key (`entry-point` for `entrypoint`) · a directive
edited after the lockfile · case and whitespace variants · a directive naming a file outside
the project. INV-BUILD-07 is `active` with a red path, but its tests are cooperative pytest
ones; nothing has been hostile to it.

Because we ship refusals that hand over the fix, the discriminator here is three-way, not two:
refuse *with the fix* (correct), refuse uselessly (a docs defect), ignore silently (the
finding). Only the third is a `SILENT`.

### Take, re-aimed: `herd` + a watchdog — the wedge class, which we genuinely cannot see
lotek composes N personas at chosen ratios against one shared board. We have no board, no
queue and no worker pool — a launcher stages and execs. But we do have exactly one shared
mutable resource under a lock: **the stage cache directory, keyed by digest.** `twin` already
races N=2 on it and asserts atomicity, so the shape is right and the scale is wrong.

What N=16 can produce that N=2 cannot: a stampede where sixteen processes each extract the
same 60 MB independently; sixteen waiters on a `.tmp-` directory whose owner was SIGKILLed and
never wrote `.ready`; lock convoy. And no child can diagnose any of it. Our per-process
`communicate(timeout=180)` eventually reports `HUNG`, but it cannot distinguish *slow because
of 16-way contention* from *wedged, permanently* — that distinction needs an observer outside
every child, sampling CPU and the byte count under each `.tmp-` every second and declaring a
wedge when all children are alive and none is progressing for K seconds.

The cheap half of this steal is the tagging, and it is the half we would miss. Once a wedge is
declared, **everything after it is `post_wedge`, not a fresh finding.** Our ledger fingerprints
and `--triage` ranks groups largest-first, so one stall would otherwise enter as fifteen `HUNG`
fingerprints and rank a single bug fifteen times — the same arithmetic error as reading
"575/575 passed" as 25× the assurance.

Cost is real: a case kind that owns N children plus a watchdog process, a `WEDGED` outcome, a
`post_wedge` field in the journal and the ledger. Worth it because of what the top-25 sweep
taught — this discriminates on **haru-pack's own concurrent state, not on the payload**, so it
runs against the synthetic fixture in seconds and never needs the 35-minute sweep.

### Decline: WebUI-first
There is no web UI. haru-pack is a CLI and a Nim launcher, and building a UI in order to have
one to drive would be the tail wagging the dog. The transferable half — *drive the surface a
human actually touches, not the API underneath* — maps to the rich terminal output that landed
under `INV-UI-01`, and the silent-success failure there is a progress line claiming a stage was
verified when it was not, or the wrapper eating a message when stdout is not a TTY. That is one
`mute`-adjacent case comparing what a TTY sees against what a pipe sees. Not a new harness.

### Order, if this gets built
`--seed` and journal-before-act (small, unblocks the rest) → the build-time case kind and
`settings-tinkerer` (best value, invariant already written) → `herd` + watchdog + `post_wedge`
(most expensive, only class we cannot currently observe at all) → TTY-vs-pipe (small).

And the reciprocal, if anyone is routing this back: a composed run with a watchdog needs to
attribute a stall to the harness or to the product, which is what our `blame` field
(`launcher` / `app` / `unknown`) and the `APP-CRASHED` outcome exist for. A watchdog that calls
its own scheduling starvation a product wedge is the `tight_address_space` mistake — a
threshold that looks thorough and discriminates nothing.
## 2. More feature ideas
- **`haru-pack doctor <project>`** — static pre-flight: detects playwright/spacy/nltk/torch
  (post-install needed), native exts (per-platform bundle), reads-`__file__` smells,
  network-at-import, missing lockfile. Emits the manifest it *thinks* you need.
- **`haru-pack init`** — infer manifest from a project (PEP723 vs pyproject, entrypoint
  from `[project.scripts]`, guess post-install from known packages).
- **Auto run-in-place shim** — inject a `sitecustomize`/`usercustomize` that repoints
  cwd + a `haru-pack.exe_dir()` helper so unmodified apps mostly "just work."
- **Splash/progress** during first-run stage + post-install (the PyInstaller `--splash`
  lesson) — a Nim webview or a console spinner.
- **Self-update channel** — optional: exe checks a URL for a newer payload hash, swaps the
  stage dir. (Signing story gets interesting; opt-in.)
- **Delta updates** — payload is content-addressed; ship only changed files between builds.
- **Multi-entrypoint** — one exe, subcommands map to different scripts (busybody-style).
- **Icon + version resources** on the PE (Windows metadata), so it looks legit + signs clean.
- **macOS** target (codesign + notarize; the append-after-sign rule is *stricter* there —
  research/04 flagged the Mach-O LINKEDIT issue).
- **Reproducible builds** — `exclude-newer` + pinned uv + pinned python build date →
  byte-identical bundles for auditability.
- **Telemetry-free by default**, but an opt-in first-run crash reporter for authors.


## 5b. Launcher language: Nim vs Mojo (and others)
Question raised: use **Mojo** for the exe instead of Nim (Mojo is a Python superset,
uv/pip-installable)?

Decision: **keep Nim for the launcher.** The launcher's hard requirements are (§0 of PLAN):
compile to a **signable Windows PE**, **cross-compile from Linux**, tiny/dependency-light,
stable. Against those:
- **Nim** — already proven end-to-end here: cross-compiles Linux→Windows PE, signs with
  osslsigncode, reads its own signed self, small binary, stable stdlib. It wins on every
  hard requirement today.
- **Mojo** — `mojo build` does emit native binaries, and the toolchain installs via
  pip/uv. But the blockers for THIS job:
  1. **Windows / cross-compile.** Mojo's native Windows target + Linux→Windows
     cross-compilation are not a solved, first-class path (historically Linux/macOS-first,
     Windows via WSL). Our primary target is Windows + code signing + cross-build-from-Linux
     — that's the deciding factor. (Mojo moves fast; re-verify current status before ruling
     it out forever.)
  2. **Runtime weight.** Mojo/MAX binaries pull a heavier runtime than a lean Nim stub; the
     launcher wants to be tiny.
  3. **Maturity/churn.** Language still evolving with breaking changes; Nim is stable.
- Where Mojo IS relevant: as a **packaged app** language. Its toolchain being uv/pip-
  installable means a haru-pack bundle could ship a Mojo-based Python app (bundle the mojo
  runtime like any dep). Good "app we package," not "the launcher."
- Also-rans for the launcher: **Zig** (excellent cross-compile + tiny, but less Python-ish
  syntax — strong plan-B), **Rust** (what pyapp uses; heavier build, great tooling), **C**
  (what PyInstaller's bootloader is; maximal control, least ergonomic). Nim stays unless a
  hard requirement forces a change.

## 3. Naming
Current: **haru-pack** (uv + "cast it at a target") — memorable, fine to keep.

UV-ray / sunlight theme (uv does the work, launcher delivers it):
- **Photon** — one quantum of light == one single-file artifact. Clean, techy. (npm/py
  name collisions likely — check.)
- **Sunray / Sunbeam** — friendly, "beam your app over."
- **Flare** — short, punchy, "launch"/"emit" vibe.
- **Corona** — the sun's outer light; also "crown." (Overloaded since 2020 — probably skip.)
- **Helios** — sun god; serious-tool feel.
- **Prism** — takes one input, emits a spectrum (of platforms). Nice metaphor for
  cross-compile.
- **Lumen / Radiant / Aurora / Blacklight / Ultraviolet / Nanometer.**
Delivery/uv-forward: **uvship, uvpack, uvcast, solarpack.**

Leaning: keep **haru-pack** as the project; if you want the light theme, **Photon** or
**Flare** are the strongest single words; **Prism** if you want to lean on the
cross-compile/one-source-many-targets story.

## 4. Positioning vs pyapp
pyapp already ships a Rust launcher. haru-pack's wedge (say it out loud in the README):
native **PEP 723 ingestion**, **truly embedded** uv+python+wheels (zero runtime network),
**run-in-place cwd + adjacent config** UX, **first-class cross-compile + code-signing from
Linux**, and the **build-fuzzer** as a correctness story pyapp doesn't have.

> **Corrected by `research/05`.** Two of those are differentiators against *pyapp*, not
> against the field: `razorblade23/PyCrucible` embeds uv by default and extracts beside the
> executable. What survives as genuinely ours: **code signing and payload integrity** (no
> tool in the Python-uv space has either — pyapp verifies nothing and accepts `http://`),
> **Linux→Windows cross-compile including thick**, the **explicit tier ladder**, **PEP 723
> ingestion**, and **licensing/expiry/machine binding**.

## 5. Ideas that were costed and declined (so they stop resurfacing)

Unlike the rest of this file, these were worked out far enough to decide against. Each has
its reasoning written down somewhere durable; the point of listing them here is that this
is the file people reach for when an idea feels new.

- **UPX-packing the bundled `uv` binary.** Declined 2026-09-10. The size win is real but it
  belongs to LZMA, not to packing, and it is obtainable without modifying a signed
  third-party executable — packing destroys uv's Authenticode signature, matches no
  publisher digest, trips AV packer heuristics, needs `paxctl -m` under hardened kernels,
  breaks macOS arm64 codesigning, and pays decompression on *every* launch. Shipping the
  payload *member* XZ-compressed got 55.59 MB → 14.17 MB (vs 22.25 MB deflated) with the
  staged binary byte-identical to the release. Implemented instead: `INV-PAYLOAD-04`.
- **A thick tier that ships no `uv` at all.** Declined 2026-09-10, with the design and
  measurements kept in [`UV_FREE_THICK.md`](UV_FREE_THICK.md). The prize fell to ~14 MB of
  exe once uv shipped compressed, and the obvious implementation — a prebuilt virtualenv —
  cannot work cross-platform at all. The version that *can* work (a flat `uv pip install
  --target` tree on `PYTHONPATH`) was validated, so read the doc rather than re-deriving it.

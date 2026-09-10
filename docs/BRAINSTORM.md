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

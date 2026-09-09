# uvcannon — Plan

A single-file, **EV-signable native launcher** that carries an arbitrary Python project
(PEP 723 script *or* a full multi-folder project), stages `uv` + a standalone Python into
per-user appdata on first run, and runs the project **as if it were a compiled binary in
the folder the exe sits in**. Windows-first, Linux supported. Written in **Nim**.

> Research backing every decision here: `research/01`–`04`. TL;DR of the big one:
> **astral `war` is NOT a builder** — it's a draft archive-format spec with *no binary
> encoding defined yet*. We honor its spirit (magic + index + per-entry zstd + atomic
> unpack) in our own overlay container, and can swap to real `war` when it ships. Real
> prior art is `ofek/pyapp` (Rust); we take its shape but keep the Nim stub + run-in-place
> UX + explicit EV-signing story.

---

## 1. UX contract (the thing that must be true)

Scenario: user downloads `myapp.exe` into `C:\Users\user\Downloads\images\`, drops a
`config.toml` next to it, double-clicks / runs it.

1. First run: launcher extracts payload to
   `%LOCALAPPDATA%\uvcannon\<payload-hash>\` (Linux: `$XDG_CACHE_HOME/uvcannon/<hash>`),
   stages `uv` + standalone Python + the app, then invokes the entrypoint.
2. **The Python sees `images\` as its working directory** — relative paths, `os.getcwd()`,
   `open("data.csv")` all resolve against `images\`, exactly like a native binary would.
3. **`config.toml` next to `myapp.exe` is found** — even though the code physically lives
   in appdata. Python must NOT use `__file__` to find it (that points into appdata).
4. Subsequent runs: hash dir already `.ready` → **skip staging, exec immediately**.
5. Works offline. No network calls at runtime.
6. The exe is a normal PE that `signtool` (EV cert) signs; no AV self-extractor stigma
   beyond what signing + reputation resolves.

### The three roots (PyInstaller's two-root lesson, made explicit)
| Root | Nim source | Exposed to Python as | Purpose |
|------|-----------|----------------------|---------|
| **CWD**   | `getCurrentDir()` | child process cwd | native relative-path behavior |
| **EXE dir** | `getAppDir()` | env `UVCANNON_EXE_DIR` | find config *adjacent to the shipped exe* |
| **STAGE dir** | appdata `<hash>/` | env `UVCANNON_STAGE` | bundled code / venv / python (internal) |

Config resolution order shipped in a tiny `uvcannon` runtime helper:
`UVCANNON_EXE_DIR` first, then CWD. Scripts never touch `__file__` for user data.

> In the user's example CWD == EXE dir == `images\` (double-click). We keep them separate
> so launching from a terminal in another directory still behaves like a native binary
> (relative paths follow the real cwd) while exe-adjacent config still resolves.

---

## 2. Architecture

```
myapp.exe  =  [ Nim launcher PE ]  ++  [ payload blob ]  ++  [ footer ]   (++ [Authenticode cert table after signing])
                     |                      |                   |
             thin native stub        zstd archive        fixed-size, scan-back magic
```

Runtime flow (thin stub — interpreter delegated to uv):
1. `getAppFilename()` → open self → **scan backward from EOF for footer magic** (survives
   an appended cert table) → read `{offset,len,sha256}`.
2. Compute stage dir `= <appdata>/uvcannon/<payload-sha256-prefix>/`.
3. If `<dir>/.ready` exists → go to step 6.
4. Else: extract payload → `<dir>.tmp-<pid>/`, verify sha256, write `.ready` **last**,
   `moveDir` (atomic rename) into `<dir>/`. Tolerate concurrent-loser race.
5. (Optional) show a one-line progress/splash during 3–4.
6. Set env (`UV_*`, roots), `startProcess(uv, workingDir=CWD, args=commandLineParams(),
   options={poParentStreams})`, `waitForExit`, propagate exit code, forward Ctrl+C.

---

## 3. Payload container format (`.uvcap`, war-inspired)

war has no binary encoding, so v0 uses a concrete, boring container and steals war's
*ideas*. Swap-in path to real war later is isolated behind one module.

- **v0 archive:** a single **zstd-compressed tar** (or zip via `zippy`). One compressed
  blob = one Nim constant / one overlay region. (war ideas kept: magic, name index,
  per-entry compression, atomic unpack, path-traversal + reserved-name rejection.)
- **Overlay footer** (fixed size, at EOF pre-signing; located by backward magic scan):
  ```
  magic        "UVCANON1"      8B
  format_ver   u16
  flags        u16             (bit0: external-payload mode; bit1: has-warmed-cache)
  payload_off  u64             (offset from start of file)
  payload_len  u64
  payload_sha  32B             (sha256 of payload bytes)
  tail_magic   "1NONACVU"      8B   (reverse sentinel for backward scan)
  ```
- **Payload tree:**
  ```
  manifest.json         # app kind, entrypoint, uv args, python version, env overrides
  app/                  # the user's project (script.py, or full project tree)
  vendor/uv[.exe]       # pinned uv binary
  vendor/python/        # extracted python-build-standalone (or omit → uv managed dir)
  vendor/env/           # OPTIONAL prebuilt venv (project mode)
  vendor/cache/         # OPTIONAL pre-warmed UV_CACHE_DIR
  locks/                # uv.lock and/or script.py.lock
  ```
- **external-payload mode** (flag): ship `myapp.exe` + `myapp.uvcap` sidecar instead of
  appending — friendlier to strict enterprise AV. Launcher finds sidecar via `getAppDir()`.

---

## 4. Driving uv (offline, both modes)

Launcher sets before spawn (see `research/02`):
```
UV_OFFLINE=1
UV_PYTHON=<stage>/vendor/python/.../python(.exe)     # path, not version
UV_PYTHON_DOWNLOADS=never
UV_PYTHON_INSTALL_DIR=<stage>/vendor/python
UV_CACHE_DIR=<stage>/vendor/cache
UVCANNON_EXE_DIR=<exe dir>   UVCANNON_STAGE=<stage>
```

- **PEP 723 single script** — ship `app/script.py` + `locks/script.py.lock` + warmed
  cache. Run: `uv run --offline --script <stage>/app/script.py -- <user args>`, child
  cwd = CWD.
- **Multi-folder project (Flask etc.)** — ship project + `uv.lock` + prebuilt
  `vendor/env`; set `UV_PROJECT_ENVIRONMENT=<stage>/vendor/env`. Run:
  `uv run --no-sync --offline --project <stage>/app <entrypoint> -- <args>`
  (`--no-sync` implies `--frozen`; never auto-sync/hit network).

Gotchas locked in: no `UV_NO_INDEX` env var (use `UV_OFFLINE`); `--project` ≠ cwd change
(only `--directory` is, which we avoid — we set child cwd ourselves); cache is not
cross-machine portable (warm on target OS/arch at build, or ship prebuilt venv).

---

## 5. Staging lifecycle
- **Location:** Windows `%LOCALAPPDATA%` (regenerable → not roaming `APPDATA`); Linux
  `$XDG_CACHE_HOME`/`~/.cache`; macOS `~/Library/Caches`. Roll path with `os.getEnv` + `/`.
- **Versioned by content hash** → upgrades are collision-free, old versions GC-able.
- **Atomic + crash-safe:** extract to `<hash>.tmp-<pid>`, `.ready` sentinel written LAST,
  `moveDir` rename. Guard `if not dirExists(final)`; tolerate loser race.
- **Eviction:** simple age/LRU sweep of old `<hash>` dirs (don't leak like onefile).

---

## 6. Build pipeline (the `uvcannon` CLI, later)
1. Read the target project; detect kind (PEP 723 script vs project w/ pyproject).
2. Resolve deps with uv on the build host (**warm cache / build venv on target OS/arch**),
   generate `uv.lock` / `script.py.lock`. Fetch pinned python-build-standalone.
3. Assemble payload tree → tar + zstd → `.uvcap`.
4. Cross-compile the Nim launcher: `nim c -d:mingw --cpu:amd64 -d:release` (Win from
   Linux via `mingw-w64`) / native Linux build. Console subsystem (`--app:console`).
5. Append payload + footer to the launcher PE. **No UPX.**
6. **Sign LAST:** `signtool sign /fd SHA256 /tr <ts> /td SHA256 /a myapp.exe` (EV cert).
   Cert table appends at EOF → footer still found by backward scan; payload is inside the
   Authenticode hash (correct: append then sign).

---

## 7. Repo layout
```
uvcannon/
  src/            # Nim launcher: main, overlay, stage, envsetup, exec, container
  builder/        # the uvcannon build CLI (assemble payload, drive nim, sign) — later
  runtime/        # tiny `uvcannon` python helper (app_dir(), exe_dir(), here())
  examples/       # hello PEP723 script + a minimal Flask app to dogfood both modes
  research/       # 01-04 (done)
  docs/           # PLAN.md (this), later: FORMAT.md, SIGNING.md
  tests/
```

---

## 8. Milestones
- **M0 (spike):** hardcoded-path Nim stub that `startProcess`es a bundled `uv` with
  `workingDir=getCurrentDir()`, proving the run-in-place + adjacent-config UX on Windows.
- **M1 (overlay):** append/scan-back footer + sha256 verify + zippy/zstd extract to
  hash-versioned appdata with atomic `.ready`.
- **M2 (uv offline):** full env wiring; PEP 723 single-script mode fully offline.
- **M3 (project mode):** prebuilt venv + `--no-sync` Flask example offline.
- **M4 (builder CLI):** `uvcannon build ./project` → unsigned exe end-to-end.
- **M5 (signing/AV):** EV signing step, external-payload mode, splash, docs.
- **M6 (Linux + polish):** Linux target, eviction, cross-platform CI.

---

## 9. Open decisions (need a call before/at M2)
1. **Python provisioning:** always embed the extracted interpreter (biggest, simplest,
   fully offline) vs ship python-build-standalone tarball + `UV_PYTHON_INSTALL_MIRROR`
   file:// (smaller exe, first-run install step). *Lean: embed for the "compiled binary"
   feel.*
2. **Single-file vs external payload default:** appended overlay (true single file) vs
   sidecar `.uvcap` (AV-friendlier). *Lean: single-file default, sidecar opt-in.*
3. **Container v0:** zstd-tar vs zip(zippy). *Lean: zstd-tar (better ratio); zippy handy
   for the zip path and it's pure-Nim.*
4. **cwd policy** when launched from a different terminal dir: real cwd (native feel) vs
   force exe dir. *Lean: real cwd for child + `UVCANNON_EXE_DIR` for adjacent config.*

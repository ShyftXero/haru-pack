# Research 02 — Staging & driving `uv` fully offline

_Agent: Null_Pointer. uv 0.10.4. Date: 2026-09-09._

## Verdict
A bundled `uv` binary can run `uv run` **fully offline** if you ship: (a) the uv binary,
(b) an extracted python-build-standalone interpreter, (c) a pre-warmed cache and/or a
prebuilt venv, (d) a lock. uv **never** changes the child's cwd unless you pass
`--directory`. `--project` only moves config discovery, not cwd.

## Launcher env (set for BOTH modes)
```
UV_OFFLINE=1                     # hard offline: cache + local files only (NOT UV_NO_INDEX — that env var does not exist)
UV_PYTHON=<abs path to bundled interpreter>   # bypass discovery + download
UV_PYTHON_DOWNLOADS=never        # defense in depth: never fetch CPython
UV_PYTHON_INSTALL_DIR=<bundled python tree>   # discovery finds bundled first
UV_CACHE_DIR=<bundled, pre-warmed cache>      # on target filesystem
# cwd: chdir to the EXE's folder (or export APP_HOME=<exe dir>) BEFORE spawning uv
```

## The critical cwd / adjacent-config gotcha
- `uv run` inherits the launcher's cwd; does NOT cd into project/script dir.
- A self-extracted script's `__file__` / `sys.argv[0]` point INTO the temp/extract dir —
  so a script reading "config next to me" via `__file__` finds the *extracted* copy, not
  the file the user placed beside the shipped exe.
- **Fix:** launcher sets cwd = exe's folder (and/or exports `APP_HOME`). Script reads
  adjacent config via `os.getcwd()` / `APP_HOME`, **never** `__file__`.
- Avoid `--directory` unless you *want* uv to re-base relative paths to a specific dir
  (it DOES change the child cwd). For run-in-place, prefer launcher-set cwd.

## Two app shapes
### Single PEP 723 script
- Deps in `# /// script ... dependencies=[...] # ///` block. `uv add --script app.py ...`.
- Pre-seed: `uv lock --script app.py` → `app.py.lock`; warm `UV_CACHE_DIR` once online on
  target OS/arch. Then offline: `uv run --offline --script <exe_dir>/app.py`.
- Reproducibility: `exclude-newer` (RFC3339) / `UV_EXCLUDE_NEWER`.

### Multi-folder project (Flask + pyproject.toml)
- Ship project + `uv.lock` + a **prebuilt venv**; set `UV_PROJECT_ENVIRONMENT=<venv>`.
- Run: `uv run --no-sync --offline --project <exe_dir> flask run ...`
  (`--no-sync` implies `--frozen`; `--locked` to hard-assert). This skips all network.
- WARNING: default `uv run`/`uv sync` **auto-locks + auto-syncs** (network + writes) and
  exact-sync **removes** packages not in the lock. Always `--no-sync`/`--frozen` offline.

## Offline python-build-standalone (if you must `uv python install`)
- `UV_PYTHON_INSTALL_MIRROR=file:///<dir>` — replaces the GitHub release URL; lay tarballs
  out to mirror the release path. `UV_PYTHON_DOWNLOADS_JSON_URL` for air-gapped metadata.
- Simplest: **just bundle the extracted interpreter** and point `UV_PYTHON` at it. No
  `uv python install` at runtime.

## Gotchas
1. **No `UV_NO_INDEX` env var.** Use `UV_OFFLINE=1` (broad) and/or `--no-index` flag.
2. **Cache is not cross-machine portable** (wants same FS as venv for hardlinks). Seed on
   same OS/arch/path, or ship a prebuilt venv. Never `uv cache prune --ci` on an offline
   bundle (it strips prebuilt wheels).
3. `--project` ≠ cwd change (common trap). Only `--directory` changes child cwd.
4. Setting `UV_PYTHON` to a *version string* (not a path) can still trigger a download —
   use the interpreter **path** + `UV_PYTHON_DOWNLOADS=never`.
5. Default uv dirs differ by OS — always pin `UV_CACHE_DIR` + `UV_PYTHON_INSTALL_DIR`
   explicitly so you never touch the end-user's real uv dirs.
6. Pin uv by shipping the exact tested binary; never `uv self update` in a bundle.

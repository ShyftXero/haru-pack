# haru-pack — sharp corners catalog

The launcher is easy. The *long tail of real projects* is where it bleeds. This is the
running list of packaging hazards + the intended handling. The `busybody` build-fuzzer
(see `BRAINSTORM.md`) exists to keep discovering these against real projects.

## A. Flask app with a browser UI (little projects) — EASY tier
Verdict: **the easy, headline use case.** Flask is pure-Python + a few pure-Python deps.
- Project mode: ship project + `uv.lock` + prebuilt venv; entrypoint runs the server.
- UX polish for "double-click → app opens in browser":
  - Bind `127.0.0.1:0` (ephemeral port), read the chosen port, `os.startfile`/`xdg-open`
    the URL. Or ship a **native webview window** (`pywebview`, or a Nim webview) so it
    feels like an app, not a terminal + browser tab.
  - Launcher should be `--app:gui` for a windowed feel (no console flash) — but then the
    child's stdio has no console (see `research/03`); route logs to a file under the
    stage dir.
  - Keep the server alive while the window is open; kill the child on window close.
- Manifest sketch: `kind:project`, `entrypoint:["python","-m","myapp"]`, `offline:true`.

## B. Playwright (and anything with a post-download runtime) — HARD tier
The canonical sharp corner. `pip install playwright` gives you the Python API but **not
the browsers**; you must run `playwright install <browser>`, which downloads ~100-300MB to
a per-user cache (`~/.cache/ms-playwright` / `%USERPROFILE%\AppData\Local\ms-playwright`),
platform-specific. Real gotcha we already have evidence for: on newer distros the bundled
**chromium fails to install; firefox works** (lotek's own busybody doc says exactly this).

Handling options (manifest `post_install`, implemented in M0):
1. **Bundle the browsers into the payload** → fully offline, big exe. Set
   `PLAYWRIGHT_BROWSERS_PATH=<stage>/vendor/ms-playwright` and ship that tree. Best UX,
   biggest artifact.
2. **Post-install download on first run** → `post_install: [["playwright","install",
   "chromium"]]`. Runs once (sentinel-guarded), needs network on first run only. Point
   `PLAYWRIGHT_BROWSERS_PATH` into the stage dir so it lands in our cache, not the user's.
3. Let the user pick the browser (firefox fallback) via manifest.
Corners: the download is slow (need the splash/progress), can fail offline, and the
browser cache must be pinned into our stage dir or it pollutes/depends-on the user's.

### Bundling Playwright **firefox** for fully-offline deployments (the plan)
Firefox is the pragmatic choice — lotek's BusyBody already found bundled **chromium fails
to install on newer distros while firefox works**. Recipe:
1. **Build time, per target platform** (browsers are OS-specific — this is the sharp part):
   `PLAYWRIGHT_BROWSERS_PATH=<payload>/vendor/ms-playwright uv run playwright install firefox`
   → lays firefox + the matching driver under the payload. Bundle that tree.
2. **Runtime**: launcher sets `PLAYWRIGHT_BROWSERS_PATH=<stage>/vendor/ms-playwright` (into
   our stage, never the user's cache) and `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` so it never
   phones home. No `post_install` needed → truly offline first run.
3. **Version lock**: the firefox build and the `playwright` python package version are
   coupled — pin both in the lock so they match, or Playwright refuses the browser.
4. **CROSS-PLATFORM DOWNLOAD CORNER**: `playwright install` fetches for the *host* OS. To
   bundle *Windows* firefox from a Linux build box you must fetch the Windows build
   explicitly (Playwright's browser CDN is per-OS; drive it with a matching
   `PLAYWRIGHT_DOWNLOAD_HOST`/manual fetch, or run the install step on/for the target OS).
   This is exactly the per-(OS,arch) rule from §D applied to browsers. Size: firefox ~85MB
   → strongly consider **external-payload/sidecar mode** so the signed exe stays lean.
5. On Windows, headed firefox needs no system deps; on Linux, headless is fine but headed
   needs X/GTK libs — document per-target.

## C. Post-install steps — GENERAL mechanism
Many projects need a one-time step after install, before first real run:
`playwright install`, `python -m spacy download`, `nltk.download`, building a Cython/
Rust ext, `flask db upgrade`, `prisma generate`, downloading a model, compiling shaders.
- Manifest `post_install: [[argv], ...]` — each run once via `uv run` in the app env,
  sentinel `.postinstall-done` written after all succeed (implemented in M0).
- Must be: idempotent, resumable (partial failure re-runs), offline-aware (fail loud with
  a clear message if network is needed and absent), and progress-reported.
- Open question: some steps write to *other* user dirs (playwright cache, HF hub). Policy:
  redirect via env into the stage dir where possible; document the ones we can't contain.

## D. Native / compiled extensions (numpy, pandas, cryptography, pillow, pydantic-core)
- uv installs prebuilt wheels → works, but the wheel is **platform + arch + python-ABI
  specific**. The bundle is therefore per-(OS,arch,pyver). Cross-building a Windows bundle
  from Linux means resolving *Windows* wheels (`uv ... --python-platform windows`) and a
  Windows standalone python — resolve on/for the target, don't reuse Linux wheels.
- Cache portability caveat (research/02): warm cache / build venv on the target platform.

## E. Data files, templates, assets adjacent-vs-bundled
- Bundled assets (templates, static/) live under the stage dir → resolve via
  `HARUPACK_STAGE` or `importlib.resources`, never `os.getcwd()`. Treat them as **read-only**.
- **Writable runtime data (a sqlite `.db`, logs, mutable config) must NOT live in the stage
  dir / adjacent to the script.** The stage is a content-addressed, hash-verified mirror of the
  payload: every bundled file is re-hashed on every run (INV-STAGE-01). So a bundled file the
  app opens **read-write in place** changes its hash, and the **next run refuses to launch** —
  `StageError: stage directory does not match this payload` — not merely "reset on upgrade". (A
  file the app *creates new* in the stage is unrecorded and ignored; it is *mutating a bundled
  file* that breaks reuse.)
- Put writable data next to the exe (`HARUPACK_EXE_DIR`), in a user data dir, or relative to
  the launch dir (cwd) — never the stage. A bundled db is a **read-only seed**: if the app must
  mutate it, copy it out to a writable location on first run.
- `haru-pack build` warns when it spots a writable-looking file (`*.db`, `*.sqlite*`, sqlite
  `-wal`/`-journal`) bundled with the code, so this is caught at build, not by a customer.
- Ship a tiny `haru-pack` runtime helper: `stage()`, `exe_dir()`, `data_dir()` so authors
  stop guessing.

Resolving the right folder (pathlib):

```python
import os
from pathlib import Path

# READ-ONLY seed shipped in the payload — never write here:
seed = Path(os.environ["HARUPACK_STAGE"]) / "app" / "seed.db"

# WRITABLE runtime data — pick one, then mkdir(parents=True, exist_ok=True):
home_dir   = Path.home() / ".yourapp"                                             # ~/.yourapp
data_dir   = Path(os.environ.get("XDG_DATA_HOME",   Path.home() / ".local/share")) / "yourapp"
config_dir = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))      / "yourapp"
beside_exe = Path(os.environ["HARUPACK_EXE_DIR"])                                  # next to the binary
launch_dir = Path.cwd()                                                            # where it was run

db = home_dir / "files.db"
db.parent.mkdir(parents=True, exist_ok=True)          # ~/.yourapp/files.db, created if absent
```

Cross-platform (Windows `%LOCALAPPDATA%`/`%APPDATA%`, macOS `~/Library`), let `platformdirs`
pick: `from platformdirs import user_data_dir; Path(user_data_dir("yourapp")) / "files.db"`.

## F. Games — asset compression + source protection
### Asset compression
- Payload is already a compressed container (zip/zstd). For a game:
  - Big assets (textures/audio/models): **per-asset zstd**, or keep them in the container
    and extract to the stage dir once (fast local mmap reads thereafter). zstd beats zip
    deflate on ratio + speed; a shared **zstd dictionary** helps many small similar files.
  - Don't recompress already-compressed assets (png/ogg/mp4) — store them.
  - Optional split: code payload appended to exe; big `assets.uvcap` sidecar (external-
    payload mode) so the signed exe stays small and AV-friendly.
### Source protection (be honest about the ceiling)
Local execution means **no true secret-keeping** — the machine must decrypt/run it, so a
determined attacker wins. You can only raise the bar. Ranked:
1. **Ship bytecode only** (`.pyc`, strip `.py`) — weak; decompilable, but stops casual eyes.
2. **Compile hot/secret modules to native** — Cython or **Nuitka** → `.pyd/.so`. Strong
   for those modules, and composes with the uv-run model (they're just installed wheels).
3. **Obfuscate** — pyarmor (works with uv/venv). Medium; raises effort.
4. **Encrypt the payload**, decrypt at runtime in the Nim stub. The key lives in the
   (signed) binary → this is obfuscation, not DRM: it stops file-copying, not RAM dumps or
   an attacker reading the decrypted stage dir. Extract to a locked temp dir + clean on
   exit to shrink the window; never claim it's unbreakable.
Recommendation for a game: **Nuitka-compile the engine/secret modules + store assets
compressed (optionally encrypted) in a sidecar**, and treat everything else as readable.
Real IP protection wants a server component, not client-side crypto.

## G. Cross-cutting corners (always on the list)
- cwd vs `__file__` vs exe-dir (the three roots) — the #1 author mistake.
- First-run time/size (extraction + post-install) → splash/progress, or it looks hung.
- AV/SmartScreen on an unsigned self-extractor → sign (EV), or external-payload mode.
- Windows path length / reserved names / spaces in the download path.
- Antivirus locking files mid-extract (retry/backoff on the atomic rename).
- Multiple instances launching at once (concurrent stage race — handled by tmp+rename).
- Long-running servers vs one-shot scripts (signal forwarding, clean child teardown).

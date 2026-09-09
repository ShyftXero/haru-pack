# uvcannon — sharp corners catalog

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
  `UVCANNON_STAGE` or `importlib.resources`, never `os.getcwd()`.
- User data (save files, user config) belongs next to the exe (`UVCANNON_EXE_DIR`) or a
  user dir — never the stage dir (it's wiped on version change).
- Ship a tiny `uvcannon` runtime helper: `stage()`, `exe_dir()`, `data_dir()` so authors
  stop guessing.

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

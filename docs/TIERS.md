# haru-pack bundling tiers

How much is baked into the exe vs fetched on the target machine. Pick with a `build` flag.

| Tier | Flag | Bundled | Fetched on target | Size (hello) | Offline |
|------|------|---------|-------------------|--------------|---------|
| **thin** | `--thin` | nothing | uv + Python + deps | ~0.4 MB | no (needs net on 1st run) |
| **default** | *(none)* | uv | Python + deps | ~23 MB | no (net on 1st run) |
| **thick** | `--thick` / `--chonky` | uv + Python (+deps) | nothing | ~90 MB | **yes** |

> **Invariant: uv is bundled in every tier except `thin`.** haru-pack never assumes the
> target machine already has uv — no supported Ubuntu LTS ships it, Debian has no CLI
> package (its ITP has been open since 2024 and only `python3-uv-build` landed), and NixOS
> documents uv's interpreter fetching as problematic. `thin` is the sole opt-out and it pays
> for that with a first-run download. Enforced in code by `tiers.bundles_uv()`, which is the
> single source of truth for both the bundler and the manifest's `fetch_uv` flag.
> Background: `research/05` §4.9.

- **thin** — smallest artifact. On first run the launcher fetches the pinned uv release,
  then uv provisions Python + deps. The download is **one code path**: `puppy` (uses the
  OS-native TLS stack — **WinHTTP/Schannel** on Windows, **libcurl** on Linux/mac), so the
  target needs **no curl/wget/PowerShell** and the Windows exe carries **no openssl**.
  Archives extracted with `zippy` (zip + gzip'd tar) — no system `tar` either.
- **default** — the middle. uv is pre-bundled; Python + deps are resolved by uv on first
  run and cached in the stage dir. Good balance of size vs first-run speed.
- **thick** (a.k.a. **chonky** 🦣) — everything baked in: uv + a standalone Python
  (staged via `uv python install`) and, for projects, a prebuilt env. Downloads **nothing**
  at runtime (`UV_OFFLINE=1`). The launcher **discovers the bundled interpreter at runtime**
  (robust to uv's version-alias symlink dir, which the zip doesn't preserve).

## What thick does NOT carry
The bundled dependency cache holds the project's **runtime** resolution only. `uv sync`
installs the default dependency groups — `dev` among them — so this used to warm the cache
with the project's own test runner and build backend and ship them inside the signed binary
(11 dists / 6.5 MB on `examples/shake-demo`). A launcher runs the entrypoint, never the
suite. Those tools are still installed at build time, into the throwaway build env, so a
`[[bundle]]` step or a `--shake` observation run can execute them — just not from the
payload. `INV-PAYLOAD-03`.

## Making thick smaller: `--shake`
`--thick` bundles the resolved dependency closure, which is always larger than the set of
files the program opens. `haru-pack build ./proj --thick --shake` runs the project's
declared test command under a file-access tracer, drops what nothing touched, then rebuilds
from the pruned payload offline and re-runs the suite — failing the build if it does not
pass (`INV-SHAKE-01`). Measured on `examples/shake-demo`: 92.1 → 75.9 MB payload. The floor
is the bundled `uv` (~55 MB unpacked) plus CPython, so expect ~50-60 MB however hard you
shake; the big wins are projects whose dependencies dwarf that. Details, limits and the
config block: [`SHAKE.md`](SHAKE.md).

## Cross-compile notes (Linux → Windows)
- **thin / default**: fully supported from Linux. `haru-pack` fetches the **Windows** uv
  release when `--target windows` (uv binaries are per-OS), and the launcher links WinHTTP
  for the runtime fetch — no openssl.
- **thick + `--target windows` from Linux**: **supported for wheel-only projects** (verified
  under wine, offline). haru-pack bundles a Windows standalone Python (python-build-standalone,
  via uv's catalog), Windows uv, and Windows wheels (`uv pip install --python-platform windows
  --only-binary :all:`); the venv builds at first run on Windows from the bundled cache.
  Bundle/`post_install` steps that must **execute** target-native code (`playwright install
  firefox`, C/Rust builds): pass **`--wine`** to run them under wine with the bundled Windows
  Python (verified: a step's output is baked into the Windows exe from Linux). The tool must
  run under wine — Playwright's Node driver is flaky under wine, so for Playwright build
  thick on Windows or use a `[[post_install]]` with `os=["windows"]` instead.

## Manifest fields set by the tier
`tier`, `offline`, `fetch_uv`, `uv_version` (thin). The interpreter for thick is
auto-detected at runtime, not pinned in the manifest.

## Example: bundled Playwright + Firefox (offline)
`examples/playwright-shot` — a project that screenshots a page with **Firefox**, built
fully offline with `--thick`:
```sh
haru-pack build examples/playwright-shot/payload --thick -o shot
./shot                      # extracts once, launches BUNDLED firefox, writes shot.png
```
Thick with `bundle_browsers: ["firefox"]` in the manifest makes `haru-pack`: stage a
standalone Python, warm a uv cache with the project deps (so the venv builds offline at
runtime), and run `playwright install firefox` into `vendor/ms-playwright`. At runtime the
launcher sets `PLAYWRIGHT_BROWSERS_PATH` into the stage + `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`
— zero network. Verified: ~245 MB exe, produces a 1280×720 PNG with `PATH=/usr/bin` and no
network. (Headed Firefox on Linux needs GTK/X libs; headless is self-contained. Cross to
Windows: build `--thick` on Windows.)

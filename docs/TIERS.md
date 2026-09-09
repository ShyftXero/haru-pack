# haru-pack bundling tiers

How much is baked into the exe vs fetched on the target machine. Pick with a `build` flag.

| Tier | Flag | Bundled | Fetched on target | Size (hello) | Offline |
|------|------|---------|-------------------|--------------|---------|
| **thin** | `--thin` | nothing | uv + Python + deps | ~0.4 MB | no (needs net on 1st run) |
| **default** | *(none)* | uv | Python + deps | ~23 MB | no (net on 1st run) |
| **thick** | `--thick` / `--chonky` | uv + Python (+deps) | nothing | ~90 MB | **yes** |

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

## Cross-compile notes (Linux → Windows)
- **thin / default**: fully supported from Linux. `haru-pack` fetches the **Windows** uv
  release when `--target windows` (uv binaries are per-OS), and the launcher links WinHTTP
  for the runtime fetch — no openssl.
- **thick + `--target windows` from Linux**: **partial (roadmap).** Deps and the Python
  interpreter *are* cross-downloadable — `uv pip install --python-platform windows
  --python-version 3.12 --only-binary :all: --target <dir>` pulls Windows wheels (incl.
  native `.pyd`, verified), and python-build-standalone Windows is a plain download; ship
  them and let uv build the venv at first run on Windows. The blocker is bundle/post_install
  steps that must **run target-native code** (e.g. `playwright install firefox`): from Linux
  those need **wine** or by-URL fetching. So today build `--thick --target windows` **on
  Windows**; a wheel-only thick-cross is feasible and planned.

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

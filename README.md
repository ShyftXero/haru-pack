# haru-pack

Pack a Python project — a **PEP 723 script** or a full **multi-folder project** (Flask,
Playwright, …) — into a single, **EV-signable native launcher** that stages `uv` + a
standalone Python and runs it **as if it were a compiled binary in the folder it was
launched from**. Windows-first, cross-compiled from Linux. Built on `uv`; launcher in Nim.

> Think PyInstaller's UX, but the interpreter + deps are delegated to `uv`, the launcher is
> a thin signable native stub, and you choose how much is bundled vs fetched on the target.

## Install
```sh
pip install haru-pack            # or:  uvx haru-pack ...
haru-pack bootstrap              # installs Nim (+zippy, puppy, parsetoml, nimcrypto) & checks the C toolchain
```

## Quickstart
```sh
# a PEP 723 script or a project dir with a manifest.toml (see below)
haru-pack build ./myproject                 # default tier: uv bundled, deps fetched 1st run
./myproject                                 # run it — behaves like a native binary

haru-pack build ./myproject --thin          # smallest; fetch uv+python+deps on target
haru-pack build ./myproject --thick         # bundle everything, fully offline (chonky 🦣)
haru-pack build ./myproject --target windows -o app.exe   # cross-compile Linux -> Windows
```

## Commands
| Command | What |
|---|---|
| `haru-pack build <dir>` | build a single-file launcher from a payload dir |
| `haru-pack bootstrap` | install Nim + launcher deps; verify the C toolchain |
| `haru-pack doctor` | check Nim / C toolchain (prints the mingw install cmd if missing) |
| `haru-pack verify <exe>` | inspect the footer + confirm payload integrity |
| `haru-pack machine-id` | print this machine's id (for `--machine` license binding) |
| `haru-pack version` | version |

## `build` flags
| Flag | Default | Meaning |
|---|---|---|
| `-o, --out PATH` | `<name>[.exe]` | output path |
| `--target host\|windows` | `host` | build target (Windows = cross-compile) |
| `--tier thin\|default\|thick` | `default` | bundling tier (below) |
| `--thin` | | shortcut for `--tier thin` |
| `--thick` / `--chonky` | | shortcut for `--tier thick` |
| `--encrypt` | off | AES-256-GCM encrypt the payload |
| `--secret TEXT` | | secret (key material) literal |
| `--secret-env VAR` | | read the secret from env var `VAR` at build |
| `--secret-prompt` | | prompt for the secret at build |
| `--embed-secret` | off | embed the secret in the exe (weakest; no runtime secret needed) |
| `--expires YYYY-MM-DD` | | license expiry |
| `--machine ID` | | bind cryptographically to a machine id (`haru-pack machine-id`) |
| `--user NAME` | | bind cryptographically to an OS username |
| `--geo CC,CC` | | allowed country codes |

`bootstrap` / `doctor` take `--target host|windows`; `bootstrap` also `--force`.

## Tiers
| Tier | Bundled | Fetched on target | Offline | Cross-compile |
|---|---|---|---|---|
| `--thin` | nothing | uv + Python + deps | no | yes |
| default | uv | Python + deps | no | yes |
| `--thick` | uv + Python (+deps/browsers) | nothing | **yes** | **no** (build on target OS) |

**Why no thick cross-compile:** the launcher cross-compiles fine, but thick bakes in
*target-OS* artifacts — a runnable standalone Python, native wheels, and any
bundle/post-install output (e.g. Playwright's Firefox) — which can only be produced by
running the target's toolchain. `uv python install` stages a host-OS interpreter, and a
Linux `playwright install firefox` fetches Linux Firefox. thin/default defer all of that to
first run on the target, so they cross-compile. Build `--thick` **on the target OS**.

## manifest.toml (projects)
Minimal:
```toml
name = "myapp"
kind = "project"                 # "script" | "project"
app_subdir = "app"
entrypoint = ["python", "-m", "myapp"]   # string (script) or argv (command)
cwd_policy = "exe"               # "launch" (native cwd, default) | "exe" (always exe-adjacent)
```
Declare build-time bundling and OS-specific run-once hooks (full reference:
[docs/MANIFEST.md](docs/MANIFEST.md)):
```toml
[[bundle]]                       # run at build, bake output into the exe (thick)
run = ["playwright", "install", "firefox"]
into = "vendor/ms-playwright"
[bundle.env]
PLAYWRIGHT_BROWSERS_PATH = "{into}"     # {into} -> stage dir at runtime
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1"

[[post_install]]                 # run once on target; os-filtered by the compiled stager
os = ["windows"]
run = ["playwright", "install", "firefox"]
```

## Runtime environment (set for your code)
| Var | Meaning |
|---|---|
| `HARUPACK_EXE_DIR` | folder the shipped exe lives in (find config next to the exe) |
| `HARUPACK_STAGE` | the extraction/stage dir (bundled resources) |
| `HARUPACK_SECRET` | (you set) license secret for an `--encrypt` build |
| `HARUPACK_GEO` | (you set) current country code for the geo check |

`open("file.txt")` follows the process cwd like a native binary; use `cwd_policy = "exe"`
to make relative paths always resolve next to the shipped exe. Never use `__file__` for
user data — the code lives in the stage dir.

## Docs
- [docs/MANIFEST.md](docs/MANIFEST.md) — full manifest reference
- [docs/TIERS.md](docs/TIERS.md) — bundling tiers + the Playwright example
- [docs/SIGNING.md](docs/SIGNING.md) — Windows EV code signing (cross-platform)
- [docs/ENCRYPTION_LICENSING.md](docs/ENCRYPTION_LICENSING.md) — `--encrypt` + license checks
- [docs/PUBLISHING.md](docs/PUBLISHING.md) — publishing to PyPI
- [docs/PLAN.md](docs/PLAN.md) · [docs/SHARP_CORNERS.md](docs/SHARP_CORNERS.md) · [docs/BRAINSTORM.md](docs/BRAINSTORM.md) · [research/](research/)

## Status
Alpha. Core verified on Linux (host + Windows cross-compile): run-in-place UX, CLI
fidelity, all three tiers, EV-signable output, offline Playwright+Firefox, and encryption
+ license checks.

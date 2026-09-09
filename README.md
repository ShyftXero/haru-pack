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
# point at a PEP 723 script or a project dir (with pyproject.toml). haru-pack auto-discovers
# the kind, Python version (requires-python / .python-version / PEP 723), and entrypoint.
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
| `--python X.Y` | auto | Python version to stage (else discovered from the project) |
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
| `--thick` | uv + Python (+deps/browsers) | nothing | **yes** | wheel-only ✓ / exec-steps: build on target |

**Thick cross-compile (Linux → Windows) — supported for wheel-only projects.**
`haru-pack build ./proj --target windows --thick` bundles a Windows standalone Python
(python-build-standalone), Windows uv, and Windows wheels (`uv pip install
--python-platform windows --only-binary :all:`), and the venv builds at first run on
Windows from the bundled cache. Verified end-to-end under wine (offline). The remaining
limit: bundle/`post_install` steps that must **execute target-native code**
(`playwright install firefox`, C/Rust source builds) can't be produced cross — build those
on the target OS (or run them under wine / fetch the binaries by URL).

## haru_pack.toml (optional declarations)
haru-pack discovers most things from your project. Add a `haru_pack.toml` at the project
root only to override or declare extras (full reference: [docs/CONFIG.md](docs/CONFIG.md)):
```toml
cwd_policy = "exe"               # "launch" (native cwd, default) | "exe" (always exe-adjacent)
entrypoint = ["python", "-m", "myapp"]   # override the discovered entrypoint
python = "3.12"                  # override the staged Python version

[encryption]                     # same fields as the --encrypt flags (secret via CLI/env only)
enabled = true
expires = "2027-01-01"
geo = ["US", "CA"]
```
Build-time bundling and OS-specific run-once hooks:
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
- [docs/CONFIG.md](docs/CONFIG.md) — haru_pack.toml reference + discovery
- [docs/TIERS.md](docs/TIERS.md) — bundling tiers + the Playwright example
- [docs/SIGNING.md](docs/SIGNING.md) — Windows EV code signing (cross-platform)
- [docs/ENCRYPTION_LICENSING.md](docs/ENCRYPTION_LICENSING.md) — `--encrypt` + license checks
- [docs/PUBLISHING.md](docs/PUBLISHING.md) — publishing to PyPI
- [docs/PLAN.md](docs/PLAN.md) · [docs/SHARP_CORNERS.md](docs/SHARP_CORNERS.md) · [docs/BRAINSTORM.md](docs/BRAINSTORM.md) · [research/](research/)

## Status
Alpha. Core verified on Linux (host + Windows cross-compile): run-in-place UX, CLI
fidelity, all three tiers, EV-signable output, offline Playwright+Firefox, and encryption
+ license checks.

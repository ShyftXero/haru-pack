# haru-pack

Pack a Python project — a **PEP 723 script** or a full **multi-folder project** (Flask,
Playwright, …) — into a single, **signable native launcher** that stages `uv` + a
standalone Python and runs it **as if it were a compiled binary in the folder it was
launched from**. Windows-first, cross-compiled from Linux. Built on `uv`; launcher in Nim.

> Think PyInstaller's UX, but the interpreter + deps are delegated to `uv`, the launcher is
> a thin signable native stub, and you choose how much is bundled vs fetched on the target.

## TL;DR

```sh
pip install haru-pack
haru-pack bootstrap          # installs Nim via choosenim; at most one sudo prompt
haru-pack yourscript.py      # -> ./yourscript, a single native binary
./yourscript
```

That is the whole thing. Point it at a script or a project directory and a binary appears.

What you get: one file, no Python required on the target, runs from whatever folder it is
in. Ship it like a compiled program.

```sh
haru-pack ./myproject                              # project dir with a pyproject.toml
haru-pack ./myproject --thick                      # bundle everything, zero network at runtime
haru-pack ./myproject --target windows -o app.exe  # cross-compile from Linux
haru-pack ./myproject --target linux-aarch64       # Raspberry Pi
```

If a project declares more than one console script, haru-pack stops and asks rather than
guessing:

```sh
haru-pack ./lotek --out lotek --entry-point "app.cli:main"
```

## Install

```sh
pip install haru-pack            # or:  uvx haru-pack ...
haru-pack bootstrap              # Nim via choosenim + verify the C toolchain
haru-pack init ./myproject       # optional: write a haru_pack.toml you can edit
```

`bootstrap` installs Nim into haru-pack's own directory. Your system Nim and your
`~/.nimble` are left alone. The only thing it asks sudo for is a C compiler, and it asks
once, showing you the exact command first.

Building for another machine? Ask for it up front and the same single prompt covers it:

```sh
haru-pack bootstrap --target linux-aarch64      # also gets the ARM cross-compiler
```

## Decisions

Short version of why this works the way it does.

**uv does the Python part.** Interpreters, dependency resolution, and virtualenvs are
solved problems. haru-pack stages a `uv` binary and gets out of the way, rather than
reimplementing an installer.

**The launcher is Nim.** It has to be a real native executable that Windows will let you
Authenticode-sign, and it has to cross-compile from Linux without a Windows machine. Nim
compiles to C and does both. It is a ~500-line stub, not an application.

**Three tiers, because "one binary" means different things.** `--thin` bundles nothing and
fetches on first run. Default bundles `uv` and fetches Python + deps once. `--thick`
bundles everything and touches no network at all. Pick by what your target is allowed to
reach, not by what is smallest.

**One code path, not two.** Host and cross builds download the same artifacts the same way.
Where there used to be a fork — a "fast path" for the host — the fast path was the
unverified one, and it was the path almost everyone took. Nim is installed exactly one way
(choosenim); there is no archive fallback and no build-from-source fallback.

**Everything downloaded is pinned.** `uv`, the Python interpreter, and choosenim are all
checked against a SHA-256 in [`src/haru_pack/pins.toml`](src/haru_pack/pins.toml) before
they are unpacked. No pin means the build refuses — it does not fall back to trusting TLS.
Digests come from the publisher's own sidecar or release API, never from hashing whatever a
server happened to send. `tools/add-pin.py` does this for you.

**Mirrors change where, never whether.** If you cannot reach github.com, point `[sources]`
at a mirror. The pin is chosen by the artifact's upstream identity *before* the URL is
rewritten, so a hostile mirror gets you a failed build, not a compromised one.

**ARM Linux is a target, not a build host.** choosenim publishes no ARM Linux binary, so
you build Pi binaries on an x86_64 machine with `--target linux-aarch64`. You never need a
toolchain on the Pi.

**It refuses instead of guessing.** Ambiguous entrypoint, missing digest, unknown target,
malformed `--entry-point`: all of these stop the build. A wrong guess here compiles
cleanly, exits 0, and fails on the customer's machine — which is the worst place to find
out.

**Claims are tested, not asserted.** [`INVARIANTS.md`](INVARIANTS.md) lists what must not
regress, each with a *red-path*: the exact edit that makes its test fail. `pytest -m
invariant` enforces that every `active` entry has a test and every `proposed` entry does
not. This exists because an audit found five documented, dated "Verified" security claims
in this repo that were never implemented.

## Commands
| Command | What |
|---|---|
| `haru-pack init [dir]` | scaffold a `haru_pack.toml` (learns from pyproject + any venv) |
| `haru-pack build <dir>` | build a single-file launcher from a project or script |
| `haru-pack bootstrap` | install Nim + launcher deps; verify the C toolchain |
| `haru-pack doctor [dir]` | check Nim / C toolchain; scan a project for needed bundle/install steps |
| `haru-pack verify <exe>` | inspect the footer + confirm payload integrity |
| `haru-pack machine-id` | print this machine's id (for `--machine` license binding) |
| `haru-pack version` | version |

## `build` flags
| Flag | Default | Meaning |
|---|---|---|
| `-o, --out PATH` | `<name>[.exe]` | output path |
| `-e, --entry-point SPEC` | discovered | what to run: `app.py`, a console script (`lotek`), or `module:callable` (`app.cli:main`) |
| `--target host\|<os>-<arch>` | `host` | e.g. `linux-aarch64` (Raspberry Pi), `windows-x86_64`, `macos-aarch64` |
| `--python X.Y` | auto | Python version to stage (else discovered from the project) |
| `--wine` | off | run execute-required bundle steps under wine (thick + `--target windows`) |
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

`bootstrap` takes repeatable `--target`, plus `--yes` and `--force`. `doctor` takes `--target`.

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
- [INVARIANTS.md](INVARIANTS.md) — properties that must not regress, each with a red-path.
  `pytest -m invariant` checks that every `active` one is claimed by a test.
- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, actors, trust boundaries, and what the
  licensing feature does and does not actually enforce
- [docs/CONFIG.md](docs/CONFIG.md) — haru_pack.toml reference + discovery
- [docs/TIERS.md](docs/TIERS.md) — bundling tiers + the Playwright example
- [docs/SIGNING.md](docs/SIGNING.md) — Windows Authenticode code signing (cross-platform)
- [docs/ENCRYPTION_LICENSING.md](docs/ENCRYPTION_LICENSING.md) — `--encrypt` + license checks
- [docs/FLEX.md](docs/FLEX.md) — the flex harness: top-25 breadth + hard targets
- [docs/RELEASING.md](docs/RELEASING.md) — cutting a release (`./scripts/cut-release.sh`)
- [docs/PUBLISHING.md](docs/PUBLISHING.md) — publishing to PyPI
- [docs/PLAN.md](docs/PLAN.md) · [docs/SHARP_CORNERS.md](docs/SHARP_CORNERS.md) · [docs/BRAINSTORM.md](docs/BRAINSTORM.md) · [research/](research/)

## Status
Alpha. Core exercised on Linux (host + Windows cross-compile): run-in-place UX, CLI
fidelity, all three tiers, signable output, offline Playwright+Firefox, and encryption
+ license checks.

Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on `--encrypt` for anything
commercial. What the licensing feature does and does not enforce:

- **Machine and user binding are cryptographic.** The identity is folded into the KDF, so a
  different machine id yields a different key and decryption fails. Note that
  `/etc/machine-id` is a writable file, so this binds to a value the target *reports*.
- **`--expires` and `--geo` are not enforcement.** Geo reads `HARUPACK_GEO` — an environment
  variable set by the person being restricted — and expiry reads their clock. Both run after
  decryption inside a binary they control.
- **The launcher verifies its payload digest before staging or executing**
  ([`INV-LAUNCH-01`](INVARIANTS.md)), but that digest is **not a MAC**: it lives in the same
  footer an attacker would edit, so someone who modifies the payload can recompute it. Real
  tamper-evidence needs a signature ([`INV-LAUNCH-03`](INVARIANTS.md), not yet implemented),
  or Authenticode on a signed Windows build.

## Prior art
haru-pack is not the first tool to stage `uv` from a native launcher.
[`ofek/pyapp`](https://github.com/ofek/pyapp) established the shape (and
[Hatch](https://hatch.pypa.io/latest/plugins/builder/binary/) builds on it);
[`PyCrucible`](https://github.com/razorblade23/PyCrucible) independently arrived at
embedding uv and extracting beside the executable; [`pex --scie`](https://docs.pex-tool.org/scie.html)
and the [a-scie](https://github.com/a-scie/lift) project named the eager/lazy bundling split
that our tiers rediscover. `research/05-uv-as-distribution-prior-art.md` credits the field
in full and records which ideas we borrowed from whom.

# haru-pack

haru-pack (하루팩)

"Haru" (하루) means "day,"
"Pack" (팩) means "pack."

If you're shipping your code off on a little adventure you might send it with a ***day***...***pack***... get it?

you can just call it `haru` for short.

Pack a Python project — a **PEP 723 script** or a full **multi-folder project** (Flask,
Playwright, …) — into a single, **signable native launcher** that stages `uv` + a
standalone Python and runs it **as if it were a compiled binary in the folder it was
launched from**. Windows-first, cross-compiled from Linux. Built on `uv`; launcher in Nim.

## Why is this even here.

I love python.

I don't like most other programming languages... idk why, I'm lazy and stubborn.

You might find yourself asking "how is this even a modern Python project if it's not written primarily in a language other than Python?!? Where's the Rust?" and that is a fair set of questions.

idk if it is a modern Python project... there is no Rust at the top layer, anyway.

I do know that the ergonomics and sharp corners of other projects left me always a bit disappointed. I love Nuitka. I really love uv. I like pyinstaller. I also like Nimlang even though it's not python. (something about it appeals to me. that'll matter in a bit)

uv really changed how I approach python development. The way you use it made sense to me so there didn't feel like quite the cognitive barrier to get over. Just the simple venv helpers did a lot to help me maintain healthier projects. The fact that I could rapidly try new python versions without risking breaking something was awesome. I appreciated Anaconda for that but it was large and had this parallel ecosystem.

I saw uv and saw what I thought could be the future of sharing my code with others. They had figure out the "getting python on the computer problem". To be fair, pyinstaller was doing this over a decade ago. Nuitka as well. but they always felt "less-than" somehow.

I wanted a tool that could offer some degree of source protection and delivery while being "comfortable" for my smooth brain.

This is my attempt at also feeling "less-than". Made possible by AI. Thanks, Claude!

Now it's got far too many flags to remember but I don't need to remember them because my agent can just re-learn it for me anytime I need to know.

## AI Disclaimer

This project was engineered with AI but that doesn't necessarily mean it's slop. Care was taken to ensure that it's robust, built with consistent standards, and able to withstand some adversarial pressure. That being said, it might also be slop. Buyer beware. I believe we should be building tools that will outlast the AI bubble. Build the tools that will continue to work when we can no longer afford to throw tokens at the problem. I'm capitalizing on that now and building the tools using AI while I still have access to it. Come with me if you want to live.

> Think PyInstaller's UX, but the interpreter + deps are delegated to `uv`, the launcher is
> a thin signable native stub, and you choose how much is bundled vs fetched on the target.

## TL;DR

```sh
uv tool install haru-pack
haru bootstrap               # installs Nim via choosenim
haru yourscript.py           # -> ./yourscript, a single native binary
./yourscript
```

`haru` and `haru-pack` are the same program — both are installed, so use whichever you feel
like typing. The rest of this README says `haru-pack` because that is the package name, and
the tool prints back whichever one you actually used.

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
guessing but you can also specify its entry-point:

```sh
haru-pack ./lotek --out lotek --entry-point "app.cli:main"
```

## Install

```sh
uv tool install haru-pack        # or:  pip install haru-pack / uvx haru-pack ...
haru-pack bootstrap              # Nim via choosenim + the pinned zig compiler
haru-pack init ./myproject       # optional: write a haru_pack.toml you can edit
```

`bootstrap` installs Nim **and** the default C compiler — a pinned `zig` — into haru-pack's
own directory. Both are plain downloads verified against a digest; your system Nim, your
`~/.nimble`, and your system compilers are left alone, and neither needs sudo. That is the
point of the zig default: `uv tool install haru-pack && haru-pack bootstrap` is the whole
setup, with nothing for the package manager to do (`INV-TOOL-02`).

You only reach for sudo if you opt out with `--cc system`: then the host C compiler, the
cross toolchains, and wine are ordinary system packages. Those are still worked out first,
so bootstrap asks once and shows you the exact command before running it.

By default it installs **everything this host can**: that is the point of the kitchen sink,
and it means you do not discover a missing cross-compiler three commands into a release.
None of it is compulsory — see the flags below, or `haru-pack bootstrap --list` to look
first. `INV-TOOL-01`.

Building for another machine? Ask for it up front and the same single prompt covers it:

```sh
haru-pack bootstrap                            # everything this host can install
haru-pack bootstrap --minimal                  # Nim only; zig arrives on first build
haru-pack bootstrap --target linux-aarch64     # exactly that, nothing else
haru-pack bootstrap --without wine             # everything except wine
haru-pack bootstrap --list                     # see what is available and what it costs
```

## Decisions

Short version of why this works the way it does.

**User ergonomics is of the utmost importance — and "user" means three people.** Whoever
works on haru-pack; the developer running `haru-pack build`; and the person who receives the
packed executable and has never heard of uv, Python, or this tool. The third is the one who
gets no error message — only "it worked" or "it didn't" — and they are why every decision
below leans on refusing at build time rather than failing on their machine. When the three
conflict, the last one wins. Full statement: [`docs/PRINCIPLES.md`](docs/PRINCIPLES.md).

**uv does the Python part.** Interpreters, dependency resolution, and virtualenvs are
solved problems. haru-pack stages a `uv` binary and gets out of the way, rather than
reimplementing an installer.

**The launcher is Nim.** It has to be a real native executable that Windows will let you
Authenticode-sign, and it has to cross-compile from Linux without a Windows machine. Nim
compiles to C and does both. It is a ~500-line stub, not an application. Why not port it to Zig, since a `zig cc` is already pinned for cross-compiling? Costed and declined in [`docs/COMMON_CRITIQUES.md`](docs/COMMON_CRITIQUES.md).

**Three tiers, because "one binary" means different things.** `--thin` bundles nothing and
fetches on first run. Default bundles `uv` and fetches Python + deps once. `--thick`
bundles everything and touches no network at all. Pick by what your target is allowed to
reach, not by what is smallest.

**Encryption protects the binary at rest; it cannot protect a secret from someone who runs
it.** The launcher stages the payload to disk in plaintext so the interpreter can run it, and
any user who can run the binary can read that staged source from their own cache. `--obfuscate`
(pyarmor by default, modular) raises the *cost* of reading it — it is not a confidentiality
boundary. A secret that must never leak must never be shipped in an artifact the client holds;
put it behind a server the client authenticates to. haru-pack states this plainly rather than
implying that "encrypted binary" means the embedded key is safe. See INV-SECRET-02 / INV-OBF-01
and the busybody `reverse_engineer` persona, which proves each edge rather than asserting it.

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

**The bundled uv is compressed, not packed.** `uv` is the biggest thing in any non-thin
payload and the payload zip only has DEFLATE, so uv ships XZ-compressed (55.59 → 14.17 MB
vs 22.25 MB deflated) and the launcher expands it during staging — about 8 MB off every
default and thick binary. The launcher expands it and checks the result against the digest
the build recorded, refusing a mismatch — so what runs is the publisher's binary, and
recorded in the stage manifest like everything else, which is precisely why this is not UPX:
packing modifies the executable, destroying uv's own signature, matching no publisher digest,
tripping AV packer heuristics, and paying the cost on every launch instead of once. The
decoder is decoder-only vendored C from xz-embedded, no target-side library.
[`docs/TIERS.md`](docs/TIERS.md).

**Thick can be shaken, on evidence, never on a guess.** `--shake` runs the project's own
test suite under a file-access tracer, keeps the bundled files it touched, then rebuilds the
environment from the pruned payload and re-runs the suite — and fails the build if that
does not pass. The observation is syscall-level rather than line coverage, because the
megabytes are in shared libraries `dlopen`ed from C extensions and in data files, neither of
which coverage can see. It refuses to run without a declared test command, keeps the static
closure of every lazy import, and writes down every file it removed. A passing suite is
evidence about the suite, not the program, so this is opt-in and the receipt is the point.
[`docs/SHAKE.md`](docs/SHAKE.md).

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
| `--shake` | off | thick only: run the project's tests under a file tracer, drop bundled files nothing touched, and refuse to ship if the suite then fails ([`docs/SHAKE.md`](docs/SHAKE.md)) |
| `--shake-keep GLOB` | | never prune paths matching `GLOB` (repeatable) |
| `--encrypt` | off | AES-256-GCM encrypt the payload |
| `--secret TEXT` | | secret (key material) literal |
| `--secret-env VAR` | | read the secret from env var `VAR` at build |
| `--secret-prompt` | | prompt for the secret at build |
| `--embed-secret` | off | embed the secret in the exe (weakest; no runtime secret needed) |
| `--obfuscate ENGINE` | `none` | obfuscate the source before packing: `none` \| `pyarmor`. Independent of `--encrypt`; wants `--thick` |
| `--obfuscate-args "…"` | | extra args passed through to the obfuscation engine |
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
python = "3.13"                  # override the staged Python version (this is the default)

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
| `HARU_SECRET` | (you set) license secret for an `--encrypt` build — default SECRET-knob canary; `--env-canary` / `--stub-env-secret-canary` change the prefix (INV-CANARY-01) |
| `HARUPACK_GEO` | (you set) current country code for the geo check |

`open("file.txt")` follows the process cwd like a native binary; use `cwd_policy = "exe"`
to make relative paths always resolve next to the shipped exe. Never use `__file__` for
user data — the code lives in the stage dir.

## Docs
- [INVARIANTS.md](INVARIANTS.md) — properties that must not regress, each with a red-path.
  `pytest -m invariant` checks that every `active` one is claimed by a test.
- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, actors, trust boundaries, and what the
  licensing feature does and does not actually enforce
- [docs/PRINCIPLES.md](docs/PRINCIPLES.md) — the one guiding principle, who the three
  "users" are when they conflict, and the no-god-modules rule that falls out of the first
  of them
- [docs/CONFIG.md](docs/CONFIG.md) — haru_pack.toml reference + discovery
- [docs/TIERS.md](docs/TIERS.md) — bundling tiers + the Playwright example
- [docs/SHAKE.md](docs/SHAKE.md) — `--shake`: pruning a thick payload on traced evidence,
  and what a passing test suite does and does not prove
- [docs/SIGNING.md](docs/SIGNING.md) — Windows Authenticode code signing (cross-platform)
- [docs/ENCRYPTION_LICENSING.md](docs/ENCRYPTION_LICENSING.md) — `--encrypt` + license checks
- [docs/FLEX.md](docs/FLEX.md) — the flex harness: top-25 breadth + hard targets
- [docs/BUSYBODY.md](docs/BUSYBODY.md) — chaos testing: the personas and how to read a report
- [docs/BUSYBODY-SCHEMA.md](docs/BUSYBODY-SCHEMA.md) — the on-disk contract for what a
  chaos run writes: journal line, finding record, ledger rollup
- [docs/BUSYBODY-PROTOCOLS.md](docs/BUSYBODY-PROTOCOLS.md) — what this harness would need
  from a shared core, and the assumptions it makes that one would have to allow
- [docs/BUSYBODY-TRANSFER.md](docs/BUSYBODY-TRANSFER.md) — the append-only log of ideas
  moved between this harness and lotek's, including the declined ones
- [docs/BUSYBODY-SHRINKING-SPIKE.md](docs/BUSYBODY-SHRINKING-SPIKE.md) — a costed and
  **declined** `ddmin`, kept for the two findings that outlived the verdict
- [docs/RELEASING.md](docs/RELEASING.md) — cutting a release (`./scripts/cut-release.sh`)
- [docs/PUBLISHING.md](docs/PUBLISHING.md) — publishing to PyPI
- [docs/adr/](docs/adr/) — architecture decision records (stub-config + canary, reap +
  RAM staging)
- [docs/UV_FREE_THICK.md](docs/UV_FREE_THICK.md) — a costed and **declined** design, kept so
  it is not rediscovered from scratch
- [docs/ZIG_TOOLCHAIN.md](docs/ZIG_TOOLCHAIN.md) — why the **default** compiler is one bundled
  `zig cc` instead of four system cross-compilers: the evidence, the shim, the byte-for-byte KAT
- [docs/COMMON_CRITIQUES.md](docs/COMMON_CRITIQUES.md) — fair objections answered once with
  evidence: why Nim **and** the zig compiler (not a Zig rewrite), where's the Rust, why not PyInstaller
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

### Packing a tree you did not write is running it

`haru-pack build .` is not a read-only operation on your source. At `--thick` it resolves
and installs your project, which calls its build backend. A `[[bundle]]` step in
`haru_pack.toml` runs at build time with your environment. A symlink in the tree is followed
out of it. A `[tool.uv] index-url` in the project decides where the wheels inside your signed
binary came from.

All of that is fine for your own repository and is how the features work. It is **not** fine
for a repository you cloned, a branch that arrived in CI, or an application an agent wrote
that nobody read. Today there is no boundary there at all: `INV-TRUST-01` through `-07` are
`proposed`, six of the seven were demonstrated by the busybody `trojan` persona on
2026-09-11, and none of them are defended yet. Treat packing an untrusted tree the way you
would treat running its `setup.py` — because you are.

## Prior art
haru-pack is not the first tool to stage `uv` from a native launcher.
[`ofek/pyapp`](https://github.com/ofek/pyapp) established the shape (and
[Hatch](https://hatch.pypa.io/latest/plugins/builder/binary/) builds on it);
[`PyCrucible`](https://github.com/razorblade23/PyCrucible) independently arrived at
embedding uv and extracting beside the executable; [`pex --scie`](https://docs.pex-tool.org/scie.html)
and the [a-scie](https://github.com/a-scie/lift) project named the eager/lazy bundling split
that our tiers rediscover. `research/05-uv-as-distribution-prior-art.md` credits the field
in full and records which ideas we borrowed from whom.

# haru-pack bundling tiers

How much is baked into the exe vs fetched on the target machine. Pick with a `build` flag.

| Tier | Flag | Bundled | Fetched on target | Size (hello) | Offline |
|------|------|---------|-------------------|--------------|---------|
| **thin** | `--thin` | nothing | uv + Python + deps | ~0.4 MB | no (needs net on 1st run) |
| **default** | *(none)* | uv | Python + deps | ~15 MB | no (net on 1st run) |
| **thick** | `--thick` / `--chonky` | uv + Python (+deps) | nothing | ~85 MB | **yes** |

> Both figures are ~8 MB smaller than they used to be because the bundled `uv` now ships
> XZ-compressed; see below. Both are measured, not derived: `hello` is **15.0 MB** at
> default tier and **85.4 MB** at thick (2026-09-11, linux-x86_64, Python 3.13). The thick
> figure read ~82 MB until 2026-09-11, which was the old number minus the saving rather
> than a measurement — caught by the documentation pass.

> **Invariant: uv is bundled in every tier except `thin`.** haru-pack never assumes the
> target machine already has uv — no supported Ubuntu LTS ships it, Debian has no CLI
> package (its ITP has been open since 2024 and only `python3-uv-build` landed), and NixOS
> documents uv's interpreter fetching as problematic. `thin` is the sole opt-out and it pays
> for that with a first-run download. Enforced in code by `tiers.bundles_uv()`, which is the
> single source of truth for both the bundler and the manifest's `fetch_uv` flag.
> Background: `research/05` §4.9.
>
> A thick tier needing no uv *at all* — shipping an installed dependency tree instead of a
> cache for uv to install from — was designed and costed on 2026-09-10 and **is not being
> pursued**. The reasoning, the measurements, and the finding that a prebuilt *venv* cannot
> be made to work cross-platform are in [`UV_FREE_THICK.md`](UV_FREE_THICK.md). Read that
> before reopening the question.

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

## The bundled uv is compressed, not packed
`uv` is the largest member of every non-thin payload, and the payload zip only has DEFLATE.
So it ships as `vendor/uv.xz` and the launcher expands it while staging. On uv 0.10.4
linux-x86_64: **55.59 MB raw → 22.25 MB deflated → 14.17 MB as XZ/LZMA2**, i.e. ~8 MB off
the finished binary. `INV-PAYLOAD-04`.

The staged `uv` is the publisher's binary, and two separate things make that true.
At build time `bundle_uv` verifies the release against the digest pinned in `pins.toml`
(`INV-SUPPLY-01`) and `compress_uv` compresses exactly those bytes. At stage time the
launcher expands the member and checks the result against the sha256 the build recorded
beside it, refusing the tree on a mismatch — measured digest `ae65ed04…` for uv 0.10.4
linux-x86_64 — and the expanded file is then recorded in `.stage-files` like every other
staged file.

Be precise about what the runtime check buys: it catches **corruption** — a truncated or
bit-rotted member, a mismatched size sidecar, a decoder bug. It does **not** defeat
tampering, because the digest sidecar sits next to the member an attacker would be
rewriting. Payload authenticity as a whole is `INV-LAUNCH-01`, still `proposed`. This
paragraph said "byte-identical to Astral's release" full stop until 2026-09-11, with
nothing at runtime behind it; an adversarial review called that out and `INV-PAYLOAD-04`
was narrowed to match the code.

That identity is why this is compression of a payload member rather than UPX-packing
the executable:
packing modifies the binary, which destroys uv's own code signature, makes the shipped
bytes match no publisher digest, trips the AV packer heuristics that target UPX most of
all, and pays decompression on *every* launch instead of once.

Cost: ~2.7 s of one-time expansion during the first run's staging, and ~100 s of
compression on the *build* host the first time a given uv version is seen (cached under the
user cache dir afterwards, keyed by input digest and preset). Decoding uses xz-embedded's
`XZ_SINGLE` mode, which uses the output buffer as its own dictionary — so there is no 64 MB
dictionary allocation, which is what makes it fine on a Raspberry Pi.

Cross-platform: the decoder is ~3 400 lines of vendored, decoder-only C from
[xz-embedded](https://github.com/tukaani-project/xz-embedded) (the one the Linux kernel
uses to boot XZ kernels), with no dependencies beyond `memcpy`. Verified compiling and
round-tripping byte-identically on Linux x86_64 and on Windows x86_64 cross-compiled from
Linux (run under wine). `aarch64` and macOS were **not** compile-tested — the toolchains
were absent on the build host — but the C is architecture-neutral. Provenance and per-file
digests: `src/haru_pack/launcher/xz/PROVENANCE.md`, enforced by `INV-PAYLOAD-05`.

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
pass (`INV-SHAKE-01`). Measured on `examples/shake-demo`: 92.1 → 75.9 MB payload — a figure
that predates `INV-PAYLOAD-03`, so the baseline is now smaller and the marginal saving less;
`SHAKE.md` carries the full caveat. The floor
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
`tier`, `offline`, `fetch_uv`; plus `uv_version` and `uv_sha256` on **thin**, where the
launcher fetches uv and checks it against that pinned digest before extracting it
(`INV-SUPPLY-05`). A `--shake` build also records a summary: `shaken`, `tracer`,
`dropped_files`, `freed_bytes`, `verified`. The interpreter for thick is auto-detected at
runtime, not pinned in the manifest.

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

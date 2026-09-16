# The default compiler: one bundled `zig cc` instead of four system cross-compilers

> **Status: ADOPTED — zig is the default C compiler (`INV-TOOL-02`).** The measurements below
> were run on 2026-09-11 and are what the decision was made on; they are kept so it can be
> re-checked rather than re-argued. `resolve_cc()` chooses zig unless `--cc system` /
> `HARUPACK_CC=system` is given, or the target is macOS (which needs the Apple SDK).

## Why bother

Today, building for everything means four system packages and a sudo prompt:

| capability | package | transitive cost |
|---|---|---|
| host | `build-essential` | large |
| `windows-x86_64` | `mingw-w64` | moderate |
| `linux-aarch64` | `gcc-aarch64-linux-gnu` | moderate |
| `linux-armv7` | `gcc-arm-linux-gnueabihf` | 16 packages |

`zig cc` is a complete C cross-compiler for all of those in a single ~50 MB download with
bundled libc and headers, needing **no sudo and no package manager**. That is the same shape
haru-pack already uses for everything else it depends on: Nim arrives via choosenim into
haru-pack's own directory, `uv` is downloaded and digest-pinned. A bundled zig would be
consistent rather than novel — and it removes the one remaining reason a first-time user has
to type a `sudo` command at all.

## What was actually verified

Each launcher below was built from this tree with `zig cc`, then **run**, and the SHA-256
known-answer test compared against the same program built with the real GCC. "Compiles" was
not accepted as evidence, because the launcher's entire stage-verification story is SHA-256
and a miscompiled crypto path would be silent.

| target | built | ran where | SHA-256 KAT |
|---|---|---|---|
| `linux-x86_64` (host) | yes | here | **PASS**, digest matches |
| `windows-x86_64` | yes, PE32+ | under wine | **PASS**, digest matches |
| `linux-aarch64` | yes | real arm64 Pi | **PASS**, byte-identical to the GCC build, including a 40 kB input |
| `linux-armv7` | yes, ARM EABI5 | not run — no armv7 hardware here | unverified |
| `macos-aarch64` | **no** | — | zig's bundled macOS headers lack `fstore_t`, which Nim's posix module needs. Cross-compiling to macOS still needs the real Apple SDK |

So one pinned download covers every target this project actually cares about. macOS was
already impossible here and remains so.

## The one thing that needs a shim

`nimcrypto`'s `sha2_neon.nim` does, under `when defined(arm64)`:

```nim
{.localPassc: "-march=armv8-a+crypto".}
```

zig's clang reads `-march=` as a CPU name for aarch64 and rejects it with
`unknown CPU: 'armv8'`, listing the CPUs it does know. A provider therefore has to translate
GCC-only flags. The shim haru-pack generates per build (`toolchain.zig_cc_shim`):

```sh
#!/bin/sh
args=""
for a in "$@"; do
  case "$a" in
    -march=armv8-a+crypto) args="$args -mcpu=baseline+aes+sha2" ;;
    -march=*)              ;;                   # drop other gcc -march spellings
    *)                     args="$args $a" ;;
  esac
done
exec zig cc -target aarch64-linux-gnu $args
```

**Known consequence, measured:** with the flag translated this way the build succeeds and
SHA-256 is *correct* — the KAT passes and matches GCC byte for byte — but the NEON-accelerated
path is not actually enabled; nimcrypto falls back to its reference implementation. An
isolated translation unit using `vsha256su0q_u32` still fails with *"requires target feature
'sha2'"*, so the right feature spelling has not been found yet. Correct but slower, and the
launcher re-hashes the staged tree on every run, so on ARM this is a real if modest startup
cost. Finding the correct zig feature flags would remove it.

## How it is built

Each item below shipped; this is the map from the design to the code.

1. **Pinned.** `pins.toml` carries a `zig` entry per build host with the ziglang.org release
   digest, downloaded and verified exactly like `uv` and choosenim (`INV-SUPPLY-01`); an
   unpinned zig is refused (`toolchain.install_zig`, `test_an_unpinned_zig_is_refused`).
2. **Installed without sudo**, into haru-pack's own directory —
   `toolchain.install_zig()`, mirroring the Nim install.
3. **A provider seam.** `Target.zig_triple()` / `nim_cpu` / `nim_os` answer "which compiler
   and what does it want called"; `build.resolve_cc()` picks the provider and
   `compile_launcher` passes the per-target Nim cfg keys `--<cpu>.<os>.gcc.exe`, which the
   generic `--gcc.exe` does *not* cover for a cross target (that cost an hour to discover).
4. **The flag shim**, generated per build rather than checked in — `toolchain.zig_cc_shim()`,
   driven by `_ZIG_FLAG_MAP`.
5. **A capability**, so it is visible and declinable in `bootstrap --list` — but with no
   system package, so it adds nothing to the sudo prompt. It **joins the kitchen sink** and is
   the default provider; `--cc system` opts out.

## The decision, and the honest costs

- **New pinned dependency**, ~50 MB. Against four system packages and a sudo prompt.
- **Different compiler.** clang, not gcc, so binaries will not be byte-identical to
  GCC-built ones. Correctness is verified above; reproducibility claims would need to say
  which provider produced a given artifact.
- **NEON SHA is lost** until the feature flags are right (see above).
- **Not a total replacement.** wine is unaffected — it is an emulator, not a compiler — and
  macOS stays out of reach.
- **Authenticode is unaffected**: signing is a property of the produced PE, not of what
  compiled it.

The ergonomic case decided it, and it is consistent with how this project already treats Nim
and uv: one verified download, no sudo, all targets. The engineering cost was a provider seam
plus a flag shim; the standing price is one more pinned artifact and reference-speed SHA on
ARM until someone finds the right zig feature spelling.

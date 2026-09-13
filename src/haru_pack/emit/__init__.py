"""Emit a reproduction kit for the launcher stub — `--emit-nim` and `--emit-c`.

Both flags drop, beside a normal build, everything needed to inspect, modify, and manually
recompile the stub, then reassemble the exact binary haru shipped:

    DIR/
      payload.bin      the exact payload bytes the binary carries (encrypted iff --encrypt)
      stubconfig.bin   the cleartext stub-config section (canary map + staging knobs)
      kit.json         this build's parameters (flags/remote/stub/out names) — DATA, read by
                        assemble.py, never spliced into its source
      assemble.py      stdlib-only reimplementation of overlay.attach: append + footer
      compile.sh       recompiles the stub, then runs `python3 assemble.py`
      README.md

`--emit-nim DIR` additionally ships `stub/` — the launcher's Nim source, byte-identical to
what haru-pack compiles — plus a `compile.sh` that reinvokes `nim c` with the SAME flag set
`build.compiler.compile_launcher` uses (`nim_target_flags`, one source, so the recipe cannot
drift; see INV-EMIT-01).

`--emit-c DIR` instead ships the Nim C backend's OWN output as plain `.c`/`.h` files (already
generated for your `--target`), plus `nimbase.h` and the vendored xz headers, so the kit needs
**no Nim toolchain** — only a `zig` (on `PATH`, or via `HARU_ZIG`). Its `compile.sh` is derived
from Nim's own build manifest (`launcher.json`), rewritten to run zig against the vendored
tree, because the Nim backend assigns per-file compile flags (nimcrypto's SHA-2 fast paths
need `-mssse3`/`-mavx2`) that a blanket `zig cc *.c` would drop; see INV-EMIT-02.

Both kits reproduce the shipped binary's OVERLAY exactly (payload + stub-config + footer are
byte-identical to what `overlay.attach` writes) via the SAME `assemble.py` / `kit.json` pair
(`_write_kit_common`, `_ASSEMBLE_PY`) — the one place that logic lives, so `--emit-nim` and
`--emit-c` cannot silently diverge on what "reassemble" means. The recompiled stub itself is a
*working* launcher but is not guaranteed byte-identical to haru's — a Nim/C compile embeds
build paths and other non-deterministic bytes. That distinction is stated in each kit's README
rather than overclaimed.

The modules, split out of a single 355-statement emit.py on 2026-09-13 (INV-MODULARITY-01):

    errors      EmitError
    nimflags    the `nim c` flag set — shared with the real build, so it cannot drift
    compilecmd  the PURE json -> zig-command transform (no filesystem; the testable part)
    templates   the text every kit carries: assemble.py, compile.sh, the READMEs
    kit         writing a kit directory, and the up-front validation of where it may go
    csources    --emit-c: the Nim C backend's own output

This file is a facade and holds no logic.
"""
from __future__ import annotations

from ..paths import launcher_src_dir
from .compilecmd import _rewrite_compile, _rewrite_link, compile_script_body
from .csources import emit_c_sources
from .errors import EmitError
from .kit import _find_nimbase, _write_kit_common, emit_nim_kit, finish_kit, validate_emit_dir
from .nimflags import nim_target_flags
from .templates import _ASSEMBLE_PY, _README, _compile_sh, _readme

__all__ = [
    "EmitError",
    "compile_script_body", "emit_c_sources", "emit_nim_kit", "finish_kit",
    "launcher_src_dir", "nim_target_flags", "validate_emit_dir",
    # Underscored, but named directly by the tests that pin the kit's bytes against
    # overlay.py's footer (INV-EMIT-01/02).
    "_ASSEMBLE_PY", "_README", "_compile_sh", "_find_nimbase", "_readme",
    "_rewrite_compile", "_rewrite_link", "_write_kit_common",
]

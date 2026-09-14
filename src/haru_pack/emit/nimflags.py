"""The `nim c` flag set — the single source of truth for it.

Defined once here and used by BOTH the real build (`build.compiler.compile_launcher`) and
the kit's generated `compile.sh`, so the emitted recipe cannot drift from the build it
claims to reproduce (INV-EMIT-01).

Split out of emit.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from ..targets import Target


# ── the `nim c` flag set — single source of truth ──────────────────────────────────────────
def nim_target_flags(tgt: Target, provider: str, shim_ref: str | None) -> list[str]:
    """The per-target `nim c` flags haru-pack compiles the launcher with (everything except
    `nim`, `c`, `--nimcache`, `--out`, and the source path). Called by
    `build.compile_launcher` for the real build and by this module for the emitted
    `compile.sh`, so the two cannot drift (INV-EMIT-01). `shim_ref` is the zig-cc wrapper the
    caller wants referenced — a real temp path in a build, `"$PWD/zig-cc"` in a kit."""
    args = ["-d:release"]
    if provider == "zig":
        cpu, os_ = tgt.nim_cpu, tgt.nim_os
        args += [f"--cpu:{cpu}", f"--os:{os_}",
                 f"--{cpu}.{os_}.gcc.exe:{shim_ref}",
                 f"--{cpu}.{os_}.gcc.linkerexe:{shim_ref}"]
    else:
        args += list(tgt.nim_flags())          # empty for a native/system build
    return args


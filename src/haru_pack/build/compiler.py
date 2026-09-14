"""Choosing a C compiler and running Nim to produce the launcher executable.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .. import emit as emit_mod
from .. import toolchain
from ..paths import launcher_src_dir
from ..targets import Target
from .errors import BuildError


# Which C compiler compiles the launcher. `zig` is the default on purpose (INV-TOOL-02):
# one pinned ~50 MB download covers every target haru-pack builds for, needs no sudo and no
# package manager, and so removes the last step between `uv tool install haru-pack` and a
# working build. `system` is the escape hatch for anyone who would rather use the cross
# toolchains they already have — and it is what a Mac target requires, since zig's bundled
# macOS headers are incomplete for Nim's posix module.
CC_PROVIDERS = ("zig", "system")
CC_ENV = "HARUPACK_CC"


def resolve_cc(cc: str = "", target=None, log=None) -> str:
    """Decide the provider. Explicit flag beats env var beats the default.

    A macOS target forces `system` rather than failing later with a header error, and says
    so — the operator asked for a Mac build, not for a lecture about zig.
    """
    say = log or (lambda _m: None)
    want = (cc or os.environ.get(CC_ENV, "") or "zig").strip().lower()
    if want not in CC_PROVIDERS:
        raise BuildError(
            f"unknown --cc {want!r}. Choose one of: {', '.join(CC_PROVIDERS)}.\n"
            f"`zig` uses the pinned compiler haru-pack installs for itself; `system` uses "
            f"the cross toolchains already on this machine.")
    if want == "zig" and target is not None:
        tgt = target if isinstance(target, Target) else Target.parse(target)
        if not tgt.zig_can_build():
            say(f"--cc zig cannot build for {tgt}; using the system compiler instead "
                f"(zig's bundled macOS headers are incomplete for Nim's posix module).")
            return "system"
    return want


def compile_launcher(nim: str, target, workdir: Path, cc: str = "", log=None) -> Path:
    tgt = target if isinstance(target, Target) else Target.parse(target)
    src = launcher_src_dir() / "main.nim"
    if not src.exists():
        raise BuildError(f"launcher source missing: {src}")
    out = workdir / ("launcher" + tgt.exe_suffix)
    # Nim writes its build manifest (nimcache/launcher.json: the exact per-file compile
    # commands + the link command) on every build, and leaves the generated C in the
    # nimcache. That is what `--emit-c` (see build()) turns into a zig compile.sh — the recipe
    # is the one Nim actually used, never a hand-written approximation (INV-EMIT-02). No extra
    # Nim flag is needed for that; `--genScript` would SKIP linking and break this real build.

    provider = resolve_cc(cc, target=tgt, log=log)
    shim = None
    if provider == "zig":
        # A generated shim, not a bare `zig cc`: Nim wants ONE executable for the compiler
        # key, and one GCC-only flag has to be translated per invocation. Nim also ignores
        # the generic `--gcc.exe` for a cross target and reads `--<cpu>.<os>.gcc.exe`, which
        # is why the keys are spelled out per target inside emit.nim_target_flags.
        zig = toolchain.find_managed_zig() or toolchain.install_zig(
            log=log or (lambda _m: None))
        shim = toolchain.zig_cc_shim(str(zig), tgt.zig_triple(), workdir / "zig-cc")
    # The per-target flag set is defined ONCE, in emit.nim_target_flags, and reused by the
    # --emit-nim kit's compile.sh, so the emitted recipe cannot drift from this build
    # (INV-EMIT-01). Only the ambient nim/nimcache/out/source path is added here.
    args = [nim, "c", *emit_mod.nim_target_flags(tgt, provider,
                                                 shim_ref=(str(shim) if shim else None)),
            f"--nimcache:{workdir/'nimcache'}", f"--out:{out}", str(src)]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 or not out.exists():
        raise BuildError(f"nim compile failed (cc={provider}):\n"
                         + (r.stderr or r.stdout)[-2000:])
    return out


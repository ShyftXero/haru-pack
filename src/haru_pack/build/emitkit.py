"""The `--emit-c` and `--emit-nim` reproduction kits written beside a finished binary.

Both kits share one rule that shapes every function here: **a kit failure must never report
an already-successful build as failed.** By the time a kit is written the binary exists, is
correct, and is chmod'd; turning a missing directory into a raise would tell the operator
their build broke when it did not. So the only hard refusal is the up-front
`validate_c_dir`, which runs BEFORE the build starts precisely so the likely causes fail
fast (INV-BASE-01 posture); everything after the binary exists degrades to a loud warning
recorded on the receipt (W2b).

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

from pathlib import Path

from .. import emit as emit_mod
from ..overlay import FOOTER_FLAG_REMOTE
from .errors import BuildError


def validate_c_dir(emit_c: str) -> Path | None:
    """Resolve and vet the --emit-c directory before any build work happens.

    Resolved now — before any tempdir or chdir — so a relative path lands where the user
    expects, and validated now so an unsafe or occupied target fails FAST, never after a
    binary has already been written.
    """
    if not emit_c:
        return None
    emit_c_dir = Path(emit_c).resolve()
    try:
        emit_mod.validate_emit_dir(emit_c_dir)
    except emit_mod.EmitError as e:
        raise BuildError(str(e)) from e
    return emit_c_dir


def write_c_kit(emit_c_dir: Path, *, info: dict, nimcache: Path, tgt, payload: bytes,
                stub_config: bytes, flags: int, source_url: str, out: Path, enc: dict,
                log, say) -> None:
    """Emit the C reproduction kit from the SAME bytes the binary was built from.

    The C that haru just compiled (in `nimcache`), plus the exact payload and stub-config
    that were attached, plus the assembler that reproduces this overlay. Footer flags
    include the remote bit iff this was a remote-fetch build, matching `attach`.
    """
    exe_name = "launcher" + tgt.exe_suffix
    try:
        emit_mod.emit_c_sources(nimcache, emit_c_dir, tgt.zig_triple(),
                                exe=exe_name, log=log)
        emit_mod.finish_kit(emit_c_dir, payload=payload, stub_config=stub_config,
                            flags=flags | (FOOTER_FLAG_REMOTE if source_url else 0),
                            remote=bool(source_url), exe=exe_name, out_name=out.name,
                            triple=tgt.zig_triple(), encrypted=bool(enc["enabled"]),
                            source_url=source_url)
        info["emit_c"] = str(emit_c_dir)
    except emit_mod.EmitError as e:
        say(f"WARNING: {out} built successfully, but the --emit-c kit is incomplete: "
            f"{e}")
        info["emit_c_error"] = str(e)


def write_nim_kit(emit_nim: str, *, info: dict, tgt, provider: str, payload: bytes,
                  stub_config: bytes, flags: int, source_url: str, out: Path, say) -> None:
    """Emit the Nim reproduction kit alongside the finished binary.

    The stub is generic, so the kit is its Nim source plus the exact DATA this build
    attached (payload + stub-config) and a script that recompiles and reassembles them.
    `flags` and `source_url` are the same values `attach()` used (INV-EMIT-01).
    """
    if not emit_nim:
        return
    try:
        dest = emit_mod.emit_nim_kit(Path(emit_nim), tgt=tgt, provider=provider,
                                     payload=payload, stub_config=stub_config, flags=flags,
                                     remote=bool(source_url), out_name=out.name, log=say)
        info["emit_nim"] = str(dest)
    except (emit_mod.EmitError, OSError) as e:
        info["emit_nim_error"] = str(e)
        say(f"WARNING: --emit-nim kit was not written: {e}\nThe packed binary at "
            f"{out} is unaffected and ready to use.")

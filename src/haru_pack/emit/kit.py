"""Writing a kit directory: the data blobs, kit.json, assemble.py, README.

One rule shapes everything here, and it is the reason `validate_emit_dir` is called by
`build` BEFORE a build starts rather than by the writers below: by the time a kit is
written the binary already exists and is correct, so a failure at this point must be a
warning, never a raised build failure. The up-front validation is what makes that
acceptable — it catches the likely causes while a refusal is still free.

Split out of emit.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path

from .. import toolchain
from ..overlay import FOOTER_FLAG_REMOTE
from ..paths import launcher_src_dir
from ..targets import Target
from .errors import EmitError
from .templates import _ASSEMBLE_PY, _README, _compile_sh, _readme


# ── --emit-c vendoring helpers ──────────────────────────────────────────────────────────────

def _find_nimbase(nim_json: dict) -> Path:
    """nimbase.h lives in Nim's lib, reached through one of the command's `-I` paths."""
    for _src, cmd in nim_json["compile"]:
        for tok in shlex.split(cmd):
            if tok.startswith("-I"):
                cand = Path(tok[2:]) / "nimbase.h"
                if cand.exists():
                    return cand
    raise EmitError("could not locate nimbase.h in the Nim compile command include paths")


def validate_emit_dir(dest: Path) -> None:
    """Refuse an unsafe or occupied --emit-c target, before the build runs (INV-BASE-01
    posture). We create and populate a tree here, so:

      * a symlink / reparse point is refused — we will not write through a link to some
        directory the operator did not name;
      * a non-empty directory is refused — the kit is a coherent set, and quietly writing
        into someone's populated folder (or half-overwriting a previous kit) is a surprise.
        Point it at a new or empty directory.
    """
    dest = Path(dest)
    if dest.is_symlink():
        raise EmitError(
            f"--emit-c target {dest} is a symlink; refusing to write the kit through it. "
            f"Point --emit-c at a real, new directory.")
    if dest.exists():
        if not dest.is_dir():
            raise EmitError(f"--emit-c target {dest} exists and is not a directory.")
        if any(dest.iterdir()):
            raise EmitError(
                f"--emit-c target {dest} is not empty; refusing to overwrite existing files. "
                f"Point --emit-c at a new or empty directory.")


def _write_kit_common(dest: Path, *, payload: bytes, stub_config: bytes, flags: int,
                      remote: bool, stub_name: str, out_name: str,
                      source_url: str = "") -> None:
    """The parts every kit shares, `--emit-nim` and `--emit-c` alike: the two config blobs,
    the reassembler, and kit.json.

    `flags` is baked FINAL here (the remote bit folded in, exactly as overlay.attach would),
    so assemble.py never has to reason about it — it writes the byte it is given. Every
    per-build parameter assemble.py needs (including `out_name`, which a caller could in
    principle hand us as an arbitrary string) is DATA here — `json.dumps`'d into kit.json and
    `json.loads`'d back in assemble.py — never spliced into assemble.py's own source text.
    `_ASSEMBLE_PY` is therefore static and shared byte-for-byte by every kit; there is no
    per-build template for a hostile `out_name` to reach into (see INV-EMIT-02's injection
    red-path).
    """
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "payload.bin").write_bytes(payload)
    (dest / "stubconfig.bin").write_bytes(stub_config)
    final_flags = flags | (FOOTER_FLAG_REMOTE if remote else 0)
    (dest / "kit.json").write_text(json.dumps({
        "flags": final_flags,
        "remote": bool(remote),
        "stub": stub_name,
        "out": out_name,
        "payload": "payload.bin",
        "stubconfig": "stubconfig.bin",
        "source_url": source_url,
    }, indent=2) + "\n")
    (dest / "assemble.py").write_text(_ASSEMBLE_PY)


def _prepare_stub_dir(dest: Path) -> Path:
    """Resolve `dest/stub` for a fresh copy, refusing anything unsafe (W2, INV-BASE-01 posture).

    Symlinks are refused outright — the kit must never write THROUGH one — and a pre-existing
    `stub/` is only removed when it is a real directory we recognize as a prior haru stub kit
    (it holds `main.nim`) or is empty. A non-empty, unrecognized `stub/` is left untouched and
    the emit is refused, so pointing `--emit-nim` at the wrong directory never deletes an
    operator's files."""
    if dest.is_symlink():
        raise EmitError(
            f"--emit-nim target {dest} is a symlink; refusing to emit through it "
            f"(INV-BASE-01 posture). Give a real directory.")
    dest.mkdir(parents=True, exist_ok=True)
    stub_dir = dest / "stub"
    if stub_dir.is_symlink():
        raise EmitError(
            f"{stub_dir} is a symlink; refusing to write through it. Remove it and retry.")
    if stub_dir.exists():
        recognized = (stub_dir / "main.nim").exists()
        if not recognized and any(stub_dir.iterdir()):
            raise EmitError(
                f"{stub_dir} exists, is not empty, and does not look like a haru-pack stub "
                f"kit (no main.nim). Refusing to delete it — choose an empty --emit-nim "
                f"directory, or clear that path yourself.")
        shutil.rmtree(stub_dir)
    return stub_dir


def emit_nim_kit(dest, *, tgt, provider: str, payload: bytes, stub_config: bytes,
                 flags: int, remote: bool, out_name: str, log=None) -> Path:
    """Write a `--emit-nim` reproduction kit to `dest`.

    Copies the launcher Nim source verbatim, drops the payload/stub-config blobs and the
    reassembler, and writes a `compile.sh` that reproduces haru-pack's own `nim c` flag set
    for `tgt` (using a durable, portable zig shim, never the build's tempdir one). Raises
    EmitError rather than clobbering an unsafe destination. See INV-EMIT-01.
    """
    dest = Path(dest)
    say = log or (lambda _m: None)
    tgt = tgt if isinstance(tgt, Target) else Target.parse(tgt)
    stub_name = "launcher" + tgt.exe_suffix

    # 1. the Nim source, verbatim — what haru compiles is what the kit compiles (INV-EMIT-01).
    stub_dir = _prepare_stub_dir(dest)
    shutil.copytree(launcher_src_dir(), stub_dir)

    # 2. the config blobs + reassembler + kit.json.
    _write_kit_common(dest, payload=payload, stub_config=stub_config, flags=flags,
                      remote=remote, stub_name=stub_name, out_name=out_name)

    # 3. a DURABLE, machine-independent zig shim (never the build's tempdir path): it calls
    #    `${HARU_ZIG:-zig} cc -target <triple>`, so it works on the packager's machine given
    #    zig on PATH — exactly the "assuming zig" contract. Reuses toolchain.zig_cc_shim, so
    #    the GCC-only-flag translation matches a real build.
    shim_ref = None
    if provider == "zig":
        toolchain.zig_cc_shim("${HARU_ZIG:-zig}", tgt.zig_triple(), dest / "zig-cc")
        shim_ref = '"$PWD/zig-cc"'

    # 4. the compile+assemble script, and 5. the guide.
    compile_sh = dest / "compile.sh"
    compile_sh.write_text(_compile_sh(tgt, provider, shim_ref, stub_name, out_name))
    compile_sh.chmod(0o755)
    (dest / "README.md").write_text(_readme(tgt, provider, remote, out_name))

    say(f"--emit-nim: wrote a Nim reproduction kit to {dest} (edit stub/, then `sh compile.sh`)")
    return dest


def finish_kit(dest: Path, payload: bytes, stub_config: bytes, flags: int,
               remote: bool, exe: str, out_name: str, triple: str,
               encrypted: bool, source_url: str = "") -> None:
    """Write the data blobs + kit.json + assemble.py + README, and append the assemble step
    to compile.sh.

    Called after `attach`, when the payload/stub-config/flags are final. `exe` is the stub
    filename compile.sh links; `out_name` is the binary the kit reproduces. Shares
    `_write_kit_common` / `_ASSEMBLE_PY` with `--emit-nim` — see the injection-safety note
    there: `out_name` is written into `kit.json` as data, never templated into
    `assemble.py`'s source."""
    dest = Path(dest)
    _write_kit_common(dest, payload=payload, stub_config=stub_config, flags=flags,
                      remote=remote, stub_name=exe, out_name=out_name,
                      source_url=source_url)
    enc_note = (", an **encrypted** container (AES-256-GCM), exactly as in the binary"
                if encrypted else " — not encrypted, so the source is readable, exactly as "
                "in the shipped binary")
    (dest / "README.md").write_text(_README.format(
        triple=triple, stub=exe, out=out_name, enc_note=enc_note))
    # Append the reassembly step so `sh compile.sh` does the whole thing end to end.
    sh = dest / "compile.sh"
    sh.write_text(sh.read_text()
                  + "python3 assemble.py\n")

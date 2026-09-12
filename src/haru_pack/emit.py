"""Emit a reproduction/assembly kit for the launcher stub (`--emit-nim`, and later
`--emit-c`), so a packager can inspect, modify and manually recompile the stub, then
reassemble the exact binary haru-pack shipped.

Why this is possible at all: the stub is ONE generic binary. Nothing about a build's
config — encryption, licence policy, reap/ephemeral, remote-fetch, injects — is compiled
into the Nim. Those live as DATA the always-present stub functions read at runtime: the
encrypted `payload.bin` (policy inside it), the cleartext `stubconfig.bin`, and the payload
manifest. Only `-d:release` and the target cpu/os vary the compile. So a faithful kit is:
the stub source + those two blobs + a reassembler that recomputes the footer.

The reassembler (`assemble.py`) is stdlib-only and mirrors `overlay.attach`'s v2 footer
exactly. It is DYNAMIC in one respect that matters: the footer records the payload's offset,
which is the stub's length — so if you edit and recompile the stub, the offsets change, and
assembly must run AFTER compilation. That is why the kit ships the parts plus a script, not a
pre-baked binary.

INV-EMIT-01 pins both halves: the emitted Nim is byte-identical to `launcher_src_dir()`, and
`assemble.py` reproduces `overlay.attach`'s bytes.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import toolchain
from .overlay import FOOTER_FLAG_REMOTE
from .paths import launcher_src_dir
from .targets import Target

# ── assemble.py ───────────────────────────────────────────────────────────────────────────
# Static, stdlib-only, dropped into every kit verbatim. Per-build parameters live in kit.json
# beside it, so this text is never templated (no f-string/brace hazards) and is shared byte-for
# -byte by --emit-nim and --emit-c. It is a faithful re-implementation of the v2 footer in
# src/haru_pack/overlay.py; the footer layout is pinned by the overlay tests, so drift there
# would be caught in CI, and INV-EMIT-01 pins that THIS file reproduces those bytes.
_ASSEMBLE_PY = '''#!/usr/bin/env python3
"""Reassemble the haru-pack binary from a (re)compiled stub + the payload/stub-config blobs
in this directory. Stdlib only. Faithful to haru-pack's overlay v2 footer.

Usage:  python3 assemble.py [STUB] [OUT]
  STUB defaults to kit.json's "stub" (the file compile.sh produces), OUT to its "out".

Run this AFTER compile.sh: the footer records the stub's length as the payload offset, so a
modified stub must be reassembled, not patched. A code signature, if any, is applied later.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = json.loads((HERE / "kit.json").read_text())

MAGIC = b"HARUPACK"
TAIL = b"KCAPURAH"
FOOTER_V2_SIZE = 116


def assemble(stub_path, out_path):
    stub = Path(stub_path).read_bytes()
    payload = (HERE / KIT["payload"]).read_bytes()
    sc = (HERE / KIT["stubconfig"]).read_bytes()
    flags = int(KIT["flags"])            # already final (encrypted/remote bits baked at emit)
    off = len(stub)
    paysha = hashlib.sha256(payload).digest()
    sc_sha = hashlib.sha256(sc).digest()
    if KIT["remote"]:
        # remote-fetch: the payload is NOT embedded. Host payload.bin at the source_url in the
        # stub-config. Layout is [stub][stub-config][footer]; payload_len is 0 but the payload
        # DIGEST is still recorded, so the launcher can verify the fetched bytes.
        stub_off = off
        footer = (MAGIC + struct.pack("<HHQQ", 2, flags, off, 0) + paysha
                  + struct.pack("<QQ", stub_off, len(sc)) + sc_sha + TAIL)
        blob = stub + sc + footer
    else:
        stub_off = off + len(payload)
        footer = (MAGIC + struct.pack("<HHQQ", 2, flags, off, len(payload)) + paysha
                  + struct.pack("<QQ", stub_off, len(sc)) + sc_sha + TAIL)
        blob = stub + payload + sc + footer
    assert len(footer) == FOOTER_V2_SIZE, len(footer)
    Path(out_path).write_bytes(blob)
    return out_path


if __name__ == "__main__":
    stub = sys.argv[1] if len(sys.argv) > 1 else str(HERE / KIT["stub"])
    out = sys.argv[2] if len(sys.argv) > 2 else str(HERE / KIT["out"])
    p = assemble(stub, out)
    try:
        Path(p).chmod(0o755)
    except OSError:
        pass
    print("wrote", p)
'''


def _write_kit_common(dest: Path, *, payload: bytes, stub_config: bytes, flags: int,
                      remote: bool, stub_name: str, out_name: str) -> None:
    """The parts every kit shares: the two config blobs, the reassembler, and kit.json.

    `flags` is baked FINAL here (the remote bit folded in, exactly as overlay.attach would),
    so assemble.py never has to reason about it — it writes the byte it is given.
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
    }, indent=2) + "\n")
    (dest / "assemble.py").write_text(_ASSEMBLE_PY)


def _nim_compile_args(tgt: Target, provider: str, shim_ref: str | None) -> list[str]:
    """The `nim c` arguments haru-pack's `build.compile_launcher` uses for this target, as
    shell tokens. Reconstructed here rather than imported so the emit path carries no
    dependency on the build module; kept in lockstep with compile_launcher."""
    args = ["-d:release"]
    if provider == "zig":
        cpu, os_ = tgt.nim_cpu, tgt.nim_os
        args += [f"--cpu:{cpu}", f"--os:{os_}",
                 f"--{cpu}.{os_}.gcc.exe:{shim_ref}",
                 f"--{cpu}.{os_}.gcc.linkerexe:{shim_ref}"]
    else:
        args += list(tgt.nim_flags())          # empty for a native/system build
    return args


def _compile_sh(tgt: Target, nim: str, provider: str, shim_ref: str | None,
                stub_name: str, out_name: str) -> str:
    """The one script that rebuilds the stub and reassembles the binary."""
    args = " ".join(_nim_compile_args(tgt, provider, shim_ref))
    if provider == "zig":
        toolnote = (
            f"#   * Nim:  haru-pack used {nim}. Override with HARU_NIM=/path/to/nim, or set it\n"
            f"#           to `nim` if Nim is on your PATH.\n"
            f"#   * zig:  invoked as `${{HARU_ZIG:-zig}} cc` through ./zig-cc. Put zig on your\n"
            f"#           PATH, or set HARU_ZIG=/path/to/zig. haru-pack's default compiler.\n")
    else:
        toolnote = (
            f"#   * Nim:  haru-pack used {nim}. Override with HARU_NIM=/path/to/nim.\n"
            f"#   * C:    the system C toolchain (this kit was emitted with --cc system).\n")
    return (
        "#!/bin/sh\n"
        "# haru-pack --emit-nim reproduction kit. Recompile the launcher stub from Nim source\n"
        "# and reassemble the packed binary. Edit stub/*.nim first if you want to change it.\n"
        "#\n"
        f"{toolnote}"
        "#\n"
        "# The payload and stub-config are DATA the compiled stub reads at runtime; you do not\n"
        "# recompile them. assemble.py appends them and writes the footer after the stub builds.\n"
        "set -e\n"
        'cd "$(dirname "$0")"\n'
        f'NIM="${{HARU_NIM:-{nim}}}"\n'
        f'"$NIM" c {args} --nimcache:"$PWD/nimcache" --out:"$PWD/{stub_name}" stub/main.nim\n'
        f'python3 assemble.py "$PWD/{stub_name}" "$PWD/{out_name}"\n'
        f'echo "done -> $PWD/{out_name}"\n'
    )


def _readme(tgt: Target, provider: str, remote: bool, out_name: str) -> str:
    remote_note = (
        "\n## Remote-fetch build\n\n"
        "This binary was built with `--source-url`, so it carries NO payload. `payload.bin` "
        "here is the sidecar you host at the source_url in `stubconfig.bin`; the stub fetches "
        "it and refuses any bytes whose sha256 is not the digest baked into the footer.\n"
        if remote else "")
    return (
        "# haru-pack — Nim stub reproduction kit (`--emit-nim`)\n\n"
        f"Target: `{tgt}`  ·  compiler: `{provider}`\n\n"
        "This directory has everything needed to inspect, modify and recompile the launcher "
        "stub, then reassemble the exact binary haru-pack produced.\n\n"
        "## What is here\n\n"
        "- `stub/` — the launcher's Nim source, byte-identical to what haru-pack compiles. "
        "The whole machine is here as readable functions: staging, uv fetch, decryption, "
        "licence gates, reap/shred, remote-fetch. What varies per build is not this code but "
        "the two blobs below.\n"
        "- `payload.bin` — the exact payload bytes (the compressed project zip, **encrypted "
        "if you built with `--encrypt`**). This is the same data the shipped binary carries; "
        "emitting it exposes nothing the binary did not already. The build secret/key is NOT "
        "here.\n"
        "- `stubconfig.bin` — the cleartext stub-config (canary map, reap/ephemeral/overwrite, "
        "base_path, source_url). Not secret.\n"
        "- `zig-cc` — a portable shim that runs `${HARU_ZIG:-zig} cc -target <triple>`.\n"
        "- `assemble.py` + `kit.json` — the stdlib-only reassembler and its parameters.\n"
        "- `compile.sh` — recompiles the stub, then runs `assemble.py`.\n\n"
        "## Rebuild it\n\n"
        "```sh\n"
        "sh compile.sh\n"
        "```\n\n"
        f"That writes `{out_name}` — byte-identical to haru-pack's output (a code signature, "
        "if you use one, is applied afterward). Editing `stub/*.nim` changes the stub's length, "
        "so `assemble.py` recomputes the footer offsets; always let `compile.sh` reassemble "
        "rather than patching the old binary.\n"
        f"{remote_note}"
    )


def emit_nim_kit(dest, *, tgt, nim: str, provider: str, payload: bytes, stub_config: bytes,
                 flags: int, remote: bool, out_name: str, log=None) -> Path:
    """Write a `--emit-nim` reproduction kit to `dest`.

    Copies the launcher Nim source verbatim, drops the payload/stub-config blobs and the
    reassembler, and writes a `compile.sh` that reproduces haru-pack's own `nim c` invocation
    for `tgt` (using a durable, portable zig shim, never the build's tempdir one). Returns
    the destination path. See INV-EMIT-01.
    """
    dest = Path(dest)
    say = log or (lambda _m: None)
    tgt = tgt if isinstance(tgt, Target) else Target.parse(tgt)
    stub_name = "launcher" + tgt.exe_suffix

    # 1. the Nim source, verbatim — what haru compiles is what the kit compiles (INV-EMIT-01).
    stub_dir = dest / "stub"
    if stub_dir.exists():
        shutil.rmtree(stub_dir)
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
    compile_sh.write_text(_compile_sh(tgt, nim, provider, shim_ref, stub_name, out_name))
    compile_sh.chmod(0o755)
    (dest / "README.md").write_text(_readme(tgt, provider, remote, out_name))

    say(f"--emit-nim: wrote a Nim reproduction kit to {dest} (edit stub/, then `sh compile.sh`)")
    return dest

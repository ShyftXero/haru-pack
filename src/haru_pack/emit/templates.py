"""The text every kit carries: the reassembler, the build script, the READMEs.

Mostly data rather than logic, and that is the reason it is its own module — mixed in with
the code that WRITES the kits, two hundred lines of embedded template made `emit` look far
denser than it is.

`_ASSEMBLE_PY` is the load-bearing one. It is dropped into every kit VERBATIM: per-build
parameters live in `kit.json` beside it, so this text is never templated (no f-string,
brace, or format hazard for a hostile `--out` name to reach into) and is shared
byte-for-byte by every emit kit, C or Nim. It is a faithful re-implementation of the v2
footer in `overlay.py`, and its MAGIC/TAIL/FOOTER_V2_SIZE MUST equal overlay's — a test
ties them together so a footer-version bump that is not reflected here fails CI
(INV-EMIT-01 / INV-EMIT-02).

Split out of emit.py 2026-09-13 (INV-MODULARITY-01). Text unchanged.
"""
from __future__ import annotations

import shlex

from ..targets import Target
from .nimflags import nim_target_flags


# INV-EMIT-01 / INV-EMIT-02 pin that THIS file reproduces overlay.attach's bytes for both kits.
_ASSEMBLE_PY = '''#!/usr/bin/env python3
"""Reassemble the haru-pack binary from a (re)compiled stub + the payload/stub-config blobs
in this directory. Stdlib only. Faithful to haru-pack's overlay v2 footer
(src/haru_pack/overlay.py — keep MAGIC/TAIL/FOOTER_V2_SIZE in sync).

Usage:  python3 assemble.py [STUB] [OUT]
  STUB defaults to kit.json's "stub" (the file compile.sh produces), OUT to its "out".

Run this AFTER compile.sh: the footer records the stub's length as the payload offset, so a
modified stub must be reassembled, not patched. A code signature, if any, is applied later.

For a remote-fetch build (kit.json's "remote") the binary carries NO payload; this also writes
OUT + ".haru-payload" — the exact bytes to host at the stub-config's source_url — mirroring
what a real --source-url build ships beside its output.
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
    if KIT["remote"]:
        (Path(out_path).parent / (Path(out_path).name + ".haru-payload")).write_bytes(payload)
    return out_path


if __name__ == "__main__":
    stub = sys.argv[1] if len(sys.argv) > 1 else str(HERE / KIT["stub"])
    out = sys.argv[2] if len(sys.argv) > 2 else str(HERE / KIT["out"])
    p = assemble(stub, out)
    try:
        Path(p).chmod(0o755)
    except OSError:
        pass
    if KIT["remote"]:
        hosted = f" — host those bytes at {KIT['source_url']}" if KIT.get("source_url") else ""
        print(f"wrote {p} (remote) + {p}.haru-payload{hosted}")
    else:
        print("wrote", p)
'''


def _compile_sh(tgt: Target, provider: str, shim_ref: str | None,
                stub_name: str, out_name: str) -> str:
    """The one script that rebuilds the stub and reassembles the binary. No build-host paths
    are baked in: Nim comes from `${HARU_NIM:-nim}` and zig from the shim's `${HARU_ZIG:-zig}`,
    so the kit is shareable. Interpolated names are shlex-quoted (N3)."""
    args = " ".join(nim_target_flags(tgt, provider, shim_ref))
    stub_q = shlex.quote(stub_name)
    out_q = shlex.quote(out_name)
    if provider == "zig":
        toolnote = (
            "#   * Nim:  set HARU_NIM=/path/to/nim, or have `nim` on your PATH.\n"
            "#   * zig:  invoked as `${HARU_ZIG:-zig} cc` through ./zig-cc. Put zig on your\n"
            "#           PATH, or set HARU_ZIG=/path/to/zig. haru-pack's default compiler.\n")
    else:
        toolnote = (
            "#   * Nim:  set HARU_NIM=/path/to/nim, or have `nim` on your PATH.\n"
            "#   * C:    the system C toolchain (this kit was emitted with --cc system).\n")
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
        'NIM="${HARU_NIM:-nim}"\n'
        f'"$NIM" c {args} --nimcache:"$PWD/nimcache" --out:"$PWD/"{stub_q} stub/main.nim\n'
        f'python3 assemble.py "$PWD/"{stub_q} "$PWD/"{out_q}\n'
        f'echo "done -> $PWD/"{out_q}\n'
    )


def _readme(tgt: Target, provider: str, remote: bool, out_name: str) -> str:
    remote_note = (
        "\n## Remote-fetch build\n\n"
        "This binary was built with `--source-url`, so it carries NO payload. `payload.bin` "
        "here is the sidecar you host at the source_url in `stubconfig.bin`; the stub fetches "
        "it and refuses any bytes whose sha256 is not the digest baked into the footer. The "
        "reassembled binary plus this hosted sidecar together are the working artifact.\n"
        if remote else "")
    return (
        "# haru-pack — Nim stub reproduction kit (`--emit-nim`)\n\n"
        f"Target: `{tgt}`  ·  compiler: `{provider}`\n\n"
        "This directory has everything needed to inspect, modify and recompile the launcher "
        "stub, then reassemble a working binary equivalent to the one haru-pack produced. The "
        "launcher itself is not guaranteed to recompile byte-for-byte (Nim/C output is not "
        "reproducible in general); what is guaranteed is a binary whose overlay verifies and "
        "whose payload and stub-config are the exact bytes this build shipped.\n\n"
        "## What is here\n\n"
        "- `stub/` — the launcher's Nim source, byte-identical to what haru-pack compiles. "
        "The whole machine is here as readable functions: staging, uv fetch, decryption, "
        "licence gates, reap/shred, remote-fetch. What varies per build is not this code but "
        "the two blobs below.\n"
        "- `payload.bin` — the exact payload bytes (the compressed project zip, **encrypted "
        "if you built with `--encrypt`**). This is the same data the shipped binary carries; "
        "emitting it exposes nothing the binary did not. The build secret/key is NOT here.\n"
        "- `stubconfig.bin` — the cleartext stub-config (canary map, reap/ephemeral/overwrite, "
        "base_path, source_url). Not secret.\n"
        "- `zig-cc` — a portable shim that runs `${HARU_ZIG:-zig} cc -target <triple>`.\n"
        "- `assemble.py` + `kit.json` — the stdlib-only reassembler and its parameters.\n"
        "- `compile.sh` — recompiles the stub, then runs `assemble.py`.\n\n"
        "## Rebuild it\n\n"
        "```sh\n"
        "sh compile.sh\n"
        "```\n\n"
        f"That writes `{out_name}`. Editing `stub/*.nim` changes the stub's length, so "
        "`assemble.py` recomputes the footer offsets; always let `compile.sh` reassemble "
        "rather than patching the old binary.\n"
        f"{remote_note}"
    )


_README = '''\
# haru-pack `--emit-c` reproduction kit

This directory holds the launcher **stub** as C, plus this build's payload and config, plus a
script that rebuilds the exact binary haru shipped.

## What it is

haru-pack's launcher is written in Nim and compiled through Nim's **C backend**. `--emit-c`
captures that C (already generated for your `--target`) so you can read it, change it, and
recompile it with **zig — no Nim toolchain required**. You do need a `zig` compiler: one on
your `PATH`, or point `HARU_ZIG` at a zig binary. Everything else the compile needs
(`nimbase.h`, the xz headers) is vendored here.

The stub is generic: every capability (decrypt, license gates, remote-fetch, reap/shred,
staging) is always present as C functions. What makes *your* build specific is data, shipped
here as two blobs:

- `payload.bin` — the packed project: a compressed zip{enc_note}. These are the exact bytes
  the binary already carries, so this file exposes nothing the shipped binary does not.
- `stubconfig.bin` — the cleartext stub-config the launcher reads before decrypting (canary
  map and the staging knobs: reap / ephemeral / overwrite / base-path / source-url).

**Handle this directory with the same care as the binary.** It exposes nothing the shipped
binary does not — `payload.bin` is byte-identical to the bytes it carries — but that means an
unencrypted payload is as readable here as in the binary, and if you built with
`--embed-secret` the (obfuscated) key rides inside `payload.bin` exactly as it rides in the
binary (INV-SECRET-02).

## Rebuild it

```sh
sh compile.sh
```

That compiles every `.c` with the `zig-cc` shim (targets `{triple}`, using a `zig` on your
`PATH` or `$HARU_ZIG`), links `./{stub}`, then runs `python3 assemble.py` to append
`payload.bin` + `stubconfig.bin` + the footer, producing `./{out}`.

Modify any `.c` first and the change flows through. `assemble.py` recomputes the footer
offsets from the recompiled stub's length, so a stub whose size changed still assembles
correctly.

## Honest limits

- The kit is **not** fully self-contained: it needs a `zig` compiler present (on `PATH`, or
  via `HARU_ZIG`). Everything else — the C, `nimbase.h`, the xz headers — is vendored, so no
  Nim toolchain is needed and no build-host absolute paths are baked in.
- `assemble.py` reproduces the **overlay** (payload + stub-config + footer) byte-for-byte
  with what haru-pack's `overlay.attach` writes.
- The recompiled **stub** is a working launcher but is not guaranteed byte-identical to
  haru's: a C compile embeds build paths and other non-deterministic bytes. If you need the
  signed artifact, sign the reassembled binary yourself — signing appends after the footer,
  which the launcher relocates by scanning backward for its magic.
- `compile.sh` and the `zig-cc` shim are POSIX shell. On a Windows build host the shim is a
  `.bat`; run the commands from `compile.sh` through it.
'''

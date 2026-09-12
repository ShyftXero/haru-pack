"""Emit a self-contained reproduction kit for the launcher stub — the `--emit-c` half.

`--emit-c DIR` drops, beside a normal build, everything needed to inspect, modify, and
**recompile the stub with zig alone — no Nim required** — and then reassemble the exact
binary haru shipped:

    DIR/
      *.c              the Nim C backend's output (the whole stub, as readable C)
      *.h              nimbase.h + the vendored xz headers, so the tree is self-contained
      zig-cc           the flag-translating shim haru itself uses (points at managed zig)
      compile.sh       zig compile+link of every .c, then `python3 assemble.py`
      payload.bin      the exact payload bytes the binary carries (encrypted iff --encrypt)
      stubconfig.bin   the cleartext stub-config section (canary map + staging knobs)
      assemble.py      stdlib-only reimplementation of overlay.attach: append + footer
      README.md

Why C-from-Nim rather than a bare `zig cc *.c`: the Nim backend assigns **per-file** flags
(nimcrypto's SHA-2 fast paths need `-mssse3` / `-mavx2`), and the generated files carry
`@`-prefixed names a C driver reads as response-file syntax. So the compile commands come
from Nim's own build manifest (`launcher.json`), rewritten to run zig against the vendored
tree. See INV-EMIT-02.

The kit reproduces the shipped binary's OVERLAY exactly (payload + stub-config + footer are
byte-identical to `overlay.attach`). The recompiled stub itself is a *working* launcher but
is not guaranteed byte-identical to haru's — a C compile embeds build paths and other
non-deterministic bytes. That distinction is stated in the emitted README rather than
overclaimed."""
from __future__ import annotations

import json
import os
import shlex
import shutil
from pathlib import Path

from . import toolchain
from .paths import launcher_src_dir


# ── the pure json → zig-command transform (the part INV-EMIT-02's unit test pins) ──────────
#
# Nim records, in `<project>.json`, the exact per-file compile command and the link command
# it ran. Each compile entry is `[source_abspath, "<cc> -c <flags…> -o <obj> <src>"]`. We keep
# every flag verbatim (zig tolerates the gcc-only ones — an unknown `-f…` is a warning, not an
# error) and change only three things, all mechanical:
#
#   1. the compiler token           -> the emitted `./zig-cc` shim (which translates the one
#                                      GCC flag zig rejects, `-march=…`, per toolchain.zig_cc_shim)
#   2. every `-I<abspath>`          -> `-I.` (all headers are vendored into the kit dir)
#   3. the object/source filenames  -> `./`-prefixed basenames, because the C driver reads a
#                                      bare leading `@` (Nim's mangled names) as a response file
#
# These functions take no I/O and no toolchain state on purpose: the red-path for INV-EMIT-02
# is to make one of them emit a fabricated compiler token, and the unit test goes red.

def _rewrite_compile(cmd: str, shim: str) -> str:
    """Rewrite one Nim compile command to run `shim` against the vendored, in-dir sources."""
    t = shlex.split(cmd)
    if len(t) < 4 or t[-3] != "-o":
        raise ValueError(f"unexpected Nim compile command shape: {cmd!r}")
    obj, src = t[-2], t[-1]
    out = [shim]
    for tok in t[1:-3]:
        out.append("-I." if tok.startswith("-I") else tok)
    out += ["-o", "./" + os.path.basename(obj), "./" + os.path.basename(src)]
    return " ".join(shlex.quote(x) for x in out)


def _rewrite_link(cmd: str, exe: str, shim: str) -> str:
    """Rewrite Nim's link command to link the in-dir objects into `./<exe>` with `shim`."""
    t = shlex.split(cmd)
    out = [shim]
    i = 1
    while i < len(t):
        tok = t[i]
        if tok == "-o":
            out += ["-o", "./" + exe]
            i += 2
            continue
        if tok.endswith(".o"):
            out.append("./" + os.path.basename(tok))
        elif tok.startswith("-I"):
            out.append("-I.")
        else:
            out.append(tok)
        i += 1
    return " ".join(shlex.quote(x) for x in out)


def compile_script_body(nim_json: dict, exe: str, shim: str) -> str:
    """PURE: Nim's build manifest -> the body of a zig compile+link script.

    `exe` is the stub filename the link step produces (e.g. `launcher` or `launcher.exe`);
    `shim` is how the script invokes the compiler (e.g. `./zig-cc`). Every emitted command
    invokes `shim` and nothing else — that is the property INV-EMIT-02's unit test asserts."""
    lines = [_rewrite_compile(cmd, shim) for _src, cmd in nim_json["compile"]]
    lines.append(_rewrite_link(nim_json["linkcmd"], exe, shim))
    return "\n".join(lines) + "\n"


# ── vendoring + kit assembly ───────────────────────────────────────────────────────────────

def _find_nimbase(nim_json: dict) -> Path:
    """nimbase.h lives in Nim's lib, reached through one of the command's `-I` paths."""
    for _src, cmd in nim_json["compile"]:
        for tok in shlex.split(cmd):
            if tok.startswith("-I"):
                cand = Path(tok[2:]) / "nimbase.h"
                if cand.exists():
                    return cand
    raise EmitError("could not locate nimbase.h in the Nim compile command include paths")


class EmitError(RuntimeError):
    """A reproduction kit could not be emitted."""


def emit_c_sources(nimcache: Path, dest: Path, triple: str, zig: str,
                   exe: str, log=None) -> str:
    """Write the C source tree + shim + compile.sh (compile+link only) into `dest`.

    Returns the shim's filename (relative to `dest`) so the caller can reference it. The
    compile.sh written here stops after the link; `finish_kit` appends the assemble step
    once the payload is known."""
    say = log or (lambda _m: None)
    nimcache = Path(nimcache)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    jpath = nimcache / "launcher.json"
    if not jpath.exists():
        raise EmitError(f"Nim build manifest missing: {jpath} (expected after a normal build)")
    nim_json = json.loads(jpath.read_text())

    # Vendor every source Nim compiled — the Nim `@m…`/`@p…`/`@n…` .c files (from the
    # nimcache) and the xz .c (from the launcher tree) both appear as compile[i][0].
    for src, _cmd in nim_json["compile"]:
        s = Path(src)
        shutil.copy2(s, dest / s.name)
    # Vendor headers so `-I.` resolves everything Nim reached by absolute path: the xz
    # headers next to the xz .c, and nimbase.h from Nim's lib.
    for h in (launcher_src_dir() / "xz").glob("*.h"):
        shutil.copy2(h, dest / h.name)
    shutil.copy2(_find_nimbase(nim_json), dest / "nimbase.h")

    # The exact flag-translating shim haru uses, pointed at the (stable) managed zig path so
    # the kit keeps working after the build's tempdir is gone.
    shim_path = toolchain.zig_cc_shim(zig, triple, dest / "zig-cc")
    shim_name = "./" + Path(shim_path).name

    body = compile_script_body(nim_json, exe, shim_name)
    script = ("#!/bin/sh\n"
              "# Recompile the haru-pack launcher stub with zig, then reassemble the binary.\n"
              "# Generated by haru-pack --emit-c. No Nim required; needs only the bundled zig.\n"
              "set -e\n"
              'cd "$(dirname "$0")"\n'
              + body)
    (dest / "compile.sh").write_text(script)
    (dest / "compile.sh").chmod(0o755)
    say(f"--emit-c: wrote C reproduction kit to {dest} "
        f"({len(nim_json['compile'])} sources, compiles with zig alone)")
    return shim_name


_ASSEMBLE_PY = '''\
#!/usr/bin/env python3
"""Reassemble the haru-pack binary from the recompiled stub + payload + stub-config.

Generated by haru-pack --emit-c. Stdlib only. This is a faithful copy of the byte layout
overlay.attach produces, with this build's flags/offsets baked in below. Offsets are
recomputed here (not baked) because they depend on the stub's length, which changes the
moment you modify and recompile the stub.
"""
import hashlib, struct, sys
from pathlib import Path

MAGIC = b"HARUPACK"
TAIL  = b"KCAPURAH"
FLAGS  = {flags}          # bit0=encrypted, bit1=remote  (this build's flags)
REMOTE = {remote}
STUB   = "{stub}"         # the file compile.sh produces
OUT    = "{out}"          # the binary this reproduces
SOURCE_URL = {source_url!r}

here = Path(__file__).resolve().parent
stub = (here / STUB).read_bytes()
payload = (here / "payload.bin").read_bytes()
stub_config = (here / "stubconfig.bin").read_bytes()
off = len(stub)
paysha = hashlib.sha256(payload).digest()
stub_sha = hashlib.sha256(stub_config).digest()

if REMOTE:
    # [stub][stub-config][footer]; payload is hosted, not embedded (payload_len = 0).
    stub_off = off
    footer = (MAGIC + struct.pack("<HHQQ", 2, FLAGS, off, 0) + paysha
              + struct.pack("<QQ", stub_off, len(stub_config)) + stub_sha + TAIL)
    (here / OUT).write_bytes(stub + stub_config + footer)
    (here / (OUT + ".haru-payload")).write_bytes(payload)
    print(f"wrote {{OUT}} (remote) + {{OUT}}.haru-payload — host those bytes at {{SOURCE_URL}}")
else:
    # [stub][payload][stub-config][footer].
    stub_off = off + len(payload)
    footer = (MAGIC + struct.pack("<HHQQ", 2, FLAGS, off, len(payload)) + paysha
              + struct.pack("<QQ", stub_off, len(stub_config)) + stub_sha + TAIL)
    (here / OUT).write_bytes(stub + payload + stub_config + footer)
    print(f"wrote {{OUT}}  ({{off + len(payload) + len(stub_config) + len(footer)}} bytes)")
'''


_README = '''\
# haru-pack `--emit-c` reproduction kit

This directory is a self-contained copy of the launcher **stub** as C, plus this build's
payload and config, plus a script that rebuilds the exact binary haru shipped.

## What it is

haru-pack's launcher is written in Nim and compiled through Nim's **C backend**. `--emit-c`
captures that C (already generated for your `--target`) so you can read it, change it, and
recompile it with **zig alone — no Nim toolchain required**.

The stub is generic: every capability (decrypt, license gates, remote-fetch, reap/shred,
staging) is always present as C functions. What makes *your* build specific is data, shipped
here as two blobs:

- `payload.bin` — the packed project: a compressed zip{enc_note}. These are the exact bytes
  the binary already carries, so this file exposes nothing the shipped binary does not.
- `stubconfig.bin` — the cleartext stub-config the launcher reads before decrypting (canary
  map and the staging knobs: reap / ephemeral / overwrite / base-path / source-url).

The secret **key** is never written here (INV-SECRET-02).

## Rebuild it

```sh
sh compile.sh
```

That compiles every `.c` with the bundled `zig-cc` shim (`{triple}`), links `./{stub}`, then
runs `python3 assemble.py` to append `payload.bin` + `stubconfig.bin` + the footer, producing
`./{out}`.

Modify any `.c` first and the change flows through. `assemble.py` recomputes the footer
offsets from the recompiled stub's length, so a stub whose size changed still assembles
correctly.

## Honest limits

- `assemble.py` reproduces the **overlay** (payload + stub-config + footer) byte-for-byte
  with what haru-pack's `overlay.attach` writes.
- The recompiled **stub** is a working launcher but is not guaranteed byte-identical to
  haru's: a C compile embeds build paths and other non-deterministic bytes. If you need the
  signed artifact, sign the reassembled binary yourself — signing appends after the footer,
  which the launcher relocates by scanning backward for its magic.
- `compile.sh` and the `zig-cc` shim are POSIX shell. On a Windows build host the shim is a
  `.bat`; run the commands from `compile.sh` through it.
'''


def finish_kit(dest: Path, payload: bytes, stub_config: bytes, flags: int,
               remote: bool, exe: str, out_name: str, triple: str,
               encrypted: bool, source_url: str = "") -> None:
    """Write the data blobs + assemble.py + README, and append the assemble step to compile.sh.

    Called after `attach`, when the payload/stub-config/flags are final. `exe` is the stub
    filename compile.sh links; `out_name` is the binary the kit reproduces."""
    dest = Path(dest)
    (dest / "payload.bin").write_bytes(payload)
    (dest / "stubconfig.bin").write_bytes(stub_config)
    (dest / "assemble.py").write_text(_ASSEMBLE_PY.format(
        flags=int(flags), remote=bool(remote), stub=exe, out=out_name,
        source_url=source_url))
    enc_note = (", **encrypted** (AES-256-GCM) — unreadable without the key"
                if encrypted else " (not encrypted — the source is readable, exactly as it "
                "is in the shipped binary)")
    (dest / "README.md").write_text(_README.format(
        triple=triple, stub=exe, out=out_name, enc_note=enc_note))
    # Append the reassembly step so `sh compile.sh` does the whole thing end to end.
    sh = dest / "compile.sh"
    sh.write_text(sh.read_text()
                  + "python3 assemble.py\n")

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
`build.compile_launcher` uses (`nim_target_flags`, one source, so the recipe cannot drift;
see INV-EMIT-01).

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
rather than overclaimed."""
from __future__ import annotations

import json
import os
import shlex
import shutil
from pathlib import Path

from . import toolchain
from .overlay import FOOTER_FLAG_REMOTE
from .paths import launcher_src_dir
from .targets import Target


class EmitError(RuntimeError):
    """A reproduction kit (`--emit-nim` or `--emit-c`) could not be written safely.

    Non-fatal to the build: by the time either kit is attempted the binary is already
    produced, so `build()` reports this as a kit warning, not a build failure."""


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
    """Rewrite one Nim compile command to run `shim` against the vendored, in-dir sources.

    `-o` is located positionally (Nim writes `<cc> -c <flags…> -o OBJ SRC`), not assumed to
    be third-from-last, so a trailing flag would not misread OBJ/SRC."""
    t = shlex.split(cmd)
    try:
        oi = t.index("-o")
        obj, src = t[oi + 1], t[oi + 2]
    except (ValueError, IndexError):
        raise ValueError(f"unexpected Nim compile command shape (no '-o OBJ SRC'): {cmd!r}")
    skip = {0, oi, oi + 1, oi + 2}
    out = [shim]
    for i, tok in enumerate(t):
        if i in skip:
            continue
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


# ── assemble.py — the ONE stdlib-only reassembler shared by --emit-nim and --emit-c ────────
# Static, dropped into every kit verbatim. Per-build parameters live in kit.json beside it, so
# this text is never templated (no f-string/brace/format hazard for a hostile --out name to
# reach into) and is shared byte-for-byte by every emit kit, C or Nim. It is a faithful
# re-implementation of the v2 footer in src/haru_pack/overlay.py; the footer constants below
# MUST equal overlay's (MAGIC/TAIL/FOOTER_V2_SIZE). A test ties them together so a footer
# -version bump in overlay.py that is not reflected here fails CI (INV-EMIT-01), and
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


# ── --emit-c ─────────────────────────────────────────────────────────────────────────────

def emit_c_sources(nimcache: Path, dest: Path, triple: str, exe: str, log=None) -> str:
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
    # nimcache) and the xz .c (from the launcher tree) both appear as compile[i][0]. Nim's
    # mangled names are unique, but two sources sharing a basename would clobber silently and
    # link the wrong object, so refuse that rather than emit a kit that builds the wrong thing.
    seen: dict[str, Path] = {}
    for src, _cmd in nim_json["compile"]:
        s = Path(src)
        prev = seen.get(s.name)
        if prev is not None and prev != s:
            raise EmitError(
                f"two sources share the basename {s.name!r} ({prev} and {s}); the vendored "
                f"kit would clobber one. This is a Nim/emit assumption break — please report it.")
        seen[s.name] = s
        shutil.copy2(s, dest / s.name)
    # Vendor headers so `-I.` resolves everything Nim reached by absolute path: the xz
    # headers next to the xz .c, and nimbase.h from Nim's lib.
    for h in (launcher_src_dir() / "xz").glob("*.h"):
        shutil.copy2(h, dest / h.name)
    shutil.copy2(_find_nimbase(nim_json), dest / "nimbase.h")

    # A durable, machine-independent shim (never this build's tempdir path): it calls
    # `${HARU_ZIG:-zig} cc -target <triple>`, so the kit works on the packager's machine given
    # zig on PATH. Reuses toolchain.zig_cc_shim — the same helper --emit-nim's kit uses — so
    # the GCC-only-flag translation matches a real build.
    toolchain.zig_cc_shim("${HARU_ZIG:-zig}", triple, dest / "zig-cc")
    shim_name = "./zig-cc"

    body = compile_script_body(nim_json, exe, shim_name)
    script = ("#!/bin/sh\n"
              "# Recompile the haru-pack launcher stub, then reassemble the binary.\n"
              "# Generated by haru-pack --emit-c. Needs no Nim; needs a zig on PATH\n"
              "# (or set HARU_ZIG to a zig binary). No absolute build-host paths.\n"
              "set -e\n"
              'cd "$(dirname "$0")"\n'
              + body)
    (dest / "compile.sh").write_text(script)
    (dest / "compile.sh").chmod(0o755)
    say(f"--emit-c: wrote C reproduction kit to {dest} "
        f"({len(nim_json['compile'])} sources; recompile with `sh compile.sh` + a zig on PATH)")
    return shim_name


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

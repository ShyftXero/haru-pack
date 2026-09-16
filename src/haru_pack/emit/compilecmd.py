"""The pure json → zig-command transform, and nothing that touches a filesystem.

This is the part INV-EMIT-02's unit test pins. The Nim C backend assigns PER-FILE compile
flags (nimcrypto's SHA-2 fast paths need `-mssse3`/`-mavx2`) that a blanket `zig cc *.c`
would drop, so the kit's compile.sh is derived from Nim's own build manifest rather than
hand-written. Keeping it pure is what makes that derivation testable without a compiler.

Split out of emit.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import shlex


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


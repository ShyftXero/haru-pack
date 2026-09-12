"""INV-EMIT-02 — `--emit-c` emits a faithful, zig-portable reproduction kit.

Things that must be true, most testable without any compiler:

  1. The json -> zig transform emits the compiler haru uses (the `./zig-cc` shim), keeps every
     per-file flag, locates `-o` positionally, and lets nothing absolute escape.
  2. The emitted `assemble.py` reproduces `overlay.attach`'s bytes exactly (appended + remote)
     and is NOT injectable via a hostile output name.
  3. `emit_c_sources` vendors nimbase.h + the xz headers and writes a RELOCATABLE shim, so the
     C tree is Nim-free and carries no build-host absolute path — checked WITHOUT a toolchain.
  4. An unsafe / occupied `--emit-c` directory is refused up front.

A nim+zig-gated test compiles the emitted C and reassembles a verifying binary; it skips
cleanly where the toolchain is absent, so the pure checks still defend the invariant on a
bare CI box.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from haru_pack import emit, overlay, toolchain
from haru_pack.bootstrap import find_nim


# A minimal stand-in for Nim's launcher.json: one Nim module, one xz source (with a per-file
# SIMD flag), and a link command — the exact shapes emit rewrites.
FAKE_JSON = {
    "compile": [
        ["/abs/nc/@mmain.nim.c",
         "gcc -c -w -fmax-errors=3 -I/nim/lib -I/abs/launcher/xz "
         "-o @mmain.nim.c.o @mmain.nim.c"],
        ["/abs/launcher/xz/xz_crc32.c",
         "gcc -c -w -msse2 -mssse3 -I/nim/lib -I/abs/launcher/xz "
         "-o @mxz@sxz_crc32.c.o xz_crc32.c"],
    ],
    "linkcmd": "gcc -o /abs/out/launcher /abs/nc/@mmain.nim.c.o "
               "/abs/nc/@mxz@sxz_crc32.c.o -lpthread",
}


@pytest.mark.invariant("INV-EMIT-02")
def test_transform_uses_the_zig_shim_and_keeps_per_file_flags():
    """Red-path: make `_rewrite_compile` emit a literal 'gcc' (or any token that is not the
    shim) and this goes red — the recipe would then not be the compiler haru uses."""
    shim = "./zig-cc"
    body = emit.compile_script_body(FAKE_JSON, "launcher", shim)
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert len(lines) == 3, body                      # two compiles + one link
    for ln in lines:
        assert ln.split()[0] == shim, f"command does not invoke the shim: {ln!r}"
    # Per-file flags survive verbatim — dropping -mssse3 breaks nimcrypto's SHA-2 fast path.
    assert "-msse2" in body and "-mssse3" in body


@pytest.mark.invariant("INV-EMIT-02")
def test_transform_is_self_contained():
    """No absolute include escapes the kit, and every mangled source is ./-prefixed so the C
    driver does not read a leading '@' as a response file."""
    body = emit.compile_script_body(FAKE_JSON, "launcher", "./zig-cc")
    assert "/nim/lib" not in body and "/abs/launcher/xz" not in body
    assert "-I." in body
    assert "./@mmain.nim.c" in body                   # source, ./-prefixed
    assert "'./@mmain.nim.c.o'" in body or "./@mmain.nim.c.o" in body   # object too
    # The link step outputs the in-dir stub and links in-dir objects.
    link = [ln for ln in body.splitlines() if ln.strip()][-1]
    assert "-o ./launcher" in link
    assert "/abs/nc/" not in link


def test_rewrite_compile_finds_o_positionally():
    """N1: `-o` is located by position, not assumed third-from-last, so a trailing token would
    not misread OBJ/SRC."""
    line = emit._rewrite_compile("gcc -c -w -I/nim/lib -o @m.nim.c.o @m.nim.c", "./zig-cc")
    assert line.split()[0] == "./zig-cc"
    assert "-o ./@m.nim.c.o" in line
    assert line.split()[-1] == "./@m.nim.c"


def test_transform_handles_system_recorded_commands():
    """N2: under `--cc system` the json records the system compiler and gcc-only flags (incl.
    `-march` on cross). The transform still yields a zig recipe driven through the shim; the
    shim, not the transform, is what drops `-march`."""
    j = {"compile": [["/a/@m.nim.c", "cc -c -march=armv8-a -I/nim/lib -o @m.nim.c.o @m.nim.c"]],
         "linkcmd": "cc -o /a/launcher /a/@m.nim.c.o"}
    body = emit.compile_script_body(j, "launcher", "./zig-cc")
    for ln in [x for x in body.splitlines() if x.strip()]:
        assert ln.split()[0] == "./zig-cc"


# ── assemble.py fidelity + injection safety ──────────────────────────────────────────────

@pytest.mark.invariant("INV-EMIT-02")
def test_assemble_reproduces_overlay_appended(tmp_path):
    """The emitted assembler must produce the SAME bytes as overlay.attach for an appended,
    encrypted build."""
    stub = b"\x7fELF" + bytes(range(256)) * 3
    payload = b"PAYLOAD-ZIP-BYTES" * 11
    sc = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\n'

    stub_file = tmp_path / "launcher"
    stub_file.write_bytes(stub)
    ref = tmp_path / "ref.bin"
    overlay.attach(stub_file, payload, ref, flags=overlay.FOOTER_FLAG_ENCRYPTED,
                   stub_config=sc)

    kit = tmp_path / "kit"
    kit.mkdir()
    (kit / "launcher").write_bytes(stub)
    (kit / "payload.bin").write_bytes(payload)
    (kit / "stubconfig.bin").write_bytes(sc)
    (kit / "compile.sh").write_text("#!/bin/sh\n")
    emit.finish_kit(kit, payload=payload, stub_config=sc,
                    flags=overlay.FOOTER_FLAG_ENCRYPTED, remote=False, exe="launcher",
                    out_name="app", triple="x86_64-linux-gnu", encrypted=True)
    r = subprocess.run([sys.executable, str(kit / "assemble.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (kit / "app").read_bytes() == ref.read_bytes()


@pytest.mark.invariant("INV-EMIT-02")
def test_assemble_reproduces_overlay_remote(tmp_path):
    """Remote-fetch: the binary carries no payload, and the payload lands in a sidecar — both
    must match overlay.attach(remote=True) + the sidecar build() writes."""
    stub = b"\x7fELF" + bytes(range(200)) * 5
    payload = b"REMOTE-CONTAINER" * 9
    sc = b'stub_config_version = 1\nsource_url = "https://x/y"\n\n[canary]\nsecret = "HARU"\n'

    stub_file = tmp_path / "launcher"
    stub_file.write_bytes(stub)
    ref = tmp_path / "ref.bin"
    # attach OR-s in the remote bit itself, so the footer flags become FOOTER_FLAG_REMOTE.
    overlay.attach(stub_file, payload, ref, flags=0, stub_config=sc, remote=True)

    kit = tmp_path / "kit"
    kit.mkdir()
    (kit / "launcher").write_bytes(stub)
    (kit / "payload.bin").write_bytes(payload)
    (kit / "stubconfig.bin").write_bytes(sc)
    (kit / "compile.sh").write_text("#!/bin/sh\n")
    emit.finish_kit(kit, payload=payload, stub_config=sc,
                    flags=overlay.FOOTER_FLAG_REMOTE, remote=True, exe="launcher",
                    out_name="app", triple="x86_64-linux-gnu", encrypted=False,
                    source_url="https://x/y")
    r = subprocess.run([sys.executable, str(kit / "assemble.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (kit / "app").read_bytes() == ref.read_bytes()
    assert (kit / "app.haru-payload").read_bytes() == payload


def _kit_with_blobs(kit):
    kit.mkdir()
    (kit / "launcher").write_bytes(b"\x7fELF" + b"\x00" * 64)
    (kit / "payload.bin").write_bytes(b"payload")
    (kit / "stubconfig.bin").write_bytes(b"cfg")
    (kit / "compile.sh").write_text("#!/bin/sh\n")


@pytest.mark.invariant("INV-EMIT-02")
def test_assemble_py_is_not_injectable_via_out_name(tmp_path):
    """C1 (critical): a hostile `--out` name is data, not code. Red-path: interpolate `out`
    with `"{out}"` instead of `{out!r}` in the template and this goes red — the injected
    `os.system` runs when the auditor executes the kit."""
    kit = tmp_path / "kit"
    _kit_with_blobs(kit)
    # If interpolated raw, this closes the string and runs code that creates a marker file.
    hostile = 'x";import os;os.system("touch PWNED");"'
    emit.finish_kit(kit, payload=b"payload", stub_config=b"cfg", flags=0, remote=False,
                    exe="launcher", out_name=hostile, triple="x86_64-linux-gnu",
                    encrypted=False)
    r = subprocess.run([sys.executable, str(kit / "assemble.py")], cwd=str(tmp_path),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "PWNED").exists(), "injected code executed — out_name not escaped"
    # The hostile string is used verbatim as the (weird but harmless) output filename.
    assert (kit / hostile).exists()


def test_finish_kit_survives_braces_in_out_name(tmp_path):
    """C1 corollary: a name with `{`/`}` must not crash the build's str.format, and the kit
    must still run."""
    kit = tmp_path / "kit"
    _kit_with_blobs(kit)
    weird = "weird{name}.bin"
    emit.finish_kit(kit, payload=b"payload", stub_config=b"cfg", flags=0, remote=False,
                    exe="launcher", out_name=weird, triple="x86_64-linux-gnu",
                    encrypted=False)
    r = subprocess.run([sys.executable, str(kit / "assemble.py")], cwd=str(kit),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (kit / weird).exists()


# ── vendoring completeness, without a toolchain (W2) ──────────────────────────────────────

def _fixture_nimcache(tmp_path):
    """A launcher.json + fake sources + a fake Nim lib holding nimbase.h — enough to run
    emit_c_sources with no Nim and no zig present."""
    nc = tmp_path / "nc"
    nc.mkdir()
    (nc / "@mmain.nim.c").write_text(
        '#include "nimbase.h"\n#include "xz.h"\nint main(void){return 0;}\n')
    nimlib = tmp_path / "nimlib"
    nimlib.mkdir()
    (nimlib / "nimbase.h").write_text("/* fake nimbase */\n")
    xz = emit.launcher_src_dir() / "xz"
    j = {"compile": [[str(nc / "@mmain.nim.c"),
                      f"gcc -c -w -I{nimlib} -I{xz} -o @mmain.nim.c.o @mmain.nim.c"]],
         "linkcmd": f"gcc -o {tmp_path}/launcher {nc}/@mmain.nim.c.o -lpthread"}
    (nc / "launcher.json").write_text(json.dumps(j))
    return nc, nimlib, xz


@pytest.mark.invariant("INV-EMIT-02")
def test_emit_c_sources_vendors_headers_without_toolchain(tmp_path):
    """W2: the compile/vendoring half of the invariant is checkable on a bare box. Red-path:
    remove the `nimbase.h` copy (or an xz-header copy) in emit_c_sources and this goes red
    with no Nim/zig present — the emitted C would no longer compile stand-alone."""
    nc, nimlib, xz = _fixture_nimcache(tmp_path)
    dest = tmp_path / "kit"
    emit.emit_c_sources(nc, dest, "x86_64-linux-gnu", exe="launcher")

    assert (dest / "nimbase.h").exists(), "nimbase.h not vendored"
    for h in xz.glob("*.h"):
        assert (dest / h.name).exists(), f"xz header {h.name} not vendored"
    assert (dest / "@mmain.nim.c").exists(), "source not vendored"

    body = (dest / "compile.sh").read_text()
    assert str(nimlib) not in body and str(xz) not in body, "absolute -I leaked into the recipe"
    assert "-I." in body

    # The shim is relocatable: no build-host absolute path, uses ${HARU_ZIG:-zig}.
    shim = (dest / "zig-cc").read_text()
    assert "${HARU_ZIG:-zig}" in shim
    assert "/home/" not in shim and str(tmp_path) not in shim


def test_emit_c_sources_refuses_basename_collision(tmp_path):
    """N3: two sources with the same basename would clobber one another when vendored."""
    nc = tmp_path / "nc"
    nc.mkdir()
    d1 = tmp_path / "d1"
    d1.mkdir()
    (d1 / "dup.c").write_text("a")
    d2 = tmp_path / "d2"
    d2.mkdir()
    (d2 / "dup.c").write_text("b")
    j = {"compile": [[str(d1 / "dup.c"), "gcc -c -I/nl -o dup.c.o dup.c"],
                     [str(d2 / "dup.c"), "gcc -c -I/nl -o dup.c.o dup.c"]],
         "linkcmd": "gcc -o x y"}
    (nc / "launcher.json").write_text(json.dumps(j))
    with pytest.raises(emit.EmitError, match="basename"):
        emit.emit_c_sources(nc, tmp_path / "kit", "x86_64-linux-gnu", exe="launcher")


# ── directory safety (W3) ─────────────────────────────────────────────────────────────────

def test_validate_emit_dir_refuses_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(emit.EmitError, match="symlink"):
        emit.validate_emit_dir(link)


def test_validate_emit_dir_refuses_nonempty(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "existing").write_text("x")
    with pytest.raises(emit.EmitError, match="not empty"):
        emit.validate_emit_dir(d)


def test_validate_emit_dir_accepts_new_or_empty(tmp_path):
    emit.validate_emit_dir(tmp_path / "does-not-exist-yet")   # no raise
    empty = tmp_path / "empty"
    empty.mkdir()
    emit.validate_emit_dir(empty)                             # no raise


# ── the whole promise, end to end (nim + a zig required) ──────────────────────────────────

@pytest.mark.invariant("INV-EMIT-02")
def test_emitted_c_compiles_with_zig_and_reassembles(tmp_path):
    """Emit the C for a host build, compile it with zig (no Nim), reassemble, and confirm the
    binary verifies. `HARU_ZIG` points the emitted shim at the managed zig, exercising the
    relocatable shim path too."""
    nim = find_nim()
    zig = toolchain.find_managed_zig()
    if not nim or not zig:
        pytest.skip("needs a real Nim and a zig to compile the emitted C")
    if sys.platform == "win32":
        pytest.skip("compile.sh + the zig-cc shim are POSIX shell")

    from haru_pack.build import compile_launcher

    work = tmp_path / "work"
    work.mkdir()
    kit = tmp_path / "kit"
    compile_launcher(nim, "host", work)          # writes nimcache/launcher.json + the C
    emit.emit_c_sources(work / "nimcache", kit, "x86_64-linux-gnu", exe="launcher")

    for name in ("compile.sh", "zig-cc", "nimbase.h"):
        assert (kit / name).exists(), f"kit missing {name}"
    assert list(kit.glob("*.c")), "no C sources emitted"

    payload = b"THE-PACKED-PAYLOAD-ZIP" * 7
    sc = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\n'
    (kit / "payload.bin").write_bytes(payload)
    (kit / "stubconfig.bin").write_bytes(sc)
    emit.finish_kit(kit, payload=payload, stub_config=sc, flags=0, remote=False,
                    exe="launcher", out_name="app", triple="x86_64-linux-gnu",
                    encrypted=False)

    env = dict(os.environ, HARU_ZIG=str(zig))    # the shim resolves zig from here
    r = subprocess.run(["sh", str(kit / "compile.sh")], capture_output=True, text=True,
                       env=env)
    assert r.returncode == 0, r.stderr[-3000:]
    reassembled = kit / "app"
    assert reassembled.exists()

    info = overlay.verify(reassembled)
    assert info["sha_ok"], "payload digest does not verify against the footer"
    assert info["stub_ok"], "stub-config digest does not verify"
    assert info["payload_len"] == len(payload)

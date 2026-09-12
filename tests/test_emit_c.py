"""INV-EMIT-02 — `--emit-c` emits a faithful, zig-only reproduction kit.

Two things must be true and are tested here without needing a compiler:

  1. The json -> zig transform emits the compiler haru actually uses (the `./zig-cc` shim),
     keeping every per-file flag, and never a fabricated command.
  2. The emitted `assemble.py` reproduces `overlay.attach`'s bytes exactly — appended and
     remote-fetch alike.

A third, nim+zig-gated test compiles the emitted C with zig alone and reassembles a binary
that verifies. It skips cleanly where the toolchain is absent, so the two pure checks still
defend the invariant on a bare CI box.
"""
from __future__ import annotations

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


@pytest.mark.invariant("INV-EMIT-02")
def test_emitted_c_compiles_with_zig_alone_and_reassembles(tmp_path):
    """The whole promise, end to end: emit the C for a host build, compile it with zig and no
    Nim, reassemble, and confirm the binary verifies.

    Red-path: drop nimbase.h from the vendored set (or leave an absolute -I in the commands)
    and `sh compile.sh` fails to find a header — the kit stops being self-contained."""
    nim = find_nim()
    zig = toolchain.find_managed_zig()
    if not nim or not zig:
        pytest.skip("needs a real Nim and the managed zig to compile the emitted C")
    if sys.platform == "win32":
        pytest.skip("compile.sh + the zig-cc shim are POSIX shell")

    from haru_pack.build import compile_launcher

    work = tmp_path / "work"
    work.mkdir()
    kit = tmp_path / "kit"
    compile_launcher(nim, "host", work, emit_c=kit)

    # The kit is self-contained.
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

    r = subprocess.run(["sh", str(kit / "compile.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-3000:]
    reassembled = kit / "app"
    assert reassembled.exists()

    info = overlay.verify(reassembled)
    assert info["sha_ok"], "payload digest does not verify against the footer"
    assert info["stub_ok"], "stub-config digest does not verify"
    assert info["payload_len"] == len(payload)

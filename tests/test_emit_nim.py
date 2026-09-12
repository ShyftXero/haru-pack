"""INV-EMIT-01 — the --emit-nim reproduction kit is faithful.

Two claims, both checkable without Nim or a C compiler (the kit copies SOURCE and writes a
reassembler; neither needs a real build to inspect):

  1. The Nim source in the kit is byte-identical to what haru-pack actually compiles
     (`launcher_src_dir()`).
  2. The emitted `assemble.py` + `payload.bin` + `stubconfig.bin` reproduce the exact overlay
     `overlay.attach()` would have written — same footer, offsets and digests — for both an
     appended and a remote-fetch build.

Red-path (walked before promoting the entry): make `emit_nim_kit` copy a stale/partial tree,
or make `assemble.py` pack the footer differently from `overlay.attach`, and the matching
assertion below goes red.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from haru_pack import emit
from haru_pack.overlay import attach, verify
from haru_pack.paths import launcher_src_dir
from haru_pack.targets import Target


def _tree(root: Path) -> dict:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


@pytest.mark.invariant("INV-EMIT-01")
def test_kit_source_is_byte_identical_to_what_haru_compiles(tmp_path):
    dest = tmp_path / "kit"
    emit.emit_nim_kit(dest, tgt=Target.parse("host"), nim="/opt/nim/bin/nim",
                      provider="zig", payload=b"payload-bytes", stub_config=b"[canary]\n",
                      flags=0, remote=False, out_name="app")
    assert _tree(dest / "stub") == _tree(launcher_src_dir()), (
        "the emitted Nim tree diverged from launcher_src_dir(); the kit would compile "
        "something other than what haru-pack ships"
    )
    # main.nim is the entrypoint compile.sh names — it must be present.
    assert (dest / "stub" / "main.nim").is_file()


@pytest.mark.invariant("INV-EMIT-01")
@pytest.mark.parametrize("remote", [False, True])
def test_assemble_reproduces_overlay_attach(tmp_path, remote):
    # A plausible compiled stub. The reassembler is agnostic to the stub's contents; what it
    # must get right is the footer/offsets/digests, which is exactly what this pins.
    stub_bytes = b"\x7fELF" + b"\x01\x02\x03" * 400
    payload = b"the-payload-zip-or-crypto-container" * 7
    sc = b"stub_config_version = 1\n\n[canary]\nsecret = \"HARU\"\n"
    flags = 1  # pretend encrypted, so the flags byte is non-zero and must round-trip

    stub_file = tmp_path / ("launcher.exe" if remote else "launcher")
    stub_file.write_bytes(stub_bytes)

    dest = tmp_path / "kit"
    emit.emit_nim_kit(dest, tgt=Target.parse("host"), nim="/opt/nim/bin/nim",
                      provider="zig", payload=payload, stub_config=sc,
                      flags=flags, remote=remote, out_name="app")

    # What overlay.attach would have written for the same inputs.
    ref = tmp_path / "ref.bin"
    attach(stub_file, payload, ref, flags=flags, stub_config=sc, remote=remote)

    got = tmp_path / "got.bin"
    r = subprocess.run([sys.executable, str(dest / "assemble.py"),
                        str(stub_file), str(got)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert got.read_bytes() == ref.read_bytes(), (
        "assemble.py did not reproduce overlay.attach's bytes; the kit would build a binary "
        "haru-pack never would"
    )
    # And the reproduced binary is a valid haru overlay. A remote build embeds no payload
    # (the launcher fetches it), so its in-file payload digest is deliberately unsatisfied —
    # exactly as overlay.attach(remote=True) leaves it. The stub-config is always present.
    v = verify(got)
    assert v["stub_ok"]
    if remote:
        assert v["payload_len"] == 0
    else:
        assert v["sha_ok"]


@pytest.mark.invariant("INV-EMIT-01")
def test_emit_nim_through_a_real_build_reassembles_the_shipped_binary(
        stub_toolchain, script_project, tmp_path):
    """The strongest form: run the real build() with --emit-nim, then prove the kit's
    assemble.py + emitted blobs reproduce the very binary the build shipped. The stub
    toolchain fakes only the C compile, so everything the kit captures is real."""
    out = tmp_path / "hello"
    kit = tmp_path / "kit"
    info = stub_toolchain.build(script_project, out, target="host", tier="thin",
                                emit_nim=str(kit))
    assert info["emit_nim"] == str(kit)
    assert (kit / "stub" / "main.nim").is_file()
    assert (kit / "compile.sh").is_file()

    # Carve the compiled-stub prefix out of the shipped binary and feed it to assemble.py.
    shipped = out.read_bytes()
    v = verify(out)
    stub_prefix = tmp_path / "launcher"
    stub_prefix.write_bytes(shipped[:v["payload_off"]])

    rebuilt = tmp_path / "hello.rebuilt"
    r = subprocess.run([sys.executable, str(kit / "assemble.py"),
                        str(stub_prefix), str(rebuilt)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert rebuilt.read_bytes() == shipped, (
        "the emitted kit did not reproduce the binary this build shipped"
    )


@pytest.mark.invariant("INV-EMIT-01")
def test_compile_sh_names_the_resolved_target(tmp_path):
    dest = tmp_path / "kit"
    emit.emit_nim_kit(dest, tgt=Target.parse("windows-x86_64"), nim="/opt/nim/bin/nim",
                      provider="zig", payload=b"p", stub_config=b"[canary]\n",
                      flags=0, remote=False, out_name="app.exe")
    sh = (dest / "compile.sh").read_text()
    tgt = Target.parse("windows-x86_64")
    assert f"--cpu:{tgt.nim_cpu}" in sh
    assert f"--os:{tgt.nim_os}" in sh
    assert "assemble.py" in sh          # the script chains compile -> reassemble
    assert (dest / "zig-cc").is_file()  # the durable, portable shim is present

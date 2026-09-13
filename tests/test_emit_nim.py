"""INV-EMIT-01 — the --emit-nim reproduction kit is faithful to the build it came from.

What is proven here, and how much of it needs a real toolchain:

  * The Nim source in the kit is byte-identical to what haru-pack compiles
    (`launcher_src_dir()`).                                            [no toolchain]
  * The emitted `assemble.py` reproduces `overlay.attach`'s exact bytes for the SAME stub,
    appended and remote.                                              [no toolchain]
  * The `nim c` flag set the kit's compile.sh uses is the SAME object `build.compile_launcher`
    uses, so the recipe cannot drift.                                 [no toolchain]
  * A REAL recompile of the emitted stub with the emitted compile.sh yields a WORKING binary:
    its overlay verifies and its payload + stub-config bytes match the shipped binary. Byte
    -for-byte identity of the launcher is NOT claimed — a Nim/C recompile is not reproducible
    in general.                                                       [nim + zig gated]

Red-path (walked before promoting the entry): make the kit copy a stale tree, make assemble.py
pack the footer differently, or let `_nim_compile_args` drift from `compile_launcher`, and the
matching assertion below goes red.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from haru_pack import emit
from haru_pack import overlay
from haru_pack.bootstrap import find_nim
from haru_pack.overlay import attach, verify
from haru_pack.paths import launcher_src_dir
from haru_pack.targets import Target
from haru_pack import toolchain


def _tree(root: Path) -> dict:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*")) if p.is_file()
    }


@pytest.mark.invariant("INV-EMIT-01")
def test_kit_source_is_byte_identical_to_what_haru_compiles(tmp_path):
    dest = tmp_path / "kit"
    emit.emit_nim_kit(dest, tgt=Target.parse("host"), provider="zig",
                      payload=b"payload-bytes", stub_config=b"[canary]\n",
                      flags=0, remote=False, out_name="app")
    assert _tree(dest / "stub") == _tree(launcher_src_dir()), (
        "the emitted Nim tree diverged from launcher_src_dir(); the kit would compile "
        "something other than what haru-pack ships"
    )
    assert (dest / "stub" / "main.nim").is_file()


@pytest.mark.invariant("INV-EMIT-01")
@pytest.mark.parametrize("remote", [False, True])
def test_assemble_reproduces_overlay_attach(tmp_path, remote):
    # Given the SAME stub, assemble.py must produce exactly what overlay.attach would. This
    # pins the reassembler's footer/offsets/digests; it does not involve a recompile.
    stub_bytes = b"\x7fELF" + b"\x01\x02\x03" * 400
    payload = b"the-payload-zip-or-crypto-container" * 7
    sc = b"stub_config_version = 1\n\n[canary]\nsecret = \"HARU\"\n"
    flags = 1  # pretend encrypted, so the flags byte is non-zero and must round-trip

    stub_file = tmp_path / ("launcher.exe" if remote else "launcher")
    stub_file.write_bytes(stub_bytes)

    dest = tmp_path / "kit"
    emit.emit_nim_kit(dest, tgt=Target.parse("host"), provider="zig",
                      payload=payload, stub_config=sc, flags=flags, remote=remote,
                      out_name="app")

    ref = tmp_path / "ref.bin"
    attach(stub_file, payload, ref, flags=flags, stub_config=sc, remote=remote)

    got = tmp_path / "got.bin"
    r = subprocess.run([sys.executable, str(dest / "assemble.py"),
                        str(stub_file), str(got)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert got.read_bytes() == ref.read_bytes(), (
        "assemble.py did not reproduce overlay.attach's bytes; the kit would build a binary "
        "haru-pack never would"
    )
    v = verify(got)
    assert v["stub_ok"]
    if remote:
        assert v["payload_len"] == 0
    else:
        assert v["sha_ok"]


@pytest.mark.invariant("INV-EMIT-01")
def test_nim_target_flags_are_the_same_object_compile_launcher_uses(tmp_path, monkeypatch):
    """Lockstep: the flags the kit's compile.sh carries are exactly the flags
    build.compile_launcher passes to `nim c`. A flag added to the real compile that bypasses
    emit.nim_target_flags would break this — the kit can no longer silently drift."""
    from haru_pack import build as build_mod

    captured = {}

    def fake_run(argv, *a, **k):
        captured["argv"] = list(argv)
        for tok in argv:
            if tok.startswith("--out:"):
                Path(tok[len("--out:"):]).write_bytes(b"\x7fELF")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(build_mod.toolchain, "find_managed_zig", lambda: Path("/fake/zig"))
    monkeypatch.setattr(build_mod.toolchain, "zig_cc_shim",
                        lambda zig, triple, dest: Path("/fake/zig-cc"))
    monkeypatch.setattr(build_mod.subprocess, "run", fake_run)

    tgt = Target.parse("host")
    build_mod.compile_launcher("/fake/nim", tgt, tmp_path, cc="zig")

    argv = captured["argv"]
    expected_flags = emit.nim_target_flags(tgt, "zig", "/fake/zig-cc")
    # argv == [nim, "c", *flags, --nimcache, --out, src]
    assert argv[:2] == ["/fake/nim", "c"]
    assert argv[2:2 + len(expected_flags)] == expected_flags, (
        "build.compile_launcher's nim flags diverged from emit.nim_target_flags; the emitted "
        "compile.sh would no longer reproduce the real build"
    )
    tail = argv[2 + len(expected_flags):]
    assert tail[0].startswith("--nimcache:")
    assert tail[1].startswith("--out:")
    assert tail[2] == str(launcher_src_dir() / "main.nim")


@pytest.mark.invariant("INV-EMIT-01")
def test_emit_footer_constants_track_overlay():
    """assemble.py hardcodes the v2 footer shape; if overlay.py bumps it, this fails so the
    kit is updated rather than silently emitting a stale reassembler (N2)."""
    src = emit._ASSEMBLE_PY
    assert f"FOOTER_V2_SIZE = {overlay.FOOTER_V2_SIZE}" in src
    assert overlay.MAGIC.decode() in src
    assert overlay.TAIL.decode() in src


@pytest.mark.invariant("INV-EMIT-01")
def test_compile_sh_names_the_resolved_target(tmp_path):
    dest = tmp_path / "kit"
    emit.emit_nim_kit(dest, tgt=Target.parse("windows-x86_64"), provider="zig",
                      payload=b"p", stub_config=b"[canary]\n", flags=0, remote=False,
                      out_name="app.exe")
    sh = (dest / "compile.sh").read_text()
    tgt = Target.parse("windows-x86_64")
    assert f"--cpu:{tgt.nim_cpu}" in sh
    assert f"--os:{tgt.nim_os}" in sh
    assert "assemble.py" in sh
    assert (dest / "zig-cc").is_file()
    # W3: no build-host absolute paths — Nim resolves via PATH/HARU_NIM only.
    assert 'NIM="${HARU_NIM:-nim}"' in sh
    assert "/home/" not in sh and os.path.expanduser("~") not in sh


@pytest.mark.invariant("INV-EMIT-01")
def test_a_real_recompile_yields_a_working_equivalent(tmp_path):
    """The load-bearing test: actually recompile the emitted stub with nim+zig, reassemble,
    and prove the result is a working equivalent of the shipped binary. Gated on the real
    toolchain (present on the dev box; skipped in a bare CI)."""
    nim = find_nim()
    zig = toolchain.find_managed_zig()
    if not nim or not zig:
        pytest.skip("needs nim + managed zig for a real recompile")
    from haru_pack import build as build_mod

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "hello.py").write_text("print('hi from emit-nim recompile')\n")
    out = tmp_path / "hello"
    kit = tmp_path / "kit"
    info = build_mod.build(proj, out, target="host", tier="thin", emit_nim=str(kit))
    assert out.exists() and info.get("emit_nim") == str(kit)

    env = dict(os.environ, HARU_NIM=nim, HARU_ZIG=str(zig))
    r = subprocess.run(["sh", "compile.sh"], cwd=kit, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"compile.sh failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    rebuilt = kit / "hello"
    assert rebuilt.exists(), "compile.sh did not produce the reassembled binary"

    vs, vr = verify(out), verify(rebuilt)
    # The recompiled binary is a valid, integrity-passing haru overlay …
    assert vr["sha_ok"] and vr["stub_ok"]
    # … and it carries this build's exact payload and stub-config (a working equivalent; we do
    # NOT claim the launcher recompiled byte-for-byte).
    ship, reb = out.read_bytes(), rebuilt.read_bytes()
    assert (ship[vs["payload_off"]:vs["payload_off"] + vs["payload_len"]]
            == reb[vr["payload_off"]:vr["payload_off"] + vr["payload_len"]]), \
        "recompiled binary's payload differs from the shipped binary's"
    assert (ship[vs["stub_off"]:vs["stub_off"] + vs["stub_len"]]
            == reb[vr["stub_off"]:vr["stub_off"] + vr["stub_len"]]), \
        "recompiled binary's stub-config differs from the shipped binary's"


@pytest.mark.invariant("INV-EMIT-01")
def test_emit_refuses_a_symlink_destination(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(emit.EmitError):
        emit.emit_nim_kit(link, tgt=Target.parse("host"), provider="zig",
                          payload=b"p", stub_config=b"s", flags=0, remote=False,
                          out_name="app")


@pytest.mark.invariant("INV-EMIT-01")
def test_emit_refuses_to_delete_a_foreign_nonempty_stub_dir(tmp_path):
    dest = tmp_path / "kit"
    (dest / "stub").mkdir(parents=True)
    keep = dest / "stub" / "important.txt"
    keep.write_text("do not delete me")
    with pytest.raises(emit.EmitError):
        emit.emit_nim_kit(dest, tgt=Target.parse("host"), provider="zig",
                          payload=b"p", stub_config=b"s", flags=0, remote=False,
                          out_name="app")
    assert keep.read_text() == "do not delete me"   # untouched


@pytest.mark.invariant("INV-EMIT-01")
def test_emit_failure_does_not_fail_the_build(stub_toolchain, script_project, tmp_path,
                                              monkeypatch):
    """W2b: the binary is written and chmod'd before the kit; a kit failure must surface as a
    warning, not turn a good build into a failed one."""
    def boom(*a, **k):
        raise emit.EmitError("simulated kit failure")

    monkeypatch.setattr(stub_toolchain.emit_mod, "emit_nim_kit", boom)
    out = tmp_path / "hello"
    info = stub_toolchain.build(script_project, out, target="host", tier="thin",
                                emit_nim=str(tmp_path / "kit"))
    assert out.exists(), "the packed binary should still be produced"
    assert info.get("emit_nim") is None
    assert "simulated kit failure" in info.get("emit_nim_error", "")


@pytest.mark.invariant("INV-SECRET-02")
def test_emit_kit_never_contains_the_build_secret(stub_toolchain, script_project, tmp_path):
    """W1: an --encrypt build's kit must not leak the key. The secret is used to derive the
    encryption key and is never stored (no --embed-secret), so it must appear in NO kit file."""
    secret = b"S3CR3T-emit-key-do-not-leak-0xDEADBEEFCAFE"
    out = tmp_path / "hello"
    kit = tmp_path / "kit"
    stub_toolchain.build(script_project, out, target="host", tier="thin",
                         encrypt=True, secret=secret, emit_nim=str(kit))
    leaked = [str(p.relative_to(kit)) for p in kit.rglob("*")
              if p.is_file() and secret in p.read_bytes()]
    assert not leaked, f"build secret leaked into kit files: {leaked}"

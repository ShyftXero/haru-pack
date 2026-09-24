"""INV-STAGE-01 (#4 relaxation) + the `--<canary>-reinstall` reserved arg (#3).

Three things, all walked here:

  * BUILD BACKSTOP (pure Python, no nim) — `build.resolve_writable` refuses to declare writable
    any importable/executable file (`.pth`/`.py`/`.so`/…, the interpreter tree, `uv`, a `+x`
    file). This is the load-bearing safety: a writable code path is a same-uid RCE primitive, so
    it fails the BUILD, not the customer. These are Red-path (c).

  * LAUNCHER RELAXATION (end-to-end, real nim launcher) — a build-DECLARED `data/app.db` may
    change on reuse (rc 0 on the 2nd run, Red-path a); a NON-declared bundled file is still
    byte-verified and a rewrite is fatal (Red-path b); replacing the declared file with a symlink
    is refused (Red-path d); and the fatal mismatch NAMES the file and points at
    `--<canary>-reinstall` (the unconditional error-message fix).

  * REINSTALL (#3, end-to-end) — `--<canary>-reinstall` WIPES then re-extracts the launcher's OWN
    computed subtree (never a path from arg/env), is consumed before the child sees it, tracks the
    build canary, and never touches a sibling of its subtree.

The build (Python) half of the stub-config emission is also checked here through a real build().

Red-paths for INV-STAGE-01 walk on a nim host; the backstop half runs everywhere, so INV-STAGE-01
keeps a claimant that executes even on a no-nim box.
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest
from _stage_helpers import (build_payload_zip, make_payload, pack, run, stage_from, stub_toml2)

from haru_pack.build import BuildError, resolve_writable, stub_config_bytes
from haru_pack.overlay import verify

# uv echoes the stage dir AND its own argv, so a test can find the stage and prove a reserved arg
# was consumed before the child ran.
UV_ECHO = ('echo "PAYLOAD_UV_RAN"\n'
           'echo "STAGE=$HARUPACK_STAGE"\n'
           'echo "ARGS=$*"\n'
           'exit 0')

MANIFEST = {"app_subdir": "app", "entrypoint": ["hello.py"]}


# ── BUILD BACKSTOP — Red-path (c): a writable code/executable file fails the build ────────────

def _tree(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    (root / "data" / "app.db").write_bytes(b"seed")
    (root / "plugins").mkdir()
    (root / "plugins" / "hook.pth").write_text("import os\n")
    (root / "app").mkdir()
    (root / "app" / "hello.py").write_text("print('hi')\n")
    (root / "vendor" / "python" / "bin").mkdir(parents=True)
    (root / "vendor" / "python" / "bin" / "python3").write_bytes(b"ELF")
    (root / "vendor" / "uv.xz").write_bytes(b"xz")
    sh = root / "data" / "run.sh"
    sh.write_text("#!/bin/sh\n")
    sh.chmod(sh.stat().st_mode | stat.S_IXUSR)
    return root


@pytest.mark.invariant("INV-STAGE-01")
def test_writable_resolves_a_data_glob_to_exact_members(tmp_path):
    d = _tree(tmp_path / "p")
    assert resolve_writable(d, ["data/app.db"], MANIFEST) == ["data/app.db"]
    assert resolve_writable(d, ["data/*.db"], MANIFEST) == ["data/app.db"]


@pytest.mark.invariant("INV-STAGE-01")
def test_writable_refuses_a_pth_file(tmp_path):
    """`.pth` is pure code — site executes its import lines at startup. Hard refuse (Red-path c)."""
    d = _tree(tmp_path / "p")
    with pytest.raises(BuildError, match=r"\.pth"):
        resolve_writable(d, ["plugins/hook.pth"], MANIFEST)


@pytest.mark.invariant("INV-STAGE-01")
def test_writable_refuses_an_executable_bit_file(tmp_path):
    d = _tree(tmp_path / "p")
    with pytest.raises(BuildError, match="executable bit"):
        resolve_writable(d, ["data/run.sh"], MANIFEST)


@pytest.mark.invariant("INV-STAGE-01")
@pytest.mark.parametrize("rel", ["app/hello.py", "vendor/python/bin/python3", "vendor/uv.xz"])
def test_writable_refuses_code_interpreter_and_uv(tmp_path, rel):
    d = _tree(tmp_path / "p")
    with pytest.raises(BuildError):
        resolve_writable(d, [rel], MANIFEST)


@pytest.mark.invariant("INV-STAGE-01")
def test_writable_refuses_a_glob_that_catches_any_code_file(tmp_path):
    """An over-broad glob that sweeps in a code file fails the BUILD — the safe direction."""
    d = _tree(tmp_path / "p")
    with pytest.raises(BuildError):
        resolve_writable(d, ["**/*"], MANIFEST)


# ── BUILD end-to-end: --writable rides the (signature-covered) stub-config + the receipt ──────

@pytest.mark.invariant("INV-STAGE-01")
def test_build_bakes_writable_into_stub_and_receipt(stub_toolchain, tmp_path):
    # Two top-level .py files + an explicit --entry-point makes discovery copy the WHOLE dir into
    # app/ (a single-.py dir would ship only that file), so the bundled data seed lands at
    # app/data/app.db — the stage-relative path the --writable glob resolves against.
    proj = tmp_path / "proj"
    (proj / "data").mkdir(parents=True)
    (proj / "hello.py").write_text("print('hi')\n")
    (proj / "helper.py").write_text("x = 1\n")
    (proj / "data" / "app.db").write_bytes(b"seed")
    out = tmp_path / "app"
    info = stub_toolchain.build(proj, out, tier="thin", entry_point="hello.py",
                                writable=["app/data/app.db"])
    sc = verify(out)["stub_config"]
    assert 'writable = ["app/data/app.db"]' in sc, sc
    assert info["staging"]["writable"] == ["app/data/app.db"]


@pytest.mark.invariant("INV-STAGE-01")
def test_build_refuses_declaring_a_source_file_writable(stub_toolchain, tmp_path):
    """End-to-end through build(): declaring the app's own .py writable fails the build."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "hello.py").write_text("print('hi')\n")
    out = tmp_path / "app"
    with pytest.raises(Exception):   # typer.Exit(2) wraps the BuildError at the CLI boundary
        stub_toolchain.build(proj, out, tier="thin", writable=["app/hello.py"])


def test_default_build_stub_config_has_no_writable_key():
    """No --writable -> the key is absent, so the v1 corpus stays byte-identical."""
    c = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    assert b"writable" not in stub_config_bytes(c)


# ── LAUNCHER end-to-end (real nim launcher) ───────────────────────────────────────────────────

def _pack(nim_launcher, tmp_path, *, writable=(), canary_secret="HARU", extra_files=None):
    src = make_payload(tmp_path / "p", uv_body=UV_ECHO,
                       extra_files=extra_files or {"data/app.db": b"seed-v1",
                                                   "bin/python": b"#!/real/python\n"})
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(secret=canary_secret, writable=list(writable)))
    return exe


@pytest.mark.invariant("INV-STAGE-01")
def test_declared_writable_file_may_change_on_reuse(nim_launcher, tmp_path):
    """Red-path (a): declare data/app.db writable, stage, rewrite it -> the 2nd run is rc 0.
    Neutralise by dropping the `mutable:` branch in recordTree/verifyTree -> the rewrite is
    treated as tampering and the 2nd run fails."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"])
    r1 = run(exe, tmp_path)
    assert r1.returncode == 0 and "PAYLOAD_UV_RAN" in r1.stdout, (r1.returncode, r1.stderr)
    stage = Path(stage_from(r1.stdout))
    db = stage / "data" / "app.db"
    db.write_bytes(b"the-app-mutated-me-between-runs")     # app rewrites its bundled seed
    r2 = run(exe, tmp_path)
    assert r2.returncode == 0 and "PAYLOAD_UV_RAN" in r2.stdout, (r2.returncode, r2.stderr)
    assert db.read_bytes() == b"the-app-mutated-me-between-runs"   # not restored, not refused


@pytest.mark.invariant("INV-STAGE-01")
def test_non_declared_bundled_file_is_still_byte_verified(nim_launcher, tmp_path):
    """Red-path (b): a NON-declared bundled file (bin/python) is still hash-pinned — rewriting it
    is fatal on reuse. Only data/app.db was declared writable."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"])
    r1 = run(exe, tmp_path)
    assert r1.returncode == 0, (r1.returncode, r1.stderr)
    stage = Path(stage_from(r1.stdout))
    (stage / "bin" / "python").write_bytes(b"#!/attacker/python\n")
    r2 = run(exe, tmp_path)
    assert r2.returncode != 0, "a rewritten non-declared file was accepted on reuse"
    assert "PAYLOAD_UV_RAN" not in r2.stdout
    assert "bin/python" in r2.stderr, r2.stderr


@pytest.mark.invariant("INV-STAGE-01")
def test_declared_writable_replaced_by_a_symlink_is_refused(nim_launcher, tmp_path):
    """Red-path (d): the mutable branch must refuse a symlink swapped in for the declared file —
    bytes are unpinned, but presence+kind+not-a-symlink are not."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"])
    r1 = run(exe, tmp_path)
    assert r1.returncode == 0, (r1.returncode, r1.stderr)
    stage = Path(stage_from(r1.stdout))
    db = stage / "data" / "app.db"
    target = tmp_path / "outside.txt"
    target.write_bytes(b"outside")
    db.unlink()
    db.symlink_to(target)
    r2 = run(exe, tmp_path)
    assert r2.returncode != 0, "a symlink swapped in for a declared-writable file was accepted"
    assert "PAYLOAD_UV_RAN" not in r2.stdout
    assert "symlink" in r2.stderr and "data/app.db" in r2.stderr, r2.stderr


@pytest.mark.invariant("INV-STAGE-01")
def test_mismatch_error_names_the_file_and_the_reinstall_remedy(nim_launcher, tmp_path):
    """The unconditional error-message fix: a modified NON-declared file surfaces verifyTree's
    specific error — naming the file, the data-dir diagnosis, and the --<canary>-reinstall remedy —
    NOT the generic 'foreign .ready' wording (which is kept only for a token mismatch)."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"])
    r1 = run(exe, tmp_path)
    assert r1.returncode == 0, (r1.returncode, r1.stderr)
    stage = Path(stage_from(r1.stdout))
    (stage / "bin" / "python").write_bytes(b"changed\n")
    r2 = run(exe, tmp_path)
    assert r2.returncode != 0
    err = r2.stderr
    assert "bin/python" in err
    assert "changed since it was unpacked" in err
    assert "--haru-reinstall" in err
    assert "SHARP_CORNERS.md section E" in err
    assert "foreign" not in err, "the token-mismatch wording leaked into a content-change error"


@pytest.mark.invariant("INV-STAGE-01")
def test_reinstall_wipes_and_reextracts(nim_launcher, tmp_path):
    """#3: after a fatal mismatch, --haru-reinstall WIPES the own-subtree and re-extracts from the
    payload — restoring even a non-declared file the operator (or an attacker) had changed. This is
    the DELIBERATE recovery; a mismatch is never auto-healed."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"])
    r1 = run(exe, tmp_path)
    stage = Path(stage_from(r1.stdout))
    (stage / "bin" / "python").write_bytes(b"tampered\n")
    (stage / "data" / "app.db").write_bytes(b"mutated")
    # mismatch is fatal without reinstall
    assert run(exe, tmp_path).returncode != 0
    # deliberate reinstall recovers
    r3 = run(exe, tmp_path, args=["--haru-reinstall"])
    assert r3.returncode == 0 and "PAYLOAD_UV_RAN" in r3.stdout, (r3.returncode, r3.stderr)
    assert (stage / "bin" / "python").read_bytes() == b"#!/real/python\n"   # re-extracted
    assert (stage / "data" / "app.db").read_bytes() == b"seed-v1"           # writable state discarded


@pytest.mark.invariant("INV-STAGE-01")
def test_reinstall_arg_is_consumed_before_the_child(nim_launcher, tmp_path):
    """#3: the reserved arg is filtered out of the child's argv; a normal user arg passes through."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"])
    r = run(exe, tmp_path, args=["--haru-reinstall", "realarg"])
    assert r.returncode == 0, (r.returncode, r.stderr)
    args_line = next((ln for ln in r.stdout.splitlines() if ln.startswith("ARGS=")), "")
    assert "realarg" in args_line
    assert "--haru-reinstall" not in args_line, args_line


@pytest.mark.invariant("INV-REAP-01")
def test_reinstall_wipes_only_its_own_subtree(nim_launcher, tmp_path):
    """#3: the wipe target is ONLY stageZip's own computed subtree, through the shared shredGuard —
    a sentinel beside the subtree survives (INV-REAP-01 / INV-BASE-01 own-subtree-only)."""
    base = tmp_path / "b"
    base.mkdir()
    src = make_payload(tmp_path / "p", uv_body=UV_ECHO, extra_files={"data/app.db": b"seed"})
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(base_path=str(base), writable=["data/app.db"]))
    r1 = run(exe, tmp_path)
    stage = Path(stage_from(r1.stdout))
    assert stage.parent == base
    sentinel = base / "KEEP_ME.txt"
    sentinel.write_text("do not delete me\n")
    r2 = run(exe, tmp_path, args=["--haru-reinstall"])
    assert r2.returncode == 0, (r2.returncode, r2.stderr)
    assert sentinel.exists(), "reinstall deleted a sibling of its own subtree"
    assert stage.exists() and (stage / "data" / "app.db").read_bytes() == b"seed"


@pytest.mark.invariant("INV-STAGE-01")
def test_reinstall_prefix_tracks_the_build_canary(nim_launcher, tmp_path):
    """#3 white-label: a build whitelabelled with secret canary ACME accepts --acme-reinstall, and
    the default --haru-reinstall no longer matches (so it reaches the child as a plain arg)."""
    exe = _pack(nim_launcher, tmp_path, writable=["data/app.db"], canary_secret="ACME")
    r1 = run(exe, tmp_path)
    stage = Path(stage_from(r1.stdout))
    (stage / "bin" / "python").write_bytes(b"tampered\n")
    # the default prefix does NOT match this white-label build -> passed through, mismatch stays fatal
    r_wrong = run(exe, tmp_path, args=["--haru-reinstall"])
    assert r_wrong.returncode != 0, "a white-label build honoured the default --haru- prefix"
    # the build's own prefix wipes and recovers
    r_ok = run(exe, tmp_path, args=["--acme-reinstall"])
    assert r_ok.returncode == 0 and "PAYLOAD_UV_RAN" in r_ok.stdout, (r_ok.returncode, r_ok.stderr)
    assert (stage / "bin" / "python").read_bytes() == b"#!/real/python\n"

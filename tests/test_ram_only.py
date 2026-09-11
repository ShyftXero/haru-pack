"""INV-RAM-01 / INV-BASE-01 — RAM-backed staging and the staging-root precedence + refusal
(Phase 2 of ADR 0004 §3/§4/§6).

The launcher (Nim) half of --ram-only and --base-path: the /dev/shm mechanism, the
`BASE_PATH env > stub base_path > (ram_only ? RAM : cache)` precedence, and the refusal of an
unsafe root. Launcher tests compile the real launcher, attach a real payload + a v2
stub-config, and run it. The build (Python) half — that --base-path is refused at build time,
and that the flags bake into the stub-config/receipt — is the `resolve_base_path` tests below
(no launcher needed) plus tests/test_canary.py.

Red-paths walked 2026-09-10 on this Linux host (neutralize -> observe red -> restore):
  * INV-RAM-01   make stage.ramBackedRoot return baseDir() -> staging leaves /dev/shm and
                 test_ram_only_stages_under_dev_shm goes red.
  * INV-BASE-01  make stage.refuseUnsafeRoot return "" -> a root base_path is no longer
                 refused; reorder main.resolveStagingRoot so stub base_path beats the env ->
                 test_env_base_path_overrides_stub_base_path goes red; drop the _is_root_like
                 raise in build.resolve_base_path -> test_build_refuses_root_base_path goes red.

See docs/adr/0004-reap-ram-staging.md and the INVARIANTS.md entries.
"""
from __future__ import annotations

import os
import shutil

import pytest
from _stage_helpers import (
    DEV_SHM,
    EXIT_BAD_STUB,
    build_payload_zip,
    make_payload,
    pack,
    run,
    stage_from,
    stub_toml2,
)

from haru_pack.build import BuildError, resolve_base_path

# ─────────────────────────────────────────────────────────────── INV-BASE-01 (precedence)

@pytest.mark.invariant("INV-BASE-01")
def test_stub_base_path_relocates_staging(nim_launcher, tmp_path):
    """A build-time base_path moves staging off the normal per-user cache."""
    altbase = tmp_path / "altbase"; altbase.mkdir()
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(base_path=str(altbase)))
    r = run(exe, tmp_path)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = stage_from(r.stdout)
    assert stage and stage.startswith(str(altbase) + os.sep), stage
    assert "/cache/haru-pack/" not in stage, f"staged under the cache despite base_path: {stage}"


@pytest.mark.invariant("INV-BASE-01")
def test_env_base_path_overrides_stub_base_path(nim_launcher, tmp_path):
    """Precedence: BASE_PATH env beats the baked stub base_path. Red-path: reorder
    resolveStagingRoot to consult sc.basePath first -> this goes red."""
    stubbase = tmp_path / "stub"; stubbase.mkdir()
    envbase = tmp_path / "env"; envbase.mkdir()
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(base_path=str(stubbase)))
    r = run(exe, tmp_path, env_extra={"HARU_BASE_PATH": str(envbase)})
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = stage_from(r.stdout)
    assert stage and stage.startswith(str(envbase) + os.sep), stage
    assert not stage.startswith(str(stubbase)), f"stub base_path beat the env: {stage}"


@pytest.mark.invariant("INV-BASE-01")
def test_base_path_env_respects_the_canary(nim_launcher, tmp_path):
    """The BASE_PATH knob's env NAME comes from the canary map (INV-CANARY-01): with the
    base_path canary set to MARK, MARK_BASE_PATH is honored and HARU_BASE_PATH is ignored."""
    envbase = tmp_path / "env"; envbase.mkdir()
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(base_path_canary="MARK"))
    # HARU_BASE_PATH must NOT be read when the canary is MARK.
    r1 = run(exe, tmp_path, env_extra={"HARU_BASE_PATH": str(envbase)})
    s1 = stage_from(r1.stdout)
    assert s1 and not s1.startswith(str(envbase)), f"HARU_BASE_PATH honored despite MARK: {s1}"
    # MARK_BASE_PATH IS read.
    r2 = run(exe, tmp_path, env_extra={"MARK_BASE_PATH": str(envbase)})
    s2 = stage_from(r2.stdout)
    assert s2 and s2.startswith(str(envbase) + os.sep), s2


# ─────────────────────────────────────────────────────────── INV-BASE-01 (runtime refusal)

@pytest.mark.invariant("INV-BASE-01")
@pytest.mark.parametrize("bad", ["/", "//"])
def test_root_stub_base_path_refused_at_runtime(nim_launcher, tmp_path, bad):
    """A baked base_path that resolves to a root is refused BEFORE anything is staged. Red-path:
    make refuseUnsafeRoot return "" -> the launcher tries to stage under the root and this
    ExitBadStub never fires."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(base_path=bad))
    r = run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "unsafe base path" in r.stderr, r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytest.mark.invariant("INV-BASE-01")
def test_root_env_base_path_refused_at_runtime(nim_launcher, tmp_path):
    """A hostile BASE_PATH env that names the filesystem root must not become an
    arbitrary-create/-delete root; it is refused defensively at runtime."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2())
    r = run(exe, tmp_path, env_extra={"HARU_BASE_PATH": "/"})
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "unsafe base path" in r.stderr, r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytest.mark.invariant("INV-BASE-01")
def test_home_env_base_path_refused_at_runtime(nim_launcher, tmp_path):
    """The home-directory root is refused too — reaping/staging a subtree directly under $HOME
    is refused, and run() sets HOME to tmp_path/home."""
    home = tmp_path / "home"
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2())
    r = run(exe, tmp_path, env_extra={"HARU_BASE_PATH": str(home)})
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "unsafe base path" in r.stderr, r.stderr


@pytest.mark.invariant("INV-BASE-01")
@pytest.mark.parametrize("suffix", ["/sub/..", "/.", "/./."])
def test_home_env_base_path_refused_even_via_dotdot(nim_launcher, tmp_path, suffix):
    """A runtime BASE_PATH that LEXICALLY resolves to the home root via `.`/`..` is refused too.
    refuseUnsafeRoot canonicalizes (normalizedPath) before comparing, mirroring the build's
    os.path.normpath. Without that step `$HOME/sub/..` slipped past the exact-string check and
    staged a `<key>-<digest>` subtree directly under $HOME (adversarial-review finding
    2026-09-10). Red-path: drop the `normalizedPath`/`pn` checks in refuseUnsafeRoot -> the
    launcher stages under $HOME (returncode 0) and this goes red."""
    home = tmp_path / "home"
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2())
    r = run(exe, tmp_path, env_extra={"HARU_BASE_PATH": str(home) + suffix})
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "unsafe base path" in r.stderr, r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


# ─────────────────────────────────────────────────────────── INV-BASE-01 (build-time refusal)
# Pure-Python, no launcher: a dangerous --base-path is rejected at build time, cross-OS (a
# --target windows build on Linux still rejects a drive root). These do NOT take nim_launcher,
# so they run even on a box with no nim.

@pytest.mark.invariant("INV-BASE-01")
@pytest.mark.parametrize("bad", ["/", "//", "\\", "\\\\", "C:\\", "C:/", "C:", "   "])
def test_build_refuses_root_base_path(bad):
    """A staging root that is empty-after-strip or a filesystem/drive/UNC root is refused at
    build time. Red-path: drop the _is_root_like raise (and the blank check) in
    resolve_base_path -> the root is accepted and this goes green."""
    with pytest.raises(BuildError):
        resolve_base_path(bad)


@pytest.mark.invariant("INV-BASE-01")
def test_build_refuses_home_base_path():
    with pytest.raises(BuildError, match="root"):
        resolve_base_path(os.path.expanduser("~"))


@pytest.mark.invariant("INV-BASE-01")
def test_build_accepts_a_real_directory_and_empty(tmp_path):
    assert resolve_base_path("") == ""                       # omitted -> normal cache
    d = str(tmp_path / "stage")
    assert resolve_base_path(d) == d                         # a dedicated dir is fine


# ─────────────────────────────────────────────────────────────── INV-RAM-01

@pytest.mark.invariant("INV-RAM-01")
@pytest.mark.skipif(not (DEV_SHM.is_dir() and os.access(DEV_SHM, os.W_OK)),
                    reason="/dev/shm not available/writable")
def test_ram_only_stages_under_dev_shm(nim_launcher, tmp_path):
    """ram-only stages under /dev/shm/haru-pack on Linux. Red-path: make ramBackedRoot return
    baseDir() -> staging lands in the cache and this goes red."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(ram_only=True))
    stage = None
    try:
        r = run(exe, tmp_path)
        assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
        stage = stage_from(r.stdout)
        assert stage and stage.startswith("/dev/shm/haru-pack/"), stage
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)     # only OUR subtree, never all of shm


@pytest.mark.invariant("INV-RAM-01")
def test_base_path_beats_ram_only(nim_launcher, tmp_path):
    """Precedence: an explicit base_path wins over ram-only, so staging does NOT go to RAM."""
    b = tmp_path / "b"; b.mkdir()
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, base_path=str(b)))
    r = run(exe, tmp_path)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = stage_from(r.stdout)
    assert stage and stage.startswith(str(b) + os.sep), stage
    assert not stage.startswith("/dev/shm"), f"ram-only beat an explicit base_path: {stage}"

"""INV-EPHEMERAL-01/02/03 — ephemeral staging is safe on a low-RAM target and controllable at
runtime (docs/adr/0005-ephemeral-safe.md).

Two halves, same split as the other staging invariants:

  * Launcher (Nim): compile the real launcher, attach a real payload + a v2 stub-config, and
    RUN it — asserting WHERE staging landed (/dev/shm vs the persistent cache) under a baked
    ram_only, an `unpacked_bytes` sizing hint, and a `<canary>_EPHEMERAL` runtime override.
  * Build (Python): the --ephemeral -> --reap coupling, --no-reap, the receipt, and the
    additive `unpacked_bytes` / `ephemeral` canary emission — no launcher needed.

Red-paths (walk: neutralize -> observe red -> restore):
  * INV-EPHEMERAL-01  make stage.ramWouldFit `return true` -> an oversized payload stages under
                      /dev/shm and test_ephemeral_oversized_payload_falls_back_to_disk goes red.
  * INV-EPHEMERAL-02  drop the `ram_only and not no_reap -> reap` coupling in build.build ->
                      test_ephemeral_implies_reap goes red.
  * INV-EPHEMERAL-03  make main.ephemeralOverride `return ""` -> HARU_EPHEMERAL=1 no longer
                      forces RAM and test_env_1_forces_ram_on_nonephemeral_binary goes red;
                      drop `if k == kEphemeral: continue` in parseStubConfig -> a four-key v1
                      stub-config fails to parse and test_v1_four_key_stub_still_parses goes red.
"""
from __future__ import annotations

import hashlib
import lzma
import os
import re
import shutil

import pytest
from _stage_helpers import (
    DEV_SHM,
    LAUNCHER_SRC,
    build_payload_zip,
    compile_launcher,
    make_payload,
    pack,
    run,
    stage_from,
    stub_toml2,
)

from haru_pack.build import (
    BuildError,
    DEFAULT_CANARY,
    _staged_tree_bytes,
    resolve_canary,
    stub_config_bytes,
)

# A size no real machine will clear the ×1.2 fit check for, so the launcher must fall back.
HUGE = 10**15            # 1 PB
FITS = 4096              # trivially fits free RAM


def _shm_ok() -> bool:
    return DEV_SHM.is_dir() and os.access(DEV_SHM, os.W_OK)


requires_shm = pytest.mark.skipif(not _shm_ok(), reason="/dev/shm unavailable/unwritable")


def _run_ok(exe, tmp_path, **kw):
    r = run(exe, tmp_path, **kw)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)
    stage = stage_from(r.stdout)
    assert stage, r.stdout
    return stage


def _cleanup(stage: str) -> None:
    if stage and stage.startswith(str(DEV_SHM)):
        shutil.rmtree(stage, ignore_errors=True)


# ───────────────────────────────────────────────── INV-EPHEMERAL-01 (fail-safe RAM-fit)

@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_ephemeral_oversized_payload_falls_back_to_disk(nim_launcher, tmp_path):
    """ram_only baked, but the payload cannot fit RAM: the stub must stage to the persistent
    cache, never /dev/shm. Red-path: ramWouldFit `return true` -> this stages under /dev/shm."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=HUGE))
    stage = _run_ok(exe, tmp_path)
    assert not stage.startswith(str(DEV_SHM)), f"oversized payload staged into RAM: {stage}"


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_ephemeral_small_payload_stages_in_ram(nim_launcher, tmp_path):
    """ram_only baked and the payload provably fits: the stub stages under /dev/shm."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=FITS, reap=True))
    stage = _run_ok(exe, tmp_path)
    try:
        assert stage.startswith(str(DEV_SHM)), f"fitting payload did not stage into RAM: {stage}"
    finally:
        _cleanup(stage)


@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_unknown_size_fails_safe_to_disk(nim_launcher, tmp_path):
    """ram_only baked but no unpacked_bytes hint (0 = unknown): the stub cannot prove a fit, so
    it fails safe to disk rather than gambling RAM."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(ram_only=True))
    stage = _run_ok(exe, tmp_path)
    assert not stage.startswith(str(DEV_SHM)), f"unknown-size payload gambled RAM: {stage}"


# ─────────────────────────────────────────────── INV-EPHEMERAL-03 (runtime override)

@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_env_0_is_ignored_not_a_downgrade(nim_launcher, tmp_path):
    """There is NO force-disk value (user decision 2026-09-12): a fitting --ephemeral binary told
    EPHEMERAL=0 still auto-stages to RAM — an env var must never downgrade an encrypted ephemeral
    payload onto disk. Red-path: make forceRamRequested treat "0" as force-disk -> this goes red."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=FITS, reap=True))
    stage = _run_ok(exe, tmp_path, env_extra={"HARU_EPHEMERAL": "0"})
    try:
        assert stage.startswith(str(DEV_SHM)), f"EPHEMERAL=0 downgraded a fitting RAM stage: {stage}"
    finally:
        _cleanup(stage)


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_env_1_forces_ram_on_nonephemeral_binary(nim_launcher, tmp_path):
    """Target autonomy: EPHEMERAL=1 stages to RAM even on a binary NOT built --ephemeral.
    Red-path: ephemeralOverride `return ""` -> this stages to disk instead."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=stub_toml2(ram_only=False))
    stage = _run_ok(exe, tmp_path, env_extra={"HARU_EPHEMERAL": "1"})
    try:
        assert stage.startswith(str(DEV_SHM)), f"EPHEMERAL=1 did not force RAM: {stage}"
    finally:
        _cleanup(stage)


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_env_1_skips_fit_check(nim_launcher, tmp_path):
    """EPHEMERAL=1 is the target asserting it fits: it stages to RAM even when the baked
    unpacked_bytes would fail the auto fit check."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=HUGE))
    stage = _run_ok(exe, tmp_path, env_extra={"HARU_EPHEMERAL": "1"})
    try:
        assert stage.startswith(str(DEV_SHM)), f"EPHEMERAL=1 respected the fit check: {stage}"
    finally:
        _cleanup(stage)


@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_override_is_canary_guarded(nim_launcher, tmp_path):
    """The override is read from `<canary.ephemeral>_EPHEMERAL` only. With the canary set to
    MARK, HARU_EPHEMERAL=1 is the WRONG name and is ignored -> staging stays on disk."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=False, ephemeral_canary="MARK"))
    stage = _run_ok(exe, tmp_path, env_extra={"HARU_EPHEMERAL": "1"})
    assert not stage.startswith(str(DEV_SHM)), f"wrong-canary EPHEMERAL was honored: {stage}"


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_override_honors_the_resolved_canary(nim_launcher, tmp_path):
    """The flip side: MARK_EPHEMERAL=1 IS the resolved name and forces RAM."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=False, ephemeral_canary="MARK"))
    stage = _run_ok(exe, tmp_path, env_extra={"MARK_EPHEMERAL": "1"})
    try:
        assert stage.startswith(str(DEV_SHM)), f"resolved-canary EPHEMERAL ignored: {stage}"
    finally:
        _cleanup(stage)


@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_v1_four_key_stub_still_parses(nim_launcher, tmp_path):
    """The additive knob keeps back-compat: a four-key [canary] stub-config (no `ephemeral`
    key) still parses and runs. Red-path: drop `if k == kEphemeral: continue` in
    parseStubConfig -> the four-key form fails with ExitBadStub and this goes red."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    # stub_toml2() with the default HARU ephemeral canary emits exactly the four-key form.
    cfg = stub_toml2()
    assert b"ephemeral" not in cfg, "fixture emitted an ephemeral key; not the v1 form"
    pack(nim_launcher, build_payload_zip(src), exe, stub_config=cfg)
    _run_ok(exe, tmp_path)


# ─────────────────────────────────────────────── INV-EPHEMERAL-02 (imply --reap)

@pytest.mark.invariant("INV-EPHEMERAL-02")
def test_ephemeral_implies_reap(stub_toolchain, script_project, tmp_path):
    """--ephemeral bakes reap=true; the receipt reports the effective value. Red-path: remove
    the coupling in build.build -> staging.reap is False and this goes red."""
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", ram_only=True)
    assert info["staging"]["ram_only"] is True
    assert info["staging"]["reap"] is True


@pytest.mark.invariant("INV-EPHEMERAL-02")
def test_no_reap_opts_out(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", ram_only=True, no_reap=True)
    assert info["staging"]["ram_only"] is True
    assert info["staging"]["reap"] is False


@pytest.mark.invariant("INV-EPHEMERAL-02")
def test_reap_and_no_reap_conflict(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    with pytest.raises(BuildError, match="conflict"):
        stub_toolchain.build(script_project, out, tier="thin", reap=True, no_reap=True)


@pytest.mark.invariant("INV-EPHEMERAL-02")
def test_ephemeral_overwrite_needs_no_explicit_reap(stub_toolchain, script_project, tmp_path):
    """--ephemeral --overwrite works without a separate --reap because the coupling provides it
    (INV-SHRED-01's `overwrite requires reap` is satisfied by the implied reap)."""
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", ram_only=True, overwrite=True)
    assert info["staging"]["overwrite"] is True
    assert info["staging"]["reap"] is True


@pytest.mark.invariant("INV-EPHEMERAL-02")
def test_ephemeral_overwrite_with_no_reap_refused(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    with pytest.raises(BuildError):
        stub_toolchain.build(script_project, out, tier="thin",
                             ram_only=True, overwrite=True, no_reap=True)


@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_receipt_records_unpacked_bytes(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", ram_only=True)
    assert info["staging"]["unpacked_bytes"] > 0


# ─────────────────────────────────────────────── stub_config_bytes (additive emission)

@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_unpacked_bytes_emitted_only_with_ram_only():
    c = resolve_canary()
    assert b"unpacked_bytes" in stub_config_bytes(c, ram_only=True, unpacked_bytes=999)
    assert b"unpacked_bytes" not in stub_config_bytes(c, unpacked_bytes=999)   # no ram_only


@pytest.mark.invariant("INV-CANARY-02")
def test_ephemeral_canary_resolves_and_emits_only_when_non_default():
    # Fifth knob resolves through the same rule; default HARU is NOT emitted (v1 corpus intact).
    assert resolve_canary()["ephemeral"] == DEFAULT_CANARY
    assert b"ephemeral" not in stub_config_bytes(resolve_canary())
    # --env-canary and the per-knob override both reach it, and then it IS emitted.
    assert resolve_canary(env_canary="MARK")["ephemeral"] == "MARK"
    assert resolve_canary(per_knob={"ephemeral": "MARK"})["ephemeral"] == "MARK"
    assert b'ephemeral = "MARK"' in stub_config_bytes(resolve_canary(env_canary="MARK"))


# ─────────────────────────────── C1: unpacked_bytes counts EXPANDED, not compressed sizes

@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_staged_tree_bytes_counts_uv_expansion(tmp_path):
    """The RAM-fit size must reflect the EXPANDED staged tree (uv is XZ'd in the payload and
    expands on stage), not the compressed payload dir. Red-path (adversarial C1): sum
    p.stat().st_size for every file -> counts the ~tiny compressed uv and this goes red."""
    pd = tmp_path / "payload"
    (pd / "vendor").mkdir(parents=True)
    (pd / "vendor" / "uv.xz").write_bytes(b"\x00" * 100)          # compressed member: 100 B
    (pd / "vendor" / "uv.xz.size").write_text("56000000")         # expands to 56 MB
    (pd / "vendor" / "uv.xz.sha256").write_text("0" * 64)
    (pd / "app").mkdir()
    (pd / "app" / "hello.py").write_text("print('hi')\n")
    got = _staged_tree_bytes(pd)
    assert got >= 56_000_000, got                                 # accounts for expansion
    naive = sum(p.stat().st_size for p in pd.rglob("*") if p.is_file())
    assert got > naive, (got, naive)                             # not the compressed sum


def _make_xz_payload(root, *, uv_body: str):
    """A payload whose vendor/uv is a REAL xz member (compressed + .size + .sha256 sidecars),
    as bundle.compress_uv writes it, so the launcher expands and runs it on stage."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(exist_ok=True)
    (root / "app" / "hello.py").write_text("print('hi')\n")
    (root / "manifest.toml").write_text(
        'name = "t"\nkind = "script"\napp_subdir = "app"\n'
        'entrypoint = ["hello.py"]\ntier = "default"\n'
        "fetch_uv = false\noffline = false\n")
    raw = ("#!/bin/sh\n# pad " + "x" * 200_000 + "\n" + uv_body + "\n").encode()
    comp = lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32,
                         filters=[{"id": lzma.FILTER_LZMA2, "preset": 1}])
    v = root / "vendor"; v.mkdir(exist_ok=True)
    (v / "uv.xz").write_bytes(comp)
    (v / "uv.xz.size").write_text(str(len(raw)))
    (v / "uv.xz.sha256").write_text(hashlib.sha256(raw).hexdigest())
    return root


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_baked_size_covers_real_uv_expansion(nim_launcher, tmp_path):
    """REAL stage: with a real xz uv member, the baked size (+ the launcher's x1.2 headroom)
    covers the actual expanded staged tree, and staging fits RAM."""
    from pathlib import Path as _P
    src = _make_xz_payload(
        tmp_path / "p",
        uv_body='echo "PAYLOAD_UV_RAN"\necho "STAGE=$HARUPACK_STAGE"\nexit 0')
    baked = _staged_tree_bytes(src)
    exe = tmp_path / "app.exe"
    # NO reap here, on purpose: this test MEASURES the staged tree (the rglob+stat below), and a
    # detached reaper would delete it mid-walk -> FileNotFoundError, flaky (it blocked merges on
    # PR #66 and #73). The size-fit gate this asserts runs BEFORE any reap, so reaping is
    # orthogonal to what this proves; the --reap path is covered by the tests above + test_shred.
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=baked))
    stage = _run_ok(exe, tmp_path)
    try:
        assert stage.startswith(str(DEV_SHM)), f"fitting real payload did not stage in RAM: {stage}"
        actual = sum(p.stat().st_size for p in _P(stage).rglob("*") if p.is_file())
        assert baked + baked // 5 >= actual, (baked, actual)     # the gate the launcher enforces
        naive = sum(p.stat().st_size for p in src.rglob("*") if p.is_file())
        assert baked > naive, (baked, naive)                     # accounts for expansion
    finally:
        _cleanup(stage)


# ─────────────────────────────── W2: overflow fails safe, does not crash

@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_overflow_unpacked_bytes_fails_safe(nim_launcher, tmp_path):
    """An int64-range unpacked_bytes must fall back to disk (fail-safe), not crash the launcher.
    Red-path (adversarial W2): use the `need = x + x div 5; if need < x` guard -> under -d:release
    the add raises an uncatchable OverflowDefect and the launcher aborts (rc != 0)."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=9223372036854775807))
    stage = _run_ok(exe, tmp_path)          # asserts rc == 0 (no crash)
    assert not stage.startswith(str(DEV_SHM)), f"overflow-range size gambled RAM: {stage}"


# ────────────────── verify: unpackedBytes is int64 (BiggestInt), not native `int` (32-bit on armv7)

@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_over_int32_unpacked_bytes_round_trips_and_gates_to_disk(tmp_path):
    """`unpacked_bytes` above the int32 range (2^31-1) must round-trip through the stub-config and
    the RAM-fit gate without truncation or a crash. `StubConfig.unpackedBytes` is `int64`
    (`BiggestInt`), read with `getBiggestInt` — NOT the native Nim `int`, which is only 32 bits on
    the supported armv7 target, so a legitimate multi-GB payload read via a narrowing `getInt()`
    could wrap to a small/negative value there (silently, under -d:release) BEFORE this fit check
    or W2's overflow guard ever runs.

    A fake `/proc/meminfo` (compile-time `haruMemRoot`, never a runtime surface) pins
    `MemAvailable` far below the payload size, so the assertion is deterministic on ANY host —
    real /dev/shm capacity varies (this dev box alone has tens of GB free), so a host-dependent
    "does it fit" check here would be flaky; a truncated/garbage size could easily still answer
    "does not fit" for the WRONG reason and hide a regression.

    Red-path (adversarial verify): revert `unpackedBytes*: int64` to `int` and `n.getBiggestInt()`
    to `n.getInt()`. On this x86_64 host `int` is already 64 bits, so nothing here goes red — which
    is exactly why the type change closes the class regardless of what this host can observe (a
    cross-compiled linux-armv7 build was confirmed to still compile clean with the int64 field;
    execution on real/emulated 32-bit ARM was not available in this environment)."""
    if shutil.which("nim") is None:
        pytest.skip("nim not installed")
    over_int32 = 2**31 + 5_000_000_000     # ~7.1 GB: past int32 range
    memroot = tmp_path / "memroot"
    (memroot / "proc").mkdir(parents=True)
    (memroot / "proc" / "meminfo").write_text(
        "MemTotal:       1024 kB\nMemAvailable:   1024 kB\n")   # far below any real ×1.2 need
    launcher = compile_launcher(tmp_path / "launcher-int32", "haruMemRoot:" + str(memroot))
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=over_int32))
    stage = _run_ok(exe, tmp_path)          # asserts rc == 0 (no crash / no uncaught Defect)
    assert not stage.startswith(str(DEV_SHM)), f"over-int32 size mis-gated into RAM: {stage}"


# ─────────────────────────────── W3: cgroup memory limit is respected

@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_cgroup_limit_forces_disk(tmp_path):
    """A tight cgroup memory limit forces the disk fallback even when host RAM is plentiful — the
    container/CI case. A compile-time memroot feeds fake cgroup/meminfo files (never a runtime
    surface in shipped builds). Red-path: drop the `cg < need` gate -> staging goes to /dev/shm."""
    if shutil.which("nim") is None:
        pytest.skip("nim not installed")
    memroot = tmp_path / "memroot"
    (memroot / "proc").mkdir(parents=True)
    (memroot / "proc" / "meminfo").write_text(
        "MemTotal:       99999999 kB\nMemAvailable:   99999999 kB\n")
    cg = memroot / "sys" / "fs" / "cgroup"; cg.mkdir(parents=True)
    (cg / "memory.max").write_text("1024\n")        # 1 KB cap -> nothing real fits
    (cg / "memory.current").write_text("0\n")
    launcher = compile_launcher(tmp_path / "launcher-cg", "haruMemRoot:" + str(memroot))
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=4096))
    stage = _run_ok(exe, tmp_path)
    assert not stage.startswith(str(DEV_SHM)), f"cgroup cap ignored, staged in RAM: {stage}"


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_cgroup_v1_limit_forces_disk(tmp_path):
    """cgroup v1 (`memory.limit_in_bytes` / `memory.usage_in_bytes`) is gated the same as v2 — the
    v1 branch of `cgroupAvailBytes` had NO fake-sysfs test at all before this (adversarial
    re-review). Only the v1 files are present here (no `memory.max`), so this also exercises the
    v2-absent -> v1-checked fallthrough. Red-path: drop the v1 branch, or its `limit - usage` gate,
    and staging goes to /dev/shm despite the 1 KB cap."""
    if shutil.which("nim") is None:
        pytest.skip("nim not installed")
    memroot = tmp_path / "memroot"
    (memroot / "proc").mkdir(parents=True)
    (memroot / "proc" / "meminfo").write_text(
        "MemTotal:       99999999 kB\nMemAvailable:   99999999 kB\n")
    cg = memroot / "sys" / "fs" / "cgroup" / "memory"; cg.mkdir(parents=True)
    (cg / "memory.limit_in_bytes").write_text("1024\n")     # 1 KB cap -> nothing real fits
    (cg / "memory.usage_in_bytes").write_text("0\n")
    launcher = compile_launcher(tmp_path / "launcher-cg-v1", "haruMemRoot:" + str(memroot))
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=4096))
    stage = _run_ok(exe, tmp_path)
    assert not stage.startswith(str(DEV_SHM)), f"cgroup v1 cap ignored, staged in RAM: {stage}"


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-01")
@pytest.mark.parametrize("layout", ["v2", "v1"])
def test_cgroup_corrupt_limit_fails_closed(tmp_path, layout):
    """A present-but-UNPARSEABLE cgroup limit file must fail CLOSED (does not fit), not be treated
    as 'no limit'. Before this fix, `cgroupAvailBytes` returned -1 ("not gated") for a limit file
    that existed but did not parse — indistinguishable from a genuinely absent file — so a
    corrupted sysfs entry silently ALLOWED RAM staging even though host RAM (per the fake
    /proc/meminfo below) is plentiful and only the cgroup layer could have refused it.

    Red-path: revert the present-but-unparseable branch(es) of `cgroupAvailBytes` to `return -1`
    and this goes red (stages to RAM instead of disk)."""
    if shutil.which("nim") is None:
        pytest.skip("nim not installed")
    memroot = tmp_path / "memroot"
    (memroot / "proc").mkdir(parents=True)
    (memroot / "proc" / "meminfo").write_text(
        "MemTotal:       99999999 kB\nMemAvailable:   99999999 kB\n")
    if layout == "v2":
        cg = memroot / "sys" / "fs" / "cgroup"; cg.mkdir(parents=True)
        (cg / "memory.max").write_text("not-a-number\n")     # present but corrupt
        (cg / "memory.current").write_text("0\n")
    else:
        cg = memroot / "sys" / "fs" / "cgroup" / "memory"; cg.mkdir(parents=True)
        (cg / "memory.limit_in_bytes").write_text("not-a-number\n")   # present but corrupt
        (cg / "memory.usage_in_bytes").write_text("0\n")
    launcher = compile_launcher(tmp_path / f"launcher-cg-corrupt-{layout}",
                                "haruMemRoot:" + str(memroot))
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=4096))
    stage = _run_ok(exe, tmp_path)
    assert not stage.startswith(str(DEV_SHM)), (
        f"corrupt cgroup limit file ({layout}) was treated as no-limit, staged in RAM: {stage}")


# ─────────────────────────────── W1: --encrypt + --ephemeral honesty

@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_encrypt_ephemeral_warns_about_disk_fallback(stub_toolchain, script_project, tmp_path):
    """--encrypt + --ephemeral (no --overwrite) warns that the decrypted tree can reach disk via
    the low-RAM fallback or <canary>_EPHEMERAL=0. Red-path (adversarial W1): remove the warning."""
    out = tmp_path / "app"
    msgs: list[str] = []
    stub_toolchain.build(script_project, out, tier="thin", ram_only=True,
                         encrypt=True, secret=b"s3cretkey", log=msgs.append)
    joined = "\n".join(msgs)
    assert "--encrypt" in joined and "ephemeral" in joined.lower()
    assert "fall" in joined.lower() and "overwrite" in joined.lower()


@requires_shm
@pytest.mark.invariant("INV-EPHEMERAL-01")
def test_ephemeral_disk_fallback_is_reaped(nim_launcher, tmp_path):
    """The auto disk fallback (payload can't fit RAM) is still REAPED when --reap is set — the
    staged subtree is gone after the app exits.

    This asserts REAPED only, not shredded: a plain `rm -rf` satisfies "the directory disappears"
    just as well as the shred-on-reap path does, so this test alone cannot distinguish the two —
    both end with `wait_gone` returning true. That the --overwrite flag survives onto the DISK
    fallback specifically (rather than being silently dropped because staging landed on disk
    instead of RAM) is asserted separately, at the source level, by
    `test_disk_fallback_overwrite_flag_is_unconditional_on_staging_root` below; the byte-level
    proof that --overwrite actually shreds (not just unlinks) lives in tests/test_shred.py, which
    runs the real overwrite/shred code on real bytes on disk."""
    from pathlib import Path as _P
    from _stage_helpers import wait_gone
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=HUGE, reap=True, overwrite=True))
    stage = _run_ok(exe, tmp_path)
    assert not stage.startswith(str(DEV_SHM)), f"expected disk fallback, got RAM: {stage}"
    assert wait_gone(_P(stage)), f"disk fallback was not reaped: {stage}"


@pytest.mark.invariant("INV-SHRED-01")
def test_disk_fallback_overwrite_flag_is_unconditional_on_staging_root():
    """The auto-disk-fallback path must still THREAD `--overwrite` through to the reaper: main.nim
    bakes `reapWanted`/`reapTarget`/`reapOverwrite` from `sc.reap`/`stageRoot`/`sc.overwrite`
    unconditionally, right after `stageZip` runs — BEFORE anything downstream cares whether `root`
    (from `resolveStagingRoot`) resolved to /dev/shm or the persistent-cache disk fallback. There
    is no code path that could special-case "landed on disk because of the RAM-fit gate" and drop
    the shred.

    This is the strongest test available from Python: whether the reaper actually shreds (vs. a
    plain unlink) can only be observed by inspecting a file BEFORE it is deleted (see
    tests/test_shred.py's harness), and the disk-fallback run above deletes its own evidence. So
    this test instead proves, at the source level, that NOTHING conditions the overwrite bake on
    which root was chosen — the one thing that WOULD make test_ephemeral_disk_fallback_is_reaped's
    "shreds" claim false without this test noticing.

    Red-path: make `reapOverwrite`'s assignment conditional on the staging root (e.g. only bake it
    when `root == ramBackedRoot()`, silently dropping shred whenever the auto-fallback lands on
    disk — precisely the case --overwrite exists to protect) and this goes red, because the three
    assignments would no longer share `stageZip`'s own indentation (one of them would move inside
    an `if`)."""
    src = LAUNCHER_SRC.read_text()
    indent_m = re.search(r"^([ \t]*)stageRoot = stageZip\(", src, re.M)
    assert indent_m, "stageRoot = stageZip(...) not found — main.nim was restructured"
    indent = indent_m.group(1)
    for line in ("reapWanted = sc.reap", "reapTarget = stageRoot", "reapOverwrite = sc.overwrite"):
        m = re.search(rf"^([ \t]*){re.escape(line)}", src, re.M)
        assert m, f"{line!r} not found in main.nim — it was renamed or removed"
        assert m.group(1) == indent, (
            f"{line!r} is no longer set at stageZip's own indentation — it may now be "
            f"conditioned on which staging root resolveStagingRoot picked, which would let the "
            f"auto-disk-fallback silently drop --overwrite")
    # And the reap call itself must be gated only on reapWanted/reapTarget, never on root choice.
    # (reapShredArg is the canary-derived --<canary>-shred flag threaded through for #3.)
    reap_call = re.search(r"^[ \t]*if reapWanted and reapTarget\.len > 0:\s*\n[ \t]*reapDetached\("
                          r"reapTarget, reapOverwrite, reapShredArg\)", src, re.M)
    assert reap_call, "reapDetached(reapTarget, reapOverwrite, ...) is no longer gated only on reapWanted/reapTarget.len"

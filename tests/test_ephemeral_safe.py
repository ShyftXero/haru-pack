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

import os
import shutil

import pytest
from _stage_helpers import (
    DEV_SHM,
    build_payload_zip,
    make_payload,
    pack,
    run,
    stage_from,
    stub_toml2,
)

from haru_pack.build import BuildError, DEFAULT_CANARY, resolve_canary, stub_config_bytes

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

@pytest.mark.invariant("INV-EPHEMERAL-03")
def test_env_0_forces_disk(nim_launcher, tmp_path):
    """A binary built --ephemeral, told EPHEMERAL=0 at runtime, stages to disk."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    pack(nim_launcher, build_payload_zip(src), exe,
         stub_config=stub_toml2(ram_only=True, unpacked_bytes=FITS))
    stage = _run_ok(exe, tmp_path, env_extra={"HARU_EPHEMERAL": "0"})
    assert not stage.startswith(str(DEV_SHM)), f"EPHEMERAL=0 still staged into RAM: {stage}"


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

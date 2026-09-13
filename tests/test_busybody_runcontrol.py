"""BusyBody run-control hardening, adopted from lotek's BusyBody (#558 fail-loud selection,
#738 single-instance run control).

INV-CHAOS-12 — an unmatched --persona/--case name is a SETUP FAILURE (exit 2), never a silent
drop: `--persona forger,typo` must not quietly run only forger and print a clean verdict.

INV-CHAOS-13 — a sweep refuses to start (exit 3) while another is genuinely LIVE, and reaps a
DEAD run's stale registry rather than trusting it. Two sweeps each stage a real interpreter and
thrash the box into the OOM killer (observed 2026-09-12), so the guard exists to stop that.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BB = REPO / "tools" / "busybody.py"


def _load_busybody():
    spec = importlib.util.spec_from_file_location("busybody_rc", BB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BB), *args],
                          capture_output=True, text=True, cwd=REPO, timeout=60)


# ─────────────────────────── INV-CHAOS-12: fail-loud selection ───────────────────────────

@pytest.mark.invariant("INV-CHAOS-12")
def test_unknown_persona_is_a_setup_failure():
    """RED-PATH: drop the `unknown` check and filter directly — an unknown persona then yields an
    empty selection and 'nothing selected' (rc 1) or, mixed with a real one, runs a shorter matrix
    and exits 0. Either way the typo is silently swallowed."""
    r = _run("--persona", "nosuchpersona")
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "unknown persona" in r.stderr and "nosuchpersona" in r.stderr


@pytest.mark.invariant("INV-CHAOS-12")
def test_a_typo_mixed_with_a_real_name_still_fails_loud():
    """The dangerous case: one good name masks a typo. Must fail, naming the typo — not run the
    good one and read clean."""
    r = _run("--case", "truncated_binary,tyop")
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "unknown case" in r.stderr and "tyop" in r.stderr


@pytest.mark.invariant("INV-CHAOS-12")
def test_a_fully_valid_selection_is_accepted():
    """A guard that rejects the normal case is worse than no guard: a real persona + --list runs."""
    r = _run("--persona", "forger", "--list")
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert "forger" in r.stdout


# ─────────────────────────── INV-CHAOS-13: single-instance ───────────────────────────

@pytest.fixture
def bb_registry(tmp_path, monkeypatch):
    bb = _load_busybody()
    reg = tmp_path / "harupack-busybody"
    # Patched on busybody_config, which is where busybody_guard reads it from. The facade
    # forwards it for reading, but assigning there would only shadow the forward.
    import busybody_config as cfg
    monkeypatch.setattr(cfg, "BB_REGISTRY", reg)
    return bb, reg


def _dead_pid() -> int:
    """A pid guaranteed dead: spawn a process, kill it, reap it."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


@pytest.mark.invariant("INV-CHAOS-13")
def test_a_live_sweep_blocks_a_second_one(bb_registry):
    """RED-PATH: delete the `if _bb_live(entry): raise SystemExit(3)` branch and a second sweep
    starts alongside the first — the exact double-stage that OOM-killed the box."""
    bb, reg = bb_registry
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        reg.mkdir(parents=True)
        (reg / "live.json").write_text(json.dumps(
            {"pid": child.pid, "run_id": "live", "born": time.time()}))
        with pytest.raises(SystemExit) as e:
            bb.guard_single_instance("second", reg / "hb", log=lambda m: None)
        assert e.value.code == 3
    finally:
        child.terminate()
        child.wait()


@pytest.mark.invariant("INV-CHAOS-13")
def test_a_dead_runs_stale_registry_is_reaped_not_trusted(bb_registry):
    """A registry left by a dead run must be reaped, not treated as a live sweep — otherwise one
    crashed run wedges the harness forever. The name (a bare pid) is not proof; the live pid is."""
    bb, reg = bb_registry
    reg.mkdir(parents=True)
    (reg / "dead.json").write_text(json.dumps(
        {"pid": _dead_pid(), "run_id": "dead", "born": time.time()}))
    mine = bb.guard_single_instance("fresh", reg / "hb", log=lambda m: None)
    assert mine.exists(), "the new run must register"
    assert not (reg / "dead.json").exists(), "the dead run's marker must be reaped"


@pytest.mark.invariant("INV-CHAOS-13")
def test_a_stale_heartbeat_makes_even_a_live_pid_reapable(bb_registry):
    """Liveness needs a FRESH heartbeat, not just a live pid — a wedged run (pid alive, heartbeat
    ancient) must not block forever. Here a live child with a stale born-time is reaped."""
    bb, reg = bb_registry
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        reg.mkdir(parents=True)
        (reg / "wedged.json").write_text(json.dumps(
            {"pid": child.pid, "run_id": "wedged", "born": time.time() - bb.BB_STALE_S - 10}))
        mine = bb.guard_single_instance("fresh", reg / "hb", log=lambda m: None)
        assert mine.exists() and not (reg / "wedged.json").exists()
    finally:
        child.terminate()
        child.wait()


@pytest.mark.invariant("INV-CHAOS-13")
def test_force_env_overrides_the_refusal(bb_registry, monkeypatch):
    """A logged, deliberate override beats a guard someone deletes: HARUPACK_BUSYBODY_FORCE=1
    starts anyway even next to a live sweep."""
    bb, reg = bb_registry
    monkeypatch.setenv("HARUPACK_BUSYBODY_FORCE", "1")
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        reg.mkdir(parents=True)
        (reg / "live.json").write_text(json.dumps(
            {"pid": child.pid, "run_id": "live", "born": time.time()}))
        mine = bb.guard_single_instance("forced", reg / "hb", log=lambda m: None)
        assert mine.exists(), "FORCE must let the run start"
        assert (reg / "live.json").exists(), "FORCE must NOT reap the live run it ran beside"
    finally:
        child.terminate()
        child.wait()


@pytest.mark.invariant("INV-CHAOS-13")
def test_registry_is_a_fixed_path_not_tmpdir_derived(monkeypatch, tmp_path):
    """The registry must NOT follow $TMPDIR. A sweep isolates its scratch with its own
    --work-root/$TMPDIR; a gettempdir-derived registry would move with that scratch dir, so two
    sweeps with different scratch roots register in different places and never see each other —
    which defeats the guard (found live on the top-100 sweep, 2026-09-12).

    RED-PATH: set `BB_REGISTRY = Path(tempfile.gettempdir()) / "harupack-busybody"` and this goes
    red — under a $TMPDIR pointing at a real writable dir the registry follows it there."""
    import tempfile as _tf
    scratch = tmp_path / "scratch"          # a REAL writable dir, so gettempdir() would honor it
    scratch.mkdir()
    monkeypatch.delenv("HARUPACK_BUSYBODY_REGISTRY", raising=False)
    monkeypatch.setenv("TMPDIR", str(scratch))
    monkeypatch.setattr(_tf, "tempdir", None, raising=False)   # bust gettempdir()'s cache
    spec = importlib.util.spec_from_file_location("busybody_fixedreg", BB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.BB_REGISTRY == Path("/tmp/harupack-busybody"), (
        f"the registry followed $TMPDIR to {mod.BB_REGISTRY} — it must be a fixed shared path"
    )


@pytest.mark.invariant("INV-CHAOS-13")
def test_the_registry_is_released_on_exit(bb_registry):
    """The marker is removed when the run ends, so the next sweep sees a clean slate. (main()'s
    finally unlinks it; here we assert the round-trip: register then unlink.)"""
    bb, reg = bb_registry
    mine = bb.guard_single_instance("solo", reg / "hb", log=lambda m: None)
    assert mine.exists()
    mine.unlink(missing_ok=True)
    assert not mine.exists()

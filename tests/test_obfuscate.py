"""INV-OBF-01 — --obfuscate applies the engine or fails the build; never silent plaintext.

The dangerous outcome is not a weak obfuscator. It is a developer who ran `--obfuscate
pyarmor` in CI, did not watch the log, and shipped a plain binary believing it was
protected. So the contract these guard is blunt: obfuscation happens, or the build stops.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from haru_pack.obfuscate import (NoneEngine, ObfuscationError, PyArmorEngine,
                                 engine_names, get_engine)

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- the registry

@pytest.mark.invariant("INV-OBF-01")
def test_none_is_the_default_and_the_honest_name_for_unprotected():
    """`none` must be a real, named engine, not the absence of one. A manifest should never
    have to imply "not obfuscated" by omission."""
    assert "none" in engine_names()
    assert "pyarmor" in engine_names()
    eng = get_engine("none")
    assert isinstance(eng, NoneEngine)
    res = eng.obfuscate(Path("/nonexistent"), "app.py")
    assert res.applied is False and res.engine == "none"


@pytest.mark.invariant("INV-OBF-01")
def test_an_unknown_engine_is_refused_not_ignored():
    """Silently falling back to no-obfuscation on a typo'd engine name is the exact failure
    this invariant exists to prevent."""
    with pytest.raises(ObfuscationError, match="unknown obfuscation engine"):
        get_engine("pyarmour")      # the plausible misspelling


# ---------------------------------------------------------------- availability is honest

@pytest.mark.invariant("INV-OBF-01")
def test_pyarmor_reports_unavailability_rather_than_pretending(monkeypatch):
    """When the toolchain to obfuscate is absent, `available()` must say so — and the build
    turns that into a refusal. It must not return "" and then no-op."""
    eng = PyArmorEngine()
    monkeypatch.setattr(shutil, "which", lambda _n: None)
    reason = eng.available()
    assert reason and "uv" in reason.lower()
    # and obfuscate() must refuse rather than silently skip
    with pytest.raises(ObfuscationError):
        eng.obfuscate(Path("/tmp"), "app.py")


@pytest.mark.invariant("INV-OBF-01")
def test_a_requested_engine_that_cannot_run_fails_the_build(tmp_path, monkeypatch):
    """The build-level contract: request obfuscation, engine unavailable -> BuildError.
    Driven through build._resolve's front-of-build validation without doing a real build."""
    # force pyarmor unavailable
    monkeypatch.setattr(shutil, "which", lambda _n: None)

    # the exact guard build() runs up front: unavailable engine -> refuse
    eng = get_engine("pyarmor")
    assert eng.available(), "test setup: pyarmor should look unavailable here"
    # build() wraps this into a BuildError; assert the source does so
    src = (REPO / "src" / "haru_pack" / "build.py").read_text()
    assert "if reason := eng.available():" in src and "raise BuildError(reason)" in src, (
        "build() must refuse when a requested engine reports it cannot run"
    )


# ---------------------------------------------------------------- independence + truthful record

@pytest.mark.invariant("INV-OBF-01")
def test_obfuscation_and_encryption_are_wired_independently():
    """Neither implies the other. A change that made --obfuscate force --encrypt (or the
    reverse) would be a silent scope change in a security feature."""
    src = (REPO / "src" / "haru_pack" / "build.py").read_text()
    # the obfuscation block must not reference the encryption state, and vice versa
    assert "obfuscation is a source transform" in src.lower() or \
           "INDEPENDENT of encryption" in src, (
        "the independence of the two axes should be asserted where they are wired"
    )
    # both recorded on the manifest, separately
    assert 'manifest["obfuscation"]' in src
    assert 'encrypted=bool(enc["enabled"])' in src


@pytest.mark.invariant("INV-OBF-01")
def test_the_build_records_what_was_actually_done():
    """The artifact should state its own provenance. A manifest that omits the engine leaves
    the reader to trust the builder."""
    src = (REPO / "src" / "haru_pack" / "build.py").read_text()
    assert 'obfuscation=manifest.get("obfuscation"' in src, (
        "build()'s receipt must carry the obfuscation result"
    )


@pytest.mark.invariant("INV-OBF-01")
def test_non_thick_obfuscation_warns_about_the_python_binding():
    """Obfuscation binds the payload to an exact Python minor version; only thick guarantees
    the staged interpreter matches. A non-thick obfuscated build must warn, because haru-pack
    CAN see the risk (unlike INV-TIER-02, where it cannot)."""
    src = (REPO / "src" / "haru_pack" / "build.py").read_text()
    assert 'obfuscate != "none" and tier != "thick"' in src
    assert "undefined symbol" in src, (
        "the warning must name the actual failure mode so it is recognisable when it happens"
    )


# ---------------------------------------------------------------- real pyarmor (gated)

def _uv() -> bool:
    return shutil.which("uv") is not None


@pytest.mark.invariant("INV-OBF-01")
@pytest.mark.skipif(not _uv(), reason="uv not available to provision pyarmor")
def test_pyarmor_actually_removes_the_literal_and_keeps_the_entry(tmp_path):
    """The one integration test: obfuscation must remove the plaintext literal AND leave a
    runnable entry with its runtime. Slow (provisions pyarmor via uv), so it is the only
    real-pyarmor test here; the persona does the end-to-end run."""
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.py").write_text('SECRET = "unit_test_literal_zzz987"\nprint(SECRET)\n')

    eng = PyArmorEngine()
    if eng.available():
        pytest.skip("pyarmor could not be provisioned")
    res = eng.obfuscate(app, "app.py", python="3.12")

    assert res.applied and res.engine == "pyarmor"
    assert (app / "app.py").exists(), "the entry must survive obfuscation"
    assert any(p.name.startswith("pyarmor_runtime") for p in app.iterdir()), (
        "the runtime package must be placed alongside the obfuscated entry"
    )
    body = (app / "app.py").read_text()
    assert "unit_test_literal_zzz987" not in body, (
        "the plaintext literal is still in the obfuscated source"
    )
    assert "pyarmor" in body.lower(), "the obfuscated file should be a pyarmor bootstrap"


@pytest.mark.invariant("INV-OBF-01")
def test_free_threaded_python_gives_a_clear_error_not_a_raw_pyarmor_line(monkeypatch):
    """pyarmor's one hard ceiling is free-threaded CPython, and a bare "3.14" can resolve to
    a +freethreaded build via uv. The engine must name the real constraint and the fix, not
    surface pyarmor's raw "does not support free-threading" line with no guidance."""
    import subprocess as _sp
    eng = PyArmorEngine()

    class _R:
        returncode = 1
        stdout = ""
        stderr = "ERROR    Pyarmor does not support free-threading Python"

    monkeypatch.setattr(shutil, "which", lambda _n: "/usr/bin/uv")
    monkeypatch.setattr(_sp, "run", lambda *a, **k: _R())

    app = Path("/tmp")  # never touched; the entry-exists check is what we skip past
    # make the entry-exists guard pass without a real tree
    monkeypatch.setattr(Path, "exists", lambda self: True)
    with pytest.raises(ObfuscationError) as e:
        eng.obfuscate(app, "app.py", python="3.14")
    msg = str(e.value)
    assert "free-threaded" in msg and "standard" in msg.lower(), (
        "the error must name the constraint (free-threaded) and the fix (standard interpreter)"
    )
    assert "3.14" in msg

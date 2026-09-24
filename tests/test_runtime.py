"""The stdlib-only `haru_pack.runtime` helper a packed app imports to find its folders."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import haru_pack.runtime as rt


def test_stage_from_env_and_none_when_unpacked(monkeypatch, tmp_path):
    monkeypatch.setenv("HARUPACK_STAGE", str(tmp_path))
    assert rt.stage() == tmp_path
    monkeypatch.delenv("HARUPACK_STAGE", raising=False)
    assert rt.stage() is None          # dev run (not packed) -> no stage


def test_exe_dir_env_then_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("HARUPACK_EXE_DIR", str(tmp_path))
    assert rt.exe_dir() == tmp_path
    monkeypatch.delenv("HARUPACK_EXE_DIR", raising=False)
    assert isinstance(rt.exe_dir(), Path)   # a real dir, no crash


def test_data_dir_and_file_are_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(sys, "platform", "linux")
    d = rt.data_dir("yourapp")
    assert d == tmp_path / "yourapp" and d.is_dir()
    f = rt.data_file("yourapp", "files.db")
    assert f == tmp_path / "yourapp" / "files.db" and f.parent.is_dir()


def test_import_stays_thin_no_heavy_deps():
    """A packed app importing the helper must NOT drag in typer/rich (the CLI's heavy deps),
    or 'depend on haru-pack for two pathlib helpers' stops being cheap. Subprocess-isolated."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import haru_pack.runtime, sys; "
         "print(int('typer' in sys.modules or 'rich' in sys.modules))"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0", f"haru_pack.runtime pulled heavy deps: {r.stdout}{r.stderr}"

"""The stdlib-only `haru_pack.helpers` a packed app imports to find its folders."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import haru_pack.helpers as h


def test_extraction_dir_from_env_and_none_when_unpacked(monkeypatch, tmp_path):
    monkeypatch.setenv("HARUPACK_STAGE", str(tmp_path))
    assert h.haru_extraction_dir() == tmp_path
    monkeypatch.delenv("HARUPACK_STAGE", raising=False)
    assert h.haru_extraction_dir() is None          # dev run (not packed) -> no stage


def test_exe_dir_env_then_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("HARUPACK_EXE_DIR", str(tmp_path))
    assert h.haru_exe_dir() == tmp_path
    monkeypatch.delenv("HARUPACK_EXE_DIR", raising=False)
    assert isinstance(h.haru_exe_dir(), Path)   # a real dir, no crash


def test_cwd_and_home_are_paths():
    assert h.haru_cwd() == Path.cwd()
    assert h.haru_user_home() == Path.home()


def test_data_dir_and_file_are_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(sys, "platform", "linux")
    d = h.haru_data_dir("yourapp")
    assert d == tmp_path / "yourapp" and d.is_dir()
    f = h.haru_data_file("yourapp", "files.db")
    assert f == tmp_path / "yourapp" / "files.db" and f.parent.is_dir()


def test_config_dir_is_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(sys, "platform", "linux")
    c = h.haru_config_dir("yourapp")
    assert c == tmp_path / "yourapp" and c.is_dir()


def test_import_stays_thin_no_heavy_deps():
    """A packed app importing the helper must NOT drag in typer/rich (the CLI's heavy deps),
    or 'depend on haru-pack for two pathlib helpers' stops being cheap. Subprocess-isolated."""
    r = subprocess.run(
        [sys.executable, "-c",
         "import haru_pack.helpers, sys; "
         "print(int('typer' in sys.modules or 'rich' in sys.modules))"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "0", f"haru_pack.helpers pulled heavy deps: {r.stdout}{r.stderr}"

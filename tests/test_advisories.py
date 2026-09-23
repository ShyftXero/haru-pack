"""Build advisories — the writable-data lint that nudges authors off the SHARP_CORNERS section E
footgun (a bundled sqlite db the app writes to in place hard-fails the second run, INV-STAGE-01).
"""
from __future__ import annotations

from haru_pack.build import advisories


def _collect():
    msgs: list = []
    return msgs, (lambda m: msgs.append(m))


def test_flags_a_bundled_sqlite_db(tmp_path):
    proj = tmp_path / "app"
    (proj / "pkg").mkdir(parents=True)
    (proj / "pkg" / "__init__.py").write_text("")
    (proj / "data.db").write_bytes(b"SQLite format 3\x00")
    msgs, say = _collect()
    hits = advisories.warn_bundled_writable_data(proj, say)
    assert "data.db" in hits, hits
    assert any("SECOND run fails to launch" in m for m in msgs), msgs


def test_flags_sqlite_sidecars(tmp_path):
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "app.py").write_text("")
    (proj / "store.db-wal").write_text("x")
    hits = advisories.warn_bundled_writable_data(proj, lambda _m: None)
    assert "store.db-wal" in hits, hits


def test_ignores_venv_clean_trees_and_single_scripts(tmp_path):
    proj = tmp_path / "app"
    (proj / ".venv").mkdir(parents=True)
    (proj / ".venv" / "cache.db").write_text("x")   # inside .venv -> not bundled -> ignored
    (proj / "main.py").write_text("print(1)\n")
    msgs, say = _collect()
    assert advisories.warn_bundled_writable_data(proj, say) == []
    assert msgs == []
    # a single-script pack has nothing bundled adjacent to it
    script = tmp_path / "hello.py"
    script.write_text("print(1)\n")
    assert advisories.warn_bundled_writable_data(script, say) == []

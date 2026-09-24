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


def test_flags_a_db_by_magic_under_any_name(tmp_path):
    # No writable-looking suffix, no role word — caught by CONTENT (SQLite header), not by name.
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "app.py").write_text("")
    (proj / "store").write_bytes(b"SQLite format 3\x00rest of header")
    hits = advisories.warn_bundled_writable_data(proj, lambda _m: None)
    assert "store" in hits, hits


def test_flags_name_role_stores_generically(tmp_path):
    # The pattern, not a fixed extension list: logs, sqlite sidecars, and appended data by ROLE.
    proj = tmp_path / "app"
    (proj / "pkg").mkdir(parents=True)
    (proj / "pkg" / "__init__.py").write_text("")
    for n in ("error.log", "log.txt", "data.csv", "store.db-wal", "app-cache.bin", "sessions.dat"):
        (proj / n).write_text("x")
    hits = set(advisories.warn_bundled_writable_data(proj, lambda _m: None))
    for n in ("error.log", "log.txt", "data.csv", "store.db-wal", "app-cache.bin", "sessions.dat"):
        assert n in hits, (n, hits)


def test_does_not_flag_read_only_assets(tmp_path):
    # Role words appear INSIDE longer words with no token boundary (metadata, database) -> no hit;
    # ordinary read-only assets shipped as seed content are left alone.
    proj = tmp_path / "app"
    proj.mkdir()
    (proj / "app.py").write_text("print(1)\n")
    for n in ("metadata.json", "database.py", "template.html", "README.md", "logo.png"):
        (proj / n).write_text("x")
    msgs, say = _collect()
    assert advisories.warn_bundled_writable_data(proj, say) == []
    assert msgs == []


def test_ignores_venv_clean_trees_and_single_scripts(tmp_path):
    proj = tmp_path / "app"
    (proj / ".venv").mkdir(parents=True)
    (proj / ".venv" / "cache.db").write_bytes(b"SQLite format 3\x00")  # in .venv -> not bundled
    (proj / "main.py").write_text("print(1)\n")
    msgs, say = _collect()
    assert advisories.warn_bundled_writable_data(proj, say) == []
    assert msgs == []
    # a single-script pack has nothing bundled adjacent to it
    script = tmp_path / "hello.py"
    script.write_text("print(1)\n")
    assert advisories.warn_bundled_writable_data(script, say) == []

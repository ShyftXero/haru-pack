"""The version a haru-pack binary reports when its payload has no `.git`.

A packed binary carries the project source but not `.git`, so the git-derived version can't be
recomputed on the target. `scripts/self-build.sh` freezes it into `_frozen_version.py`, which
`_version.read_frozen()` reads. Without this a downloaded binary reports `haru-pack 0+unknown`
and the self-build smoke check (which requires the binary to report the release version) fails.
"""
from __future__ import annotations

from haru_pack._version import read_frozen


def test_absent_frozen_file_is_none(tmp_path):
    assert read_frozen(tmp_path) is None


def test_frozen_version_is_read_in_the_form_self_build_writes(tmp_path):
    # exactly what scripts/self-build.sh writes: `printf 'VERSION = "%s"\n' "$VERSION"`
    (tmp_path / "_frozen_version.py").write_text('VERSION = "20260916221652"\n', encoding="utf-8")
    assert read_frozen(tmp_path) == "20260916221652"


def test_frozen_version_is_bare_and_tolerates_quotes_and_whitespace(tmp_path):
    (tmp_path / "_frozen_version.py").write_text("VERSION =   '20260101000000'  \n", encoding="utf-8")
    assert read_frozen(tmp_path) == "20260101000000"

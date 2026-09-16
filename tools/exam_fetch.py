"""Getting a real package onto this machine and turning it into a runnable project.

Everything here is upstream of running anything: read the matrix, ask PyPI what the sdist
is, unpack it, find the suite, work out what the suite needs, and write a project that
haru-pack can be pointed at.

Split out of exam.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tarfile
import tomllib                       # stdlib since 3.11; the floor is >=3.12
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
from haru_pack import tomlio  # noqa: E402

PACKAGES = REPO / "flex" / "packages.toml"
LEDGER = REPO / "flex" / "exam-results.json"
PAGE = REPO / "top_n_pypi_stats.md"
MARKER = "EXAM_OK"


# ─────────────────────────────────────────────────────────── the top-N, from the matrix
def top_n() -> list[dict]:
    """The ranked top-N packages, from the same generated matrix flex already reads, so this
    page and the flex matrix cannot disagree about who the top-N are."""
    data = tomlio.load(PACKAGES)
    pk = [p for p in data.get("package", []) if p.get("list") == "top25"]
    pk.sort(key=lambda p: p.get("rank", 10**6))
    return pk


# ─────────────────────────────────────────────────────────── acquisition (network)
def pypi_meta(pkg: str) -> dict:
    """(sdist_url, version, repo_url, pypi_url) from PyPI's JSON API."""
    d = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30))
    ver = d["info"]["version"]
    sd = next((f["url"] for f in d["releases"].get(ver, [])
               if f["packagetype"] == "sdist"), "")
    urls = {k.lower(): v for k, v in (d["info"].get("project_urls") or {}).items()}
    repo = ""
    for key in ("source", "source code", "repository", "code", "github", "homepage"):
        if key in urls:
            repo = urls[key]
            break
    return {"sdist_url": sd, "version": ver, "repo_url": repo,
            "pypi_url": f"https://pypi.org/project/{pkg}/"}


def fetch_sdist(url: str, dest: Path) -> Path:
    raw = urllib.request.urlopen(url, timeout=120).read()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as t:
        # filter="data" is the safe extractor: it refuses absolute paths, `..` escapes,
        # device/pipe members and unsafe metadata. These sdists come from PyPI — semi-trusted
        # at best — so a hostile one must not be able to write outside `dest`. It also silences
        # the Python 3.14 DeprecationWarning, which is warning about exactly this default.
        t.extractall(dest, filter="data")
    return next(p for p in dest.iterdir() if p.is_dir())


def locate_suite(root: Path) -> tuple[str, list[Path]]:
    """The test tree at the sdist root. Layouts seen across the top-25: a tests/ or test/ or
    testing/ directory, or a bare test_*.py at the root (six). The whole directory is taken,
    not just *.py — packaging's tests carry binary fixtures the suite reads."""
    for name in ("tests", "test", "testing"):
        d = root / name
        if d.is_dir() and (any(d.rglob("test_*.py")) or any(d.rglob("*_test.py"))):
            return "dir", [d]
    roots = sorted(root.glob("test_*.py")) + sorted(root.glob("*_test.py"))
    conf = [root / "conftest.py"] if (root / "conftest.py").exists() else []
    if roots:
        return "files", roots + conf
    return "none", []


def test_deps(root: Path) -> list[str]:
    """The package's OWN declared test dependencies. Guessing pytest+hypothesis is not enough
    (packaging's suite imports `pretend` and `tomli_w`), and neither is a fixed list of group
    NAMES — idna puts its test deps under an extra called `all`, others use `test`/`dev`/`ci`.
    So the group is found by content: any optional-dependency group or dependency-group that
    itself lists pytest is a test group, and we take it whole. Extra tools it drags in (ruff,
    mypy, coverage) are harmless; a missing test import is a collection error."""
    pp = root / "pyproject.toml"
    found: list[str] = []
    if pp.exists():
        data = tomllib.loads(pp.read_text(encoding="utf-8"))
        groups = {**data.get("project", {}).get("optional-dependencies", {}),
                  **data.get("dependency-groups", {})}
        for items in groups.values():
            strs = [i for i in items if isinstance(i, str)]   # skip {include-group: ...}
            if any("pytest" in s.lower() for s in strs):
                found += strs
    if not any("pytest" in d.lower() for d in found):
        found.append("pytest")
    return sorted(set(found))


# ─────────────────────────────────────────────────────────── build the exam project
def make_project(pkg: str, imp: str, ver: str, kind: str, suite: list[Path], deps: list[str],
                 proj: Path, sdist_root: Path) -> None:
    app = proj / "exam"
    app.mkdir(parents=True)
    (app / "__init__.py").write_text("")
    # Ship the WHOLE unpacked sdist, not just the tests/ subtree, and run pytest from the sdist
    # ROOT. A project's suite is written to run from a checkout: it imports in-tree test helpers
    # that live BESIDE tests/ (urllib3's `dummyserver`, jmespath's `tests` package), reads data
    # files by a root-relative path, and points `directory="tests/statics"`-style config at the
    # root (starlette). Shipping only tests/ and running from a scratch cwd breaks all of those —
    # the ModuleNotFoundError / FileNotFoundError classes that dominate the failures. So: copy the
    # root, chdir into it, and APPEND it to sys.path (append, not insert(0), so the INSTALLED
    # package under test still wins `import pkg` — only the un-installed in-tree helpers fall
    # through to the source tree).
    shutil.copytree(sdist_root, app / "_src")
    if kind == "dir":
        targets = [str(suite[0].relative_to(sdist_root))]
    else:
        targets = [str(f.relative_to(sdist_root)) for f in suite if f.name != "conftest.py"]
    targets_lit = ", ".join(repr(t) for t in targets)
    (app / "__main__.py").write_text(
        "import os, pathlib, sys\n"
        "import pytest\n"
        # A best-effort "does the packed library import" note. NOT fatal: the guessed import name
        # is wrong for namespace packages (opentelemetry-api -> opentelemetry, google-api-core ->
        # google.api_core, proto-plus -> proto), and failing the whole exam on the guess would
        # false-fail a package whose OWN suite imports it correctly. The suite is the real proof.
        "try:\n"
        f"    import {imp}  # noqa: F401\n"
        "except Exception as _e:\n"
        f"    print('exam: note: could not import {imp!r} by guessed name (' + repr(_e) + "
        "'); running the suite anyway')\n"
        "src = pathlib.Path(__file__).parent / '_src'\n"
        "sys.path.append(str(src))   # in-tree test helpers, without shadowing the installed pkg\n"
        "os.chdir(src)              # root-relative data files / directory= config resolve\n"
        # -o addopts= clears the project's own addopts (--cov, -p plugins it does not ship),
        # which would newly fail suites that pass today; markers/testpaths from config still apply.
        "rc = pytest.main(['-q', '--no-header', '-p', 'no:cacheprovider', '-o', 'addopts=', "
        f"{targets_lit}])\n"
        f"if rc == 0:\n    print({MARKER!r}, {pkg!r}, 'passed its own suite inside the binary')\n"
        "sys.exit(rc)\n")
    # json.dumps, not f'"{d}"': a PEP 508 marker carries double quotes
    # (`exceptiongroup; python_version < "3.11"`), and naive wrapping closes the TOML string
    # early — an "Unclosed array" that failed the build for pydantic / pydantic-core. JSON
    # string escaping (`\"`) is exactly TOML basic-string escaping.
    dep_line = ", ".join(json.dumps(d) for d in [f"{pkg}=={ver}", *deps])
    (proj / "pyproject.toml").write_text(
        '[project]\nname = "exam"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        f"dependencies = [{dep_line}]\n")
    (proj / "haru_pack.toml").write_text('entrypoint = ["python", "-m", "exam"]\n')


def offline_env(cold: Path) -> dict:
    import os
    env = dict(os.environ)
    env["XDG_CACHE_HOME"] = str(cold)
    env["UV_OFFLINE"] = "1"
    env["UV_PYTHON_DOWNLOADS"] = "never"
    for v in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy"):
        env[v] = "http://127.0.0.1:9"          # discard port; nothing listens
    env.pop("NO_PROXY", None)
    tmp = cold / "tmp"                          # pytest's tmp_path wants an owned base dir
    tmp.mkdir(parents=True, exist_ok=True)
    env["TMPDIR"] = str(tmp)
    return env


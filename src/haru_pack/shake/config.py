"""What `--shake` was told to do: the error type, the config object, and how it resolves.

`ShakeError` lives here rather than in its own module because everything that raises it
already needs `ShakeConfig`, so there is no cycle to break.

Split out of shake.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


class ShakeError(RuntimeError):
    """A shake could not be performed, or could not be proven safe. Always fatal."""


# ---------------------------------------------------------------------------- cache buckets
#
# uv's cache is several independently-versioned buckets. Which ones a runtime `uv sync
# --frozen --offline` actually needs was determined empirically on 2026-09-10 (uv 0.10.4)
# by deleting each bucket from a warmed cache and re-syncing into a fresh env:
#
#   archive-v0     REQUIRED  unpacked wheel trees; this is what gets linked into the venv
#   wheels-v6      REQUIRED  without it: "Failed to download werkzeug==3.1.8 ... wasn't
#                            found in the cache"
#   sdists-v9      kept      empty for wheel-only projects, load-bearing for sdist deps
#   simple-v20     DROPPED   PyPI index responses. 4.4 MB on a five-dependency project.
#                            Only a *resolve* reads them and thick resolves at build time.
#   builds-v0      DROPPED   build backend scratch
#   interpreter-v4 DROPPED   cached interpreter probes — and they embed the BUILD HOST's
#                            absolute paths (`/home/<operator>`) in a payload that gets
#                            shipped and signed. Dropping it is a size win and a hygiene
#                            one; cf. INV-PAYLOAD-01.
#
# Matched by prefix because the version suffix moves with uv. An UNRECOGNISED bucket is
# KEPT: a future uv that stores something load-bearing under a new name must not be
# silently pruned by a rule written before it existed.
_CACHE_KEEP_PREFIXES = ("archive-", "wheels-", "sdists-")
_CACHE_DROP_PREFIXES = ("simple-", "builds-", "interpreter-")


# ------------------------------------------------------------------- interpreter rulepack
#
# The bundled standalone Python is pruned by RULE, not by observation, and that asymmetry
# is deliberate. The stdlib is where lazy and conditional imports are densest (`encodings`
# resolved by name at runtime, `ctypes` reaching for `lib-dynload`, codecs chosen by
# locale), so "delete every stdlib file the test run did not open" buys tens of megabytes
# and risks a failure the suite cannot see. These entries are things that cannot be
# imported at all, or that exist to *build* against the interpreter rather than run on it.
_PY_DROP_ALWAYS = (
    "lib/python*/test/*",              # CPython's own regression suite
    "lib/python*/*/test/*",
    "lib/python*/idlelib/*",           # the bundled IDE
    "lib/python*/turtledemo/*",
    "lib/python*/pydoc_data/*",         # topic text for interactive help()
    "lib/python*/ensurepip/_bundled/*",  # a whole bundled pip wheel (~2.1 MB)
    "lib/python*/config-*/*",          # Makefile + libpython*.a: for compiling extensions
    "include/*",                        # C headers, same reason
    "share/man/*", "share/doc/*", "share/terminfo/*",
    "lib/*.a", "lib/*.o",
)
# Dropped only when the observation run never touched the feature. Tk is a 10-20 MB family
# spread across the stdlib, lib-dynload and `lib/`, and a GUI app must keep all of it.
_PY_DROP_UNLESS_OBSERVED = {
    "tkinter": ("lib/python*/tkinter/*", "lib/python*/lib-dynload/_tkinter*",
                "lib/libtcl*", "lib/libtk*", "lib/tcl8*", "lib/tk8*", "lib/itcl*",
                "lib/tdbc*", "lib/thread2*", "lib/libBLT*"),
    "lib2to3": ("lib/python*/lib2to3/*",),
    "sqlite3": (),        # intentionally empty: named here so nobody "optimises" it in
}                          # later. sqlite3 is small and reached by lazy import constantly.

# Never pruned from a dependency tree, whatever the tracer saw. These are not features, they
# are the machinery that makes a package findable: `importlib.metadata`, entry points and
# `uv`'s own install bookkeeping all read `*.dist-info`, and a `.pth` runs at interpreter
# start. `*.data/` holds the wheel's non-purelib payload (scripts, headers, shared data);
# it is small and getting it wrong is silent, so it stays whole.
_DIST_ALWAYS_KEEP_DIRS = (".dist-info", ".data", ".egg-info")
_DIST_ALWAYS_KEEP_GLOBS = ("*.pth", "*/py.typed", "py.typed")


@dataclass
class ShakeConfig:
    """Resolved `[shake]` block. `test` is mandatory — see INV-SHAKE-03."""
    test: list = field(default_factory=list)
    also_run: list = field(default_factory=list)
    keep: list = field(default_factory=list)
    follow_lazy_imports: bool = True
    shake_interpreter: bool = True


def resolve_config(app_dir: Path, decl: dict, cli_keep=()) -> ShakeConfig:
    """Work out how to *observe* this project, or refuse.

    A shake with no observation is a shake with no evidence, and a deletion with no
    evidence is exactly the class of bug this repo refuses to ship (INV-SHAKE-03). So the
    absence of a test command is a hard error with instructions, not a fallback to some
    default "probably fine" rulepack.
    """
    sh = dict(decl.get("shake") or {})
    test = list(sh.get("test") or [])
    if not test and _has_pytest_config(app_dir):
        test = ["pytest"]
    if not test:
        raise ShakeError(
            "--shake needs a test command to observe, and this project does not declare "
            "one.\nAdd it to haru_pack.toml:\n\n"
            "    [shake]\n    test = [\"pytest\", \"-q\"]\n\n"
            "haru-pack will not delete files from a payload on the strength of a guess "
            "about what the program needs. If the project has no suite, build without "
            "--shake.")
    also = [list(c) if isinstance(c, (list, tuple)) else [c] for c in (sh.get("also_run") or [])]
    return ShakeConfig(test=test, also_run=also,
                       keep=[*(sh.get("keep") or []), *cli_keep],
                       follow_lazy_imports=bool(sh.get("follow_lazy_imports", True)),
                       shake_interpreter=bool(sh.get("shake_interpreter", True)))


def _has_pytest_config(app_dir: Path) -> bool:
    """Does the project configure pytest, or at least have somewhere for it to look?

    A bare `tests/` directory counts. `[tool.pytest.ini_options]` in pyproject.toml counts.
    A `pytest.ini`/`tox.ini`/`setup.cfg` is not parsed for a pytest section — presence of
    the file plus a test directory is enough of a signal, and a wrong guess here only ever
    produces "no tests ran", which the verify phase reports as a failure.
    """
    if (app_dir / "tests").is_dir() or (app_dir / "test").is_dir():
        return True
    if (app_dir / "pytest.ini").exists():
        return True
    pp = app_dir / "pyproject.toml"
    if pp.exists():
        try:
            return "[tool.pytest.ini_options]" in pp.read_text(encoding="utf-8")
        except OSError:
            return False
    return False

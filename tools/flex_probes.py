"""What the flex harness puts inside the binary, and what it asks that binary to prove.

Three rungs, cheapest first. Only the first two live here; the third is `tools/exam.py`.

    importable   the payload carries a library that IMPORTS          flex, default
    smoke        the library does one small real thing               flex --style smoke
    suite        the library passes its OWN test suite               tools/exam.py

WHY `importable` IS THE DEFAULT

The smoke bodies are hand-written, one per package, in `flex/curation.toml`. That makes each
one a second thing that can break for reasons that have nothing to do with packaging — an API
moved, a keyword was removed, the package wants a display. When that happens the run says
"flex failed", and someone has to read a traceback to find out whether haru-pack did anything
wrong at all. `importable` has exactly one failure mode, and it is the one the harness exists
to detect.

That is a narrowing, and it is a real cost: a default run no longer exercises the library.
`--style smoke` is still there, and `tools/exam.py` still runs the package's own suite.

THE IMPORT NAME IS DISCOVERED, NEVER GUESSED

`pip install pillow` gives you `import PIL`. There is no rule that recovers that from the
name, which is why `flex/curation.toml` carried eight hand-curated `import_name` entries —
eight human guesses, each able to go stale without anyone noticing.

`_provided_modules` asks the installed distribution instead. It runs INSIDE the packaged
binary, where the distribution actually exists, so nothing has to be curated up front. Its
source is embedded into the generated app by `inspect.getsource`, which means the function
these tests exercise and the function that ships are the same text rather than two copies
that drift.
"""
from __future__ import annotations

import inspect
import json

MARKER = "FLEX_OK"

#: Prefix of the machine-readable line the probe prints. The marker alone is a yes/no; the
#: harness also needs the module names it resolved, so it can check them against the curated
#: expectations in `flex/curation.toml` (INV-FLEX-03).
JSON_MARKER = "FLEX_JSON"

STYLES = ("importable", "smoke")


# ────────────────────────────────────────────── embedded in the binary AND tested directly

def _provided_modules(dist, mapping=None, top_level=None):
    """(top-level modules `dist` installed, how we found out).

    Three routes, best first, and the route is RETURNED rather than hidden — a guess that
    reads like a fact is how `flex/curation.toml` grew eight of them.

      packages_distributions   exact: the installed metadata, inverted. 3.10+.
      top_level.txt            the wheel said so. Works back to 3.8, absent from some wheels.
      guess                    `name.replace("-", "_")`. Wrong for pillow, and it says so.

    Normalisation is PEP 503: `typing-extensions`, `typing_extensions` and `Typing.Extensions`
    are one distribution, and comparing them raw silently resolves nothing.

    `mapping` and `top_level` are injectable so this is testable without installing anything.
    Everything it needs is imported inside the function body, because this source is embedded
    into a generated module that has no other imports.
    """
    import re

    def norm(s):
        return re.sub(r"[-_.]+", "-", str(s).strip()).lower()

    want = norm(dist)

    if mapping is None:
        try:
            from importlib.metadata import packages_distributions
            mapping = packages_distributions()
        except Exception:
            mapping = None
    if mapping:
        mods = sorted({m for m, dists in mapping.items()
                       if any(norm(d) == want for d in (dists or ()))})
        if mods:
            return mods, "packages_distributions"

    if top_level is None:
        try:
            from importlib.metadata import distribution
            top_level = distribution(dist).read_text("top_level.txt")
        except Exception:
            top_level = None
    if top_level:
        mods = sorted({ln.strip() for ln in top_level.splitlines() if ln.strip()})
        if mods:
            return mods, "top_level.txt"

    return [str(dist).replace("-", "_")], "guess"


# ───────────────────────────────────────────────────────────────────── the generated bodies

_IMPORTABLE_MAIN = '''
DIST = {dist!r}


def main():
    mods, how = _provided_modules(DIST)
    print("resolved {{}} -> {{}} (via {{}})".format(DIST, ", ".join(mods), how))

    failed = []
    for name in mods:
        try:
            importlib.import_module(name)
            print("successfully imported {{}}".format(name))
        except KeyboardInterrupt:
            raise
        except BaseException:
            # The FULL traceback, not a one-line summary: this output is the only artefact
            # left to dig into after the container is gone. SystemExit is caught on purpose —
            # a package that exits during import has failed, and must not read as a pass.
            traceback.print_exc()
            failed.append(name)
        finally:
            # Cleanup. Flushing matters: stdout is block-buffered when piped, so without it
            # the tracebacks and the success lines come back interleaved in the wrong order
            # and the log is much harder to read than it needs to be.
            sys.stdout.flush()
            sys.stderr.flush()

    print("{json_marker} " + json.dumps(
        {{"dist": DIST, "modules": mods, "how": how, "failed": failed}}, sort_keys=True))
    if failed:
        return 1
    print("{marker}")
    return 0


raise SystemExit(main())
'''

_PRELUDE = "import importlib\nimport json\nimport sys\nimport traceback\n\n"


def importable_body(pkg: dict) -> str:
    """`flexapp/__main__.py` for the importable style.

    Note what is NOT here: any use of `pkg["import_name"]`. The binary resolves its own
    modules, so a curated value cannot steer the probe — it can only be checked against the
    result afterwards, which is the whole point of INV-FLEX-03.
    """
    return (_PRELUDE
            + inspect.getsource(_provided_modules)
            + _IMPORTABLE_MAIN.format(dist=pkg["name"], marker=MARKER,
                                      json_marker=JSON_MARKER))


def smoke_body(pkg: dict) -> str:
    """`flexapp/__main__.py` for the smoke style: exercise the package, then print the marker.

    Unchanged behaviour, moved here from `tools/flex-run.py`. This one DOES honour
    `import_name`, because a hand-written smoke body is a hand-written thing throughout and
    the curated name is part of it.
    """
    name = pkg["name"]
    imp = pkg.get("import_name", name.replace("-", "_"))
    body = (pkg.get("smoke") or "").strip("\n")
    if not body:
        body = (f"import {imp} as _m\n"
                f"print('version:', getattr(_m, '__version__', 'unknown'))\n"
                f"print('{MARKER}')")
    extra = ""
    mod = pkg.get("module")
    if mod:
        # The package ships its own `python -m` entrypoint; run it too, in-process, so its
        # stdout is part of the evidence that the module is importable AND executable.
        extra = ("\nimport runpy\n"
                 f"print('--- python -m {mod} ---')\n"
                 "try:\n"
                 f"    runpy.run_module({mod!r}, run_name='__main__')\n"
                 "except SystemExit:\n"
                 "    pass\n")
    return body + extra + "\n"


def body_for(pkg: dict, style: str) -> str:
    if style == "importable":
        return importable_body(pkg)
    if style == "smoke":
        return smoke_body(pkg)
    raise ValueError(f"unknown probe style {style!r}; expected one of {STYLES}")


# ───────────────────────────────────────────────────────────── reading the probe's report back

def parse_report(stdout: str) -> dict | None:
    """The `FLEX_JSON` payload, or None if the probe never got far enough to print one."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(JSON_MARKER + " "):
            try:
                return json.loads(line[len(JSON_MARKER) + 1:])
            except ValueError:
                return None
    return None


def curation_conflict(pkg: dict, report: dict | None) -> str:
    """"" if the curated `import_name` agrees with what the binary found, else why not.

    INV-FLEX-03. The curated value is an ASSERTION about reality, so a mismatch is a failure
    of the manifest rather than of the package — and the message has to say that, or someone
    will go looking for a bug in a package that is fine.
    """
    curated = pkg.get("import_name")
    if not curated or not report:
        return ""
    found = report.get("modules") or []
    if curated in found:
        return ""
    return (f"flex/curation.toml claims {pkg['name']} imports as {curated!r}, but the "
            f"installed distribution provides {found or '(nothing)'} "
            f"(resolved via {report.get('how')}). The manifest is stale — fix or delete the "
            f"import_name entry; the package is not necessarily at fault.")

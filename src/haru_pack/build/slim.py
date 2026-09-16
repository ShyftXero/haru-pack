"""`--slim-python` — drop the known-unused interpreter furniture, opt-in.

A `--thick` binary bundles python-build-standalone (PBS) unmodified, and shipping it
unmodified is what makes `INV-SUPPLY-01` meaningful: the staged interpreter is byte-for-byte
the pinned artifact the publisher released, verified against a digest, and a third party can
repeat that check. Pruning it breaks that property, so this prune runs ONLY after the
interpreter has been fetched and digest-verified — `thick.stage` calls it immediately after
`bundle_python` returns — and it records every path it removed on the build receipt, so the
provenance chain reads "verified PBS artifact, then these N files removed by haru-pack",
not "some tree we assembled" (`INV-SHAKE-05`).

Unlike `--shake`, this needs no test suite. `--shake` deletes on *evidence* — it observes a
real run and re-proves the result — and refuses without a declared test command. This drops
a FIXED, known-unused set instead: things a packed app cannot reach because uv does the
installing (pip, ensurepip), because they only exist to compile against the interpreter (the
C headers), or because they are the interactive-help/IDE furniture (idlelib, pydoc_data). It
is opt-in precisely because static safety cannot be proven for every project — a program that
imports `tkinter`, or shells out to pip/ensurepip at runtime, must NOT use `--slim-python`.
See docs/SLIM.md and the `--slim-python` help.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

# The known-unused set. Every entry is a STRUCTURAL directory name, never a heuristic, and
# it is matched PREFIX-FREE against every path suffix (see `_suffixes`) so an upstream layout
# that adds a `python/` or `install/` level cannot silently disable a rule — the exact trap
# that once made `--shake`'s interpreter prune match nothing and save zero.
SLIM_DROP = (
    # tkinter: the Python bindings, the C extension, and the whole Tcl/Tk data + lib stack.
    "lib/python*/tkinter/*",
    "lib/python*/lib-dynload/_tkinter*",
    "lib/libtcl*", "lib/libtk*", "lib/tcl8*", "lib/tk8*", "lib/itcl*",
    "lib/tdbc*", "lib/thread2*", "lib/libBLT*",
    # pip, installed into the interpreter's own site-packages. uv does the installing; the
    # shipped app never imports pip. (Only pip — a runtime dist lives under vendor/cache.)
    "lib/python*/site-packages/pip/*",
    "lib/python*/site-packages/pip-*/*",
    # ensurepip, including its bundled pip/setuptools wheels.
    "lib/python*/ensurepip/*",
    # the bundled IDE, and the topic text for interactive help().
    "lib/python*/idlelib/*",
    "lib/python*/pydoc_data/*",
    # C headers: only needed to compile extensions against the interpreter, not to run it.
    "include/*",
    # man pages. terminfo under share/ is deliberately NOT here — a console app needs it.
    "share/man/*",
)


def _suffixes(rel: str) -> list:
    """Every path-component suffix of `rel`, so a rule can be written prefix-free.

    PBS extracts to a `python/` directory and some layouts add an `install/` level under it,
    so the interpreter really lands at `vendor/python/python/lib/python3.12/...`. Matching a
    rule against every suffix means a new upstream prefix cannot quietly turn it off — the
    lesson `--shake`'s rulepack learned the hard way.
    """
    parts = rel.split("/")
    return ["/".join(parts[i:]) for i in range(len(parts))]


def slim_python(pydir: Path, payload: Path, log=None) -> dict:
    """Remove the known-unused furniture from an ALREADY-verified interpreter tree.

    Precondition: the caller has fetched and digest-verified this interpreter first
    (`INV-SUPPLY-01`); `thick.stage` runs this immediately after `bundle_python`. Returns a
    report naming every removed path and its size, for the build receipt.
    """
    say = log or (lambda _m: None)
    removed: list[tuple[str, int]] = []
    freed = 0
    for f in sorted(p for p in pydir.rglob("*") if p.is_file() or p.is_symlink()):
        rel = f.relative_to(pydir).as_posix()
        cands = _suffixes(rel)
        if any(fnmatch.fnmatch(c, g) for c in cands for g in SLIM_DROP):
            n = f.stat().st_size if not f.is_symlink() else 0
            removed.append((f.relative_to(payload).as_posix(), n))
            f.unlink()
            freed += n
    # Sweep the directories the removals emptied, deepest first. Cosmetic — an empty tree
    # weighs nothing in the payload zip — but it keeps the staged tree honest to the receipt.
    for d in sorted((p for p in pydir.rglob("*") if p.is_dir() and not p.is_symlink()),
                    key=lambda p: len(p.parts), reverse=True):
        try:
            d.rmdir()
        except OSError:
            pass
    say(f"slim-python: removed {len(removed)} interpreter file(s), {freed / 1e6:.1f} MB "
        f"uncompressed (pip, ensurepip, tkinter/tcl-tk, idlelib, pydoc_data, C headers, "
        f"man pages) AFTER digest verification")
    return {
        "removed_files": len(removed),
        "freed_bytes": freed,
        "removed_paths": [p for p, _ in removed],
        "removed": [{"path": p, "bytes": n} for p, n in removed],
    }


def maybe_slim(pydir: Path, payload: Path, *, slim: bool, log=None) -> dict:
    """The gate. Default builds (`slim=False`) prune NOTHING and return an empty report, so
    the interpreter ships byte-for-byte the verified PBS artifact (`INV-SUPPLY-01`)."""
    if not slim:
        return {}
    return slim_python(pydir, payload, log=log)

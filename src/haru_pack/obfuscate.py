"""Source obfuscation, as a modular engine — with pyarmor as the default.

## What this is honestly for, and what it is not

haru-pack can encrypt the payload inside the distributed binary. That protects the secret AT
REST: someone who has the exe but does not run it cannot read the source out of it. But the
launcher stages the payload to disk in plaintext so the interpreter can run it — that is not
an oversight, it is how running Python works — and any user who can execute the binary can
read the staged tree out of their own cache. See INV-SECRET-02.

Obfuscation does not change that boundary. It cannot: whatever runs on the target must be
runnable, so it must be recoverable. What obfuscation changes is the COST of understanding
what was recovered. pyarmor turns readable source into a bootstrap plus an encrypted code
object that its runtime executes, so a `grep` of the stage no longer yields the API key as a
string literal and the logic is not sitting there as `.py`. A determined reverse engineer
with the binary, a debugger and time still wins; most casual rummaging does not.

So the honest claim, and the only one made anywhere in this codebase, is:

    obfuscation raises the cost of reading the staged source. It is not a confidentiality
    boundary, and a secret that must never be recovered must never be shipped to the client.

The busybody `reverse_engineer` persona exists to keep that claim honest: it plants a known
secret, builds with and without obfuscation, and rummages the stage. "The literal is gone
from the staged source" is a fact it measures, not one this module asserts.

## Why modular

pyarmor is commercial, versioned, and occasionally unavailable (offline target, licence
lapse, a future where it is abandoned). This project's whole reason for existing is to
outlive the tools it leans on, so the engine is an interface with pyarmor as one
implementation. A `none` engine is the explicit default when nothing is asked for, and it is
also the honest fallback name — never a silent one.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["ObfuscationResult", "ObfuscationEngine", "get_engine", "engine_names",
           "ObfuscationError"]


class ObfuscationError(RuntimeError):
    """Requested obfuscation could not be applied. The build must fail rather than ship
    something that claims a protection it does not have."""


@dataclass
class ObfuscationResult:
    engine: str
    applied: bool
    files: int = 0
    note: str = ""
    # A truthful record for the manifest. The artifact should be able to state what was done
    # to it without anyone having to trust the person who built it.
    detail: dict = field(default_factory=dict)


class ObfuscationEngine:
    """Transform an application tree in place before it is packed.

    An engine mutates `app_dir` so that the same entrypoint still runs, but the source is no
    longer plainly readable. It must be idempotent enough to run on a fresh copy each build,
    and it must fail loudly rather than partially.
    """

    name = "base"

    def available(self) -> str:
        """"" if this engine can run here, else a human reason why it cannot."""
        raise NotImplementedError

    def obfuscate(self, app_dir: Path, entry_rel: str, python: str = "",
                  log=None) -> ObfuscationResult:
        raise NotImplementedError


class NoneEngine(ObfuscationEngine):
    """Does nothing, and says so. The default when `--obfuscate` is not passed, and the
    honest name for "no obfuscation" — so a manifest never has to imply protection by
    omission."""

    name = "none"

    def available(self) -> str:
        return ""

    def obfuscate(self, app_dir: Path, entry_rel: str, python: str = "",
                  log=None) -> ObfuscationResult:
        return ObfuscationResult(engine="none", applied=False,
                                 note="no obfuscation applied")


class PyArmorEngine(ObfuscationEngine):
    """Obfuscate with pyarmor (https://github.com/dashingsoft/pyarmor), run through uv.

    pyarmor is invoked as `uv run --python <version> --with pyarmor -- pyarmor gen`. Two
    reasons this is right rather than importing pyarmor directly:

      * pyarmor binds its obfuscated code to the interpreter version that produced it. The
        binary stages a specific Python (the manifest's `python`, default 3.12), so the
        obfuscation MUST target that version or the app fails to load at runtime — measured:
        obfuscating under 3.14 and staging 3.12 produces a bootstrap the staged interpreter
        cannot execute. Running pyarmor under the target version via uv fixes this exactly.
      * haru-pack then needs no pyarmor dependency of its own. uv — already the whole staging
        mechanism — provisions pyarmor on demand for the right interpreter.

    pyarmor's `gen` writes the obfuscated sources under `<out>/<app_dir_basename>/` and a
    sibling `<out>/pyarmor_runtime_*/`. Both are moved into the app dir so the entry keeps
    its path and `from pyarmor_runtime_* import ...` resolves alongside it.

    Supported interpreters: STANDARD CPython 3.7 through 3.14 (verified 3.11/3.12/3.13/3.14
    all obfuscate and run when targeted). pyarmor does NOT support free-threaded (GIL-less)
    CPython — the `+freethreaded` / `python3.14t` builds — and a bare "3.14" can resolve to
    one of those via uv, so that failure is caught and re-raised with the real constraint.
    There is nothing special about 3.12; it is only haru-pack's default `python`.
    """

    name = "pyarmor"

    def __init__(self, extra_args: tuple = ()):
        self._extra = tuple(extra_args)

    def available(self) -> str:
        if shutil.which("uv") is None:
            return ("obfuscation with pyarmor runs it under the target Python via uv, and "
                    "uv is not on PATH. Install uv, or choose another --obfuscate engine. "
                    "haru-pack will NOT silently ship unobfuscated when you asked for it.")
        return ""

    def obfuscate(self, app_dir: Path, entry_rel: str, python: str = "",
                  log=None) -> ObfuscationResult:
        say = log or (lambda _m: None)
        if reason := self.available():
            raise ObfuscationError(reason)
        if not (app_dir / entry_rel).exists():
            raise ObfuscationError(
                f"obfuscation entrypoint {entry_rel!r} does not exist in the app tree")

        pyver = python or "3.12"
        out = Path(tempfile.mkdtemp(prefix="haru-pyarmor-"))
        try:
            cmd = ["uv", "run", "--python", pyver, "--with", "pyarmor", "--",
                   "pyarmor", "gen", "--output", str(out), *self._extra, str(app_dir)]
            say(f"pyarmor: obfuscating {app_dir.name}/ under Python {pyver} (entry "
                f"{entry_rel})")
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            if r.returncode != 0:
                blob = (r.stderr or r.stdout)
                if "free-threading" in blob or "free-threaded" in blob:
                    # The one Python variant pyarmor refuses. Bare "3.13"/"3.14" can resolve
                    # to a +freethreaded build via uv, so name the real constraint and the
                    # fix rather than surfacing pyarmor's raw line.
                    raise ObfuscationError(
                        f"pyarmor does not support free-threaded (GIL-less) CPython, and the "
                        f"interpreter resolved for Python {pyver} is a free-threaded build. "
                        f"pyarmor works on STANDARD CPython (3.7 through 3.14). Pin a standard "
                        f"interpreter (e.g. --python 3.12), or drop --obfuscate for a "
                        f"free-threaded target.")
                raise ObfuscationError(
                    "pyarmor gen failed:\n" + blob.strip()[-800:])

            inner = out / app_dir.name
            runtimes = [d for d in out.iterdir()
                        if d.is_dir() and d.name.startswith("pyarmor_runtime")]
            if not inner.is_dir() or not runtimes:
                raise ObfuscationError(
                    f"pyarmor output layout not understood (looked for {app_dir.name}/ and "
                    f"pyarmor_runtime_*/ in {out}); got {[p.name for p in out.iterdir()]}")

            # Data files pyarmor does not reproduce (it only rewrites code) are preserved.
            preserved = _non_python_files(app_dir)
            for child in list(app_dir.iterdir()):
                shutil.rmtree(child, ignore_errors=True) if child.is_dir() else child.unlink()
            for item in inner.iterdir():
                dest = app_dir / item.name
                shutil.copytree(item, dest) if item.is_dir() else shutil.copy2(item, dest)
            for rt in runtimes:
                shutil.copytree(rt, app_dir / rt.name)
            restored = 0
            for rel, data in preserved.items():
                dest = app_dir / rel
                if not dest.exists():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
                    restored += 1

            if not (app_dir / entry_rel).exists():
                raise ObfuscationError(
                    f"obfuscated tree is missing the entrypoint {entry_rel!r}; pyarmor may "
                    f"have relocated it — pass --entry-point explicitly")

            n_py = sum(1 for _ in app_dir.rglob("*.py"))
            trial = "trial" in (r.stderr + r.stdout).lower()
            return ObfuscationResult(
                engine="pyarmor", applied=True, files=n_py,
                note=(f"pyarmor gen under Python {pyver} ({n_py} .py, {restored} asset(s) "
                      f"preserved)" + ("  [pyarmor is UNLICENSED/trial — size-limited and "
                                       "not for redistribution; buy a licence for release]"
                                       if trial else "")),
                detail={"python": pyver, "extra_args": list(self._extra), "trial": trial})
        finally:
            shutil.rmtree(out, ignore_errors=True)


def _non_python_files(app_dir: Path) -> dict:
    """Data files pyarmor will not reproduce, captured so they survive the swap.

    pyarmor rewrites code; a bundled `.json`, `.csv` or template is not its concern and would
    otherwise vanish when the original tree is cleared.
    """
    out = {}
    for p in app_dir.rglob("*"):
        if p.is_file() and p.suffix != ".py" and "__pycache__" not in p.parts:
            out[str(p.relative_to(app_dir))] = p.read_bytes()
    return out


# The registry. New engines register here; the CLI and the manifest speak these names.
_ENGINES: dict = {
    "none": NoneEngine,
    "pyarmor": PyArmorEngine,
}


def engine_names() -> list:
    return sorted(_ENGINES)


def get_engine(name: str, args=()) -> ObfuscationEngine:
    """Resolve an engine by name. `--obfuscate` with no value means pyarmor, the default
    real engine; the absence of the flag means `none`. `args` are engine-specific
    pass-through (pyarmor gen flags)."""
    if name not in _ENGINES:
        raise ObfuscationError(
            f"unknown obfuscation engine {name!r}; available: {', '.join(engine_names())}")
    cls = _ENGINES[name]
    try:
        return cls(tuple(args)) if args else cls()
    except TypeError:
        # an engine that takes no args was handed some; that is a usage error, not a crash
        raise ObfuscationError(f"engine {name!r} does not accept extra arguments") from None

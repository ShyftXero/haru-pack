"""Cases about WHERE the app runs and what alphabet it is handed.

    cartographer  the run-in-place contract: odd directories, symlinks, hostile argv
    polyglot      locale and encoding

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations


import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

from busybody_config import (ADDRESS_SPACE_MB, FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
import fcntl  # noqa: E402,F401
import termios  # noqa: E402,F401

# ================================================================================
# APP-LEVEL PERSONAS
#
# Everything above this line attacks the LAUNCHER, and the launcher is byte-identical in
# every binary haru-pack produces. That is why the 2026-09-10 top-25 sweep produced 575
# runs and only 23 distinct fingerprints: each case answered the same 25 times.
#
# These personas attack the PACKAGED APPLICATION instead — how the thing inside meets a
# hostile environment. That genuinely differs per package: numpy dlopens a BLAS, click
# inspects whether stdout is a terminal, pygments cares about the locale, torch wants
# address space, and iniconfig does none of it. Run these with `--fixtures top25` and the
# fingerprints should actually diverge.
#
# The expectation for most of them is "RAN or REFUSED, never CRASHED / HUNG / SILENT" —
# an application legitimately cannot start under a 64 MB address-space limit, and failing
# cleanly there is correct. What must never happen is a wedge, a raw traceback from the
# launcher, or a silent exit 0. The `blame` field records whether a non-zero exit came
# from the launcher or from the app, which is the distinction these personas turn on.
# ================================================================================

# ---------------------------------------------------------------- cartographer

@case("cartographer", ("RAN",),
      "Run the binary from a directory whose name contains spaces, unicode and a quote. "
      "haru-pack's headline claim is that a binary behaves like a compiled program in the "
      "folder it was launched from, and cwd is passed to the child — so a path the shell "
      "would need to quote is exactly where naive path handling breaks.",
      inv="INV-LAUNCH-07",
      remedy="A CRASHED or SILENT here means a path is being interpolated into a command "
             "string somewhere instead of passed as argv. Find it; nothing in the launcher "
             "should build a shell command from a path.")
def launched_from_an_awkward_directory(exe: Path, work: Path) -> dict:
    odd = work / "a dir with spaces 'and' quotes \u00e9\u00fc\u4f60\u597d"
    odd.mkdir(parents=True, exist_ok=True)
    return run_exe(exe, odd, env=clean_env(work / "c"))


@case("cartographer", ("RAN",),
      "Invoke through a symlink rather than the real path. Packaging tools that locate "
      "their own payload by argv[0] break here; haru-pack uses getAppFilename(), so this "
      "should be a non-event — and the case exists to keep it one.",
      inv="INV-LAUNCH-01",
      remedy="A refusal means self-location followed the symlink to somewhere without the "
             "payload. getAppFilename() must resolve the real executable.")
def invoked_through_a_symlink(exe: Path, work: Path) -> dict:
    link = work / "via-symlink"
    link.symlink_to(exe)
    return run_exe(link, work, env=clean_env(work / "c"))


@case("cartographer", ("RAN", "REFUSED", "APP-CRASHED"),
      "Run from a read-only working directory. An application that writes beside itself "
      "fails; one that does not, does not — which is precisely the kind of per-package "
      "difference the launcher-level cases cannot show.",
      remedy="Either outcome is acceptable, but the blame field must say `app` when it "
             "fails: the launcher has no business writing to cwd.")
def read_only_working_directory(exe: Path, work: Path) -> dict:
    ro = work / "readonly"
    ro.mkdir(parents=True, exist_ok=True)
    os.chmod(ro, 0o555)
    try:
        return run_exe(exe, ro, env=clean_env(work / "c"))
    finally:
        os.chmod(ro, 0o755)


@case("cartographer", ("RAN",),
      "argv passthrough: extra arguments, ones that look like flags, and shell "
      "metacharacters. README promises args reach the program 'like python' with no "
      "injected `--`, so this is a documented contract.",
      remedy="If the app never sees these, the launcher is swallowing or reordering argv. "
             "If the shell interprets them, something is building a command string.")
def hostile_argv_passthrough(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c"),
                   args=["--not-a-haru-flag", "-x", "a b c", "$(echo pwned)", "a;b|c", "--"])


# ---------------------------------------------------------------- polyglot

@case("polyglot", ("RAN", "APP-CRASHED"),
      "The C locale, no LANG, and legacy encoding forced on. Packages that decode text "
      "diverge sharply here — pygments, pyyaml and charset-normalizer all care, iniconfig "
      "does not.",
      remedy="A UnicodeDecodeError blamed on the app is a per-package fact worth "
             "recording. One blamed on the launcher means the launcher is decoding "
             "something it should be passing through as bytes.")
def c_locale_and_legacy_encoding(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", LC_ALL="C", LANG="C",
                                            PYTHONUTF8="0", PYTHONIOENCODING="ascii"))


@case("polyglot", ("RAN",),
      "A stage path containing non-ASCII. The cache directory carries the payload digest, "
      "but its parent is the user's — and users have unicode in their home directory.",
      inv="INV-STAGE-01",
      remedy="A failure here means a path is being encoded with the wrong codec, most "
             "likely where the stage token is written or compared.")
def unicode_in_the_cache_path(exe: Path, work: Path) -> dict:
    cache = work / "caché-\u4f60\u597d"
    cache.mkdir(parents=True, exist_ok=True)
    return run_exe(exe, work, env=clean_env(cache))



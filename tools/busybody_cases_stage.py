"""Cases that attack the STAGE and the environment around it.

    vandal         wrecks a staged tree AFTER a successful first run
    landlord       a hostile environment: read-only cache, no HOME, empty PATH, umask 077
    twin           two cold starts racing the same stage key
    timetraveller  clock skew and location spoofing

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "src"))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from haru_pack import overlay  # noqa: E402,F401

from busybody_config import (FATAL, MARKER, case)  # noqa: E402,F401
from busybody_runner import (Ctx, InfraFailure, blame, classify, clean_env,  # noqa: E402,F401
                             dir_bytes, infra_failure_reason, run_exe, stage_root,
                             warm, work_root_report)
from busybody_herd import herd_collect, herd_deadline, herd_start, herd_verdict, stage_key  # noqa: E402,F401
from busybody_stall import StallWatch  # noqa: E402,F401

# ================================================================ vandal

@case("vandal", ("REFUSED",),
      "Run once successfully, then edit a staged file. The next run must notice — this is "
      "INV-STAGE-01's whole reason to exist.",
      inv="INV-STAGE-01",
      remedy="SILENT means the modified file ran: verifyStagedDir is not re-hashing "
             "recorded files on reuse, or the file was wrongly treated as runtime-mutable. "
             "Check isRuntimeMutable's exemption list — it has been wrong twice.")
def staged_file_modified_after_success(exe: Path, work: Path) -> dict:
    cache, first = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    victims = [p for p in root.rglob("*.py") if p.is_file()]
    if not victims:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0,
                "stdout": "no staged .py to vandalise", "stderr": ""}
    v = victims[0]
    v.chmod(v.stat().st_mode | stat.S_IWUSR)
    v.write_text("print('VANDALISED')\n")
    r = run_exe(exe, work, env=clean_env(cache))
    if "VANDALISED" in r["stdout"]:
        r["outcome"] = "SILENT"
    return r


@case("vandal", ("REFUSED",),
      "Delete a recorded file from a working stage. Missing is as bad as modified.",
      inv="INV-STAGE-01",
      remedy="verifyStagedDir must treat a missing recorded file as fatal, not skip it.")
def staged_file_deleted(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    victims = [p for p in root.rglob("*.py") if p.is_file()]
    if not victims:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "nothing to delete",
                "stderr": ""}
    victims[0].unlink()
    return run_exe(exe, work, env=clean_env(cache))


@case("vandal", ("REFUSED", "RAN"),
      "Open the whole staged tree to the world after it worked. Group/other-writable code "
      "is code anyone can replace before the next run.",
      inv="INV-STAGE-01",
      remedy="Refusing is stronger. If it runs, the mode check on the stage root is not "
             "being applied on the reuse path.")
def stage_opened_to_the_world(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    os.chmod(root, 0o777)
    return run_exe(exe, work, env=clean_env(cache))


@case("vandal", ("REFUSED", "RAN"),
      "Replace the stage directory with a symlink pointing somewhere else entirely.",
      inv="INV-STAGE-01",
      remedy="assertSafePath uses lstat specifically to catch this. A run means the symlink "
             "was followed.")
def stage_replaced_with_symlink(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    elsewhere = work / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    shutil.rmtree(root)
    root.symlink_to(elsewhere, target_is_directory=True)
    return run_exe(exe, work, env=clean_env(cache))



@case("vandal", ("REFUSED",),
      "Modify a native library (.so/.pyd) in a staged tree, not a .py file. Verification "
      "must cover compiled artifacts too — they are the ones an attacker would rather "
      "replace, and the ones a naive 'check the Python files' implementation misses. "
      "Measured 2026-09-10: catches a flipped byte in a wheel's .so AND in the bundled "
      "interpreter's own libpython. NOTE: this was added believing it would be "
      "payload-sensitive (pure-Python packages having no .so to modify). That was wrong "
      "at the thick tier, where every payload ships an interpreter and therefore ships "
      ".so files — iniconfig, which is pure Python, caught a modified libpython. The case "
      "is worth keeping for what it does prove; it does NOT vary by package.",
      inv="INV-STAGE-01",
      remedy="SILENT or RAN means .stage-files does not record native libraries, or "
             "isRuntimeMutable exempts them. Compiled code must be covered by the same "
             "digest manifest as source.")
def native_library_modified_after_success(exe: Path, work: Path) -> dict:
    cache, _ = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0, "stdout": "no stage", "stderr": ""}
    libs = [p for p in root.rglob("*.so") if p.is_file()] + \
           [p for p in root.rglob("*.pyd") if p.is_file()]
    # Prefer something inside the app's own venv over the bundled interpreter's stdlib.
    libs.sort(key=lambda p: (".venv" not in str(p), len(str(p))))
    if not libs:
        # Only reachable at a tier that bundles no interpreter; at thick this never fires.
        return {"outcome": "REFUSED", "rc": None, "seconds": 0,
                "stdout": "", "stderr": "SKIPPED: no native library in the payload"}
    v = libs[0]
    v.chmod(v.stat().st_mode | stat.S_IWUSR)
    data = bytearray(v.read_bytes())
    data[len(data) // 2] ^= 0xFF          # flip a byte in the middle of the machine code
    v.write_bytes(bytes(data))
    return run_exe(exe, work, env=clean_env(cache))


# ================================================================ landlord

@case("landlord", ("REFUSED",),
      "The cache directory is read-only. Nothing can be staged; say so instead of dying "
      "in a way nobody can act on.",
      inv="INV-LAUNCH-06",
      remedy="Expect a clear 'cannot write to cache' style message naming the path. A "
             "traceback here is the classic unhandled OSError.")
def read_only_cache(exe: Path, work: Path) -> dict:
    cache = work / "rocache"
    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, 0o555)
    try:
        return run_exe(exe, work, env=clean_env(cache))
    finally:
        os.chmod(cache, 0o755)


@case("landlord", ("REFUSED", "RAN"),
      "No HOME and no XDG_CACHE_HOME. The launcher has to put the stage somewhere; "
      "whatever it decides, it must not crash deciding.",
      inv="INV-LAUNCH-06",
      remedy="getHomeDir() with no HOME is the usual culprit. Either fall back or refuse "
             "with a message; do not propagate the exception.")
def no_home_at_all(exe: Path, work: Path) -> dict:
    env = clean_env(work / "unused-cache")
    env.pop("HOME", None)
    env.pop("XDG_CACHE_HOME", None)          # clean_env sets it; this case removes both
    return run_exe(exe, work, env=env)


@case("landlord", ("REFUSED", "RAN"),
      "An empty PATH. A thick binary should not care; anything else should complain "
      "clearly rather than exploding.",
      remedy="A thick binary should not consult PATH at all. Other tiers should say they "
             "cannot find uv, naming what they looked for.")
def empty_path(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", PATH=""))


@case("landlord", ("RAN",),
      "A paranoid umask (077). Files created during staging must still be usable by the "
      "process that made them.",
      inv="INV-STAGE-01",
      remedy="Staging hardens permissions deliberately; make sure it does not strip the "
             "owner's own read/execute bits under a restrictive umask.")
def hostile_umask(exe: Path, work: Path) -> dict:
    old = os.umask(0o077)
    try:
        return run_exe(exe, work, env=clean_env(work / "umaskcache"))
    finally:
        os.umask(old)


# ================================================================ twin

@case("twin", ("RAN",),
      "Two first runs at the same instant on one cold cache. Both should end up working: "
      "the loser of the race must not get a half-built stage.",
      inv="INV-STAGE-01",
      remedy="Staging is meant to be atomic: build in a per-process .tmp- directory, then "
             "move into place. A failure here means the move is not atomic or the loser "
             "reads a partially written tree.",
      serial=True)
def two_cold_starts_at_once(exe: Path, work: Path) -> dict:
    cache = work / "racecache"
    cache.mkdir(parents=True, exist_ok=True)
    env = clean_env(cache)
    a = subprocess.Popen([str(exe)], cwd=work, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    b = subprocess.Popen([str(exe)], cwd=work, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    outs = []
    for p in (a, b):
        try:
            o, e = p.communicate(timeout=180)
            outs.append((p.returncode, o, e))
        except subprocess.TimeoutExpired:
            p.kill()
            outs.append((None, "", "timeout"))
    worst = "RAN"
    detail = []
    for rc, o, e in outs:
        c = classify(rc, o, e, rc is None)
        detail.append(f"rc={rc} {c}")
        if c in FATAL or (c == "REFUSED" and worst == "RAN"):
            worst = c
    return {"outcome": worst, "rc": outs[0][0], "seconds": 0,
            "stdout": " ; ".join(detail), "stderr": (outs[0][2] or "")[-300:]}




# ================================================================ timetraveller

@case("timetraveller", ("RAN",),
      "Spoof the location the geo check reads. HARUPACK_GEO is supplied by the person "
      "being restricted, so this MUST get through — the docs say the check is advisory. "
      "A refusal here would mean the documentation understates what geo does.",
      inv="see THREAT_MODEL.md",
      remedy="RAN is correct and expected. If this ever refuses, the geo check became "
             "load-bearing and README/THREAT_MODEL must stop calling it advisory.")
def geo_spoofed(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", HARUPACK_GEO="XX"))


@case("timetraveller", ("RAN",),
      "An unencrypted binary must ignore licence variables entirely rather than taking a "
      "detour through code that does not apply to it.",
      remedy="An unencrypted payload must not enter the licence path at all.")
def licence_vars_on_an_unencrypted_binary(exe: Path, work: Path) -> dict:
    return run_exe(exe, work, env=clean_env(work / "c", HARUPACK_SECRET="not-a-secret",
                                            HARUPACK_GEO="ZZ"))



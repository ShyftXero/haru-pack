"""Cases that attack the LAUNCHER itself: the binary, its payload, its first stage.

    butterfingers  accidental corruption — truncation, a lost exec bit, a kill mid-stage
    squatter       something already at the stage path when the launcher arrives
    forger         a payload edited to still look valid

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import io
import os
import shutil
import signal
import subprocess
import sys
import time
import zipfile
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

# ================================================================ butterfingers

@case("butterfingers", ("REFUSED",),
      "A download that stopped halfway leaves a short file. It must be reported, not "
      "executed and not crashed on.",
      inv="INV-LAUNCH-05, INV-LAUNCH-06",
      remedy="A short file has no valid footer. overlay.findFooter should report that and "
             "exit; if you got a traceback, the top-level handler in main.nim is missing or "
             "the failure is a Defect (which CatchableError cannot catch) and needs an "
             "explicit bounds check instead.")
def truncated_binary(exe: Path, work: Path) -> dict:
    victim = work / "truncated"
    data = exe.read_bytes()
    victim.write_bytes(data[: len(data) // 2])
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("butterfingers", ("REFUSED",),
      "Only the launcher arrived; the payload never did. The footer is gone entirely.",
      inv="INV-LAUNCH-05",
      remedy="Expect 'no payload appended'. Anything else means findFooter is reading past "
             "the end of a short file.")
def payload_lopped_off(exe: Path, work: Path) -> dict:
    victim = work / "nopayload"
    info = overlay.verify(exe)
    victim.write_bytes(exe.read_bytes()[: info["payload_off"]])
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("butterfingers", ("RAN",),
      "Ctrl-C during the first-run staging, then run again. The half-written stage must "
      "not poison every later run — recovery is the whole point of a cache.",
      inv="INV-STAGE-01",
      remedy="A leftover .tmp- directory or a stage with no .ready must be discarded and "
             "rebuilt, not reused and not treated as fatal. Check stageZip's reuse path.",
      serial=True)
def killed_mid_stage(exe: Path, work: Path) -> dict:
    cache = work / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    p = subprocess.Popen([str(exe)], cwd=work, env=clean_env(cache),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)                       # let it get into staging
    p.send_signal(signal.SIGKILL)
    p.wait(timeout=30)
    return run_exe(exe, work, env=clean_env(cache))


@case("butterfingers", ("REFUSED", "RAN"),
      "A file manager copy that dropped the executable bit. Refusing is fine; a confusing "
      "crash is not.",
      remedy="Nothing to fix in haru-pack if this refuses — the OS did it. Recorded so the "
             "failure mode is known and does not get mistaken for corruption.")
def not_executable(exe: Path, work: Path) -> dict:
    victim = work / "noexec"
    shutil.copy2(exe, victim)
    victim.chmod(0o644)
    return run_exe(victim, work, env=clean_env(work / "c"))


# ================================================================ squatter

@case("squatter", ("REFUSED", "RAN"),
      "Something is already sitting at the stage path with a plausible .ready token. It "
      "token. It must be verified or replaced — never trusted and executed.",
      inv="INV-STAGE-01",
      remedy="SILENT here means the squatter's code ran: the trust-on-first-use bug is "
             "back. stageZip must validate the .ready token against this payload's digest "
             "and re-hash every file in .stage-files before reusing a tree.")
def precreated_stage_with_fake_ready(exe: Path, work: Path) -> dict:
    cache, first = warm(exe, work)
    root = stage_root(cache)
    if root is None:
        return {"outcome": "SILENT", "rc": 0, "seconds": 0,
                "stdout": "no stage produced", "stderr": ""}
    shutil.rmtree(root)
    root.mkdir(parents=True)
    (root / ".ready").write_text("1")                 # the old, trusted-blindly token
    (root / "app").mkdir()
    (root / "app" / "evil.py").write_text("print('SQUATTER WAS HERE')\n")
    r = run_exe(exe, work, env=clean_env(cache))
    if "SQUATTER WAS HERE" in r["stdout"]:
        r["outcome"] = "SILENT"                       # ran the squatter's tree
    return r


@case("squatter", ("RAN",),
      "A `uv` earlier on PATH than the bundled one. A thick binary claims to be hermetic, "
      "so it must ignore it.",
      inv="INV-LAUNCH-04",
      remedy="SILENT means findUv consulted PATH before the bundled binary. The thick tier "
             "must use its own vendor/uv unconditionally and die if it is missing.")
def uv_planted_on_path(exe: Path, work: Path) -> dict:
    fake = work / "fakebin"
    fake.mkdir(parents=True, exist_ok=True)
    uv = fake / "uv"
    uv.write_text("#!/bin/sh\necho 'PLANTED UV RAN' >&2\nexit 3\n")
    uv.chmod(0o755)
    env = clean_env(work / "c2", PATH=f"{fake}:{os.environ.get('PATH', '')}")
    r = run_exe(exe, work, env=env)
    if "PLANTED UV RAN" in r["stderr"]:
        r["outcome"] = "SILENT"
    return r


@case("squatter", ("REFUSED", "RAN"),
      "The cache directory exists but is owned by nobody in particular and world-writable "
      "— a shared /tmp-style cache.",
      inv="INV-STAGE-01",
      remedy="Refusing is the stronger behaviour. If it runs, confirm assertSafePath still "
             "rejects group/world-writable stage paths on POSIX.")
def world_writable_cache(exe: Path, work: Path) -> dict:
    cache = work / "wwcache"
    (cache / "haru-pack").mkdir(parents=True, exist_ok=True)
    os.chmod(cache / "haru-pack", 0o777)
    return run_exe(exe, work, env=clean_env(cache))


# ================================================================ forger

@case("forger", ("REFUSED",),
      "One byte flipped inside the payload, footer untouched. This is exactly what "
      "INV-LAUNCH-01's digest check exists to catch.",
      inv="INV-LAUNCH-01",
      remedy="A RAN here means the launcher is not verifying its payload digest — the "
             "check was removed or is running after staging. It must happen before "
             "openContainer and before stageZip.")
def payload_byte_flipped(exe: Path, work: Path) -> dict:
    victim = work / "flipped"
    data = bytearray(exe.read_bytes())
    info = overlay.verify(exe)
    data[info["payload_off"] + 64] ^= 0xFF
    victim.write_bytes(bytes(data))
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("forger", ("RAN",),
      "The real version of the tamper attack: rebuild the payload zip properly — valid "
      "CRC32s and all — then recompute the footer digest to match. This is EXPECTED to "
      "succeed. INV-LAUNCH-01 says in its own Note that the footer digest is not a MAC, "
      "and this case is what that sentence means in practice. A first draft of this case "
      "just flipped a byte and got REFUSED, which looked like tamper-detection but was "
      "actually the zip's own CRC32 refusing a corrupt archive — an incidental check that "
      "an attacker simply would not trip.",
      inv="INV-LAUNCH-01 (Note), INV-LAUNCH-03",
      remedy="RAN is the documented, expected outcome and is why INV-LAUNCH-03 (a real "
             "signature) is still open. If this ever REFUSES, the payload gained genuine "
             "authentication: update INV-LAUNCH-01's Note, and promote INV-LAUNCH-03 if a "
             "signature is what did it.")
def payload_reforged_with_valid_crcs(exe: Path, work: Path) -> dict:
    """Craft a valid replacement payload rather than corrupting the existing one."""

    info = overlay.verify(exe)
    data = exe.read_bytes()
    off, ln = info["payload_off"], info["payload_len"]
    original = data[off:off + ln]
    if original[:2] != b"PK":
        return {"outcome": "RAN", "rc": 0, "seconds": 0,
                "stdout": "payload is not a plain zip (encrypted build); case not applicable",
                "stderr": ""}

    buf = io.BytesIO()
    replaced = False
    with zipfile.ZipFile(io.BytesIO(original)) as src, \
         zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            body = src.read(item.filename)
            if item.filename.endswith("app.py") and not replaced:
                body = b"print('FORGED PAYLOAD RAN')\n"
                replaced = True
            dst.writestr(item, body)
    forged = buf.getvalue()

    launcher = work / "stub"
    launcher.write_bytes(data[:off])
    victim = work / "reforged"
    overlay.attach(launcher, forged, victim)      # writes a correct footer for the new bytes
    victim.chmod(0o755)

    r = run_exe(victim, work, env=clean_env(work / "c"))
    if "FORGED PAYLOAD RAN" in r["stdout"]:
        # Expected: the substituted code ran. Report it as RAN, since the documented
        # behaviour is that a recomputed digest is accepted.
        r["outcome"] = "RAN"
        r["stdout"] = "FORGED PAYLOAD RAN (expected — the footer digest is not a MAC)"
    return r


@case("forger", ("REFUSED",),
      "Absurd payload extent in the footer: 2**63 bytes at an impossible offset. Must be "
      "rejected by size, not discovered by allocating (INV-LAUNCH-05).",
      inv="INV-LAUNCH-05",
      remedy="CRASHED means footerFault is not validating the extent against the file size "
             "before use. A RangeDefect is a Defect, not a CatchableError, so it cannot be "
             "caught downstream — it has to be checked up front.")
def footer_extent_is_nonsense(exe: Path, work: Path) -> dict:
    import struct
    victim = work / "badextent"
    data = bytearray(exe.read_bytes())
    at = overlay.verify(exe)["footer_at"]
    struct.pack_into("<Q", data, at + 12, 2 ** 63)    # payloadOff
    victim.write_bytes(bytes(data))
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("forger", ("REFUSED",),
      "A second, later footer appended after the real one. Backward scan finds the last "
      "magic, so an attacker who appends wins unless the extent is validated.",
      inv="INV-LAUNCH-05",
      remedy="The appended footer names an extent outside the file, so the size check "
             "should reject it. A crash means that check is missing or runs too late.")
def second_footer_appended(exe: Path, work: Path) -> dict:
    import struct
    victim = work / "twofooters"
    data = bytearray(exe.read_bytes())
    fake = (overlay.MAGIC + struct.pack("<HHQQ", 1, 0, len(data) + 999999, 4096)
            + b"\x00" * 32 + overlay.TAIL)
    victim.write_bytes(bytes(data) + fake)
    victim.chmod(0o755)
    return run_exe(victim, work, env=clean_env(work / "c"))


@case("forger", ("RAN", "REFUSED"),
      "HARUPACK_DEV_STAGE pointed at an attacker's tree. A release build must IGNORE the "
      "variable and run its own payload — so RAN is the correct outcome here, and SILENT "
      "(the attacker's tree executing) is the failure. Refusing outright is also fine. "
      "The first version of this case expected REFUSED, which was simply wrong: ignoring "
      "an environment variable is not the same as rejecting the binary.",
      inv="INV-LAUNCH-02",
      remedy="SILENT means a release build still honours HARUPACK_DEV_STAGE — the "
             "`when defined(haruDev)` gate is gone. Verify with: strings <binary> | grep "
             "HARUPACK_DEV_STAGE (should print nothing).")
def dev_stage_redirect(exe: Path, work: Path) -> dict:
    evil = work / "evil-stage"
    (evil / "app").mkdir(parents=True, exist_ok=True)
    (evil / "manifest.toml").write_text(
        'name = "evil"\nkind = "script"\nentrypoint = ["evil.py"]\n')
    (evil / "app" / "evil.py").write_text("print('DEV STAGE HIJACK')\n")
    r = run_exe(exe, work, env=clean_env(work / "c", HARUPACK_DEV_STAGE=str(evil)))
    if "DEV STAGE HIJACK" in r["stdout"]:
        r["outcome"] = "SILENT"
    elif r["outcome"] == "RAN":
        r["outcome"] = "RAN"          # ignored the variable and ran normally: correct
    return r



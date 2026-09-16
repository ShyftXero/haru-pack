"""quotamaster — the mounts you cannot fake, run inside a container.

noexec, ENOSPC, a read-only root and a cgroup memory limit are properties of a real mount,
not of a directory. These cases skip rather than lie when docker is unavailable.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_compose_run import COMPOSED_APP  # noqa: E402

import shutil
import subprocess
import sys
import time
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
from busybody_fixtures import build_fixture  # noqa: E402,F401
from busybody_wedge import _build  # noqa: E402,F401

# ------------------------------------------------------- quotamaster: real mounts, in docker

# Some target hostility cannot be faked in-process. A noexec mount is the clearest example:
# staging writes an interpreter and then execs it, so a cache on a noexec filesystem fails at
# exec with EACCES. That is a real and common deployment configuration — /tmp is noexec on
# any hardened host, and CIS benchmarks recommend it — and mount(2) needs privileges this
# harness should never ask for.
#
# So these run the artifact inside a container where the mount options are chosen by docker
# rather than by us. The image is a plain glibc base: thick binaries carry their own
# interpreter, so nothing else is needed, and using a stock image keeps the case honest about
# what the binary actually requires of a host.

DOCKER_IMAGE = "debian:12-slim"


def _docker_available() -> str:
    """"" if docker can run, else the reason it cannot."""
    if not shutil.which("docker"):
        return "docker is not installed"
    r = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        pull = subprocess.run(["docker", "pull", "-q", DOCKER_IMAGE],
                              capture_output=True, text=True, timeout=600)
        if pull.returncode != 0:
            return f"{DOCKER_IMAGE} unavailable: {(pull.stderr or '').strip()[:120]}"
    return ""


def _docker_run(exe: Path, work: Path, *, cache_opts: str, extra=(),
                timeout: int = 600) -> dict:
    """Run `exe` in a container whose cache mount carries `cache_opts`."""
    stage = work / "docker"
    stage.mkdir(parents=True, exist_ok=True)
    inner = stage / exe.name
    shutil.copy2(exe, inner)
    inner.chmod(0o755)

    argv = ["docker", "run", "--rm", "--network", "none",
            "-v", f"{stage}:/w",
            "--tmpfs", f"/cache:{cache_opts}" if cache_opts else "/cache",
            "-e", "XDG_CACHE_HOME=/cache",
            "-e", "HOME=/cache",
            "-w", "/w", *extra, DOCKER_IMAGE, f"/w/{exe.name}"]
    t0 = time.monotonic()
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        rc, out, err, to = r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = None, (e.stdout or b"").decode("utf8", "replace"), \
            (e.stderr or b"").decode("utf8", "replace"), True
    secs = round(time.monotonic() - t0, 1)

    # Docker's own failures are the harness's problem, not haru-pack's.
    if rc is not None and rc in (125, 126, 127) and "haru-pack" not in (out + err):
        return {"outcome": "CASE-ERROR", "rc": rc, "seconds": secs, "blame": "harness",
                "stdout": "", "stderr": f"docker could not start the run: "
                                        f"{(err or out).strip()[-300:]}"}
    outcome = classify(rc, out, err, to)
    return {"outcome": outcome, "rc": rc, "seconds": secs,
            "blame": blame(out, err) if outcome != "RAN" else "none",
            "stdout": (out or "").strip()[-400:], "stderr": (err or "").strip()[-400:],
            "docker": " ".join(argv[:12])}


def _thick_for_docker(work: Path) -> tuple:
    """A thick binary to take into a container. Built once per case; thick is the only tier
    that can run with --network none."""
    proj = work / "dproj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(COMPOSED_APP)
    out = work / "dockerable"
    rc, so, se = _build(proj / "app.py", out, "--tier", "thick", timeout=2400)
    return (rc == 0 and out.exists()), out, (so + se).strip()[-300:]


def _quotamaster(work: Path, *, cache_opts: str, extra=(), needs_msg: str) -> dict:
    if why := _docker_available():
        return {"outcome": "REFUSED", "rc": None, "seconds": 0, "blame": "harness",
                "stdout": "", "stderr": f"SKIPPED: {why}"}
    ok, exe, note = _thick_for_docker(work)
    if not ok:
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"thick build failed: {note}"}
    r = _docker_run(exe, work, cache_opts=cache_opts, extra=extra)
    r["needs"] = needs_msg
    return r


@case("quotamaster", ("REFUSED", "RAN"),
      "The cache is on a noexec mount, as /tmp is on any hardened host. Staging writes an "
      "interpreter and then execs it, so this fails at exec with EACCES. A refusal is the "
      "right outcome — but the message has to name the mount, because 'permission denied' "
      "sends the operator to check file ownership and they will find nothing wrong with it.",
      inv="INV-STAGE-01",
      remedy="If this CRASHES or is SILENT, the exec failure is not being handled. If it "
             "REFUSES without saying 'noexec' or naming the directory, the diagnostic is "
             "the finding: suggest HARU_CACHE_DIR or an equivalent on an exec-capable path.",
      per_fixture=False, serial=True)
def cache_on_a_noexec_mount(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="noexec,size=2g",
                        needs_msg="docker, for a real noexec mount")


@case("quotamaster", ("REFUSED", "RAN"),
      "The cache filesystem is 24 MB — far smaller than a staged interpreter. Writes fail "
      "partway, which produces a PARTIAL stage rather than no stage: the case that most "
      "needs an integrity check, because the next run may find a plausible-looking "
      "directory and use it.",
      inv="INV-STAGE-01",
      remedy="A truncated stage must never be treated as complete. If a later run reuses "
             "it, the ready-marker is being written before the stage is verified.",
      per_fixture=False, serial=True)
def cache_filesystem_is_far_too_small(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="size=24m",
                        needs_msg="docker, for a real size-limited filesystem")


@case("quotamaster", ("REFUSED", "RAN"),
      "A read-only root filesystem with only the cache writable — a hardened container, and "
      "an increasingly normal way to ship software. Anything the launcher writes outside "
      "its cache fails here, and that is worth knowing before a customer finds it.",
      inv="INV-STAGE-01",
      remedy="Every write must go through the cache directory. A failure here names the "
             "path that was written outside it.",
      per_fixture=False, serial=True)
def read_only_root_filesystem(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="size=2g", extra=("--read-only",),
                        needs_msg="docker, for a real read-only rootfs")


@case("quotamaster", ("REFUSED", "RAN", "APP-CRASHED"),
      "512 MB of container memory, enforced by a cgroup rather than by RLIMIT_AS. A cgroup "
      "limit kills on the OOM path instead of failing an allocation, so the process gets "
      "SIGKILL with no traceback and no message — which is a different failure from the "
      "rlimit case and must not be reported as a silent success.",
      inv="INV-STAGE-01",
      remedy="An OOM kill has rc 137 and no output. If that is classified as SILENT rather "
             "than as a kill, the classifier needs to learn 137.",
      per_fixture=False, serial=True)
def cgroup_memory_limit(exe: Path, work: Path) -> dict:
    return _quotamaster(work, cache_opts="size=2g", extra=("-m", "512m"),
                        needs_msg="docker, for a real cgroup memory limit")



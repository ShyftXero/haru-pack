"""Running a binary and deciding what happened to it.

The two halves that matter: `run_exe` puts a real executable under real limits, and
`classify`/`blame` turn an exit status and two streams into ONE outcome name. Everything
else in the harness is a case that calls the first and a report that reads the second.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import hashlib  # noqa: E402

import json
import os
import random
import subprocess
import time
from pathlib import Path

import busybody_config as cfg
from busybody_config import MARKER
from busybody_ledger import SCHEMA_VERSION



class Ctx:
    """What a case can reach back to: its seed, a place to announce a fault, the heartbeat.

    Module-level rather than a parameter because every case takes (exe, work) and widening
    all of them to reach this would be churn for no signal.

    THE JOURNAL IS NOT HERE ON PURPOSE. A case may run in a worker process under --jobs,
    and run_one's contract is that the parent is the only journal writer, so the append
    order stays deterministic with one fsync-per-line writer. A worker therefore announces
    a fault to a FILE in its own work directory; the parent folds those lines into the
    journal when the record comes back. The file is the durable half: it is written and
    fsynced before the fault, so it survives the worker being killed by it, which is the
    entire point of announcing beforehand.

    Every method is a no-op when no case is in progress. The unit tests exec this module
    with importlib and there is no run then; a context that raised outside a run would make
    a case that announces its faults untestable.
    """

    work = None             # set by run_one for the duration of one case; else None
    run_dir = None
    seed = 0
    case = ""
    fixture = ""

    PERTURBATIONS = "perturbations.jsonl"

    @classmethod
    def enter(cls, work, seed: int, case: str, fixture: str, run_dir=None) -> None:
        cls.work, cls.seed, cls.case, cls.fixture = work, seed, case, fixture
        cls.run_dir = run_dir

    @classmethod
    def clear(cls) -> None:
        cls.work, cls.run_dir, cls.case, cls.fixture = None, None, "", ""

    @classmethod
    def rng(cls, salt: str = "") -> random.Random:
        """A stream determined by (run seed, case, fixture, salt) and nothing else.

        hashlib, not the hash() builtin: hash() is salted per process, so the same --seed
        would draw a different stream every run and the one thing a seed is for — landing
        a fault at the same moment twice — would silently not work. It also has to hold
        across a process boundary, because under --jobs the case runs in a worker.
        """
        basis = "|".join((str(cls.seed), cls.case, cls.fixture, salt))
        digest = hashlib.sha256(basis.encode("utf-8")).digest()[:8]
        return random.Random(int.from_bytes(digest, "big"))

    @classmethod
    def perturb(cls, action: str, **fields) -> None:
        """Announce a NEMESIS action BEFORE performing it, never after.

        `nemesis` is Jepsen's word for deliberate fault injection — the process that
        partitions the network, pauses a node, skews a clock. It is the right word for what
        this records: a fault the harness CHOSE, as opposed to the probabilistic kind
        (FoundationDB calls that **buggification**), which is what a trait's firing
        probability produces. Both end up in this file; the distinction is whether a human
        named the fault or a draw did.

        A fault whose moment was chosen from a seed is unattributable if it is recorded
        after the fact: a kill at 0.4s and a kill at 4.0s leave the same case name with
        different outcomes and nothing says which moment was chosen. Recorded beforehand,
        the harness's own jitter can never be read as a product defect.
        """
        if cls.work is None:
            return
        rec = {"schema_version": SCHEMA_VERSION, "at": round(time.time(), 3),
               "kind": "perturb", "case": cls.case,
               "fixture": cls.fixture, "seed": cls.seed, "action": action, **fields}
        with open(Path(cls.work) / cls.PERTURBATIONS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    @classmethod
    def observe(cls, kind: str, **fields) -> None:
        """Record something the harness SAW rather than something it did.

        Same durable channel as perturb() and deliberately not the same record type: a
        perturbation is a fault this harness injected, and a stall is a fact about the
        product. Filing an observation as a perturbation would make the seeded records
        untrustworthy — a reader could no longer tell which entries the harness caused.
        """
        if cls.work is None:
            return
        rec = {"schema_version": SCHEMA_VERSION, "at": round(time.time(), 3), "kind": kind,
               "case": cls.case, "fixture": cls.fixture, "seed": cls.seed, **fields}
        with open(Path(cls.work) / cls.PERTURBATIONS, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    @classmethod
    def forensics(cls, reason: str, cache=None) -> str:
        """Collect a forensic bundle NOW, from the living system. Returns its path, or "".

        The distinction that makes this worth having: `preserve()` copies what the case LEFT
        BEHIND, afterwards. This captures what was GOING ON, at the moment. By the time a
        case returns, the processes are gone, the descriptors are closed, and which of the
        sixteen children was holding the stage is unrecoverable — and a HUNG or STALLED
        finding is exactly the one where the record is least useful and the live state is
        most.

        Written into the work directory, the same durable channel `perturb` and `observe`
        use, so it survives this process being killed by the thing it is documenting.

        Never raises and never blocks for long; see busybody_bundle for the rules its
        collectors follow. A collector that throws while investigating a failure turns a
        finding into a CASE-ERROR and loses both.
        """
        if cls.work is None:
            return ""
        try:
            import busybody_bundle

            bundle = busybody_bundle.collect(work=cls.work, cache=cache, reason=reason)
            bundle.update(case=cls.case, fixture=cls.fixture, seed=cls.seed)
            n = len(list(Path(cls.work).glob("forensics-*.json")))
            dest = Path(cls.work) / f"forensics-{n:02d}.json"
            dest.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
            return str(dest)
        except Exception:
            # Deliberately bare. This runs on the failure path; a forensic collector that
            # can itself fail the case is worse than no forensic collector.
            return ""

    @classmethod
    def announced(cls, work) -> list:
        """The fault announcements one case left behind, oldest first."""
        p = Path(work) / cls.PERTURBATIONS
        if not p.is_file():
            return []
        out = []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    @classmethod
    def beat(cls) -> None:
        # A case that can outlast busybody_ledger.HEARTBEAT_STALE_S (120s) must beat from
        # inside itself. The driver beats only BETWEEN cases, so a herd case that runs
        # longer goes stale while it is still working — and a stale heartbeat is exactly
        # how reap_orphans and prune_runs decide a run is dead and delete its work dirs.
        # A plain rewrite, mirroring Journal.beat: last writer wins, and freshness is the
        # only thing the file means, so a worker writing it is not a second log writer.
        if cls.run_dir is None:
            return
        try:
            (Path(cls.run_dir) / "heartbeat").write_text(str(time.time()))
        except OSError:
            pass


# ---------------------------------------------------------------- outcome classification

TRACEBACK_MARKERS = (
    "Traceback (most recent call last)",      # Python
    "Error: unhandled exception",             # Nim
    "[IndexDefect]", "[RangeDefect]", "[ValueError]", "[OSError]",
    "sysFatal", "signal SIGSEGV", "core dumped",
)


# The harness's own environment running out of room is not a chaos finding. Disk quota and
# no-space are never imposed deliberately by any persona — `hoarder` starves file
# descriptors, address space and TMPDIR writability, never capacity — so seeing one of these
# means the box gave up, and every result after it is garbage.
#
# Measured 2026-09-10, the hard way: a 925-run sweep exhausted the user quota on /tmp at case
# 168 and reported 470 "findings", all of them the same environment failure wearing 30
# different persona costumes. --analyze showed the tell immediately (the same five fixtures
# passing every case, and those five were the first five built) but the run had already
# written 470 rows to the findings ledger.
# These are broad in text — `No space left on device` / `[Errno 28]` / `Disk quota exceeded`
# would, read literally, also match a case that DELIBERATELY induces the condition (the
# quotamaster persona builds a `size=24m` mount to watch the launcher refuse cleanly). That
# would be a false infra-abort: a case working as designed, misread as the box failing. VERIFIED
# 2026-09-12 under docker that it does NOT fire — `cache_filesystem_is_far_too_small` grades
# REFUSED, 1/1 as expected, because the launcher WRAPS the OS error in its own `haru-pack: …`
# diagnostic and never surfaces the raw marker string into the graded child's output. So the
# collision is latent, not live; if a future launcher (or a package's uv/python) ever leaked a
# raw ENOSPC/quota string into a graded case, scope the marker to the harness's own writes (as
# the journal marker already is) rather than widening it. The `while writing the journal` suffix
# on the read-only marker is that scoping done right — it only fires on the HARNESS's own write.
INFRA_MARKERS = (
    "Disk quota exceeded", "errno: 122", "[Errno 122]",
    "No space left on device", "errno: 28", "[Errno 28]",
    "Read-only file system) while writing the journal",
)


def dir_bytes(d: Path) -> int:
    """Apparent size of a tree. Metadata only, so it is cheap enough to call per case."""
    total = 0
    for root, _dirs, files in os.walk(d, onerror=lambda _e: None):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


class InfraFailure(RuntimeError):
    """The box, not the product. Aborts the sweep instead of scoring it."""


def infra_failure_reason(r: dict) -> str:
    """Return the environment failure in this result, or "" if it is a real outcome."""
    blob = (r.get("stdout") or "") + (r.get("stderr") or "")
    for m in INFRA_MARKERS:
        if m in blob:
            line = next((ln.strip() for ln in blob.splitlines() if m in ln), m)
            return line[:200]
    return ""


def work_root_report(root: Path) -> list:
    """Lines describing the scratch filesystem, including the trap that bit us.

    `df` reports free space on the filesystem. A user quota is invisible to it, so a box can
    report 31 GB free and still refuse the harness's next write at 24 GB. If the mount says
    `usrquota` or `grpquota`, say so — that number is the real ceiling and it is not the one
    df prints.
    """
    lines = []
    try:
        st = os.statvfs(root)
        free_gb = st.f_bavail * st.f_frsize / 1024**3
        lines.append(f"scratch    : {root}  ({free_gb:.1f} GiB free per statvfs)")
    except OSError as e:
        lines.append(f"scratch    : {root}  (could not stat: {e})")
        return lines
    try:
        mounts = Path("/proc/mounts").read_text().splitlines()
    except OSError:
        return lines
    best, opts = "", ""
    for ln in mounts:
        parts = ln.split()
        if len(parts) >= 4 and str(root).startswith(parts[1]) and len(parts[1]) > len(best):
            best, opts = parts[1], parts[3]
    if any(q in opts for q in ("usrquota", "grpquota", "prjquota", "quota")):
        lines.append(f"             {best} has a quota ({opts.split(',')[-1]}). The number "
                     f"above is NOT the ceiling —")
        lines.append("             a per-user quota is invisible to statvfs. Use "
                     "--work-root to move scratch")
        lines.append("             somewhere unquota'd if a long sweep dies with errno 122.")
    return lines


def blame(out: str, err: str) -> str:
    """Who failed: the launcher, the packaged app, or the OS?

    An app-level case makes this distinction load-bearing. "haru-pack refused to run" and
    "the application started and then died" are different facts, and a run under a tiny
    memory limit is SUPPOSED to produce the second. Without the split, a persona that
    stresses the application reads as a launcher defect.

    The launcher prefixes every diagnostic with "haru-pack:", which is what makes this
    cheap. An app traceback has no such prefix.

    Four parties, not two. This function can only distinguish the first two from output, so
    the others are set explicitly by whoever knows:

      launcher  haru-pack reported it. Always a defect unless a case expected it.
      app       the packaged application reported it. Expected when a persona starved it.
      os        the kernel refused before either got a turn — `not_executable` chmods the
                binary to 000, so exec is denied. Calling that "app" would be a lie in the
                direction that hides defects.
      harness   busybody itself broke (CASE-ERROR). Never a statement about haru-pack.
      builder   `haru-pack build` reported it, or should have. The wedge persona attacks a
                declaration rather than a binary, so its findings belong to the build, not
                to the launcher — a config contradiction is fixed in a different file by a
                different person.

    Every non-RAN result carries one. A missing blame surfaces in --analyze as a "?" bucket,
    which is a hole in triage rather than a finding — there were 25 in the 2026-09-10 sweep,
    all from run_exe's OSError path returning early without setting it.
    """
    blob = (out or "") + (err or "")
    if "haru-pack:" in blob:
        return "launcher"
    if any(m in blob for m in TRACEBACK_MARKERS) or blob.strip():
        return "app"
    return "unknown"


def classify(rc, out: str, err: str, timed_out: bool, *, unresolved: bool = False) -> str:
    """Map a process outcome onto the vocabulary.

    `unresolved` distinguishes HUNG from INDETERMINATE, and the difference is what the
    harness is entitled to claim.

    HUNG says "this would never have exited". One process, given its own full timeout, with
    nothing else competing for the machine, is enough to support that. A herd of sixteen
    children sharing one deadline is NOT: a child still working when the clock ran out may
    have been seconds from finishing, and the observer that can tell the difference is the
    stall watchdog, which makes its own claim separately. So a deadline kill inside the herd
    passes `unresolved=True` and gets INDETERMINATE — Jepsen's `:info`, the absence of a
    verdict rather than a bad one.

    CRASHED vs APP-CRASHED is the distinction that makes app-level personas usable. A Nim
    traceback out of the launcher is always a defect. A Python traceback out of the PACKAGED
    APPLICATION, when a case deliberately starved it, is the application declining to run in
    the box it was given — the correct answer, not a bug in haru-pack.

    Measured 2026-09-10: numpy under a 768 MB address-space ceiling raises during
    `import numpy._core.multiarray`. Calling that CRASHED made a working, calibrated case
    look like a product defect.
    """
    blob = (out or "") + (err or "")
    if timed_out:
        return "INDETERMINATE" if unresolved else "HUNG"
    if any(m in blob for m in TRACEBACK_MARKERS):
        return "CRASHED" if blame(out, err) == "launcher" else "APP-CRASHED"
    if rc == 0:
        return "RAN" if MARKER in out else "SILENT"
    return "REFUSED"


def run_exe(exe: Path, cwd: Path, env=None, timeout: int | None = None, args=(),
            rlimits=None, argv0=None) -> dict:
    """Run a packed binary and classify what happened.

    `rlimits` applies resource limits in the child ({resource.RLIMIT_AS: (soft, hard)}),
    which is how the app-level personas starve an application without touching the host.
    `argv0` overrides argv[0] without renaming the file.

    `timeout` of None means cfg.DEFAULT_TIMEOUT_S, which --timeout sets. It must never reach
    subprocess as None: that is not "the default", it is no ceiling at all, and a hung
    launcher would hang the whole sweep instead of reporting HUNG.
    """
    timeout = cfg.DEFAULT_TIMEOUT_S if timeout is None else timeout
    pre = None
    if rlimits:
        import resource

        def pre():          # noqa: E306 - runs in the child, after fork, before exec
            for what, limits in rlimits.items():
                try:
                    resource.setrlimit(what, limits)
                except (ValueError, OSError):
                    pass

    t0 = time.monotonic()
    try:
        argv = [argv0 or str(exe), *args]
        r = subprocess.run(argv, capture_output=True, text=True, executable=str(exe),
                           timeout=timeout, cwd=cwd, env=env, preexec_fn=pre)
        rc, out, err, to = r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired as e:
        rc, out, err, to = None, (e.stdout or b"").decode("utf8", "replace"), \
            (e.stderr or b"").decode("utf8", "replace"), True
    except (PermissionError, OSError) as e:
        # The OS refused to exec the file at all. That is a refusal by the system, not a
        # haru-pack crash, and it is what "the executable bit got dropped" looks like.
        return {"outcome": "REFUSED", "rc": None, "seconds": round(time.monotonic() - t0, 1),
                "blame": "os", "stdout": "", "stderr": f"{type(e).__name__}: {e}"}
    outcome = classify(rc, out, err, to)
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": blame(out, err) if outcome != "RAN" else "none",
            "stdout": (out or "").strip()[-400:], "stderr": (err or "").strip()[-400:]}


# Variables that make a child process adopt the CALLER's Python environment. busybody runs
# real haru-pack binaries, which run uv, which honours these — so leaving them in place lets
# a chaos case reach back out and modify the environment busybody itself is running from.
#
# This is not hypothetical. The first run of `payload_reforged_with_valid_crcs` rebuilt this
# repository's own .venv against the staged interpreter, leaving .venv/bin/python a dangling
# symlink into a work directory that was then deleted. A chaos harness that damages the
# checkout it is testing is worse than no harness.
_CONTAMINATING = ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP",
                  "UV_PROJECT_ENVIRONMENT", "UV_PYTHON", "UV_CACHE_DIR", "CONDA_PREFIX")


def clean_env(cache: Path, **extra) -> dict:
    """A run in its own cache, isolated from the caller's Python environment."""
    env = dict(os.environ)
    for var in _CONTAMINATING:
        env.pop(var, None)
    env["XDG_CACHE_HOME"] = str(cache)
    env.update({k: v for k, v in extra.items() if v is not None})
    for k, v in extra.items():
        if v is None:
            env.pop(k, None)
    return env


def stage_root(cache: Path) -> Path | None:
    """The staged tree the launcher created under this cache, if any."""
    base = cache / "haru-pack"
    if not base.is_dir():
        return None
    dirs = [d for d in base.iterdir() if d.is_dir() and not d.name.endswith(".tmp")]
    return sorted(dirs)[0] if dirs else None


def warm(exe: Path, work: Path) -> tuple:
    """Run once so a stage exists. Returns (cache, result)."""
    cache = work / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    return cache, run_exe(exe, work, env=clean_env(cache))



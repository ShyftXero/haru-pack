"""Traits from the packed application and the machine it lands on.

    understudy   the packaged application behaving badly
    revenant     an on-disk stage left by an older, different haru-pack
    quotamaster  target storage hostility — noexec, full, read-only, quota'd
    packrat      payload extremes: enormous files, device nodes, absurd file counts

Split out of busybody_traits.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import resource

from busybody_compose import trait

APP_OK = "BUSYBODY_OK"


# ============================================================================== understudy
# The application misbehaves and the launcher must stay honest about it: right exit code,
# no orphans, no invented success.

@trait("understudy_exits_nonzero", "build", "project",
       "The app exits 255. The launcher must propagate it rather than reporting its own "
       "success — a wrapper that eats exit codes breaks every caller downstream.",
       degrades=True, inv="INV-LAUNCH-06")
def _us_rc255(ctx):
    ctx.files["app.py"] = f'print("{APP_OK}")\nimport sys\nsys.exit(255)\n'


@trait("understudy_hard_exits", "build", "project",
       "os._exit(0), skipping every cleanup handler. Anything the launcher relies on the "
       "child doing politely does not happen.",
       conflicts=("understudy_exits_nonzero",), inv="INV-LAUNCH-06")
def _us_hard_exit(ctx):
    ctx.files["app.py"] = f'import os\nprint("{APP_OK}", flush=True)\nos._exit(0)\n'


@trait("understudy_orphans_a_child", "build", "project",
       "Forks a child that outlives the parent and holds stdout open. A launcher that waits "
       "on the pipe rather than the process hangs; one that reaps properly does not.",
       conflicts=("understudy_exits_nonzero", "understudy_hard_exits"),
       inv="INV-LAUNCH-06")
def _us_orphan(ctx):
    ctx.files["app.py"] = (
        "import os, sys, time\n"
        "if os.fork() == 0:\n"
        "    time.sleep(30)\n"
        "    os._exit(0)\n"
        f'print("{APP_OK}", flush=True)\n'
        "sys.exit(0)\n"
    )


@trait("understudy_floods_stdout", "build", "project",
       "8 MB to stdout. A launcher that captures into memory without draining deadlocks on "
       "a full pipe, which looks exactly like a hang in the application.",
       conflicts=("understudy_exits_nonzero", "understudy_hard_exits",
                  "understudy_orphans_a_child"),
       inv="INV-LAUNCH-06")
def _us_flood(ctx):
    ctx.files["app.py"] = (
        "import sys\n"
        f'print("{APP_OK}", flush=True)\n'
        "sys.stdout.write('x' * 8_000_000)\n"
    )


@trait("understudy_writes_into_its_own_stage", "build", "project",
       "The app modifies the staged tree it is running from. The next run's integrity check "
       "must notice, and must not be so strict that a legitimately-writing app is broken.",
       conflicts=("understudy_exits_nonzero", "understudy_hard_exits",
                  "understudy_orphans_a_child", "understudy_floods_stdout"),
       inv="INV-STAGE-01")
def _us_selfwrite(ctx):
    ctx.files["app.py"] = (
        "import pathlib, sys\n"
        f'print("{APP_OK}", flush=True)\n'
        "here = pathlib.Path(__file__).parent\n"
        "try:\n"
        "    (here / 'scribble.txt').write_text('the app was here\\n')\n"
        "except OSError as e:\n"
        "    print('could not write into my own stage:', e)\n"
    )


# ================================================================================= revenant
# State left behind by a different version of haru-pack. Distinct from `squatter`, which
# plants a hostile stage; this plants a PLAUSIBLE one from the past.

@trait("revenant_stage_from_an_older_layout", "run", "cache",
       "A cache entry with an old directory layout and a valid-looking ready marker. The "
       "launcher must decide it is unusable rather than half-adopting it.",
       inv="INV-STAGE-01",
       fires=0.6)
def _rv_old_layout(ctx):
    def plant(work, exe):
        cache = work / "c" / "haru-pack"
        old = cache / "stage-legacy"
        old.mkdir(parents=True, exist_ok=True)
        (old / "READY").write_text("1\n")
        (old / "python").mkdir(exist_ok=True)
        (old / "manifest.toml").write_text('name = "old"\nkind = "script"\n')
    ctx.pre.append(plant)


@trait("revenant_manifest_from_the_future", "run", "cache",
       "A staged manifest declaring a schema version newer than this launcher knows. "
       "Refusing is correct; guessing is how a future format gets silently misread.",
       inv="INV-STAGE-01",
       fires=0.5)
def _rv_future(ctx):
    def plant(work, exe):
        cache = work / "c" / "haru-pack"
        cache.mkdir(parents=True, exist_ok=True)
        (cache / "manifest.toml").write_text(
            'name = "future"\nkind = "script"\nschema = 99\n')
    ctx.pre.append(plant)


@trait("revenant_cache_owned_by_nobody", "run", "cache",
       "A cache directory the current user cannot write. Common on a shared host where root "
       "ran the binary first; the failure must name the directory.",
       conflicts=("quotamaster_readonly_cache",), inv="INV-STAGE-01",
       fires=0.5)
def _rv_foreign_cache(ctx):
    def plant(work, exe):
        cache = work / "c" / "haru-pack"
        cache.mkdir(parents=True, exist_ok=True)
        cache.chmod(0o500)
    ctx.pre_late.append(plant)          # after any trait that plants INTO the cache


# ============================================================================= quotamaster
# Target-side storage hostility. The noexec case is the one that matters: staging writes an
# interpreter and then execs it, so a cache on a noexec mount is a real deployment failure
# that no amount of correct code avoids — it has to be diagnosed.

@trait("quotamaster_readonly_cache", "run", "cache",
       "The cache directory exists and is read-only. Staging cannot proceed and the message "
       "has to say so, naming the path.",
       conflicts=("foreman_no_home", "revenant_cache_owned_by_nobody"),
       inv="INV-STAGE-01")
def _qm_ro_cache(ctx):
    def plant(work, exe):
        cache = work / "c" / "haru-pack"
        cache.mkdir(parents=True, exist_ok=True)
        cache.chmod(0o555)
    ctx.pre_late.append(plant)          # after any trait that plants INTO the cache


@trait("quotamaster_tiny_file_limit", "run", "proc",
       "RLIMIT_NOFILE of 24. Extracting a payload opens files; a launcher that leaks "
       "descriptors dies here and nowhere else.",
       degrades=True, inv="INV-STAGE-01")
def _qm_nofile(ctx):
    ctx.rlimits[resource.RLIMIT_NOFILE] = (24, 24)


@trait("quotamaster_tiny_fsize_limit", "run", "proc",
       "RLIMIT_FSIZE just under the staged interpreter's size. Writes are truncated rather "
       "than refused, so this produces a PARTIAL stage — the case that most needs to be "
       "caught by an integrity check rather than by a crash later.",
       degrades=True, inv="INV-STAGE-01")
def _qm_fsize(ctx):
    ctx.rlimits[resource.RLIMIT_FSIZE] = (8 * 1024 * 1024, 8 * 1024 * 1024)


@trait("quotamaster_noexec_cache", "run", "cache",
       "The cache lives on a noexec mount. Staging writes an interpreter and then execs it, "
       "so this fails at exec with EACCES — a real and common deployment configuration "
       "(/tmp is noexec on hardened hosts) that the diagnostic must name specifically.",
       needs=("docker",), inv="INV-STAGE-01")
def _qm_noexec(ctx):
    # Applied by the docker runner, which mounts the cache noexec. Nothing to do in-process:
    # mount(2) needs privileges we do not have and should not ask for.
    ctx.env["HARU_BUSYBODY_NOEXEC"] = "1"


# ================================================================================= packrat
# Payload extremes. Answers "does it refuse, hang, or hand me a 2 GB binary?"

@trait("packrat_one_enormous_file", "build", "payload",
       "A 600 MB incompressible file in the project. Either the build refuses with a size, "
       "or it produces a binary that size — both defensible, silence is not.",
       degrades=True, inv="INV-PAYLOAD-01",
       fires=0.25)
def _pr_huge(ctx):
    def make(proj):
        with open(proj / "huge.bin", "wb") as fh:
            chunk = os.urandom(1 << 20)
            for _ in range(600):
                fh.write(chunk)
    ctx.post.append(make)


@trait("packrat_many_tiny_files", "build", "payload",
       "40,000 small files. Per-file overhead in the zip and in the integrity manifest "
       "dominates; this is where an O(n^2) walk stops being theoretical.",
       inv="INV-PAYLOAD-01",
       fires=0.35)
def _pr_many(ctx):
    def make(proj):
        d = proj / "many"
        for i in range(200):
            sub = d / f"{i:03d}"
            sub.mkdir(parents=True, exist_ok=True)
            for j in range(200):
                (sub / f"f{j:03d}.txt").write_text(f"{i}:{j}\n")
    ctx.post.append(make)


@trait("packrat_device_nodes_and_fifos", "build", "payload",
       "A fifo in the project. Not a regular file: a builder that opens it to read blocks "
       "forever, which is a hang rather than an error.",
       inv="INV-PAYLOAD-01",
       fires=0.6)
def _pr_fifo(ctx):
    def make(proj):
        try:
            os.mkfifo(proj / "pipe.fifo")
        except (OSError, AttributeError):
            pass
        try:
            (proj / "sock").symlink_to("/dev/null")
        except OSError:
            pass
    ctx.post.append(make)



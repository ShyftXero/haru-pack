"""The trait catalogue: eleven personas' worth of hostility, in composable pieces.

Each trait is one small mutation with a declared phase and layer. Nothing here asserts
anything — expectations belong to the runner, because a trait's effect depends entirely on
what it is stacked with. That is the whole reason for the split.

Personas represented, and what each contributes:

    greenhorn     a developer's first day: wrong paths, wrong flags, output in silly places
    foreman       the environment CI actually provides: no TTY, no HOME, read-only tree
    crosseyed     a foreign --target, so the payload must not contain host objects
    babel         filenames that are legal here and illegal, colliding or unencodable there
    understudy    the packaged application behaving badly
    revenant      an on-disk stage left by an older, different haru-pack
    quotamaster   target storage hostility — noexec, full, read-only, quota'd
    packrat       payload extremes: enormous files, device nodes, absurd file counts
    tourist       the artifact on a platform that is not its own
    auditor       credential-shaped files planted where the payload builder will see them
    archivist     a build that must be byte-reproducible

`archivist`, `auditor` and `crosseyed` also own explicit property-checking cases in
busybody.py: "these two builds are identical" and "no ELF objects in a Windows payload" are
assertions about an artifact, not conditions to survive, so they are not traits. The traits
they contribute here are the parts that compose — the foreign target, the planted secret, the
fixed timestamp.
"""
from __future__ import annotations

import os
import resource
import shutil
import stat

from busybody_compose import trait

APP_OK = "BUSYBODY_OK"


# =============================================================================== greenhorn
# Wrong invocation rather than wrong config — contradictory declarations are `wedge`'s job
# (INV-CHAOS-07). The property here is that every refusal names the fix. A traceback is the
# finding; a clear "no such thing to build, try X" is a pass.

@trait("greenhorn_output_into_missing_dir", "build", "cli",
       "`-o build/out/app` when build/out does not exist. Extremely common, and the "
       "difference between creating the parent and refusing is a decision nobody has "
       "written down.",
       inv="INV-BUILD-01",
       fires=0.7)
def _gh_missing_dir(ctx):
    ctx.cli += ["-o", str(ctx.proj.parent / "no" / "such" / "dir" / "app")]


@trait("greenhorn_output_over_the_input", "build", "cli",
       "`-o` pointing at the script being packed. The build reads the input while writing "
       "the output; truncating the source mid-build would destroy the user's file.",
       inv="INV-BUILD-01",
       fires=0.5)
def _gh_out_over_in(ctx):
    ctx.cli += ["-o", str(ctx.proj / "app.py")]


@trait("greenhorn_tier_easter_egg", "build", "cli",
       "`--tier chonky`. tiers.py defines CHONKY as an alias and nothing tests that the CLI "
       "accepts it, so the joke may not work.",
       conflicts=("greenhorn_bogus_target",),
       fires=0.5)
def _gh_chonky(ctx):
    ctx.cli += ["--tier", "chonky"]
    ctx.tier = ""          # the trait supplies the tier itself


@trait("greenhorn_bogus_target", "build", "cli",
       "`--target win64` — a plausible spelling of something that does not exist. The list "
       "of real targets must appear in the error, or the user has to read the source.",
       inv="INV-BUILD-01",
       fires=0.6)
def _gh_bogus_target(ctx):
    ctx.cli += ["--target", "win64"]
    ctx.runnable = False


@trait("greenhorn_source_is_a_pyc", "build", "cli",
       "Pointed at a .pyc. Recognisably Python to a human, not something that can be packed, "
       "and the refusal has to say which.",
       inv="INV-BUILD-01",
       fires=0.5)
def _gh_pyc(ctx):
    ctx.files["compiled.pyc"] = "\x00\x00\x00\x00not really bytecode"
    ctx.entry = "compiled.pyc"


@trait("greenhorn_symlink_loop_in_project", "build", "project",
       "A symlink cycle in the project. copytree walks it; an unguarded walk never returns.",
       inv="INV-PAYLOAD-01",
       fires=0.4)
def _gh_symlink_loop(ctx):
    def make(proj):
        a, b = proj / "loop_a", proj / "loop_b"
        for p in (a, b):
            shutil.rmtree(p, ignore_errors=True)
            p.unlink(missing_ok=True) if p.is_symlink() else None
        a.symlink_to(b, target_is_directory=True)
        b.symlink_to(a, target_is_directory=True)
    ctx.post.append(make)


# ================================================================================= foreman
# What a CI runner actually hands a build. Individually dull, and that is the point: the
# interesting question is which stack of them produces something other than a clean refusal.

@trait("foreman_no_tty", "run", "proc",
       "No controlling terminal, as under any CI runner. Anything gated on isatty takes the "
       "other branch — including the licence prompt, where a hang is the serious outcome.",
       inv="INV-SECRET-01")
def _fm_no_tty(ctx):
    ctx.stdin_closed = True


@trait("foreman_no_home", "run", "env",
       "HOME unset. uv and Python both derive cache and config locations from it, so an "
       "unguarded default lands somewhere surprising or fails outright.",
       conflicts=("quotamaster_readonly_cache",), inv="INV-STAGE-01")
def _fm_no_home(ctx):
    ctx.env.pop("HOME", None)


@trait("foreman_ci_true", "run", "env",
       "CI=true and TERM=dumb. Libraries change behaviour on these — progress bars, colour, "
       "interactive fallbacks — and a launcher should be indifferent to all of it.")
def _fm_ci(ctx):
    ctx.env.update({"CI": "true", "TERM": "dumb", "NO_COLOR": "1",
                    "PYTHONUNBUFFERED": "1"})


@trait("foreman_hostile_umask", "run", "proc",
       "umask 077. Staged files become owner-only; anything assuming group or world read "
       "breaks, and anything that CREATES world-writable files is a finding in the other "
       "direction.",
       inv="INV-STAGE-01")
def _fm_umask(ctx):
    ctx.pre.append(lambda work, exe: os.umask(0o077))


@trait("foreman_source_date_epoch", "build", "env",
       "SOURCE_DATE_EPOCH set, as reproducible-build CI does. A build that ignores it cannot "
       "produce the same bytes twice, which makes a signed artifact unauditable.",
       inv="INV-BUILD-03")
def _fm_sde(ctx):
    ctx.env["SOURCE_DATE_EPOCH"] = "1700000000"


@trait("foreman_readonly_checkout", "build", "project",
       "The project directory is read-only, as in a CI cache mount. A build that needs to "
       "write next to the source fails here — and it should not need to.",
       inv="INV-BUILD-01")
def _fm_readonly_src(ctx):
    def lock(proj):
        for p in sorted(proj.rglob("*"), reverse=True):
            if p.is_file():
                p.chmod(0o444)
        proj.chmod(0o555)
    ctx.post_late.append(lock)          # after every trait that writes to the project


# =============================================================================== crosseyed
# A foreign --target. The artifact cannot run here, so these set no_run and the pipeline
# switches to static verification of the payload's contents.

@trait("crosseyed_target_windows", "build", "payload",
       "--target windows. The payload must contain PE/wheel content for Windows and no ELF "
       "shared objects from this host. uv's --python-platform cross-download is subtle "
       "enough that a host .so slipping in is a live possibility.",
       conflicts=("crosseyed_target_aarch64", "greenhorn_bogus_target"),
       no_run=True, inv="INV-TIER-03")
def _cx_windows(ctx):
    ctx.cli += ["--target", "windows"]
    ctx.target = "windows"
    ctx.runnable = False


@trait("crosseyed_target_aarch64", "build", "payload",
       "--target linux-aarch64 on an x86-64 host. Every ELF object in the payload must be "
       "EM_AARCH64; an x86-64 interpreter in an ARM payload is a binary that dies on a "
       "Raspberry Pi with an exec format error.",
       conflicts=("crosseyed_target_windows", "greenhorn_bogus_target"),
       no_run=True, inv="INV-TIER-03")
def _cx_aarch64(ctx):
    ctx.cli += ["--target", "linux-aarch64"]
    ctx.target = "linux-aarch64"
    ctx.runnable = False


# =================================================================================== babel
# Filenames that are legal on this filesystem and a problem on the target's, or a problem
# for the zip in between.

@trait("babel_case_colliding_files", "build", "payload",
       "README and readme in one payload. Both survive here and collide on extraction to a "
       "case-insensitive filesystem, where the second silently overwrites the first.",
       inv="INV-PAYLOAD-01",
       fires=0.7)
def _bb_case(ctx):
    ctx.files["README"] = "upper\n"
    ctx.files["readme"] = "lower\n"


@trait("babel_windows_reserved_names", "build", "payload",
       "Files called aux, con and nul. Legal here, impossible to create on Windows, so "
       "extraction fails partway and leaves a half-staged tree.",
       inv="INV-PAYLOAD-01",
       fires=0.6)
def _bb_reserved(ctx):
    for n in ("aux", "con", "nul", "com1"):
        ctx.files[f"{n}.txt"] = f"reserved: {n}\n"
        ctx.files[n] = f"reserved bare: {n}\n"


@trait("babel_very_long_paths", "build", "payload",
       "A path over 260 characters. Fine here; the classic Windows MAX_PATH failure there, "
       "and a staging error that arrives after the download.",
       inv="INV-PAYLOAD-01",
       fires=0.6)
def _bb_long(ctx):
    deep = "/".join("d" * 24 for _ in range(12))
    ctx.files[f"{deep}/leaf.txt"] = "deep\n"


@trait("babel_non_utf8_filename", "build", "payload",
       "A filename that is not valid UTF-8. The zip format has no opinion; the extractor "
       "does, and a launcher that decodes names strictly will refuse its own payload.",
       inv="INV-PAYLOAD-01",
       fires=0.4)
def _bb_nonutf8(ctx):
    def make(proj):
        try:
            (proj / os.fsdecode(b"bad\xff\xfename.txt")).write_text("latin junk\n")
        except OSError:
            pass       # a filesystem that refuses is not a haru-pack finding
    ctx.post.append(make)


@trait("babel_symlink_escaping_the_project", "build", "payload",
       "A symlink pointing outside the project. If it is followed, the payload contains "
       "whatever it aimed at — /etc/passwd is the classic — and if it is packed as a link, "
       "extraction can write outside the stage.",
       inv="INV-PAYLOAD-01",
       fires=0.5)
def _bb_escape(ctx):
    def make(proj):
        link = proj / "outside.txt"
        link.unlink(missing_ok=True)
        try:
            link.symlink_to("/etc/hostname")
        except OSError:
            pass
    ctx.post.append(make)


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


# ================================================================================= auditor
# Credential-shaped files planted where the payload builder will see them. The assertion —
# grep the finished binary — lives in busybody.py; the planting composes.

AUDITOR_SECRETS = {
    ".env": "API_KEY=busybody_secret_dotenv_9a8b7c\n",
    ".envrc": "export TOKEN=busybody_secret_envrc_1f2e3d\n",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nbusybody_secret_idrsa_4c5d6e\n",
    "credentials.json": '{"key": "busybody_secret_credsjson_7a8b9c"}\n',
    "secrets.yaml": "password: busybody_secret_yaml_2b3c4d\n",
    "app.pem": "-----BEGIN CERTIFICATE-----\nbusybody_secret_pem_5e6f7a\n",
    ".aws/credentials": "[default]\naws_secret_access_key = busybody_secret_aws_8b9c0d\n",
    ".npmrc": "//registry.npmjs.org/:_authToken=busybody_secret_npmrc_3d4e5f\n",
}


@trait("auditor_plants_credentials", "build", "project",
       "Every credential shape the ignore list claims to cover, dropped in the project root "
       "as a real build directory accumulates them. The planted values are unique strings, "
       "so the finished binary can be grepped for each one.",
       inv="INV-PAYLOAD-01",
       fires=0.8)
def _au_plant(ctx):
    ctx.files.update(AUDITOR_SECRETS)


@trait("auditor_plants_a_git_history", "build", "project",
       "A .git directory holding a credential in a loose object. Excluding .git is about "
       "size for most people and about secrets for anyone who has committed one.",
       inv="INV-PAYLOAD-01",
       fires=0.7)
def _au_git(ctx):
    ctx.files[".git/config"] = (
        "[remote \"origin\"]\n"
        "\turl = https://user:busybody_secret_giturl_6f7a8b@example.com/x.git\n")
    ctx.files[".git/HEAD"] = "ref: refs/heads/main\n"


@trait("auditor_plants_a_venv_with_a_token", "build", "project",
       "A .venv containing a token, which is what a real working tree looks like. Excluded "
       "for size; the consequence of forgetting is a published credential.",
       inv="INV-PAYLOAD-01",
       fires=0.7)
def _au_venv(ctx):
    ctx.files[".venv/pyvenv.cfg"] = "home = /usr\n"
    ctx.files[".venv/pip.conf"] = (
        "[global]\nindex-url = https://x:busybody_secret_pipconf_9c0d1e@pypi.example/simple\n")


@trait("auditor_plants_a_secret_in_pycache", "build", "project",
       "A credential inside __pycache__. Excluded as build noise rather than as a secret, so "
       "it is the exclusion most likely to be relaxed by someone optimising a payload.",
       inv="INV-PAYLOAD-01",
       fires=0.6)
def _au_pycache(ctx):
    ctx.files["__pycache__/leak.cpython-312.pyc"] = (
        "\x00\x00\x00\x00busybody_secret_pycache_2e3f4a")


# ================================================================================= tourist
# The artifact on a platform that is not its own. The honest scope here is "fails cleanly":
# a real foreign run needs a real foreign machine.

@trait("tourist_runs_a_foreign_binary", "run", "proc",
       "Exec a binary built for another architecture. The kernel refuses with an exec format "
       "error; the requirement is that the harness and the launcher both report that as what "
       "it is rather than as a corrupt payload.",
       needs=("cross-built-artifact",), inv="INV-TIER-03")
def _tr_foreign(ctx):
    ctx.env["HARU_BUSYBODY_FOREIGN"] = "1"


@trait("tourist_wine", "run", "proc",
       "Run the Windows artifact under wine. Not Windows, but it exercises the PE loader and "
       "the overlay's survival of a real foreign toolchain.",
       needs=("wine",), inv="INV-TIER-03")
def _tr_wine(ctx):
    ctx.env["HARU_BUSYBODY_WINE"] = "1"


# ============================================================================== archivist
# Reproducibility. The comparison is a case in busybody.py; what composes is the condition
# under which reproducibility is claimed.

@trait("archivist_shifted_mtimes", "build", "project",
       "Every source file given a different mtime than the previous build would see. A "
       "payload that embeds mtimes is not reproducible, and a signed artifact nobody can "
       "reproduce is one nobody can audit.",
       inv="INV-BUILD-03",
       fires=0.8)
def _ar_mtimes(ctx):
    def touch(proj):
        for i, p in enumerate(sorted(proj.rglob("*"))):
            if p.is_file():
                os.utime(p, (1600000000 + i * 7, 1600000000 + i * 7))
    ctx.post.append(touch)


@trait("archivist_odd_permissions", "build", "project",
       "Mixed permission bits across the project. The payload must normalise them or two "
       "checkouts of one commit produce different binaries.",
       inv="INV-BUILD-03",
       fires=0.7)
def _ar_perms(ctx):
    def chmods(proj):
        modes = (0o644, 0o600, 0o755, 0o444)
        for i, p in enumerate(sorted(proj.rglob("*"))):
            if p.is_file():
                try:
                    p.chmod(modes[i % len(modes)] | stat.S_IRUSR)
                except OSError:
                    pass
    ctx.post.append(chmods)

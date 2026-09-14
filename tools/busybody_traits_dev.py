"""Traits from the people and machines that BUILD a package.

    greenhorn   a developer's first day: wrong paths, wrong flags, output in silly places
    foreman     the environment CI actually provides: no TTY, no HOME, read-only tree
    crosseyed   a foreign --target, so the payload must not contain host objects
    babel       filenames legal here and illegal, colliding or unencodable there

Nothing here asserts anything — expectations belong to the runner, because a trait's effect
depends entirely on what it is stacked with.

Split out of busybody_traits.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import os
import shutil

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



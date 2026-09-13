"""trojan — the project you were asked to package is the attacker.

The hostile programs themselves live in busybody_hostile*; these are the cases that run
them and read what they managed to do. Everything they do is inert: capability is proven by
touching a marker, never by causing harm.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import busybody_config as cfg  # noqa: E402

from busybody_compose_run import _payload_members  # noqa: E402
from busybody_runner import TRACEBACK_MARKERS  # noqa: E402

import io
import re
import shutil
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
from busybody_wedge import _build  # noqa: E402,F401

# ================================================================ trojan
#
# The persona whose attacker is the INPUT. Everything else in this file attacks a finished
# binary or the environment around a build; `trojan` is the source tree handed to
# `haru-pack build`, written by someone who is not on your side.
#
# The hostile programs and their detectors live in `tools/busybody_hostile.py` — one file
# an auditor can read end to end — and the safety rules they obey are stated at the top of
# it. The `@case` registrations stay here beside every other persona, because cases are
# plain Python functions and greppability is the reason.


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _unwound(log: str) -> bool:
    """Did a raw stdlib traceback reach the operator?

    `classify()` matches TRACEBACK_MARKERS against raw text, which is right for a packed
    binary's output and wrong for `haru-pack build`: the CLI renders exceptions through
    rich, which writes the header as `\\x1b[1mTraceback \\x1b[0m\\x1b[1;2m(most recent call
    last)\\x1b[0m` — bold even under NO_COLOR — so the marker is never contiguous. Three
    trojan cases were scored REFUSED while printing forty lines of `shutil.py` frames and
    build-host paths at the operator.

    Deliberately local to this persona rather than folded into `classify()`. Changing the
    shared classifier would silently re-score every other persona's history, and that is a
    decision with a before-and-after to measure, not a drive-by.
    """
    return any(m in _ANSI.sub("", log) for m in TRACEBACK_MARKERS)


def _artifact_scanner(exe: Path, blob: bytes):
    """Return f(needles) -> {needle: [where]}, over the binary AND its decompressed payload.

    Grepping the finished binary is not the strong check it reads as. Payload members are
    DEFLATE'd, so a secret inside a packed file is simply not present in the exe's bytes:
    the trojan persona's second shakedown run reported CONTAINED for a private key that a
    hand test had already proved `copytree` writes into the payload.

    A leak through the manifest, a Nim literal or a warmed uv cache IS visible in the raw
    bytes — that is why `auditor` grepped them in the first place — so this does both, in
    one pass over the archive, and says which surface each hit came from.
    """
    def scan(needles) -> dict:
        want = [(n, n.encode() if isinstance(n, str) else n) for n in needles]
        hits = {n: [] for n, _ in want}
        for n, b in want:
            if b in blob:
                hits[n].append("<binary bytes>")
        try:
            info = overlay.verify(exe)
            payload = blob[info["payload_off"]:info["payload_off"] + info["payload_len"]]
            with zipfile.ZipFile(io.BytesIO(payload)) as z:
                for member in z.namelist():
                    if member.endswith("/"):
                        continue
                    with z.open(member) as fh:
                        data = fh.read()
                    for n, b in want:
                        if b in data:
                            hits[n].append(member)
        except Exception:
            # No readable payload is itself reported by the caller; a scanner that raised
            # here would turn "unreadable" into "clean", which is the wrong direction.
            pass
        return hits
    return scan


def _trojan(name: str, work: Path) -> dict:
    """Build one hostile project inside a sandbox and ask its detector what happened."""
    from busybody_hostile import ATTACKS, Evidence, planted_home

    spec = ATTACKS[name]
    home = planted_home(work)
    drop = work / "drop"
    drop.mkdir(parents=True, exist_ok=True)
    proj = work / "gift"
    spec["plant"](proj, home)

    # TMPDIR is redirected into the work directory, so a hostile program that drops a file
    # "in temp" — the realistic choice, and the one it can find without cooperation from
    # this harness — drops it somewhere the reaper deletes. HOME is left alone on purpose:
    # redirecting it hides ~/.choosenim and every case refuses before reaching its attack.
    # clean_env already scrubs the variables that would let a child adopt busybody's own
    # Python environment.
    env = clean_env(work / "tc", TMPDIR=str(drop))

    pre = None
    if spec.get("fsize_mb"):
        import resource

        def pre():          # noqa: E306 - runs in the child, after fork, before exec
            cap = spec["fsize_mb"] * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))
            except (ValueError, OSError):
                pass

    out = work / f"trojan-{name[:28]}"
    haru = shutil.which("haru-pack") or str(cfg.REPO / ".venv" / "bin" / "haru-pack")
    argv = [haru, "build", str(proj), "-o", str(out), "--tier", spec["tier"]]
    t0 = time.monotonic()
    timed_out = False
    try:
        r = subprocess.run(argv, capture_output=True, text=True, env=env,
                           timeout=spec["timeout"], preexec_fn=pre)
        rc, log = r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        rc, timed_out = None, True
        log = (e.stdout or b"").decode("utf8", "replace") + \
              (e.stderr or b"").decode("utf8", "replace")

    blob, members = b"", []
    if out.exists():
        blob = out.read_bytes()
        try:
            members = _payload_members(out)
        except Exception as e:
            # A binary whose payload cannot be read is itself information, and it must not
            # be reported as a clean build. Detectors that only consult `members` would see
            # an empty list and say CONTAINED.
            return {"outcome": "CASE-ERROR", "rc": rc, "seconds": round(time.monotonic() - t0, 1),
                    "blame": "harness", "stdout": "",
                    "stderr": f"built, but its payload could not be read: {type(e).__name__}: {e}"}

    # The wedge persona's hardest-won lesson, applied here: a build that refused without
    # mentioning any part of the hostile construct did not reach it, so calling that a pass
    # would be the same mistake as taking a CRC32 rejection for tamper detection. The first
    # shakedown run of this persona hit it four times — choosenim, because HOME had been
    # redirected — and every one of them read as a clean REFUSED until this check existed.
    #
    # It runs BEFORE the traceback check below, and the order cost a run to learn: three
    # cases were filed as CRASHED caused by their own attack when what actually happened was
    # an unpinned-interpreter refusal that rendered a traceback on the way out. "Did it
    # reach the attack?" has to be answered before "how did it fail?".
    unwound = _unwound(log)
    if not out.exists() and not timed_out and \
            not any(n.lower() in log.lower() for n in spec["names"]):
        note = (" It DID unwind rather than refusing cleanly, which is worth a look on its "
                "own — but not under this case's name.") if unwound else ""
        return {"outcome": "REFUSED-UNRELATED", "rc": rc,
                "seconds": round(time.monotonic() - t0, 1), "blame": "builder", "stdout": "",
                "stderr": (f"build refused without mentioning any of {spec['names']}, so the "
                           f"attack was never reached.{note} "
                           f"{_ANSI.sub('', log).strip()[-300:]}")}

    ev = Evidence(name=name, proj=proj, home=home, drop=drop, exe=out, rc=rc or 0, log=log,
                  timed_out=timed_out, members=members, blob=blob,
                  scan=_artifact_scanner(out, blob))
    outcome, msg = spec["verdict"](ev)

    # A refusal that unwinds is not a refusal: the operator asked to package a directory and
    # got stdlib frames and absolute build-host paths. But this is a FALLBACK, not a gate in
    # front of the detector, and that distinction is the whole finding in two cases. `uv sync`
    # failing because the packed project redirected the index to a discard port IS the attack
    # landing; it also unwinds. Scored as CRASHED first, both cases reported a traceback and
    # buried the ESCAPED underneath it.
    if outcome in ("CONTAINED", "REFUSED") and not out.exists() and unwound:
        outcome = "CRASHED"
        msg = ("the build did not refuse — it unwound. A raw traceback with build-host paths "
               f"reached the operator: {_ANSI.sub('', log).strip()[-400:]}")

    good = outcome in ("CONTAINED", "SANCTIONED")
    return {"outcome": outcome, "rc": rc, "seconds": round(time.monotonic() - t0, 1),
            "blame": "none" if good else "builder",
            "stdout": f"{MARKER} {msg}" if good else "", "stderr": "" if good else msg}


@case("trojan", ("CONTAINED", "REFUSED"),
      "A project tree containing symlinks whose own names are innocuous — assets/logo.png, "
      "README.md — pointing at credential files OUTSIDE the project. `_IGNORE` is "
      "`shutil.ignore_patterns`, which matches the name of the entry being copied and never "
      "the target of a link, and `copytree(symlinks=False)` dereferences. INV-PAYLOAD-01 is "
      "satisfied to the letter and defeated in substance.",
      inv="INV-TRUST-06",
      remedy="The finding names the exact token and the link that carried it. Decide what a "
             "symlink leaving the source tree means: refuse the build, skip the link, or "
             "copy it as a link. Following it into the payload is the one answer that ships "
             "the operator's key inside a signed binary.", per_fixture=False)
def a_symlink_walks_a_private_key_into_the_payload(exe: Path, work: Path) -> dict:
    return _trojan("a_symlink_walks_a_private_key_into_the_payload", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "A directory symlink pointing at its own project root. `copytree` follows it and "
      "recurses until the path length stops it (measured: depth 40, then `shutil.Error`). "
      "Nothing is stolen here; the question is whether the operator gets a refusal that "
      "names the loop or a stdlib traceback full of build-host paths.",
      inv="INV-TRUST-07",
      remedy="If this reports CRASHED, wrap the payload copy and turn the OSError into a "
             "diagnostic that names the offending path.", per_fixture=False)
def a_symlink_loop_makes_the_payload_infinite(exe: Path, work: Path) -> dict:
    return _trojan("a_symlink_loop_makes_the_payload_infinite", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "A symlink to a path that does not exist. Verified 2026-09-11: `copytree` raises "
      "`shutil.Error` listing the broken entry. A repository with a broken link in it is "
      "more often sloppiness than malice, which is exactly why the build must handle it "
      "like any other bad input rather than by unwinding.",
      inv="INV-TRUST-07",
      remedy="Same fix as the loop case: one handler around the payload copy.",
      per_fixture=False)
def a_broken_symlink_stops_the_build(exe: Path, work: Path) -> dict:
    return _trojan("a_broken_symlink_stops_the_build", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "A symlink named data.bin pointing at /dev/zero. Dereferenced, it is an infinite "
      "file, and the payload builder reads it into the operator's disk. The build child "
      "runs under RLIMIT_FSIZE so the case cannot fill the disk it is testing on — which is "
      "also the fix being asked for.",
      inv="INV-TRUST-07",
      remedy="Bound the payload copy: refuse non-regular files, or cap the total copied "
             "size and name the file that blew the cap.", per_fixture=False)
def a_character_device_feeds_the_payload_forever(exe: Path, work: Path) -> dict:
    return _trojan("a_character_device_feeds_the_payload_forever", work)


@case("trojan", ("CONTAINED", "REFUSED", "SANCTIONED"),
      "A packed project whose own haru_pack.toml carries a [[bundle]] step. The argv runs "
      "at build time, on the build host, with the operator's full environment — and "
      "`build.py` runs the steps in a bare loop with no line printed first. Cloning a "
      "repository and running `haru-pack build .` is therefore code execution by that "
      "repository's author. The verdict turns on whether the log NAMED the argv before "
      "running it, not on whether it ran: naming it is what makes the capability consensual.",
      inv="INV-TRUST-01",
      remedy="Print every [[bundle]] argv before executing it, and gate project-supplied "
             "steps behind an explicit flag when the declaration came from the packed tree "
             "rather than from the operator.",
      serial=True, per_fixture=False)
def a_bundle_step_runs_unannounced_on_the_build_host(exe: Path, work: Path) -> dict:
    return _trojan("a_bundle_step_runs_unannounced_on_the_build_host", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "A project with no haru_pack.toml at all — only a pyproject.toml whose build-system "
      "names an in-tree backend via `backend-path`. At --thick, `uv sync --project` "
      "installs the project, which imports and calls that backend. This is the standard "
      "sdist supply-chain vector pointed at a build host that believes it is only copying "
      "files, and no amount of auditing haru-pack's own config format would see it.",
      inv="INV-TRUST-02",
      remedy="Decide whether `haru-pack build` on an untrusted tree is a supported "
             "operation. If it is, dependency staging needs `--no-build`/wheel-only "
             "resolution or a sandbox; if it is not, say so in the docs and refuse to "
             "resolve a project whose build backend is in-tree.",
      serial=True, per_fixture=False)
def a_build_backend_owns_the_build_host(exe: Path, work: Path) -> dict:
    return _trojan("a_build_backend_owns_the_build_host", work)


@case("trojan", ("CONTAINED", "REFUSED", "SANCTIONED"),
      "A packed project declaring [[post_install]]. That argv is carried in the payload "
      "manifest and executed BY THE LAUNCHER on the customer's machine, on first run, under "
      "whatever signature the binary carries. --thick warns about it; this case runs at the "
      "tier that actually uses post_install, and asks whether the operator is told there "
      "too.",
      inv="INV-TRUST-03",
      remedy="Name every post_install step in the build log at every tier, with the word "
             "'customer' in the sentence. An operator who signs a binary is vouching for "
             "that argv.", per_fixture=False)
def a_post_install_step_ships_code_to_the_customer(exe: Path, work: Path) -> dict:
    return _trojan("a_post_install_step_ships_code_to_the_customer", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "Files whose names contain backslashes — one legal filename here, three levels of "
      "escape on Windows. `build_payload_zip` stores names with `as_posix()`, and "
      "THREAT_MODEL B7 records target-side extraction as [R], relayed and unverified. This "
      "is the half of B7 that CAN be checked on this machine: a payload can be read without "
      "being run.",
      inv="INV-SUPPLY-03",
      remedy="Normalise or refuse member names that are ambiguous across separator "
             "conventions, at zip time, on the host — the target extractor is the one "
             "component this project cannot test.", per_fixture=False)
def a_filename_escapes_the_payload_on_windows(exe: Path, work: Path) -> dict:
    return _trojan("a_filename_escapes_the_payload_on_windows", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "A project declaring `app_subdir = \".\"` and shipping its own manifest.toml and "
      "vendor/uv. `validate_manifest` rejects '..', absolute paths and drive letters — the "
      "wedge persona's first finding — and '.' is none of those. It puts the project tree "
      "at the payload root, where the launcher's control files live.",
      inv="INV-TRUST-04",
      remedy="Reject an app_subdir that resolves to the payload root, or assemble the "
             "payload so that control files are written after, and cannot be displaced by, "
             "the application tree.", per_fixture=False)
def the_project_supplies_the_payloads_control_files(exe: Path, work: Path) -> dict:
    return _trojan("the_project_supplies_the_payloads_control_files", work)


@case("trojan", ("CONTAINED", "REFUSED"),
      "A packed project whose own pyproject.toml and uv.toml set index-url. If uv honours "
      "them, the PROJECT decides which index the wheels inside the operator's signed "
      "artifact came from — dependency substitution with the vendor's signature on the end "
      "of it. The redirect points at 127.0.0.1:9 (discard), so nothing leaves the machine "
      "and a build that tries to reach it says so in the log.",
      inv="INV-TRUST-05",
      remedy="First surface uv's stderr: `warm_cache_and_lock` raises CalledProcessError "
             "with the output captured and discarded, so this case currently cannot tell "
             "'uv honoured the project's index' from 'uv failed for some other reason'. "
             "Then pass the operator's resolved index configuration explicitly to every uv "
             "invocation (`--index-url`/`--no-config`) so a file in the packed tree cannot "
             "choose the source of the bytes that get signed.",
      serial=True, per_fixture=False)
def the_project_chooses_where_its_dependencies_come_from(exe: Path, work: Path) -> dict:
    return _trojan("the_project_chooses_where_its_dependencies_come_from", work)



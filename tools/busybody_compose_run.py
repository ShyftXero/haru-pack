"""Composition: build and run one STACK of traits, then read the artifact statically.

A persona that runs alone asks a closed question. Stacking asks what happens when two
hostilities meet, which is where the interesting answers are.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import busybody_config as cfg  # noqa: E402

from busybody_compose import TRAITS  # noqa: E402

import dataclasses
import io
import shutil
import subprocess
import sys
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
from busybody_compose import BuildCtx, RunCtx, realize  # noqa: E402,F401

# ======================================================= composition: stacking the personas

# A persona that runs alone is an integration test in a costume. The question chaos
# engineering asks is which COMBINATION of individually-survivable conditions is not
# survivable — and no amount of running them one at a time will answer it.
#
# The pass condition for a composed run is deliberately weak, because nobody has reasoned
# about combination 7,431 of 10,000:
#
#     RAN / REFUSED / APP-CRASHED     acceptable
#     CRASHED / HUNG / SILENT         never acceptable
#
# That is the existing FATAL set. Composition needs no new vocabulary, only a weaker
# expectation. "haru-pack refuses intelligibly under any stack of hostile conditions" is a
# property worth having. "haru-pack always works" is not, and asserting it would be exactly
# the sort of overclaim INVARIANTS.md exists to catch.

COMPOSED_APP = f"""# /// script
# requires-python = "==3.12.*"
# ///
print("{MARKER}", "composed fixture ran")
"""


def _payload_members(exe: Path) -> list:
    """(name, first 4 bytes) for every payload member, without staging anything.

    Static inspection is what makes the cross-target checks possible at all: a Windows
    payload cannot be executed here, but it can be read.
    """
    info = overlay.verify(exe)
    data = exe.read_bytes()
    blob = data[info["payload_off"]:info["payload_off"] + info["payload_len"]]
    out = []
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        for n in z.namelist():
            if n.endswith("/"):
                continue
            with z.open(n) as fh:
                out.append((n, fh.read(20)))
    return out


ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
# e_machine values from the ELF header, little-endian, at offset 18.
EM = {0x3E: "x86-64", 0xB7: "aarch64", 0x28: "arm", 0xF3: "riscv64", 0x03: "i386"}


def _elf_machine(head: bytes) -> str:
    if not head.startswith(ELF_MAGIC) or len(head) < 20:
        return ""
    return EM.get(head[18] | (head[19] << 8), f"unknown(0x{head[18]:02x})")


def _build_composed(ctx, work: Path) -> tuple:
    """Materialise a BuildCtx into a real project and build it. Returns (rc, out, err, exe)."""
    ctx.proj.mkdir(parents=True, exist_ok=True)
    (ctx.proj / "app.py").write_text(COMPOSED_APP)
    for rel, body in ctx.files.items():
        f = ctx.proj / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    if ctx.decl:
        lines = []
        for k, v in ctx.decl.items():
            lines.append(f"{k} = {v!r}" if isinstance(v, str) else f"{k} = {v}")
        (ctx.proj / "haru_pack.toml").write_text("\n".join(lines) + "\n")
    for fn in [*ctx.post, *ctx.post_late]:
        fn(ctx.proj)

    out = work / ctx.out_name
    args = ["--tier", ctx.tier] if ctx.tier else []
    haru = shutil.which("haru-pack") or str(cfg.REPO / ".venv" / "bin" / "haru-pack")
    env = {**clean_env(work / "bc"), **ctx.env}
    entry = ctx.proj / ctx.entry
    r = subprocess.run([haru, "build", str(entry), "-o", str(out), *args, *ctx.cli],
                       capture_output=True, text=True, timeout=2400, env=env)
    return r.returncode, r.stdout or "", r.stderr or "", out


def _static_verdict(ctx, exe: Path) -> dict:
    """For a foreign target: read the payload instead of running it."""
    if not exe.exists():
        return {"outcome": "REFUSED", "rc": 1, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": "no artifact produced"}
    try:
        members = _payload_members(exe)
    except Exception as e:
        return {"outcome": "CRASHED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"payload unreadable: {type(e).__name__}: {e}"}

    # Magic, not filenames. The first draft matched any path containing "manylinux", which
    # flagged pip's vendored `_manylinux.py` — the platform-DETECTION module, pure Python
    # source, not a wheel. Caught by the compose-1 baseline on 2026-09-10. A binary object is
    # identified by its bytes; a wheel only by an actual `.whl` name.
    def _is_wheel(n: str) -> bool:
        return n.endswith(".whl")

    problems = []
    if ctx.target == "windows":
        elves = [n for n, h in members if h.startswith(ELF_MAGIC)]
        if elves:
            problems.append(f"{len(elves)} ELF object(s) in a Windows payload, e.g. "
                            f"{elves[:3]}")
        linux_wheels = [n for n, _ in members if _is_wheel(n)
                        and ("manylinux" in n or "linux_x86_64" in n)]
        if linux_wheels:
            problems.append(f"linux wheel(s) in a Windows payload: {linux_wheels[:3]}")
    elif ctx.target == "linux-aarch64":
        wrong = [(n, m) for n, h in members if (m := _elf_machine(h))
                 and m not in ("aarch64", "arm")]
        if wrong:
            problems.append(f"{len(wrong)} non-ARM ELF object(s) in an aarch64 payload, "
                            f"e.g. {wrong[:3]}")
        x86_wheels = [n for n, _ in members if _is_wheel(n)
                      and ("x86_64" in n or "amd64" in n)]
        if x86_wheels:
            problems.append(f"x86 wheel(s) in an aarch64 payload: {x86_wheels[:3]}")

    if problems:
        # Built cleanly and shipped the wrong architecture. The binary would fail on the
        # target it was explicitly built for, which is the same shape as SILENT-WEDGE:
        # a quiet success that produces a broken artifact.
        return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": " | ".join(problems)[:400]}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} payload matches target {ctx.target}, "
                      f"{len(members)} member(s) inspected", "stderr": ""}


def _show(v) -> str:
    """A value rendered so that CHANGING it changes the string. Not a hash — readable."""
    if callable(v):
        return f"<fn {getattr(v, '__name__', '?')}>"
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_show(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(f"{k}:{_show(x)}" for k, x in sorted(v.items())) + "}"
    return repr(v)


def _snapshot(ctx) -> str:
    """The whole of a trait context, as a comparable string.

    This is the INJECTION POINT for a composed run. Every trait in this catalogue acts by
    mutating the context it is handed — `ctx.cli += [...]`, `ctx.files[...] = ...`,
    `ctx.env[...] = ...`, appending to `ctx.post` — and none touches the filesystem directly
    inside its own body. So "did this trait's mutation land?" is answerable exactly, by
    comparing the context before and after, with no per-trait bookkeeping.
    """
    return "|".join(f"{f.name}={_show(getattr(ctx, f.name))}"
                    for f in dataclasses.fields(ctx))


def _apply_traits(names, ctx) -> list:
    """Run each trait against `ctx`. Returns the names that changed NOTHING.

    A trait that fires and leaves the injection point untouched is a fault that was
    swallowed before it reached the target — and the outcome it produces is indistinguishable
    from "the system absorbed the fault correctly", which is the specific confusion this
    exists to remove. AWS FIS spends one of its five stop-condition alarms on the same
    distinction.

    The result is a finding about the HARNESS, never about haru-pack. See
    `_stack_record`/`inert`.
    """
    inert = []
    for n in names:
        before = _snapshot(ctx)
        TRAITS[n]["fn"](ctx)
        if _snapshot(ctx) == before:
            inert.append(n)
    return inert


def run_stack(fixture_exe: Path, work: Path, combo: tuple, seed: int,
              run_index: int, force: bool = False, golden: bool = False) -> dict:
    """Run one stack of traits. The single code path for every composed run.

    `golden` marks the un-perturbed control: an empty stack, run through this exact path, so
    the baseline is produced by the same machinery as everything it is the baseline FOR. A
    control built beside the pipeline rather than through it measures the wrong thing.
    """
    fired = realize(combo, seed, run_index, force=force)
    skipped = [n for n in fired if TRAITS[n]["needs"] and not _have(TRAITS[n]["needs"])]
    fired = tuple(n for n in fired if n not in skipped)

    build_traits = [n for n in fired if TRAITS[n]["phase"] == "build"]
    run_traits = [n for n in fired if TRAITS[n]["phase"] == "run"]

    meta = {"selected": list(combo), "fired": list(fired), "skipped": skipped,
            "seed": seed, "run_index": run_index, "golden": golden,
            "layers": sorted({TRAITS[n]["layer"] for n in fired})}
    inert: list = []

    exe, build_note = fixture_exe, ""
    bctx = None
    if build_traits:
        bctx = BuildCtx(proj=work / "proj")
        inert += _apply_traits(build_traits, bctx)
        rc, so, se, built = _build_composed(bctx, work)
        build_note = (so + se).strip()[-300:]
        if rc != 0 or not built.exists():
            # A refusal at build time is a fine outcome for a hostile stack, provided it is
            # a refusal and not a traceback.
            outcome = "CRASHED" if any(m in (so + se) for m in TRAITS_TRACEBACKS) \
                else "REFUSED"
            return {**meta, "inert": inert, "outcome": outcome, "rc": rc, "seconds": 0,
                    "blame": "builder", "stdout": "", "stderr": build_note}
        exe = built
        if not bctx.runnable:
            return {**meta, "inert": inert, **_static_verdict(bctx, exe),
                    "build_note": build_note}

    rctx = RunCtx(env=clean_env(work / "c"), cwd=work)
    inert += _apply_traits(run_traits, rctx)
    for fn in [*rctx.pre, *rctx.pre_late]:
        fn(work, exe)

    degrades = any(TRAITS[n]["degrades"] for n in fired)
    r = run_exe(exe, rctx.cwd or work, env=rctx.env, timeout=rctx.timeout,
                args=rctx.args, rlimits=rctx.rlimits or None, argv0=rctx.argv0)
    if degrades and r["outcome"] == "CRASHED" and r.get("blame") == "app":
        # A trait that declared it can starve the application got what it asked for.
        r["outcome"] = "APP-CRASHED"
    return {**meta, "inert": inert, **r, "build_note": build_note}


# Markers that mean the BUILD produced a traceback rather than a diagnostic. Separate from
# TRACEBACK_MARKERS because a build is Python and a launcher is Nim, and the Python ones
# would false-positive on a launcher's own error text.
TRAITS_TRACEBACKS = ("Traceback (most recent call last)", "Error: unhandled exception")


def _have(needs: tuple) -> bool:
    for n in needs:
        if n == "docker":
            if not shutil.which("docker"):
                return False
        elif n == "wine":
            if not shutil.which("wine"):
                return False
        elif n == "cross-built-artifact":
            return False        # supplied by the tourist cases, not by a plain stack
    return True



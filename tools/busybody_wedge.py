"""The wedge persona's apparatus: build a project with a hostile declaration, then look.

A finding here is never "config was weird". Each case names the artifact property it
expected to be damaged, so the finding is "config was weird AND the resulting binary has
this specific defect" (INV-CHAOS-07).

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import busybody_config as cfg  # noqa: E402

from busybody_fixtures import APP  # noqa: E402

import shutil
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

# ---------------------------------------------------------------- wedge: hostile config

# A "wedge" is a configuration where two directives cannot both be honoured. Every other
# persona attacks a binary that was already built; this one attacks the DECLARATION, and it
# is a different class of bug — a wedge that builds cleanly ships an artifact whose
# behaviour nobody predicted from reading the config.
#
# Three acceptable answers, and one that is not:
#
#   REFUSED       the build stopped and the message named BOTH sides of the contradiction.
#                 Best outcome: the wedge cannot reach a customer.
#   WARNED        it built, and said what it had to override to do so. Acceptable when one
#                 side has documented precedence.
#   RAN           it built AND the predicted artifact damage did not occur, because the
#                 wedge was not actually a contradiction. The case is wrong, not the tool.
#   SILENT-WEDGE  it built, said nothing, and the artifact carries the damage. A FINDING.
#
# The last one is why this persona exists. Each case names the artifact property it expects
# to be damaged, so a finding is not "config was weird" but "config was weird AND here is
# the resulting binary's specific defect".

WEDGE_HINTS = ("warning", "conflict", "contradict", "ignored", "overrid", "precedence",
               "but ", "instead of", "cannot", "refus", "expired", "excluded")


def _wedge_project(work: Path, decl: str, app: str = "", extra: dict | None = None) -> Path:
    """A minimal project with a hostile haru_pack.toml. Returns the project directory."""
    proj = work / "proj"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(app or APP)
    (proj / "haru_pack.toml").write_text(decl)
    for name, body in (extra or {}).items():
        f = proj / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    return proj


def _build(proj: Path, out: Path, *args, timeout: int = 900) -> tuple:
    haru = shutil.which("haru-pack") or str(cfg.REPO / ".venv" / "bin" / "haru-pack")
    r = subprocess.run([haru, "build", str(proj), "-o", str(out), *args],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def _wedge(work: Path, decl: str, *, sides: tuple, damage, build_args=(),
           app: str = "", extra: dict | None = None, target: str = "") -> dict:
    """Build a wedged project and classify what haru-pack did about it.

    `sides`  the two halves of the contradiction, as substrings that a good diagnostic would
             mention. A message that names only one half is not much better than silence:
             it tells you what happened without telling you what it collided with.
    `damage` callable(exe) -> str. Runs the artifact and returns a description of the
             predicted damage, or "" if the artifact is actually fine. Only consulted when
             the build succeeded quietly.
    `target` build this path INSIDE the project instead of the project directory. The
             declaration directory is `project if project.is_dir() else project.parent`, so
             pointing at `app.py` still reads a sibling `pyproject.toml` for its
             `[tool.haru-pack]` table while discovery treats the target as a PEP 723
             script — which is the only way to exercise the pyproject home without also
             owing discovery a `[project.scripts]` entry or a `__main__.py`, and therefore
             without a case about config precedence failing for a reason about discovery.
    """
    proj = _wedge_project(work, decl, app=app, extra=extra)
    out = work / "wedged"
    rc, so, se = _build(proj / target if target else proj, out, *build_args)
    blob = (so + se)
    low = blob.lower()

    if rc != 0 or not out.exists():
        named = [x for x in sides if x.lower() in low]
        if not named:
            # It refused, but for something other than the wedge — so this case did not
            # actually exercise its contradiction, and calling it a pass would be the same
            # mistake `payload_edited_and_footer_recomputed` made when it took a CRC32
            # rejection as proof of tamper detection. The case is what needs fixing here,
            # not necessarily the product.
            return {"outcome": "REFUSED-UNRELATED", "rc": rc, "seconds": 0,
                    "blame": "builder", "stdout": "", "stderr": (
                        f"build refused without mentioning either side of {sides}, so the "
                        f"wedge itself was never reached: {blob.strip()[-300:]}")}
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"build refused, naming {len(named)}/{len(sides)} side(s) of the "
                    f"conflict {sides}: {blob.strip()[-300:]}")}

    said = any(h in low for h in WEDGE_HINTS) and any(x.lower() in low for x in sides)
    if said:
        return {"outcome": "WARNED", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": blob.strip()[-300:], "stderr": ""}

    harm = damage(out) if damage else ""
    if harm:
        return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"built with no mention of the conflict {sides}, and the artifact is "
                    f"damaged: {harm}")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} built quietly and the artifact was undamaged", "stderr": ""}


def _run_artifact(exe: Path, work: Path, args=()) -> tuple:
    """Run a wedged artifact once. Returns (outcome, message)."""
    r = run_exe(exe, work, env=clean_env(work / "wc"), timeout=180, args=args)
    return r["outcome"], (r.get("stderr") or r.get("stdout") or "").strip()[:200]



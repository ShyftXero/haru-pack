"""archivist / auditor / crosseyed, as explicit property checks rather than traits.

"These two builds are identical" and "no ELF objects in a Windows payload" are ASSERTIONS
about an artifact, not conditions to survive — so they are cases, not traits. The traits
those personas also contribute are the composable parts (the fixed timestamp, the planted
secret, the foreign target) and live in busybody_traits_*.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_cases_trojan import _artifact_scanner  # noqa: E402
from busybody_compose import TRAITS, BuildCtx  # noqa: E402
from busybody_compose_run import COMPOSED_APP, _build_composed, _static_verdict  # noqa: E402

import hashlib
import io
import re
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
from busybody_compose_run import _elf_machine, _payload_members  # noqa: E402,F401
from busybody_wedge import _build  # noqa: E402,F401

# ------------------------------------------------- archivist / auditor / crosseyed as cases
# These three personas assert a PROPERTY of an artifact rather than surviving a condition,
# so they are cases, not traits. "These two builds are identical" and "no ELF in a Windows
# payload" are not things to endure; they are things to check. The parts of them that DO
# compose — the foreign target, the planted secret, the shifted mtimes — live in
# busybody_traits.py and take part in stacks like everything else.


@case("archivist", ("RAN", "REFUSED"),
      "The same input built twice must produce the same payload bytes. An EV-signed binary "
      "nobody can reproduce is one nobody can audit: there is no way to show that the "
      "signed artifact corresponds to the source it claims to. payload.py writes zip "
      "entries with z.write(), which takes mtime and mode from disk, and nothing honours "
      "SOURCE_DATE_EPOCH — so this is expected to fail until it is fixed.",
      inv="INV-BUILD-03",
      remedy="Normalise the zip: a fixed date_time from SOURCE_DATE_EPOCH (or a constant), "
             "a fixed external_attr, and the already-sorted member order. The payload is "
             "the part that must be stable; the launcher stub is compiled and can differ.",
      per_fixture=False, serial=True)
def two_builds_of_one_input_are_identical(exe: Path, work: Path) -> dict:

    proj = work / "repro"
    proj.mkdir(parents=True, exist_ok=True)
    (proj / "app.py").write_text(COMPOSED_APP)

    digests, sizes, notes = [], [], []
    for i in (1, 2):
        out = work / f"repro-{i}"
        rc, so, se = _build(proj / "app.py", out, "--tier", "thin", timeout=1800)
        if rc != 0 or not out.exists():
            return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                    "stdout": "", "stderr": f"build {i} failed: {(so + se).strip()[-300:]}"}
        info = overlay.verify(out)
        blob = out.read_bytes()[info["payload_off"]:
                                info["payload_off"] + info["payload_len"]]
        digests.append(hashlib.sha256(blob).hexdigest())
        sizes.append(len(blob))
        # Touch nothing between builds: the point is that an unchanged tree is enough.
        notes.append(f"build{i}: {len(blob)}B sha={digests[-1][:16]}")

    if digests[0] == digests[1]:
        return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
                "stdout": f"{MARKER} payload reproducible: {digests[0][:16]}", "stderr": ""}

    diff = _first_zip_difference(work / "repro-1", work / "repro-2")
    return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
            "stdout": "", "stderr": (
                f"two builds of an unchanged tree differ. {' | '.join(notes)}. "
                f"first difference: {diff}")}


def _first_zip_difference(a: Path, b: Path) -> str:
    """Name the first differing member and WHY, so the fix is obvious from the report."""
    mem = []
    for exe in (a, b):
        info = overlay.verify(exe)
        blob = exe.read_bytes()[info["payload_off"]:
                                info["payload_off"] + info["payload_len"]]
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            mem.append({i.filename: i for i in z.infolist()})
    only_a = sorted(set(mem[0]) - set(mem[1]))
    only_b = sorted(set(mem[1]) - set(mem[0]))
    if only_a or only_b:
        return f"member sets differ (only in first: {only_a[:3]}, only in second: {only_b[:3]})"
    for name in sorted(mem[0]):
        x, y = mem[0][name], mem[1][name]
        if x.date_time != y.date_time:
            return (f"{name}: date_time {x.date_time} vs {y.date_time} "
                    f"(mtime is being embedded; honour SOURCE_DATE_EPOCH)")
        if x.external_attr != y.external_attr:
            return (f"{name}: external_attr {x.external_attr:#o} vs {y.external_attr:#o} "
                    f"(permission bits are being embedded; normalise them)")
        if x.CRC != y.CRC:
            return f"{name}: content differs (CRC {x.CRC:#x} vs {y.CRC:#x})"
    return "member metadata identical but the compressed bytes differ (compressor state?)"


@case("auditor", ("RAN", "REFUSED"),
      "Every credential shape the ignore list claims to cover is planted in the project, "
      "then the FINISHED BINARY is grepped for each planted value. The existing hygiene "
      "test reads decompressed zip members, which cannot see a secret that leaked by "
      "another route — through the manifest, a Nim string, or a warmed uv cache.",
      inv="INV-PAYLOAD-01",
      remedy="Any hit names the exact planted string; find where that path is copied. A "
             "leak here is published the moment the binary is distributed, and signing it "
             "makes the leak authentic.",
      per_fixture=False, serial=True)
def no_planted_secret_survives_into_the_binary(exe: Path, work: Path) -> dict:
    from busybody_traits import AUDITOR_SECRETS

    ctx = BuildCtx(proj=work / "leaky", tier="thick", out_name="leaky-bin")
    for name in ("auditor_plants_credentials", "auditor_plants_a_git_history",
                 "auditor_plants_a_venv_with_a_token",
                 "auditor_plants_a_secret_in_pycache"):
        TRAITS[name]["fn"](ctx)
    rc, so, se, out = _build_composed(ctx, work)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"build failed: {(so + se).strip()[-300:]}"}

    planted = {}
    for body in ctx.files.values():
        for tok in re.findall(r"busybody_secret_[a-z]+_[0-9a-f]+", body):
            planted[tok] = True
    for body in AUDITOR_SECRETS.values():
        for tok in re.findall(r"busybody_secret_[a-z]+_[0-9a-f]+", body):
            planted[tok] = True

    blob = out.read_bytes()
    # Both surfaces, not just the exe's bytes: a secret that leaked into a PACKED FILE is
    # DEFLATE'd inside the payload zip and does not appear in the binary at all. This case
    # used to grep `blob` alone, which is the right check for a leak via the manifest, a Nim
    # literal or a warmed cache — and blind to the most likely leak of all. Found while
    # building the trojan persona, 2026-09-11.
    hits = _artifact_scanner(out, blob)(tuple(planted))
    leaked = {k: v for k, v in hits.items() if v}
    if leaked:
        where = "; ".join(f"{k} in {v}" for k, v in leaked.items())
        return {"outcome": "SILENT-WEDGE", "rc": 0, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": (
                    f"{len(leaked)} of {len(planted)} planted secret(s) are present in the "
                    f"finished artifact: {where}")}
    return {"outcome": "RAN", "rc": 0, "seconds": 0, "blame": "none",
            "stdout": f"{MARKER} none of {len(planted)} planted secret(s) reached the "
                      f"binary ({len(blob) / 1e6:.0f}MB scanned)", "stderr": ""}


def _crosseyed(work: Path, trait_name: str, target: str) -> dict:
    ctx = BuildCtx(proj=work / f"cross-{target}", tier="thick",
                   out_name=f"cross-{target}")
    TRAITS[trait_name]["fn"](ctx)
    rc, so, se, out = _build_composed(ctx, work)
    if rc != 0 or not out.exists():
        return {"outcome": "REFUSED", "rc": rc, "seconds": 0, "blame": "builder",
                "stdout": "", "stderr": f"cross build failed: {(so + se).strip()[-400:]}"}
    return _static_verdict(ctx, out)


@case("crosseyed", ("RAN", "REFUSED"),
      "A --target windows --thick payload must contain no ELF objects from this host and no "
      "linux wheels. uv's --python-platform cross-download resolves wheels for the target "
      "without executing them, which is the right mechanism and a subtle one: a host .so "
      "reaching the payload produces a Windows binary that fails on first run, after the "
      "build reported success.",
      inv="INV-TIER-03",
      remedy="Inspect the payload members named in the finding. A host object in a foreign "
             "payload means something was staged with the host interpreter instead of "
             "resolved for the target.",
      per_fixture=False, serial=True)
def a_windows_payload_carries_no_linux_objects(exe: Path, work: Path) -> dict:
    return _crosseyed(work, "crosseyed_target_windows", "windows")


@case("crosseyed", ("RAN", "REFUSED"),
      "A --target linux-aarch64 --thick payload must contain only ARM ELF objects. An "
      "x86-64 interpreter in an aarch64 payload is a binary that dies on a Raspberry Pi "
      "with an exec format error — and the Pi is a stated target for this project, so the "
      "failure would land on a real user rather than in CI.",
      inv="INV-TIER-03",
      remedy="Check e_machine on the payload members named in the finding. 0x3E is x86-64; "
             "0xB7 is aarch64.",
      per_fixture=False, serial=True)
def an_aarch64_payload_carries_no_x86_objects(exe: Path, work: Path) -> dict:
    return _crosseyed(work, "crosseyed_target_aarch64", "linux-aarch64")




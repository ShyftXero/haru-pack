"""wedge cases about a DECLARATION that cannot be honoured as written.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_fixtures import APP  # noqa: E402

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
from busybody_wedge import (WEDGE_HINTS, _build, _run_artifact, _wedge,  # noqa: E402,F401
                            _wedge_project)

@case("wedge", ("REFUSED", "WARNED"),
      "The declared entrypoint is a file the payload builder deliberately excludes. "
      "`_SECRET_PATTERNS` drops `secrets.*` so a credentials file cannot be packed by "
      "accident — but the same rule silently removes a file someone named as the "
      "entrypoint. Two correct rules, one artifact, and they disagree.",
      inv="INV-CHAOS-07",
      remedy="Name both sides: the entrypoint that was requested and the ignore rule that "
             "removed it. Refusing is better than shipping a binary with no entrypoint.",
      per_fixture=False)
def entrypoint_is_excluded_by_secret_hygiene(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\nentrypoint = ["secrets.py"]\n',
        sides=("secrets.py", "entrypoint"),
        damage=damage,
        extra={"secrets.py": APP},
    )


@case("wedge", ("REFUSED", "WARNED"),
      "haru_pack.toml pins an interpreter older than the project says it needs. The "
      "declaration beats discovery by design, so the pin wins and the binary ships a "
      "Python the application cannot run on. Nothing about the build looks wrong.",
      inv="INV-CHAOS-07",
      remedy="Compare the declared python against requires-python and say which one lost. "
             "Precedence is fine; silent precedence on an incompatible version is not.",
      per_fixture=False)
def declared_python_is_older_than_the_app_requires(exe: Path, work: Path) -> dict:
    app = ('# a 3.12-only construct: PEP 695 type parameter syntax\n'
           'type Alias = int\n'
           'def f[T](x: T) -> T: return x\n'
           f'print("{MARKER}", f(1))\n')

    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\npython = "3.9"\n',
        sides=("3.9", "python"),
        damage=damage,
        app=app,
        extra={"pyproject.toml": '[project]\nname = "wedged"\n'
                                 'requires-python = ">=3.12"\nversion = "0"\n'},
    )


@case("wedge", ("REFUSED", "WARNED"),
      "`app_subdir` climbs out of the payload with `..`. Every path the launcher resolves "
      "is relative to the payload root, so a subdir that escapes it either writes files "
      "the launcher will never look for, or writes them somewhere it should not.",
      inv="INV-CHAOS-07",
      remedy="Reject an app_subdir that is absolute or contains `..`. This is the same "
             "class as a zip-slip and deserves the same flat refusal.",
      per_fixture=False)
def app_subdir_escapes_the_payload(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\napp_subdir = "../escaped"\n',
        sides=("app_subdir", ".."),
        damage=damage,
    )


@case("wedge", ("REFUSED", "WARNED"),
      "The licence expires before the binary is built. Encryption accepts the policy and "
      "seals it in, producing an artifact that is dead on arrival — it will refuse every "
      "run, forever, and the refusal will look like a licensing bug to whoever receives it.",
      inv="INV-CHAOS-07",
      remedy="An expiry in the past is a typo, not a policy. Refuse at build time, where "
             "the person who can fix it is still watching.",
      per_fixture=False)
def licence_expires_before_it_is_built(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        # REFUSED here is the artifact being dead on arrival, which IS the damage
        return "" if outcome == "RAN" else f"artifact is dead on arrival: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\n\n[encryption]\nenabled = true\n'
        'expires = "2001-01-01"\nembed_secret = true\n',
        sides=("2001", "expire"),
        damage=damage,
        # A secret is required before the expiry is even looked at — refusing without one
        # is a correct guard, and without this the case never reached its own wedge.
        build_args=("--secret", "wedge-test-key"),
    )


@case("wedge", ("REFUSED", "WARNED", "RAN"),
      "`--tier thin` says bundle nothing; the declaration asks to bundle python and uv. "
      "One of them is not happening. Which one, and does the binary's actual size agree "
      "with the tier it claims?",
      inv="INV-CHAOS-07",
      remedy="Tier is the coarse control and should win, but say so. A 60 MB binary from a "
             "`thin` build, or a 6 MB one that claims to bundle Python, is a lie about "
             "what the artifact needs at runtime.",
      per_fixture=False)
def thin_tier_asked_to_bundle_everything(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        # thin must not carry an interpreter. Size is the cheap, robust check.
        mb = out.stat().st_size / 1e6
        if mb > 20:
            return (f"thin-tier artifact is {mb:.0f}MB, so it bundled what thin says it "
                    f"does not; the tier no longer predicts the runtime requirement")
        return ""
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\nbundle = ["python", "uv"]\n',
        sides=("thin", "bundle"),
        damage=damage,
        build_args=("--tier", "thin"),
    )


@case("wedge", ("REFUSED", "WARNED", "RAN"),
      "`cwd_policy` is set to a value that does not exist. The launcher reads it with a "
      "string default, so an unknown value is not an error anywhere — it silently takes "
      "whichever branch the comparison falls through to, and the binary resolves relative "
      "paths differently than the config says it will.",
      inv="INV-CHAOS-07",
      remedy="Validate the enum at build time against the values the launcher actually "
             "implements. A typo'd policy should not be indistinguishable from a chosen one.",
      per_fixture=False)
def cwd_policy_is_not_a_policy(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        if outcome != "RAN":
            return f"artifact does not run: {outcome} {msg}"
        # It ran. The damage is that an invalid enum was accepted in silence — a typo is
        # now indistinguishable from a decision. Report it as a note-level wedge.
        return ("an unknown cwd_policy was accepted without comment, so a typo and a "
                "deliberate choice produce identical builds")
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\ncwd_policy = "sideways"\n',
        sides=("cwd_policy", "sideways"),
        damage=damage,
    )


@case("wedge", ("REFUSED", "WARNED"),
      "A machine-locked binary with no key anywhere. The policy demands a specific host, "
      "`embed_secret` is off, and no secret is supplied — so the artifact can never be "
      "decrypted by anyone, including the person who built it.",
      inv="INV-CHAOS-07",
      remedy="A policy with no reachable key is unusable by construction. Refuse, and name "
             "the missing key rather than the policy.",
      per_fixture=False)
def locked_to_a_machine_with_no_key(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact cannot be decrypted: {outcome} {msg}"
    return _wedge(
        work,
        'name = "wedged"\nkind = "script"\n\n[encryption]\nenabled = true\n'
        'machine = "some-other-host"\nembed_secret = false\n',
        sides=("machine", "secret"),
        damage=damage,
    )


@case("wedge", ("REFUSED", "WARNED", "RAN"),
      "Three names for one artifact: pyproject says one thing, haru_pack.toml another, "
      "`-o` a third. Precedence exists and is documented, but a build that never mentions "
      "the two it discarded leaves the operator to guess which name the manifest carries "
      "— and the manifest name is what the launcher reports about itself.",
      inv="INV-CHAOS-07",
      remedy="`-o` names the FILE; `name` names the artifact in the manifest. If those "
             "differ, say so once — they are different fields and conflating them is how "
             "a binary reports a name nobody recognises.",
      per_fixture=False)
def three_names_for_one_artifact(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        outcome, msg = _run_artifact(out, work)
        return "" if outcome == "RAN" else f"artifact does not run: {outcome} {msg}"
    return _wedge(
        work,
        # The entrypoint is declared so that ENTRYPOINT ambiguity is not what gets
        # refused. The wedge under test is the name, and a case has to isolate its wedge
        # or it measures whichever guard happens to fire first.
        'name = "from-haru-toml"\nkind = "script"\nentrypoint = ["app.py"]\n',
        sides=("from-haru-toml", "wedged"),
        damage=damage,
        extra={"pyproject.toml": '[project]\nname = "from-pyproject"\nversion = "0"\n'},
    )


# The pyproject home, the CLI, and the keys nobody validates.
#
# The eight cases above feed contradictions through `haru_pack.toml`. These seven attack
# the rest of the ladder — `discovery < [tool.haru-pack] in pyproject.toml < haru_pack.toml
# < CLI flags` — which is where an operator actually edits, because it is the file that
# already declares everything else about their project.
#
# Each one reads its answer out of manifest.toml at the payload zip root rather than from
# the build log. The log names no directive at all, so "it built and said nothing" cannot
# be distinguished from "it built and honoured me" without opening the artifact. Those are
# the same bytes the launcher parses at stage time, so what they assert is a property of
# the SHIPPED binary.
#
# Source: docs/BRAINSTORM.md section 1b, 2026-09-11 — lotek asked for an eager-admin

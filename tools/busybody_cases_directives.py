"""wedge cases about two directives that DISAGREE, and about what the manifest records.

Split out of busybody.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from busybody_fixtures import APP  # noqa: E402

import io
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
from busybody_wedge import (WEDGE_HINTS, _build, _run_artifact, _wedge,  # noqa: E402,F401
                            _wedge_project)

# persona and INV-BUILD-07's Assets paragraph was already the oracle for it.

def payload_manifest(exe: Path) -> dict:
    """The manifest.toml out of an artifact's payload, without running the artifact.

    Only valid for an unencrypted payload, which is every case here.
    """
    import tomllib          # own group: stdlib from 3.11, and this file targets newer

    info = overlay.verify(exe)
    at, ln = info["payload_off"], info["payload_len"]
    with zipfile.ZipFile(io.BytesIO(exe.read_bytes()[at:at + ln])) as z:
        return tomllib.loads(z.read("manifest.toml").decode("utf-8"))


def manifest_entrypoint(exe) -> list:
    """The entrypoint argv the artifact records, or [] if there is no artifact."""
    try:
        return list(payload_manifest(exe).get("entrypoint") or []) if exe else []
    except (OSError, KeyError, ValueError):
        return []


PYPROJECT = '[project]\nname = "wedged"\nversion = "0.0.1"\n\n'


@case("wedge", ("REFUSED",),
      "A [tool.haru_pack] table with an UNDERSCORE in pyproject.toml — one character away "
      "from the name haru-pack reads, and the spelling a developer who thinks in Python "
      "identifiers writes first. Refusing is the only safe answer: the alternative is a "
      "binary whose entire configuration was addressed to nobody. This is the calibration "
      "case for the six below it. INV-BUILD-07 guards it explicitly, so it should pass, "
      "and if it does not then nothing else these cases report can be trusted either.",
      inv="INV-BUILD-07",
      remedy="The guard is the `if \"haru-pack\" not in tool and \"haru_pack\" in tool` "
             "branch in build._declarations, and INV-BUILD-07's Red-path names deleting "
             "it. A quiet build here means it is gone: restore it, and check that "
             "test_an_underscored_tool_table_is_refused_not_ignored is still red without "
             "it.",
      per_fixture=False)
def an_underscored_tool_table(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        ep = manifest_entrypoint(out)
        return (f"the table was addressed to nobody and the build said so to nobody: "
                f"artifact entrypoint {ep or 'unreadable'}")
    return _wedge(
        work,
        "# no sidecar: the pyproject table is the whole declaration\n",
        sides=("haru_pack",),
        damage=damage,
        target="app.py",
        extra={"pyproject.toml": PYPROJECT + '[tool.haru_pack]\nentrypoint = "app.py"\n'},
    )


@case("wedge", ("REFUSED", "WARNED"),
      "A directive key misspelled the way this one actually gets misspelled: `entry-point` "
      "for `entrypoint`, inside a correctly-named [tool.haru-pack] table, naming a second "
      "script that exists. Nothing in the ladder validates keys — _declarations merges the "
      "table wholesale and _resolve reads the handful of names it knows with decl.get() — "
      "so the directive rides all the way into a merged dict nobody ever asks about and "
      "the build exits 0. The artifact runs the DISCOVERED entrypoint instead, which is "
      "the developer three months later wondering why a directive did nothing.",
      inv="INV-BUILD-07",
      remedy="Refuse, the way the underscored table is refused and for the same reason: "
             "validate the merged dict's top-level keys in build._declarations against the "
             "set actually read — entrypoint, name, kind, app_subdir, cwd_policy, "
             "verbose_uv, python, encryption, shake, bundle, pre_install, post_install, "
             "uv_run_args, plus sources in Sources.resolve — and name the nearest match: "
             "'unknown directive \"entry-point\"; did you mean \"entrypoint\"?'. "
             "INV-BUILD-07's Statement covers the underscored TABLE and says nothing about "
             "an unknown KEY inside a correctly-named one, so the Statement needs widening "
             "to 'a directive haru-pack does not read is never silently ignored', with a "
             "claiming test per spelling.",
      per_fixture=False)
def a_directive_key_with_a_plausible_typo(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        ep = manifest_entrypoint(out)
        return ("" if ep == ["cli.py"] else
                f"the directive named cli.py and the artifact runs {ep or 'nothing'}")
    return _wedge(
        work,
        "# the typo lives in the pyproject table\n",
        sides=("entry-point", "entrypoint"),
        damage=damage,
        target="app.py",
        extra={"pyproject.toml": PYPROJECT + '[tool.haru-pack]\nentry-point = "cli.py"\n',
               "cli.py": APP},
    )


@case("wedge", ("RAN", "WARNED"),
      "The two directive homes disagree: [tool.haru-pack] in pyproject.toml names one "
      "entrypoint and a haru_pack.toml sidecar beside it names another, which is the "
      "ordinary state of a tree someone is mid-way through moving. The documented ladder "
      "puts the sidecar above pyproject.toml — it is the local override — so the artifact "
      "must name the sidecar's script. This pins documented precedence rather than hunting "
      "a bug: a ladder nobody tests is a ladder that silently inverts.",
      inv="INV-BUILD-07",
      remedy="If the artifact names the pyproject entrypoint, the merge order in "
             "build._declarations has inverted: pyproject is read first and the sidecar's "
             "dict.update must land on top of it. Fix the order, not the documentation — "
             "the sidecar is the only option for a tree with no pyproject.toml and the "
             "local override for one that has it.",
      per_fixture=False)
def two_directive_homes_disagree(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        ep = manifest_entrypoint(out)
        return ("" if ep == ["sidecar.py"] else
                f"the sidecar outranks pyproject, but the artifact runs {ep or 'nothing'}")
    return _wedge(
        work,
        'entrypoint = "sidecar.py"\n',
        sides=("sidecar.py", "pyproject.py"),
        damage=damage,
        target="app.py",
        extra={"pyproject.toml": PYPROJECT + '[tool.haru-pack]\nentrypoint = "pyproject.py"\n',
               "sidecar.py": APP,
               "pyproject.py": APP},
    )


@case("wedge", ("RAN", "WARNED"),
      "A directive contradicted by the CLI flag that duplicates it: the sidecar declares "
      "one entrypoint and `-e` on the command line names another. The ladder puts flags at "
      "the top, so the flag must win — an operator overriding a checked-in declaration for "
      "one build is the whole reason flags outrank files.",
      inv="INV-BUILD-07",
      remedy="explicit_ep = entry_point or decl.get(\"entrypoint\") in build._resolve is "
             "what puts the flag first. If the declaration wins instead, that expression "
             "has been reordered and every --entry-point override is silently ignored.",
      per_fixture=False)
def a_directive_contradicted_by_its_cli_flag(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        ep = manifest_entrypoint(out)
        return ("" if ep == ["flag.py"] else
                f"-e flag.py was overridden by the declaration: artifact runs "
                f"{ep or 'nothing'}")
    return _wedge(
        work,
        'entrypoint = "declared.py"\n',
        sides=("flag.py", "declared.py"),
        damage=damage,
        build_args=("-e", "flag.py"),
        extra={"declared.py": APP, "flag.py": APP},
    )


@case("wedge", ("REFUSED", "WARNED"),
      "Two tier flags that cannot both hold: --thin and --thick on one command line. "
      "cli._run_build resolves them with two unguarded ifs, so thick wins by being second "
      "and nothing is said about it. The operator asked for the smallest possible binary "
      "and for the largest, and got the largest with no indication which request lost — "
      "which is the same shape as every other case here, one level up, in the flags rather "
      "than in the file.",
      inv="INV-CHAOS-07",
      remedy="Refuse when both are passed, naming both: 'both --thin and --thick were "
             "given; they select different tiers'. The two ifs in cli._run_build are "
             "`if thin: tier = \"thin\"` then `if thick or chonky: tier = \"thick\"`, so "
             "last-write-wins is an accident of ordering rather than a documented "
             "precedence — unlike the config ladder, nothing states that thick beats thin.",
      per_fixture=False)
def contradictory_tier_flags(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        try:
            tier = str(payload_manifest(out).get("tier", "?"))
        except (OSError, KeyError, ValueError):
            tier = "?"
        return (f"built tier {tier!r} without mentioning that --thin was overruled"
                if tier != "thin" else "")
    return _wedge(
        work,
        "# the contradiction is in the flags, not the file\n",
        sides=("--thin", "--thick"),
        damage=damage,
        build_args=("--thin", "--thick"),
    )


@case("wedge", ("REFUSED",),
      "A declared entrypoint outside the project tree, in the two spellings an operator "
      "reaches for: `../shared/cli.py` (the app lives one level up beside its siblings) "
      "and `sub/../../shared/cli.py` (the same file, reached through a directory that "
      "really exists). Only the project's own tree is copied into the payload, so either "
      "one names a file that will not be there — a guaranteed first-run failure on the "
      "customer's machine, decidable at build time.",
      inv="INV-BUILD-04",
      remedy="_PLAIN_NAME in entrypoints.resolve_entrypoint rejects a leading '..' or '/', "
             "which is what refuses the first spelling. The second is not a spelling "
             "problem and cannot be fixed in that regex: verify_script_file resolves "
             "Path(project) / spec and asks is_file(), so an interior '..' that lands on a "
             "real file outside the tree passes. Resolve the candidate and require it to "
             "stay under decl_dir — the containment check archives._is_within already "
             "applies to archive members (INV-SUPPLY-03) — and refuse with the resolved "
             "path in the message. Note this is the same class as "
             "app_subdir_escapes_the_payload, in a different field: that one is guarded by "
             "validate_manifest and this one is not.",
      per_fixture=False)
def a_declared_entrypoint_outside_the_tree(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        ep = manifest_entrypoint(out)
        escaped = [x for x in ep if ".." in str(x)]
        return (f"the artifact records an entrypoint outside its own payload: {escaped}"
                if escaped else "")
    return _wedge(
        work,
        'entrypoint = "sub/../../shared/cli.py"\n',
        sides=("shared/cli.py", "outside"),
        damage=damage,
        extra={"sub/keep.py": "# a directory that really exists\n",
               "../shared/cli.py": APP},
    )


@case("wedge", ("RAN", "WARNED"),
      "A [[bundle]]-style list in BOTH homes. The documented merge is per top-level key "
      "and not deep, so the sidecar's list REPLACES the pyproject one rather than "
      "extending it. Worth pinning precisely because the tempting implementation is the "
      "wrong one: concatenating would let an operator add a bundle step but never remove "
      "an inherited one, and the step they thought they had deleted would keep running in "
      "every artifact.",
      inv="INV-BUILD-07",
      remedy="The merge is `merged.update(...)` per home in build._declarations, which is "
             "replacement by construction. If the artifact's manifest carries both lists "
             "concatenated, someone has made the merge deep — INV-BUILD-07's Note states "
             "the opposite, so either the code or that Note is now wrong.",
      per_fixture=False)
def a_bundle_list_in_both_homes(exe: Path, work: Path) -> dict:
    def damage(out: Path):
        try:
            got = payload_manifest(out).get("bundle") or []
        except (OSError, KeyError, ValueError):
            return "the artifact's manifest could not be read"
        names = [str(b.get("dest", b)) for b in got] if isinstance(got, list) else [str(got)]
        if names == ["from-sidecar"]:
            return ""
        if "from-pyproject" in names and "from-sidecar" in names:
            return (f"both homes' bundle lists survived into the artifact ({names}) — the "
                    f"merge concatenated where it documents replacement")
        return f"the artifact's bundle list is {names}, not the sidecar's"
    return _wedge(
        work,
        'entrypoint = "app.py"\n\n[[bundle]]\nsrc = "keep.txt"\ndest = "from-sidecar"\n',
        sides=("from-sidecar", "from-pyproject"),
        damage=damage,
        target="app.py",
        extra={"pyproject.toml": PYPROJECT + '[tool.haru-pack]\nentrypoint = "app.py"\n'
                                 '\n[[tool.haru-pack.bundle]]\nsrc = "keep.txt"\n'
                                 'dest = "from-pyproject"\n',
               "keep.txt": "bundled\n"},
    )



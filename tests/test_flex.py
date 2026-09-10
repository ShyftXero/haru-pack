"""INV-FLEX-01/02 — the flex harness's package list is reproducible and honest.

The flex matrix decides what haru-pack is tested against, so "where did this list come
from" has to have an answer that does not depend on anyone's memory. Two properties:

  INV-FLEX-01  `flex/packages.toml` is a pure function of two committed files. Regenerate
               it offline, years from now, and get the same bytes.
  INV-FLEX-02  The hard-target list and `scaffold.py`'s KNOWN table are the same knowledge
               written twice. They must not drift.

These run offline. Nothing here builds a binary — that is `tools/flex-run.py`, which needs
a toolchain and several minutes.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from haru_pack import scaffold, tomlio

REPO = Path(__file__).resolve().parent.parent
FLEX = REPO / "flex"
SOURCES = FLEX / "sources.toml"
CURATION = FLEX / "curation.toml"
PACKAGES = FLEX / "packages.toml"
GEN = REPO / "tools" / "gen-package-manifest.py"


@pytest.fixture(scope="module")
def manifest():
    return tomlio.load(PACKAGES)


@pytest.fixture(scope="module")
def curation():
    return tomlio.load(CURATION)


# ---------------------------------------------------------------- reproducibility

@pytest.mark.invariant("INV-FLEX-01")
def test_the_committed_manifest_matches_its_inputs():
    """Red-path: hand-edit flex/packages.toml, or change curation.toml without
    regenerating. `--check` regenerates from the inputs and compares."""
    r = subprocess.run([sys.executable, str(GEN), "--check"],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, (
        "flex/packages.toml is stale or hand-edited.\n"
        f"{r.stdout}{r.stderr}\nRegenerate: python tools/gen-package-manifest.py"
    )


@pytest.mark.invariant("INV-FLEX-01")
def test_generation_is_deterministic(tmp_path):
    """Same inputs twice -> identical bytes. No clock, no network, no set iteration order."""
    outs = []
    for _ in range(2):
        r = subprocess.run([sys.executable, str(GEN)], capture_output=True, text=True, cwd=REPO)
        assert r.returncode == 0, r.stderr
        outs.append(PACKAGES.read_bytes())
    assert outs[0] == outs[1], "regenerating produced different bytes"


@pytest.mark.invariant("INV-FLEX-01")
def test_the_generator_takes_no_network_and_no_clock():
    """Red-path: make the generator fetch the ranking itself.

    Then the 'same' command produces a different file every month and the manifest stops
    being reproducible — which is the entire reason fetching is a separate tool.
    """
    import ast
    tree = ast.parse(GEN.read_text())
    banned = {"urllib", "http", "requests", "socket", "random", "datetime", "time"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    offenders = imported & banned
    assert not offenders, (
        f"tools/gen-package-manifest.py imports {sorted(offenders)}; generation must be a "
        f"pure function of flex/sources.toml + flex/curation.toml, with no network and no "
        f"clock, or the manifest stops being reproducible"
    )


@pytest.mark.invariant("INV-FLEX-01")
def test_the_manifest_records_where_the_ranking_came_from(manifest):
    """A reader of packages.toml alone must be able to tell what produced it."""
    src = manifest.get("source", {})
    for field in ("name", "url", "last_update", "snapshot_sha256"):
        assert src.get(field), f"packages.toml [source] is missing {field}"
    assert len(src["snapshot_sha256"]) == 64
    assert src["url"].startswith("https://")


@pytest.mark.invariant("INV-FLEX-01")
def test_the_raw_snapshot_is_not_committed():
    """The big upstream blob is gitignored; the small extract is what regenerates the
    manifest. Red-path: commit flex/snapshots/, and the repo grows a megabyte of churn per
    refresh for data that is already summarized."""
    tracked = subprocess.run(["git", "ls-files", "flex/"], capture_output=True, text=True,
                             cwd=REPO).stdout.split()
    assert not [f for f in tracked if "snapshots/" in f], \
        f"raw snapshots are committed: {[f for f in tracked if 'snapshots/' in f]}"
    assert "flex/sources.toml" in tracked, "the extract must be committed or nothing regenerates"


# ---------------------------------------------------------------- the lists

@pytest.mark.invariant("INV-FLEX-01")
def test_top_n_matches_the_ranking_order(manifest):
    """The top-N list must be the ranking, in order, minus curated-out entries — not a
    hand-picked selection that happens to look plausible."""
    ranking = tomlio.load(SOURCES)["ranking"]
    curated = tomlio.load(CURATION).get("package", {})
    skipped = {n for n, e in curated.items() if e.get("skip")}
    expected = [n for n in ranking if n not in skipped][:manifest["top_n"]]

    got = [p["name"] for p in manifest["package"] if p["list"] == "top25"]
    assert got == expected, "the top-N list is not the ranking order"
    assert [p["rank"] for p in manifest["package"] if p["list"] == "top25"] == \
        list(range(1, len(got) + 1))


@pytest.mark.invariant("INV-FLEX-02")
def test_hard_targets_match_the_scaffold_known_table(curation):
    """Red-path: add a package to scaffold.KNOWN without adding it to flex/curation.toml.

    The KNOWN table is haru-pack's list of packages that need special handling, and the
    hard-target list is what proves that handling works. Two copies of the same knowledge
    that drift apart is how a tool ends up claiming support it no longer has.
    """
    hard = curation.get("hard", {})
    known = set(scaffold.KNOWN)
    claimed = {h.get("known", name) for name, h in hard.items()}

    assert claimed <= known, (
        f"hard targets naming packages absent from scaffold.KNOWN: {sorted(claimed - known)}"
    )
    assert known <= claimed, (
        f"scaffold.KNOWN packages with no hard target: {sorted(known - claimed)}. "
        f"Every package haru-pack claims to handle specially needs a test that it does."
    )


@pytest.mark.invariant("INV-FLEX-02")
def test_every_hard_target_says_what_corner_it_exercises(manifest):
    """A hard target with no stated reason is just another package."""
    for p in manifest["package"]:
        if p["list"] != "hard_targets":
            continue
        assert p.get("corner", "").strip(), f"{p['name']} does not say what makes it hard"
        assert len(p["corner"]) > 20, f"{p['name']}'s corner is too vague: {p['corner']!r}"


@pytest.mark.invariant("INV-FLEX-02")
def test_expected_failures_are_declared_not_discovered(manifest):
    """weasyprint needs system libraries pip cannot bundle. That it fails is the FINDING.
    Marking it expected keeps a known limitation from reading as a regression — and makes
    an unexpected PASS visible, which is the interesting direction."""
    xfail = [p["name"] for p in manifest["package"] if p.get("expect_failure")]
    assert "weasyprint" in xfail, (
        "weasyprint is no longer marked expect_failure; if it now packs cleanly that is a "
        "real result worth investigating, not a silent edit"
    )


# ---------------------------------------------------------------- smoke scripts

@pytest.mark.invariant("INV-FLEX-01")
def test_every_smoke_script_is_valid_python_and_signals_success(manifest):
    """A smoke body that does not compile fails at build time, minutes in, with a confusing
    error. Compile them here in milliseconds instead."""
    import ast
    sys.path.insert(0, str(REPO / "tools"))
    for p in manifest["package"]:
        smoke = p.get("smoke")
        if not smoke:
            continue
        try:
            ast.parse(smoke)
        except SyntaxError as e:
            pytest.fail(f"{p['name']}'s smoke script does not parse: {e}")
        assert "FLEX_OK" in smoke, (
            f"{p['name']}'s smoke script never prints FLEX_OK, so the runner cannot tell "
            f"success from a silent no-op"
        )


@pytest.mark.invariant("INV-FLEX-01")
def test_generated_scripts_declare_their_dependency():
    """The runner writes PEP 723 scripts; the dependency block is what makes uv install
    the package under test at all."""
    sys.path.insert(0, str(REPO / "tools"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("flexrun", REPO / "tools" / "flex-run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    s = mod.script_for({"name": "pyyaml", "import_name": "yaml", "python": "3.12",
                        "smoke": "import yaml\nprint('FLEX_OK')"})
    assert "# /// script" in s and 'dependencies = ["pyyaml"]' in s
    assert s.rstrip().endswith("print('FLEX_OK')")

    # no smoke -> import the IMPORT name, not the distribution name
    s2 = mod.script_for({"name": "pyyaml", "import_name": "yaml"})
    assert "import yaml as _m" in s2 and 'dependencies = ["pyyaml"]' in s2

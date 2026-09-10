"""INV-TIER-01 — `--thick` means what it says: no network at run time.

The tier table describes thick as "bundle uv + Python (+venv) — download NOTHING, fully
offline". That was false for PEP 723 scripts. `assemble_payload` warmed the dependency
cache only for `kind == "project"`, so a thick build of

    # /// script
    # dependencies = ["pyyaml"]
    # ///

shipped uv and an interpreter but not pyyaml, and reached the network on first run. The
build reported success and the tier's own description said otherwise.

Observed on 2026-09-09, before the fix, running the binary with a pristine cache and
UV_OFFLINE=1:

    hint: Packages were unavailable because the network was disabled. When the network
    is disabled, registry packages may only be read from the cache.

The payload was also 1.7 MB smaller than the fixed one — the missing wheel.

These tests are offline and fast. The end-to-end proof (build thick, run with a cold cache
and uv barred from the network) is `tools/flex-run.py --tier thick --offline-check`, which
needs a toolchain and minutes.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from haru_pack import build as build_mod
from haru_pack import bundle, discovery

SCRIPT = """# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml", "click>=8"]
# ///
import yaml
print(yaml.safe_load("a: 1"))
"""


@pytest.fixture
def script(tmp_path) -> Path:
    p = tmp_path / "demo.py"
    p.write_text(SCRIPT)
    return p


@pytest.mark.invariant("INV-TIER-01")
def test_pep723_dependencies_are_discovered(script):
    """You cannot stage what you never parsed. Red-path: drop `dependencies` from
    discovery._pep723 and the thick path has nothing to warm."""
    d = discovery.discover(script)
    assert d["kind"] == "script"
    assert d["dependencies"] == ["pyyaml", "click>=8"], (
        "PEP 723 inline dependencies are not being read"
    )
    assert d["python"] == "3.12"


@pytest.mark.invariant("INV-TIER-01")
def test_no_dependency_block_is_not_an_error(tmp_path):
    """A script with no inline metadata is normal and must stage nothing, not crash."""
    p = tmp_path / "bare.py"
    p.write_text("print('hi')\n")
    assert discovery.discover(p)["dependencies"] == []


@pytest.mark.invariant("INV-TIER-01")
def test_script_dependencies_reach_the_manifest(script):
    """_resolve must carry them from discovery to assemble_payload."""
    manifest, _, _, _, _ = build_mod._resolve(script, "thick", "", "", [], "", "", False)
    assert manifest["script_dependencies"] == ["pyyaml", "click>=8"]


@pytest.mark.invariant("INV-TIER-01")
def test_the_thick_path_stages_script_dependencies():
    """Red-path: replace the `warm_cache_for_script(...)` call in assemble_payload with
    `pass`, rebuild a thick script binary, and run it with a pristine cache and
    UV_OFFLINE=1. Walked 2026-09-09: it failed with uv's "Packages were unavailable
    because the network was disabled"."""
    src = inspect.getsource(build_mod.assemble_payload)
    assert "warm_cache_for_script(" in src, (
        "the thick path no longer stages a script's dependencies, so `--thick` ships a "
        "binary that still needs the network on first run"
    )
    # and it must be reached for scripts specifically, not only projects
    assert 'kind") == "script"' in src or "kind'] == 'script'" in src, (
        "the staging call is not guarded on the script kind; projects already had their "
        "cache warmed, scripts were the gap"
    )


@pytest.mark.invariant("INV-TIER-01")
def test_warming_uses_uvs_script_mode():
    """`uv sync --script` is what resolves PEP 723 inline metadata. Resolving the script as
    if it were a project would either fail or silently stage the wrong dependency set."""
    src = inspect.getsource(bundle.warm_cache_for_script)
    assert '"--script"' in src, "warm_cache_for_script does not use uv's --script mode"
    assert "UV_CACHE_DIR" in src, (
        "the warm must land in the bundled cache directory or nothing ships"
    )


@pytest.mark.invariant("INV-TIER-01")
def test_build_time_metadata_does_not_leak_into_the_payload_manifest():
    """`script_dependencies` is for the builder. The launcher has no use for it, and a
    manifest field nothing reads is a field someone later mistakes for load-bearing."""
    src = inspect.getsource(build_mod.assemble_payload)
    assert 'manifest.pop("script_dependencies"' in src
    nim = (Path(__file__).resolve().parent.parent
           / "src/haru_pack/launcher/manifest.nim").read_text()
    assert "script_dependencies" not in nim


@pytest.mark.invariant("INV-TIER-01")
def test_staging_is_announced(script):
    """Loud, per the design: staging dependencies into a payload changes what ships and how
    big it is, so it says so. Red-path: drop the log call and a thick build silently gains
    or loses megabytes."""
    src = inspect.getsource(build_mod.assemble_payload)
    assert "staging" in src.lower() and "log" in src, (
        "dependency staging happens silently; the operator cannot tell what went in"
    )

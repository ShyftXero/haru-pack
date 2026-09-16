"""INV-SUPPLY-01 — the arm64 Nim is pinned, and a mismatch never becomes a silent rebuild.

choosenim publishes no linux-aarch64 binary (`haru_pack.toolchain` documents the table), so
that host needs a second route to a compiler. The primary route is a prebuilt binary this
repository publishes; compiling from the pinned source is the fallback (issue #32).

The interesting property is not "it downloads a thing". It is the distinction between a GAP
and a MISMATCH: no pin for this platform may fall back to a source build, and a pinned
artifact whose bytes are wrong must not. Collapsing those two into one non-zero exit would
turn a supply-chain signal into an hour-long recompile that nobody reads.

Offline: these drive the scripts with a temporary pins file and a local URL.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from haru_pack import tomlio  # noqa: E402

DOCKER = REPO / "docker"
BINARY = DOCKER / "install-nim-binary.py"
SOURCE = DOCKER / "install-nim-source.py"

NO_PIN_FOR_PLATFORM = 3


def run(script: Path, pins: Path, dest: Path):
    return subprocess.run([sys.executable, str(script), str(pins), str(dest)],
                          capture_output=True, text=True, timeout=120)


def write_pins(path: Path, entries: str) -> Path:
    path.write_text(f'schema_version = 1\n\n{entries}', encoding="utf-8")
    return path


def make_nim_tarball(tmp: Path, name: str = "nim-9.9.9") -> tuple[Path, str]:
    """A tarball shaped like a built Nim tree: <root>/bin/nim."""
    root = tmp / "build" / name
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "nim").write_text("#!/bin/sh\necho nim 9.9.9\n", encoding="utf-8")
    blob = tmp / f"{name}.tar.xz"
    with tarfile.open(blob, "w:xz") as tf:
        tf.add(root, arcname=name)
    return blob, hashlib.sha256(blob.read_bytes()).hexdigest()


# ─────────────────────────────────────────── gap vs mismatch: the distinction that matters

def test_no_pin_for_this_platform_is_a_gap_not_a_failure(tmp_path):
    """Exit 3 tells the caller "you may fall back". Red-path: return 1 here.

    On a platform with no pinned binary, refusing outright would leave arm64 with no route to
    a compiler at all — which is the situation issue #32 exists to end.
    """
    pins = write_pins(tmp_path / "pins.toml", "")
    r = run(BINARY, pins, tmp_path / "out")
    assert r.returncode == NO_PIN_FOR_PLATFORM, r.stderr
    assert "nothing pinned" in r.stderr


def test_a_digest_mismatch_is_never_a_gap(tmp_path):
    """Red-path: return 3 on a mismatch, and `auto` quietly compiles instead.

    That would be the worst outcome available: a pinned artifact arrived wrong, and the only
    trace is that the build took an hour longer than usual.
    """
    blob, _real = make_nim_tarball(tmp_path)
    import platform as _p
    plat = "linux-aarch64" if _p.machine() in ("aarch64", "arm64") else "linux-x86_64"
    pins = write_pins(tmp_path / "pins.toml",
                      '[[artifact]]\nkind = "nim"\nvariant = "binary"\n'
                      f'platform = "{plat}"\nversion = "9.9.9"\n'
                      f'sha256 = "{"0" * 64}"\nurl = "{blob.as_uri()}"\n')
    r = run(BINARY, pins, tmp_path / "out")
    assert r.returncode == 1, f"a mismatch must not be exit 3:\n{r.stderr}"
    assert "DIGEST MISMATCH" in r.stderr
    assert "do not fall back" in r.stderr.lower()


def test_stdout_carries_the_path_and_nothing_else(tmp_path):
    """Regression. These scripts' stdout IS their return value — callers do `src="$(...)"`.

    A progress line on stdout ended up inside the captured path, and the arm64 image build
    failed forty seconds in with:

        acquire-nim.sh: cd: can't cd to install-nim-source: nim 2.2.6 from https://...

    which names neither the script's real problem nor the word "stdout". Red-path: move either
    progress line back to stdout.
    """
    blob, digest = make_nim_tarball(tmp_path)
    import platform as _p
    plat = "linux-aarch64" if _p.machine() in ("aarch64", "arm64") else "linux-x86_64"
    pins = write_pins(tmp_path / "pins.toml",
                      '[[artifact]]\nkind = "nim"\nvariant = "binary"\n'
                      f'platform = "{plat}"\nversion = "9.9.9"\n'
                      f'sha256 = "{digest}"\nurl = "{blob.as_uri()}"\n')
    r = run(BINARY, pins, tmp_path / "out")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().count("\n") == 0, (
        f"stdout must be exactly one line (a path); got:\n{r.stdout}"
    )
    assert Path(r.stdout.strip()).is_dir(), f"stdout is not a usable path: {r.stdout!r}"
    assert "install-nim-binary:" in r.stderr, "progress belongs on stderr, not nowhere"


def test_a_matching_pinned_binary_installs(tmp_path):
    blob, digest = make_nim_tarball(tmp_path)
    import platform as _p
    plat = "linux-aarch64" if _p.machine() in ("aarch64", "arm64") else "linux-x86_64"
    pins = write_pins(tmp_path / "pins.toml",
                      '[[artifact]]\nkind = "nim"\nvariant = "binary"\n'
                      f'platform = "{plat}"\nversion = "9.9.9"\n'
                      f'sha256 = "{digest}"\nurl = "{blob.as_uri()}"\n')
    out = tmp_path / "out"
    r = run(BINARY, pins, out)
    assert r.returncode == 0, r.stderr
    assert (out / "nim-9.9.9" / "bin" / "nim").exists()


def test_an_unfetchable_pin_is_a_gap(tmp_path):
    """The release is not public yet, or the network is down. Falling back is right."""
    pins = write_pins(tmp_path / "pins.toml",
                      '[[artifact]]\nkind = "nim"\nvariant = "binary"\n'
                      'platform = "linux-aarch64"\nversion = "9.9.9"\n'
                      f'sha256 = "{"0" * 64}"\n'
                      'url = "file:///nonexistent/nim-9.9.9-linux-aarch64.tar.xz"\n')
    r = run(BINARY, pins, tmp_path / "out")
    assert r.returncode == NO_PIN_FOR_PLATFORM


def test_two_pins_for_one_platform_are_refused_rather_than_guessed(tmp_path):
    """Ambiguity here means silently installing a different compiler than intended."""
    entry = ('[[artifact]]\nkind = "nim"\nvariant = "binary"\n'
             'platform = "linux-aarch64"\nversion = "{v}"\n'
             f'sha256 = "{"0" * 64}"\nurl = "file:///x"\n')
    pins = write_pins(tmp_path / "pins.toml",
                      entry.format(v="1.1.1") + "\n" + entry.format(v="2.2.2"))
    import platform as _p
    if _p.machine() not in ("aarch64", "arm64"):
        pytest.skip("platform-specific entries; this assertion is about aarch64 rows")
    r = run(BINARY, pins, tmp_path / "out")
    assert r.returncode == 1
    assert "cannot choose" in r.stderr


# ───────────────────────────────────────────────────── the source fallback is pinned too

def test_the_source_build_refuses_an_unpinned_tarball(tmp_path):
    """Red-path: let the source script fetch whatever URL it is handed.

    The fallback is not the place to relax the rule — it is the path that runs when the
    primary one failed, which is exactly when nobody is watching closely.
    """
    pins = write_pins(tmp_path / "pins.toml", "")
    r = run(SOURCE, pins, tmp_path / "out")
    assert r.returncode == 1
    assert 'variant = "source"' in r.stderr


def test_the_real_pins_file_has_exactly_one_nim_source():
    """The repo's own pins, not a fixture. Both scripts refuse ambiguity, so this would break
    an arm64 image build rather than pick wrongly — but it should never get that far."""
    # `haru_pack.tomlio`, not a bare `import tomllib`: tomllib is 3.11+, this project's floor
    # is 3.9, and CI's 3.9 job is the one that caught it. tomlio is the repo's own shim.
    pins = tomlio.load(REPO / "src" / "haru_pack" / "pins.toml")
    src = [a for a in pins["artifact"]
           if a.get("kind") == "nim" and a.get("variant") == "source"]
    assert len(src) == 1, f"expected one pinned nim source, got {len(src)}"
    assert src[0]["sha256"] and len(src[0]["sha256"]) == 64
    assert "nim-lang.org" in src[0]["url"]
    assert "sha256" in src[0].get("provenance", ""), (
        "a pin's provenance must point at the publisher's own digest, not at a download"
    )


def test_any_pinned_nim_binary_cites_a_build_log_as_provenance():
    """A binary this project built is a weaker claim than one upstream published.

    The pin has to say where it came from in a way a reader can check — a workflow run URL,
    not a name. Vacuous today (no binary pinned yet); it goes red the moment one is added
    with provenance like "built on the maintainer's Pi".
    """
    # `haru_pack.tomlio`, not a bare `import tomllib`: tomllib is 3.11+, this project's floor
    # is 3.9, and CI's 3.9 job is the one that caught it. tomlio is the repo's own shim.
    pins = tomlio.load(REPO / "src" / "haru_pack" / "pins.toml")
    for a in pins["artifact"]:
        if a.get("kind") == "nim" and a.get("variant") == "binary":
            prov = a.get("provenance", "")
            assert "actions/runs/" in prov, (
                f"nim binary pin for {a.get('platform')} cites {prov!r}; provenance for an "
                f"artifact we built must be the workflow run that built it"
            )

"""INV-PAYLOAD-07 — the payload carries a format version, and the launcher refuses one newer
than it understands.

The concrete skew this closes (#44): #40 added the `.haru-links` payload member, and a launcher
built BEFORE #40 has no `materialiseLinks`. Given a post-#40 payload it does not fail — it stages
`.haru-links` as an ordinary text file and the ~1000 aliases it lists never appear, so `bin/python`
is silently missing from the staged tree. Nothing enforced that the two halves matched; a
`payload_format` integer in manifest.toml, refused when it exceeds `MaxSupportedPayloadFormat`,
gives every future member the same protection at once.

The launcher tests here are end-to-end, in the spirit of test_launcher_integrity.py: they compile
the real Nim launcher, append a real payload, and RUN the resulting executable — a claim about the
version gate that never ran a binary would be exactly the vacuity INVARIANTS.md exists to prevent.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

from haru_pack.build import assemble_payload
from haru_pack.overlay import attach
from haru_pack.payload import PAYLOAD_FORMAT, build_payload_zip

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_SRC = REPO / "src/haru_pack/launcher/main.nim"

# Declared in launcher/main.nim. A distinct code is the point: "it did not run" is not evidence,
# "it refused for THIS reason" is.
EXIT_PAYLOAD_FORMAT = 12

needs_nim = pytest.mark.skipif(shutil.which("nim") is None,
                               reason="nim not installed; the launcher cannot be built")


# ---------------------------------------------------------------- build helpers

def _compile(out: Path, *defines: str) -> Path:
    args = ["nim", "c", "-d:release", f"--nimcache:{out.parent / ('nimcache-' + out.name)}",
            f"--out:{out}", *[f"-d:{d}" for d in defines], str(LAUNCHER_SRC)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0 or not out.exists():
        pytest.fail("nim compile failed:\n" + (r.stderr or r.stdout)[-3000:])
    return out


@pytest.fixture(scope="session")
def release_launcher(tmp_path_factory) -> Path:
    return _compile(tmp_path_factory.mktemp("nim-release") / "launcher")


def _fake_uv(path: Path, marker: str) -> Path:
    """A stand-in for uv that announces itself and succeeds — so a test can see whether the
    launcher got all the way to executing it, or refused first."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "{marker}"\nexit 0\n')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def make_payload_dir(root: Path, *, payload_format: int | None = None,
                     uv_marker: str = "PAYLOAD_UV_RAN") -> Path:
    """A minimal but real payload tree. `payload_format=None` writes NO key at all — the
    pre-#44 shape a legacy payload has, which must still be accepted."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(exist_ok=True)
    (root / "app" / "hello.py").write_text("print('hi')\n")
    lines = ['name = "t"', 'kind = "script"', 'app_subdir = "app"',
             'entrypoint = ["hello.py"]', 'tier = "default"',
             "fetch_uv = false", "offline = false"]
    if payload_format is not None:
        lines.append(f"payload_format = {payload_format}")
    (root / "manifest.toml").write_text("\n".join(lines) + "\n")
    _fake_uv(root / "vendor" / "uv", uv_marker)
    return root


def build_exe(launcher: Path, payload: bytes, out: Path) -> dict:
    info = attach(launcher, payload, out)
    out.chmod(0o755)
    return info


def run_exe(exe: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    """Run a built launcher with a hermetic cache dir and an EMPTY PATH, so a real `uv` on this
    box can never be what a test observes. umask 022: this box runs 002 and stage.nim refuses a
    group-writable stage dir."""
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    (tmp_path / "home").mkdir(exist_ok=True)
    env = {"HOME": str(tmp_path / "home"), "XDG_CACHE_HOME": str(cache), "PATH": ""}
    return subprocess.run([str(exe)], capture_output=True, text=True, cwd=tmp_path,
                          env=env, umask=0o022)


# ---------------------------------------------------------------- the build side

@pytest.mark.invariant("INV-PAYLOAD-07")
def test_build_stamps_the_current_payload_format(tmp_path):
    """assemble_payload writes `payload_format = PAYLOAD_FORMAT` into every manifest, so the
    launcher's gate has something to check. Without this the field is a dead constant and the
    guarantee still rests on "always build both at once"."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "hello.py").write_text("print('hi')\n")
    manifest = {"app_subdir": "app", "kind": "script", "entrypoint": ["hello.py"]}
    payload = assemble_payload(proj, manifest, "thin", "host", "3.13", tmp_path / "asm")
    written = tomllib.loads((payload / "manifest.toml").read_text())
    assert written.get("payload_format") == PAYLOAD_FORMAT == 1, (
        "manifest.toml did not carry the current payload_format", written)


# ---------------------------------------------------------------- the launcher gate

@needs_nim
@pytest.mark.invariant("INV-PAYLOAD-07")
def test_current_payload_format_runs(release_launcher, tmp_path):
    """A payload declaring the format this launcher was built for stages and runs normally."""
    src = make_payload_dir(tmp_path / "payload", payload_format=1)
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)


@needs_nim
@pytest.mark.invariant("INV-PAYLOAD-07")
def test_legacy_payload_with_no_format_key_is_accepted(release_launcher, tmp_path):
    """Backward compatibility (#44): a payload predating this field has NO payload_format at
    all. It must read back as legacy/0 and run — breaking existing payloads to add the check
    would be a worse regression than the one it prevents."""
    src = make_payload_dir(tmp_path / "payload", payload_format=None)
    assert "payload_format" not in (src / "manifest.toml").read_text(), (
        "the fixture must NOT write the key — this test would otherwise prove nothing about "
        "the missing-key path")
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)


@needs_nim
@pytest.mark.invariant("INV-PAYLOAD-07")
def test_payload_format_newer_than_supported_is_refused(release_launcher, tmp_path):
    """The efficacy test. A payload declaring a format ABOVE MaxSupportedPayloadFormat is a
    payload this launcher cannot interpret — the #44 old-launcher/new-payload case. It must
    refuse with the dedicated exit code and NEVER reach execution of its bundled uv."""
    src = make_payload_dir(tmp_path / "payload", payload_format=2)
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_PAYLOAD_FORMAT, (r.returncode, r.stdout, r.stderr)
    assert "newer than this launcher understands" in r.stderr, r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout, (
        "the launcher executed the payload despite its format being one it cannot interpret")


@needs_nim
@pytest.mark.invariant("INV-PAYLOAD-07")
def test_a_far_future_format_is_also_refused(release_launcher, tmp_path):
    """Not just off-by-one: any format above the ceiling is refused, and the message reports
    the declared value so the operator can tell how far ahead their payload is."""
    src = make_payload_dir(tmp_path / "payload", payload_format=99)
    exe = tmp_path / "app.exe"
    build_exe(release_launcher, build_payload_zip(src), exe)
    r = run_exe(exe, tmp_path)
    assert r.returncode == EXIT_PAYLOAD_FORMAT, (r.returncode, r.stdout, r.stderr)
    assert "(99)" in r.stderr, r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout

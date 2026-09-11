"""INV-LAUNCH-08 / INV-LAUNCH-09 / INV-STUB-01 / INV-CANARY-01 — Phase 1 of ADR 0003.

The versioned footer (v1 68B / v2 116B), the cleartext stub-config it carries, the per-knob
canary map, and the payload `inject` (env-append). End-to-end, in the spirit of
test_launcher_integrity.py: every test compiles the real Nim launcher, attaches a real
payload (+ optional stub-config) with overlay.attach(), and RUNS the resulting executable.
Nothing on the launcher side is stubbed.

`uv` is a shell script that prints markers, so a test can tell whether execution was reached
and what environment the child actually saw.

See docs/adr/0003-stub-config-and-canary.md.
"""
from __future__ import annotations

import shutil
import stat
import struct
import subprocess
from pathlib import Path

import pytest

from haru_pack import crypto
from haru_pack.overlay import attach
from haru_pack.payload import build_payload_zip

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_SRC = REPO / "src/haru_pack/launcher/main.nim"

# Exit codes declared in launcher/main.nim.
EXIT_NO_SECRET = 4
EXIT_BAD_FOOTER = 8
EXIT_BAD_STUB = 10

pytestmark = pytest.mark.skipif(shutil.which("nim") is None,
                                reason="nim not installed; the launcher cannot be built")


def _compile(out: Path, *defines: str) -> Path:
    args = ["nim", "c", "-d:release", f"--nimcache:{out.parent / ('nc-' + out.name)}",
            f"--out:{out}", *[f"-d:{d}" for d in defines], str(LAUNCHER_SRC)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0 or not out.exists():
        pytest.fail("nim compile failed:\n" + (r.stderr or r.stdout)[-3000:])
    return out


@pytest.fixture(scope="session")
def launcher(tmp_path_factory) -> Path:
    return _compile(tmp_path_factory.mktemp("nim-stub") / "launcher")


def _uv(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def make_payload(root: Path, *, uv_body: str = 'echo "PAYLOAD_UV_RAN"\nexit 0',
                 manifest_extra: str = "") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(exist_ok=True)
    (root / "app" / "hello.py").write_text("print('hi')\n")
    (root / "manifest.toml").write_text(
        'name = "t"\nkind = "script"\napp_subdir = "app"\n'
        'entrypoint = ["hello.py"]\ntier = "default"\n'
        "fetch_uv = false\noffline = false\n" + manifest_extra)
    _uv(root / "vendor" / "uv", uv_body)
    return root


def stub_toml(secret: str = "HARU", uv_ver: str = "HARU",
              source_url: str = "HARU", base_path: str = "HARU") -> bytes:
    """The Phase-1 stub-config schema (ADR 0003 §2.1)."""
    return (f"stub_config_version = 1\n\n[canary]\n"
            f'secret = "{secret}"\nuv_ver = "{uv_ver}"\n'
            f'source_url = "{source_url}"\nbase_path = "{base_path}"\n').encode()


def build(launcher: Path, payload: bytes, out: Path, *, flags: int = 0,
          stub_config: bytes | None = None) -> dict:
    info = attach(launcher, payload, out, flags=flags, stub_config=stub_config)
    out.chmod(0o755)
    return info


def run(exe: Path, tmp_path: Path, *, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    cache = tmp_path / "cache"
    cache.mkdir(exist_ok=True)
    (tmp_path / "home").mkdir(exist_ok=True)
    env = {"HOME": str(tmp_path / "home"), "XDG_CACHE_HOME": str(cache), "PATH": ""}
    env.update(env_extra or {})
    # stdin=DEVNULL so the no-secret path never blocks on the interactive prompt; umask 022
    # because stage.nim refuses a group-writable stage dir on this 002 box.
    return subprocess.run([str(exe)], capture_output=True, text=True, cwd=tmp_path,
                          env=env, umask=0o022, stdin=subprocess.DEVNULL)


def _encrypted(zip_bytes: bytes, secret: bytes = b"s3cret") -> bytes:
    box = crypto.encrypt(zip_bytes, secret, iters=2000)
    assert box.startswith(crypto.MAGIC)
    return box


# ------------------------------------------------------------------ INV-LAUNCH-08

@pytest.mark.invariant("INV-LAUNCH-08")
def test_v1_binary_still_loads(launcher, tmp_path):
    """Backward compatibility: a v1 (stub_config=None, 68B) footer still loads and runs."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    info = build(launcher, build_payload_zip(src), exe)   # stub_config=None -> v1
    assert info["format_ver"] == 1
    r = run(exe, tmp_path)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert r.returncode == 0


@pytest.mark.invariant("INV-LAUNCH-08")
def test_v2_binary_with_stub_loads(launcher, tmp_path):
    """A v2 (116B) footer with a valid stub-config loads and runs — the reader dispatched
    on format_ver and located the stub by size, not by a second scan."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    info = build(launcher, build_payload_zip(src), exe, stub_config=stub_toml())
    assert info["format_ver"] == 2
    r = run(exe, tmp_path)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert r.returncode == 0


@pytest.mark.invariant("INV-LAUNCH-08")
@pytest.mark.parametrize("field,value", [("stub_off", 2 ** 63), ("stub_len", 2 ** 63),
                                         ("stub_off", 2 ** 64 - 1), ("stub_len", 0)])
def test_hostile_stub_extent_is_refused_cleanly(launcher, tmp_path, field, value):
    """stubOff/stubLen come off disk exactly like payloadOff/payloadLen; validate by size,
    do not discover the problem by handing an attacker-chosen length to setPosition/readStr."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    build(launcher, build_payload_zip(src), exe, stub_config=stub_toml())
    data = bytearray(exe.read_bytes())
    i = data.rfind(b"HARUPACK")                       # v2 footer: stub_off@+60, stub_len@+68
    at = i + 60 + (0 if field == "stub_off" else 8)
    data[at:at + 8] = struct.pack("<Q", value)
    exe.write_bytes(bytes(data))
    r = run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_FOOTER, (r.returncode, r.stdout, r.stderr)
    assert "corrupt payload footer" in r.stderr
    assert "Traceback" not in r.stderr and "RangeDefect" not in r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


# ------------------------------------------------------------------ INV-STUB-01

@pytest.mark.invariant("INV-STUB-01")
def test_intact_stub_config_runs(launcher, tmp_path):
    """Control: an untouched v2 stub-config passes its digest, parses, and the build runs."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    build(launcher, build_payload_zip(src), exe, stub_config=stub_toml())
    r = run(exe, tmp_path)
    assert r.returncode == 0 and "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stderr)


@pytest.mark.invariant("INV-STUB-01")
def test_tampered_stub_config_is_refused(launcher, tmp_path):
    """The efficacy test. The edit (HARU -> XARU) leaves the stub-config valid TOML with a
    valid canary, so nothing downstream would reject it — ONLY the sha256 changed. The
    payload is unencrypted, so without the digest guard the altered map parses and the build
    runs (rc 0); the guard must turn that into ExitBadStub instead."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    info = build(launcher, build_payload_zip(src), exe, stub_config=stub_toml())
    data = bytearray(exe.read_bytes())
    region = bytes(data[info["stub_off"]:info["stub_off"] + info["stub_len"]])
    j = region.find(b'"HARU"')                        # first canary value (secret)
    assert j != -1
    data[info["stub_off"] + j + 1] = ord("X")         # HARU -> XARU, still a valid prefix
    exe.write_bytes(bytes(data))
    r = run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "stub-config integrity check FAILED" in r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytest.mark.invariant("INV-STUB-01")
def test_unparseable_stub_config_is_refused(launcher, tmp_path):
    """A stub-config with a CORRECT digest but invalid TOML fails closed with ExitBadStub
    and a one-line diagnostic, never a Nim traceback: the try/except around parseStubConfig
    maps parsetoml's error to the exit code (INV-LAUNCH-06)."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    build(launcher, build_payload_zip(src), exe, stub_config=b"this is = = not [[[ toml\n")
    r = run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "stub-config" in r.stderr
    assert ".nim(" not in r.stderr and "Traceback" not in r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytest.mark.invariant("INV-STUB-01")
def test_unsupported_stub_version_is_refused(launcher, tmp_path):
    """A stub-config the launcher cannot understand fails closed with ExitBadStub, not a
    traceback (the digest still matches — this is the parse-side of the same exit code)."""
    src = make_payload(tmp_path / "p")
    exe = tmp_path / "app.exe"
    bad = b'stub_config_version = 2\n\n[canary]\nsecret = "HARU"\n'
    build(launcher, build_payload_zip(src), exe, stub_config=bad)
    r = run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_STUB, (r.returncode, r.stdout, r.stderr)
    assert "stub_config_version" in r.stderr
    assert "Traceback" not in r.stderr


# ------------------------------------------------------------------ INV-CANARY-01

@pytest.mark.invariant("INV-CANARY-01")
def test_default_secret_canary_is_haru_secret(launcher, tmp_path):
    """Default canary: the decryption key is read from HARU_SECRET, and the retired
    HARUPACK_SECRET is not read (setting only it fails to decrypt)."""
    src = make_payload(tmp_path / "p")
    box = _encrypted(build_payload_zip(src))
    exe = tmp_path / "app.exe"
    build(launcher, box, exe, flags=1, stub_config=stub_toml())    # secret canary = HARU

    ok = run(exe, tmp_path, env_extra={"HARU_SECRET": "s3cret"})
    assert ok.returncode == 0 and "PAYLOAD_UV_RAN" in ok.stdout, (ok.returncode, ok.stderr)

    legacy = run(exe, tmp_path, env_extra={"HARUPACK_SECRET": "s3cret"})
    assert legacy.returncode == EXIT_NO_SECRET, (legacy.returncode, legacy.stderr)
    assert "HARU_SECRET" in legacy.stderr
    assert "PAYLOAD_UV_RAN" not in legacy.stdout


@pytest.mark.invariant("INV-CANARY-01")
def test_per_knob_secret_canary_override(launcher, tmp_path):
    """A per-knob override (secret canary = MARK) makes the key read MARK_SECRET and ONLY
    that: HARU_SECRET is then invalid for it. Proves the SECRET knob reads exactly
    <canary.secret>_SECRET, resolved from the stub-config."""
    src = make_payload(tmp_path / "p")
    box = _encrypted(build_payload_zip(src))
    exe = tmp_path / "app.exe"
    build(launcher, box, exe, flags=1, stub_config=stub_toml(secret="MARK"))

    ok = run(exe, tmp_path, env_extra={"MARK_SECRET": "s3cret"})
    assert ok.returncode == 0 and "PAYLOAD_UV_RAN" in ok.stdout, (ok.returncode, ok.stderr)

    haru = run(exe, tmp_path, env_extra={"HARU_SECRET": "s3cret"})
    assert haru.returncode == EXIT_NO_SECRET, (haru.returncode, haru.stderr)
    assert "MARK_SECRET" in haru.stderr
    assert "PAYLOAD_UV_RAN" not in haru.stdout


# ------------------------------------------------------------------ INV-LAUNCH-09

@pytest.mark.invariant("INV-LAUNCH-09")
def test_inject_reaches_the_child(launcher, tmp_path):
    """Every manifest `inject` pair is set in the child environment before uv is invoked; a
    fake uv echoes them back. Values split on the FIRST '=' only. A reserved key the
    launcher also sets (HARUPACK_STAGE) is overwritten by the launcher — reserved wins."""
    uv_body = ('echo "PAYLOAD_UV_RAN"\n'
               'echo "INJ_ONE=$INJ_ONE"\n'
               'echo "INJ_TWO=$INJ_TWO"\n'
               'echo "STAGE=$HARUPACK_STAGE"\nexit 0')
    manifest_extra = 'inject = ["INJ_ONE=hello", "INJ_TWO=a=b=c", "HARUPACK_STAGE=PWNED"]\n'
    src = make_payload(tmp_path / "p", uv_body=uv_body, manifest_extra=manifest_extra)
    exe = tmp_path / "app.exe"
    build(launcher, build_payload_zip(src), exe, stub_config=stub_toml())
    r = run(exe, tmp_path)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "INJ_ONE=hello" in r.stdout, r.stdout
    assert "INJ_TWO=a=b=c" in r.stdout, r.stdout          # split on the FIRST '=' only
    assert "STAGE=PWNED" not in r.stdout, (
        "an inject overwrote a launcher-reserved var — the launcher's own vars must win")
    assert "PWNED" not in r.stdout

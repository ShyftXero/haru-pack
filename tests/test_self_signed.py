"""INV-SIGN-01 — --self-signed edit-detection, and its documented honest limit.

Two layers are tested here:

* **Python overlay** (`overlay.attach(sign_key=...)` / `overlay.verify`) — the v3 footer
  round-trips, a payload edit drops `sha_ok`, and an edit to the signed region drops `sig_ok`.
  No Nim needed.
* **The real launcher, end to end** — compiled, fed a self-signed build, and RUN. These are
  the ones that matter: they prove the shipped binary refuses the two attacks --self-signed
  DOES stop and — deliberately, asserted so nobody over-claims — RUNS the one it does not
  (tamper + re-sign + swap the embedded key). That last case is the honest limit in code.

The launcher tests mirror tests/test_launcher_integrity.py: a fake `uv` prints a marker so
"did it reach execution?" is observable, and the payload edit lands in a zip comment so the
extracted tree is byte-identical and only the sha256 (hence the signature) differs.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from haru_pack import overlay
from haru_pack.build.canary import resolve_canary, stub_config_bytes
from haru_pack.overlay import attach, verify
from haru_pack.payload import build_payload_zip

REPO = Path(__file__).resolve().parent.parent
LAUNCHER_SRC = REPO / "src/haru_pack/launcher/main.nim"
ED25519_TEST = REPO / "tests/launcher_ed25519_test.nim"

EXIT_DIGEST_MISMATCH = 6
EXIT_BAD_SIGNATURE = 13

# A cleartext stub-config is what makes a build v2/v3 (signing requires the stub locator). Use
# the real builder so the launcher's parser (which requires a [canary] table) accepts it.
STUB = stub_config_bytes(resolve_canary())


# ----------------------------------------------------------- Python overlay layer

def test_overlay_self_signed_roundtrips(tmp_path):
    stub = tmp_path / "stub"; stub.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    payload = b"PK\x03\x04" + bytes(range(256)) * 4
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "app"
    info = attach(stub, payload, out, stub_config=STUB, sign_key=key)
    assert info["format_ver"] == 3
    assert info["self_signed"] is True
    got = verify(out)
    assert got["format_ver"] == 3
    assert got["sha_ok"] is True and got["stub_ok"] is True
    assert got["sig_ok"] is True
    # the receipt fingerprint is sha256 of the raw public key
    want_fp = hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest()
    assert got["pubkey_sha256"] == want_fp == info["pubkey_sha256"]


def test_overlay_payload_edit_drops_sha_ok(tmp_path):
    stub = tmp_path / "stub"; stub.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    payload = b"PK\x03\x04" + bytes(range(256)) * 4
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "app"
    info = attach(stub, payload, out, stub_config=STUB, sign_key=key)
    data = bytearray(out.read_bytes())
    data[info["payload_off"] + 10] ^= 0xFF
    out.write_bytes(bytes(data))
    got = verify(out)
    assert got["sha_ok"] is False          # digest caught it (INV-LAUNCH-01 layer)


def test_overlay_signed_region_edit_drops_sig_ok(tmp_path):
    """Flip a byte inside the SIGNED region (the payload digest) without re-signing: the
    signature must no longer verify. This is the property the digest alone cannot give."""
    stub = tmp_path / "stub"; stub.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    payload = b"PK\x03\x04" + bytes(range(256)) * 4
    key = Ed25519PrivateKey.generate()
    out = tmp_path / "app"
    attach(stub, payload, out, stub_config=STUB, sign_key=key)
    data = bytearray(out.read_bytes())
    i = data.rfind(overlay.MAGIC)
    data[i + overlay._SIGNED_OFF + 30] ^= 0xFF   # a payloadSha byte, inside footer[8:108]
    out.write_bytes(bytes(data))
    assert verify(out)["sig_ok"] is False


def test_overlay_refuses_self_signed_without_stub(tmp_path):
    stub = tmp_path / "stub"; stub.write_bytes(b"\x7fELF" + b"\x00" * 64)
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="requires a stub-config"):
        attach(stub, b"payload", tmp_path / "o", sign_key=key)


# ----------------------------------------------------------- launcher, end to end

pytestmark_nim = pytest.mark.skipif(shutil.which("nim") is None,
                                    reason="nim not installed; the launcher cannot be built")


def _compile(out: Path, src: Path, *defines: str) -> Path:
    args = ["nim", "c", "-d:release", "--hints:off",
            f"--nimcache:{out.parent / ('nc-' + out.name)}", f"--out:{out}",
            *[f"-d:{d}" for d in defines], str(src)]
    r = subprocess.run(args, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0 or not out.exists():
        pytest.fail("nim compile failed:\n" + (r.stderr or r.stdout)[-3000:])
    return out


@pytest.fixture(scope="session")
def launcher(tmp_path_factory) -> Path:
    return _compile(tmp_path_factory.mktemp("nim") / "launcher", LAUNCHER_SRC)


def _fake_uv(path: Path, marker: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\necho "{marker}"\nexit 0\n')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _payload_dir(root: Path, marker: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app").mkdir(exist_ok=True)
    (root / "app" / "hello.py").write_text("print('hi')\n")
    (root / "manifest.toml").write_text(
        'name = "t"\nkind = "script"\napp_subdir = "app"\n'
        'entrypoint = ["hello.py"]\ntier = "default"\n'
        "fetch_uv = false\noffline = false\n")
    _fake_uv(root / "vendor" / "uv", marker)
    return root


def _commented_payload(tmp_path, marker="PAYLOAD_UV_RAN") -> bytes:
    src = _payload_dir(tmp_path / "payload", marker)
    z = build_payload_zip(src)
    buf = io.BytesIO(z)
    with zipfile.ZipFile(buf, "a") as zf:
        zf.comment = b"C" * 64
    return buf.getvalue()


def _run(exe: Path, tmp_path: Path):
    cache = tmp_path / "cache"; cache.mkdir(exist_ok=True)
    (tmp_path / "home").mkdir(exist_ok=True)
    env = {"HOME": str(tmp_path / "home"), "XDG_CACHE_HOME": str(cache), "PATH": ""}
    return subprocess.run([str(exe)], capture_output=True, text=True, cwd=tmp_path,
                          env=env, umask=0o022)


def _flip_comment_byte(data: bytearray, info: dict) -> None:
    """Flip a byte inside the zip's trailing comment — extraction stays byte-identical."""
    pos = info["payload_off"] + info["payload_len"] - 16
    data[pos] ^= 0xFF


def _footer_at(data: bytes) -> int:
    return data.rfind(overlay.MAGIC)


def _set_payload_sha(data: bytearray, new_payload: bytes) -> None:
    i = _footer_at(data)
    data[i + 28:i + 60] = hashlib.sha256(new_payload).digest()


def _resign(data: bytearray, key: Ed25519PrivateKey, *, embed_pubkey: bool) -> None:
    i = _footer_at(data)
    signed = bytes(data[i + overlay._SIGNED_OFF:i + overlay._SIGNED_END])
    sig = key.sign(signed)
    data[i + overlay._SIG_OFF:i + overlay._SIG_END] = sig
    if embed_pubkey:
        data[i + overlay._PUBKEY_OFF:i + overlay._PUBKEY_END] = key.public_key().public_bytes_raw()


def _build(launcher: Path, payload: bytes, out: Path, key: Ed25519PrivateKey | None) -> dict:
    info = attach(launcher, payload, out, stub_config=STUB, sign_key=key)
    out.chmod(0o755)
    return info


@pytestmark_nim
def test_launcher_ed25519_matches_rfc8032(tmp_path):
    """The vendored Nim verifier agrees with the RFC 8032 §7.1 vectors and rejects a flipped
    signature / wrong message. If this port is wrong, everything below is meaningless."""
    exe = _compile(tmp_path / "ed", ED25519_TEST)
    r = subprocess.run([str(exe)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL OK" in r.stdout


@pytestmark_nim
@pytest.mark.invariant("INV-SIGN-01")
def test_intact_self_signed_build_runs(launcher, tmp_path):
    key = Ed25519PrivateKey.generate()
    exe = tmp_path / "app.exe"
    _build(launcher, _commented_payload(tmp_path), exe, key)
    r = _run(exe, tmp_path)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert r.returncode == 0


@pytestmark_nim
@pytest.mark.invariant("INV-SIGN-01")
def test_v2_unsigned_build_still_loads(launcher, tmp_path):
    """Regression: a v2 (unsigned, stub-carrying) binary must keep loading unchanged after
    the v3 footer landed. The format dispatch, not a rebuild, is what protects it."""
    exe = tmp_path / "app.exe"
    info = _build(launcher, _commented_payload(tmp_path), exe, None)
    assert info["format_ver"] == 2
    r = _run(exe, tmp_path)
    assert "PAYLOAD_UV_RAN" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert r.returncode == 0


@pytestmark_nim
@pytest.mark.invariant("INV-SIGN-01")
def test_case_i_tamper_and_repack_digest_but_no_resign_is_refused(launcher, tmp_path):
    """(i) Edit the payload after signing and recompute the footer digest so INV-LAUNCH-01's
    check passes — but do NOT re-sign. The signature must catch it (exit 13), which is exactly
    the value --self-signed adds over the bare digest."""
    key = Ed25519PrivateKey.generate()
    exe = tmp_path / "app.exe"
    info = _build(launcher, _commented_payload(tmp_path), exe, key)
    data = bytearray(exe.read_bytes())
    _flip_comment_byte(data, info)
    edited = bytes(data[info["payload_off"]:info["payload_off"] + info["payload_len"]])
    _set_payload_sha(data, edited)                 # digest check would now PASS
    exe.write_bytes(bytes(data)); exe.chmod(0o755)
    r = _run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_SIGNATURE, (r.returncode, r.stdout, r.stderr)
    assert "signature check FAILED" in r.stderr
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytestmark_nim
@pytest.mark.invariant("INV-SIGN-01")
def test_case_ii_resign_with_other_key_without_swapping_pubkey_is_refused(launcher, tmp_path):
    """(ii) Edit, recompute the digest, and re-sign with a DIFFERENT key — but leave the
    embedded public key alone. The signature no longer matches the embedded key: exit 13."""
    key = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    exe = tmp_path / "app.exe"
    info = _build(launcher, _commented_payload(tmp_path), exe, key)
    data = bytearray(exe.read_bytes())
    _flip_comment_byte(data, info)
    edited = bytes(data[info["payload_off"]:info["payload_off"] + info["payload_len"]])
    _set_payload_sha(data, edited)
    _resign(data, attacker, embed_pubkey=False)    # sign with attacker key, keep vendor pubkey
    exe.write_bytes(bytes(data)); exe.chmod(0o755)
    r = _run(exe, tmp_path)
    assert r.returncode == EXIT_BAD_SIGNATURE, (r.returncode, r.stdout, r.stderr)
    assert "PAYLOAD_UV_RAN" not in r.stdout


@pytestmark_nim
@pytest.mark.invariant("INV-SIGN-01")
def test_case_iii_resign_and_swap_pubkey_PASSES_the_documented_limit(launcher, tmp_path):
    """(iii) THE HONEST LIMIT, asserted so nobody claims otherwise. Edit, recompute the digest,
    re-sign with the attacker's key, AND swap the embedded public key to the attacker's. The
    launcher runs it — because the public key lives in the same file. --self-signed is
    edit-detection, NOT tamper-evidence, unless the fingerprint is pinned out of band."""
    key = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    exe = tmp_path / "app.exe"
    info = _build(launcher, _commented_payload(tmp_path), exe, key)
    data = bytearray(exe.read_bytes())
    _flip_comment_byte(data, info)                  # a real payload edit (benign, so it runs)
    edited = bytes(data[info["payload_off"]:info["payload_off"] + info["payload_len"]])
    _set_payload_sha(data, edited)
    _resign(data, attacker, embed_pubkey=True)     # re-sign AND swap the embedded key
    exe.write_bytes(bytes(data)); exe.chmod(0o755)
    r = _run(exe, tmp_path)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "PAYLOAD_UV_RAN" in r.stdout, (
        "the documented limit did not hold as described — a tamper + re-sign + key-swap must "
        "PASS. If this stops passing, the honest limit in docs/SIGNING.md and INV-SIGN-01 is "
        "now wrong and must be re-examined")

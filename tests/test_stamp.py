"""overlay.stamp round-trip: re-stamp changes the stub-config, payload is preserved.

One runnable check that fails if stamp/readback round-trips wrong (issue #80).
No Nim required — fake launcher bytes are sufficient to exercise the Python path.
Issue #83 adds three inject tests at the bottom: round-trip, reserved-key refusal,
and secret-shape warning (unencrypted) / silence (encrypted).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from haru_pack.overlay import FOOTER_FLAG_ENCRYPTED, FOOTER_FLAG_REMOTE, attach, stamp, verify


@pytest.fixture
def base_exe(tmp_path: Path) -> tuple[Path, bytes, bytes]:
    """A minimal haru-pack binary: tiny fake ELF + small fake payload + stub-config."""
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 64)
    payload = b"PK\x03\x04" + b"\xab" * 128
    stub1 = (
        b'stub_config_version = 1\n\n[canary]\n'
        b'secret = "HARU"\nuv_ver = "HARU"\n'
        b'source_url = "HARU"\nbase_path = "HARU"\n'
    )
    out = tmp_path / "base.exe"
    attach(launcher, payload, out, stub_config=stub1)
    return out, payload, stub1


def test_stamp_produces_valid_footer(base_exe, tmp_path):
    """verify() accepts the stamped binary and reports both digests as OK."""
    src, payload, _ = base_exe
    stub2 = (
        b'stub_config_version = 1\n\n[canary]\n'
        b'secret = "CUST001"\nuv_ver = "HARU"\n'
        b'source_url = "HARU"\nbase_path = "HARU"\n'
    )
    out = tmp_path / "cust001.exe"
    stamp(src, stub2, out)
    info = verify(out)
    assert info["sha_ok"], "payload digest mismatch after stamp"
    assert info["stub_ok"], "stub-config digest mismatch after stamp"


def test_stamp_preserves_payload(base_exe, tmp_path):
    """Payload bytes and their sha256 are identical before and after stamp."""
    src, payload, _ = base_exe
    stub2 = b'stub_config_version = 1\n\n[canary]\nsecret = "X"\nuv_ver = "X"\nsource_url = "X"\nbase_path = "X"\n'
    out = tmp_path / "stamped.exe"
    result = stamp(src, stub2, out)
    assert result["payload_len"] == len(payload)
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()


def test_stamp_replaces_stub_config(base_exe, tmp_path):
    """The new canary token appears in the stamped binary's stub-config."""
    src, _, _ = base_exe
    stub2 = b'stub_config_version = 1\n\n[canary]\nsecret = "NEWCANARY"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    out = tmp_path / "stamped.exe"
    stamp(src, stub2, out)
    info = verify(out)
    assert 'secret = "NEWCANARY"' in info["stub_config"]


def test_stamp_overwrites_src_in_place(base_exe):
    """stamp(src, new, src) is safe — read completes before write."""
    src, payload, _ = base_exe
    stub2 = b'stub_config_version = 1\n\n[canary]\nsecret = "INPLACE"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    stamp(src, stub2, src)  # out == src
    info = verify(src)
    assert info["sha_ok"] and info["stub_ok"]
    assert 'secret = "INPLACE"' in info["stub_config"]
    assert info["payload_len"] == len(payload)


def test_stamp_v1_binary_becomes_v2(tmp_path):
    """Stamping a v1 (no stub-config) binary produces a valid v2 binary."""
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 32)
    payload = b"PK" + b"\xcd" * 64
    out_v1 = tmp_path / "v1.exe"
    attach(launcher, payload, out_v1)   # v1: no stub_config argument
    assert verify(out_v1)["format_ver"] == 1

    stub = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    out_v2 = tmp_path / "v2.exe"
    stamp(out_v1, stub, out_v2)
    info = verify(out_v2)
    assert info["format_ver"] == 2
    assert info["sha_ok"] and info["stub_ok"]


def test_stamp_refuses_corrupt_binary(tmp_path):
    """stamp raises ValueError on a binary whose payload digest does not match."""
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 32)
    payload = b"PK" + b"\xff" * 64
    out = tmp_path / "good.exe"
    attach(launcher, payload, out)

    # Corrupt one payload byte
    data = bytearray(out.read_bytes())
    info = verify(out)
    data[info["payload_off"]] ^= 0xFF
    out.write_bytes(bytes(data))

    stub = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    with pytest.raises(ValueError, match="digest mismatch"):
        stamp(out, stub, tmp_path / "stamped.exe")


def test_stamp_preserves_encrypted_flag(tmp_path):
    """The ENCRYPTED flag bit in the footer is preserved during stamp."""
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 32)
    payload = b"ENCRYPTED_CONTAINER" + b"\x00" * 32
    stub1 = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    out = tmp_path / "enc.exe"
    attach(launcher, payload, out, flags=FOOTER_FLAG_ENCRYPTED, stub_config=stub1)

    stub2 = b'stub_config_version = 1\n\n[canary]\nsecret = "CUST"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    stamped = tmp_path / "enc_stamped.exe"
    stamp(out, stub2, stamped)
    assert verify(stamped)["flags"] & FOOTER_FLAG_ENCRYPTED


def test_stamp_refuses_remote_binary(tmp_path):
    """stamp raises ValueError on a remote-fetch binary (FOOTER_FLAG_REMOTE)."""
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 32)
    payload = b"PK" + b"\xab" * 64
    stub1 = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    out = tmp_path / "remote.exe"
    attach(launcher, payload, out, stub_config=stub1, remote=True)

    stub2 = b'stub_config_version = 1\n\n[canary]\nsecret = "CUST"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    with pytest.raises(ValueError, match="remote-fetch"):
        stamp(out, stub2, tmp_path / "stamped.exe")


def test_stamp_refuses_corrupt_v3_stub(tmp_path):
    """stamp raises ValueError on a v3 (self-signed) binary with a corrupt stub-config."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        pytest.skip("cryptography not available")

    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 32)
    payload = b"PK" + b"\xcd" * 64
    stub1 = b'stub_config_version = 1\n\n[canary]\nsecret = "HARU"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    sign_key = Ed25519PrivateKey.generate()
    out = tmp_path / "signed.exe"
    attach(launcher, payload, out, stub_config=stub1, sign_key=sign_key)

    # Corrupt one byte in the stub-config region
    data = bytearray(out.read_bytes())
    info = verify(out)
    data[info["stub_off"]] ^= 0xFF
    out.write_bytes(bytes(data))

    stub2 = b'stub_config_version = 1\n\n[canary]\nsecret = "CUST"\nuv_ver = "HARU"\nsource_url = "HARU"\nbase_path = "HARU"\n'
    with pytest.raises(ValueError, match="digest mismatch"):
        stamp(out, stub2, tmp_path / "stamped.exe")


# ------------------------------------------------------------------ issue #83: --inject

def _make_base_exe(tmp_path: Path) -> tuple[Path, bytes]:
    launcher = tmp_path / "launcher"
    launcher.write_bytes(b"\x7fELF" + b"\x00" * 64)
    payload = b"PK\x03\x04" + b"\xab" * 128
    stub = (
        b'stub_config_version = 1\n\n[canary]\n'
        b'secret = "HARU"\nuv_ver = "HARU"\n'
        b'source_url = "HARU"\nbase_path = "HARU"\n'
    )
    out = tmp_path / "base.exe"
    attach(launcher, payload, out, stub_config=stub)
    return out, payload


def test_stamp_inject_round_trips_into_stub_config(tmp_path):
    """[inject] values appear in the re-read stub-config; payload is byte-identical."""
    from haru_pack.build.canary import stub_config_bytes
    src, payload = _make_base_exe(tmp_path)
    canary = {"secret": "HARU", "uv_ver": "HARU", "source_url": "HARU", "base_path": "HARU"}
    sc = stub_config_bytes(canary, inject=["LOTEK_RUNNER_TOKEN=abc123",
                                           "LOTEK_RUNNER_ID=device42"])
    out = tmp_path / "stamped.exe"
    result = stamp(src, sc, out)
    info = verify(out)
    assert info["sha_ok"] and info["stub_ok"]
    assert 'LOTEK_RUNNER_TOKEN = "abc123"' in info["stub_config"]
    assert 'LOTEK_RUNNER_ID = "device42"' in info["stub_config"]
    # payload unchanged
    assert result["payload_len"] == len(payload)


def test_stamp_inject_reserved_key_refused(tmp_path):
    """resolve_injects() refuses HARUPACK_* and reserved UV_* keys for --inject."""
    from haru_pack.build.inject import resolve_injects
    from haru_pack.build.errors import BuildError
    with pytest.raises(BuildError, match="reserved key"):
        resolve_injects(["HARUPACK_STAGE=pwned"], encrypted=False)
    with pytest.raises(BuildError, match="reserved key"):
        resolve_injects(["UV_PYTHON=evil"], encrypted=False)


def test_stamp_inject_secret_shaped_warns_unencrypted_silent_encrypted(tmp_path):
    """secret-shaped inject warns on unencrypted builds and is silent on encrypted ones."""
    from haru_pack.build.inject import resolve_injects
    log: list[str] = []
    resolve_injects(["API_TOKEN=abcdefghij0123456789KLMN"], encrypted=False, log=log.append)
    assert any("WARNING" in m and "secret-shaped" in m for m in log), log

    log.clear()
    resolve_injects(["API_TOKEN=abcdefghij0123456789KLMN"], encrypted=True, log=log.append)
    assert not any("WARNING" in m for m in log)

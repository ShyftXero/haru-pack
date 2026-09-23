"""--self-signed key storage: permissions, fail-hard-on-missing, no silent rotation.

These guard the two decisions in `build/signing.py` that are security posture, not
convenience: a build never mints a key (so an ephemeral CI home cannot rotate it silently),
and a group/world-readable key is refused rather than used.
"""
from __future__ import annotations

import os
import stat

import pytest

from haru_pack.build import signing
from haru_pack.build.signing import SigningError

pytestmark = pytest.mark.skipif(os.name != "posix",
                                reason="POSIX permission bits; keystore perms are POSIX-only")


def test_generate_writes_0600_key_in_0700_dir(tmp_path):
    keydir = tmp_path / "ks"
    path = keydir / "key"
    _, fp = signing.generate_key(path)
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(keydir.stat().st_mode) == 0o700
    assert len(fp) == 64 and int(fp, 16) >= 0        # sha256 hex fingerprint
    assert len(path.read_bytes()) == 32              # raw Ed25519 seed


def test_load_roundtrips_the_same_fingerprint(tmp_path):
    path = tmp_path / "key"
    _, fp_gen = signing.generate_key(path)
    _, fp_load = signing.load_key(path)
    assert fp_gen == fp_load


def test_generate_refuses_to_overwrite_without_force(tmp_path):
    path = tmp_path / "key"
    signing.generate_key(path)
    with pytest.raises(SigningError, match="already exists"):
        signing.generate_key(path)
    # force rotates deliberately, and to a different key
    _, fp1 = signing.load_key(path)
    _, fp2 = signing.generate_key(path, overwrite=True)
    assert fp1 != fp2


def test_load_refuses_group_or_world_readable_key(tmp_path):
    path = tmp_path / "key"
    signing.generate_key(path)
    os.chmod(path, 0o644)                              # group/other can read it now
    with pytest.raises(SigningError, match="group/other-accessible"):
        signing.load_key(path)


def test_load_refuses_a_non_32_byte_file(tmp_path):
    path = tmp_path / "key"
    path.write_bytes(b"not a key")
    os.chmod(path, 0o600)
    with pytest.raises(SigningError, match="32-byte"):
        signing.load_key(path)


def test_load_signing_key_fails_hard_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    project = tmp_path / "proj"; project.mkdir()
    with pytest.raises(SigningError) as ei:
        signing.load_signing_key(project)
    msg = str(ei.value)
    assert "does not mint one during a build" in msg    # explains the no-rotate stance
    assert "haru-pack keygen" in msg                     # tells the operator what to do


def test_load_signing_key_uses_explicit_sign_key_path(tmp_path):
    keypath = tmp_path / "mine.key"
    _, fp = signing.generate_key(keypath)
    project = tmp_path / "proj"; project.mkdir()
    key, got_fp, used = signing.load_signing_key(project, str(keypath))
    assert got_fp == fp
    assert used == keypath


def test_default_key_path_is_per_project_and_under_xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    pa = signing.default_key_path(a)
    pb = signing.default_key_path(b)
    assert str(pa).startswith(str(tmp_path / "cfg" / "haru-pack"))
    assert pa != pb                                      # different projects, different keys
    assert signing.default_key_path(a) == pa             # stable for the same project


# ----------------------------------------------------- --sign-key: OpenSSH Ed25519 keys (#71)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402


def _write_0600(path, data: bytes):
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def _openssh_ed25519(path, key, passphrase: bytes | None = None):
    enc = (serialization.BestAvailableEncryption(passphrase) if passphrase
           else serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.OpenSSH, enc)
    return _write_0600(path, pem)


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes_raw()


def test_sign_key_accepts_openssh_ed25519_and_embeds_that_pubkey(tmp_path):
    """An OpenSSH Ed25519 --sign-key yields the SAME embedded pubkey/fingerprint as the raw
    seed of that key — i.e. the key a dev publishes at github.com/<user>.keys."""
    key = ed25519.Ed25519PrivateKey.generate()
    path = _openssh_ed25519(tmp_path / "id_ed25519", key)
    loaded, fp = signing.load_key(path)
    assert _raw_pub(loaded) == _raw_pub(key)                 # embedded pubkey == the SSH pubkey
    assert fp == signing.fingerprint(_raw_pub(key))


def test_sign_key_openssh_signs_byte_identically_to_the_raw_seed(tmp_path):
    """The OpenSSH path re-derives the raw seed and signs EXACTLY as the keystore path — so a
    --self-signed build stays byte-reproducible regardless of which file shape carried the key."""
    key = ed25519.Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    ssh = signing.load_key(_openssh_ed25519(tmp_path / "id_ed25519", key))[0]
    raw = signing.load_key(_write_0600(tmp_path / "seed", seed))[0]
    msg = b"\x03\x00" + b"haru-pack footer signed region" * 3
    assert ssh.sign(msg) == raw.sign(msg)                    # deterministic + same seed


def test_raw_32_byte_seed_still_works(tmp_path):
    """Regression: the pre-#71 raw-seed file shape keeps loading unchanged."""
    key = ed25519.Ed25519PrivateKey.generate()
    path = _write_0600(tmp_path / "seed", key.private_bytes_raw())
    loaded, fp = signing.load_key(path)
    assert _raw_pub(loaded) == _raw_pub(key)


def test_passphrase_protected_openssh_via_env(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _openssh_ed25519(tmp_path / "id_ed25519", key, passphrase=b"correct horse")
    monkeypatch.setenv("HP_PASS", "correct horse")
    project = tmp_path / "proj"; project.mkdir()
    loaded, fp, used = signing.load_signing_key(project, str(path), passphrase_env="HP_PASS")
    assert _raw_pub(loaded) == _raw_pub(key)
    assert used == path


def test_passphrase_wrong_gives_clear_error(tmp_path, monkeypatch):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _openssh_ed25519(tmp_path / "id_ed25519", key, passphrase=b"correct horse")
    monkeypatch.setenv("HP_PASS", "WRONG")
    project = tmp_path / "proj"; project.mkdir()
    with pytest.raises(SigningError, match="passphrase.*wrong|wrong"):
        signing.load_signing_key(project, str(path), passphrase_env="HP_PASS")


def test_passphrase_missing_on_encrypted_key_is_refused_not_prompted(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _openssh_ed25519(tmp_path / "id_ed25519", key, passphrase=b"correct horse")
    with pytest.raises(SigningError, match="passphrase-protected"):
        signing.load_key(path)                               # no passphrase supplied


def test_passphrase_env_unset_is_refused(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    path = _openssh_ed25519(tmp_path / "id_ed25519", key, passphrase=b"pw")
    project = tmp_path / "proj"; project.mkdir()
    with pytest.raises(SigningError, match="is not set"):
        signing.load_signing_key(project, str(path), passphrase_env="DEFINITELY_UNSET_VAR")


def test_rsa_openssh_key_is_refused_not_minted(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption())
    path = _write_0600(tmp_path / "id_rsa", pem)
    with pytest.raises(SigningError, match="not Ed25519"):
        signing.load_key(path)


def test_ecdsa_openssh_key_is_refused_not_minted(tmp_path):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = ec_key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.OpenSSH,
                              serialization.NoEncryption())
    path = _write_0600(tmp_path / "id_ecdsa", pem)
    with pytest.raises(SigningError, match="not Ed25519"):
        signing.load_key(path)


def test_public_key_file_is_refused(tmp_path):
    """A `.pub` (or any non-private-key) file must be refused, not silently accepted — this is
    the shape an agent-only key leaves on disk."""
    key = ed25519.Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                        serialization.PublicFormat.OpenSSH)
    path = _write_0600(tmp_path / "id_ed25519.pub", pub)
    with pytest.raises(SigningError):
        signing.load_key(path)

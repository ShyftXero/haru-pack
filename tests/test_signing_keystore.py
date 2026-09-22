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

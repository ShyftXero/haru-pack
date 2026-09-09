"""INV-BUILD-01, INV-BUILD-02, INV-SECRET-02 — the build reports what it did.

Red-path for INV-BUILD-02: revert the `encrypt` parameter threaded through
`cli.build -> build.build -> build._resolve` and restore the old enablement rule

    "enabled": bool(e.get("enabled")) or any([expires, geo, machine, user, embed_secret])

then `test_bare_encrypt_flag_actually_encrypts` goes red — which is precisely what the
shipped code did before 2026-09-09, including in a documented example.
"""
from __future__ import annotations

import zipfile

import pytest

from haru_pack import crypto
from haru_pack.build import BuildError, _resolve
from haru_pack.overlay import verify


def _payload_bytes(exe):
    info = verify(exe)
    data = exe.read_bytes()
    return data[info["payload_off"]:info["payload_off"] + info["payload_len"]]


@pytest.mark.invariant("INV-BUILD-02")
def test_bare_encrypt_flag_actually_encrypts(stub_toolchain, script_project, tmp_path):
    """`--encrypt --secret X` with no policy flag must produce an encrypted payload."""
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin",
                                secret=b"hunter2", encrypt=True)
    assert info["encrypted"] is True
    assert _payload_bytes(out).startswith(crypto.MAGIC), (
        "the build reported success with a plaintext payload — this is the C1 regression"
    )


@pytest.mark.invariant("INV-BUILD-02")
def test_encrypt_without_a_secret_fails_loudly(stub_toolchain, script_project, tmp_path):
    """The only alternative to encrypting is a non-zero exit. Never a silent downgrade."""
    with pytest.raises(BuildError, match="no secret"):
        stub_toolchain.build(script_project, tmp_path / "app", tier="thin",
                             secret=None, encrypt=True)


# (expires, geo, machine, user, embed_secret, encrypt) — the six documented triggers
_TRIGGERS = {
    "encrypt":       ("", [], "", "", False, True),
    "expires":       ("2099-01-01", [], "", "", False, False),
    "geo":           ("", ["US"], "", "", False, False),
    "machine":       ("", [], "abc123", "", False, False),
    "user":          ("", [], "", "alice", False, False),
    "embed_secret":  ("", [], "", "", True, False),
}


@pytest.mark.invariant("INV-BUILD-02")
@pytest.mark.parametrize("trigger", sorted(_TRIGGERS))
def test_every_documented_trigger_enables_encryption(script_project, trigger):
    """Each flag the README documents as implying encryption must actually imply it.

    `--encrypt` alone was the one that did not, for the whole life of the feature.
    """
    args = _TRIGGERS[trigger]
    _, enc, _, _ = _resolve(script_project, "thin", "", *args)
    assert enc["enabled"] is True, f"--{trigger} does not enable encryption"


@pytest.mark.invariant("INV-BUILD-02")
def test_no_trigger_means_no_encryption(script_project):
    """The converse: a build that asked for nothing must not silently encrypt."""
    _, enc, _, _ = _resolve(script_project, "thin", "", "", [], "", "", False, False)
    assert enc["enabled"] is False


@pytest.mark.invariant("INV-BUILD-01")
def test_unencrypted_build_does_not_claim_encryption(stub_toolchain, script_project, tmp_path):
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin")
    assert info["encrypted"] is False
    body = _payload_bytes(out)
    assert not body.startswith(crypto.MAGIC)
    assert zipfile.is_zipfile(out.parent / out.name) or body[:2] == b"PK", (
        "an unencrypted payload should be a plain zip"
    )


@pytest.mark.invariant("INV-BUILD-01")
def test_receipt_cannot_lie_about_encryption(stub_toolchain, script_project, tmp_path,
                                             monkeypatch):
    """Neutralize the encryption step while leaving the request in place; the build must
    refuse rather than emit a binary whose receipt says 'encrypted'."""
    monkeypatch.setattr(crypto, "encrypt", lambda payload, secret, **kw: payload)
    monkeypatch.setattr(stub_toolchain.crypto, "encrypt", lambda payload, secret, **kw: payload)
    with pytest.raises(BuildError, match="does not match the payload"):
        stub_toolchain.build(script_project, tmp_path / "app", tier="thin",
                             secret=b"hunter2", encrypt=True)


@pytest.mark.invariant("INV-SECRET-02")
def test_secret_never_lands_in_a_produced_artifact(stub_toolchain, script_project, tmp_path):
    secret = b"correct-horse-battery-staple"
    out = tmp_path / "app"
    info = stub_toolchain.build(script_project, out, tier="thin", secret=secret, encrypt=True)

    assert secret not in out.read_bytes(), "the build secret is present in the shipped binary"
    assert secret.decode() not in repr(info), "the build receipt leaks the secret"
    for p in script_project.rglob("*"):
        if p.is_file():
            assert secret not in p.read_bytes(), f"secret written back into the source tree: {p}"

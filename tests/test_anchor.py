"""INV-SIGN-02 — `verify --pin` anchors a build's embedded key to a published identity.

Two layers:

* **Anchor unit** (`haru_pack.anchor`) — parses a `.keys` body, resolves a --pin spec to a URL,
  and fails closed on network error / empty body / no key / no match. `_fetch` is monkeypatched
  so no test touches the network.
* **The `verify --pin` command end to end**, including the MANDATORY INV-SIGN-02 Red-path: a
  binary re-keyed to a key the pinned `.keys` does not list is refused (nonzero exit), even
  though it is internally consistent (INV-SIGN-01 would accept it — that is exactly the gap this
  closes).
"""
from __future__ import annotations

import base64
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from haru_pack import anchor, cli, overlay
from haru_pack.anchor import (
    AnchorError,
    check_embedded_pubkey,
    parse_authorized_keys,
    resolve_spec,
)
from haru_pack.build.canary import resolve_canary, stub_config_bytes
from haru_pack.overlay import attach

STUB = stub_config_bytes(resolve_canary())
runner = CliRunner()


def _keys_line(key: Ed25519PrivateKey, comment: str = "user@host") -> str:
    """The exact `ssh-ed25519 <base64> comment` line GitHub serves at /<user>.keys."""
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode() + f" {comment}"


def _pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()


# ------------------------------------------------------------------- parsing

def test_parse_extracts_ed25519_raw_pubkey():
    key = Ed25519PrivateKey.generate()
    got = parse_authorized_keys(_keys_line(key))
    assert got == [key.public_key().public_bytes_raw()]


def test_parse_ignores_non_ed25519_and_malformed_lines_safely():
    good = Ed25519PrivateKey.generate()
    body = "\n".join([
        "# a comment",
        "",
        "ssh-rsa AAAAB3NzaC1yc2E-not-really-checked rsa@host",       # wrong type -> ignored
        "ssh-ed25519 !!!not-base64!!! broken@host",                  # bad base64 -> ignored
        "ssh-ed25519 " + base64.b64encode(b"short").decode(),        # decodes but not a key
        "sk-ssh-ed25519 AAAAstuff fido@host",                        # FIDO type -> ignored
        _keys_line(good),                                            # the one real key
    ])
    assert parse_authorized_keys(body) == [good.public_key().public_bytes_raw()]


def test_parse_rejects_wire_blob_with_trailing_junk():
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes_raw()
    blob = (struct.pack(">I", 11) + b"ssh-ed25519"
            + struct.pack(">I", 32) + raw + b"TRAILING")
    line = "ssh-ed25519 " + base64.b64encode(blob).decode()
    assert parse_authorized_keys(line) == []


# ------------------------------------------------------------------- spec resolution

def test_resolve_github_spec():
    assert resolve_spec("github:octocat") == "https://github.com/octocat.keys"


def test_resolve_keys_url_requires_https():
    assert resolve_spec("keys-url:https://ex.com/k") == "https://ex.com/k"
    with pytest.raises(AnchorError, match="https"):
        resolve_spec("keys-url:http://ex.com/k")


def test_resolve_rejects_unknown_and_bad_user():
    with pytest.raises(AnchorError, match="unrecognized"):
        resolve_spec("twitter:someone")
    with pytest.raises(AnchorError, match="github user"):
        resolve_spec("github:")


# ------------------------------------------------------------------- check (fail-closed)

def test_check_matches_when_embedded_key_is_published(monkeypatch):
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(anchor, "_fetch", lambda url: _keys_line(key))
    res = check_embedded_pubkey(_pub_hex(key), "github:me")
    assert res.matched is True and res.n_keys == 1


def test_check_no_match_returns_false_not_raises(monkeypatch):
    published = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    monkeypatch.setattr(anchor, "_fetch", lambda url: _keys_line(published))
    res = check_embedded_pubkey(_pub_hex(other), "github:me")
    assert res.matched is False


def test_check_fails_closed_on_network_error(monkeypatch):
    def boom(url):
        raise AnchorError("could not fetch anchor keys from x: refused")
    monkeypatch.setattr(anchor, "_fetch", boom)
    with pytest.raises(AnchorError):
        check_embedded_pubkey(_pub_hex(Ed25519PrivateKey.generate()), "github:me")


def test_check_fails_closed_on_empty_body(monkeypatch):
    monkeypatch.setattr(anchor, "_fetch", lambda url: "   \n")
    with pytest.raises(AnchorError, match="empty body"):
        check_embedded_pubkey(_pub_hex(Ed25519PrivateKey.generate()), "github:me")


def test_check_fails_closed_on_body_with_no_ed25519_keys(monkeypatch):
    monkeypatch.setattr(anchor, "_fetch", lambda url: "ssh-rsa AAAAB3xx rsa@host\n")
    with pytest.raises(AnchorError, match="no ssh-ed25519 keys"):
        check_embedded_pubkey(_pub_hex(Ed25519PrivateKey.generate()), "github:me")


# ------------------------------------------------------------------- verify --pin, end to end

def _footer_at(data: bytes) -> int:
    return data.rfind(overlay.MAGIC)


def _signed_build(tmp_path, key: Ed25519PrivateKey):
    stub = tmp_path / "stub"; stub.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    payload = b"PK\x03\x04" + bytes(range(256)) * 4
    exe = tmp_path / "app.exe"
    attach(stub, payload, exe, stub_config=STUB, sign_key=key)
    return exe


def _rekey(exe, new_key: Ed25519PrivateKey):
    """Re-sign the build with a DIFFERENT key AND swap the embedded pubkey — the internally
    consistent forgery INV-SIGN-01 accepts (its case iii) and INV-SIGN-02 must catch."""
    data = bytearray(exe.read_bytes())
    i = _footer_at(data)
    signed = bytes(data[i + overlay._SIGNED_OFF:i + overlay._SIGNED_END])
    data[i + overlay._SIG_OFF:i + overlay._SIG_END] = new_key.sign(signed)
    data[i + overlay._PUBKEY_OFF:i + overlay._PUBKEY_END] = new_key.public_key().public_bytes_raw()
    exe.write_bytes(bytes(data))


def test_verify_pin_matches_a_published_key(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    exe = _signed_build(tmp_path, key)
    monkeypatch.setattr(anchor, "_fetch", lambda url: _keys_line(key))
    r = runner.invoke(cli.app, ["verify", str(exe), "--pin", "github:me"])
    assert r.exit_code == 0, r.output
    assert "anchor: OK" in r.output


@pytest.mark.invariant("INV-SIGN-02")
def test_rekeyed_binary_not_in_keys_is_refused(tmp_path, monkeypatch):
    """MANDATORY Red-path. A build signed by A, then re-keyed to B (re-signed + embedded key
    swapped so the signature is internally valid — INV-SIGN-01 accepts it), pinned to a `.keys`
    that lists A but NOT B: `verify --pin` must refuse with a nonzero exit. Neutralize the check
    in anchor.py and this flips to exit 0."""
    vendor = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    exe = _signed_build(tmp_path, vendor)
    _rekey(exe, attacker)                                   # now signed by, and embeds, attacker
    # sanity: the tampered binary is internally consistent (sig verifies under embedded key)
    assert overlay.verify(exe)["sig_ok"] is True
    assert overlay.verify(exe)["pubkey"] == _pub_hex(attacker)
    # the pinned identity publishes only the vendor's key
    monkeypatch.setattr(anchor, "_fetch", lambda url: _keys_line(vendor))
    r = runner.invoke(cli.app, ["verify", str(exe), "--pin", "github:vendor"])
    assert r.exit_code != 0, r.output
    assert "anchor: FAILED" in r.output
    assert "does not publish" in r.output


def test_verify_pin_fails_closed_on_network_error(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    exe = _signed_build(tmp_path, key)

    def boom(url):
        raise AnchorError("could not fetch anchor keys: connection refused")
    monkeypatch.setattr(anchor, "_fetch", boom)
    r = runner.invoke(cli.app, ["verify", str(exe), "--pin", "github:me"])
    assert r.exit_code != 0, r.output
    assert "anchor: FAILED" in r.output


def test_verify_pin_on_unsigned_build_is_refused(tmp_path):
    """A v2 (unsigned) build has no embedded key; --pin must refuse rather than pass vacuously."""
    stub = tmp_path / "stub"; stub.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    exe = tmp_path / "app.exe"
    attach(stub, b"PK\x03\x04payload", exe, stub_config=STUB)   # no sign_key -> v2
    r = runner.invoke(cli.app, ["verify", str(exe), "--pin", "github:me"])
    assert r.exit_code != 0, r.output
    assert "nothing to anchor" in r.output

"""Anchored verification: is a build's EMBEDDED signing key one the pinned identity publishes?

`--self-signed` alone is edit-detection, not tamper-evidence: the public key rides in the same
file as the signature, so an attacker who re-signs an edited payload and swaps the embedded key
verifies fine (INV-SIGN-01's documented limit). The missing half is an OUT-OF-BAND anchor — a
copy of the trusted key the attacker cannot rewrite. This module fetches that copy from a
channel tied to the dev's identity (their GitHub `.keys`, served over TLS, or an org's own HTTPS
key list) and checks the build's embedded pubkey against it. A match upgrades the build from
edit-detection to identity-anchored provenance (INV-SIGN-02).

Honest limit, stated so it is not over-claimed (INV-DOC-02): the anchor is only as strong as
GitHub-account + TLS trust. An attacker who takes over the account, or presents a mis-issued
certificate for the host, forges the anchor. This is a real, useful reduction of trust — not an
elimination of it. The launcher itself still pins NOTHING (INV-SIGN-01 is unchanged); this is a
guarantee the `verify` TOOL provides to a recipient who runs haru-pack, not something a bare exe
does for a recipient who does not.

Everything here FAILS CLOSED: a network error, an empty body, a body with no usable key, a
malformed embedded pubkey, or no match all deny the anchor. stdlib `urllib` is used on purpose —
its default TLS uses the system trust store, sidestepping any bundled-CA question.
"""
from __future__ import annotations

import base64
import binascii
import struct
import urllib.error
import urllib.request
from dataclasses import dataclass

_TIMEOUT = 30
_MAX_BODY = 1 << 20            # 1 MiB — a .keys list is a few KiB; cap a hostile/huge response


class AnchorError(Exception):
    """A --pin anchor could not be established: network, empty/malformed source, or bad input.

    A NO-MATCH is NOT raised as this — it is a legitimate, well-formed answer of "no". The CLI
    treats both an AnchorError and a no-match as failure (nonzero exit); both are fail-closed."""


@dataclass
class AnchorResult:
    matched: bool
    url: str
    n_keys: int             # how many ssh-ed25519 keys the source published (and we checked)


def _read_ssh_string(blob: bytes, off: int) -> tuple[bytes, int]:
    """Read one SSH `string` (4-byte big-endian length prefix + body). Raises on truncation."""
    (length,) = struct.unpack_from(">I", blob, off)
    off += 4
    if length > len(blob) - off:
        raise ValueError("ssh string length runs past end of blob")
    return blob[off:off + length], off + length


def _decode_ssh_wire_ed25519(blob: bytes) -> bytes | None:
    """Decode an SSH-wire ed25519 public key to its 32 raw bytes, or None if it is not one.

    Wire form (RFC 8709): string "ssh-ed25519", then string of the 32 raw public bytes, with
    nothing trailing. Anything else — a different algorithm, a short blob, trailing junk —
    returns None so the caller ignores that line rather than trusting a half-parsed key."""
    try:
        alg, off = _read_ssh_string(blob, 0)
        if alg != b"ssh-ed25519":
            return None
        raw, off = _read_ssh_string(blob, off)
    except (struct.error, ValueError):
        return None
    if len(raw) != 32 or off != len(blob):
        return None
    return raw


def parse_authorized_keys(text: str) -> list[bytes]:
    """Parse an authorized_keys / `.keys` body into a list of raw 32-byte ed25519 public keys.

    Only `ssh-ed25519` entries are collected; RSA/ECDSA/sk- lines and any line that fails to
    decode are ignored safely (a malformed line must not deny an otherwise-valid list, nor be
    mistaken for a match). Comments and blank lines are skipped."""
    keys: list[bytes] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        # GitHub `.keys` (and a bare authorized_keys) put the type first. We deliberately do NOT
        # try to parse leading key-options: an ed25519 line with options is unusual for a
        # published anchor, and mis-parsing options is a worse failure than skipping the line.
        if len(parts) < 2 or parts[0] != "ssh-ed25519":
            continue
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except (binascii.Error, ValueError):
            continue
        raw = _decode_ssh_wire_ed25519(blob)
        if raw is not None:
            keys.append(raw)
    return keys


def resolve_spec(spec: str) -> str:
    """Turn a --pin SPEC into the HTTPS URL its keys are fetched from.

    `github:<user>`      -> https://github.com/<user>.keys
    `keys-url:<https...>` -> the URL verbatim (must be https)."""
    if spec.startswith("github:"):
        user = spec[len("github:"):].strip()
        if not user or "/" in user or any(c.isspace() for c in user):
            raise AnchorError(f"invalid --pin github user {user!r}; expected github:<user>")
        return f"https://github.com/{user}.keys"
    if spec.startswith("keys-url:"):
        url = spec[len("keys-url:"):].strip()
        if not url.startswith("https://"):
            raise AnchorError("--pin keys-url:<url> must be an https:// URL (an out-of-band "
                              "anchor over plaintext http is no anchor at all)")
        return url
    raise AnchorError(f"unrecognized --pin spec {spec!r}; use github:<user> or "
                      f"keys-url:<https-url>")


def _fetch(url: str) -> str:
    """GET `url` over TLS (system trust store) and return the decoded body, failing closed."""
    req = urllib.request.Request(url, headers={"User-Agent": "haru-pack-verify"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:   # noqa: S310 (https-only, enforced in resolve_spec)
            body = resp.read(_MAX_BODY + 1)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise AnchorError(f"could not fetch anchor keys from {url}: {e}")
    if len(body) > _MAX_BODY:
        raise AnchorError(f"anchor source {url} returned more than {_MAX_BODY} bytes — refusing")
    return body.decode("utf-8", "replace")


def fetch_anchor_keys(spec: str) -> tuple[str, list[bytes]]:
    """Resolve `spec`, fetch it, and return (url, [raw ed25519 pubkeys]). Fails closed on a
    network error, an empty body, or a body with no usable ssh-ed25519 key."""
    url = resolve_spec(spec)
    text = _fetch(url)
    if not text.strip():
        raise AnchorError(f"anchor source {url} returned an empty body — refusing (fail-closed)")
    keys = parse_authorized_keys(text)
    if not keys:
        raise AnchorError(f"anchor source {url} published no ssh-ed25519 keys — nothing to "
                          f"anchor against (fail-closed)")
    return url, keys


def check_embedded_pubkey(embedded_pubkey_hex: str, spec: str) -> AnchorResult:
    """Fetch the anchor for `spec` and report whether the build's embedded ed25519 pubkey (hex,
    from `overlay.verify(exe)['pubkey']`) is among the published keys.

    Raises AnchorError for every fail-closed condition EXCEPT a clean no-match, which is
    returned as `AnchorResult(matched=False, ...)` so the caller can print the specific keys it
    checked and still exit nonzero."""
    try:
        embedded = bytes.fromhex(embedded_pubkey_hex)
    except (ValueError, TypeError):
        raise AnchorError("the build carries no valid embedded ed25519 public key to anchor")
    if len(embedded) != 32:
        raise AnchorError(f"embedded public key is {len(embedded)} bytes, not a 32-byte "
                          f"ed25519 key — cannot anchor")
    url, keys = fetch_anchor_keys(spec)
    return AnchorResult(matched=embedded in keys, url=url, n_keys=len(keys))

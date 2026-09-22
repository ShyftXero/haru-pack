"""--self-signed key storage and Ed25519 signing (build side).

`--self-signed` signs a build with an Ed25519 key so the launcher can detect a post-build
payload edit (INV-SIGN-01). This module owns the KEY: where it lives, its permissions, and
the deliberate refusal to invent one during a build.

Two decisions are load-bearing and are NOT conveniences to relax:

* **Fail-hard on a missing key; never auto-generate during a build.** A build that silently
  minted a new key whenever it could not find one would rotate the key on every ephemeral CI
  home (a fresh `$HOME` per job), and any recipient who pinned yesterday's fingerprint would
  see today's build "verify" under a key they never saw. Silent rotation is theatre. So a
  build with `--self-signed` and no key REFUSES and tells the operator to mint one explicitly
  (`haru-pack keygen`) or point at one (`--sign-key`). Key generation is its own deliberate
  act, announced with the fingerprint.
* **Refuse a group/world-readable key.** A signing key readable by other users on the box is
  not a signing key. The keystore dir is 0700 and the key file 0600; a key with looser bits
  is refused rather than used, because using it would quietly weaken the guarantee the
  fingerprint is supposed to make.

The key is a raw 32-byte Ed25519 seed (RFC 8032). Ed25519 is deterministic, so the same key
over the same footer yields the same signature — haru-pack's byte-identical rebuild survives
signing, with no salt or per-build randomness (that would defeat reproducible builds).
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .errors import BuildError


class SigningError(BuildError):
    """A --self-signed build could not get a usable key (missing, or bad permissions)."""


def _config_home() -> Path:
    """The base of the per-user config tree: $XDG_CONFIG_HOME, else ~/.config."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg)
    return Path(os.path.expanduser("~")) / ".config"


def project_hash(project: Path) -> str:
    """A stable 16-hex tag for a project path, so each project gets its own default key.

    The resolved absolute path is hashed, so the same project always maps to the same key
    dir regardless of the cwd the build ran from."""
    resolved = str(Path(project).resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16]


def default_key_dir(project: Path) -> Path:
    """~/.config/haru-pack/<hash-of-project>/ — the per-project keystore directory."""
    return _config_home() / "haru-pack" / project_hash(project)


def default_key_path(project: Path) -> Path:
    """The default signing-key file for a project (inside its keystore directory)."""
    return default_key_dir(project) / "key"


def fingerprint(public_bytes: bytes) -> str:
    """The published identity of a signing key: SHA-256 of its 32-byte raw public key, hex.

    This is what a vendor publishes OUT OF BAND so a recipient can pin it; it is what makes
    --self-signed mean anything about provenance (INV-SIGN-01's honest limit)."""
    return hashlib.sha256(public_bytes).hexdigest()


def _priv_from_seed(seed: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if len(seed) != 32:
        raise SigningError(f"signing key must be a raw 32-byte Ed25519 seed, got {len(seed)} "
                           f"bytes — this file is not a haru-pack signing key")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _refuse_loose_perms(path: Path) -> None:
    """Refuse a key any group or other user can read (POSIX only). On Windows the bit model
    does not apply, so the check is skipped there — noted, not silently assumed safe."""
    if os.name != "posix":
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SigningError(
            f"refusing to use signing key {path}: it is group/other-accessible "
            f"(mode {stat.S_IMODE(mode):04o}). A signing key must be private — run "
            f"`chmod 600 {path}` (and 700 its directory), or regenerate it.")


def generate_key(path: Path, *, overwrite: bool = False):
    """Mint a new Ed25519 key at `path`, dir 0700 / file 0600, and return (private_key,
    fingerprint). Refuses to clobber an existing key unless `overwrite=True`, because a
    silent overwrite is exactly the rotation this module exists to prevent."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = Path(path)
    if path.exists() and not overwrite:
        raise SigningError(
            f"a signing key already exists at {path}. Refusing to overwrite it — that would "
            f"rotate the key silently. Delete it deliberately first if you truly mean to.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    # Write with 0600 from the start: create with O_CREAT|O_EXCL-like intent via opener, so
    # the seed never briefly exists world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, seed)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)
    pub = key.public_key().public_bytes_raw()
    return key, fingerprint(pub)


def load_key(path: Path):
    """Load a signing key from `path`, refusing a missing or loosely-permissioned file.
    Returns (private_key, fingerprint)."""
    path = Path(path)
    if not path.exists():
        raise SigningError(f"no signing key at {path}")
    _refuse_loose_perms(path)
    key = _priv_from_seed(path.read_bytes())
    pub = key.public_key().public_bytes_raw()
    return key, fingerprint(pub)


def resolve_signing(project: Path, *, self_signed: bool, sign_key: str, cert_file: str,
                    tgt, out: Path, say):
    """Resolve --self-signed / --cert-file BEFORE any binary exists (docs/PRINCIPLES.md), and
    return (sign_priv, signing_info, cert_info).

    A missing signing key or a --cert-file on the wrong OS target is a refusal the operator
    should pay nothing for, so it happens here in the preflight. The signing key is fail-hard —
    haru-pack never mints one during a build (see this module's docstring). `plan_authenticode`
    only wires the deferred Windows flow; it does not sign. Extracted from `orchestrate.build`
    so that function and module stay inside their INV-MODULARITY-01 budgets."""
    from . import authenticode      # lazy: keeps orchestrate's import fan-out down
    sign_priv = None
    signing_info: dict = {}
    if self_signed:
        sign_priv, sign_fp, sign_path = load_signing_key(project, sign_key)
        signing_info = {"self_signed": True, "pubkey_sha256": sign_fp,
                        "key_path": str(sign_path)}
        say(f"--self-signed: signing with Ed25519 key {sign_path}\n"
            f"  public-key fingerprint (sha256): {sign_fp}\n"
            f"  HONEST LIMIT: --self-signed detects post-build payload edits by anyone who "
            f"does not ALSO rewrite the embedded public key; it is NOT tamper-evidence unless "
            f"this fingerprint is PINNED OUT OF BAND (docs/SIGNING.md).")
    elif sign_key:
        raise BuildError("--sign-key was given without --self-signed; add --self-signed to "
                         "sign the build, or drop --sign-key.")
    cert_info = authenticode.plan_authenticode(cert_file=cert_file, tgt=tgt, out=out, say=say)
    return sign_priv, signing_info, cert_info


def load_signing_key(project: Path, sign_key_path: str = ""):
    """Resolve the key a --self-signed build should use, FAIL-HARD if it is absent.

    `--sign-key <path>` wins; otherwise the per-project default keystore key is used. In
    neither case is a key generated here — see the module docstring. Returns (private_key,
    fingerprint, path)."""
    path = Path(sign_key_path) if sign_key_path else default_key_path(project)
    if not path.exists():
        where = "--sign-key path" if sign_key_path else "default keystore"
        raise SigningError(
            f"--self-signed needs a signing key but none exists at the {where}:\n  {path}\n"
            f"haru-pack does not mint one during a build (that would rotate the key on every "
            f"ephemeral CI home and break any recipient who pinned the old fingerprint). "
            f"Create one deliberately:\n"
            f"  haru-pack keygen" + (f" --key {path}" if sign_key_path else "")
            + "\nrecord the printed fingerprint, publish it out of band, and re-run the build.")
    key, fp = load_key(path)
    return key, fp, path

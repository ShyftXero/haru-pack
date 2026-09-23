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

The default keystore key is a raw 32-byte Ed25519 seed (RFC 8032). `--sign-key <path>` may
instead point at an existing OpenSSH-format Ed25519 private key (e.g. `~/.ssh/id_ed25519`) —
haru-pack extracts its raw seed and signs EXACTLY as with a keystore seed, so the embedded
public key then equals the dev's published GitHub SSH key and a recipient can anchor to it
(`haru-pack verify --pin github:<user>`, INV-SIGN-02). This is deliberate cross-protocol reuse
of an SSH auth key; it is signing raw haru-pack footer bytes (never an SSHSIG envelope, which
the launcher's raw verifier cannot check), mitigated — not eliminated — by the footer's
`03 00` formatVer prefix not being a valid SSH auth-request blob. Non-Ed25519 keys (RSA/ECDSA),
FIDO/hardware `sk-ssh-ed25519` keys, and agent-only keys are REFUSED, never worked around: a
key whose seed we cannot hold is not a key we can sign a reproducible build with.

Ed25519 is deterministic, so the same key over the same footer yields the same signature —
haru-pack's byte-identical rebuild survives signing, with no salt or per-build randomness (that
would defeat reproducible builds).
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
                           f"bytes — this file is not a haru-pack signing key (if it is an "
                           f"OpenSSH key, its `-----BEGIN OPENSSH PRIVATE KEY-----` header was "
                           f"not found)")
    return Ed25519PrivateKey.from_private_bytes(seed)


_OPENSSH_HEADER = b"-----BEGIN OPENSSH PRIVATE KEY-----"


def _looks_like_openssh(data: bytes) -> bool:
    """True for an OpenSSH-format private key file (what `ssh-keygen -t ed25519` writes).

    The raw keystore seed is 32 opaque bytes with no header, so the PEM armor is an
    unambiguous discriminator between the two accepted --sign-key file shapes."""
    return data.lstrip().startswith(_OPENSSH_HEADER)


def _priv_from_openssh(data: bytes, passphrase: bytes | None, path: Path):
    """Load an OpenSSH Ed25519 private key and return an Ed25519PrivateKey re-derived from its
    raw seed, so signing is byte-identical to the keystore-seed path.

    FAIL-HARD (never mint, never work around) on anything that is not a software Ed25519 seed we
    can hold: RSA/ECDSA, FIDO/hardware `sk-ssh-ed25519`, a public key or agent-only reference,
    and a wrong/missing passphrase. Cross-protocol reuse of an SSH auth key is the point (the
    embedded pubkey becomes the dev's GitHub key); minting a *different* key because theirs did
    not fit would silently break that anchor, which is exactly what this module refuses to do."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_ssh_private_key
    try:
        key = load_ssh_private_key(data, password=passphrase)
    except UnsupportedAlgorithm as e:
        if "bcrypt" in str(e).lower():
            raise SigningError(
                f"cannot decrypt the passphrase-protected OpenSSH key {path}: the `bcrypt` "
                f"package (OpenSSH's key-derivation function) is not installed. Install it "
                f"(`pip install bcrypt`) or use an unencrypted key.")
        raise SigningError(
            f"refusing to sign with {path}: it is an OpenSSH key type haru-pack cannot use "
            f"({e}). A FIDO/hardware `sk-ssh-ed25519` key never exposes its private seed, so a "
            f"reproducible raw-footer signature is impossible; use a software Ed25519 key "
            f"(`ssh-keygen -t ed25519`) or `haru-pack keygen`.")
    except (ValueError, TypeError) as e:
        # cryptography raises TypeError("...password was not provided") for a missing passphrase
        # and ValueError("Corrupt data: broken checksum") for a wrong one.
        msg = str(e).lower()
        if ("password" in msg or "corrupt" in msg or "checksum" in msg or "decrypt" in msg
                or "protected" in msg):
            hint = ("no passphrase was supplied — pass one with `--sign-key-passphrase-env "
                    "<ENVVAR>`" if passphrase is None else
                    "the supplied passphrase is wrong")
            raise SigningError(
                f"refusing to sign with {path}: the OpenSSH key is passphrase-protected and "
                f"{hint}. haru-pack never prompts interactively during a build.")
        raise SigningError(
            f"refusing to sign with {path}: it is not a usable OpenSSH private key ({e}). "
            f"Point --sign-key at an unencrypted or passphrase-env'd Ed25519 private key file "
            f"(not a `.pub`, not an agent-only key).")
    if not isinstance(key, Ed25519PrivateKey):
        kind = type(key).__name__.replace("PrivateKey", "")
        raise SigningError(
            f"refusing to sign with {path}: it is an {kind} key, not Ed25519. haru-pack signs "
            f"the footer with Ed25519 only (the launcher's vendored verifier does Ed25519 and "
            f"nothing else); it will NOT mint a substitute key. Use an Ed25519 key.")
    # Re-derive from the raw seed so the private_key object, and every signature it makes, is
    # byte-identical to the keystore-seed path.
    return Ed25519PrivateKey.from_private_bytes(key.private_bytes_raw())


def _priv_from_key_file(data: bytes, *, passphrase: bytes | None, path: Path):
    """Dispatch a --sign-key file to the OpenSSH loader or the raw-seed loader."""
    if _looks_like_openssh(data):
        return _priv_from_openssh(data, passphrase, path)
    return _priv_from_seed(data)


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


def load_key(path: Path, *, passphrase: bytes | None = None):
    """Load a signing key from `path`, refusing a missing or loosely-permissioned file.

    Accepts either a raw 32-byte keystore seed or an OpenSSH-format Ed25519 private key; the
    `passphrase` (bytes) applies only to an encrypted OpenSSH key. Returns (private_key,
    fingerprint)."""
    path = Path(path)
    if not path.exists():
        raise SigningError(f"no signing key at {path}")
    _refuse_loose_perms(path)
    key = _priv_from_key_file(path.read_bytes(), passphrase=passphrase, path=path)
    pub = key.public_key().public_bytes_raw()
    return key, fingerprint(pub)


def resolve_signing(project: Path, *, self_signed: bool, sign_key: str, cert_file: str,
                    tgt, out: Path, say, sign_key_passphrase_env: str = ""):
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
        sign_priv, sign_fp, sign_path = load_signing_key(
            project, sign_key, passphrase_env=sign_key_passphrase_env)
        signing_info = {"self_signed": True, "pubkey_sha256": sign_fp,
                        "key_path": str(sign_path)}
        say(f"--self-signed: signing with Ed25519 key {sign_path}\n"
            f"  public-key fingerprint (sha256): {sign_fp}\n"
            f"  HONEST LIMIT: --self-signed detects post-build payload edits by anyone who "
            f"does not ALSO rewrite the embedded public key; it is NOT tamper-evidence unless "
            f"this fingerprint is PINNED OUT OF BAND.\n"
            f"  PUBLISH it so recipients can pin it: GPG- or SSH-sign the fingerprint with a key "
            f"people already associate with you (e.g. served at github.com/<you>.gpg or "
            f"github.com/<you>.keys). See docs/SIGNING.md 'Publishing your fingerprint'. "
            f"(On Windows, use --cert-file/Authenticode instead — no manual pin needed.)")
    elif sign_key:
        raise BuildError("--sign-key was given without --self-signed; add --self-signed to "
                         "sign the build, or drop --sign-key.")
    elif sign_key_passphrase_env:
        raise BuildError("--sign-key-passphrase-env was given without --self-signed; it only "
                         "applies when signing a build with an encrypted OpenSSH --sign-key.")
    cert_info = authenticode.plan_authenticode(cert_file=cert_file, tgt=tgt, out=out, say=say)
    return sign_priv, signing_info, cert_info


def load_signing_key(project: Path, sign_key_path: str = "", *, passphrase_env: str = ""):
    """Resolve the key a --self-signed build should use, FAIL-HARD if it is absent.

    `--sign-key <path>` wins (a raw keystore seed OR an OpenSSH Ed25519 key); otherwise the
    per-project default keystore key is used. In neither case is a key generated here — see the
    module docstring. `passphrase_env`, if set, names an environment variable whose value is the
    passphrase for an encrypted OpenSSH key (never prompted for interactively during a build).
    Returns (private_key, fingerprint, path)."""
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
    passphrase: bytes | None = None
    if passphrase_env:
        val = os.environ.get(passphrase_env)
        if val is None:
            raise SigningError(
                f"--sign-key-passphrase-env named ${passphrase_env}, but that environment "
                f"variable is not set. Export it with the key's passphrase, or drop the flag "
                f"for an unencrypted key.")
        passphrase = val.encode("utf-8")
    key, fp = load_key(path, passphrase=passphrase)
    return key, fp, path

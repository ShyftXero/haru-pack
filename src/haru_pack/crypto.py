"""Optional AES-256-GCM payload encryption + license policy (no PKI).

Container v2 (little-endian), stored as the attached payload when encrypted (footer flag bit0):
  magic "HPAKENC1"(8) | version u16 | flags u16 | kdf_iters u32 |
  salt[16] | nonce[12] | tag[16] |
  esecret_len u16 | esecret[..]        # embedded secret, XOR-obfuscated (weakest key source)
  ciphertext[..]                        # AES-256-GCM( policy_len u32 | policy | payload.zip )

The license policy is stored INSIDE the ciphertext, not in cleartext — a reverse-engineer
sees no expiry/geo/etc. All license checks run AFTER decryption.

AAD (INV-CRYPTO-04): every header byte preceding the ciphertext EXCEPT the 16-byte tag
field — i.e. blob[0:44] + blob[60:62+esecret_len]. Version, flags, kdf_iters, salt, nonce,
esecret_len and esecret are therefore authenticated: editing one is *detected* by the tag,
not merely unproductive. The tag field is elided because a GCM tag cannot authenticate
itself; editing it is caught by tag verification. Version 1 used the bare magic as AAD and
is not readable by a v2 launcher (`cryptbox.nim` rejects it by version, before prompting).

Key = PBKDF2-HMAC-SHA256(secret [+ machine-id][+ user], salt, iters, 32).
flags: bit0 bind_machine, bit1 bind_user, bit2 embedded_secret.
"""
from __future__ import annotations
import hashlib, json, os, platform, struct, subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"HPAKENC1"
CONTAINER_VERSION = 2                     # v1 = AAD was the bare magic; v2 = whole header
TAG_OFF, TAG_LEN, HDR_FIXED = 44, 16, 62  # tag at [44:60]; fixed header ends at esecret
OBFUS = b"haru-pack/embedded-secret/v1"   # XOR pad for the (weak) embedded secret
KDF_ITERS = 200_000

BIND_MACHINE, BIND_USER, EMBED_SECRET = 1, 2, 4

def machine_id() -> str:
    try:
        if platform.system() == "Linux":
            for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if os.path.exists(p):
                    return open(p).read().strip()
        elif platform.system() == "Darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split('"')[-2]
        elif platform.system() == "Windows":
            out = subprocess.run(["reg", "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
                capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "MachineGuid" in line:
                    return line.split()[-1]
    except Exception:
        pass
    return ""

def current_user() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or ""

def _xor(b: bytes, pad: bytes) -> bytes:
    return bytes(x ^ pad[i % len(pad)] for i, x in enumerate(b))

def container_aad(blob: bytes) -> bytes:
    """The v2 AAD for a serialized container: the whole header minus the tag field.

    One definition, genuinely used by `encrypt()` below and by the tests, so a test that
    constrains this function constrains the bytes the cipher actually saw. `cryptbox.nim`
    builds the same bytes; the offsets are asserted equal in tests/test_container.py.
    """
    if len(blob) < HDR_FIXED:
        raise ValueError("truncated container header")
    eslen = struct.unpack_from("<H", blob, HDR_FIXED - 2)[0]
    if len(blob) < HDR_FIXED + eslen:
        raise ValueError("truncated container header (esecret)")
    return blob[:TAG_OFF] + blob[TAG_OFF + TAG_LEN:HDR_FIXED + eslen]


def derive_key(secret: bytes, salt: bytes, iters: int,
               machine: str | None, user: str | None) -> bytes:
    pw = secret
    if machine: pw += b"\x1f" + machine.encode()
    if user:    pw += b"\x1f" + user.encode()
    return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, 32)

def encrypt(payload: bytes, secret: bytes, *, expires: str = "", geo=None,
            machine: str = "", user: str = "", embed_secret: bool = False,
            iters: int = KDF_ITERS) -> bytes:
    salt = os.urandom(16)          # per-build -> ephemeral key
    nonce = os.urandom(12)
    flags = 0
    if machine: flags |= BIND_MACHINE
    if user:    flags |= BIND_USER
    if embed_secret: flags |= EMBED_SECRET
    policy = json.dumps({"expires": expires, "geo": geo or [],
                         "machine": machine, "user": user},
                        separators=(",", ":"), sort_keys=True).encode()
    key = derive_key(secret, salt, iters, machine or None, user or None)
    plaintext = struct.pack("<I", len(policy)) + policy + payload   # policy hidden inside
    esecret = _xor(secret, OBFUS) if embed_secret else b""
    # the header is built first so it can be fed to the AEAD as AAD (INV-CRYPTO-04)
    head_a = (MAGIC + struct.pack("<HHI", CONTAINER_VERSION, flags, iters)
              + salt + nonce)                                       # blob[0:44]
    head_b = struct.pack("<H", len(esecret)) + esecret               # blob[60:62+eslen]

    # Lay out the container with a placeholder tag and derive the AAD from that layout with
    # container_aad(), rather than assembling the same bytes a second time by hand. The tag
    # field is the one region container_aad() excludes, so the placeholder never reaches the
    # AEAD and the real tag is spliced in below.
    #
    # This is not stylistic. When encrypt() built its own AAD independently, every test that
    # exercised container_aad() proved nothing about what encrypt() actually fed the cipher:
    # the adversarial verifier reverted this line to the v1 bare magic and five of the six
    # tests claiming INV-CRYPTO-04 stayed green. Routing the writer through the same function
    # the tests inspect is what makes those tests bite.
    aad = container_aad(head_a + b"\x00" * TAG_LEN + head_b)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    ct, tag = ct_tag[:-TAG_LEN], ct_tag[-TAG_LEN:]
    return head_a + tag + head_b + ct

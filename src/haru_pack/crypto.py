"""Optional AES-256-GCM payload encryption + license policy (no PKI).

Container (little-endian), stored as the attached payload when encrypted (footer flag bit0):
  magic "HPAKENC1"(8) | version u16 | flags u16 | kdf_iters u32 |
  salt[16] | nonce[12] | tag[16] |
  esecret_len u16 | esecret[..]        # embedded secret, XOR-obfuscated (weakest key source)
  policy_len u32 | policy[..]          # JSON, authenticated as GCM AAD (tamper-evident)
  ciphertext[..]                        # AES-256-GCM(payload.zip)

Key = PBKDF2-HMAC-SHA256(secret [+ machine-id][+ user], salt, iters, 32).
flags: bit0 bind_machine, bit1 bind_user, bit2 embedded_secret.
"""
from __future__ import annotations
import hashlib, json, os, platform, struct, subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"HPAKENC1"
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
    ct_tag = AESGCM(key).encrypt(nonce, payload, policy)   # ciphertext || 16B tag
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    esecret = _xor(secret, OBFUS) if embed_secret else b""
    out = bytearray()
    out += MAGIC + struct.pack("<HHI", 1, flags, iters) + salt + nonce + tag
    out += struct.pack("<H", len(esecret)) + esecret
    out += struct.pack("<I", len(policy)) + policy
    out += ct
    return bytes(out)

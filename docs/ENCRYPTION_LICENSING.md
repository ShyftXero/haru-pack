# haru-pack — encryption & license checks (implemented v1)

Opt-in `--encrypt`: AES-256-GCM payload encryption + license gating by expiry, machine,
user, and location. **No PKI / no certs** — the trust anchor is a secret you choose.

## Honest ceiling
Local execution means the machine must decrypt to run, so this **raises the bar** (stops
copying/sharing, enforces policy) but is **not** unbreakable against a determined
reverse-engineer. Machine/user binding is *cryptographic* (wrong machine can't derive the
key); expiry/location are *checks* (a patched binary could skip a pure comparison, but the
policy can't be edited without breaking decryption). For hard enforcement add a server.

## How it works (no PKI)
- Payload encrypted with **AES-256-GCM**. The license **policy JSON is inside the GCM
  plaintext**, prefixed by its length, ahead of the payload zip — so a reverse-engineer
  sees no expiry/geo/machine/user in the clear, and cannot edit them without the key.
  (`INV-CRYPTO-01`, `INV-CRYPTO-03`.)
  Earlier revisions of this document, and the header comment in `cryptbox.nim`, said the
  policy *was* the AAD. It never was. The tamper-evidence is real but comes from the
  policy being inside the ciphertext, not from the AAD — and a maintainer "correcting"
  the code to match the old wording would have moved the policy into the clear.
- **Container v2:** the AAD is every header byte before the ciphertext *except* the 16-byte
  tag field — `blob[0:44] + blob[60:62+esecret_len]`. Version, flags, KDF iterations, salt,
  nonce, `esecret_len` and the embedded secret are therefore **tamper-evident**: editing one
  is detected by the tag, not merely unproductive. The tag is elided because a GCM tag cannot
  authenticate itself. (`INV-CRYPTO-04`.)
  In **v1** the AAD was the bare magic, leaving the header outside the AEAD — fail-closed
  (a header edit changed key derivation, so the open failed) but not tamper-evident. A v2
  launcher **rejects a v1 container by version**, before prompting for a secret, so binaries
  built before this change must be rebuilt.
- Key = **PBKDF2-HMAC-SHA256(secret [+ machine-id][+ user], random-per-build salt, 200k)**.
  The per-build salt makes the key **ephemeral**; machine/user binding is folded into the
  KDF so an unauthorized machine simply can't derive the key.

## Build
```sh
# secret sources (pick one): literal, env var, or interactive prompt
haru-pack build ./app --encrypt --secret 's3cret'         --expires 2027-01-01
haru-pack build ./app --encrypt --secret-env LIC_SECRET   --geo US,CA
haru-pack build ./app --encrypt --secret-prompt
# bind cryptographically to a machine / user (get the id from the customer):
haru-pack build ./app --encrypt --secret s --machine <id> --user alice
# embed the secret in the exe (WEAKEST — no runtime secret needed):
haru-pack build ./app --encrypt --secret s --embed-secret
```
Get a target machine's id: `haru-pack machine-id` (customer runs it, sends you the value).

## Runtime secret resolution (precedence)
1. env `HARUPACK_SECRET`  2. embedded (if `--embed-secret`)  3. interactive prompt (TTY).
Location check reads `HARUPACK_GEO` (offline geo is weak — online lookup is future work).

## Failure messages (exit codes)
- expired → `license expired (DATE)` (3)
- location → `not licensed for this location` (3)
- no secret available → prompt to set `HARUPACK_SECRET` (4)
- wrong secret / wrong machine / wrong user / tampered → single message (5)

## Honest ceiling, part 2: what expiry and geo actually are

Machine and user binding are cryptographic — the key genuinely cannot be derived on a
machine whose id differs. Note that `/etc/machine-id` is a writable file, not a hardware
root of trust, so this binds to a *value the target reports*, not to hardware.

Expiry and geo are **not** controls in the same sense:

- **Geo** reads the `HARUPACK_GEO` environment variable. The person being restricted
  supplies the value. `HARUPACK_GEO=US` defeats it completely. It is a configuration
  affordance, not an enforcement mechanism.
- **Expiry** compares against the local system clock, which the same person sets.

Both checks run after decryption, inside a binary the licensee controls, so both can also
be patched out. They are useful for keeping honest customers honest and for making
accidental misuse visible. Do not sell them as enforcement.

## Verified (2026-09-09, re-scoped 2026-09-09)

The original wording of this section asserted a list of manual observations, including
"Nim (nimcrypto) ↔ Python (`cryptography`) containers interop byte-for-byte", with no test
behind any of it. Nothing here re-checked itself, and one claim in the sibling
`docs/SIGNING.md` was false when written.

What is covered by executable tests today (`pytest -m invariant`):

| Claim | Evidence |
|---|---|
| Policy fields never appear in cleartext in a built container | `INV-CRYPTO-01` |
| Policy is recoverable after authenticated decryption, from inside the GCM plaintext | `INV-CRYPTO-01` |
| A wrong machine id cannot derive the key | `INV-CRYPTO-03` |
| Tampering with salt/nonce/tag/ciphertext/iters breaks the open | `INV-CRYPTO-03` |
| The Nim reader's byte offsets match the Python writer's | `INV-CRYPTO-02` (parses `cryptbox.nim`) |
| `--encrypt` actually encrypts | `INV-BUILD-02` |
| A build never reports encryption it did not apply | `INV-BUILD-01` |

Not covered, and deliberately not claimed: end-to-end decryption **by the compiled Nim
launcher**. `INV-CRYPTO-02` compares byte offsets parsed out of the Nim source against the
Python writer, which catches layout drift but is not a cross-implementation interop test.
Running one requires the Nim toolchain in CI.

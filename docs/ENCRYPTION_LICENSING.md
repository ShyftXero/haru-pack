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
- Payload encrypted with **AES-256-GCM**. The license **policy JSON is the GCM AAD** →
  editing any field breaks decryption (tamper-evident) — no signature/keypair needed.
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

## Verified (2026-09-09)
correct secret decrypts+runs; wrong secret → GCM auth failure; embedded secret runs with
no env; `--expires 2020-01-01` → refused; `--machine <this>` runs, `--machine <other>` →
key mismatch. Nim (nimcrypto) ↔ Python (`cryptography`) containers interop byte-for-byte.

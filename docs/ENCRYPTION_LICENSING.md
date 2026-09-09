# uvcannon — optional encryption & license checks

Optional, opt-in wrapper features: **AES-256 payload encryption** + **license gating**
by hostname, date/time, location, or any combination.

## 0. Threat model — read this first (honest ceiling)
Local execution means the machine must ultimately decrypt and run the code, so **the key
and the checks are present on the client**. These features **raise the bar** — stop casual
copying, sharing, and out-of-policy use — but are **not unbreakable** against a determined
reverse-engineer with the binary + a debugger. For *hard* enforcement you need a **server
component** (online activation / license heartbeat / server-issued keys). Everything below
is designed to make the offline path as strong as offline can be, and to degrade to
online when you need real teeth. Never advertise it as DRM-proof.

## 1. AES-256 payload encryption
- Payload container (`.uvcap`) encrypted with **AES-256-GCM** (authenticated: detects
  tampering). Nonce + tag stored in the overlay footer (footer format gains an
  `enc` flag + nonce field). Append-then-sign order is unchanged.
- Launcher decrypts in the Nim stub (via `nimcrypto`) before extraction.
- **Key sources** (manifest `encryption.key_source`):
  1. `embedded` — key baked into the (signed) binary. Obfuscation-grade: stops copying the
     raw payload, not binary RE. Pair with source-protection (Nuitka) for the code itself.
  2. `license` — key = KDF(license file + machine fingerprint). Payload only decrypts on an
     authorized machine; editing/patching the check doesn't yield the key.
  3. `passphrase` — user types a secret at launch. Strong, UX cost.
  4. `server` — key fetched after online activation, cached encrypted-at-rest bound to the
     machine. **Strongest offline-after-first-run**; needs network at least once.
- **Leakage caveat:** uv needs files on disk, so decrypted *code* lands in the stage dir in
  plaintext during a run. Mitigate: decrypt to a locked/ACL'd dir, wipe on exit (shrinks
  the window, doesn't close it). For **assets**, keep them encrypted in the container and
  decrypt on-read inside the app (a shipped `uvcannon` helper) — never hits disk plaintext.

## 2. License checks (combinable)
Each is a boolean predicate; combine with `and`/`or`/a small policy expression.

| Check | How (offline) | Sharp corners |
|-------|---------------|---------------|
| **hostname / machine** | Windows `MachineGuid` (registry), Linux `/etc/machine-id`, macOS IOPlatformUUID; optionally MAC/CPUID. Bind license to a fingerprint. | Fingerprint changes (reimage, new NIC) → need a re-activation path; don't over-bind. |
| **date / time** | current time vs `not_before`/`not_after`. | **Clock rollback**: store a tamper-evident "high-water" last-seen time (signed, in appdata); offline can't fully stop rollback — server time is the real fix. |
| **location** | IP geolocation (needs network) or timezone/locale (offline, weak). | VPNs defeat IP geo; offline geo (tz/locale) is trivially spoofed. True geofencing = online. |

## 3. Design: signed license file + gated decryption (recommended)
Resist tampering by making the license itself unforgeable and by keying decryption on it.
1. Vendor holds an **Ed25519 private key**; the launcher **embeds the public key**.
2. License = JSON `{ machine_ids, not_before, not_after, geo, features }` **Ed25519-signed**.
3. Launcher: find license (adjacent to exe via `UVCANNON_EXE_DIR`, embedded, or fetched) →
   **verify signature** with the embedded pubkey → **evaluate policy** vs current
   machine/time/geo → only on pass, **derive/release the AES key** → decrypt → stage → run.
4. Because the AES key is bound to a valid license (source `license`), **patching out the
   check doesn't produce the key** — the two must be linked or the check is just a branch to
   NOP. This is the key design point.
5. Strongest tier: key is **server-issued** on activation; the client never contains it.

## 4. Manifest wiring (sketch)
```json
"encryption": { "enabled": true, "cipher": "aes-256-gcm", "key_source": "license" },
"license": {
  "enabled": true,
  "pubkey": "<base64 ed25519 public key>",
  "require": { "machine": true, "time": true, "geo": ["US","CA"] },
  "combine": "and",
  "license_file": "license.lic",
  "activation_url": "https://vendor.example/activate"
}
```

## 5. Build/CLI surface (future)
- `uvcannon build --encrypt --key-source license --license-pubkey key.pub ...`
- `uvcannon license issue --machine <id> --expires 2027-01-01 --geo US --key vendor.key`
  → emits a signed `license.lic` to drop next to the exe.
- Keep signing keys off the build box where possible (HSM/KMS), like the code-signing cert.

## 6. Failure UX
Refuse with a clear, specific message ("license expired 2026-01-01", "not licensed for this
machine — activate at <url>"), never a silent crash. Distinguish *no license* (prompt to
activate) from *invalid/expired* (contact vendor).

## 7. Busybody fuzzer axes to add
clock-rollback, machine-id change mid-run, missing/tampered/expired license, offline while
`key_source=server`, geo via VPN, and "patch the check" (assert encryption defeats it).

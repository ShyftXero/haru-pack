# haru-pack — Windows code signing

Requirement: the produced exe **may ship unsigned but MUST support signing** with a
publicly-trusted Authenticode code-signing certificate. The whole flow is **cross-platform
(runs on Linux CI)** — no Windows machine required.

> **Do not buy an EV certificate.** Microsoft Trusted Root Program requirements §3.D.3:
> *"Starting February 2024, Microsoft will no longer accept or recognize EV Code Signing
> Certificates… Beginning in August 2024, all EV Code Signing OIDs will be removed from
> existing roots in the Microsoft Trusted Root Program, and **all Code Signing certificates
> will be treated equally**."* EV is not "faster to earn reputation" — the distinction no
> longer exists. An OV certificate is the correct purchase. See `research/05` Part 7.

## Why our design is signable
- Nim compiles to a normal C-linked **Authenticode-capable PE** (mingw-w64 or MSVC).
- We **append the payload + a 68-byte footer, then sign** — never the reverse.
  Authenticode hashes the whole file except the checksum field, the cert data-directory
  entry, and the attribute certificate table. Our overlay is inside that hash, so signing
  after appending is valid and tamper-evident.
- The cert table is appended at EOF **after** our footer, so the footer is no longer at
  EOF. The launcher (`src/overlay.nim`) **scans backward for the magic** `HARUPACK` (and
  tail `KCAPURAH`) to relocate it — the same trick PyInstaller uses so an OS-added
  signature can't hide the payload cookie.
- **No UPX** — it invalidates a prior signature and trips AV/SmartScreen heuristics.

## Golden order (build → attach → sign)
```sh
# 1. cross-compile launcher on Linux -> Windows PE
nim c -d:mingw --cpu:amd64 -d:release --out:build/app.exe src/main.nim

# 2. attach payload (BEFORE signing)
python3 builder/attach.py build/app.exe app.uvcap build/app.attached.exe

# 3. sign LAST (see options below)  4. verify
```

## Signing options (all Linux-capable)
`signtool` is Windows-only. For a cross-compiled pipeline use:

### A. osslsigncode + hardware token (PKCS#11)
Since June 2023 the CA/Browser Forum baseline requirements put **all** code-signing private
keys — OV included, not just EV — on FIPS-certified hardware (HSM/USB token, e.g.
SafeNet/YubiHSM), so this path is unchanged by dropping EV. Drive the token via the PKCS#11
engine:
```sh
osslsigncode sign \
  -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so \
  -pkcs11module /usr/lib/libeToken.so \
  -certs codesign-cert.pem -key "pkcs11:object=...;type=private" \
  -h sha256 -ts http://timestamp.digicert.com \
  -in build/app.attached.exe -out build/app.exe
```
Caveat: many hardware tokens require an interactive PIN → awkward for headless CI.
Option B avoids this entirely and is the recommended path.

### B. jsign + cloud signer (preferred, modern, headless)
`jsign` (Java, cross-platform) signs PE/MSI using cloud keys — **Azure Trusted Signing**,
Azure Key Vault, AWS KMS, GCP KMS, HashiCorp Vault. No physical token, CI-friendly, and
Azure Trusted Signing issues the cert too (pay-as-you-go).
```sh
jsign --storetype TRUSTEDSIGNING \
  --keystore <account>.<region>.codesigning.azure.net \
  --alias <cert-profile> \
  --tsaurl http://timestamp.acs.microsoft.com \
  build/app.exe
```

### C. Native Windows (if you have a box)
```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a build\app.exe
```

## Always
- **RFC3161 timestamp** (`-ts` / `/tr` + `/td SHA256`) so the signature outlives cert expiry.
- **RSA, not ECC.** Smart App Control "allows applications signed with RSA-based digital
  certificates… It does not currently support elliptic-curve cryptography (ECC)", and the
  Trusted Root Program likewise excludes ECC and keys > 4096. Choose this at provisioning
  time — it is not changeable later without a new certificate.
- **One signing identity, kept as long as possible.** SmartScreen reputation attaches to the
  file hash *and* the publisher certificate; renewing to a new thumbprint appears to reset
  publisher reputation with no documented recourse. Plan renewals accordingly.
- **Keep the launcher's bytes stable across releases.** Reputation accrues to the stub's
  hash, and a stub that rarely changes keeps it for years even as the app it carries
  changes. This is the actual mechanism behind "signed installers stop getting warnings" —
  not the certificate class.
- **Verify**: `osslsigncode verify -in build/app.exe` — check *Calculated == Current
  message digest*. Then `python3 builder/verify.py build/app.exe` to confirm the payload
  footer + sha256 survived.

## Enterprise-AV escape hatch
If a single self-extracting stub still trips strict Defender policies, ship
**external-payload mode**: `app.exe` (signed, tiny) + `app.uvcap` sidecar. Launcher finds
the sidecar via `getAppDir()`. Onedir-like, least-suspicious posture.

## Validated (2026-09-09, corrected 2026-09-09)

Cross-compiled on Linux, attached payload, signed with `osslsigncode` (throwaway cert),
`osslsigncode verify` reported matching Authenticode digests, and the Nim exe (under wine)
relocated its footer from its own **signed** image. Only the cert *chain* failed
(self-signed) — any publicly-trusted code-signing cert resolves that. See `docs/PLAN.md` §10.

**Correction, and then a correction to the correction.** The original wording claimed the
launcher "verified its payload sha256". When that was written it was false: `main.nim`
hex-encoded the footer digest and used the first 16 characters as a staging-directory name,
never comparing it to anything. It is now true — `INV-LAUNCH-01` landed on 2026-09-09 and
the launcher refuses to stage or decrypt a payload whose SHA-256 does not match its footer.
Both states are recorded here because a doc that quietly flips from wrong to right teaches
you nothing about how much to trust the next sentence.

What is covered by tests today:

| Claim | Evidence |
|---|---|
| The launcher verifies the payload digest before staging or executing it | `INV-LAUNCH-01` — `tests/test_launcher_integrity.py` |
| The footer round-trips and detects payload modification at build time | `INV-PAYLOAD-02` — `tests/test_overlay_integrity.py` |
| The footer survives data appended after it (the cert table) | `INV-PAYLOAD-02` |
| The payload is **signature**-verified rather than digest-checked | **Not implemented.** `INV-LAUNCH-03`, `proposed` |

The digest is **not a MAC.** It lives in the same footer an attacker would edit, so someone
who modifies the payload can recompute it and still execute. It catches corruption and naive
edits; it is not tamper-evidence. On Windows that comes from Authenticode over the overlay.
An unsigned ELF has no equivalent, which is why `INV-LAUNCH-03` stays open.

## Known gap: the payload we stage is not covered by our signature
Signing the launcher says nothing about the uv and CPython it stages. uv's own binaries are
signed and notarized as of uv 0.12.12; **python-build-standalone artifacts are not signed at
all**. Under Windows Smart App Control — which requires every binary to be recognized or
signed, not just the entry point — a signed stub confers nothing on an unsigned staged
interpreter.

Partially mitigated as of 2026-09-09: every staged artifact is pinned to a SHA-256 in
`src/haru_pack/pins.toml` and verified at build time before it enters the payload
(`INV-SUPPLY-01`), and the payload as a whole is digest-checked at launch
(`INV-LAUNCH-01`). That closes "did we stage the bytes upstream published"; it does not make
the staged interpreter *signed*, so Smart App Control's requirement is still unmet. See
`research/05` Part 5 (#3) and Part 9.4.

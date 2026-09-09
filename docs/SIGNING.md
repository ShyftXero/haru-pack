# uvcannon — Windows code signing

Requirement: the produced exe **may ship unsigned but MUST support signing** with an EV
code-signing certificate. The whole flow is **cross-platform (runs on Linux CI)** — no
Windows machine required.

## Why our design is signable
- Nim compiles to a normal C-linked **Authenticode-capable PE** (mingw-w64 or MSVC).
- We **append the payload + a 68-byte footer, then sign** — never the reverse.
  Authenticode hashes the whole file except the checksum field, the cert data-directory
  entry, and the attribute certificate table. Our overlay is inside that hash, so signing
  after appending is valid and tamper-evident.
- The cert table is appended at EOF **after** our footer, so the footer is no longer at
  EOF. The launcher (`src/overlay.nim`) **scans backward for the magic** `UVCANON1` (and
  tail `1NONACVU`) to relocate it — the same trick PyInstaller uses so an OS-added
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

### A. osslsigncode + hardware EV token (PKCS#11)
EV private keys are non-exportable (FIPS 140-2 HSM/USB token, e.g. SafeNet/YubiHSM).
Drive the token via the PKCS#11 engine:
```sh
osslsigncode sign \
  -pkcs11engine /usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so \
  -pkcs11module /usr/lib/libeToken.so \
  -certs ev-cert.pem -key "pkcs11:object=...;type=private" \
  -h sha256 -ts http://timestamp.digicert.com \
  -in build/app.attached.exe -out build/app.exe
```
Caveat: many EV tokens require an interactive PIN → awkward for headless CI.

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
- **EV cert** → immediate SmartScreen reputation (the real reason to buy EV over OV).
- **Verify**: `osslsigncode verify -in build/app.exe` — check *Calculated == Current
  message digest*. Then `python3 builder/verify.py build/app.exe` to confirm the payload
  footer + sha256 survived.

## Enterprise-AV escape hatch
If a single self-extracting stub still trips strict Defender policies, ship
**external-payload mode**: `app.exe` (signed, tiny) + `app.uvcap` sidecar. Launcher finds
the sidecar via `getAppDir()`. Onedir-like, least-suspicious posture.

## Validated (2026-09-09)
Cross-compiled on Linux, attached payload, signed with `osslsigncode` (throwaway cert),
`osslsigncode verify` reported matching Authenticode digests, and the Nim exe (under wine)
relocated its footer + verified its payload sha256 from its own **signed** image. Only the
cert *chain* failed (self-signed) — an EV cert resolves that. See `docs/PLAN.md` §10.

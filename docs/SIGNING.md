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

## `--self-signed` (Ed25519, any platform) — edit-detection, NOT tamper-evidence

`--cert-file` above is the real thing on Windows: the OS validates the Authenticode signature
against a trusted chain, so an editor cannot re-sign without the vendor's (non-exportable) key.
ELF and Mach-O have no such OS-enforced equivalent baked into the loader. `--self-signed` is a
deliberately weaker, cross-platform mechanism that fills part of that gap — and its limit has to
be stated every time it is, or it becomes an over-claim (INV-DOC-02).

What it does. `--self-signed` generates (or reuses) an Ed25519 key and signs the build's footer
— specifically the structural + digest fields (format version, flags, payload offset/length,
payload sha256, stub-config offset/length, stub-config sha256). The signature and the public key
ride in a new v3 footer tail. At launch the binary verifies the payload and stub-config digests
against the actual bytes first (INV-LAUNCH-01 / INV-STUB-01), THEN checks the signature over
those digests, so a valid signature transitively covers the payload and stub. A payload edit
that recomputes the footer digest but does not re-sign is refused (exit 13). This is
INV-SIGN-01.

The honest limit. **`--self-signed` detects post-build payload edits by anyone who does not ALSO
rewrite the embedded public key; it is NOT tamper-evidence unless the fingerprint is pinned OUT
OF BAND.** The public key lives in the same file as the signature (a signature cannot
authenticate itself), so an attacker who edits the payload can re-sign it with their own key and
overwrite the embedded key — and it verifies. haru-pack's own test suite asserts exactly this
case passes, so the limit cannot be quietly forgotten. It becomes real assurance only when the
recipient obtains the key's fingerprint through a channel the attacker does not control (your
website over HTTPS, a signed release note, a keyserver) and compares it. The build prints the
fingerprint and records it on the receipt precisely so a vendor can publish it:

```
haru-pack keygen                 # once, deliberately; prints and stores the key + fingerprint
haru-pack build app/ --self-signed
# receipt: self_signed.public_key_sha256 = <64 hex> — PUBLISH this out of band
```

It does **not** claim INV-LAUNCH-03 (a signature anchored out of band), which stays `proposed`.

Key handling, on purpose:
- **Storage.** `~/.config/haru-pack/<hash-of-project>/key`, directory `0700`, file `0600`. A
  group- or world-readable key is refused, not used.
- **No silent rotation.** A build with `--self-signed` and no key FAILS — it never mints one
  mid-build. On an ephemeral CI home (a fresh `$HOME` per job) auto-generation would rotate the
  key every run, and every recipient who pinned yesterday's fingerprint would "verify" under a
  key they never saw. Mint the key once with `haru-pack keygen` (or point at one with
  `--sign-key <path>`), record the fingerprint, and reuse it. Key loss is loud, not papered over.
- **Reproducible.** Ed25519 is deterministic (RFC 8032), so `--self-signed` adds no per-build
  randomness — the same commit + key rebuilds byte-for-byte. No salt.

Implementation note: nimcrypto ships no public-key primitive, so the launcher's verifier is a
vendored TweetNaCl port (`src/haru_pack/launcher/ed25519.nim`, public domain), checked against
the RFC 8032 §7.1 vectors. Signing uses the `cryptography` library on the build side. See
INV-SUPPLY-02's note on what this means for the pinning story.

## macOS code signing / notarization — OUT OF SCOPE (this issue)

A third real path exists and this issue does **not** implement it: Apple `codesign` + Developer
ID + notarization (stapling). It is a distinct trust root with its own tooling and its own
Apple-account requirement, and pretending `--self-signed` substitutes for it would be an
over-claim. For a Mach-O build today: `--self-signed` gives you the same edit-detection (with the
same out-of-band-pin limit) it gives an ELF, and nothing more. A macOS `codesign`/notarization
seam is future work, tracked separately from #61.

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

Partially mitigated as of 2026-09-09 — but read what the mitigation covers, because "every
staged artifact is verified by us" is not true and was claimed here until 2026-09-15. Three
different levels of assurance go into one payload:

- **The two staged binaries — uv and the CPython interpreter — are ours to check.** Each is
  verified at build time against a SHA-256 pinned in `src/haru_pack/pins.toml` before it enters
  the payload, and an unpinned artifact is refused rather than fetched (`INV-SUPPLY-01`,
  `INV-SUPPLY-06`, `INV-SUPPLY-07`).
- **The application's own wheels are hash-verified, but not by us.** `INV-SUPPLY-08` makes the
  install hash-checked; the hashes come from the lockfile and **uv** enforces them. That is
  delegated verification — good, and a different thing from a pin in this repository.
- **The Nim compiler that builds the launcher is not pinned at all.** haru-pack pins the
  choosenim installer; choosenim fetches the toolchain from nim-lang.org and nothing here hashes
  it (`INV-SUPPLY-01`, residual-gap Note). It is not *staged*, so it is outside this section's
  gap — but it is in the exe you are about to sign.

On top of that the payload as a whole is digest-checked at launch (`INV-LAUNCH-01`, with the
caveats above — it is not a MAC). Together that closes "did we stage the bytes upstream
published" for the two staged binaries; it does not make the staged interpreter *signed*, so
Smart App Control's requirement is still unmet. See `research/05` Part 5 (#3) and Part 9.4.

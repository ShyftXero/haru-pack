# haru-pack — invariants

Properties this codebase has decided must never regress. Adopted from the lotek
`INVARIANTS.md` pattern; the ID scheme, the mandatory **Red-path**, and the
machine-checked linkage contract are the same.

## Why this file exists

haru-pack's first full adversarial review (2026-09-09) found five security claims
that were documented, dated, and marked "Verified" — and unimplemented. The failure
mode is not carelessness; it is that **prose evidence is satisfiable by a claim**.
A paragraph saying "the launcher verifies its payload sha256" costs the same to write
whether or not the code does it. `pytest -m invariant` does not.

The design constraint, borrowed from lotek's process retrospective:

> Any new control must produce evidence a human can check in under a minute,
> or it will be satisfied with a claim.

## Entry format

| Field | Meaning |
|---|---|
| `Status` | `active` — **must** have ≥1 test marked `@pytest.mark.invariant("<id>")`. `proposed` — **must** have zero. A `proposed` entry is a known gap, honestly labelled, not a promise. |
| `Statement` | One falsifiable sentence. |
| `Actors` | Who is on the other side of it. |
| `Assets` | What is lost if it breaks. |
| `Red-path` | **Mandatory.** What you would break to watch the claiming test go red. If you cannot write this, you do not have an invariant — you have a wish. |
| `Source` | The commit, audit, or incident it was mined from. |
| `Territory` | Repo-relative paths where the behavior lives. Required once `active`. |

## What this file does and does not prove

The linkage contract (`tests/test_invariants_enforced.py`) proves that every `active`
invariant is **claimed** by at least one test. It **cannot prove efficacy** — it has no
way to distinguish a test that would go red along the red-path from one that could not.
That is why the Red-path field is mandatory and why neutralize-then-observe-red is the
expected workflow before marking an invariant `active`.

`INV-LAUNCH-01` through `INV-LAUNCH-04`, `INV-SUPPLY-01`, `INV-SUPPLY-02` and
`INV-SECRET-01` are deliberately `proposed`. The behavior is **not implemented**. They are
written down so the gap is legible, not so it looks covered.

---

## BUILD — the build pipeline reports what it actually did

### INV-BUILD-01
Status: active
Statement: `build()` reports `encrypted=True` only if the bytes actually attached to the
launcher are an encrypted container; a build never claims a protection it did not apply.
Actors: the operator running the build; anyone downstream reading the build receipt.
Assets: the operator's belief about whether the shipped artifact is protected.
Red-path: Hardcode `encrypted=True` in the `info.update(...)` call in `build.build`, or
detach it from the branch that actually calls `crypto.encrypt`. The claiming test inspects
the produced payload for the container magic and goes red.
Source: CRIT C1 — `--encrypt` accepted a secret, printed success, and shipped plaintext.
Territory: src/haru_pack/build.py, src/haru_pack/cli.py

### INV-BUILD-02
Status: active
Statement: A build that requests encryption on the command line either produces an
encrypted payload or fails with a non-zero exit; there is no path that silently downgrades.
Actors: the operator; the licensee the encryption was meant to constrain.
Assets: the payload's confidentiality; the entire licensing story built on it.
Red-path: Remove `encrypt` from the parameters threaded into `build.build()` and restore
the `any([expires, geo, machine, user, embed_secret])` enablement rule. `--encrypt --secret X`
with no policy flag then exits 0 with a plaintext payload and the claiming test goes red.
Source: CRIT C1, adversarial review 2026-09-09. The bug shipped in a documented example.
Territory: src/haru_pack/cli.py, src/haru_pack/build.py

---

## CRYPTO — the container is what both implementations think it is

### INV-CRYPTO-01
Status: active
Statement: The license policy never appears in cleartext anywhere in a built artifact;
expiry, geo, machine and user are recoverable only after successful authenticated decryption.
Actors: a licensee reverse-engineering the binary they were shipped.
Assets: the policy itself (knowing the expiry date is the first step to editing it).
Red-path: Move the policy from inside the AES-GCM plaintext to the container header (which
is what `docs/ENCRYPTION_LICENSING.md` incorrectly described for months). The claiming test
scans the whole container for the policy's field values and goes red.
Source: Adversarial review 2026-09-09, finding N17 — three contradictory descriptions of
this container, two of them wrong about the mechanism that provides this property.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim

### INV-CRYPTO-02
Status: active
Statement: The container's byte layout is fixed and identical on the writer (Python) and
reader (Nim) sides; a change to one without the other is caught before release.
Actors: a maintainer editing either side; an AI agent editing one file in isolation.
Assets: every encrypted build ever shipped — a silent offset drift bricks them at runtime
with a message that reads as "wrong secret".
Red-path: Change any offset constant in `crypto.encrypt`'s header packing, or in
`cryptbox.parseBox`'s slice bounds, without changing the other. The claiming test asserts
the Python-produced offsets against the offsets parsed out of the Nim source and goes red.
Source: Adversarial review 2026-09-09. `docs/ENCRYPTION_LICENSING.md` asserted byte-for-byte
interop under a dated "Verified" heading with no test behind it.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim

### INV-CRYPTO-03
Status: active
Statement: Tampering with any byte of an encrypted container causes authenticated decryption
to fail; the container is never partially trusted.
Actors: a licensee editing the shipped binary to extend or remove their license.
Assets: the payload; the enforceability of every policy field.
Red-path: Pass `None` as the AAD in `AESGCM.encrypt`, or ignore the returned tag when
assembling the container. The claiming test flips a bit in each container region and asserts
authentication failure on every one; it goes red for the region that stopped being covered.
Source: Adversarial review 2026-09-09.
Territory: src/haru_pack/crypto.py

### INV-CRYPTO-04
Status: proposed
Statement: The container header — version, flags, KDF iteration count, salt, nonce and
embedded-secret length — is covered by the AEAD, so tampering with it is *detected* rather
than merely unproductive.
Actors: a licensee editing the header of a binary they were shipped.
Assets: the distinction between "cannot be changed" and "gains nothing by changing".
Red-path: Once the AAD covers the header — flip the `flags` byte and observe an
authentication failure attributable to the tag, not to a derived-key mismatch.
Source: Found by `test_header_is_unauthenticated_but_fail_closed` while writing the
INV-CRYPTO-03 suite on 2026-09-09. The AAD is the fixed magic `HPAKENC1`, so 62 bytes of
header sit outside it. Today the effect is fail-closed: every header edit changes key
derivation and the open fails. It is a robustness gap, not a bypass.
Note: Fixing this requires a coordinated change to `crypto.py` and `cryptbox.nim` plus a
container version bump; a one-sided change bricks every existing encrypted build. Do not
attempt it without the ability to compile and run the Nim launcher.
Territory: src/haru_pack/crypto.py, src/haru_pack/launcher/cryptbox.nim

---

## PAYLOAD — only what the operator meant to ship gets shipped

### INV-PAYLOAD-01
Status: active
Statement: No file matching a credential-material pattern (`.env`, `*.pem`, `*.key`,
`id_rsa*`, `.ssh/`, `.aws/`, `credentials*`, `*.p12`, `*.pfx`) is copied into a payload,
regardless of where it sits in the source tree.
Actors: an operator who runs `haru-pack build .` in a project directory that also holds
their working `.env`; every recipient of the resulting binary.
Assets: the operator's API keys, signing keys, and cloud credentials — published inside a
binary that is, by design, distributed widely and often signed.
Red-path: Delete the credential patterns from `build._IGNORE`. The claiming test builds a
payload from a fixture tree containing `.env` and `id_rsa` and asserts they are absent from
the zip; it goes red immediately.
Source: CRIT C4, adversarial review 2026-09-09. `_IGNORE` excluded `.git` and `__pycache__`
but nothing secret-shaped.
Territory: src/haru_pack/build.py

### INV-PAYLOAD-02
Status: active
Statement: `overlay.verify()` reports `sha_ok=False` for any modification to the attached
payload; the build-time integrity check is not decorative.
Actors: anyone tampering with a distributed binary; the operator running `haru-pack verify`.
Assets: the only integrity signal haru-pack offers on unsigned (ELF) output.
Red-path: Make `verify()` return `sha_ok=True` unconditionally, or compare the digest against
itself. The claiming test mutates one payload byte and goes red.
Source: Adversarial review 2026-09-09, findings C2/C3.
Note: This invariant covers the **build-time** check only. The **runtime** launcher does not
perform it at all — see `INV-LAUNCH-01`, which is `proposed` for exactly that reason. Do not
read this entry as evidence that shipped binaries self-verify. They do not.
Territory: src/haru_pack/overlay.py

---

## LAUNCH — what the shipped binary does on a machine you do not control

### INV-LAUNCH-01
Status: proposed
Statement: The launcher refuses to stage or execute a payload whose SHA-256 does not match
the digest recorded in its own footer.
Actors: anyone who can write to a distributed binary — a mirror, a shared fileserver, malware
already resident on the target.
Assets: code execution under the vendor's identity and (on Windows) their EV signature. The
payload contains `pre_install`/`post_install` argv that the launcher runs.
Red-path: Once implemented — corrupt one payload byte in a built exe without touching the
footer, run it, and observe it refuse. Today that binary runs the modified payload happily.
Source: CRIT C2, adversarial review 2026-09-09. `main.nim` reads `ft.payloadSha`, hex-encodes
it, and uses the first 16 characters as a **cache directory name**. It never compares it to
anything. `docs/SIGNING.md` claimed under a dated "Validated (2026-09-09)" heading that this
check had been observed working.
Note: A footer digest is not a MAC — an attacker who edits the payload can recompute it. This
invariant, once implemented, defends against corruption and naive edits; it is not
tamper-evidence. Real tamper-evidence on Windows comes from Authenticode over the overlay.
Linux ELF output has no equivalent. `INV-LAUNCH-03` is the real fix.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/launcher/overlay.nim

### INV-LAUNCH-02
Status: proposed
Statement: The `HARUPACK_DEV_STAGE` staging bypass is absent from release builds; a
distributed launcher cannot be redirected to an arbitrary payload tree by an environment
variable.
Actors: anyone who can set an environment variable for the victim's process.
Assets: the vendor's code-signing identity. A signed launcher that runs attacker-chosen code
on demand is a signed proxy for arbitrary execution, and it skips decryption and every
license check on that path.
Red-path: Once gated behind `when defined(haruDev)` — build a release launcher, set
`HARUPACK_DEV_STAGE=/tmp/anything`, run it, and observe it ignore the variable.
Source: CRIT C5, adversarial review 2026-09-09.
Territory: src/haru_pack/launcher/main.nim

### INV-LAUNCH-03
Status: proposed
Statement: The launcher verifies a signature over the payload — not merely a digest — before
executing anything it contains, on every platform including ELF targets.
Actors: as INV-LAUNCH-01, plus an attacker who can rewrite the footer.
Assets: as INV-LAUNCH-01.
Red-path: Once implemented — re-sign a payload with the wrong key and observe refusal.
Source: Adversarial review 2026-09-09, finding C3. Directly analogous to lotek's runner
self-upgrade gate, where a SHA-256 manifest match only *proposes* an upgrade and a valid
Ed25519 signature is required to act on it.
Territory: src/haru_pack/launcher/main.nim, src/haru_pack/overlay.py

### INV-LAUNCH-04
Status: proposed
Statement: A launcher built at the `thick` tier executes only binaries staged from its own
payload; it never resolves `uv` or an interpreter from `PATH` or the working directory.
Actors: anyone who can drop a file named `uv` into the target's PATH or cwd.
Assets: execution under the application's identity, defeating the tier's offline/hermetic claim.
Red-path: Once implemented — place a fake `uv` earlier in PATH than the bundled one and
observe the bundled one still win.
Source: Adversarial review 2026-09-09, finding W14. `main.findUv` consults `findExe("uv")`
before falling back to fetching.
Territory: src/haru_pack/launcher/main.nim

---

## SUPPLY — what we execute that we did not write

### INV-SUPPLY-01
Status: proposed
Statement: Every artifact haru-pack downloads and then executes — Nim, uv, and the
python-build-standalone interpreter — is verified against a pinned digest before use.
Actors: anyone who can serve or tamper with a release asset; a compromised upstream account.
Assets: the build host's toolchain, and every binary it subsequently produces. The staged
interpreter ends up inside a signed customer deliverable.
Red-path: Once implemented — point a download at a modified archive with a valid TLS
certificate and observe the build refuse.
Source: Adversarial review 2026-09-09, finding W6. Four download sites, zero checks:
`bootstrap.install_nim`, `bundle.bundle_uv`, `bundle.bundle_python`, `uvfetch.ensureUv`.
`uv python list --output-format json` already returns a `sha256` per entry that
`_find_python_url` reads past and discards.
Territory: src/haru_pack/bootstrap.py, src/haru_pack/bundle.py, src/haru_pack/launcher/uvfetch.nim

### INV-SUPPLY-02
Status: proposed
Statement: The Nim libraries linked into a shipped launcher are version-pinned, so the same
commit produces the same cryptographic implementation.
Actors: not an attacker — entropy. Also anyone who compromises a nimble package.
Assets: reproducibility, and the meaning of any statement about the launcher's crypto.
Red-path: Once pinned — resolve dependencies twice across a library release and observe the
same versions.
Source: Adversarial review 2026-09-09, finding W7. `nimble install -y zippy puppy parsetoml
nimcrypto` is unpinned, eleven lines below `NIM_VERSION = "2.2.6"  # pinned; bump deliberately`.
Territory: src/haru_pack/bootstrap.py

### INV-SUPPLY-03
Status: active
Statement: No archive is extracted with a call that permits writes outside the destination
directory; every `tarfile` extraction passes `filter="data"`.
Actors: whoever controls an archive we fetched over unverified TLS (see INV-SUPPLY-01).
Assets: the build host's filesystem.
Red-path: Drop the `filter=` argument from any `extractall` call in `bootstrap.py` or
`bundle.py`. The claiming test scans the source for unfiltered `extractall` and goes red.
Source: Adversarial review 2026-09-09, finding W8. `requires-python = ">=3.9"`, where the
tarfile default is the pre-CVE-2007-4559 behavior.
Territory: src/haru_pack/bootstrap.py, src/haru_pack/bundle.py

---

## SECRET — key material does not leak sideways

### INV-SECRET-01
Status: proposed
Statement: A license secret typed at the runtime prompt is never echoed to the terminal.
Actors: shoulder-surfers; anyone reading a recorded terminal session or CI log.
Assets: the license secret, which is the entire trust anchor — there is no PKI behind it.
Red-path: Once implemented — run an encrypted build interactively and observe no echo.
Source: Adversarial review 2026-09-09, finding W11. `cryptbox.resolveSecret` uses
`stdin.readLine()`; `std/terminal` is already imported but `readPasswordFromStdin` is not used.
Territory: src/haru_pack/launcher/cryptbox.nim

### INV-SECRET-02
Status: active
Statement: A build secret is never written into a manifest, a build receipt, or any other
artifact the build produces.
Actors: anyone who reads the project repo or the shipped binary.
Assets: the license secret.
Red-path: Add the secret to the `info` dict returned by `build.build`, or to the manifest
written by `assemble_payload`. The claiming test builds with a known secret and asserts it
appears in no produced file or return value; it goes red.
Source: Adversarial review 2026-09-09. `docs/CONFIG.md` states the secret is never stored in
config — asserted in prose only.
Note: This does **not** cover `--secret <literal>`, which puts key material in shell history
and `ps` output. That is a documented sharp edge, not a defended one.
Territory: src/haru_pack/build.py, src/haru_pack/cli.py

---

## DOC — claims are traceable to evidence

### INV-DOC-01
Status: active
Statement: Every `INV-` identifier cited anywhere in `src/`, `docs/`, `tests/` or a root
markdown file resolves to a real entry in this file.
Actors: a future maintainer or AI agent citing an invariant that was never declared.
Assets: the credibility of the whole scheme. lotek added this scanner after discovering
`INV-MODULARITY-01` cited across seven source files and five plans docs without ever
being declared.
Red-path: Write `INV-NONSENSE-99` in any tracked file. The claiming test goes red.
Source: Adopted from lotek `tests/test_invariants_enforced.py`.
Territory: INVARIANTS.md, tests/test_invariants_enforced.py

### INV-DOC-02
Status: active
Statement: A dated "Verified" or "Validated" claim in the docs names the invariant or test
that backs it; verification is never asserted in prose alone.
Actors: an AI agent writing a plausible-sounding validation record for work it did not do.
Assets: the reader's ability to tell a checked claim from an imagined one. Both existing
"Verified (2026-09-09)" footers in this repo predated any test; the one in `docs/SIGNING.md`
described a runtime SHA-256 check that has never existed in the code.
Red-path: Add a `## Verified (2026-01-01)` heading to any doc with no `INV-` reference in
its body. The claiming test goes red.
Source: CRIT C2, adversarial review 2026-09-09. This is the control aimed squarely at the
hallucinated-security-feature failure mode.
Territory: docs/, tests/test_invariants_enforced.py

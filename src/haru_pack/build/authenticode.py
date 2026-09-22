"""--cert-file: the Windows Authenticode signing SEAM (not the signature itself).

Authenticode over the PE is the REAL tamper-evidence on Windows (INV-LAUNCH-03's platform
half): the OS validates the signature against a trusted chain, so an editor cannot re-sign
without the vendor's key. That key is the catch. Since the June-2023 CA/Browser Forum
baseline, publicly-trusted code-signing private keys are non-exportable — they live on a
FIPS HSM/token or a cloud signer (Azure Trusted Signing / Key Vault, AWS/GCP KMS), driven by
`osslsigncode` (PKCS#11) or `jsign` (docs/SIGNING.md). haru-pack cannot hold such a key and
must not pretend to: there is no raw-PEM path here on purpose.

So this module WIRES the flag and the hook point and defers the actual invocation to the
SIGNING.md flow. It refuses the cases it can prove wrong at build time (a non-Windows target,
a missing cert file) and, for a PE, emits the exact golden-order command to run against the
produced binary. What it deliberately does NOT do — yet — is shell out to `osslsigncode`/
`jsign` itself; that needs the operator's token/cloud credentials and is marked as the
remaining piece rather than faked (see the PR / docs/SIGNING.md).
"""
from __future__ import annotations

from pathlib import Path

from ..targets import Target
from .errors import BuildError


def plan_authenticode(*, cert_file: str, tgt: Target, out: Path, say) -> dict:
    """Validate a --cert-file request and emit the signing instructions. Returns a receipt
    fragment recording the deferred intent; raises BuildError on a request that cannot be
    satisfied at all (wrong OS target, missing cert)."""
    if not cert_file:
        return {}
    if tgt.os != "windows":
        raise BuildError(
            f"--cert-file is Windows Authenticode signing, but the target is '{tgt}'. "
            f"Authenticode covers a PE only. For an ELF/macOS build use --self-signed "
            f"(honest limit applies), or drop --cert-file for this target.")
    cert = Path(cert_file)
    if not cert.exists():
        raise BuildError(f"--cert-file {cert_file!r} does not exist.")
    say(
        "--cert-file: Authenticode signing is DEFERRED to your signing tool — haru-pack does "
        "not hold your (non-exportable) code-signing key. The PE is written UNSIGNED; sign it "
        "LAST, after this build, so the footer stays inside the Authenticode hash:\n"
        f"  osslsigncode sign -pkcs11engine <engine> -pkcs11module <module> \\\n"
        f"    -certs {cert} -key 'pkcs11:object=...;type=private' \\\n"
        f"    -h sha256 -ts http://timestamp.digicert.com \\\n"
        f"    -in {out} -out {out}.signed\n"
        "  # or jsign with a cloud signer (Azure Trusted Signing / KMS) — see docs/SIGNING.md\n"
        "Then: `osslsigncode verify` (Calculated == Current message digest) and "
        "`haru-pack verify` (footer + payload sha256 intact).")
    return {"cert_file": str(cert), "signed": False, "deferred": True,
            "tool": "osslsigncode|jsign", "note": "sign the PE last; see docs/SIGNING.md"}

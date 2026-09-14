"""`build()` — the order the phases of a build happen in, and nothing else.

Read top to bottom, this module is meant to be the readable summary of what `haru-pack
build` does: preflight, resolve, decide the knobs, produce the artifact, write the receipt.
Each phase's actual work lives in a sibling module. That is deliberate — when this function
held all of it, the shape of a build was invisible underneath ninety lines of advisory
prose and forty lines of receipt assembly.

The ONE thing that must stay true here: every refusal that can be made before a binary
exists is made before a binary exists (docs/PRINCIPLES.md). The preflight and knob phases
run entirely ahead of the temporary directory, so a bad canary token, a past expiry, an
impossible `--shake` or an unwritable `--emit-c` target costs the operator nothing.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from .. import crypto
from ..bootstrap import detect_c_toolchain, find_nim
from ..obfuscate import ObfuscationError, get_engine      # noqa: F401  (ObfuscationError re-export)
from ..overlay import FOOTER_FLAG_ENCRYPTED
from ..payload import build_payload_zip
from ..targets import Target
from . import advisories, emitkit, receipt
from .assemble import assemble_payload
from .canary import resolve_canary, stub_config_bytes
from .compiler import compile_launcher, resolve_cc
from .declare import _resolve
from .errors import BuildError
from .geo import build_geo_policy
from .inject import resolve_injects
from .staging import _attach_payload, resolve_base_path, resolve_source_url
from .tree import _staged_tree_bytes
from .validate import prepare_output_dir
from .. import shake as shake_mod


def _preflight(tgt: Target, cc: str, log) -> tuple[str, str, dict]:
    """Everything that must exist on THIS machine before a build is worth starting.

    Returns (nim path, cc provider, toolchain info).
    """
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    # The SYSTEM toolchain is only required when it is the one being used. With the default
    # `--cc zig` the compiler is the pinned one haru-pack installs for itself, so demanding
    # `build-essential` here would defeat the entire point of that default — no sudo, no
    # package manager (INV-TOOL-02). This gate used to run unconditionally.
    provider = resolve_cc(cc, target=tgt, log=log)
    if provider == "system":
        tc = detect_c_toolchain(tgt)
        if not tc["ok"]:
            raise BuildError(
                f"C toolchain missing for target '{tgt}':\n{tc['advice']}\n"
                f"Or drop `--cc system` and let haru-pack use its own pinned zig, which "
                f"needs no system packages.")
    else:
        tc = {"ok": True, "compiler": f"zig ({tgt.zig_triple()})", "advice": ""}
    return nim, provider, tc


def _record_obfuscation(manifest: dict, obfuscate: str, obfuscate_args, tier: str,
                        python: str, say) -> None:
    """Validate the requested engine and record it on the manifest for assemble_payload.

    Validated HERE, at the front of the build, so an unknown engine or a missing pyarmor
    fails before any work — never after producing a binary the user believes is obfuscated.
    """
    if obfuscate and obfuscate != "none":
        eng = get_engine(obfuscate)          # raises ObfuscationError on an unknown name
        if reason := eng.available():
            raise BuildError(reason)
    manifest["_obfuscation"] = {"engine": obfuscate or "none",
                                "args": list(obfuscate_args)}
    if obfuscate_args and obfuscate in (None, "", "none"):
        raise BuildError("obfuscation arguments were given but no engine was selected; "
                         "pass --obfuscate <engine>")
    advisories.announce_obfuscation_tier(obfuscate=obfuscate, tier=tier, python=python, say=say)


def build(project: Path, out: Path, target: str = "host", tier: str = "default",
          secret: bytes | None = None, expires: str = "", geo=None,
          geo_restrict=(), geo_api_urls=(), geo_consensus: int = 1,
          machine: str = "", user: str = "", embed_secret: bool = False,
          obfuscate: str = "none", obfuscate_args=(),
          python: str = "", wine: bool = False, encrypt: bool = False,
          entry_point: str = "", shake: bool = False, shake_keep=(),
          env_canary: str = "", env_canary_random: bool = False,
          stub_env_secret_canary: str = "", stub_env_uv_ver_canary: str = "",
          stub_env_source_url_canary: str = "", stub_env_base_path_canary: str = "",
          stub_env_ephemeral_canary: str = "",
          reap: bool = False, overwrite: bool = False, ram_only: bool = False,
          no_reap: bool = False, base_path: str = "", source_url: str = "", env_append=None,
          cc: str = "", emit_c: str = "", emit_nim: str = "", log=None) -> dict:
    project = Path(project); out = Path(out)
    prepare_output_dir(out)
    say = log or (lambda _m: None)
    emit_c_dir = emitkit.validate_c_dir(emit_c)
    tgt = target if isinstance(target, Target) else Target.parse(target)
    nim, provider, tc = _preflight(tgt, cc, log)

    # Phase 4: fold --geo / --geo-restrict / --geo-restrict-api-url / --geo-restrict-consensus
    # into the uniform gate object BEFORE resolve, so enc["geo"] carries the online-gate policy
    # (INV-GATE-01 / INV-GEO-01). {} = no geo gate.
    geo_policy = build_geo_policy(geo, geo_restrict, geo_api_urls, geo_consensus)
    manifest, enc, pyver, source, sources = _resolve(project, tier, python, expires, geo_policy,
                                                     machine, user, embed_secret, encrypt,
                                                     entry_point, log=log)
    _record_obfuscation(manifest, obfuscate, obfuscate_args, tier, python, say)
    if enc["enabled"] and secret is None:
        raise BuildError("encryption is configured but no secret — pass "
                         "--secret / --secret-env / --secret-prompt")

    # Canary map + injects are resolved BEFORE any compilation, so a bad token or a reserved
    # inject fails fast (like --shake's preconditions) rather than after producing a payload.
    # The secret-shaped inject WARNING depends on whether the payload will be encrypted, which
    # is known here (INV-INJECT-01). One resolution rule for all five knobs (INV-CANARY-02).
    canary = resolve_canary(env_canary, env_canary_random,
                            per_knob={"secret": stub_env_secret_canary,
                                      "uv_ver": stub_env_uv_ver_canary,
                                      "source_url": stub_env_source_url_canary,
                                      "base_path": stub_env_base_path_canary,
                                      "ephemeral": stub_env_ephemeral_canary}, log=log)
    injects = resolve_injects(env_append, encrypted=enc["enabled"], log=log)
    base_path = resolve_base_path(base_path)
    source_url = resolve_source_url(source_url)   # Phase 3 (INV-REMOTE-01); "" = appended delivery
    reap = advisories.couple_staging_flags(reap=reap, overwrite=overwrite, ram_only=ram_only,
                                           no_reap=no_reap, say=say)
    advisories.announce_staging(enc=enc, reap=reap, overwrite=overwrite, ram_only=ram_only,
                                base_path=base_path, say=say)
    if injects:
        # Lives in the PAYLOAD manifest (post-decrypt), so --encrypt hides it (docs/adr/0003
        # §4.3). Carried through assemble_payload's manifest dump; the launcher reads `inject`.
        manifest["inject"] = injects

    shake_report: dict = {}
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            payload_dir = assemble_payload(source, manifest, tier, tgt, pyver, tdp / "asm",
                                           wine, sources=sources, log=log, shake=shake,
                                           shake_keep=shake_keep,
                                           shake_report=shake_report)
        except shake_mod.ShakeError as e:
            # A shake that cannot be PROVEN safe is a failed build, not a smaller one. The
            # alternative — warn and ship the unshaken payload — hands the operator a
            # binary that is nothing like the one they asked for, and they find out from
            # its size or not at all.
            raise BuildError(f"--shake refused to ship: {e}") from e
        # The staged-tree size baked into the stub-config so the launcher can size its RAM-fit
        # check BEFORE staging (docs/adr/0007, INV-EPHEMERAL-01). This is the EXPANDED tree the
        # launcher stages (uv is un-XZ'd on stage), not the compressed payload dir — see
        # _staged_tree_bytes. Only needed when staging may go to RAM.
        unpacked_bytes = _staged_tree_bytes(payload_dir) if ram_only else 0
        payload = build_payload_zip(payload_dir)
        flags = 0
        if enc["enabled"]:
            payload = crypto.encrypt(payload, secret, expires=enc["expires"], geo=enc["geo"],
                                     machine=enc["machine"], user=enc["user"],
                                     embed_secret=enc["embed_secret"])
            flags = FOOTER_FLAG_ENCRYPTED
        # INV-BUILD-01: never report a protection we did not apply. Checked against the
        # bytes about to be attached, not against the intent that produced them.
        if enc["enabled"] != payload.startswith(crypto.MAGIC):
            raise BuildError(
                "internal: encryption state does not match the payload "
                f"(requested={enc['enabled']}, container={payload.startswith(crypto.MAGIC)}). "
                "Refusing to emit a binary whose build receipt would be wrong.")
        launcher = compile_launcher(nim, tgt, tdp, cc=cc, log=log)
        sc_bytes = stub_config_bytes(canary, reap=reap, overwrite=overwrite,
                                     ram_only=ram_only, base_path=base_path,
                                     source_url=source_url, unpacked_bytes=unpacked_bytes)
        # Every NEW binary is v2: it always carries the cleartext, signature-covered
        # stub-config section the launcher reads before decrypt (docs/adr/0003 §1.5).
        info = _attach_payload(launcher=launcher, payload=payload, out=out, flags=flags,
                               sc_bytes=sc_bytes, source_url=source_url, say=say)
        if emit_c_dir is not None:
            emitkit.write_c_kit(emit_c_dir, info=info, nimcache=tdp / "nimcache", tgt=tgt,
                                payload=payload, stub_config=sc_bytes, flags=flags,
                                source_url=source_url, out=out, enc=enc, log=log, say=say)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    receipt.finish(info, sources=sources, provider=provider, tier=tier, tgt=tgt, nim=nim,
                   compiler=tc["compiler"], out=out, enc=enc, manifest=manifest, pyver=pyver,
                   canary=canary, reap=reap, overwrite=overwrite, ram_only=ram_only,
                   base_path=base_path, source_url=source_url, unpacked_bytes=unpacked_bytes,
                   shake_report=shake_report)
    emitkit.write_nim_kit(emit_nim, info=info, tgt=tgt, provider=provider, payload=payload,
                          stub_config=sc_bytes, flags=flags, source_url=source_url, out=out,
                          say=say)
    return info

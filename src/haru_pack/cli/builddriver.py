"""The build itself, as a plain function with ordinary Python defaults.

There are two ways to ask for a build — the `build` subcommand and the bare
`haru-pack <path>` form — and exactly one implementation, `_run_build`, with ordinary
Python defaults. That is deliberate and was learned the hard way: routing the bare form
through `ctx.invoke` left every parameter the caller did not pass as a typer `OptionInfo`
sentinel rather than its default, which printed "🦣 chonky mode" on a plain
`haru-pack hello.py` and then crashed on `OptionInfo.encode()`.

Separated from the typer command in `buildcmd` so that the option DECLARATIONS and the
build LOGIC are not the same file: the declarations change when a flag is added, the logic
changes when a build changes, and they have almost no imports in common.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged; `_run_build`'s
phases are now named functions rather than one 86-statement block.
"""
from __future__ import annotations

import os
from pathlib import Path

import typer

from ..build import BuildError
from ..build import build as build_exe
from ..discovery import AmbiguousProject, EmptyProject
from ..entrypoints import EntryPointError
from ..targets import Target, TargetError
from ..tiers import TIERS
from ..ui import print
from .naming import prog
from .report import _report_ambiguity


def _resolve_tier(tier: str, thin: bool, thick: bool, chonky: bool) -> str:
    """The tier flags are aliases for `--tier`; refuse a name that is not one."""
    if thin: tier = "thin"
    if thick or chonky: tier = "thick"
    if tier not in TIERS:
        print(f"unknown tier '{tier}' ({'|'.join(TIERS)})", style="error"); raise typer.Exit(2)
    if chonky:
        print("🦣 chonky mode: bundling everything…", style="magenta")
    return tier


def _resolve_ephemeral(*, ram_only: bool, ephemeral: bool, reap: bool, no_reap: bool) -> bool:
    """Fold `--ram-only`/`--ephemeral` into one value, and say when a flag does nothing.

    NAMING (N1): three names, one concept split across build-time and runtime.
      --ephemeral   the flag a packager types (build-time)
      ram_only      the WIRE key it maps to in the stub-config / build() kwarg (unchanged since
                    ADR 0004 §2.2 pins the v1 corpus) — so `ram_only == ephemeral` here
      EPHEMERAL     the RUNTIME canary knob (<canary>_EPHEMERAL) the TARGET sets (docs/adr/0007)
    --ram-only is the deprecated surface name of --ephemeral (docs/adr/0004).
    """
    if ram_only and not ephemeral:
        print(f"{prog()}: --ram-only is deprecated; use --ephemeral (same behavior)", style="warn")
    ram_only = ephemeral or ram_only
    # N2: --no-reap only opts out of the reap that --ephemeral IMPLIES; with neither --ephemeral
    # nor --reap there is no reap to opt out of, so it is a no-op. Say so rather than let it look
    # like it did something.
    if no_reap and not (ram_only or reap):
        print(f"{prog()}: --no-reap has no effect without --ephemeral (or --reap) — nothing "
              f"implies a reap to opt out of", style="warn")
    return ram_only


def _default_out(project: Path, target: str) -> Path:
    """Where the binary lands when `--out` was not given: the project name, target-suffixed."""
    try:
        suffix = Target.parse(target).exe_suffix
    except TargetError as e:
        print(f"{prog()}: {e}", style="error"); raise typer.Exit(2)
    return Path(project.name or "app").with_suffix(suffix)


def _resolve_secret(*, encrypt, embed_secret, secret, secret_env, secret_prompt,
                    expires, machine, user, geo, geo_restrict):
    """Decide whether this build is encrypted, and get the secret if it is.

    Any policy field at all forces encryption (INV-BUILD-02), so a declared licence or gate
    can never ship unenforced; a missing secret then fails here rather than silently.
    """
    want_enc = (encrypt or embed_secret or secret or secret_env or secret_prompt or expires
                or machine or user or geo or geo_restrict)
    sec = None
    if want_enc:
        if secret:            sec = secret.encode()
        elif secret_env:      sec = os.environ.get(secret_env, "").encode()
        elif secret_prompt:
            import getpass; sec = getpass.getpass("build secret: ").encode()
        if not sec:
            print("encryption requested but no secret — use --secret / --secret-env / --secret-prompt", style="error"); raise typer.Exit(2)
    return want_enc, sec


def _print_receipt(info: dict) -> None:
    """What the operator sees when a build worked: what was made, and what was NOT."""
    tag = " 🔒encrypted" if info.get("encrypted") else ""
    ob = (info.get("obfuscation") or {})
    if ob.get("applied"):
        tag += f" 🌀{ob.get('engine')}"
    if info.get("shake"):
        sh = info["shake"]
        before, after = sh["payload_bytes_before"], sh["payload_bytes_after"]
        pct = (100.0 * (before - after) / before) if before else 0.0
        print(f"shaken: {sh['dropped_files']} files, {before/1e6:.1f} → "
                    f"{after/1e6:.1f} MB unpacked ({pct:.0f}% off), traced with "
                    f"{sh['tracer']} — receipt {sh['report']}", style="ok")
    if info.get("slim_python"):
        sp = info["slim_python"]
        print(f"slim-python: {sp['removed_files']} interpreter files removed after digest "
                    f"verification, {sp['freed_bytes']/1e6:.1f} MB unpacked — every path on "
                    f"the receipt", style="ok")
    print(f"built {info['out']}  (tier={info['tier']}, target={info['target']}, "
                f"{info['payload_len']} B payload, sha {info['sha256'][:16]}…){tag}", style="ok")
    # A kit that was not written is reported next to the binary that WAS, and says so —
    # the build is fine, and the operator should not have to infer that.
    if info.get("emit_c"):
        print(f"emitted C reproduction kit: {info['emit_c']}  (recompile: sh compile.sh)",
              style="ok")
    elif info.get("emit_c_error"):
        print(f"emit-c kit NOT written: {info['emit_c_error']}  (the binary above is fine)",
              style="warn")
    if info.get("emit_nim"):
        print(f"emit-nim kit: {info['emit_nim']}  (edit stub/, then `sh compile.sh`)", style="ok")
    elif info.get("emit_nim_error"):
        print(f"emit-nim kit NOT written: {info['emit_nim_error']}  (the binary above is fine)",
              style="warn")


def _run_build(*, project, out=None, target="host", tier="default", thin=False, thick=False,
               chonky=False, encrypt=False, secret=None, secret_env=None, secret_prompt=False,
               embed_secret=False, expires="", machine="", user="", geo="",
               geo_restrict=None, geo_restrict_api_url=None, geo_restrict_consensus=1, python="",
               entry_point="", wine=False, obfuscate="none", obfuscate_args="",
               shake=False, shake_keep=(), slim_python=False,
               env_canary="", env_canary_random=False,
               stub_env_secret_canary="", stub_env_uv_ver_canary="",
               stub_env_source_url_canary="", stub_env_base_path_canary="",
               stub_env_ephemeral_canary="",
               reap=False, ephemeral=False, ram_only=False, no_reap=False, overwrite=False,
               base_path="", source_url="", env_append=None, cc="", emit_c="",
               emit_nim="", self_signed=False, sign_key="", cert_file="") -> None:
    """The build, as a plain function with real Python defaults.

    Both entry points call this: the `build` subcommand and the bare `haru-pack <path>`
    form. See this module's docstring for why it is not `ctx.invoke`.
    """
    tier = _resolve_tier(tier, thin, thick, chonky)
    ram_only = _resolve_ephemeral(ram_only=ram_only, ephemeral=ephemeral, reap=reap,
                                  no_reap=no_reap)
    if out is None:
        out = _default_out(project, target)
    want_enc, sec = _resolve_secret(encrypt=encrypt, embed_secret=embed_secret, secret=secret,
                                    secret_env=secret_env, secret_prompt=secret_prompt,
                                    expires=expires, machine=machine, user=user, geo=geo,
                                    geo_restrict=geo_restrict)
    try:
        info = build_exe(project, out, target=target, tier=tier, secret=sec,
                         expires=expires, geo=[g for g in geo.split(",") if g],
                         geo_restrict=list(geo_restrict or []),
                         geo_api_urls=list(geo_restrict_api_url or []),
                         geo_consensus=geo_restrict_consensus,
                         machine=machine, user=user, embed_secret=embed_secret, python=python,
                         wine=wine, encrypt=bool(want_enc),   # INV-BUILD-02
                         obfuscate=obfuscate,
                         obfuscate_args=[a for a in obfuscate_args.split() if a],
                         entry_point=entry_point, shake=shake,
                         shake_keep=list(shake_keep or []), slim_python=slim_python,
                         cc=cc, emit_c=emit_c,
                         env_canary=env_canary, env_canary_random=env_canary_random,
                         stub_env_secret_canary=stub_env_secret_canary,
                         stub_env_uv_ver_canary=stub_env_uv_ver_canary,
                         stub_env_source_url_canary=stub_env_source_url_canary,
                         stub_env_base_path_canary=stub_env_base_path_canary,
                         stub_env_ephemeral_canary=stub_env_ephemeral_canary,
                         reap=reap, overwrite=overwrite, ram_only=ram_only, no_reap=no_reap,
                         base_path=base_path, source_url=source_url,
                         env_append=list(env_append or []),
                         emit_nim=emit_nim,
                         self_signed=self_signed, sign_key=sign_key, cert_file=cert_file,
                         log=lambda m: print(
                             f"{prog()}: {m}",
                             style="warn" if "WARNING" in m else "info"))
    except EmptyProject as e:
        # Nothing to pack (pyc-only / empty dir). Refuse cleanly — --entry-point can't
        # rescue a source that isn't there — never a raw ValueError traceback (INV-BUILD-01).
        print(f"{prog()}: {e}", style="error"); raise typer.Exit(2)
    except AmbiguousProject as e:
        _report_ambiguity(project, e)
        raise typer.Exit(2)
    except TargetError as e:
        print(f"{prog()}: {e}", style="error"); raise typer.Exit(2)
    except EntryPointError as e:
        print(str(e), style="error"); raise typer.Exit(2)
    except BuildError as e:
        print(str(e), style="error"); raise typer.Exit(2)
    _print_receipt(info)

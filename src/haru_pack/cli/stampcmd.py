"""`haru stamp` — replace a built binary's stub-config without recompiling or re-encrypting.

Compile the launcher once; call `stamp` for each recipient with their own canary tokens and
staging options. The payload bytes (and their encrypted state) are preserved exactly.
"""
from __future__ import annotations

from pathlib import Path

import typer

from ..build.canary import resolve_canary, stub_config_bytes
from ..build.errors import BuildError
from ..build.staging import resolve_base_path
from ..overlay import FOOTER_FLAG_REMOTE, stamp as _stamp, verify
from ..ui import print
from .naming import prog
from .root import app


@app.command()
def stamp(
        src: Path = typer.Argument(..., help="built haru-pack binary to re-stamp"),
        out: Path = typer.Option(..., "--out", "-o", help="output exe path"),
        env_canary: str = typer.Option("", "--env-canary", metavar="TOKEN",
            help="canary prefix for ALL stub knobs (default HARU); knob K reads "
                 "<TOKEN>_K at runtime. Must match ^[A-Za-z_][A-Za-z0-9_]*$"),
        env_canary_random: bool = typer.Option(False, "--env-canary-random",
            help="pick a random [A-Z][A-Z0-9]{7} canary for all knobs and print it"),
        stub_env_secret_canary: str = typer.Option("", "--stub-env-secret-canary",
            metavar="TOKEN", help="override the SECRET knob's canary only"),
        stub_env_uv_ver_canary: str = typer.Option("", "--stub-env-uv-ver-canary",
            metavar="TOKEN", help="override the UV_VER knob's canary only"),
        stub_env_source_url_canary: str = typer.Option("", "--stub-env-source-url-canary",
            metavar="TOKEN", help="override the SOURCE_URL knob's canary only"),
        stub_env_base_path_canary: str = typer.Option("", "--stub-env-base-path-canary",
            metavar="TOKEN", help="override the BASE_PATH knob's canary only"),
        stub_env_ephemeral_canary: str = typer.Option("", "--stub-env-ephemeral-canary",
            metavar="TOKEN", help="override the EPHEMERAL knob's canary only"),
        reap: bool = typer.Option(False, "--reap",
            help="detached on-exit cleanup of the staged subtree"),
        overwrite: bool = typer.Option(False, "--overwrite",
            help="shred staged files before reap (requires --reap)"),
        ephemeral: bool = typer.Option(False, "--ephemeral",
            help="best-effort RAM-backed staging root"),
        base_path: str = typer.Option("", "--base-path", metavar="DIR",
            help="staging-root default for stamped copies ('' = normal per-user cache)")):
    """Re-stamp a built binary with a new stub-config. No recompile, no re-encrypt.

    Compile the launcher once with `build`; call `stamp` for each recipient with their
    own canary tokens and staging options. The payload bytes (and their encrypted state)
    are preserved exactly — only the cleartext stub-config changes.

    Honest limit: the stamped values are recoverable from the binary (cleartext). Use
    short-TTL tokens or swap the real credential on first run if secrecy matters.
    """
    if not src.exists():
        print(f"{prog()}: {src}: no such file", style="error"); raise typer.Exit(2)
    try:
        src_info = verify(src)
    except ValueError as e:
        print(f"{prog()}: {src}: {e}", style="error"); raise typer.Exit(2)

    if src_info["flags"] & FOOTER_FLAG_REMOTE:
        print(f"{prog()}: {src}: cannot re-stamp a remote-fetch binary — the payload is "
              "not embedded. Host a new payload at the new URL and rebuild instead.",
              style="error"); raise typer.Exit(2)

    say = lambda m: print(f"{prog()}: {m}",
                          style="warn" if m.startswith("WARNING") else "info")
    try:
        canary = resolve_canary(
            env_canary, env_canary_random,
            per_knob={"secret": stub_env_secret_canary,
                      "uv_ver": stub_env_uv_ver_canary,
                      "source_url": stub_env_source_url_canary,
                      "base_path": stub_env_base_path_canary,
                      "ephemeral": stub_env_ephemeral_canary},
            log=say)
        base_path_v = resolve_base_path(base_path)
    except BuildError as e:
        print(str(e), style="error"); raise typer.Exit(2)

    sc = stub_config_bytes(canary, reap=reap, overwrite=overwrite,
                           ram_only=ephemeral, base_path=base_path_v)

    try:
        result = _stamp(src, sc, out)
    except (ValueError, OSError) as e:
        print(f"{prog()}: {e}", style="error"); raise typer.Exit(2)

    try:
        out.chmod(0o755)
    except Exception:
        pass

    enc_tag = " (payload encrypted)" if src_info["flags"] & 1 else ""
    print(f"stamped {out}  ({result['payload_len']} B payload, "
          f"sha {result['sha256'][:16]}…){enc_tag}", style="ok")

"""The small commands: version, verify, init, machine-id.

Grouped by size rather than by subject, deliberately. Each is a handful of lines with no
shared state, and four one-screen modules would be four files nobody can tell apart.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from pathlib import Path

import typer

from .. import __version__
from ..overlay import verify as verify_exe
from ..ui import fields, print
from .root import app


@app.command()
def version():
    """Show the haru-pack version."""
    print(f"haru-pack {__version__}")


@app.command()
def verify(exe: Path):
    """Inspect a built launcher's footer + confirm payload integrity."""
    info = verify_exe(exe)
    # Aligned on a terminal, `key: value` lines when piped — `ui.table` decides, because
    # this is the command a CI job runs and its output has to stay greppable.
    fields(info.items(), title=str(exe))
    ok = info["sha_ok"]
    print("payload integrity: OK" if ok else "payload integrity: FAILED",
          style="ok" if ok else "error")
    raise typer.Exit(0 if ok else 1)

@app.command()
def init(path: Path = typer.Argument(Path("."), help="project dir or script"),
         force: bool = typer.Option(False, "--force", help="overwrite an existing haru_pack.toml")):
    """Scaffold a haru_pack.toml, pre-filled from discovery + any available venv."""
    from .. import scaffold
    from ..discovery import discover
    out_dir = path if path.is_dir() else path.parent
    out = out_dir / "haru_pack.toml"
    if out.exists() and not force:
        print(f"{out} already exists (use --force)", style="warn"); raise typer.Exit(1)
    try:
        disc = discover(path)
    except Exception as e:
        print(f"discovery failed: {e}", style="error"); raise typer.Exit(2)
    deps = set(scaffold.project_deps(path, disc))
    learned = False
    venv = scaffold.find_venv(out_dir)
    if venv:
        vver, vpkgs = scaffold.venv_info(venv)
        if vpkgs: deps |= set(vpkgs); learned = True
        if vver and not disc.get("python"): disc["python"] = vver
        print(f"learned from venv: {venv}  ({len(vpkgs)} packages, python {vver or '?'})", style="info")
    out.write_text(scaffold.render(disc, sorted(deps), learned_from_venv=learned))
    print(f"wrote {out}  (kind={disc['kind']}, entrypoint={disc['entrypoint']}, python={disc.get('python') or 'auto'})", style="ok")

@app.command("machine-id")
def machine_id_cmd():
    """Print this machine's id (give it to a vendor to bind an --encrypt license)."""
    from ..crypto import machine_id
    print(machine_id())

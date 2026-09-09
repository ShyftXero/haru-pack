from __future__ import annotations
from pathlib import Path
import typer
from . import __version__
from .bootstrap import (find_nim, nim_version, install_nim, ensure_zippy,
                        detect_c_toolchain)
from .build import build as build_exe, BuildError
from .overlay import verify as verify_exe

app = typer.Typer(add_completion=False, help="haru-pack — pack a Python project into a single, signable native launcher.")

@app.command()
def version():
    """Show the haru-pack version."""
    typer.echo(f"haru-pack {__version__}")

@app.command()
def doctor(target: str = typer.Option("host", help="'host' or 'windows' (cross-compile)")):
    """Check the build toolchain (Nim, zippy, C compiler) and advise on what's missing."""
    nim = find_nim()
    typer.secho(f"nim       : {nim_version(nim) if nim else 'NOT FOUND — run `haru-pack bootstrap`'}",
                fg=("green" if nim else "red"))
    tc = detect_c_toolchain(target)
    typer.secho(f"C ({target}) : {tc['compiler'] if tc['ok'] else 'MISSING'}",
                fg=("green" if tc["ok"] else "red"))
    if not tc["ok"]:
        typer.secho(tc["advice"], fg="yellow")
    if not nim or not tc["ok"]:
        raise typer.Exit(1)

@app.command()
def bootstrap(target: str = typer.Option("host", help="also verify the toolchain for this target"),
              force: bool = typer.Option(False, help="reinstall Nim even if present")):
    """Install Nim (+zippy) into a managed dir and verify the C toolchain."""
    typer.echo("installing/locating Nim ...")
    nim = install_nim(force=force)
    typer.secho(f"nim: {nim_version(nim)}  ({nim})", fg="green")
    typer.echo("ensuring zippy ...")
    typer.secho("zippy: ok" if ensure_zippy(nim) else "zippy: FAILED (nimble install zippy)",
                fg=("green" if ensure_zippy(nim) else "red"))
    tc = detect_c_toolchain(target)
    if tc["ok"]:
        typer.secho(f"C toolchain ({target}): {tc['compiler']}", fg="green")
    else:
        typer.secho(f"C toolchain ({target}) MISSING:", fg="red")
        typer.secho(tc["advice"], fg="yellow")

@app.command()
def build(project: Path = typer.Argument(..., help="payload dir (contains manifest.json + app/)"),
          out: Path = typer.Option(None, "--out", "-o", help="output exe path"),
          target: str = typer.Option("host", help="'host' or 'windows'")):
    """Build a single-file launcher from a project payload dir."""
    if out is None:
        out = Path((project.name or "app")) .with_suffix(".exe" if target == "windows" else "")
    try:
        info = build_exe(project, out, target=target)
    except BuildError as e:
        typer.secho(str(e), fg="red"); raise typer.Exit(2)
    typer.secho(f"built {info['out']}  ({info['payload_len']} B payload, sha {info['sha256'][:16]}…, "
                f"target={info['target']})", fg="green")

@app.command()
def verify(exe: Path):
    """Inspect a built launcher's footer + confirm payload integrity."""
    info = verify_exe(exe)
    for k, v in info.items():
        typer.echo(f"{k:20}: {v}")
    raise typer.Exit(0 if info["sha_ok"] else 1)

def main():
    app()

if __name__ == "__main__":
    main()

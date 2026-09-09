from __future__ import annotations
from pathlib import Path
import typer
from . import __version__
from .bootstrap import (find_nim, nim_version, install_nim, ensure_nim_deps,
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
    typer.echo("ensuring nim deps (zippy, puppy) ...")
    ok = ensure_nim_deps(nim)
    typer.secho("nim deps: ok" if ok else "nim deps: FAILED (nimble install zippy puppy)",
                fg=("green" if ok else "red"))
    tc = detect_c_toolchain(target)
    if tc["ok"]:
        typer.secho(f"C toolchain ({target}): {tc['compiler']}", fg="green")
    else:
        typer.secho(f"C toolchain ({target}) MISSING:", fg="red")
        typer.secho(tc["advice"], fg="yellow")

@app.command()
def build(project: Path = typer.Argument(..., help="payload dir (contains manifest.json + app/)"),
          out: Path = typer.Option(None, "--out", "-o", help="output exe path"),
          target: str = typer.Option("host", help="'host' or 'windows'"),
          tier: str = typer.Option("default", help="thin | default | thick"),
          thin: bool = typer.Option(False, "--thin", help="bundle NOTHING; fetch uv+python+deps on target"),
          thick: bool = typer.Option(False, "--thick", help="bundle EVERYTHING; download nothing (offline)"),
          chonky: bool = typer.Option(False, "--chonky", hidden=True)):
    """Build a single-file launcher from a project payload dir.

    Tiers: --thin (smallest, needs network) · default (uv bundled) · --thick/--chonky
    (uv + Python bundled, fully offline)."""
    if thin: tier = "thin"
    if thick or chonky: tier = "thick"
    if tier not in ("thin", "default", "thick"):
        typer.secho(f"unknown tier '{tier}' (thin|default|thick)", fg="red"); raise typer.Exit(2)
    if chonky:
        typer.secho("🦣 chonky mode: bundling everything…", fg="magenta")
    if out is None:
        out = Path((project.name or "app")).with_suffix(".exe" if target == "windows" else "")
    try:
        info = build_exe(project, out, target=target, tier=tier)
    except BuildError as e:
        typer.secho(str(e), fg="red"); raise typer.Exit(2)
    typer.secho(f"built {info['out']}  (tier={info['tier']}, target={info['target']}, "
                f"{info['payload_len']} B payload, sha {info['sha256'][:16]}…)", fg="green")

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

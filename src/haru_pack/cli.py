from __future__ import annotations
import os
from pathlib import Path
import typer
from typer.core import TyperGroup
from . import __version__
from .bootstrap import (find_nim, nim_version, install_nim, ensure_nim_deps,
                        detect_c_toolchain)
from .build import build as build_exe, BuildError
from .discovery import AmbiguousProject
from .entrypoints import EntryPointError
from .overlay import verify as verify_exe
from .targets import KNOWN_TARGETS, Target, TargetError

class _DefaultToBuild(TyperGroup):
    """Make `haru-pack somescript.py` mean `haru-pack build somescript.py`.

    Implemented at the group level rather than as a callback with a positional argument.
    A positional on the callback competes with subcommand dispatch: click binds the first
    token to it, so `haru-pack version` was parsed as "build the project named 'version'".
    Here the token is only rewritten when it is NOT a registered command and does not look
    like a flag, so every subcommand keeps working untouched.
    """

    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["build"] + args
        return super().parse_args(ctx, args)


app = typer.Typer(add_completion=False, cls=_DefaultToBuild,
                  help="haru-pack — pack a Python project into a single, signable native "
                       "launcher.\n\nThe simple case needs no subcommand: "
                       "`haru-pack somescript.py`.")



def _run_build(*, project, out=None, target="host", tier="default", thin=False, thick=False,
               chonky=False, encrypt=False, secret=None, secret_env=None, secret_prompt=False,
               embed_secret=False, expires="", machine="", user="", geo="", python="",
               entry_point="", wine=False) -> None:
    """The build, as a plain function with real Python defaults.

    Both entry points call this: the `build` subcommand and the bare `haru-pack <path>`
    form. Deliberately NOT via `ctx.invoke`, which leaves any parameter the caller did not
    pass as a typer `OptionInfo` sentinel rather than its default — the first version of
    the bare form did that and produced "🦣 chonky mode" on a plain `haru-pack hello.py`,
    then crashed on `OptionInfo.encode()`. One implementation, ordinary keyword defaults.
    """
    if thin: tier = "thin"
    if thick or chonky: tier = "thick"
    if tier not in ("thin", "default", "thick"):
        typer.secho(f"unknown tier '{tier}' (thin|default|thick)", fg="red"); raise typer.Exit(2)
    if chonky:
        typer.secho("🦣 chonky mode: bundling everything…", fg="magenta")
    if out is None:
        try:
            suffix = Target.parse(target).exe_suffix
        except TargetError as e:
            typer.secho(f"haru-pack: {e}", fg="red"); raise typer.Exit(2)
        out = Path(project.name or "app").with_suffix(suffix)
    want_enc = encrypt or embed_secret or secret or secret_env or secret_prompt or expires or machine or user or geo
    sec = None
    if want_enc:
        if secret:            sec = secret.encode()
        elif secret_env:      sec = os.environ.get(secret_env, "").encode()
        elif secret_prompt:
            import getpass; sec = getpass.getpass("build secret: ").encode()
        if not sec:
            typer.secho("encryption requested but no secret — use --secret / --secret-env / --secret-prompt",
                        fg="red"); raise typer.Exit(2)
    try:
        info = build_exe(project, out, target=target, tier=tier, secret=sec,
                         expires=expires, geo=[g for g in geo.split(",") if g],
                         machine=machine, user=user, embed_secret=embed_secret, python=python,
                         wine=wine, encrypt=bool(want_enc),   # INV-BUILD-02
                         entry_point=entry_point)
    except AmbiguousProject as e:
        _report_ambiguity(project, e)
        raise typer.Exit(2)
    except TargetError as e:
        typer.secho(f"haru-pack: {e}", fg="red"); raise typer.Exit(2)
    except EntryPointError as e:
        typer.secho(str(e), fg="red"); raise typer.Exit(2)
    except BuildError as e:
        typer.secho(str(e), fg="red"); raise typer.Exit(2)
    tag = " 🔒encrypted" if info.get("encrypted") else ""
    typer.secho(f"built {info['out']}  (tier={info['tier']}, target={info['target']}, "
                f"{info['payload_len']} B payload, sha {info['sha256'][:16]}…){tag}", fg="green")


@app.command()
def version():
    """Show the haru-pack version."""
    typer.echo(f"haru-pack {__version__}")


def _report_ambiguity(project: Path, e: "AmbiguousProject") -> None:
    """Explain the choice, then write the config that records it — do not guess.

    A wrong guess here builds cleanly and runs the wrong program, so the failure shows up
    at the customer rather than at the build. Refusing costs the operator one command.
    """
    typer.secho(f"haru-pack: {e}", fg="yellow")
    if e.candidates:
        typer.echo("\ncandidates:")
        for c in e.candidates:
            typer.echo(f"  - {c}")
    out_dir = project if project.is_dir() else project.parent
    cfg = out_dir / "haru_pack.toml"
    typer.echo("\npick one, either way:")
    first = e.candidates[0] if e.candidates else "app.cli:main"
    typer.echo(f"  haru-pack build {project} --entry-point {first}")
    if cfg.exists():
        typer.echo(f"  ...or set `entrypoint` in {cfg}")
    else:
        typer.echo(f"  ...or run `haru-pack init {project}` to write {cfg.name} and edit it")


@app.command()
def doctor(path: Path = typer.Argument(None, help="project/script to scan for needed bundle/install steps"),
           target: str = typer.Option("host",
               help="'host', or <os>-<arch>: " + ", ".join(KNOWN_TARGETS))):
    """Check the build toolchain, and (if given a project) detect needed bundle/post_install steps."""
    nim = find_nim()
    typer.secho(f"nim       : {nim_version(nim) if nim else 'NOT FOUND — run `haru-pack bootstrap`'}",
                fg=("green" if nim else "red"))
    tc = detect_c_toolchain(target)
    typer.secho(f"C ({target}) : {tc['compiler'] if tc['ok'] else 'MISSING'}",
                fg=("green" if tc["ok"] else "red"))
    if not tc["ok"]:
        typer.secho(tc["advice"], fg="yellow")

    if path is not None:
        from .discovery import discover
        from . import scaffold
        try:
            disc = discover(path)
        except Exception as e:
            typer.secho(f"project scan skipped: {e}", fg="yellow")
            disc = None
        if disc is not None:
            deps = set(scaffold.project_deps(path, disc))
            venv = scaffold.find_venv(path if path.is_dir() else path.parent)
            if venv:
                _, vpkgs = scaffold.venv_info(venv)
                deps |= set(vpkgs)
                typer.secho(f"scanned {len(deps)} deps ({disc['kind']}; venv: {venv.name})", fg="cyan")
            else:
                typer.secho(f"scanned {len(deps)} deps ({disc['kind']}; no venv)", fg="cyan")
            hints = scaffold.detect(sorted(deps))
            if not hints:
                typer.secho("bundle steps: none needed — plain deps only ✓", fg="green")
            else:
                typer.secho("needed bundle/install steps:", fg="yellow")
                for h in hints:
                    tag = {"bundle": "bundle (offline)", "post_install": "post_install (1st run)",
                           "note": "note"}[h["kind"]]
                    typer.echo(f"  • {h['package']:14} [{tag}]  {h['why']}")
                typer.secho("  run `haru-pack init` to scaffold them into haru_pack.toml", fg="cyan")

    if not nim or not tc["ok"]:
        raise typer.Exit(1)

@app.command()
def bootstrap(target: str = typer.Option("host",
                  help="also verify the toolchain for this target (<os>-<arch>)"),
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
          target: str = typer.Option("host",
              help="'host', or <os>-<arch>: " + ", ".join(KNOWN_TARGETS)),
          tier: str = typer.Option("default", help="thin | default | thick"),
          thin: bool = typer.Option(False, "--thin", help="bundle NOTHING; fetch uv+python+deps on target"),
          thick: bool = typer.Option(False, "--thick", help="bundle EVERYTHING; download nothing (offline)"),
          chonky: bool = typer.Option(False, "--chonky", hidden=True),
          encrypt: bool = typer.Option(False, "--encrypt", help="AES-256-GCM encrypt the payload"),
          secret: str = typer.Option(None, "--secret", help="secret literal (key material)"),
          secret_env: str = typer.Option(None, "--secret-env", help="env var to read the secret from (build)"),
          secret_prompt: bool = typer.Option(False, "--secret-prompt", help="prompt for the secret"),
          embed_secret: bool = typer.Option(False, "--embed-secret", help="embed the secret in the exe (weakest)"),
          expires: str = typer.Option("", "--expires", help="license expiry YYYY-MM-DD"),
          machine: str = typer.Option("", "--machine", help="bind to this machine-id (cryptographic)"),
          user: str = typer.Option("", "--user", help="bind to this OS username (cryptographic)"),
          geo: str = typer.Option("", "--geo", help="allowed country codes, comma-separated"),
          python: str = typer.Option("", "--python", help="Python version to stage (e.g. 3.12); default auto/3.12"),
          entry_point: str = typer.Option("", "--entry-point", "-e",
              help="what to run: a script (app.py), a console script (lotek), or "
                   "module:callable (app.cli:main) — same spelling as [project.scripts]"),
          wine: bool = typer.Option(False, "--wine", help="run execute-required bundle steps under wine (thick cross)")):
    """Build a single-file launcher from a project payload dir.

    Tiers: --thin (smallest, needs network) · default (uv bundled) · --thick/--chonky
    (uv + Python bundled, fully offline)."""
    _run_build(project=project, out=out, target=target, tier=tier, thin=thin, thick=thick,
               chonky=chonky, encrypt=encrypt, secret=secret, secret_env=secret_env,
               secret_prompt=secret_prompt, embed_secret=embed_secret, expires=expires,
               machine=machine, user=user, geo=geo, python=python, entry_point=entry_point,
               wine=wine)

@app.command()
def verify(exe: Path):
    """Inspect a built launcher's footer + confirm payload integrity."""
    info = verify_exe(exe)
    for k, v in info.items():
        typer.echo(f"{k:20}: {v}")
    raise typer.Exit(0 if info["sha_ok"] else 1)

@app.command()
def init(path: Path = typer.Argument(Path("."), help="project dir or script"),
         force: bool = typer.Option(False, "--force", help="overwrite an existing haru_pack.toml")):
    """Scaffold a haru_pack.toml, pre-filled from discovery + any available venv."""
    from .discovery import discover
    from . import scaffold
    out_dir = path if path.is_dir() else path.parent
    out = out_dir / "haru_pack.toml"
    if out.exists() and not force:
        typer.secho(f"{out} already exists (use --force)", fg="yellow"); raise typer.Exit(1)
    try:
        disc = discover(path)
    except Exception as e:
        typer.secho(f"discovery failed: {e}", fg="red"); raise typer.Exit(2)
    deps = set(scaffold.project_deps(path, disc))
    learned = False
    venv = scaffold.find_venv(out_dir)
    if venv:
        vver, vpkgs = scaffold.venv_info(venv)
        if vpkgs: deps |= set(vpkgs); learned = True
        if vver and not disc.get("python"): disc["python"] = vver
        typer.secho(f"learned from venv: {venv}  ({len(vpkgs)} packages, python {vver or '?'})", fg="cyan")
    out.write_text(scaffold.render(disc, sorted(deps), learned_from_venv=learned))
    typer.secho(f"wrote {out}  (kind={disc['kind']}, entrypoint={disc['entrypoint']}, python={disc.get('python') or 'auto'})", fg="green")

@app.command("machine-id")
def machine_id_cmd():
    """Print this machine's id (give it to a vendor to bind an --encrypt license)."""
    from .crypto import machine_id
    typer.echo(machine_id())

def main():
    app()

if __name__ == "__main__":
    main()

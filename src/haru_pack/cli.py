from __future__ import annotations
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List
import typer

# rich, via a wrapper that keeps markup OFF by default: rich reads `[project.scripts]`
# as a style tag and silently prints nothing. See ui.py.
from .ui import print, fields, console as ui_console
from rich.text import Text
from typer.core import TyperGroup
from . import __version__
from .bootstrap import (find_nim, nim_version, ensure_nim_deps, nim_dep_specs,
                        detect_c_toolchain)
from . import toolchain
from .toolchain import ToolchainError
from .build import build as build_exe, BuildError
from .discovery import AmbiguousProject
from .entrypoints import EntryPointError
from .overlay import verify as verify_exe
from .targets import KNOWN_TARGETS, Target, TargetError
from .tiers import TIERS

def prog() -> str:
    """The command name the user actually typed — `haru-pack` or `haru`.

    Both are real console scripts (see `[project.scripts]`), so a message that hardcodes
    one of them tells half the users to type something other than what they just used.
    Copy-pasteable output is the whole point of those messages (docs/PRINCIPLES.md), and a
    command they did not invoke is one more thing to translate in their head.

    Falls back to `haru-pack` when argv[0] is something unhelpful — `python -m haru_pack`,
    a pytest runner, a frozen launcher.

    Split on BOTH separators rather than with `Path`: `Path(r"C:\\...\\haru.exe").name`
    returns the whole string on POSIX, because a backslash is an ordinary character there.
    That matters because this is a Windows-first tool whose argv[0] is routinely a Windows
    path, and it is the same mistake the vendored decoder's include path made under mingw.
    """
    raw = sys.argv[0] if sys.argv else ""
    name = re.split(r"[\\/]", raw)[-1] if raw else ""
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name if name in ("haru", "haru-pack") else "haru-pack"


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
               entry_point="", wine=False, obfuscate="none", obfuscate_args="",
               shake=False, shake_keep=(), env_canary="", env_canary_random=False,
               stub_env_secret_canary="", stub_env_uv_ver_canary="",
               stub_env_source_url_canary="", stub_env_base_path_canary="",
               reap=False, ram_only=False, base_path="",
               env_append=None) -> None:
    """The build, as a plain function with real Python defaults.

    Both entry points call this: the `build` subcommand and the bare `haru-pack <path>`
    form. Deliberately NOT via `ctx.invoke`, which leaves any parameter the caller did not
    pass as a typer `OptionInfo` sentinel rather than its default — the first version of
    the bare form did that and produced "🦣 chonky mode" on a plain `haru-pack hello.py`,
    then crashed on `OptionInfo.encode()`. One implementation, ordinary keyword defaults.
    """
    if thin: tier = "thin"
    if thick or chonky: tier = "thick"
    if tier not in TIERS:
        print(f"unknown tier '{tier}' ({'|'.join(TIERS)})", style="error"); raise typer.Exit(2)
    if chonky:
        print("🦣 chonky mode: bundling everything…", style="magenta")
    if out is None:
        try:
            suffix = Target.parse(target).exe_suffix
        except TargetError as e:
            print(f"{prog()}: {e}", style="error"); raise typer.Exit(2)
        out = Path(project.name or "app").with_suffix(suffix)
    want_enc = encrypt or embed_secret or secret or secret_env or secret_prompt or expires or machine or user or geo
    sec = None
    if want_enc:
        if secret:            sec = secret.encode()
        elif secret_env:      sec = os.environ.get(secret_env, "").encode()
        elif secret_prompt:
            import getpass; sec = getpass.getpass("build secret: ").encode()
        if not sec:
            print("encryption requested but no secret — use --secret / --secret-env / --secret-prompt", style="error"); raise typer.Exit(2)
    try:
        info = build_exe(project, out, target=target, tier=tier, secret=sec,
                         expires=expires, geo=[g for g in geo.split(",") if g],
                         machine=machine, user=user, embed_secret=embed_secret, python=python,
                         wine=wine, encrypt=bool(want_enc),   # INV-BUILD-02
                         obfuscate=obfuscate,
                         obfuscate_args=[a for a in obfuscate_args.split() if a],
                         entry_point=entry_point, shake=shake,
                         shake_keep=list(shake_keep or []),
                         env_canary=env_canary, env_canary_random=env_canary_random,
                         stub_env_secret_canary=stub_env_secret_canary,
                         stub_env_uv_ver_canary=stub_env_uv_ver_canary,
                         stub_env_source_url_canary=stub_env_source_url_canary,
                         stub_env_base_path_canary=stub_env_base_path_canary,
                         reap=reap, ram_only=ram_only, base_path=base_path,
                         env_append=list(env_append or []),
                         log=lambda m: print(
                             f"{prog()}: {m}",
                             style="warn" if "WARNING" in m else "info"))
    except AmbiguousProject as e:
        _report_ambiguity(project, e)
        raise typer.Exit(2)
    except TargetError as e:
        print(f"{prog()}: {e}", style="error"); raise typer.Exit(2)
    except EntryPointError as e:
        print(str(e), style="error"); raise typer.Exit(2)
    except BuildError as e:
        print(str(e), style="error"); raise typer.Exit(2)
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
    print(f"built {info['out']}  (tier={info['tier']}, target={info['target']}, "
                f"{info['payload_len']} B payload, sha {info['sha256'][:16]}…){tag}", style="ok")


@app.command()
def version():
    """Show the haru-pack version."""
    print(f"haru-pack {__version__}")


def _report_ambiguity(project: Path, e: AmbiguousProject) -> None:
    """Explain the choice, then write the config that records it — do not guess.

    A wrong guess here builds cleanly and runs the wrong program, so the failure shows up
    at the customer rather than at the build. Refusing costs the operator one command.
    """
    print(f"{prog()}: {e}", style="warn")
    if e.candidates:
        print("\ncandidates:")
        for c in e.candidates:
            print(f"  - {c}")
    out_dir = project if project.is_dir() else project.parent
    cfg = out_dir / "haru_pack.toml"
    print("\npick one, either way:")
    first = e.candidates[0] if e.candidates else "app.cli:main"
    print(f"  {prog()} build {project} --entry-point {first}")
    if cfg.exists():
        print(f"  ...or set `entrypoint` in {cfg}")
    else:
        print(f"  ...or run `{prog()} init {project}` to write {cfg.name} and edit it")


def _report_capabilities(selected=()) -> None:
    """Show every optional capability, whether it is installed, and what it costs.

    This exists because the default is the kitchen sink: an operator is entitled to see what
    that means in megabytes before agreeing to it, and `wine` alone is the difference between
    a small install and a large one. Sizes come from apt when apt is present and are left
    blank rather than guessed when it is not.
    """
    chosen = {c.name for c in selected}
    rows = []
    for c in toolchain.capabilities():
        # only meaningful for something you do not have yet, which is exactly
        # when you are deciding whether to install it
        weight = "" if c.present else toolchain.install_weight(c.packages)
        rows.append((
            ("*" if c.name in chosen else " ") + " " + c.name,
            "installed" if c.present else "missing",
            weight or "-",
            ", ".join(c.packages),
            c.unlocks,
        ))
    print("capabilities (* = selected by the flags you gave)", style="info")
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    for r in rows:
        line = Text()
        line.append(f"  {r[0]:<{widths[0]}}  ", style="key")
        line.append(f"{r[1]:<{widths[1]}}  ", style="ok" if r[1] == "installed" else "warn")
        line.append(f"{r[2]:>{widths[2]}}  {r[3]:<{widths[3]}}  ", style="detail")
        line.append(r[4])
        ui_console.print(line)
    print("")
    print("the host C compiler and Nim are not listed: they are not optional, and a "
          "haru-pack that cannot build for its own machine is not a working install.",
          style="detail")
    no_pkg = [t for t in KNOWN_TARGETS
              if t not in {c.name for c in toolchain.capabilities()}]
    if no_pkg:
        print(f"no cross toolchain is known for: {', '.join(no_pkg)} — those are either "
              f"native here or not cross-compilable from this host (macOS needs a Mac or "
              f"osxcross).", style="detail")


@app.command()
def doctor(path: Path = typer.Argument(None, help="project/script to scan for needed bundle/install steps"),
           target: str = typer.Option("host",
               help="'host', or <os>-<arch>: " + ", ".join(KNOWN_TARGETS))):
    """Check the build toolchain, and (if given a project) detect needed bundle/post_install steps."""
    nim = find_nim()
    print(f"nim       : {nim_version(nim) if nim else f'NOT FOUND — run `{prog()} bootstrap`'}",
          style=("ok" if nim else "error"))
    tc = detect_c_toolchain(target)
    print(f"C ({target}) : {tc['compiler'] if tc['ok'] else 'MISSING'}",
          style=("ok" if tc["ok"] else "error"))
    if not tc["ok"]:
        print(tc["advice"], style="warn")

    # What can this host build for, and what is missing? Previously the only way to find out
    # was to run a build and read the failure — and `wine` was invisible entirely, so a
    # `--wine` bundle step failed on a host the operator believed was fully set up
    # (INV-TOOL-01).
    caps = toolchain.capabilities()
    from .targets import KNOWN_TARGETS
    # wine is a TOOL, not a target — listing it under "can build for" would be wrong, and
    # the flag to add it differs (`--with` vs `--target`).
    tgt_have = [c.name for c in caps if c.present and c.name in KNOWN_TARGETS]
    tgt_lack = [c.name for c in caps if not c.present and c.name in KNOWN_TARGETS]
    tool_have = [c.name for c in caps if c.present and c.name not in KNOWN_TARGETS]
    tool_lack = [c.name for c in caps if not c.present and c.name not in KNOWN_TARGETS]
    print(f"can build for : {', '.join(['host'] + tgt_have)}", style="ok")
    if tgt_lack:
        print(f"  not set up  : {', '.join(tgt_lack)}  "
              f"(`{prog()} bootstrap --target {tgt_lack[0]}`)", style="warn")
    if tool_have:
        print(f"build tools   : {', '.join(tool_have)}", style="ok")
    if tool_lack:
        print(f"  not set up  : {', '.join(tool_lack)}  "
              f"(`{prog()} bootstrap --with {tool_lack[0]}`)", style="warn")
    print(f"                full list: `{prog()} bootstrap --list`", style="detail")

    if path is not None:
        from . import scaffold
        from .discovery import discover
        try:
            disc = discover(path)
        except Exception as e:
            print(f"project scan skipped: {e}", style="warn")
            disc = None
        if disc is not None:
            deps = set(scaffold.project_deps(path, disc))
            venv = scaffold.find_venv(path if path.is_dir() else path.parent)
            if venv:
                _, vpkgs = scaffold.venv_info(venv)
                deps |= set(vpkgs)
                print(f"scanned {len(deps)} deps ({disc['kind']}; venv: {venv.name})", style="info")
            else:
                print(f"scanned {len(deps)} deps ({disc['kind']}; no venv)", style="info")
            hints = scaffold.detect(sorted(deps))
            if not hints:
                print("bundle steps: none needed — plain deps only ✓", style="ok")
            else:
                print("needed bundle/install steps:", style="warn")
                for h in hints:
                    tag = {"bundle": "bundle (offline)", "post_install": "post_install (1st run)",
                           "note": "note"}[h["kind"]]
                    print(f"  • {h['package']:14} [{tag}]  {h['why']}")
                print(f"  run `{prog()} init` to scaffold them into haru_pack.toml", style="info")

    if not nim or not tc["ok"]:
        raise typer.Exit(1)

@app.command()
def bootstrap(target: List[str] = typer.Option(None, "--target",
                  help="prepare cross-compiling to this target; repeatable. Giving any "
                       "--target or --with makes the selection EXACT"),
              with_: List[str] = typer.Option(None, "--with", metavar="NAME",
                  help="add one capability by name (e.g. wine); repeatable"),
              without: List[str] = typer.Option(None, "--without", metavar="NAME",
                  help="kitchen sink MINUS this capability; repeatable"),
              minimal: bool = typer.Option(False, "--minimal",
                  help="host compiler + Nim only — no cross toolchains, no wine"),
              list_: bool = typer.Option(False, "--list",
                  help="show what is available, what it costs, and what each unlocks; "
                       "install nothing"),
              yes: bool = typer.Option(False, "--yes", "-y",
                  help="run the system package command without asking"),
              force: bool = typer.Option(False, "--force", help="reinstall Nim even if present")):
    """Install the toolchain. One command, at most one sudo prompt.

    The default is the kitchen sink: the host C compiler, Nim, every cross toolchain this
    host knows how to install, and wine. That is deliberate — the common case is wanting to
    build for everything, and discovering a missing cross-compiler three commands into a
    release is worse than installing one you did not need.

    It is not compulsory, though. Nothing in the kitchen sink is required to build for this
    machine, so every piece of it can be declined:

        haru-pack bootstrap                            everything
        haru-pack bootstrap --minimal                  host compiler + Nim only
        haru-pack bootstrap --target linux-aarch64     exactly that, nothing else
        haru-pack bootstrap --without wine             everything except wine
        haru-pack bootstrap --list                     look first, install nothing

    Nim comes from choosenim, into haru-pack's own directory — your system Nim and your
    ~/.nimble are left alone. Everything that needs sudo is a system package, and they are
    all worked out first so there is one prompt rather than one per capability.
    """
    caps, unknown = toolchain.select_capabilities(
        targets=list(target or []), minimal=minimal,
        without=list(without or []), with_=list(with_ or []))
    if unknown:
        names = ", ".join(c.name for c in toolchain.capabilities())
        print(f"unknown capability: {', '.join(unknown)}", style="error")
        print(f"known names: {names}", style="warn")
        raise typer.Exit(2)

    if list_:
        _report_capabilities(caps)
        raise typer.Exit(0)

    if caps:
        print(f"selected {len(caps)} capability/ies: "
              + ", ".join(c.name for c in caps), style="info")
    elif minimal:
        print("--minimal: host compiler + Nim only", style="info")

    # 1. system packages: work out everything needed, ask ONCE.
    missing = toolchain.missing_packages(caps)
    if missing:
        cmd = toolchain.sudo_command(missing)
        print(f"needs {len(missing)} system package(s): {', '.join(missing)}", style="warn")
        if not cmd:
            print("install them with your package manager, then re-run "
                        f"`{prog()} bootstrap`.", style="warn")
            raise typer.Exit(1)
        print("\n    " + " ".join(cmd) + "\n")
        run_it = yes or typer.confirm("run it now?", default=True)
        if not run_it:
            print(f"skipped. Run that command, then `{prog()} bootstrap` again.", style="warn")
            raise typer.Exit(1)
        rc = subprocess.call(cmd)
        if rc != 0:
            print(f"package install failed (exit {rc}). Run the command above by hand.", style="error")
            raise typer.Exit(rc)
    else:
        print("system packages: nothing needed ✓", style="ok")

    # 2. Nim, via choosenim, with no sudo at all.
    try:
        nim = toolchain.install_nim(force=force, log=lambda m: print(f"  {m}"))
    except ToolchainError as e:
        print(str(e), style="error"); raise typer.Exit(1)
    print(f"nim: {nim_version(nim)}  ({nim})", style="ok")

    # 3. the launcher's Nim libraries, pinned.
    print("ensuring nim deps (" + ", ".join(nim_dep_specs()) + ") ...")
    ok = ensure_nim_deps(nim)
    print("nim deps: ok" if ok else "nim deps: FAILED",
          style=("ok" if ok else "error"))
    if not ok:
        raise typer.Exit(1)

    # 4. report the toolchain per target that was actually selected. Derived from the
    #    capabilities rather than a separate `targets` list, so the summary cannot claim a
    #    target the install never covered.
    chosen_targets = [c.name for c in caps if c.name in KNOWN_TARGETS]
    for t in ["host", *chosen_targets]:
        tc = detect_c_toolchain(t)
        print(f"C ({t}) : {tc['compiler'] if tc['ok'] else 'MISSING'}",
              style=("ok" if tc["ok"] else "error"))
        if not tc["ok"]:
            print(tc["advice"], style="warn")

    print(f"\nready — try `{prog()} yourscript.py`", style="ok")


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
          python: str = typer.Option("", "--python", help="Python version to stage (e.g. 3.13); default auto/3.13"),
          entry_point: str = typer.Option("", "--entry-point", "-e",
              help="what to run: a script (app.py), a console script (lotek), or "
                   "module:callable (app.cli:main) — same spelling as [project.scripts]"),
          wine: bool = typer.Option(False, "--wine", help="run execute-required bundle steps under wine (thick cross)"),
          obfuscate: str = typer.Option("none", "--obfuscate", help="obfuscate the source before packing: none | pyarmor (default engine when a value is omitted). Independent of --encrypt."),
          obfuscate_args: str = typer.Option("", "--obfuscate-args", help="extra args passed through to the obfuscation engine, quoted"),
          shake: bool = typer.Option(False, "--shake",
              help="thick only: run the project's tests under a file tracer and drop bundled "
                   "files nothing touched; refuses to ship if the suite then fails"),
          shake_keep: List[str] = typer.Option(None, "--shake-keep", metavar="GLOB",
              help="never prune paths matching GLOB (repeatable)"),
          env_canary: str = typer.Option("", "--env-canary", metavar="TOKEN",
              help="canary prefix for ALL stub knobs (default HARU); knob K is read at runtime "
                   "as <TOKEN>_<K> (e.g. HARU_SECRET). Must match ^[A-Za-z_][A-Za-z0-9_]*$"),
          env_canary_random: bool = typer.Option(False, "--env-canary-random",
              help="pick a random [A-Z][A-Z0-9]{7} canary for all knobs and PRINT it — record "
                   "it; you set the secret at runtime as <TOKEN>_SECRET"),
          stub_env_secret_canary: str = typer.Option("", "--stub-env-secret-canary",
              metavar="TOKEN", help="override the SECRET knob's canary only"),
          stub_env_uv_ver_canary: str = typer.Option("", "--stub-env-uv-ver-canary",
              metavar="TOKEN", help="override the UV_VER knob's canary only"),
          stub_env_source_url_canary: str = typer.Option("", "--stub-env-source-url-canary",
              metavar="TOKEN", help="override the SOURCE_URL knob's canary only"),
          stub_env_base_path_canary: str = typer.Option("", "--stub-env-base-path-canary",
              metavar="TOKEN", help="override the BASE_PATH knob's canary only"),
          reap: bool = typer.Option(False, "--reap",
              help="after the app exits, spawn a DETACHED process that deletes the staged "
                   "subtree, then exit without waiting (fire-and-forget cleanup)"),
          ram_only: bool = typer.Option(False, "--ram-only",
              help="best-effort RAM-backed staging: Linux stages under /dev/shm when available "
                   "(else falls back to the cache). Governs only where the STUB stages — not "
                   "the app's own disk writes; not guaranteed on Windows/macOS"),
          base_path: str = typer.Option("", "--base-path", metavar="DIR",
              help="staging-root default baked into the stub-config (a canary-named BASE_PATH "
                   "env var overrides it at runtime). Refused if it is a root/drive/home path"),
          env_append: list[str] = typer.Option(None, "--env-append", metavar="KEY=VALUE",
              help="inject KEY=VALUE into the child env before uv AND the app (repeatable). "
                   "Lives in the payload — use --encrypt to hide a secret value")):
    """Build a single-file launcher from a project payload dir.

    Tiers: --thin (smallest, needs network) · default (uv bundled) · --thick/--chonky
    (uv + Python bundled, fully offline)."""
    _run_build(project=project, out=out, target=target, tier=tier, thin=thin, thick=thick,
               chonky=chonky, encrypt=encrypt, secret=secret, secret_env=secret_env,
               secret_prompt=secret_prompt, embed_secret=embed_secret, expires=expires,
               machine=machine, user=user, geo=geo, python=python, entry_point=entry_point,
               wine=wine, obfuscate=obfuscate, obfuscate_args=obfuscate_args,
               shake=shake, shake_keep=shake_keep, env_canary=env_canary,
               env_canary_random=env_canary_random,
               stub_env_secret_canary=stub_env_secret_canary,
               stub_env_uv_ver_canary=stub_env_uv_ver_canary,
               stub_env_source_url_canary=stub_env_source_url_canary,
               stub_env_base_path_canary=stub_env_base_path_canary,
               reap=reap, ram_only=ram_only, base_path=base_path,
               env_append=env_append)

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
    from . import scaffold
    from .discovery import discover
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
    from .crypto import machine_id
    print(machine_id())

def main():
    app()

if __name__ == "__main__":
    main()

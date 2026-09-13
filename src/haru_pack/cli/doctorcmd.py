"""`haru-pack doctor` — what this machine can build, and what it is missing.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from pathlib import Path

import typer

from .. import toolchain
from ..bootstrap import detect_c_toolchain, find_nim, nim_version
from ..targets import KNOWN_TARGETS
from ..ui import print
from .naming import prog
from .root import app


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

"""`haru-pack bootstrap` — install the toolchains a build needs, without sudo.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import subprocess
from typing import List

import typer

from .. import toolchain
from ..bootstrap import (detect_c_toolchain, ensure_nim_deps, nim_dep_specs,
                        nim_version)
from ..targets import KNOWN_TARGETS
from ..toolchain import ToolchainError
from ..ui import print
from .naming import prog
from .report import _report_capabilities
from .root import app


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

    # 2. zig, if selected: a pinned download into haru-pack's own directory, no sudo. Done
    #    before Nim so that a host with no system compiler at all still ends up able to
    #    build — which is the whole point of zig being the default (INV-TOOL-02).
    if any(c.name == "zig" for c in caps):
        try:
            zig = toolchain.install_zig(log=lambda m: print(f"  {m}"))
            print(f"zig: {zig}", style="ok")
        except Exception as e:
            print(f"zig install failed: {e}", style="error")
            print("You can still build with `--cc system` if you have a C toolchain.",
                  style="warn")
            raise typer.Exit(1)

    # 3. Nim, via choosenim, with no sudo at all.
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

    # 5. report the toolchain per target that was actually selected. Derived from the
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


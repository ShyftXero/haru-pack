"""Two long-form explanations the CLI prints: an ambiguous project, and what is installed.

Both are here for the same reason. They are mostly formatting, they are the parts of the
CLI most likely to be edited for wording rather than behaviour, and neither belongs to a
single command — `_report_ambiguity` is reached from a build, `_report_capabilities` from
`doctor` and `bootstrap`.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from pathlib import Path

from rich.text import Text

from .. import toolchain
from ..discovery import AmbiguousProject
from ..targets import KNOWN_TARGETS
from ..ui import console as ui_console
from ..ui import print
from .naming import prog


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
    print("Nim is not listed because it is not optional. The host C compiler is not "
          "listed either, and since `zig` became the default compiler it is no longer "
          "required at all — it is needed only for `--cc system` (and for a macOS target, "
          "which zig cannot build).", style="detail")
    no_pkg = [t for t in KNOWN_TARGETS
              if t not in {c.name for c in toolchain.capabilities()}]
    if no_pkg:
        print(f"no cross toolchain is known for: {', '.join(no_pkg)} — those are either "
              f"native here or not cross-compilable from this host (macOS needs a Mac or "
              f"osxcross).", style="detail")

from __future__ import annotations
from pathlib import Path
from platformdirs import user_data_dir

APP = "haru-pack"

def data_dir() -> Path:
    return Path(user_data_dir(APP, appauthor=False))

def toolchain_dir() -> Path:
    return data_dir() / "toolchain"

def nim_dir() -> Path:
    return toolchain_dir() / "nim"

def launcher_src_dir() -> Path:
    """Nim launcher source shipped inside the wheel."""
    return Path(__file__).resolve().parent / "launcher"

def exe_suffix(target) -> str:
    """`.exe` iff the TARGET is Windows — not iff the build host is."""
    from .targets import Target
    tgt = target if hasattr(target, "os") else Target.parse(target)
    return tgt.exe_suffix

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

def cache_dir() -> Path:
    """Build-time scratch that is safe to delete and expensive to recompute.

    Currently just the XZ-compressed `uv` binaries: compressing uv at preset 9 takes ~100 s
    and the result is a pure function of (uv version, asset, preset), so paying it on every
    build would be a gratuitous regression in build time.
    """
    from platformdirs import user_cache_dir
    return Path(user_cache_dir(APP, appauthor=False))


def launcher_src_dir() -> Path:
    """Nim launcher source shipped inside the wheel."""
    return Path(__file__).resolve().parent / "launcher"

def exe_suffix(target) -> str:
    """`.exe` iff the TARGET is Windows — not iff the build host is."""
    from .targets import Target
    tgt = target if hasattr(target, "os") else Target.parse(target)
    return tgt.exe_suffix

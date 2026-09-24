"""A terribly thin, stdlib-only wrapper so a PACKED app can find its folders.

Import it from your app::

    from haru_pack.runtime import stage, exe_dir, data_dir, data_file

haru-pack stages the payload to a **read-only, hash-verified** tree and runs your code as if it
were a compiled binary in the folder it was launched from. So the rule (docs/SHARP_CORNERS.md
section E) is: read bundled assets from :func:`stage` (read-only), and write runtime data to a
per-user data dir or the launch dir — **never into the stage**, or the launcher refuses to run
on the next launch (INV-STAGE-01). These helpers resolve the right place; each is a couple of
lines around ``os`` + ``pathlib`` and imports nothing heavy, so depending on haru-pack for them
is cheap — or copy the two lines you need.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def stage() -> Path | None:
    """The staged, **read-only** payload tree root (``HARUPACK_STAGE``). ``None`` when the code
    is not running from a packed binary (e.g. ``python app.py`` during development). Bundled
    assets live under here — read them, never write into them."""
    v = os.environ.get("HARUPACK_STAGE")
    return Path(v) if v else None


def exe_dir() -> Path:
    """The folder the packed binary lives in (``HARUPACK_EXE_DIR``) — a good spot for data that
    should sit *next to the exe*. Falls back to the launching script's directory when not packed."""
    v = os.environ.get("HARUPACK_EXE_DIR")
    return Path(v) if v else Path(sys.argv[0]).resolve().parent


def launch_dir() -> Path:
    """Where the user actually ran the binary (the current working directory)."""
    return Path.cwd()


def home() -> Path:
    """The user's home directory."""
    return Path.home()


def _user_dir(xdg: str, win_envs: tuple, *, posix: tuple, mac: tuple) -> Path:
    v = os.environ.get(xdg)
    if v:
        return Path(v)
    if sys.platform == "win32":
        for e in win_envs:
            b = os.environ.get(e)
            if b:
                return Path(b)
        return Path.home()
    if sys.platform == "darwin":
        return Path.home().joinpath(*mac)
    return Path.home().joinpath(*posix)


def data_dir(app: str, *, create: bool = True) -> Path:
    """A per-user, **writable** data directory for ``app`` (``XDG_DATA_HOME`` /
    ``%LOCALAPPDATA%`` / ``~/Library/Application Support``). Created unless ``create=False``."""
    d = _user_dir("XDG_DATA_HOME", ("LOCALAPPDATA", "APPDATA"),
                  posix=(".local", "share"), mac=("Library", "Application Support")) / app
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def config_dir(app: str, *, create: bool = True) -> Path:
    """A per-user, **writable** config directory for ``app`` (``XDG_CONFIG_HOME`` / ``%APPDATA%``
    / ``~/Library/Preferences``). Created unless ``create=False``."""
    d = _user_dir("XDG_CONFIG_HOME", ("APPDATA", "LOCALAPPDATA"),
                  posix=(".config",), mac=("Library", "Preferences")) / app
    if create:
        d.mkdir(parents=True, exist_ok=True)
    return d


def data_file(app: str, name: str) -> Path:
    """A writable path for ``name`` under the app's data dir (parent created). e.g.
    ``data_file("yourapp", "files.db")`` -> ``~/.local/share/yourapp/files.db``. If you bundled
    a seed db, copy it here on first run and open THIS copy, not the one in :func:`stage`."""
    return data_dir(app) / name

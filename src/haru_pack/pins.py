"""Load the pinned artifact digests from `pins.toml`.

The digests used to be dict literals in `bundle.py`. They are data, not code: a maintainer
bumping `uv` should edit a table with a text editor, and a reader auditing what a build
trusted should be able to read that table without following Python. Keeping them in source
also meant provenance lived in a comment above the dict rather than next to the value it
described.

`pins.toml` is packaged with the wheel, so an installed haru-pack pins exactly what the
release pinned. Regenerate or extend it with `tools/add-pin.py`.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from . import tomlio

__all__ = ["PinsError", "pins_path", "load", "uv_digests", "python_digests", "zig_digests",
           "nim_digests", "choosenim_digests", "provenance"]

SCHEMA_VERSION = 1
_HEX = frozenset("0123456789abcdef")


class PinsError(RuntimeError):
    """pins.toml is missing, unparseable, or malformed.

    Fatal on purpose. A build that cannot read its pins must not fall back to downloading
    things unverified — that would turn a packaging mistake into a silent security downgrade.
    """


def pins_path() -> Path:
    return Path(__file__).resolve().parent / "pins.toml"


def _check_digest(d: str, where: str) -> str:
    d = (d or "").strip().lower()
    if len(d) != 64 or not set(d) <= _HEX:
        raise PinsError(f"{where}: {d!r} is not a sha256 hex digest")
    return d


@lru_cache(maxsize=1)
def load(path: str | None = None) -> dict:
    """Parse pins.toml into {"uv": {version: {asset: sha}}, "python": {url: sha}, ...}."""
    p = Path(path) if path else pins_path()
    if not p.exists():
        raise PinsError(
            f"{p} is missing. haru-pack cannot verify anything it downloads without it and "
            "will not proceed unverified. If this is an installed copy, the package is "
            "incomplete — reinstall.")
    try:
        data = tomlio.load(p)
    except Exception as e:
        raise PinsError(f"{p} is not valid TOML: {e}") from e

    ver = data.get("schema_version")
    if ver != SCHEMA_VERSION:
        raise PinsError(
            f"{p}: schema_version {ver!r}, expected {SCHEMA_VERSION}. Refusing to guess how "
            "to read a format this haru-pack does not know.")

    uv: dict = {}
    python: dict = {}
    nim: dict = {}
    choosenim: dict = {}
    zig: dict = {}
    prov: dict = {}
    for i, a in enumerate(data.get("artifact") or []):
        kind = a.get("kind")
        where = f"{p}: artifact #{i + 1}"
        if kind == "uv":
            v, asset = a.get("version"), a.get("asset")
            if not v or not asset:
                raise PinsError(f"{where}: a uv entry needs both `version` and `asset`")
            uv.setdefault(v, {})[asset] = _check_digest(a.get("sha256"), where)
            prov[f"uv:{v}:{asset}"] = a.get("provenance", "")
        elif kind == "python":
            url = a.get("url")
            if not url:
                raise PinsError(f"{where}: a python entry needs `url`")
            python[url] = _check_digest(a.get("sha256"), where)
            prov[f"python:{url}"] = a.get("provenance", "")
        elif kind == "zig":
            v, asset = a.get("version"), a.get("asset")
            if not v or not asset:
                raise PinsError(f"{where}: a zig entry needs both `version` and `asset`")
            zig.setdefault(v, {})[asset] = {
                "sha256": _check_digest(a.get("sha256"), where),
                "url": a.get("url", ""),
            }
            prov[f"zig:{v}:{asset}"] = a.get("provenance", "")
        elif kind in ("nim", "choosenim"):
            v, asset = a.get("version"), a.get("asset")
            if not v or not asset:
                raise PinsError(f"{where}: a {kind} entry needs both `version` and `asset`")
            bucket = nim if kind == "nim" else choosenim
            bucket.setdefault(v, {})[asset] = {
                "sha256": _check_digest(a.get("sha256"), where),
                "url": a.get("url", ""),
            }
            prov[f"{kind}:{v}:{asset}"] = a.get("provenance", "")
        else:
            raise PinsError(
                f"{where}: unknown kind {kind!r} "
                "(expected 'uv', 'python', 'nim', 'choosenim' or 'zig')")

    if not uv and not python:
        raise PinsError(f"{p} contains no artifacts")
    return {"uv": uv, "python": python, "nim": nim, "choosenim": choosenim,
            "zig": zig, "provenance": prov}


def uv_digests() -> dict:
    return load()["uv"]


def python_digests() -> dict:
    return load()["python"]


def nim_digests() -> dict:
    """{version: {asset: {"sha256", "url"}}} for Nim's own archives."""
    return load()["nim"]


def choosenim_digests() -> dict:
    """{version: {asset: {"sha256", "url"}}} for choosenim binaries."""
    return load()["choosenim"]


def zig_digests() -> dict:
    """{version: {build-host: {"sha256", "url"}}} for the zig cross-compiler.

    Keyed by haru-pack build host (`linux-x86_64`, …), not by zig's own naming, so callers
    ask the question they actually have.
    """
    return load()["zig"]


def provenance() -> dict:
    """Where each digest came from — the publisher channel, per entry."""
    return load()["provenance"]

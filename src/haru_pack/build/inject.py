"""--env-append: extra environment the launcher sets before running the app.

The reserved-key refusal and the secret-shaped warning both exist for the same reason: an
inject that is silently dropped, or a credential that silently ships in plaintext, is a
build that lied about what it produced (INV-BUILD-01/02, INV-SECRET-02).

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import re as _re

from .errors import BuildError


# vars AFTER the inject loop and so WINS on a collision (INV-LAUNCH-09); an inject that lands on
# one of these would be silently dropped. A silently-ineffective inject is exactly the class
# INV-BUILD-01/02 exist to forbid, so the build refuses it outright rather than shipping a lie.
_RESERVED_INJECT_KEYS = frozenset({
    "UV_CACHE_DIR", "UV_PYTHON", "UV_PYTHON_INSTALL_DIR", "UV_PYTHON_DOWNLOADS",
    "UV_OFFLINE", "UV_PROJECT_ENVIRONMENT", "PYTHONPYCACHEPREFIX", "PYTHONPATH",
})
# Secret-shaped inject detection (docs/adr/0003 §4.3) — deterministic, so the warning is
# reproducible. Same honesty as --embed-secret (INV-SECRET-02): an unencrypted payload ships the
# value recoverable in plaintext, and haru-pack says so rather than letting the operator assume.
_SECRET_KEY_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "APIKEY", "API_KEY",
                       "PRIVATE_KEY", "ACCESS_KEY")
_SECRET_VALUE_RE = _re.compile(r"[A-Za-z0-9+/=_-]{20,}\Z")


def _looks_secret_shaped(key: str, value: str) -> bool:
    """Deterministic 'this inject looks like a credential' test (docs/adr/0003 §4.3)."""
    ku = key.upper()
    if ku.endswith("_KEY") or any(m in ku for m in _SECRET_KEY_MARKERS):
        return True
    return bool(_SECRET_VALUE_RE.fullmatch(value))


def resolve_injects(env_append, encrypted: bool, log=None) -> list:
    """Validate --env-append into the manifest `inject` list (docs/adr/0003 §4.3).

    Refuses a malformed (`no '='`, empty KEY) or reserved-KEY inject — an inject the launcher
    would silently drop is the class INV-BUILD-01/02 forbid. On an UNENCRYPTED build, warns
    loudly for a secret-shaped inject, the same honesty as --embed-secret (INV-SECRET-02): the
    value ships recoverable in plaintext. An ENCRYPTED build hides the payload, so no warning.
    Called 'inject', never 'project'. Each entry is stored verbatim; the launcher splits on the
    FIRST '=' (INV-LAUNCH-09), so an odd VALUE containing '=' round-trips faithfully."""
    injects: list = []
    for raw in (env_append or []):
        if "=" not in raw:
            raise BuildError(f"--env-append must be KEY=VALUE; got {raw!r} with no '='.")
        key, value = raw.split("=", 1)
        if not key:
            raise BuildError(f"--env-append has an empty KEY: {raw!r}.")
        if key.startswith("HARUPACK_") or key in _RESERVED_INJECT_KEYS:
            raise BuildError(
                f"--env-append {key}=… uses a reserved key. The launcher sets its own "
                f"HARUPACK_*, the managed UV_*, PYTHONPYCACHEPREFIX and PYTHONPATH AFTER the "
                f"injects and wins on a collision (INV-LAUNCH-09), so this inject would be "
                f"silently dropped. Rename it, or configure the launcher's behaviour directly.")
        if not encrypted and _looks_secret_shaped(key, value):
            say = log or (lambda _m: None)
            say(f"WARNING: --env-append {key}=… looks secret-shaped and this build is NOT "
                f"encrypted, so the value ships recoverable in plaintext in the binary. Add "
                f"--encrypt to hide it inside the payload, or confirm it is not a secret "
                f"(INV-SECRET-02).")
        injects.append(raw)
    return injects


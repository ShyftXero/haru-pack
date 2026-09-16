"""Where third-party artifacts come from — the one module that knows about GitHub.

Two separate ideas that are easy to conflate:

**Origin** (this module) is *where the bytes are fetched from*. It is a deployment and
policy question. Plenty of environments cannot reach github.com — an air-gapped build
host, a corporate proxy, a mirror mandated by policy — so every default base URL here is
overridable.

**Integrity** (`archives.fetch_verified` + the pin tables in `bundle.py`) is *whether the
bytes are the ones we expected*. It is a security question and it is NOT negotiable.

The two are deliberately independent, and the ordering below is what makes a mirror safe:
a pinned digest is looked up by the artifact's **upstream** URL, and only then is the
download point rewritten to the mirror. Pointing haru-pack at a hostile mirror therefore
gets you a `DigestMismatch`, not a compromised build. A mirror changes availability, never
trust. Do not "fix" a mirror mismatch by editing the pin.

Configure in `haru_pack.toml`:

    [sources]
    uv_base     = "https://mirror.example/uv/releases/download"
    python_base = "https://mirror.example/python-build-standalone/releases/download"
    index_url   = "https://pypi.example/simple"

or per-invocation via the environment, which is what CI usually wants:

    HARUPACK_UV_BASE, HARUPACK_PYTHON_BASE, HARUPACK_INDEX_URL

A mirror is expected to be a path-preserving reverse proxy: everything after the base is
reused verbatim, so `<base>/0.10.4/uv-x86_64-unknown-linux-gnu.tar.gz` must resolve. That
is the same shape `uv python install --mirror` expects.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["Sources", "DEFAULT_UV_BASE", "DEFAULT_PYTHON_BASE", "MirrorError"]

DEFAULT_UV_BASE = "https://github.com/astral-sh/uv/releases/download"
DEFAULT_PYTHON_BASE = "https://github.com/astral-sh/python-build-standalone/releases/download"


class MirrorError(RuntimeError):
    """A mirror was configured but an upstream URL did not have the shape to rewrite."""


def _clean(url: str) -> str:
    return (url or "").strip().rstrip("/")


@dataclass(frozen=True)
class Sources:
    """Resolved artifact origins for one build."""

    uv_base: str = DEFAULT_UV_BASE
    python_base: str = DEFAULT_PYTHON_BASE
    index_url: str = ""            # "" = uv's default (PyPI)

    # ---------------------------------------------------------------- construction
    @classmethod
    def resolve(cls, declaration: dict | None = None, env: dict | None = None) -> "Sources":
        """haru_pack.toml `[sources]` first, then the environment, then upstream defaults."""
        decl = (declaration or {}).get("sources") or {}
        env = os.environ if env is None else env
        return cls(
            uv_base=_clean(decl.get("uv_base") or env.get("HARUPACK_UV_BASE") or DEFAULT_UV_BASE),
            python_base=_clean(decl.get("python_base") or env.get("HARUPACK_PYTHON_BASE")
                               or DEFAULT_PYTHON_BASE),
            index_url=_clean(decl.get("index_url") or env.get("HARUPACK_INDEX_URL") or ""),
        )

    # ---------------------------------------------------------------- properties
    @property
    def uses_defaults(self) -> bool:
        return (self.uv_base == DEFAULT_UV_BASE
                and self.python_base == DEFAULT_PYTHON_BASE
                and not self.index_url)

    # ---------------------------------------------------------------- URL building
    def uv_url(self, version: str, asset: str) -> str:
        """Download point for a uv release asset."""
        return f"{self.uv_base}/{version}/{asset}"

    def python_url(self, upstream_url: str) -> str:
        """Rewrite a python-build-standalone URL onto the configured base.

        `upstream_url` is what uv's catalog gave us, and it is also the key the digest is
        pinned under. Callers MUST look the digest up by the upstream URL and download from
        the value returned here — never the other way around.
        """
        if self.python_base == DEFAULT_PYTHON_BASE:
            return upstream_url
        if not upstream_url.startswith(DEFAULT_PYTHON_BASE + "/"):
            raise MirrorError(
                f"cannot rewrite {upstream_url!r} onto mirror {self.python_base!r}: it does "
                f"not start with the expected upstream base {DEFAULT_PYTHON_BASE!r}. Refusing "
                "to guess a mirror path for an artifact from an unrecognised host.")
        return self.python_base + upstream_url[len(DEFAULT_PYTHON_BASE):]

    # ---------------------------------------------------------------- uv plumbing
    def uv_index_args(self) -> list:
        """Extra argv for uv commands that resolve packages."""
        return ["--default-index", self.index_url] if self.index_url else []

    def uv_python_mirror_args(self) -> list:
        """Extra argv for `uv python install`.

        Only used where uv fetches an interpreter itself. haru-pack's own staging path
        downloads and verifies directly instead (INV-SUPPLY-07).
        """
        return ["--mirror", self.python_base] if self.python_base != DEFAULT_PYTHON_BASE else []

    def describe(self) -> str:
        """One line for the build receipt, so an operator can see what a build trusted."""
        if self.uses_defaults:
            return "upstream defaults (github.com)"
        bits = []
        if self.uv_base != DEFAULT_UV_BASE: bits.append(f"uv={self.uv_base}")
        if self.python_base != DEFAULT_PYTHON_BASE: bits.append(f"python={self.python_base}")
        if self.index_url: bits.append(f"index={self.index_url}")
        return "; ".join(bits)

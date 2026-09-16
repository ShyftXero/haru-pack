"""Hatchling in-tree metadata hook.

Sets the package version from the HEAD git commit at build time — the BARE 14-digit timestamp
(``YYYYMMDDHHMMSS``), matching ``src/haru_pack/_version.py``. The wheel deliberately gets the form
WITHOUT the ``+g<shorthash>`` local segment: PyPI refuses PEP 440 local versions on upload, so the
published artifact must be the bare timestamp (a git checkout still shows the hash at runtime — see
``_version.py``). Hatchling loads this file because ``pyproject.toml`` declares
``[tool.hatch.metadata.hooks.custom]`` and lists ``version`` in ``project.dynamic``. A build with no
git (e.g. from an sdist that dropped ``.git``) falls back to ``0+unknown``.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from hatchling.metadata.plugin.interface import MetadataHookInterface


def _bare_build_id(root: Path) -> str:
    # Load src/haru_pack/_version.py standalone (it imports only stdlib) so we don't import the
    # `haru_pack` package, whose runtime deps aren't installed in the build environment.
    path = root / "src" / "haru_pack" / "_version.py"
    spec = importlib.util.spec_from_file_location("_haru_version_build", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        return "0+unknown"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.git_build_id(root, with_hash=False) or "0+unknown"


class CustomMetadataHook(MetadataHookInterface):
    """Provides the dynamic ``version`` field from git at build time."""

    def update(self, metadata: dict) -> None:
        metadata["version"] = _bare_build_id(Path(self.root))

"""The one exception a reproduction kit raises, alone so no sibling has to import
another module to raise it.
"""
from __future__ import annotations


class EmitError(RuntimeError):
    """A reproduction kit (`--emit-nim` or `--emit-c`) could not be written safely.

    Non-fatal to the build: by the time either kit is attempted the binary is already
    produced, so `build()` reports this as a kit warning, not a build failure."""


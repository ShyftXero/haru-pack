"""The one exception type every build-time refusal raises.

It lives alone in its own module so that every other module in this package can import it
without importing any of its siblings — a shared error type is the classic accidental
source of an import cycle.
"""
from __future__ import annotations


class BuildError(RuntimeError): ...

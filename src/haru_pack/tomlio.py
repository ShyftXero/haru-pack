from __future__ import annotations
from pathlib import Path
try:
    import tomllib as _toml            # py3.11+
except ModuleNotFoundError:            # py3.9/3.10
    import tomli as _toml
import tomli_w

def load(path) -> dict:
    return _toml.loads(Path(path).read_text())

def dump(data: dict, path) -> None:
    Path(path).write_text(tomli_w.dumps(data))

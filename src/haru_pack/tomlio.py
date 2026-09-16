from __future__ import annotations
from pathlib import Path
import tomllib as _toml                 # stdlib since 3.11; the floor is >=3.12
import tomli_w

def load(path) -> dict:
    return _toml.loads(Path(path).read_text())

def dump(data: dict, path) -> None:
    Path(path).write_text(tomli_w.dumps(data))

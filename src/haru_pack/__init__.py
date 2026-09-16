"""haru-pack: pack a Python project into a single, signable native launcher."""
# git-derived, single source of truth (YYYYMMDDHHMMSS[+g<hash>]) — see _version.py. Re-exported
# here so `from haru_pack import __version__` and `haru-pack version` keep working.
from ._version import __version__ as __version__

"""The trait catalogue: eleven personas' worth of hostility, in composable pieces.

Each trait is one small mutation with a declared phase and layer. Nothing here asserts
anything — expectations belong to the runner, because a trait's effect depends entirely on
what it is stacked with. That is the whole reason for the split.

Personas represented, and what each contributes:

    greenhorn     a developer's first day: wrong paths, wrong flags, output in silly places
    foreman       the environment CI actually provides: no TTY, no HOME, read-only tree
    crosseyed     a foreign --target, so the payload must not contain host objects
    babel         filenames that are legal here and illegal, colliding or unencodable there
    understudy    the packaged application behaving badly
    revenant      an on-disk stage left by an older, different haru-pack
    quotamaster   target storage hostility — noexec, full, read-only, quota'd
    packrat       payload extremes: enormous files, device nodes, absurd file counts
    tourist       the artifact on a platform that is not its own
    auditor       credential-shaped files planted where the payload builder will see them
    archivist     a build that must be byte-reproducible

`archivist`, `auditor` and `crosseyed` also own explicit property-checking cases in
busybody.py: "these two builds are identical" and "no ELF objects in a Windows payload" are
assertions about an artifact, not conditions to survive, so they are not traits. The traits
they contribute here are the parts that compose — the foreign target, the planted secret, the
fixed timestamp.
"""
from __future__ import annotations

# Imported for their SIDE EFFECT: each module's `@trait(...)` decorators run on import and
# register into busybody_compose's catalogue. Drop one of these lines and a whole persona
# silently stops being generated — no error, just a smaller sweep that still looks complete.
# `tests/test_compose.py` counts the catalogue for exactly that reason.
from busybody_traits_app import *       # noqa: F401,F403
from busybody_traits_dev import *       # noqa: F401,F403
from busybody_traits_supply import *    # noqa: F401,F403
from busybody_traits_supply import AUDITOR_SECRETS   # noqa: F401  (named by busybody.py)

"""Refusals for a declaration that cannot be honoured as written.

Everything here was mined from busybody's `wedge` persona (INV-CHAOS-07), which feeds
haru-pack contradictory config and reports anything that builds cleanly anyway. Each of
these built cleanly once.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import datetime as _dt
import re as _re
from pathlib import Path

from .errors import BuildError


# The values `main.nim` actually implements. It reads the policy with a string default and
# compares it to "exe", so anything else silently means "launch" — a typo and a deliberate
# choice produce identical binaries, and the one place the difference shows up is a customer
# resolving a relative path from the wrong directory.
CWD_POLICIES = ("launch", "exe")

def validate_encryption(enc: dict) -> None:
    """Refuse a licence policy that cannot ever be satisfied.

    Found by busybody's `wedge` persona (INV-CHAOS-07). An expiry in the past built cleanly
    and produced a binary that refuses every run, forever — `cryptbox.nim` compares the
    policy date against now and quits with "license expired". The person who can fix a
    typo'd year is the person running the build, and they are not watching by the time the
    artifact reaches a customer.
    """
    exp = str(enc.get("expires") or "")
    if not exp:
        return
    # The launcher parses exactly `yyyy-MM-dd` (cryptbox.nim), so anything else is a policy
    # the artifact will fail to interpret at all. The shape is checked before strptime
    # because strptime is LENIENT about zero-padding — it accepts "2030-1-1", which Nim's
    # `parse` with a "yyyy-MM-dd" pattern does not. Accepting a date here that the launcher
    # cannot read would move the failure to the target, which is the whole thing this
    # function exists to prevent.
    try:
        if not _re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp):
            raise ValueError(exp)
        when = _dt.datetime.strptime(exp, "%Y-%m-%d").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        raise BuildError(
            f"expires must be YYYY-MM-DD; got {exp!r}.\n"
            f"The launcher parses this date with that exact format and cannot interpret "
            f"anything else.") from None
    now = _dt.datetime.now(_dt.timezone.utc)
    if when < now:
        raise BuildError(
            f"expires is in the past: {exp} (today is {now:%Y-%m-%d}).\n"
            f"This would build a binary that refuses every run from the moment it is "
            f"created, and the\nrefusal reads as a licensing problem to whoever receives "
            f"it. If that is genuinely intended,\nsay so with a date that has not passed "
            f"yet and let it lapse.")


def validate_manifest(manifest: dict) -> None:
    """Refuse a declaration that cannot be honoured as written.

    Both checks here were found by busybody's `wedge` persona (INV-CHAOS-07), which feeds
    haru-pack contradictory config and reports anything that builds cleanly anyway. Both
    built cleanly, and one of them produced a binary that could not find its own entrypoint.
    """
    sub = str(manifest.get("app_subdir", "app"))
    bad = (Path(sub).is_absolute() or ".." in Path(sub).parts
           or sub.startswith(("/", "\\")) or ":" in sub)
    if bad:
        # Same class as a zip-slip: a path from config that escapes the root it is
        # resolved against. The payload builder copies the project to payload/<app_subdir>,
        # so `..` writes the application OUTSIDE the payload — the zip is assembled from
        # the payload root, the app is not under it, and the launcher stages a binary whose
        # entrypoint is simply absent. Measured: `can't open file '.../escaped/app.py'`.
        raise BuildError(
            f"app_subdir must be a relative path inside the payload; got {sub!r}.\n"
            f"An app_subdir containing '..' or an absolute path writes the application "
            f"outside the\npayload, so the launcher stages a binary whose entrypoint is "
            f"missing. The build would\nsucceed and the artifact would fail on the target.")

    policy = str(manifest.get("cwd_policy", "launch"))
    if policy not in CWD_POLICIES:
        raise BuildError(
            f"cwd_policy must be one of {', '.join(CWD_POLICIES)}; got {policy!r}.\n"
            f"The launcher compares this against 'exe' and treats everything else as "
            f"'launch', so an\nunrecognised value is indistinguishable from a chosen one — "
            f"and the difference only\nshows up as a relative path resolving from the wrong "
            f"directory on someone else's machine.")

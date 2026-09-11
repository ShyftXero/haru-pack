"""INV-CHAOS-07 — a config that cannot be honoured as written is refused at build time.

Every other guard in this suite protects the binary at runtime. These protect the meaning of
the build: a contradictory declaration that builds cleanly is the worst shape available,
because the build is the last point at which the person who can fix it is still watching.

All three defects below were found by busybody's `wedge` persona on its first run, and each
had already produced a working, silent, broken artifact before it was caught.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest

from haru_pack.build import (CWD_POLICIES, BuildError, validate_encryption,
                             validate_manifest)

REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- app_subdir

@pytest.mark.invariant("INV-CHAOS-07")
@pytest.mark.parametrize("sub", ["../escaped", "..", "a/../..", "/abs/path",
                                 "C:\\\\windows", "sub/../../out"])
def test_an_app_subdir_that_escapes_the_payload_is_refused(sub):
    """Same class as a zip-slip: a path from config escaping the root it resolves against.

    The payload builder copies the project to `payload/<app_subdir>`, so `..` writes the
    application OUTSIDE the payload. The zip is then assembled from the payload root, the
    app is not under it, and the launcher stages a binary with no entrypoint. Measured
    before the fix: `can't open file '.../escaped/app.py'`.
    """
    with pytest.raises(BuildError) as e:
        validate_manifest({"app_subdir": sub, "cwd_policy": "launch"})
    assert "app_subdir" in str(e.value), "the message must name the setting at fault"


@pytest.mark.invariant("INV-CHAOS-07")
@pytest.mark.parametrize("sub", ["app", "src/app", "a/b/c"])
def test_ordinary_app_subdirs_still_build(sub):
    """A guard that rejects the normal case is worse than no guard."""
    validate_manifest({"app_subdir": sub, "cwd_policy": "launch"})


# ---------------------------------------------------------------- cwd_policy

@pytest.mark.invariant("INV-CHAOS-07")
def test_an_unrecognised_cwd_policy_is_refused():
    """`main.nim` compares this against "exe" and treats everything else as "launch", so a
    typo and a deliberate choice produce identical binaries. The difference only shows up as
    a relative path resolving from the wrong directory on someone else's machine."""
    with pytest.raises(BuildError) as e:
        validate_manifest({"app_subdir": "app", "cwd_policy": "sideways"})
    msg = str(e.value)
    assert "cwd_policy" in msg and "sideways" in msg, (
        "name both sides: the setting and the value it was given"
    )


@pytest.mark.invariant("INV-CHAOS-07")
@pytest.mark.parametrize("policy", CWD_POLICIES)
def test_every_declared_cwd_policy_is_accepted(policy):
    validate_manifest({"app_subdir": "app", "cwd_policy": policy})


@pytest.mark.invariant("INV-CHAOS-07")
def test_the_policy_list_matches_what_the_launcher_implements():
    """The check is only worth having if it validates against reality.

    Red-path: add a value to CWD_POLICIES that main.nim does not branch on, and the config
    starts accepting a policy the launcher silently downgrades — the original bug with an
    extra step.
    """
    nim = (REPO / "src" / "haru_pack" / "launcher" / "main.nim").read_text()
    manifest_nim = (REPO / "src" / "haru_pack" / "launcher" / "manifest.nim").read_text()

    # the launcher's default is one of ours
    default = re.search(r'gs\(t,\s*"cwd_policy",\s*"([a-z]+)"\)', manifest_nim)
    assert default, "cwd_policy is no longer read from the manifest with a default"
    assert default.group(1) in CWD_POLICIES, (
        f"the launcher defaults to {default.group(1)!r}, which the build does not allow"
    )

    # every non-default value we accept must be a value the launcher actually branches on
    for policy in CWD_POLICIES:
        if policy == default.group(1):
            continue
        assert f'"{policy}"' in nim, (
            f"the build accepts cwd_policy={policy!r} but main.nim never compares against "
            f"it, so it is silently treated as {default.group(1)!r}"
        )


# ---------------------------------------------------------------- expiry

@pytest.mark.invariant("INV-CHAOS-07")
def test_a_licence_that_has_already_expired_is_refused():
    """`cryptbox.nim` compares the policy date to now and quits with "license expired", so
    a past date builds an artifact that is dead on arrival — and the refusal reads as a
    licensing problem to whoever receives it rather than as the typo it is."""
    with pytest.raises(BuildError) as e:
        validate_encryption({"enabled": True, "expires": "2001-01-01"})
    assert "past" in str(e.value) and "2001-01-01" in str(e.value)


@pytest.mark.invariant("INV-CHAOS-07")
def test_a_future_expiry_is_fine_and_an_absent_one_is_not_a_policy():
    later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365)).strftime("%Y-%m-%d")
    validate_encryption({"enabled": True, "expires": later})
    validate_encryption({"enabled": True, "expires": ""})
    validate_encryption({"enabled": True})


@pytest.mark.invariant("INV-CHAOS-07")
@pytest.mark.parametrize("bad", ["01/01/2030", "2030-1-1", "next tuesday", "2030",
                                 "2030-13-01"])
def test_an_expiry_the_launcher_cannot_parse_is_refused(bad):
    """The launcher parses exactly `yyyy-MM-dd`. Anything else is a policy the artifact
    cannot interpret at all, which is a different failure from an expired one."""
    with pytest.raises(BuildError):
        validate_encryption({"enabled": True, "expires": bad})


# ---------------------------------------------------------------- wired in

@pytest.mark.invariant("INV-CHAOS-07")
def test_the_validators_are_actually_called_by_the_build():
    """Both were written because an artifact shipped without them. A validator nothing calls
    is the same as no validator, and it reads better in a diff."""
    src = (REPO / "src" / "haru_pack" / "build.py").read_text()
    body = src[src.index("def _resolve("):src.index("def assemble_payload(")]
    assert "validate_manifest(manifest)" in body, (
        "_resolve must validate the manifest before any build work happens"
    )
    assert "validate_encryption(enc)" in body, (
        "_resolve must validate the licence policy before any build work happens"
    )

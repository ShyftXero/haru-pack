"""The per-knob canary catalogue and the cleartext stub-config section.

A "canary" is the env-name prefix the launcher reads each runtime knob from. The catalogue
is closed on purpose: adding a knob is a format change on BOTH halves (here and
launcher/stubconfig.nim), which is the point.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

import re as _re
import secrets
import string

from .errors import BuildError


# ── Stub-config + per-knob canary (docs/adr/0003-stub-config-and-canary.md §2/§3/§5) ──
# The closed knob catalogue, in the fixed order the cleartext stub-config section writes them.
# Matches launcher/stubconfig.nim `Knob{kSecret,kUvVer,kSourceUrl,kBasePath,kEphemeral}` and its
# lowercase `[canary]` keys — adding a knob is a format change on BOTH halves, on purpose
# (INV-CANARY-02). `ephemeral` (docs/adr/0007) is the fifth knob: the runtime RAM/disk staging
# toggle. It is ADDITIVE — its `[canary]` key is emitted ONLY when non-default (see
# stub_config_bytes), so a build that does not customise it stays byte-identical to the v1
# corpus, and a v1 launcher (which never sees a co-emitted new stub) is unaffected.
_MANDATORY_CANARY_KNOBS = ("secret", "uv_ver", "source_url", "base_path")
CANARY_KNOBS = (*_MANDATORY_CANARY_KNOBS, "ephemeral")
DEFAULT_CANARY = "HARU"
# ^[A-Za-z_][A-Za-z0-9_]*$ — a non-empty, valid env-name prefix. Enforced here at build time,
# re-validated by the launcher's parseStubConfig, so neither half trusts the other blindly.
_CANARY_RE = _re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _random_canary() -> str:
    """One random `[A-Z][A-Z0-9]{7}` token (8 chars) for --env-canary-random."""
    return (secrets.choice(string.ascii_uppercase)
            + "".join(secrets.choice(string.ascii_uppercase + string.digits)
                      for _ in range(7)))


def resolve_canary(env_canary: str = "", env_canary_random: bool = False,
                   per_knob: dict | None = None, log=None) -> dict:
    """Resolve the per-knob canary map (docs/adr/0003 §5). Precedence, per knob independently:

        --stub-env-<knob>-canary  >  --env-canary / --env-canary-random  >  built-in "HARU"

    Refuses two conflicting all-knobs defaults, and any resolved token (default or per-knob)
    that is not a valid env-name prefix (§5.2). On --env-canary-random, logs each knob's final
    token so the packager can record what to set at runtime (§5.3). The map is NOT secret
    (INV-SECRET-02 covers the secret VALUE only)."""
    per_knob = per_knob or {}
    if env_canary and env_canary_random:
        raise BuildError(
            "--env-canary and --env-canary-random set two conflicting all-knobs canary "
            "defaults. Pass one or the other.")
    default = _random_canary() if env_canary_random else (env_canary or DEFAULT_CANARY)
    canary: dict = {}
    for knob in CANARY_KNOBS:
        tok = per_knob.get(knob) or default
        if not _CANARY_RE.fullmatch(tok):
            src = (f"--stub-env-{knob.replace('_', '-')}-canary" if per_knob.get(knob)
                   else ("--env-canary-random" if env_canary_random else "--env-canary"))
            raise BuildError(
                f"canary token {tok!r} (from {src}) is not a valid env-name prefix.\n"
                f"The launcher reads knob {knob.upper()} from <canary>_{knob.upper()} at "
                f"runtime, so the canary must match ^[A-Za-z_][A-Za-z0-9_]*$.")
        canary[knob] = tok
    if env_canary_random:
        say = log or (lambda _m: None)
        say("--env-canary-random: record these — the launcher reads each knob at runtime "
            "as <TOKEN>_<KNOB>:")
        for knob in CANARY_KNOBS:
            say(f"  {knob:10} -> {canary[knob]}_{knob.upper()}")
    return canary


def _toml_basic_str(s: str) -> str:
    """Minimal TOML basic-string escape for a base_path (a path may carry `\\` on a Windows
    target). Only backslash and double-quote need escaping for a single-line basic string."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def stub_config_bytes(canary: dict, *, reap: bool = False, overwrite: bool = False,
                      ram_only: bool = False, base_path: str = "",
                      source_url: str = "", unpacked_bytes: int = 0) -> bytes:
    """The cleartext stub-config TOML section (docs/adr/0003 §2.1 + docs/adr/0004 §2 +
    docs/adr/0007), UTF-8, in fixed order. Canary tokens are validated env-name prefixes, so no
    escaping is needed.

    The optional keys `reap`/`overwrite`/`ram_only`/`base_path`/`source_url`, the
    `unpacked_bytes` sizing hint, and the `ephemeral` canary are all emitted ONLY when
    non-default, so a build that uses none of them is byte-identical to the Phase-1 stub-config
    (the v1 corpus and its exact-bytes test are unchanged). Their absence is today's behaviour,
    so no stub_config_version bump is needed (docs/adr/0004 §2, docs/adr/0007 §back-compat).
    `source_url` (Phase 3, INV-REMOTE-01) names WHERE to fetch the payload; it is not a trust
    anchor (the footer digest is), so it needs no escaping beyond TOML basic-string quoting.
    Read before decryption by launcher/stubconfig.parseStubConfig; sha-checked first
    (INV-STUB-01)."""
    lines = ["stub_config_version = 1"]
    # Top-level keys must precede the [canary] table (TOML). Emit only when non-default.
    if reap:
        lines.append("reap = true")
    if overwrite:
        lines.append("overwrite = true")           # shred-on-reap (docs/adr/0004 5b, INV-SHRED-01)
    if ram_only:
        lines.append("ram_only = true")
    if base_path:
        lines.append(f"base_path = {_toml_basic_str(base_path)}")
    if source_url:
        lines.append(f"source_url = {_toml_basic_str(source_url)}")
    # unpacked_bytes sizes the launcher's RAM-fit check (docs/adr/0007, INV-EPHEMERAL-01). It is
    # only consulted when staging MAY go to RAM, so it is emitted only alongside ram_only — a
    # non-ephemeral binary's stub-config never carries it and stays byte-identical to v1.
    if ram_only and unpacked_bytes > 0:
        lines.append(f"unpacked_bytes = {int(unpacked_bytes)}")
    lines += ["", "[canary]"]
    lines += [f'{knob} = "{canary[knob]}"' for knob in _MANDATORY_CANARY_KNOBS]
    # The EPHEMERAL knob rides the closed catalogue but is additive: its `[canary]` key is written
    # only when its token differs from the default, so the v1 default corpus is unchanged
    # (docs/adr/0007 §back-compat). The launcher defaults a missing key to HARU.
    if canary.get("ephemeral", DEFAULT_CANARY) != DEFAULT_CANARY:
        lines.append(f'ephemeral = "{canary["ephemeral"]}"')
    return ("\n".join(lines) + "\n").encode("utf-8")


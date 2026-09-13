from __future__ import annotations
import datetime as _dt
import re as _re
import os, secrets, shutil, string, subprocess, tempfile
from pathlib import Path
from . import tomlio, discovery, crypto, toolchain
from . import emit as emit_mod
from .paths import launcher_src_dir
from .payload import build_payload_zip
from .overlay import attach, FOOTER_FLAG_ENCRYPTED, FOOTER_FLAG_REMOTE
from .bootstrap import find_nim, detect_c_toolchain
from .tiers import apply_tier, bundles_uv
from .sources import Sources
from .targets import Target
from .entrypoints import (resolve_entrypoint, verify_object_ref, verify_script_file,
                          verify_console_script, is_object_ref, EntryPointError)
from .obfuscate import ObfuscationError, get_engine
from .bundle import (bundle_uv, bundle_python, warm_cache_and_lock,
                     warm_cache_windows, run_bundle_step, run_bundle_steps_wine,
                     warm_cache_for_script, install_dev_tools, compress_uv,
                     UV_SHA256, UV_VERSION)
from . import shake as shake_mod

class BuildError(RuntimeError): ...


# The interpreter version a build stages when nothing else says otherwise. Named rather than
# repeated as a literal so that scripts/self-build.sh can ASK for it — it used to sed this
# file for a line ending in `or "N.N"`, which would silently build release artifacts against
# the wrong Python if the source moved (adversarial review 2026-09-11). Moved 3.12 -> 3.13
# on 2026-09-10; changing it here changes it everywhere.
DEFAULT_PYTHON = "3.13"

# INV-PAYLOAD-01: a payload is appended to a binary that gets distributed, and often
# signed. Anything credential-shaped that lands in it is published. Build directories
# routinely sit next to a working .env, so exclusion is the default, not the operator's job.
_SECRET_PATTERNS = ("*.env", ".env", ".env.*", ".envrc", ".direnv",
                    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
                    "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
                    ".ssh", ".aws", ".gnupg", ".netrc", "_netrc",
                    "credentials", "credentials.*", "secrets.*", "*.secret",
                    ".npmrc", ".pypirc", "service-account*.json")

_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".venv", "venv", "*.egg-info",
                                 "dist", "build", ".git", "haru_pack.toml", ".mypy_cache",
                                 ".pytest_cache", ".ruff_cache", "*.exe",
                                 *_SECRET_PATTERNS)

# The values `main.nim` actually implements. It reads the policy with a string default and
# compares it to "exe", so anything else silently means "launch" — a typo and a deliberate
# choice produce identical binaries, and the one place the difference shows up is a customer
# resolving a relative path from the wrong directory.
CWD_POLICIES = ("launch", "exe")

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

# inject (env-append) reserved keys (docs/adr/0003 §4.3). The launcher sets its own reserved
# vars AFTER the inject loop and so WINS on a collision (INV-LAUNCH-09); an inject that lands on
# one of these would be silently dropped. A silently-ineffective inject is exactly the class
# INV-BUILD-01/02 exist to forbid, so the build refuses it outright rather than shipping a lie.
_RESERVED_INJECT_KEYS = frozenset({
    "UV_CACHE_DIR", "UV_PYTHON", "UV_PYTHON_INSTALL_DIR", "UV_PYTHON_DOWNLOADS",
    "UV_OFFLINE", "UV_PROJECT_ENVIRONMENT", "PYTHONPYCACHEPREFIX", "PYTHONPATH",
})
# Secret-shaped inject detection (docs/adr/0003 §4.3) — deterministic, so the warning is
# reproducible. Same honesty as --embed-secret (INV-SECRET-02): an unencrypted payload ships the
# value recoverable in plaintext, and haru-pack says so rather than letting the operator assume.
_SECRET_KEY_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "APIKEY", "API_KEY",
                       "PRIVATE_KEY", "ACCESS_KEY")
_SECRET_VALUE_RE = _re.compile(r"[A-Za-z0-9+/=_-]{20,}\Z")


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


# ── base_path safety (docs/adr/0004 §5, INV-BASE-01) ──────────────────────────────────────
# A staging root that is a filesystem/drive/UNC root or a home-directory root is refused. The
# launcher creates AND (with --reap) deletes a create-and-delete-own subtree beneath this
# root, so the root must never be a place whose pollution or deletion would be catastrophic.
# The build refuses the obvious shapes here (fail fast, cross-OS aware — a --target windows
# build on Linux must still reject `C:\`); the launcher re-refuses defensively at runtime,
# where the target's real "/" and $HOME are knowable (refuseUnsafeRoot in stage.nim).
_DRIVE_ROOT_RE = _re.compile(r"[A-Za-z]:[\\/]?\Z")     # C:  C:\  C:/
_FS_ROOT_RE = _re.compile(r"[\\/]+\Z")                 # /  \  //  \\  (posix root / UNC-ish)


def _is_root_like(path: str) -> bool:
    p = path.rstrip("/\\") or path            # keep a lone "/" as "/"
    if p in ("/", "\\"):
        return True
    if _FS_ROOT_RE.fullmatch(path):           # bare separators only -> a root
        return True
    if _DRIVE_ROOT_RE.fullmatch(path):        # Windows drive root, any build OS
        return True
    home = os.path.expanduser("~")
    return bool(home and home != "~" and os.path.normpath(p) == os.path.normpath(home))


def resolve_base_path(base_path: str) -> str:
    """Validate the --base-path staging root (docs/adr/0004 §3/§5). '' means 'normal cache'
    (the default, no refusal). A non-empty value that is empty-after-strip, a filesystem/drive/
    UNC root, or the build host's home root is REFUSED at build time (INV-BASE-01). The value
    is stored verbatim in the cleartext stub-config; the launcher applies the same refusal
    against the TARGET's real roots at runtime."""
    if not base_path:
        return ""
    if not base_path.strip():
        raise BuildError("--base-path is blank. Omit it for the normal per-user cache, or "
                         "give a real staging directory.")
    if _is_root_like(base_path):
        raise BuildError(
            f"--base-path {base_path!r} resolves to a filesystem, drive, or home-directory "
            f"root. The launcher stages AND (with --reap) deletes a subtree under this path, "
            f"so it must be a dedicated directory, never a root (docs/adr/0004 §5).")
    return base_path


def resolve_source_url(source_url: str) -> str:
    """Validate the Phase-3 remote-fetch URL (docs/adr/0005, INV-REMOTE-01). "" = appended
    delivery (the default). This is a build-time sanity check to catch a typo, NOT a security
    boundary: the launcher does not trust the URL at all — it fetches from it and verifies the
    bytes against the build-baked footer digest, so a hostile URL can only cause a fail-closed
    refusal. We require an http/https scheme (the launcher's puppy HTTP client speaks those)
    and a non-empty host, and reject leading/trailing whitespace that would smuggle into TOML."""
    if not source_url:
        return ""
    if source_url != source_url.strip():
        raise BuildError("--source-url has leading or trailing whitespace.")
    lo = source_url.lower()
    if not (lo.startswith("http://") or lo.startswith("https://")):
        raise BuildError(
            f"--source-url {source_url!r} must be an http:// or https:// URL — the launcher "
            f"fetches the payload over HTTP (and verifies it against the baked digest). "
            f"Host the payload sidecar this build writes at that URL.")
    rest = source_url.split("://", 1)[1]
    host = rest.split("/", 1)[0]
    if not host:
        raise BuildError(f"--source-url {source_url!r} has no host.")
    return source_url


# ── Phase-4 execution gates: online geo/ip (docs/adr/0006, INV-GATE-01 / INV-GEO-01) ──
DEFAULT_GEO_ENDPOINT = "https://ipwho.is/"


def _normalize_geo(geo) -> dict:
    """Coerce a geo spec into the Phase-4 gate OBJECT {endpoints?, consensus?, allow[]}.

    {} / None -> {} (no gate); a dict -> as-is; a list of country codes (a haru_pack.toml
    `[encryption] geo = [...]` or a legacy caller) -> allow-rules on country_code. This keeps a
    declared-in-TOML country list working while the wire format is the uniform gate object."""
    if not geo:
        return {}
    if isinstance(geo, dict):
        return geo
    return {"allow": [{"country_code": str(g)} for g in geo if g]}


def build_geo_policy(countries, restrict, api_urls, consensus) -> dict:
    """Assemble the encrypted geo/ip execution-gate policy from CLI inputs (INV-GATE-01 /
    INV-GEO-01). Returns {} when no allow-rule is given (no gate). The gate is uniform: resolve
    the caller's IP+geo from a consensus of online resolvers, match an allow-policy, fail closed.

      * --geo US,CA            -> two rules {country_code: US} OR {country_code: CA}
      * --geo-restrict "a=1,b=2" -> one rule {a:1, b:2} (AND within), OR'd across repeats
      * --geo-restrict-api-url -> resolver endpoints (default ipwho.is)
      * --geo-restrict-consensus -> K endpoints must resolve AND agree (default 1)

    Any resolver field can be asserted (so ip=1.2.3.4 is an ip gate) — one mechanism, not a
    bespoke rule per gate. Refuses a consensus that can never be reached, and endpoints/consensus
    set with no rule (a gate that does nothing is the SILENT-WEDGE class, INV-CHAOS-07)."""
    allow: list[dict] = [{"country_code": c} for c in (countries or []) if c]
    for spec in (restrict or []):
        rule: dict = {}
        for pair in spec.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise BuildError(
                    f"--geo-restrict rule {spec!r} has a term without '=': {pair!r}. Use "
                    f"field=value[,field=value] (e.g. country_code=US,region=Texas).")
            k, v = (p.strip() for p in pair.split("=", 1))
            if not k or not v:
                raise BuildError(f"--geo-restrict rule {spec!r} has an empty field or value.")
            rule[k] = v
        if rule:
            allow.append(rule)
    if not allow:
        if api_urls or (consensus and consensus != 1):
            raise BuildError(
                "--geo-restrict-api-url / --geo-restrict-consensus configure a geo gate but no "
                "allow-rule was given, so nothing would be enforced. Add --geo or --geo-restrict, "
                "or drop the endpoint/consensus flags.")
        return {}
    # Dedup while preserving order: a consensus is only meaningful across DISTINCT resolvers.
    # Listing the same URL K times would otherwise let one server (or one on-path MITM that
    # intercepts it) satisfy the whole quorum — silently voiding "one endpoint lying doesn't
    # decide the gate". Consensus is checked against the UNIQUE count.
    seen: set = set()
    endpoints: list[str] = []
    for u in (api_urls or []):
        u = u.strip()
        if not u:
            continue
        if not (u.lower().startswith("http://") or u.lower().startswith("https://")):
            raise BuildError(f"--geo-restrict-api-url {u!r} must be an http:// or https:// URL.")
        if u not in seen:
            seen.add(u)
            endpoints.append(u)
    if not endpoints:
        endpoints = [DEFAULT_GEO_ENDPOINT]
    k = consensus or 1
    if k < 1:
        raise BuildError("--geo-restrict-consensus must be >= 1.")
    if k > len(endpoints):
        raise BuildError(
            f"--geo-restrict-consensus={k} exceeds the {len(endpoints)} DISTINCT resolver "
            f"endpoint(s) configured, so consensus can never be reached and the gate would "
            f"fail closed forever. Add more distinct --geo-restrict-api-url, or lower the "
            f"consensus.")
    return {"endpoints": endpoints, "consensus": k, "allow": allow}


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


def _staged_tree_bytes(payload_dir: Path) -> int:
    """Size of the tree the launcher will STAGE, for the RAM-fit check (docs/adr/0007,
    INV-EPHEMERAL-01).

    Not `du` of the payload dir: `uv` ships XZ-compressed (`uv.xz`, ~14 MB) and the launcher
    EXPANDS it on stage (~56 MB) via `expandCompressedMembers`. Summing the compressed bytes
    would under-count by ~40 MB and could hand the RAM gate a "fits" verdict for a tree that
    then OOMs the small box the gate exists to protect (adversarial review C1). So for every
    `.xz` member the build wrote a `.xz.size` sidecar for (see `bundle.compress_uv`), count the
    EXPANDED size, and drop the `.xz` and its metadata sidecars from the count entirely — they
    are removed before the launcher records the tree. The result is the staged tree's real size;
    the launcher applies the ×1.2 headroom on top (INV-EPHEMERAL-01)."""
    total = 0
    for p in payload_dir.rglob("*"):
        if not p.is_file():
            continue
        name = p.name
        if name.endswith((".xz.size", ".xz.sha256")):
            continue                        # metadata sidecars, not part of the staged tree
        if name.endswith(".xz"):
            sidecar = p.with_name(name + ".size")
            if sidecar.exists():
                try:
                    total += int(sidecar.read_text().strip())   # EXPANDED size
                    continue
                except ValueError:
                    pass
            # Sidecar missing OR present-but-unparseable (the `except ValueError` above): either
            # way the launcher's own expandCompressedMembers refuses to stage this member at all
            # (StageError: "no .size sidecar" / "unreadable size sidecar"), so a build that ships
            # this tree unchanged would never actually reach the RAM-fit check with it. Count the
            # compressed size as the best available fallback for THIS estimate; it does not change
            # what the launcher will do at runtime.
            total += p.stat().st_size
            continue
        total += p.stat().st_size
    return total


def _looks_secret_shaped(key: str, value: str) -> bool:
    """Deterministic 'this inject looks like a credential' test (docs/adr/0003 §4.3)."""
    ku = key.upper()
    if ku.endswith("_KEY") or any(m in ku for m in _SECRET_KEY_MARKERS):
        return True
    return bool(_SECRET_VALUE_RE.fullmatch(value))


def resolve_injects(env_append, encrypted: bool, log=None) -> list:
    """Validate --env-append into the manifest `inject` list (docs/adr/0003 §4.3).

    Refuses a malformed (`no '='`, empty KEY) or reserved-KEY inject — an inject the launcher
    would silently drop is the class INV-BUILD-01/02 forbid. On an UNENCRYPTED build, warns
    loudly for a secret-shaped inject, the same honesty as --embed-secret (INV-SECRET-02): the
    value ships recoverable in plaintext. An ENCRYPTED build hides the payload, so no warning.
    Called 'inject', never 'project'. Each entry is stored verbatim; the launcher splits on the
    FIRST '=' (INV-LAUNCH-09), so an odd VALUE containing '=' round-trips faithfully."""
    injects: list = []
    for raw in (env_append or []):
        if "=" not in raw:
            raise BuildError(f"--env-append must be KEY=VALUE; got {raw!r} with no '='.")
        key, value = raw.split("=", 1)
        if not key:
            raise BuildError(f"--env-append has an empty KEY: {raw!r}.")
        if key.startswith("HARUPACK_") or key in _RESERVED_INJECT_KEYS:
            raise BuildError(
                f"--env-append {key}=… uses a reserved key. The launcher sets its own "
                f"HARUPACK_*, the managed UV_*, PYTHONPYCACHEPREFIX and PYTHONPATH AFTER the "
                f"injects and wins on a collision (INV-LAUNCH-09), so this inject would be "
                f"silently dropped. Rename it, or configure the launcher's behaviour directly.")
        if not encrypted and _looks_secret_shaped(key, value):
            say = log or (lambda _m: None)
            say(f"WARNING: --env-append {key}=… looks secret-shaped and this build is NOT "
                f"encrypted, so the value ships recoverable in plaintext in the binary. Add "
                f"--encrypt to hide it inside the payload, or confirm it is not a secret "
                f"(INV-SECRET-02).")
        injects.append(raw)
    return injects


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


# Which C compiler compiles the launcher. `zig` is the default on purpose (INV-TOOL-02):
# one pinned ~50 MB download covers every target haru-pack builds for, needs no sudo and no
# package manager, and so removes the last step between `uv tool install haru-pack` and a
# working build. `system` is the escape hatch for anyone who would rather use the cross
# toolchains they already have — and it is what a Mac target requires, since zig's bundled
# macOS headers are incomplete for Nim's posix module.
CC_PROVIDERS = ("zig", "system")
CC_ENV = "HARUPACK_CC"


def resolve_cc(cc: str = "", target=None, log=None) -> str:
    """Decide the provider. Explicit flag beats env var beats the default.

    A macOS target forces `system` rather than failing later with a header error, and says
    so — the operator asked for a Mac build, not for a lecture about zig.
    """
    say = log or (lambda _m: None)
    want = (cc or os.environ.get(CC_ENV, "") or "zig").strip().lower()
    if want not in CC_PROVIDERS:
        raise BuildError(
            f"unknown --cc {want!r}. Choose one of: {', '.join(CC_PROVIDERS)}.\n"
            f"`zig` uses the pinned compiler haru-pack installs for itself; `system` uses "
            f"the cross toolchains already on this machine.")
    if want == "zig" and target is not None:
        tgt = target if isinstance(target, Target) else Target.parse(target)
        if not tgt.zig_can_build():
            say(f"--cc zig cannot build for {tgt}; using the system compiler instead "
                f"(zig's bundled macOS headers are incomplete for Nim's posix module).")
            return "system"
    return want


def compile_launcher(nim: str, target, workdir: Path, cc: str = "", log=None) -> Path:
    tgt = target if isinstance(target, Target) else Target.parse(target)
    src = launcher_src_dir() / "main.nim"
    if not src.exists():
        raise BuildError(f"launcher source missing: {src}")
    out = workdir / ("launcher" + tgt.exe_suffix)
    # Nim writes its build manifest (nimcache/launcher.json: the exact per-file compile
    # commands + the link command) on every build, and leaves the generated C in the
    # nimcache. That is what `--emit-c` (see build()) turns into a zig compile.sh — the recipe
    # is the one Nim actually used, never a hand-written approximation (INV-EMIT-02). No extra
    # Nim flag is needed for that; `--genScript` would SKIP linking and break this real build.

    provider = resolve_cc(cc, target=tgt, log=log)
    shim = None
    if provider == "zig":
        # A generated shim, not a bare `zig cc`: Nim wants ONE executable for the compiler
        # key, and one GCC-only flag has to be translated per invocation. Nim also ignores
        # the generic `--gcc.exe` for a cross target and reads `--<cpu>.<os>.gcc.exe`, which
        # is why the keys are spelled out per target inside emit.nim_target_flags.
        zig = toolchain.find_managed_zig() or toolchain.install_zig(
            log=log or (lambda _m: None))
        shim = toolchain.zig_cc_shim(str(zig), tgt.zig_triple(), workdir / "zig-cc")
    # The per-target flag set is defined ONCE, in emit.nim_target_flags, and reused by the
    # --emit-nim kit's compile.sh, so the emitted recipe cannot drift from this build
    # (INV-EMIT-01). Only the ambient nim/nimcache/out/source path is added here.
    args = [nim, "c", *emit_mod.nim_target_flags(tgt, provider,
                                                 shim_ref=(str(shim) if shim else None)),
            f"--nimcache:{workdir/'nimcache'}", f"--out:{out}", str(src)]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 or not out.exists():
        raise BuildError(f"nim compile failed (cc={provider}):\n"
                         + (r.stderr or r.stdout)[-2000:])
    return out


def _declarations(decl_dir: Path) -> dict:
    """Merge the project's build directives from both places it may declare them.

    Precedence, lowest first — the same shape `discovery`'s docstring already described:

        discovery  <  [tool.haru-pack] in pyproject.toml  <  haru_pack.toml  <  CLI flags

    `[tool.haru-pack]` exists because a project that is already a package has one obvious
    home for its own build configuration, and asking for a second file to say "this is how
    I am bundled" is friction for no gain. `haru_pack.toml` stays, wins where both speak,
    and remains what `haru-pack init` writes — it is the sidecar for a tree that has no
    pyproject.toml at all (a bare script, a folder of `.py` files), and the local override
    for one that does.

    The merge is per top-level key, not deep: a `[[bundle]]` list in `haru_pack.toml`
    REPLACES the one in pyproject.toml rather than appending to it. Concatenating would
    mean an operator could not remove an inherited step, only add to it, and "why is this
    build still running a step I deleted" is a bad afternoon.
    """
    merged: dict = {}
    pp = decl_dir / "pyproject.toml"
    if pp.exists():
        tool = (tomlio.load(pp).get("tool") or {})
        if "haru-pack" not in tool and "haru_pack" in tool:
            # Refuse rather than silently ignore. A config table that is read by nobody is
            # worse than a missing one: the operator believes it took effect.
            raise BuildError(
                f"{pp} has a [tool.haru_pack] table; haru-pack reads [tool.haru-pack] "
                f"(hyphen, matching the distribution name). Rename the table — it is "
                f"being ignored, and silently honouring both spellings would mean two "
                f"places to look when a directive does not apply.")
        merged.update(tool.get("haru-pack") or {})
    side = decl_dir / "haru_pack.toml"
    if side.exists():
        merged.update(tomlio.load(side))
    return merged


def _resolve(project: Path, tier: str, python_cli: str,
             expires, geo, machine, user, embed_secret, encrypt: bool = False,
             entry_point: str = "", log=None):
    """Discover + merge haru_pack.toml + CLI. Returns (manifest, enc, python_version)."""
    # The declaration is read FIRST. Discovery only has to succeed when nothing else says
    # what to run: refusing to guess (INV-BUILD-03) must never become refusing to obey.
    # This ordering was backwards, and the symptom was absurd — a project with an explicit
    # `entrypoint` in haru_pack.toml was rejected with advice telling the operator to set
    # `entrypoint` in haru_pack.toml.
    decl_dir = project if project.is_dir() else project.parent
    decl = _declarations(decl_dir)
    explicit_ep = entry_point or decl.get("entrypoint")
    try:
        disc = discovery.discover(project)
    except discovery.AmbiguousProject as e:
        if not explicit_ep:
            raise
        # Ambiguity is resolved: the operator said which one. Keep what the exception
        # already worked out about the project so the rest of the merge is unchanged.
        disc = {"kind": e.kind, "name": e.name, "app_subdir": "app",
                "entrypoint": [], "python": e.python, "source": e.source or project}
    # --entry-point beats haru_pack.toml beats discovery. Accepts a script name, a
    # console-script name, or a `module:callable` object reference in the same spelling
    # [project.scripts] uses — resolved to argv here so the launcher never parses it.
    ep = entry_point or decl.get("entrypoint") or disc["entrypoint"]
    # A `module:callable` becomes a `python -c "from module import attr"` argv and nothing
    # used to check that the import resolves, so a typo built cleanly, exited 0, and failed
    # on the customer's machine at first run (INV-BUILD-04). Checked statically — parsing
    # the module rather than importing it, so nothing of the project executes on the build
    # host and the check works for cross-compiled targets too. Silent unless it is certain.
    if isinstance(ep, str):
        problem = verify_object_ref(ep, decl_dir) or verify_script_file(ep, decl_dir)
        if problem:
            raise EntryPointError(problem)
        # A bare console-script name cannot be checked for certain without an environment —
        # the launcher runs `uv run <name>`, which also resolves scripts provided by
        # DEPENDENCIES. So say what could not be verified rather than refusing a build that
        # is probably fine; `assemble_payload` upgrades this to a refusal at thick, where
        # there is a real environment to look in.
        if not is_object_ref(ep) and not ep.endswith(".py"):
            level, msg = verify_console_script(ep, decl_dir)
            if level == "warn" and log:
                log(f"WARNING: {msg}")
    ep = resolve_entrypoint(ep, name=decl.get("name", disc["name"]),
                            kind=decl.get("kind", disc["kind"]))
    manifest = {
        "name": decl.get("name", disc["name"]),
        "kind": decl.get("kind", disc["kind"]),
        "app_subdir": decl.get("app_subdir", disc["app_subdir"]),
        "entrypoint": ep,
        "cwd_policy": decl.get("cwd_policy", "launch"),
        "verbose_uv": decl.get("verbose_uv", False),
        # PEP 723 inline dependencies, so the thick tier can stage them (INV-TIER-01).
        "script_dependencies": list(disc.get("dependencies") or []),
        # `[shake]` — how to OBSERVE this project, and what to keep regardless. Carried
        # here (and popped before the manifest is written) for the same reason
        # script_dependencies is: it is build-time input, not something the launcher reads.
        "shake_declared": dict(decl.get("shake") or {}),
    }
    for k in ("bundle", "pre_install", "post_install", "uv_run_args"):
        if k in decl:
            manifest[k] = decl[k]
    pyver = (python_cli or decl.get("python", "") or disc.get("python", "")
         or DEFAULT_PYTHON)
    e = decl.get("encryption", {})
    # `geo` arrives as the assembled gate object (build_geo_policy) or {}; fall back to a
    # haru_pack.toml `[encryption] geo = [...]` country list, normalized to the same object
    # shape (INV-GEO-01). Resolve it ONCE and use the SAME object for both the enabled test and
    # the policy value — otherwise a geo declared only in TOML sets no enabled bit and is
    # silently dropped (ships plaintext, no gate: the SILENT-WEDGE class, INV-CHAOS-07).
    geo_obj = _normalize_geo(geo) if geo else _normalize_geo(e.get("geo", []))
    exp = expires or e.get("expires", "")
    mach = machine or e.get("machine", "")
    usr = user or e.get("user", "")
    embed = embed_secret or bool(e.get("embed_secret"))
    enc = {
        # INV-BUILD-02: an explicit --encrypt must enable encryption on its own. It was
        # previously dropped here, so `--encrypt --secret X` with no policy flag attached a
        # PLAINTEXT payload and exited 0. Every policy field — from CLI OR haru_pack.toml —
        # forces encryption, so a declared licence/gate can never silently ship unenforced;
        # a missing secret then fails LOUDLY at the `enabled and secret is None` guard below.
        "enabled": bool(encrypt) or bool(e.get("enabled"))
                   or any([exp, geo_obj.get("allow"), mach, usr, embed]),
        "expires": exp,
        "geo": geo_obj,
        "machine": mach,
        "user": usr,
        "embed_secret": embed,
    }
    validate_manifest(manifest)
    if enc["enabled"]:
        validate_encryption(enc)
    return manifest, enc, pyver, disc["source"], Sources.resolve(decl)

def _entry_relpath(manifest: dict) -> str:
    """The .py file the obfuscator should treat as the entry, relative to the app dir.

    entrypoint is argv resolved for the launcher; for obfuscation we only need a real .py
    to hand pyarmor. A module:callable or console-script entry has no single file, so fall
    back to the app package's __init__ or the first .py — pyarmor obfuscates the whole tree
    regardless, and this only decides which file the "did the entry survive" check watches.
    """
    ep = manifest.get("entrypoint") or []
    for tok in ep:
        if isinstance(tok, str) and tok.endswith(".py"):
            return tok
    return "app.py"


def assemble_payload(source: Path, manifest: dict, tier: str, target,
                     python: str, workdir: Path, wine: bool = False,
                     sources: Sources | None = None, eager_deps: bool = False,
                     log=None, shake: bool = False, shake_keep=(),
                     shake_report: dict | None = None) -> Path:
    sources = sources or Sources()
    tgt = target if isinstance(target, Target) else Target.parse(target)
    # --shake's preconditions are checked BEFORE anything is downloaded. Discovering that a
    # shake was impossible after staging a 90 MB interpreter wastes the operator's time,
    # and — worse — the tempting fix at that point is to carry on and emit an unshaken
    # binary, which is precisely the "asked for small, silently got fat" outcome the flag
    # exists to prevent. Refuse early and say what to do instead.
    if shake:
        if tier != "thick":
            raise BuildError(
                f"--shake needs --thick (got tier '{tier}'). At thin/default the "
                "dependencies are not in the payload — uv fetches them on the target — so "
                "there is nothing to prune and no size to save.")
        if not tgt.is_host:
            raise BuildError(
                f"--shake cannot build for --target {tgt} from here. Observing which files "
                "a program touches means RUNNING its test suite, and this host cannot run "
                f"{tgt} binaries. Shake on a {tgt} machine, or build for {tgt} without it.")
        if manifest.get("kind") != "project":
            raise BuildError(
                "--shake needs a project (a pyproject.toml with a dependency group to run "
                "the suite from), not a single PEP 723 script. A script's payload is its "
                "inline dependencies and there is no declared test command to observe.")
    payload = workdir / "payload"
    app = payload / manifest["app_subdir"]
    if source.is_file():
        app.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, app / source.name)
    else:
        shutil.copytree(source, app, ignore=_IGNORE)

    # Obfuscation is a source transform, applied to the copied app before anything else reads
    # it — cache warming, dependency staging and the zip all see the obfuscated tree. It is
    # INDEPENDENT of encryption: you can obfuscate a plaintext-payload binary, encrypt an
    # unobfuscated one, do both, or neither. They protect different things (see
    # INV-SECRET-02) and are wired on separate axes so neither implies the other.
    obf = manifest.get("_obfuscation")
    if obf and obf.get("engine", "none") != "none":
        engine = get_engine(obf["engine"], obf.get("args") or ())
        entry_rel = _entry_relpath(manifest)
        try:
            res = engine.obfuscate(app, entry_rel, python=python, log=log)
        except ObfuscationError as e:
            # A failed obfuscation must fail the build. Shipping the plaintext the user asked
            # to hide, silently, is the exact anti-pattern INV-SECRET-02 and INV-DOC-02 guard.
            raise BuildError(f"obfuscation failed: {e}") from e
        manifest["obfuscation"] = {"engine": res.engine, "applied": res.applied,
                                   "files": res.files}
        say = log or (lambda _m: None)
        say(f"obfuscation: {res.note}")
        say("obfuscation raises the cost of reading the staged source; it is NOT a "
            "confidentiality boundary. A secret that must never be recovered must never be "
            "shipped (INV-SECRET-02).")
    else:
        manifest.setdefault("obfuscation", {"engine": "none", "applied": False})

    manifest = apply_tier(dict(manifest), tier)
    vendor = payload / "vendor"
    # tiers.bundles_uv is the single statement of which tiers ship a uv (main's
    # INV-TIER work); tgt/sources carry the arch and mirror plumbing.
    if bundles_uv(tier):
        uv_exe = bundle_uv(tgt, vendor, sources=sources)
        # INV-PAYLOAD-04. uv is the biggest thing in a non-thin payload and the payload zip
        # is DEFLATE-only, so it ships XZ-compressed and the launcher expands it during
        # staging. Guarded on the return value because `conftest.stub_toolchain` replaces
        # bundle_uv with a stub that stages no binary at all.
        if uv_exe and Path(uv_exe).is_file():
            compress_uv(uv_exe, log=log)
    else:
        # THIN tier: uv is downloaded on the customer's machine and then executed, so the
        # launcher wants a digest to check it against BEFORE extracting it (INV-SUPPLY-05).
        # `uvfetch.nim` has had that mechanism since 2026-09-09 with its own note saying
        # "Nothing populates `uv_sha256` yet — writing it at build time lives in the Python
        # build/tier code, not here", and it warned on every fetch that it had no pin. This
        # is that. The value is the digest of the release ARCHIVE from pins.toml, which is
        # what uvfetch hashes; it is deliberately NOT the digest of the bundled binary that
        # `compress_uv` records for the other tiers.
        asset = tgt.uv_asset()
        digest = UV_SHA256.get(UV_VERSION, {}).get(asset)
        if not digest:                                              # INV-SUPPLY-01
            raise BuildError(
                f"no pinned sha256 for uv {UV_VERSION} asset {asset}, so a --thin binary "
                f"would fetch and execute an unverified uv on the target. Add it with:\n"
                f"    python tools/add-pin.py uv {UV_VERSION} {asset}")
        manifest["uv_sha256"] = digest
        manifest["uv_version"] = UV_VERSION
    if tier == "thick":
        steps = manifest.get("bundle") or []
        if steps and not tgt.is_host and not wine:
            raise BuildError(
                f"bundle steps run target-native code and can't be produced for --target "
                f"{tgt} from here. Re-run with --wine, build --thick on a {tgt} machine, or "
                f"fetch by URL.")
        py = bundle_python(tgt, vendor, version=python, sources=sources)
        if manifest.get("kind") == "project" or steps:
            app_dir = payload / manifest["app_subdir"]
            cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
            if tgt.is_host:
                tmp_env = Path(tempfile.mkdtemp(prefix="haru-warm-"))
                try:
                    warm_cache_and_lock(app_dir, py, cache, tmp_env, sources=sources)
                    # The bundled cache above is runtime-only (INV-PAYLOAD-03). Dev tools
                    # go into the throwaway env only, so a [[bundle]] step or a --shake
                    # observation can still run them without the payload carrying them.
                    if steps or shake:
                        install_dev_tools(app_dir, tmp_env, sources=sources, log=log)
                    # At thick there IS an environment, so a console-script entrypoint can
                    # be checked for certain instead of warned about (INV-BUILD-08). This
                    # is the strongest form of the check and the only one that can see a
                    # script provided by a dependency rather than by the project.
                    ep_argv = manifest.get("entrypoint") or []
                    if len(ep_argv) == 1 and not ep_argv[0].endswith(".py"):
                        level, msg = verify_console_script(ep_argv[0], app_dir,
                                                           env_dir=tmp_env)
                        if level == "error":
                            raise BuildError(msg)
                    for step in steps:
                        run_bundle_step(step, payload, tmp_env, app_dir)
                    if shake:
                        # `tmp_env` is the right place to observe from and the reason the
                        # shake happens here rather than after the payload is assembled:
                        # it was built by uv FROM THE BUNDLED CACHE with the BUNDLED
                        # interpreter, so every path the tracer sees maps onto a file that
                        # is actually in the payload. Observing a project's own `.venv`
                        # instead would trace a different resolution against a different
                        # Python and produce a keep set for a payload that does not exist.
                        cfg = shake_mod.resolve_config(
                            app_dir, {"shake": manifest.get("shake_declared") or {}},
                            cli_keep=shake_keep)
                        rep = shake_mod.shake(payload, app_dir, cache, py, tmp_env, cfg,
                                              workdir, sources=sources, log=log)
                        if shake_report is not None:
                            shake_report.update(rep)
                        manifest.update(shake_mod.manifest_summary(rep))
                finally:
                    shutil.rmtree(tmp_env, ignore_errors=True)
            else:
                warm_cache_windows(app_dir, cache, python, sources=sources)
                if steps and wine:
                    run_bundle_steps_wine(steps, payload, py, app_dir)
            manifest["cache_dir"] = "vendor/cache"

        # A PEP 723 script's dependencies live in its inline metadata, and until 2026-09-09
        # nothing staged them: `kind == "project"` got its cache warmed and `kind ==
        # "script"` did not, so `--thick` produced a binary that still hit the network on
        # first run. The tier's contract is "download NOTHING", so at thick this is not
        # optional and not silent (INV-TIER-01).
        if manifest.get("kind") == "script" and target_is_host(tgt):
            deps = manifest.get("script_dependencies") or []
            if deps:
                cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
                say = log or (lambda _m: None)
                say(f"staging {len(deps)} script dependency/ies into the payload: "
                    + ", ".join(deps[:6]) + (" …" if len(deps) > 6 else ""))
                warm_cache_for_script(Path(source), py, cache, sources=sources)
                manifest["cache_dir"] = "vendor/cache"
    # INV-TIER-02. `post_install` means "fetch/setup on the target, on first run"; thick
    # means "download NOTHING, fully offline" and sets UV_OFFLINE=1 in the launcher. Those
    # are contradictory, and haru-pack used to accept the combination silently. It cannot
    # know whether a given step needs the network — `flask db upgrade` does not, `spacy
    # download` does — so it warns rather than refusing, and names the steps.
    #
    # Measured 2026-09-09 on the flex hard targets: spacy's documented post_install failed
    # on the FIRST run of a thick binary (uv refused the download the tier had disabled),
    # and nltk's succeeded with network but failed the offline check. Both are the
    # documented advice from scaffold.KNOWN, combined with a tier that forbids it.
    if tier == "thick" and manifest.get("post_install"):
        say = log or (lambda _m: None)
        steps = manifest["post_install"]
        say(f"WARNING: {len(steps)} post_install step(s) with --thick. thick sets "
            f"UV_OFFLINE=1, so any step that downloads will FAIL on the target. Move the "
            f"work to a [[bundle]] step (runs at build time, output ships in the payload) "
            f"or use --tier default.")
        for st in steps:
            run = st.get("run") if isinstance(st, dict) else st
            say(f"  post_install: {' '.join(run) if isinstance(run, list) else run}")

    manifest.pop("script_dependencies", None)   # build-time only; not for the launcher
    manifest.pop("shake_declared", None)        # ditto — the launcher never re-shakes
    tomlio.dump(manifest, payload / "manifest.toml")
    return payload

def target_is_host(tgt) -> bool:
    """Cache warming runs the TARGET's interpreter, so it only works building for this box.

    Cross-compiled thick builds use warm_cache_windows, which resolves wheels for the
    target platform without executing them.
    """
    return tgt.is_host


def build(project: Path, out: Path, target: str = "host", tier: str = "default",
          secret: bytes | None = None, expires: str = "", geo=None,
          geo_restrict=(), geo_api_urls=(), geo_consensus: int = 1,
          machine: str = "", user: str = "", embed_secret: bool = False,
          obfuscate: str = "none", obfuscate_args=(),
          python: str = "", wine: bool = False, encrypt: bool = False,
          entry_point: str = "", shake: bool = False, shake_keep=(),
          env_canary: str = "", env_canary_random: bool = False,
          stub_env_secret_canary: str = "", stub_env_uv_ver_canary: str = "",
          stub_env_source_url_canary: str = "", stub_env_base_path_canary: str = "",
          stub_env_ephemeral_canary: str = "",
          reap: bool = False, overwrite: bool = False, ram_only: bool = False,
          no_reap: bool = False, base_path: str = "", source_url: str = "", env_append=None,
          cc: str = "", emit_c: str = "", emit_nim: str = "", log=None) -> dict:
    project = Path(project); out = Path(out)
    # The operator's -o may name a directory that does not exist yet. Create it now rather
    # than let the final `out.write_bytes` die with a raw FileNotFoundError — busybody's
    # `greenhorn_output_into_missing_dir` turned that into a CRASHED (not a clean refusal).
    # A parent that cannot be created is refused intelligibly, never a bare traceback
    # (INV-BUILD-01).
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise BuildError(f"cannot create the output directory {out.parent}: {e}")
    # --emit-c: a C reproduction kit written beside the binary. Resolve the directory now
    # (before any tempdir/chdir) so a relative path lands where the user expects, and validate
    # it up front so an unsafe/occupied target fails FAST — before the whole build runs, never
    # after a binary has already been written (INV-BASE-01 posture; see emit.validate_emit_dir).
    emit_c_dir = Path(emit_c).resolve() if emit_c else None
    if emit_c_dir is not None:
        from . import emit as _emit
        try:
            _emit.validate_emit_dir(emit_c_dir)
        except _emit.EmitError as e:
            raise BuildError(str(e)) from e
    tgt = target if isinstance(target, Target) else Target.parse(target)
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    # The SYSTEM toolchain is only required when it is the one being used. With the default
    # `--cc zig` the compiler is the pinned one haru-pack installs for itself, so demanding
    # `build-essential` here would defeat the entire point of that default — no sudo, no
    # package manager (INV-TOOL-02). This gate used to run unconditionally.
    provider = resolve_cc(cc, target=tgt, log=log)
    if provider == "system":
        tc = detect_c_toolchain(tgt)
        if not tc["ok"]:
            raise BuildError(
                f"C toolchain missing for target '{tgt}':\n{tc['advice']}\n"
                f"Or drop `--cc system` and let haru-pack use its own pinned zig, which "
                f"needs no system packages.")
    else:
        tc = {"ok": True, "compiler": f"zig ({tgt.zig_triple()})", "advice": ""}
    # Phase 4: fold --geo / --geo-restrict / --geo-restrict-api-url / --geo-restrict-consensus
    # into the uniform gate object BEFORE resolve, so enc["geo"] carries the online-gate policy
    # (INV-GATE-01 / INV-GEO-01). {} = no geo gate.
    geo_policy = build_geo_policy(geo, geo_restrict, geo_api_urls, geo_consensus)
    manifest, enc, pyver, source, sources = _resolve(project, tier, python, expires, geo_policy,
                                                     machine, user, embed_secret, encrypt,
                                                     entry_point, log=log)
    # Record the requested engine on the manifest so assemble_payload can apply it. Validated
    # here, at the front of the build, so an unknown engine or a missing pyarmor fails before
    # any work — never after producing a binary the user believes is obfuscated.
    if obfuscate and obfuscate != "none":
        eng = get_engine(obfuscate)          # raises ObfuscationError on an unknown name
        if reason := eng.available():
            raise BuildError(reason)
    manifest["_obfuscation"] = {"engine": obfuscate or "none",
                                "args": list(obfuscate_args)}
    if obfuscate_args and obfuscate in (None, "", "none"):
        raise BuildError("obfuscation arguments were given but no engine was selected; "
                         "pass --obfuscate <engine>")
    # Obfuscation binds the payload to an EXACT Python minor version: pyarmor's runtime .so
    # references version-private symbols, so a payload obfuscated for 3.12 fails to import
    # under 3.11 or 3.13 (measured 2026-09-10). Only the thick tier guarantees the staged
    # interpreter is the one obfuscation targeted; thin/default resolve a Python on the
    # target and may not land on the same minor. haru-pack CAN see this, so it says so
    # (INV-OBF-01).
    if obfuscate and obfuscate != "none" and tier != "thick":
        say = log or (lambda _m: None)
        say(f"WARNING: --obfuscate with tier={tier}. Obfuscation is bound to Python "
            f"{python or '3.13'} EXACTLY, and only --thick bundles that interpreter. On "
            f"thin/default the target may resolve a different Python minor and the binary "
            f"will fail to start with an 'undefined symbol' import error. Use --thick, or "
            f"ensure the target has exactly Python {python or '3.13'}.")
    if enc["enabled"] and secret is None:
        raise BuildError("encryption is configured but no secret — pass "
                         "--secret / --secret-env / --secret-prompt")
    # Canary map + injects are resolved BEFORE any compilation, so a bad token or a reserved
    # inject fails fast (like --shake's preconditions) rather than after producing a payload.
    # The secret-shaped inject WARNING depends on whether the payload will be encrypted, which
    # is known here (INV-INJECT-01). One resolution rule for all five knobs (INV-CANARY-02).
    canary = resolve_canary(env_canary, env_canary_random,
                            per_knob={"secret": stub_env_secret_canary,
                                      "uv_ver": stub_env_uv_ver_canary,
                                      "source_url": stub_env_source_url_canary,
                                      "base_path": stub_env_base_path_canary,
                                      "ephemeral": stub_env_ephemeral_canary}, log=log)
    injects = resolve_injects(env_append, encrypted=enc["enabled"], log=log)
    # Phase-2 staging knobs (docs/adr/0004). base_path is refused at build time if it is a
    # root; reap/ram-only are baked into the cleartext stub-config below (INV-BASE-01 /
    # INV-RAM-01 / INV-REAP-01). HONEST DISCLAIMER, said out loud at build: --ephemeral governs
    # only where the STUB stages the payload tree — haru cannot control the packed app's OWN
    # disk writes, and on Windows/macOS there is no guaranteed RAM filesystem.
    base_path = resolve_base_path(base_path)
    source_url = resolve_source_url(source_url)   # Phase 3 (INV-REMOTE-01); "" = appended delivery
    say = log or (lambda _m: None)
    # --ephemeral implies --reap (docs/adr/0007, INV-EPHEMERAL-02): "ephemeral" means "not
    # permanent", so a RAM/ephemeral stage cleans itself up by default. --no-reap opts out for a
    # restart-heavy service that wants to reuse the staged tree across runs. The coupling happens
    # BEFORE the overwrite check so --ephemeral --overwrite works without a separate --reap.
    if ram_only and not no_reap and not reap:
        reap = True
        say("--ephemeral implies --reap: the staged tree is deleted after the app exits. "
            "Pass --no-reap to keep it (e.g. to reuse a RAM stage across restarts).")
    if no_reap and reap:
        # An explicit --reap and --no-reap together is a contradiction; refuse rather than guess.
        raise BuildError("--reap and --no-reap conflict: pass one. --no-reap only opts out of the "
                         "reap that --ephemeral would otherwise imply.")
    # --overwrite is shred-ON-reap: the reaper is what runs the shred, so overwrite without reap
    # would silently do nothing. Refuse it at build rather than ship a binary that ignores a
    # security flag the packager asked for (INV-SHRED-01).
    if overwrite and not reap:
        raise BuildError("--overwrite is shred-on-reap and needs --reap to run: without --reap "
                         "nothing deletes the stage, so nothing shreds it. Add --reap (or drop "
                         "--no-reap if you passed it with --ephemeral), or drop --overwrite.")
    if enc["geo"].get("allow"):
        gp = enc["geo"]
        say(f"--geo-restrict: online location gate — {len(gp['allow'])} allow-rule(s), "
            f"{len(gp.get('endpoints', [DEFAULT_GEO_ENDPOINT]))} resolver endpoint(s), consensus "
            f"{gp.get('consensus', 1)}. It resolves the caller's IP+geo at runtime and FAILS "
            f"CLOSED if fewer than the consensus resolve or agree — no env var can set or bypass "
            f"it (the old HARUPACK_GEO bypass is gone). HONEST LIMIT: this is an IP check, not a "
            f"presence check — a VPN/proxy whose exit IP is in an allowed location passes. Lives "
            f"inside the encrypted policy, so it needs --encrypt (and a secret).")
    if overwrite:
        say("--overwrite: shred-on-reap. The detached reaper overwrites each staged file with "
            "matching-length random data and fsyncs BEFORE unlinking, so a plaintext blob on disk "
            "resists SIMPLE file-undelete (Recuva/PhotoRec/TestDisk) on a non-CoW filesystem. This "
            "is NOT a secure erase: SSD wear-leveling (LBA != PBA), copy-on-write filesystems, "
            "snapshots/VSS, journals, and swap can all retain the original bytes (THREAT_MODEL.md). "
            "The durable defense is --encrypt + --ephemeral: decrypt only to RAM, nothing to shred.")
    if ram_only:
        say("--ephemeral: best-effort RAM-backed staging (wire key still `ram_only`). Linux stages "
            "under /dev/shm (tmpfs) when available, else falls back to the persistent cache with a "
            "note - truly RAM-only ONLY on Linux. Windows/macOS have no unprivileged RAM disk (no "
            "tmpfs; a RAM disk needs a signed kernel driver + admin), so it is best-effort there. "
            "It governs only where the STUB stages the payload tree - not the packed app's own "
            "disk writes.")
    # --encrypt + --ephemeral is often reached for as "nothing plaintext ever hits disk". It is
    # NOT absolute, and saying so at build time is the same honesty INV-SECRET-02 / INV-BUILD-01
    # require (adversarial review W1). On a low-RAM target the RAM stage FALLS BACK to the
    # persistent cache and the decrypted tree lands on disk. (There is no env value that forces
    # disk — the EPHEMERAL knob only enables RAM — so this is an availability fallback, not an
    # attacker-controlled downgrade.) That fallback is still reaped, but a plain unlink is
    # recoverable; --overwrite shreds it (INV-SHRED-01).
    if ram_only and enc["enabled"]:
        if overwrite:
            say("--encrypt + --ephemeral: on a low-RAM target the decrypted tree can fall back to "
                "disk; --overwrite is set, so that fallback is shredded on reap. Still not a secure "
                "erase (THREAT_MODEL.md).")
        else:
            say("WARNING: --encrypt + --ephemeral is NOT an absolute 'nothing reaches disk'. On a "
                "low-RAM target the decrypted tree FALLS BACK to the persistent cache; that fallback "
                "is reaped but a plain unlink is recoverable. Add --overwrite to shred the fallback, "
                "or accept the residual (THREAT_MODEL.md, docs/adr/0007 §5).")
    if reap:
        say("--reap: after the app exits the stub spawns a detached, fire-and-forget deletion "
            "of the staged subtree it created this run, then exits without waiting. Only that "
            "subtree is removed — never the base path itself.")
    if base_path:
        say(f"--base-path: staging root default baked into the stub-config as {base_path!r}. "
            "A canary-named BASE_PATH env var overrides it at runtime; the launcher refuses a "
            "root/drive/home path defensively.")
    if injects:
        # Lives in the PAYLOAD manifest (post-decrypt), so --encrypt hides it (docs/adr/0003
        # §4). Carried through assemble_payload's manifest dump; the launcher reads `inject`.
        manifest["inject"] = injects
    shake_report: dict = {}
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        try:
            payload_dir = assemble_payload(source, manifest, tier, tgt, pyver, tdp / "asm",
                                           wine, sources=sources, log=log, shake=shake,
                                           shake_keep=shake_keep,
                                           shake_report=shake_report)
        except shake_mod.ShakeError as e:
            # A shake that cannot be PROVEN safe is a failed build, not a smaller one. The
            # alternative — warn and ship the unshaken payload — hands the operator a
            # binary that is nothing like the one they asked for, and they find out from
            # its size or not at all.
            raise BuildError(f"--shake refused to ship: {e}") from e
        # The staged-tree size baked into the stub-config so the launcher can size its RAM-fit
        # check BEFORE staging (docs/adr/0007, INV-EPHEMERAL-01). This is the EXPANDED tree the
        # launcher stages (uv is un-XZ'd on stage), not the compressed payload dir — see
        # _staged_tree_bytes. Only needed when staging may go to RAM.
        unpacked_bytes = _staged_tree_bytes(payload_dir) if ram_only else 0
        payload = build_payload_zip(payload_dir)
        flags = 0
        if enc["enabled"]:
            payload = crypto.encrypt(payload, secret, expires=enc["expires"], geo=enc["geo"],
                                     machine=enc["machine"], user=enc["user"],
                                     embed_secret=enc["embed_secret"])
            flags = FOOTER_FLAG_ENCRYPTED
        # INV-BUILD-01: never report a protection we did not apply. Checked against the
        # bytes about to be attached, not against the intent that produced them.
        if enc["enabled"] != payload.startswith(crypto.MAGIC):
            raise BuildError(
                "internal: encryption state does not match the payload "
                f"(requested={enc['enabled']}, container={payload.startswith(crypto.MAGIC)}). "
                "Refusing to emit a binary whose build receipt would be wrong.")
        launcher = compile_launcher(nim, tgt, tdp, cc=cc, log=log)
        sc_bytes = stub_config_bytes(canary, reap=reap, overwrite=overwrite,
                                     ram_only=ram_only, base_path=base_path,
                                     source_url=source_url, unpacked_bytes=unpacked_bytes)
        # Every NEW binary is v2: it always carries the cleartext, signature-covered
        # stub-config section the launcher reads before decrypt (docs/adr/0003 §1.5).
        if source_url:
            # Phase 3 remote-fetch (INV-REMOTE-01): the payload is NOT embedded. attach records
            # its digest as the trust anchor and sets the remote flag; we write the exact
            # container bytes to a sidecar the packager hosts at source_url. The binary carries
            # only [launcher][stub-config][footer].
            info = attach(launcher, payload, out, flags=flags, stub_config=sc_bytes, remote=True)
            sidecar = out.with_name(out.name + ".haru-payload")
            sidecar.write_bytes(payload)
            info["source_url"] = source_url
            info["payload_sidecar"] = str(sidecar)
            say(f"--source-url: remote-fetch delivery. The binary carries NO payload — host these "
                f"exact bytes at {source_url}:\n  {sidecar}\n  ({len(payload)} bytes, sha256 "
                f"{info['sha256']}). The launcher fetches the URL and refuses any bytes whose "
                f"sha256 is not exactly that digest (INV-REMOTE-01), so a mirror or CDN must "
                f"serve these bytes unchanged.")
        else:
            info = attach(launcher, payload, out, flags=flags, stub_config=sc_bytes)
        if emit_c_dir is not None:
            # Emit the reproduction kit AFTER the binary is written and from the SAME bytes:
            # the C haru just compiled (nimcache in tdp), plus the exact payload + stub-config
            # that were attached, plus the assembler that reproduces this overlay. Footer flags
            # include the remote bit iff this was a remote-fetch build, matching attach.
            #
            # A kit failure here must NOT report an already-successful build as failed — the
            # binary exists and is correct. So an EmitError becomes a loud warning, not a raise
            # (the up-front validate_emit_dir already caught the likely causes before the build).
            from . import emit
            exe_name = "launcher" + tgt.exe_suffix
            try:
                emit.emit_c_sources(tdp / "nimcache", emit_c_dir, tgt.zig_triple(),
                                    exe=exe_name, log=log)
                emit.finish_kit(emit_c_dir, payload=payload, stub_config=sc_bytes,
                                flags=flags | (FOOTER_FLAG_REMOTE if source_url else 0),
                                remote=bool(source_url), exe=exe_name, out_name=out.name,
                                triple=tgt.zig_triple(), encrypted=bool(enc["enabled"]),
                                source_url=source_url)
                info["emit_c"] = str(emit_c_dir)
            except emit.EmitError as e:
                say(f"WARNING: {out} built successfully, but the --emit-c kit is incomplete: "
                    f"{e}")
                info["emit_c_error"] = str(e)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    # The receipt records WHERE this build's third-party bytes came from. An operator
    # auditing a signed artifact should not have to guess whether a mirror was in play.
    info.update(sources=sources.describe(), cc=provider,
                tier=tier, target=str(tgt), nim=nim, compiler=tc["compiler"], out=str(out),
                encrypted=bool(enc["enabled"]), kind=manifest["kind"], python=pyver,
                # The resolved canary map (env-name prefixes) is not secret — recording it aids
                # auditing (INV-CANARY-02). The secret VALUE still lands in no artifact
                # (INV-SECRET-02).
                canary=canary,
                # Phase-2/3 staging knobs (docs/adr/0004 + 0007): not secret, and recording them
                # lets an auditor see whether a binary reaps / stages to RAM / relocates its cache.
                # `reap` here is the EFFECTIVE value after the --ephemeral coupling, so the receipt
                # never claims a cleanup the binary will not do (INV-EPHEMERAL-02, INV-BUILD-01).
                staging={"reap": bool(reap), "overwrite": bool(overwrite),
                         "ram_only": bool(ram_only), "base_path": base_path,
                         "source_url": source_url,
                         "unpacked_bytes": int(unpacked_bytes)},
                obfuscation=manifest.get("obfuscation", {"engine": "none",
                                                         "applied": False}))
    if shake_report:
        info["shake"] = {k: shake_report[k] for k in
                         ("tracer", "dropped_files", "freed_bytes",
                          "payload_bytes_before", "payload_bytes_after")}
        info["shake"]["report"] = str(shake_mod.write_report(shake_report, out))
    # --emit-nim: a reproduction kit alongside the finished binary. The stub is generic, so
    # the kit is its Nim source plus the exact DATA this build attached (payload + stub-config)
    # and a script that recompiles and reassembles them. `flags` and `source_url` are the same
    # values attach() used above (INV-EMIT-01). The binary is ALREADY written and chmod'd, so a
    # kit failure is reported as a distinct kit warning, never as a build failure (W2b).
    if emit_nim:
        try:
            dest = emit_mod.emit_nim_kit(Path(emit_nim), tgt=tgt, provider=provider,
                                         payload=payload, stub_config=sc_bytes, flags=flags,
                                         remote=bool(source_url), out_name=out.name, log=say)
            info["emit_nim"] = str(dest)
        except (emit_mod.EmitError, OSError) as e:
            info["emit_nim_error"] = str(e)
            say(f"WARNING: --emit-nim kit was not written: {e}\nThe packed binary at "
                f"{out} is unaffected and ready to use.")
    return info

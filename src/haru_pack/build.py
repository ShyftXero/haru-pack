from __future__ import annotations
import datetime as _dt
import re as _re
import os, secrets, shutil, string, subprocess, tempfile
from pathlib import Path
from . import tomlio, discovery, crypto
from .paths import launcher_src_dir
from .payload import build_payload_zip
from .overlay import attach
from .bootstrap import find_nim, detect_c_toolchain
from .tiers import apply_tier, bundles_uv
from .sources import Sources
from .targets import Target
from .entrypoints import (resolve_entrypoint, verify_object_ref, verify_script_file,
                          verify_console_script, is_object_ref, EntryPointError)
from .obfuscate import ObfuscationError, get_engine
from .bundle import (bundle_uv, bundle_python, warm_cache_and_lock,
                     warm_cache_windows, run_bundle_step, run_bundle_steps_wine,
                     warm_cache_for_script, install_dev_tools, compress_uv)
from . import shake as shake_mod

class BuildError(RuntimeError): ...

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
# Matches launcher/stubconfig.nim `Knob{kSecret,kUvVer,kSourceUrl,kBasePath}` and its lowercase
# `[canary]` keys — adding a knob is a format change on BOTH halves, on purpose (INV-CANARY-02).
CANARY_KNOBS = ("secret", "uv_ver", "source_url", "base_path")
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


def stub_config_bytes(canary: dict, *, reap: bool = False, ram_only: bool = False,
                      base_path: str = "") -> bytes:
    """The cleartext stub-config TOML section (docs/adr/0003 §2.1 + docs/adr/0004 §2), UTF-8,
    in fixed order. Canary tokens are validated env-name prefixes, so no escaping is needed.

    The Phase-2 keys `reap`/`ram_only`/`base_path` are emitted ONLY when non-default, so a
    build that uses none of them is byte-identical to the Phase-1 stub-config (the v1 corpus
    and its exact-bytes test are unchanged). Their absence is today's behaviour, so no
    stub_config_version bump is needed (docs/adr/0004 §2). Read before decryption by
    launcher/stubconfig.parseStubConfig; sha-checked first (INV-STUB-01)."""
    lines = ["stub_config_version = 1"]
    # Top-level keys must precede the [canary] table (TOML). Emit only when non-default.
    if reap:
        lines.append("reap = true")
    if ram_only:
        lines.append("ram_only = true")
    if base_path:
        lines.append(f"base_path = {_toml_basic_str(base_path)}")
    lines += ["", "[canary]"]
    lines += [f'{knob} = "{canary[knob]}"' for knob in CANARY_KNOBS]
    return ("\n".join(lines) + "\n").encode("utf-8")


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


def compile_launcher(nim: str, target, workdir: Path) -> Path:
    tgt = target if isinstance(target, Target) else Target.parse(target)
    src = launcher_src_dir() / "main.nim"
    if not src.exists():
        raise BuildError(f"launcher source missing: {src}")
    out = workdir / ("launcher" + tgt.exe_suffix)
    args = [nim, "c", "-d:release", f"--nimcache:{workdir/'nimcache'}", f"--out:{out}"]
    args += tgt.nim_flags()          # empty for a native build
    args.append(str(src))
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 or not out.exists():
        raise BuildError("nim compile failed:\n" + (r.stderr or r.stdout)[-2000:])
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
    pyver = python_cli or decl.get("python", "") or disc.get("python", "") or "3.13"
    e = decl.get("encryption", {})
    enc = {
        # INV-BUILD-02: an explicit --encrypt must enable encryption on its own. It was
        # previously dropped here, so `--encrypt --secret X` with no policy flag attached a
        # PLAINTEXT payload and exited 0.
        "enabled": bool(encrypt) or bool(e.get("enabled"))
                   or any([expires, geo, machine, user, embed_secret]),
        "expires": expires or e.get("expires", ""),
        "geo": geo or e.get("geo", []),
        "machine": machine or e.get("machine", ""),
        "user": user or e.get("user", ""),
        "embed_secret": embed_secret or bool(e.get("embed_secret")),
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
          machine: str = "", user: str = "", embed_secret: bool = False,
          obfuscate: str = "none", obfuscate_args=(),
          python: str = "", wine: bool = False, encrypt: bool = False,
          entry_point: str = "", shake: bool = False, shake_keep=(),
          env_canary: str = "", env_canary_random: bool = False,
          stub_env_secret_canary: str = "", stub_env_uv_ver_canary: str = "",
          stub_env_source_url_canary: str = "", stub_env_base_path_canary: str = "",
          reap: bool = False, ram_only: bool = False, base_path: str = "",
          env_append=None, log=None) -> dict:
    project = Path(project); out = Path(out)
    tgt = target if isinstance(target, Target) else Target.parse(target)
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    tc = detect_c_toolchain(tgt)
    if not tc["ok"]:
        raise BuildError(f"C toolchain missing for target '{tgt}':\n{tc['advice']}")
    manifest, enc, pyver, source, sources = _resolve(project, tier, python, expires, geo,
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
    # is known here (INV-INJECT-01). One resolution rule for all four knobs (INV-CANARY-02).
    canary = resolve_canary(env_canary, env_canary_random,
                            per_knob={"secret": stub_env_secret_canary,
                                      "uv_ver": stub_env_uv_ver_canary,
                                      "source_url": stub_env_source_url_canary,
                                      "base_path": stub_env_base_path_canary}, log=log)
    injects = resolve_injects(env_append, encrypted=enc["enabled"], log=log)
    # Phase-2 staging knobs (docs/adr/0004). base_path is refused at build time if it is a
    # root; reap/ram-only are baked into the cleartext stub-config below (INV-BASE-01 /
    # INV-RAM-01 / INV-REAP-01). HONEST DISCLAIMER, said out loud at build: --ram-only governs
    # only where the STUB stages the payload tree — haru cannot control the packed app's OWN
    # disk writes, and on Windows/macOS there is no guaranteed RAM filesystem.
    base_path = resolve_base_path(base_path)
    say = log or (lambda _m: None)
    if ram_only:
        say("--ram-only: best-effort RAM-backed staging. Linux stages under /dev/shm (tmpfs) "
            "when available, else falls back to the persistent cache with a note. Windows/macOS "
            "have no guaranteed RAM filesystem, so this is not guaranteed there. It governs only "
            "where the STUB stages the payload tree — not the packed app's own disk writes.")
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
        payload = build_payload_zip(payload_dir)
        flags = 0
        if enc["enabled"]:
            payload = crypto.encrypt(payload, secret, expires=enc["expires"], geo=enc["geo"],
                                     machine=enc["machine"], user=enc["user"],
                                     embed_secret=enc["embed_secret"])
            flags = 1
        # INV-BUILD-01: never report a protection we did not apply. Checked against the
        # bytes about to be attached, not against the intent that produced them.
        if enc["enabled"] != payload.startswith(crypto.MAGIC):
            raise BuildError(
                "internal: encryption state does not match the payload "
                f"(requested={enc['enabled']}, container={payload.startswith(crypto.MAGIC)}). "
                "Refusing to emit a binary whose build receipt would be wrong.")
        launcher = compile_launcher(nim, tgt, tdp)
        # Every NEW binary is v2: it always carries the cleartext, signature-covered
        # stub-config section the launcher reads before decrypt (docs/adr/0003 §1.5).
        info = attach(launcher, payload, out, flags=flags,
                      stub_config=stub_config_bytes(canary, reap=reap, ram_only=ram_only,
                                                    base_path=base_path))
    try:
        out.chmod(0o755)
    except Exception:
        pass
    # The receipt records WHERE this build's third-party bytes came from. An operator
    # auditing a signed artifact should not have to guess whether a mirror was in play.
    info.update(sources=sources.describe(),
                tier=tier, target=str(tgt), nim=nim, compiler=tc["compiler"], out=str(out),
                encrypted=bool(enc["enabled"]), kind=manifest["kind"], python=pyver,
                # The resolved canary map (env-name prefixes) is not secret — recording it aids
                # auditing (INV-CANARY-02). The secret VALUE still lands in no artifact
                # (INV-SECRET-02).
                canary=canary,
                # Phase-2 staging knobs (docs/adr/0004): not secret, and recording them lets an
                # auditor see whether a binary reaps / stages to RAM / relocates its cache.
                staging={"reap": bool(reap), "ram_only": bool(ram_only),
                         "base_path": base_path},
                obfuscation=manifest.get("obfuscation", {"engine": "none",
                                                         "applied": False}))
    if shake_report:
        info["shake"] = {k: shake_report[k] for k in
                         ("tracer", "dropped_files", "freed_bytes",
                          "payload_bytes_before", "payload_bytes_after")}
        info["shake"]["report"] = str(shake_mod.write_report(shake_report, out))
    return info

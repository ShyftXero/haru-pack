from __future__ import annotations
import datetime as _dt
import re as _re
import shutil, subprocess, tempfile
from pathlib import Path
from . import tomlio, discovery, crypto
from .paths import launcher_src_dir
from .payload import build_payload_zip
from .overlay import attach
from .bootstrap import find_nim, detect_c_toolchain
from .tiers import apply_tier, bundles_uv
from .sources import Sources
from .targets import Target
from .entrypoints import resolve_entrypoint
from .obfuscate import ObfuscationError, get_engine
from .bundle import (bundle_uv, bundle_python, warm_cache_and_lock,
                     warm_cache_windows, run_bundle_step, run_bundle_steps_wine,
                     warm_cache_for_script)

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

def _resolve(project: Path, tier: str, python_cli: str,
             expires, geo, machine, user, embed_secret, encrypt: bool = False,
             entry_point: str = ""):
    """Discover + merge haru_pack.toml + CLI. Returns (manifest, enc, python_version)."""
    # The declaration is read FIRST. Discovery only has to succeed when nothing else says
    # what to run: refusing to guess (INV-BUILD-03) must never become refusing to obey.
    # This ordering was backwards, and the symptom was absurd — a project with an explicit
    # `entrypoint` in haru_pack.toml was rejected with advice telling the operator to set
    # `entrypoint` in haru_pack.toml.
    decl_dir = project if project.is_dir() else project.parent
    decl = {}
    p = decl_dir / "haru_pack.toml"
    if p.exists():
        decl = tomlio.load(p)
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
                     log=None) -> Path:
    sources = sources or Sources()
    tgt = target if isinstance(target, Target) else Target.parse(target)
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
        bundle_uv(tgt, vendor, sources=sources)
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
                    for step in steps:
                        run_bundle_step(step, payload, tmp_env, app_dir)
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
          entry_point: str = "", log=None) -> dict:
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
                                                     entry_point)
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
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        payload_dir = assemble_payload(source, manifest, tier, tgt, pyver, tdp / "asm",
                                       wine, sources=sources, log=log)
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
        info = attach(launcher, payload, out, flags=flags)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    # The receipt records WHERE this build's third-party bytes came from. An operator
    # auditing a signed artifact should not have to guess whether a mirror was in play.
    info.update(sources=sources.describe(),
                tier=tier, target=str(tgt), nim=nim, compiler=tc["compiler"], out=str(out),
                encrypted=bool(enc["enabled"]), kind=manifest["kind"], python=pyver,
                obfuscation=manifest.get("obfuscation", {"engine": "none",
                                                         "applied": False}))
    return info

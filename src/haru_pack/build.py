from __future__ import annotations
import shutil, subprocess, tempfile
from pathlib import Path
from . import tomlio, discovery, crypto
from .paths import launcher_src_dir, exe_suffix
from .payload import build_payload_zip
from .overlay import attach
from .bootstrap import find_nim, detect_c_toolchain
from .tiers import apply_tier
from .bundle import (bundle_uv, bundle_python, warm_cache_and_lock,
                     warm_cache_windows, run_bundle_step, run_bundle_steps_wine)

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

def compile_launcher(nim: str, target: str, workdir: Path) -> Path:
    src = launcher_src_dir() / "main.nim"
    if not src.exists():
        raise BuildError(f"launcher source missing: {src}")
    out = workdir / ("launcher" + exe_suffix(target))
    args = [nim, "c", "-d:release", f"--nimcache:{workdir/'nimcache'}", f"--out:{out}"]
    if target == "windows":
        args += ["-d:mingw", "--cpu:amd64"]
    args.append(str(src))
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 or not out.exists():
        raise BuildError("nim compile failed:\n" + (r.stderr or r.stdout)[-2000:])
    return out

def _resolve(project: Path, tier: str, python_cli: str,
             expires, geo, machine, user, embed_secret, encrypt: bool = False):
    """Discover + merge haru_pack.toml + CLI. Returns (manifest, enc, python_version)."""
    disc = discovery.discover(project)
    decl_dir = project if project.is_dir() else project.parent
    decl = {}
    p = decl_dir / "haru_pack.toml"
    if p.exists():
        decl = tomlio.load(p)
    ep = decl.get("entrypoint", disc["entrypoint"])
    if isinstance(ep, str):
        ep = [ep]
    manifest = {
        "name": decl.get("name", disc["name"]),
        "kind": decl.get("kind", disc["kind"]),
        "app_subdir": decl.get("app_subdir", disc["app_subdir"]),
        "entrypoint": ep,
        "cwd_policy": decl.get("cwd_policy", "launch"),
        "verbose_uv": decl.get("verbose_uv", False),
    }
    for k in ("bundle", "pre_install", "post_install", "uv_run_args"):
        if k in decl:
            manifest[k] = decl[k]
    pyver = python_cli or decl.get("python", "") or disc.get("python", "") or "3.12"
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
    return manifest, enc, pyver, disc["source"]

def assemble_payload(source: Path, manifest: dict, tier: str, target: str,
                     python: str, workdir: Path, wine: bool = False) -> Path:
    payload = workdir / "payload"
    app = payload / manifest["app_subdir"]
    if source.is_file():
        app.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, app / source.name)
    else:
        shutil.copytree(source, app, ignore=_IGNORE)
    manifest = apply_tier(dict(manifest), tier)
    vendor = payload / "vendor"
    if tier in ("default", "thick"):
        bundle_uv(target, vendor)
    if tier == "thick":
        steps = manifest.get("bundle") or []
        if steps and target != "host" and not wine:
            raise BuildError(
                f"bundle steps run target-native code and can't be produced for --target "
                f"{target} from here. Re-run with --wine, build --thick on the target OS, or "
                f"fetch by URL.")
        py = bundle_python(target, vendor, version=python)
        if manifest.get("kind") == "project" or steps:
            app_dir = payload / manifest["app_subdir"]
            cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
            if target == "host":
                tmp_env = Path(tempfile.mkdtemp(prefix="haru-warm-"))
                try:
                    warm_cache_and_lock(app_dir, py, cache, tmp_env)
                    for step in steps:
                        run_bundle_step(step, payload, tmp_env, app_dir)
                finally:
                    shutil.rmtree(tmp_env, ignore_errors=True)
            else:
                warm_cache_windows(app_dir, cache, python)
                if steps and wine:
                    run_bundle_steps_wine(steps, payload, py, app_dir)
            manifest["cache_dir"] = "vendor/cache"
    tomlio.dump(manifest, payload / "manifest.toml")
    return payload

def build(project: Path, out: Path, target: str = "host", tier: str = "default",
          secret: bytes | None = None, expires: str = "", geo=None,
          machine: str = "", user: str = "", embed_secret: bool = False,
          python: str = "", wine: bool = False, encrypt: bool = False) -> dict:
    project = Path(project); out = Path(out)
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    tc = detect_c_toolchain(target)
    if not tc["ok"]:
        raise BuildError(f"C toolchain missing for target '{target}':\n{tc['advice']}")
    manifest, enc, pyver, source = _resolve(project, tier, python, expires, geo,
                                            machine, user, embed_secret, encrypt)
    if enc["enabled"] and secret is None:
        raise BuildError("encryption is configured but no secret — pass "
                         "--secret / --secret-env / --secret-prompt")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        payload_dir = assemble_payload(source, manifest, tier, target, pyver, tdp / "asm", wine)
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
        launcher = compile_launcher(nim, target, tdp)
        info = attach(launcher, payload, out, flags=flags)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    info.update(tier=tier, target=target, nim=nim, compiler=tc["compiler"], out=str(out),
                encrypted=bool(enc["enabled"]), kind=manifest["kind"], python=pyver)
    return info

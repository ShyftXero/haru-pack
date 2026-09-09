from __future__ import annotations
import shutil, subprocess, tempfile
from pathlib import Path
from .paths import launcher_src_dir, exe_suffix
from .payload import build_payload_zip
from .overlay import attach
from .bootstrap import find_nim, detect_c_toolchain
from .tiers import apply_tier
import shutil as _sh, tempfile as _tf
from . import tomlio
from .bundle import bundle_uv, bundle_python, warm_cache_and_lock, warm_cache_windows, run_bundle_step
from . import crypto

class BuildError(RuntimeError): ...

def compile_launcher(nim: str, target: str, workdir: Path) -> Path:
    """Compile the bundled Nim launcher. nimcache + output go to a temp dir so this
    works even when the source is read-only (pip site-packages)."""
    src = launcher_src_dir() / "main.nim"
    if not src.exists():
        raise BuildError(f"launcher source missing: {src}")
    out = workdir / ("launcher" + exe_suffix(target))
    nimcache = workdir / "nimcache"
    args = [nim, "c", "-d:release", f"--nimcache:{nimcache}", f"--out:{out}"]
    if target == "windows":
        args += ["-d:mingw", "--cpu:amd64"]
    args.append(str(src))
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0 or not out.exists():
        raise BuildError("nim compile failed:\n" + (r.stderr or r.stdout)[-2000:])
    return out

def assemble_payload(project_dir: Path, tier: str, target: str, workdir: Path, python: str = "3.12") -> Path:
    """Copy the project, augment its manifest for the tier, and bundle binaries."""
    payload = workdir / "payload"
    shutil.copytree(project_dir, payload)
    mf = payload / "manifest.toml"
    manifest = apply_tier(tomlio.load(mf), tier)
    vendor = payload / "vendor"
    if tier in ("default", "thick"):
        bundle_uv(target, vendor)
    if tier == "thick":
        steps = manifest.get("bundle") or []
        if steps and target != "host":
            raise BuildError(
                "bundle steps run target-native code and can't be produced for "
                f"--target {target} from here. Build --thick on the target OS, run them "
                "under wine, or fetch the artifacts by URL.")
        py = bundle_python(target, vendor, version=python)  # launcher rediscovers at runtime
        if manifest.get("kind") == "project" or steps:
            app_dir = payload / manifest.get("app_subdir", "app")
            cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
            if target == "host":
                tmp_env = Path(_tf.mkdtemp(prefix="haru-warm-"))   # throwaway, NOT shipped
                try:
                    warm_cache_and_lock(app_dir, py, cache, tmp_env)
                    for step in steps:
                        run_bundle_step(step, payload, tmp_env, app_dir)
                finally:
                    _sh.rmtree(tmp_env, ignore_errors=True)
            else:
                warm_cache_windows(app_dir, cache, python)   # cross: download win wheels
            manifest["cache_dir"] = "vendor/cache"
    tomlio.dump(manifest, mf)
    return payload

def build(project_dir: Path, out: Path, target: str = "host", tier: str = "default",
          secret: bytes | None = None, expires: str = "", geo=None,
          machine: str = "", user: str = "", embed_secret: bool = False,
          python: str = "") -> dict:
    project_dir = Path(project_dir); out = Path(out)
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    tc = detect_c_toolchain(target)
    if not tc["ok"]:
        raise BuildError("C toolchain missing for target '%s':\n%s" % (target, tc["advice"]))
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        payload_dir = assemble_payload(project_dir, tier, target, tdp / "asm", python or "3.12")
        payload = build_payload_zip(payload_dir)
        flags = 0
        if secret is not None:
            payload = crypto.encrypt(payload, secret, expires=expires, geo=geo,
                                     machine=machine, user=user, embed_secret=embed_secret)
            flags = 1
        launcher = compile_launcher(nim, target, tdp)
        info = attach(launcher, payload, out, flags=flags)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    info.update(tier=tier, target=target, nim=nim, compiler=tc["compiler"], out=str(out), encrypted=bool(secret))
    return info

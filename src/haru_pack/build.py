from __future__ import annotations
import json, shutil, subprocess, tempfile
from pathlib import Path
from .paths import launcher_src_dir, exe_suffix
from .payload import build_payload_zip
from .overlay import attach
from .bootstrap import find_nim, detect_c_toolchain
from .tiers import apply_tier
import shutil as _sh, tempfile as _tf
from .bundle import bundle_uv, bundle_python, warm_cache_and_lock, install_browsers

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

def assemble_payload(project_dir: Path, tier: str, target: str, workdir: Path) -> Path:
    """Copy the project, augment its manifest for the tier, and bundle binaries."""
    payload = workdir / "payload"
    shutil.copytree(project_dir, payload)
    mf = payload / "manifest.json"
    manifest = apply_tier(json.loads(mf.read_text()), tier)
    vendor = payload / "vendor"
    if tier in ("default", "thick"):
        bundle_uv(target, vendor)
    if tier == "thick":
        py = bundle_python(target, vendor)  # launcher rediscovers interpreter at runtime
        browsers = manifest.get("bundle_browsers") or []
        if browsers:
            app_dir = payload / manifest.get("app_subdir", "app")
            cache = vendor / "cache"; cache.mkdir(parents=True, exist_ok=True)
            tmp_env = Path(_tf.mkdtemp(prefix="haru-warm-"))   # throwaway, NOT shipped
            try:
                warm_cache_and_lock(app_dir, py, cache, tmp_env)
                install_browsers(tmp_env, browsers, vendor / "ms-playwright")
            finally:
                _sh.rmtree(tmp_env, ignore_errors=True)
            manifest["cache_dir"] = "vendor/cache"
            manifest["browsers_path"] = "vendor/ms-playwright"
    mf.write_text(json.dumps(manifest, indent=2))
    return payload

def build(project_dir: Path, out: Path, target: str = "host", tier: str = "default") -> dict:
    project_dir = Path(project_dir); out = Path(out)
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    tc = detect_c_toolchain(target)
    if not tc["ok"]:
        raise BuildError("C toolchain missing for target '%s':\n%s" % (target, tc["advice"]))
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        payload_dir = assemble_payload(project_dir, tier, target, tdp / "asm")
        payload = build_payload_zip(payload_dir)
        launcher = compile_launcher(nim, target, tdp)
        info = attach(launcher, payload, out)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    info.update(tier=tier, target=target, nim=nim, compiler=tc["compiler"], out=str(out))
    return info

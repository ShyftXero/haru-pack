from __future__ import annotations
import subprocess, tempfile
from pathlib import Path
from .paths import launcher_src_dir, exe_suffix
from .payload import build_payload_zip
from .overlay import attach
from .bootstrap import find_nim, detect_c_toolchain

class BuildError(RuntimeError): ...

def compile_launcher(nim: str, target: str, workdir: Path) -> Path:
    """Compile the bundled Nim launcher to a native binary. nimcache + output go to
    a temp dir so this works even when the source is read-only (pip site-packages)."""
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

def build(project_dir: Path, out: Path, target: str = "host") -> dict:
    project_dir = Path(project_dir); out = Path(out)
    nim = find_nim()
    if not nim:
        raise BuildError("Nim not found. Run `haru-pack bootstrap` first.")
    tc = detect_c_toolchain(target)
    if not tc["ok"]:
        raise BuildError("C toolchain missing for target '%s':\n%s" % (target, tc["advice"]))
    payload = build_payload_zip(project_dir)
    with tempfile.TemporaryDirectory() as td:
        launcher = compile_launcher(nim, target, Path(td))
        info = attach(launcher, payload, out)
    try:
        out.chmod(0o755)
    except Exception:
        pass
    info.update(target=target, nim=nim, compiler=tc["compiler"], out=str(out))
    return info

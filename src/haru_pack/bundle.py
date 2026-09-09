from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile, urllib.request, zipfile
from pathlib import Path
from .archives import safe_extract_tar

UV_VERSION = "0.10.4"

def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(map(str, cmd))}\n" + (r.stderr or r.stdout)[-1500:])
    return r

def _export_reqs(app_dir: Path) -> list:
    """Locked requirements for a project, minus uv export's ANSI-colored comment lines."""
    env = dict(os.environ, NO_COLOR="1")
    exp = _run(["uv", "export", "--project", str(app_dir), "--no-hashes", "--no-header",
                "--format", "requirements-txt"], env=env).stdout
    return [l.strip() for l in exp.splitlines()
            if l.strip() and not l.strip().startswith(("#", "-e", "-r", "-c"))]

_UV_ASSET = {
    "windows": "uv-x86_64-pc-windows-msvc.zip",
    "linux":   "uv-x86_64-unknown-linux-gnu.tar.gz",
    "darwin":  "uv-x86_64-apple-darwin.tar.gz",
}

def _host_os() -> str:
    if sys.platform == "win32": return "windows"
    if sys.platform == "darwin": return "darwin"
    return "linux"

def _target_os(target: str) -> str:
    return _host_os() if target == "host" else target  # target is "windows" for cross

def _extract_find(archive: Path, name: str, dest: Path) -> None:
    with tempfile.TemporaryDirectory() as td:
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as z: z.extractall(td)
        else:
            safe_extract_tar(archive, td)          # INV-SUPPLY-03
        for root, _, files in os.walk(td):
            if name in files:
                shutil.move(os.path.join(root, name), dest)
                return
    raise RuntimeError(f"{name} not found inside {archive.name}")

def bundle_uv(target: str, vendor_dir: Path, version: str = UV_VERSION) -> Path:
    """Place a uv binary for the target OS into vendor_dir. Host: copy local uv if present,
    else download; cross: download the target-OS release."""
    vendor_dir.mkdir(parents=True, exist_ok=True)
    tos = _target_os(target)
    exe = "uv.exe" if tos == "windows" else "uv"
    dest = vendor_dir / exe
    if target == "host":
        local = shutil.which("uv")
        if local:
            shutil.copy2(local, dest)
            if tos != "windows": dest.chmod(0o755)
            return dest
    url = f"https://github.com/astral-sh/uv/releases/download/{version}/{_UV_ASSET[tos]}"
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / _UV_ASSET[tos]
        urllib.request.urlretrieve(url, arc)
        _extract_find(arc, exe, dest)
    if tos != "windows": dest.chmod(0o755)
    return dest

def _find_python_url(target_os: str, version: str) -> str:
    """Use uv's python-build-standalone catalog to find a download URL for another OS."""
    out = subprocess.run(["uv", "python", "list", "--all-platforms", "--all-versions",
                          "--output-format", "json"], capture_output=True, text=True, check=True)
    best = None
    for e in json.loads(out.stdout):
        if e.get("os") != target_os or e.get("arch") != "x86_64": continue
        if e.get("implementation") != "cpython" or e.get("variant") != "default": continue
        if not e.get("version", "").startswith(version): continue
        url = e.get("url") or ""
        if "install_only" not in url: continue
        if best is None or e["version"] > best[0]:
            best = (e["version"], url)
    if not best:
        raise RuntimeError(f"no python-build-standalone {version} for {target_os}/x86_64")
    return best[1]

def bundle_python(target: str, vendor_dir: Path, version: str = "3.12") -> Path:
    """thick: stage a standalone Python into vendor/python. host: uv python install.
    cross (windows): download python-build-standalone (install_only, relocatable)."""
    pydir = vendor_dir / "python"
    pydir.mkdir(parents=True, exist_ok=True)
    if target == "host":
        env = dict(os.environ, UV_PYTHON_INSTALL_DIR=str(pydir))
        subprocess.run(["uv", "python", "install", version], env=env, check=True,
                       capture_output=True, text=True)
    else:
        target_os = _target_os(target)  # "windows"
        url = _find_python_url(target_os, version)
        with tempfile.TemporaryDirectory() as td:
            arc = Path(td) / "py.tar.gz"
            urllib.request.urlretrieve(url, arc)
            # install_only extracts to pydir/python/...
            safe_extract_tar(arc, pydir)               # INV-SUPPLY-03
    exe = "python.exe" if _target_os(target) == "windows" else "python3"
    cands = [c for c in {c.resolve() for c in pydir.rglob(exe)}
             if c.is_file() and "venv" not in (q.lower() for q in c.parts)]
    if not cands:
        raise RuntimeError("staged Python interpreter not found")
    return min(cands, key=lambda c: len(c.parts))   # top-level interpreter, not a template


def warm_cache_and_lock(app_dir: Path, py: Path, cache_dir: Path, tmp_env: Path) -> None:
    """Populate a bundled uv cache with the project's deps (+ write uv.lock) using a
    THROWAWAY env outside the payload, so the runtime can build its venv offline."""
    env = dict(os.environ, UV_CACHE_DIR=str(cache_dir), UV_PYTHON=str(py),
               UV_PYTHON_DOWNLOADS="never", UV_PROJECT_ENVIRONMENT=str(tmp_env))
    subprocess.run(["uv", "sync", "--project", str(app_dir)], env=env, check=True,
                   capture_output=True, text=True)


def run_bundle_step(step: dict, payload: Path, tmp_env: Path, app_dir: Path) -> None:
    """Run a declared build-time bundle step in the project's throwaway env. {into} in the
    step env expands to the absolute bundle dir; whatever the command writes there ships."""
    into_rel = step.get("into", "")
    into_abs = (payload / into_rel) if into_rel else payload
    into_abs.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    bindir = tmp_env / ("Scripts" if sys.platform == "win32" else "bin")
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    for k, v in (step.get("env") or {}).items():
        env[k] = v.replace("{into}", str(into_abs))
    subprocess.run(step["run"], env=env, cwd=str(app_dir), check=True,
                   capture_output=True, text=True)


def warm_cache_windows(app_dir: Path, cache_dir: Path, version: str) -> None:
    """Cross: lock (host) then download WINDOWS wheels into the bundled uv cache so the
    venv builds offline at first run on Windows. Wheel-only (no target execution)."""
    _run(["uv", "lock", "--project", str(app_dir)])
    reqs = _export_reqs(app_dir)
    if not reqs:
        return
    with tempfile.TemporaryDirectory() as td:
        rf = Path(td) / "r.txt"; rf.write_text("\n".join(reqs))
        env = dict(os.environ, UV_CACHE_DIR=str(cache_dir))
        _run(["uv", "pip", "install", "--python-platform", "windows",
              "--python-version", version, "--only-binary", ":all:",
              "--target", str(Path(td) / "t"), "-r", str(rf)], env=env)


def run_bundle_steps_wine(steps: list, payload: Path, win_python: Path, app_dir: Path) -> None:
    """Run execute-required bundle steps for a Windows target UNDER WINE on Linux, using the
    bundled Windows Python. Produces Windows-native artifacts (e.g. Windows Firefox)."""
    wine = shutil.which("wine")
    if not wine:
        raise RuntimeError("--wine given but `wine` is not installed on the build host")
    prefix = Path(tempfile.mkdtemp(prefix="haru-wine-"))
    base = dict(os.environ, WINEPREFIX=str(prefix), WINEDEBUG="-all",
                NO_COLOR="1", FORCE_COLOR="0", CI="1", TERM="dumb")
    try:
        winenv = prefix / "be"
        _run([wine, str(win_python), "-m", "venv", str(winenv)], env=base)
        py = winenv / "Scripts" / "python.exe"
        # install the project's deps into the wine venv so the tools exist
        reqs = _export_reqs(app_dir)
        if reqs:
            rf = prefix / "r.txt"; rf.write_text("\n".join(reqs))
            _run([wine, str(py), "-m", "pip", "install", "-r", str(rf)], env=base)
        for step in steps:
            into_abs = payload / step.get("into", "")
            into_abs.mkdir(parents=True, exist_ok=True)
            env = dict(base)
            for k, v in (step.get("env") or {}).items():
                env[k] = v.replace("{into}", str(into_abs))
            cmd = step["run"]
            exe = py if cmd[0] == "python" else winenv / "Scripts" / (cmd[0] + ".exe")
            _run([wine, str(exe), *cmd[1:]], env=env)
    finally:
        shutil.rmtree(prefix, ignore_errors=True)

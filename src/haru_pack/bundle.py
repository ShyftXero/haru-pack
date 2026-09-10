from __future__ import annotations
import json, os, platform, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path
from .archives import safe_extract_tar, fetch_verified, UnpinnedArtifact
from .sources import Sources

UV_VERSION = "0.10.4"

# INV-SUPPLY-01. sha256 per uv release asset, keyed by uv version then asset name.
# Captured 2026-09-09 from the release's published `<asset>.sha256` sidecars and
# cross-checked against the release API's per-asset `digest` field; the two channels
# agreed on all three assets. A version with no table entry has no pin, and
# `bundle_uv` refuses rather than downloading an unverified uv.
UV_SHA256 = {
    "0.10.4": {
        "uv-x86_64-pc-windows-msvc.zip":
            "0f0e22d7507633bfb38d9b42fb6a0341f1f74b8e80b070a31231c354812432a3",
        "uv-x86_64-unknown-linux-gnu.tar.gz":
            "6b52a47358deea1c5e173278bf46b2b489747a59ae31f2a4362ed5c6c1c269f7",
        "uv-x86_64-apple-darwin.tar.gz":
            "df6dd1c3ebeab4369a098c516c15c233c62bf789a40a4864b30dad1d38d7604e",
    },
}

# INV-SUPPLY-01. python-build-standalone interpreters, keyed by the *exact* URL uv's
# catalog hands us (percent-encoding included). This one matters most: the staged
# interpreter is copied into a customer deliverable that the operator then signs, so a
# tampered archive here is code execution under the vendor's identity, EV certificate
# and all.
#
# Note for whoever bumps this: `uv python list --output-format json` does NOT carry a
# digest. Checked against uv 0.10.4 on 2026-09-09 -- the entry keys are exactly
# {arch, implementation, key, libc, os, path, symlink, url, variant, version,
# version_parts}. INVARIANTS.md's claim that a `sha256` field is there to be picked up
# is wrong for this uv. Digests below came from the release instead: the `<asset>.sha256`
# sidecar where one is published (the 20250317 build), and the release API's per-asset
# `digest` field where it is not (the 20260211 build ships no sidecars).
_PBS = "https://github.com/astral-sh/python-build-standalone/releases/download/"
PBS_SHA256 = {
    _PBS + "20260211/cpython-3.12.12%2B20260211-x86_64-pc-windows-msvc-install_only_stripped.tar.gz":
        "93bf8e8c05ede0077b197a29c99ebdaf253497f27190097494265150b4e70ba8",
    _PBS + "20260211/cpython-3.12.12%2B20260211-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz":
        "1dbaa624a09e15afe7efbdac08d42993135a68db8d34f986ef6977a6d77bdc3c",
    _PBS + "20250317/cpython-3.12.9%2B20250317-x86_64-pc-windows-msvc-install_only_stripped.tar.gz":
        "ee338839315bdd8af5fc935f9595eca20ebebdd250726c5816b2d0cf94d1e661",
    _PBS + "20250317/cpython-3.12.9%2B20250317-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz":
        "a36bc60c38fe146e908e2e71fc21266c8558b24a9407226b1d887212839437ef",
    _PBS + "20260211/cpython-3.13.12%2B20260211-x86_64-pc-windows-msvc-install_only_stripped.tar.gz":
        "b73415a86dcf298a2f4a585c5371fb1cf003576d2bdc2b80a34d5321284b2ed4",
    _PBS + "20260211/cpython-3.13.12%2B20260211-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz":
        "bab0e2aeec8a32a7f5cb62240d088d50ea468ef6d7522681bc171d527a5ba6f8",
}

def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(map(str, cmd))}\n" + (r.stderr or r.stdout)[-1500:])
    return r

def _export_reqs(app_dir: Path) -> list:
    """Locked requirements for a project, minus uv export's ANSI-colored comment lines."""
    env = dict(os.environ, NO_COLOR="1")
    # Hashes are KEPT (INV-SUPPLY-08). uv emits them by default; this used to pass
    # --no-hashes and then fed the hashless result to `uv pip install`, discarding
    # integrity data the lockfile already had. The continuation lines of a hashed
    # requirement (`    --hash=sha256:...`) must survive, so only comments and
    # -e/-r/-c directives are dropped and indentation is preserved.
    exp = _run(["uv", "export", "--project", str(app_dir), "--no-header",
                "--format", "requirements-txt"], env=env).stdout
    out = []
    for line in exp.splitlines():
        st = line.strip()
        if not st or st.startswith(("#", "-e ", "-r ", "-c ")):
            continue
        out.append(line.rstrip())
    return out

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

def bundle_uv(target: str, vendor_dir: Path, version: str = UV_VERSION,
              sources: Sources | None = None) -> Path:
    """Place a verified uv binary for the target OS into vendor_dir — ONE path, host or cross.

    The host branch used to `shutil.which("uv")` and copy whatever it found straight into the
    payload, where it gets zipped, shipped and signed. That meant the binary a customer
    executes was whatever happened to be first on the build operator's PATH: no digest, no
    version guarantee, and a trivial supply-chain foothold on a developer workstation
    (INV-SUPPLY-06). It also made host builds non-reproducible — two machines produced
    different payloads from the same commit.

    Everything is downloaded from a pinned, verified source now. `sources` decides *where*
    from; the digest decides *whether we keep it*.
    """
    sources = sources or Sources()
    vendor_dir.mkdir(parents=True, exist_ok=True)
    tos = _target_os(target)
    exe = "uv.exe" if tos == "windows" else "uv"
    dest = vendor_dir / exe
    asset = _UV_ASSET[tos]
    digest = UV_SHA256.get(version, {}).get(asset)
    if not digest:                                                  # INV-SUPPLY-01
        raise UnpinnedArtifact(
            f"no pinned sha256 for uv {version} asset {asset}; haru-pack will not bundle an "
            f"unverified uv. Record the publisher's digest in bundle.UV_SHA256 (the release "
            f"publishes {asset}.sha256) before bumping UV_VERSION.")
    url = sources.uv_url(version, asset)          # mirror-aware; the pin above is not
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / asset
        fetch_verified(url, arc, digest, what=f"uv {version} ({asset})")       # INV-SUPPLY-01
        _extract_find(arc, exe, dest)
    if tos != "windows": dest.chmod(0o755)
    return dest

def _host_arch() -> str:
    m = platform.machine().lower()
    return {"amd64": "x86_64", "x86_64": "x86_64",
            "arm64": "aarch64", "aarch64": "aarch64"}.get(m, m)


def _find_python_url(target_os: str, version: str, arch: str = "x86_64") -> str:
    """Find the UPSTREAM python-build-standalone URL for an (os, arch, version).

    Returns the upstream URL even when a mirror is configured: it is the key the digest is
    pinned under. `Sources.python_url()` rewrites it to the download point afterwards, so a
    mirror can never dodge the pin (INV-SUPPLY-10).

    Note for whoever maintains this: uv's catalog carries no `sha256` field (checked against
    uv 0.10.4), so digests come from the release, not from here.
    """
    out = subprocess.run(["uv", "python", "list", "--all-platforms", "--all-versions",
                          "--output-format", "json"], capture_output=True, text=True, check=True)
    best = None
    for e in json.loads(out.stdout):
        if e.get("os") != target_os or e.get("arch") != arch: continue
        if e.get("implementation") != "cpython" or e.get("variant") != "default": continue
        if not e.get("version", "").startswith(version): continue
        url = e.get("url") or ""
        if "install_only" not in url: continue
        if best is None or e["version"] > best[0]:
            best = (e["version"], url)
    if not best:
        raise RuntimeError(
            f"no python-build-standalone {version} for {target_os}/{arch} in uv's catalog. "
            f"`uv python list --all-platforms --all-versions` shows what is available.")
    return best[1]

def bundle_python(target: str, vendor_dir: Path, version: str = "3.12",
                  sources: Sources | None = None) -> Path:
    """Stage a standalone Python into vendor/python — ONE path for host and cross.

    This used to fork: cross downloaded and verified the archive, while `host` — the DEFAULT
    — shelled out to `uv python install` with the operator's whole environment forwarded, so
    the interpreter that ends up inside a signed customer binary was fetched by a subprocess
    haru-pack never inspected. Two code paths meant one of them was unverified, and it was
    the one almost everybody uses (INV-SUPPLY-07).

    Now both go through the same three steps: resolve the upstream URL, look the pinned
    digest up by that URL, download it (from a mirror if one is configured) and verify.
    """
    sources = sources or Sources()
    pydir = vendor_dir / "python"
    pydir.mkdir(parents=True, exist_ok=True)
    target_os = _target_os(target)
    arch = _host_arch() if target == "host" else "x86_64"

    upstream = _find_python_url(target_os, version, arch)
    digest = PBS_SHA256.get(upstream)
    if not digest:                                                  # INV-SUPPLY-01
        raise UnpinnedArtifact(
            f"no pinned sha256 for {upstream}; haru-pack will not stage an unverified "
            "interpreter into a binary you are about to sign. Record the digest in "
            "bundle.PBS_SHA256 (the python-build-standalone release publishes a "
            "<asset>.sha256 sidecar, and the release API carries a per-asset digest). "
            "Do not remove this check, and do not invent a digest to satisfy it.")
    url = sources.python_url(upstream)                              # mirror, pin unchanged
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / "py.tar.gz"
        fetch_verified(url, arc, digest,
                       what=f"python-build-standalone {version} ({target_os}/{arch})")
        safe_extract_tar(arc, pydir)                   # INV-SUPPLY-03
    exe = "python.exe" if _target_os(target) == "windows" else "python3"
    cands = [c for c in {c.resolve() for c in pydir.rglob(exe)}
             if c.is_file() and "venv" not in (q.lower() for q in c.parts)]
    if not cands:
        raise RuntimeError("staged Python interpreter not found")
    return min(cands, key=lambda c: len(c.parts))   # top-level interpreter, not a template


def warm_cache_and_lock(app_dir: Path, py: Path, cache_dir: Path, tmp_env: Path,
                        sources: Sources | None = None) -> None:
    """Populate a bundled uv cache with the project's deps (+ write uv.lock) using a
    THROWAWAY env outside the payload, so the runtime can build its venv offline."""
    env = dict(os.environ, UV_CACHE_DIR=str(cache_dir), UV_PYTHON=str(py),
               UV_PYTHON_DOWNLOADS="never", UV_PROJECT_ENVIRONMENT=str(tmp_env))
    # `uv sync` resolves from uv.lock, which carries per-wheel hashes that uv verifies,
    # so this path is hash-checked by uv itself (INV-SUPPLY-08).
    subprocess.run(["uv", "sync", "--project", str(app_dir),
                    *(sources or Sources()).uv_index_args()],
                   env=env, check=True, capture_output=True, text=True)


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


def warm_cache_windows(app_dir: Path, cache_dir: Path, version: str,
                       sources: Sources | None = None) -> None:
    """Cross: lock (host) then download WINDOWS wheels into the bundled uv cache so the
    venv builds offline at first run on Windows. Wheel-only (no target execution)."""
    _run(["uv", "lock", "--project", str(app_dir)])
    reqs = _export_reqs(app_dir)
    if not reqs:
        return
    with tempfile.TemporaryDirectory() as td:
        rf = Path(td) / "r.txt"; rf.write_text("\n".join(reqs))
        env = dict(os.environ, UV_CACHE_DIR=str(cache_dir))
        # --require-hashes (INV-SUPPLY-08): _export_reqs now keeps the lockfile's hashes,
        # so a substituted wheel fails here instead of being cached into the payload.
        _run(["uv", "pip", "install", "--python-platform", "windows",
              "--python-version", version, "--only-binary", ":all:", "--require-hashes",
              *(sources or Sources()).uv_index_args(),
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

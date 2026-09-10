from __future__ import annotations
import platform, shutil, subprocess, sys, tempfile
from pathlib import Path
from .paths import nim_dir
from .archives import safe_extract_tar, fetch_verified, UnpinnedArtifact

NIM_VERSION = "2.2.6"  # pinned; bump deliberately

# INV-SUPPLY-01. sha256 of each published Nim archive for NIM_VERSION, keyed by the
# archive filename. Captured 2026-09-09 from nim-lang.org's own `<archive>.sha256`
# sidecars. Bump these in the same commit as NIM_VERSION: the keys embed the version,
# so a stale table means "no pin", and no pin means install_nim refuses rather than
# trusting TLS alone.
#
# linux_arm64 is deliberately absent. nim-lang.org publishes no aarch64 build for
# 2.2.6 -- both nim-2.2.6-linux_arm64.tar.xz and its .sha256 return 404 -- so there is
# no real digest to record. A fabricated one would be worse than the gap: install_nim
# raises UnpinnedArtifact on that platform and the operator installs Nim via choosenim.
NIM_SHA256 = {
    f"nim-{NIM_VERSION}-linux_x64.tar.xz":
        "38b8407f87d78bd207390051e4c76f38a45d0a26983cb262017c899b56ad8d06",
    f"nim-{NIM_VERSION}_x64.zip":
        "557eed9a9193a3bc812245a997d678fd6dc2c2dec6cfa9ba664a16b310115584",
}

# ---------- Nim ----------
def find_nim() -> str | None:
    """Prefer a managed Nim, then one on PATH."""
    managed = nim_dir() / "bin" / ("nim.exe" if sys.platform == "win32" else "nim")
    if managed.exists():
        return str(managed)
    return shutil.which("nim")

def nim_version(nim: str) -> str | None:
    try:
        out = subprocess.run([nim, "--version"], capture_output=True, text=True, timeout=30)
        return out.stdout.splitlines()[0] if out.returncode == 0 else None
    except Exception:
        return None

def _nim_archive_url() -> tuple[str, str]:
    m = platform.machine().lower()
    if sys.platform.startswith("linux"):
        arch = {"x86_64": "linux_x64", "aarch64": "linux_arm64"}.get(m)
        if not arch:
            raise RuntimeError(f"no prebuilt Nim for linux/{m}; install Nim manually or via choosenim")
        return f"https://nim-lang.org/download/nim-{NIM_VERSION}-{arch}.tar.xz", "tar.xz"
    if sys.platform == "win32":
        return f"https://nim-lang.org/download/nim-{NIM_VERSION}_x64.zip", "zip"
    raise RuntimeError("macOS: install Nim via `brew install nim` or choosenim (https://nim-lang.org/install.html)")

def install_nim(force: bool = False) -> str:
    """Download + extract a pinned Nim into the managed toolchain dir."""
    existing = find_nim()
    if existing and not force:
        return existing
    url, kind = _nim_archive_url()
    name = url.rsplit("/", 1)[-1]
    digest = NIM_SHA256.get(name)
    if not digest:                                                  # INV-SUPPLY-01
        raise UnpinnedArtifact(       # refuse before removing the toolchain we already have
            f"no pinned sha256 for {name}; haru-pack will not install an unverified Nim "
            f"toolchain. Record the publisher's digest in bootstrap.NIM_SHA256 "
            f"(nim-lang.org serves {name}.sha256), or install Nim yourself via choosenim.")
    dest = nim_dir()
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / f"nim.{kind}"
        fetch_verified(url, arc, digest, what=f"Nim {NIM_VERSION} ({name})")   # INV-SUPPLY-01
        extract_to = Path(td) / "x"
        if kind == "tar.xz":
            safe_extract_tar(arc, extract_to)       # INV-SUPPLY-03
        else:
            import zipfile
            with zipfile.ZipFile(arc) as z:
                z.extractall(extract_to)
        inner = next(p for p in extract_to.iterdir() if p.is_dir())
        shutil.move(str(inner), str(dest))
    nim = find_nim()
    if not nim:
        raise RuntimeError("Nim install failed (binary not found after extract)")
    return nim

# INV-SUPPLY-02. The launcher imports these (puppy pulls webby in turn). Pinned to
# exact versions, because `nimble install zippy` resolves to whatever was newest that
# day: nimcrypto is the AES-256-GCM implementation linked into every shipped launcher,
# and unpinned deps mean two builds of the same commit are two different binaries.
# These are the versions this repo builds and tests against; bump deliberately.
NIM_DEPS = {
    "zippy": "0.10.12",
    "puppy": "2.1.2",
    "parsetoml": "0.7.2",
    "nimcrypto": "0.7.3",
}

def nim_dep_specs() -> list:
    """`nimble install` arguments. `pkg@version` is nimble's exact-version syntax."""
    return [f"{pkg}@{ver}" for pkg, ver in NIM_DEPS.items()]

def ensure_nim_deps(nim: str) -> bool:
    """The launcher imports zippy + puppy; make sure nimble has them, at pinned versions."""
    nimble = str(Path(nim).with_name("nimble" + (".exe" if sys.platform == "win32" else "")))
    if not Path(nimble).exists():
        nimble = shutil.which("nimble") or "nimble"
    ok = True
    for spec in nim_dep_specs():                                    # INV-SUPPLY-02
        try:
            r = subprocess.run([nimble, "install", "-y", spec], capture_output=True, text=True, timeout=600)
            ok = ok and r.returncode == 0
        except Exception:
            ok = False
    return ok

# ---------- C toolchain (esp. lin->win cross) ----------
def _distro_mingw_cmd() -> str:
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1); info[k] = v.strip().strip('"')
    except Exception:
        pass
    ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()
    if any(d in ident for d in ("debian", "ubuntu")):
        return "sudo apt install mingw-w64"
    if any(d in ident for d in ("fedora", "rhel", "centos")):
        return "sudo dnf install mingw64-gcc"
    if "arch" in ident:
        return "sudo pacman -S mingw-w64-gcc"
    if any(d in ident for d in ("suse", "opensuse")):
        return "sudo zypper install mingw64-cross-gcc"
    if sys.platform == "darwin":
        return "brew install mingw-w64"
    return "install the 'mingw-w64' cross toolchain from your package manager"

def detect_c_toolchain(target) -> dict:
    """Is there a C compiler that can produce a binary for `target`? Returns {ok, compiler, advice}.

    Cross-compiling is the whole reason this project uses Nim, so a missing toolchain has to
    produce a sentence the operator can act on — the package name for their distro — rather
    than a link error from deep inside a Nim build.
    """
    from .targets import Target, TargetError
    try:
        tgt = target if hasattr(target, "os") else Target.parse(target)
    except TargetError as e:
        return {"ok": False, "compiler": None, "advice": str(e)}

    if tgt.is_host:
        for c in ("cc", "gcc", "clang"):
            p = shutil.which(c)
            if p:
                return {"ok": True, "compiler": p, "advice": ""}
        if sys.platform == "win32":
            return {"ok": False, "compiler": None,
                    "advice": "no C compiler found; run `choosenim` (bundles mingw) or install "
                              "MSVC Build Tools"}
        return {"ok": False, "compiler": None,
                "advice": "no C compiler found; install gcc/clang from your package manager"}

    cc, pkg = tgt.cross_cc()
    if cc is None:
        return {"ok": False, "compiler": None,
                "advice": f"haru-pack has no cross-compiler mapping for {tgt}. Build natively on "
                          f"a {tgt} machine, or add one to targets._CROSS_CC."}
    found = shutil.which(cc)
    if found:
        return {"ok": True, "compiler": found, "advice": ""}
    return {"ok": False, "compiler": None,
            "advice": (f"cross-compiling to {tgt} needs {cc}:\n"
                       f"    {_install_hint(pkg)}\n"
                       f"Alternatively, build natively on a {tgt} machine.")}


def _install_hint(pkg: str) -> str:
    """Best-effort package-manager line for this host. Wrong guesses are cheap; a bare
    package name with no command is not actionable."""
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1); info[k] = v.strip().strip('"')
    except Exception:
        pass
    ident = (info.get("ID", "") + " " + info.get("ID_LIKE", "")).lower()
    if sys.platform == "darwin":
        return f"brew install {pkg}"
    if any(d in ident for d in ("debian", "ubuntu", "raspbian")):
        return f"sudo apt install {pkg}"
    if any(d in ident for d in ("fedora", "rhel", "centos")):
        return f"sudo dnf install {pkg}"
    if "arch" in ident:
        return f"sudo pacman -S {pkg}"
    if any(d in ident for d in ("suse", "opensuse")):
        return f"sudo zypper install {pkg}"
    return f"install '{pkg}' with your package manager"

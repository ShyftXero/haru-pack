from __future__ import annotations
import hashlib, json, os, re, shutil, subprocess, sys, tempfile, zipfile
from pathlib import Path
from .archives import safe_extract_tar, fetch_verified, UnpinnedArtifact
from .sources import Sources
from .targets import Target
from . import pins

UV_VERSION = "0.10.4"

# INV-SUPPLY-01. The digests themselves live in pins.toml — data, hand-editable, each
# entry carrying the publisher channel it came from. They were dict literals here until
# 2026-09-09; a maintainer bumping uv should be editing a table, not Python, and a reader
# auditing what a build trusted should not have to follow code to find out.
#
# Loaded eagerly at import so a missing or malformed pins.toml fails immediately and
# loudly, rather than at the moment of the first download when a fallback would be
# tempting. `tools/add-pin.py` adds entries.
UV_SHA256 = pins.uv_digests()
PBS_SHA256 = pins.python_digests()

def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(map(str, cmd))}\n" + (r.stderr or r.stdout)[-1500:])
    return r

def _export_reqs(app_dir: Path, dev: bool = True) -> list:
    """Locked requirements for a project, minus uv export's ANSI-colored comment lines.

    `dev` says whether the project's dev group is included, and the caller chooses by ONE
    question: do these requirements end up in the payload? `warm_cache_windows` downloads
    them into the bundled cache, so it passes `dev=False` (INV-PAYLOAD-03) — the shipped
    binary runs the entrypoint, never the suite. The wine build env is a build-time
    throwaway, so it keeps the default and a `[[bundle]]` step can reach a dev tool.
    """
    env = dict(os.environ, NO_COLOR="1")
    # Hashes are KEPT (INV-SUPPLY-08). uv emits them by default; this used to pass
    # --no-hashes and then fed the hashless result to `uv pip install`, discarding
    # integrity data the lockfile already had. The continuation lines of a hashed
    # requirement (`    --hash=sha256:...`) must survive, so only comments and
    # -e/-r/-c directives are dropped and indentation is preserved.
    exp = _run(["uv", "export", "--project", str(app_dir), "--no-header",
                *([] if dev else ["--no-dev"]),
                "--format", "requirements-txt"], env=env).stdout
    out = []
    for line in exp.splitlines():
        st = line.strip()
        if not st or st.startswith(("#", "-e ", "-r ", "-c ")):
            continue
        out.append(line.rstrip())
    return out


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
    tgt = target if isinstance(target, Target) else Target.parse(target)
    vendor_dir.mkdir(parents=True, exist_ok=True)
    exe = tgt.uv_exe
    dest = vendor_dir / exe
    asset = tgt.uv_asset()
    digest = UV_SHA256.get(version, {}).get(asset)
    if not digest:                                                  # INV-SUPPLY-01
        raise UnpinnedArtifact(
            f"no pinned sha256 for uv {version} asset {asset}; haru-pack will not bundle an "
            f"unverified uv. Add it with:\n"
            f"    python tools/add-pin.py uv {version} {asset}\n"
            f"which fetches the publisher's digest into src/haru_pack/pins.toml.")
    url = sources.uv_url(version, asset)          # mirror-aware; the pin above is not
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / asset
        fetch_verified(url, arc, digest, what=f"uv {version} ({asset})")       # INV-SUPPLY-01
        _extract_find(arc, exe, dest)
    if tgt.os != "windows": dest.chmod(0o755)
    return dest

XZ_PRESET = 9

def compress_uv(uv_path: Path, version: str = UV_VERSION, preset: int = XZ_PRESET,
                log=None) -> tuple:
    """Replace a staged `uv` with `uv.xz` + `uv.xz.size`; the launcher expands it (INV-PAYLOAD-04).

    `uv` is the largest member of every non-thin payload and the payload zip only has
    DEFLATE. Measured on uv 0.10.4 linux-x86_64 (2026-09-10): 55.59 MB raw, 22.25 MB
    deflated, **14.17 MB** as XZ/LZMA2 — 8.08 MB off the finished binary.

    Two deliberate constraints on the stream, both of which the launcher depends on:

    * **`FORMAT_XZ`, `CHECK_CRC32`, LZMA2 only, no BCJ filter.** The vendored decoder is
      built without `xz_dec_bcj.c` (see `launcher/xz/PROVENANCE.md`). A BCJ filter would
      compress an x86 binary further and the decoder would reject it *on the customer's
      machine*, so the filter chain is spelled out here rather than left to a preset.
    * **The uncompressed size ships beside it.** The launcher decodes in one shot with
      `XZ_SINGLE`, which needs the output size up front and in exchange needs no separate
      64 MB dictionary — the difference between this being fine on a Raspberry Pi and not.

    The result is cached under `paths.cache_dir()`, keyed by the digest of the input plus
    the preset. Compressing at preset 9 takes ~100 s and is a pure function of its input,
    so a second build reuses it. `uv` staged from this is byte-identical to the release —
    that is the property that made this preferable to UPX.
    """
    import lzma
    from .paths import cache_dir
    say = log or (lambda _m: None)
    raw = uv_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    ck = cache_dir() / "uv-xz" / f"{digest}-p{preset}.xz"
    if ck.exists():
        comp = ck.read_bytes()
        say(f"uv: reusing cached xz ({len(comp) / 1e6:.1f} MB)")
    else:
        say(f"uv: compressing {len(raw) / 1e6:.1f} MB with xz preset {preset} "
            f"(once per uv version; cached afterwards)")
        comp = lzma.compress(raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32,
                             filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])
        ck.parent.mkdir(parents=True, exist_ok=True)
        tmp = ck.with_suffix(".part")
        tmp.write_bytes(comp)
        tmp.replace(ck)                      # atomic: two builds may race here
    dest = uv_path.with_name(uv_path.name + ".xz")
    dest.write_bytes(comp)
    dest.with_name(dest.name + ".size").write_text(str(len(raw)), encoding="utf-8")
    uv_path.unlink()
    say(f"uv: {len(raw) / 1e6:.1f} MB -> {len(comp) / 1e6:.1f} MB compressed in the "
        f"payload; the launcher expands it to a byte-identical binary at stage time")
    return len(raw), len(comp), digest


# python-build-standalone is published on GitHub; uv reports whatever mirror it currently
# prefers as the download URL. uv 0.12 moved that to releases.astral.sh; 0.10 used
# github.com. If the pin key tracked uv's mirror choice, every uv upgrade would invalidate
# every python pin. It does not: the pin key is canonicalised to the GitHub release URL — the
# publisher's own, where the digest sidecar and release-API `digest` live — so a mirror is
# just a download point that `Sources.python_url()` rewrites to afterwards (INV-SUPPLY-11).
_PBS_CANON = "https://github.com/astral-sh/python-build-standalone/releases/download"
_PBS_MIRROR_RE = re.compile(
    r"https://[^/]+/(?:github/)?"
    r"(?:astral-sh/)?python-build-standalone/releases/download")


def _canonical_pbs_url(url: str) -> str:
    """Rewrite any python-build-standalone mirror URL to its canonical GitHub form.

    Both `releases.astral.sh/github/python-build-standalone/...` (uv 0.12) and
    `github.com/astral-sh/python-build-standalone/...` (uv 0.10) map to the same GitHub
    release asset, which is the one the publisher's digest describes.
    """
    return _PBS_MIRROR_RE.sub(_PBS_CANON, url, count=1)


def _vt(v: str) -> tuple:
    """(major, minor, patch) for numeric comparison. '3.13.9' < '3.13.14' — lexically it is
    not, which is the bug this replaces."""
    return tuple(int(x) for x in re.findall(r"\d+", v.split("+")[0])[:3])


def _find_python_url(target_os: str, version: str, arch: str = "x86_64") -> str:
    """Find the canonical UPSTREAM python-build-standalone URL for an (os, arch, version).

    Returns the GitHub release URL — the key the digest is pinned under — regardless of which
    mirror uv reports. `Sources.python_url()` rewrites it to the actual download point
    afterwards, so a mirror can never dodge the pin (INV-SUPPLY-10, INV-SUPPLY-11).

    Prefers a version that is ALREADY PINNED for this (os, arch): haru-pack should stage a
    known, verified interpreter, not silently chase whatever patch uv's catalog advanced to
    this week. Only when no pin exists for the requested minor does it fall back to uv's
    newest — and then the pin check refuses it, loudly, which is the signal to run add-pin.

    Note: uv's catalog carries no `sha256` field, so digests come from the release, not here.
    """
    # --all-arches is REQUIRED, not decorative: without it uv lists only x86_64 and armv7,
    # so every aarch64 lookup returns nothing and a Raspberry Pi target looks unsupported.
    out = subprocess.run(["uv", "python", "list", "--all-platforms", "--all-arches",
                          "--all-versions", "--output-format", "json"],
                         capture_output=True, text=True, check=True)
    pinned_urls = set(PBS_SHA256)
    best_pinned = None       # (version_tuple, canonical_url) that has a pin
    best_any = None          # (version_tuple, canonical_url) newest overall, for add-pin
    for e in json.loads(out.stdout):
        if e.get("os") != target_os or e.get("arch") != arch: continue
        if e.get("implementation") != "cpython" or e.get("variant") != "default": continue
        if e.get("libc") not in (None, "none", "gnu", "gnueabihf"): continue   # not musl
        if not e.get("version", "").startswith(version): continue
        url = e.get("url") or ""
        if "install_only" not in url: continue
        canon = _canonical_pbs_url(url)
        vt = _vt(e["version"])
        if best_any is None or vt > best_any[0]:
            best_any = (vt, canon)
        if canon in pinned_urls and (best_pinned is None or vt > best_pinned[0]):
            best_pinned = (vt, canon)
    chosen = best_pinned or best_any
    if not chosen:
        raise RuntimeError(
            f"no python-build-standalone {version} for {target_os}/{arch} in uv's catalog. "
            f"`uv python list --all-platforms --all-versions` shows what is available.")
    return chosen[1]

def bundle_python(target: str, vendor_dir: Path, version: str = "3.13",
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
    tgt = target if isinstance(target, Target) else Target.parse(target)
    pydir = vendor_dir / "python"
    pydir.mkdir(parents=True, exist_ok=True)
    target_os, arch = tgt.os, tgt.arch

    upstream = _find_python_url(target_os, version, arch)
    digest = PBS_SHA256.get(upstream)
    if not digest:                                                  # INV-SUPPLY-01
        raise UnpinnedArtifact(
            f"no pinned sha256 for {upstream}; haru-pack will not stage an unverified "
            "interpreter into a binary you are about to sign. Add it with:\n"
            f"    python tools/add-pin.py python {upstream}\n"
            "which fetches the publisher's digest into src/haru_pack/pins.toml. Do not "
            "remove this check, and do not invent a digest to satisfy it.")
    url = sources.python_url(upstream)                              # mirror, pin unchanged
    with tempfile.TemporaryDirectory() as td:
        arc = Path(td) / "py.tar.gz"
        fetch_verified(url, arc, digest,
                       what=f"python-build-standalone {version} ({target_os}/{arch})")
        safe_extract_tar(arc, pydir)                   # INV-SUPPLY-03
    exe = tgt.python_exe
    cands = [c for c in {c.resolve() for c in pydir.rglob(exe)}
             if c.is_file() and "venv" not in (q.lower() for q in c.parts)]
    if not cands:
        raise RuntimeError("staged Python interpreter not found")
    return min(cands, key=lambda c: len(c.parts))   # top-level interpreter, not a template


def warm_cache_and_lock(app_dir: Path, py: Path, cache_dir: Path, tmp_env: Path,
                        sources: Sources | None = None) -> None:
    """Populate a bundled uv cache with the project's RUNTIME deps (+ write uv.lock) using
    a THROWAWAY env outside the payload, so the runtime can build its venv offline.

    `--no-dev` is load-bearing, not tidiness (INV-PAYLOAD-03). `uv sync` installs the
    *default* dependency groups, and `dev` is one of them, so this call used to warm the
    bundled cache with the project's test and build tooling — pytest, hatchling, pygments,
    trove-classifiers — and every byte of it shipped inside the signed binary. Measured on
    `examples/shake-demo` (2026-09-10): 11 dists and 6.5 MB of wheel trees that no shipped
    binary can reach, because the launcher runs the project's entrypoint, never its suite.

    The environment those tools were incidentally providing is a separate concern: bundle
    steps and `--shake`'s observation run do need them, so `install_dev_tools` puts them
    into `tmp_env` from the BUILD HOST's cache afterwards. Same env contents as before,
    without the payload paying for it.
    """
    env = dict(os.environ, UV_CACHE_DIR=str(cache_dir), UV_PYTHON=str(py),
               UV_PYTHON_DOWNLOADS="never", UV_PROJECT_ENVIRONMENT=str(tmp_env))
    # `uv sync` resolves from uv.lock, which carries per-wheel hashes that uv verifies,
    # so this path is hash-checked by uv itself (INV-SUPPLY-08).
    subprocess.run(["uv", "sync", "--project", str(app_dir), "--no-dev",
                    *(sources or Sources()).uv_index_args()],
                   env=env, check=True, capture_output=True, text=True)


def install_dev_tools(app_dir: Path, tmp_env: Path,
                      sources: Sources | None = None, log=None) -> list:
    """Add the project's dev-group tools to the throwaway build env, NOT to the payload.

    `UV_CACHE_DIR` is deliberately left at the build host's default here. That is the whole
    trick: the tools land in `tmp_env` — where a `[[bundle]]` step or `--shake`'s
    observation run can execute them — while the bundled cache under `vendor/` keeps only
    what the shipped binary can actually import.

    Failure is a warning, not an error. A project with no dev group is the common case, and
    a dev group that will not resolve is a problem for the operator's own tooling, not a
    reason to refuse to build a binary whose runtime dependencies resolved fine. A
    `[[bundle]]` step that needed a missing tool fails loudly on its own.
    """
    say = log or (lambda _m: None)
    base = dict(os.environ, NO_COLOR="1", UV_PYTHON_DOWNLOADS="never")
    exp = subprocess.run(["uv", "export", "--project", str(app_dir), "--only-dev",
                          "--no-hashes", "--no-header", "--no-emit-project",
                          "--format", "requirements-txt"],
                         env=base, capture_output=True, text=True)
    reqs = [ln.strip() for ln in exp.stdout.splitlines()
            if ln.strip() and not ln.strip().startswith(("#", "-"))]
    # No dev group at all is the common case and says nothing worth printing. A dev group
    # that will not even *export* is a different thing and is worth a line, since the next
    # bundle step or shake observation is about to fail for a reason that started here.
    if exp.returncode != 0:
        say("WARNING: could not resolve the project's dev dependency group "
            f"(`uv export --only-dev` exited {exp.returncode}). Build steps and --shake "
            "observation runs will not have its tools:\n" + (exp.stderr or "")[-500:])
        return []
    if not reqs:
        return []
    with tempfile.TemporaryDirectory() as td:
        rf = Path(td) / "dev.txt"
        rf.write_text("\n".join(reqs) + "\n")
        r = subprocess.run(["uv", "pip", "install", "--python", str(py_of(tmp_env)),
                            *(sources or Sources()).uv_index_args(), "-r", str(rf)],
                           env=base, capture_output=True, text=True)
    if r.returncode != 0:
        say(f"WARNING: the dev dependency group did not install into the build env "
            f"({len(reqs)} requirement(s)). A [[bundle]] step or --shake observation that "
            f"needs one of those tools will fail next:\n" + (r.stderr or r.stdout)[-500:])
        return []
    say(f"build env: {len(reqs)} dev tool(s) installed OUTSIDE the payload "
        f"(bundle steps / --shake need them; the shipped binary does not)")
    return reqs


def py_of(env_dir: Path) -> Path:
    """The interpreter inside a venv, whichever layout this platform uses."""
    for c in (env_dir / "bin" / "python", env_dir / "bin" / "python3",
              env_dir / "Scripts" / "python.exe"):
        if c.exists():
            return c
    return env_dir / "bin" / "python"


def warm_cache_for_script(script: Path, py: Path, cache_dir: Path,
                          sources: Sources | None = None) -> None:
    """Stage a PEP 723 script's declared dependencies into the bundled uv cache.

    `uv sync --script` resolves the inline metadata and downloads into UV_CACHE_DIR, which
    ships inside the payload. Without this a `--thick` build of a script with dependencies
    still reaches the network on first run — the tier's whole promise is that it does not.

    The project path has always done this (`warm_cache_and_lock`); scripts were the gap.
    """
    env = dict(os.environ, UV_CACHE_DIR=str(cache_dir), UV_PYTHON=str(py),
               UV_PYTHON_DOWNLOADS="never")
    _run(["uv", "sync", "--script", str(script),
          *(sources or Sources()).uv_index_args()], env=env)


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
    reqs = _export_reqs(app_dir, dev=False)          # INV-PAYLOAD-03
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

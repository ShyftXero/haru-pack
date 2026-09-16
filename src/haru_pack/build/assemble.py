"""Building the payload tree: the app, the vendored uv/interpreter, the warmed cache.

This is the part of a build that produces the BYTES the customer will run, so nearly every
refusal in it is about never shipping something different from what was asked for.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

from pathlib import Path

from .. import tomlio
from ..bundle import UV_SHA256, UV_VERSION, bundle_uv, compress_uv
from ..obfuscate import ObfuscationError, get_engine
from ..sources import Sources
from ..targets import Target
from ..tiers import apply_tier, bundles_uv
from . import thick as thick_mod
from .declare import _entry_relpath
from .errors import BuildError
from .tree import copy_app_tree


def _check_shake_preconditions(shake: bool, tier: str, tgt, manifest: dict) -> None:
    """Refuse an impossible `--shake` BEFORE anything is downloaded.

    Discovering that a shake was impossible after staging a 90 MB interpreter wastes the
    operator's time, and — worse — the tempting fix at that point is to carry on and emit an
    unshaken binary, which is precisely the "asked for small, silently got fat" outcome the
    flag exists to prevent. Refuse early and say what to do instead.
    """
    if not shake:
        return
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


def _apply_obfuscation(manifest: dict, app: Path, python: str, log) -> None:
    """Obfuscation is a source transform, applied to the copied app before anything else
    reads it — cache warming, dependency staging and the zip all see the obfuscated tree.

    It is INDEPENDENT of encryption: you can obfuscate a plaintext-payload binary, encrypt
    an unobfuscated one, do both, or neither. They protect different things (see
    INV-SECRET-02) and are wired on separate axes so neither implies the other.
    """
    obf = manifest.get("_obfuscation")
    if not (obf and obf.get("engine", "none") != "none"):
        manifest.setdefault("obfuscation", {"engine": "none", "applied": False})
        return
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


def _stage_uv(manifest: dict, tier: str, tgt, vendor: Path, sources, log) -> None:
    """Ship uv in the payload, or pin the digest the launcher will check the download against."""
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
        return
    # THIN tier: uv is downloaded on the customer's machine and then executed, so the
    # launcher wants a digest to check it against BEFORE extracting it (INV-SUPPLY-05).
    # `uvfetch.nim` has had that mechanism since 2026-09-09 with its own note saying
    # "Nothing populates `uv_sha256` yet — writing it at build time lives in the Python
    # build/tier code, not here", and it warned on every fetch that it had no pin. This
    # is that. The value is the digest of the release ARCHIVE from pins.toml, which is
    # what uvfetch hashes; it is deliberately NOT the digest of the bundled binary that
    # `compress_uv` records for the other tiers.
    asset = tgt.uv_asset()
    digest = UV_SHA256.get(UV_VERSION, {}).get(asset)
    if not digest:                                              # INV-SUPPLY-01
        raise BuildError(
            f"no pinned sha256 for uv {UV_VERSION} asset {asset}, so a --thin binary "
            f"would fetch and execute an unverified uv on the target. Add it with:\n"
            f"    python tools/add-pin.py uv {UV_VERSION} {asset}")
    manifest["uv_sha256"] = digest
    manifest["uv_version"] = UV_VERSION


def _warn_post_install_at_thick(manifest: dict, tier: str, log) -> None:
    """INV-TIER-02. `post_install` means "fetch/setup on the target, on first run"; thick
    means "download NOTHING, fully offline" and sets UV_OFFLINE=1 in the launcher.

    Those are contradictory, and haru-pack used to accept the combination silently. It
    cannot know whether a given step needs the network — `flask db upgrade` does not,
    `spacy download` does — so it warns rather than refusing, and names the steps.

    Measured 2026-09-09 on the flex hard targets: spacy's documented post_install failed on
    the FIRST run of a thick binary (uv refused the download the tier had disabled), and
    nltk's succeeded with network but failed the offline check. Both are the documented
    advice from scaffold.KNOWN, combined with a tier that forbids it.
    """
    if not (tier == "thick" and manifest.get("post_install")):
        return
    say = log or (lambda _m: None)
    steps = manifest["post_install"]
    say(f"WARNING: {len(steps)} post_install step(s) with --thick. thick sets "
        f"UV_OFFLINE=1, so any step that downloads will FAIL on the target. Move the "
        f"work to a [[bundle]] step (runs at build time, output ships in the payload) "
        f"or use --tier default.")
    for st in steps:
        run = st.get("run") if isinstance(st, dict) else st
        say(f"  post_install: {' '.join(run) if isinstance(run, list) else run}")


def assemble_payload(source: Path, manifest: dict, tier: str, target,
                     python: str, workdir: Path, wine: bool = False,
                     sources: Sources | None = None, eager_deps: bool = False,
                     log=None, shake: bool = False, shake_keep=(),
                     shake_report: dict | None = None, slim: bool = False,
                     slim_report: dict | None = None) -> Path:
    sources = sources or Sources()
    tgt = target if isinstance(target, Target) else Target.parse(target)
    _check_shake_preconditions(shake, tier, tgt, manifest)
    payload = workdir / "payload"
    app = payload / manifest["app_subdir"]
    copy_app_tree(source, app)
    _apply_obfuscation(manifest, app, python, log)

    manifest = apply_tier(dict(manifest), tier)
    vendor = payload / "vendor"
    _stage_uv(manifest, tier, tgt, vendor, sources, log)
    if tier == "thick":
        thick_mod.stage(payload=payload, vendor=vendor, manifest=manifest, source=source,
                        tgt=tgt, python=python, wine=wine, sources=sources, log=log,
                        shake=shake, shake_keep=shake_keep, shake_report=shake_report,
                        workdir=workdir, slim=slim, slim_report=slim_report)
    _warn_post_install_at_thick(manifest, tier, log)

    manifest.pop("script_dependencies", None)   # build-time only; not for the launcher
    manifest.pop("shake_declared", None)        # ditto — the launcher never re-shakes
    tomlio.dump(manifest, payload / "manifest.toml")
    return payload

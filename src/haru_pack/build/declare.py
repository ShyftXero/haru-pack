"""Reading what the project says about itself, and merging it with the CLI.

Precedence, lowest first:

    discovery  <  [tool.haru-pack] in pyproject.toml  <  haru_pack.toml  <  CLI flags

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from pathlib import Path

from .. import discovery, tomlio
from ..entrypoints import (EntryPointError, is_object_ref, resolve_entrypoint,
                           verify_console_script, verify_object_ref, verify_script_file)
from ..sources import Sources
from .errors import BuildError
from .geo import _normalize_geo
from .validate import validate_encryption, validate_manifest



# The interpreter version a build stages when nothing else says otherwise. Named rather than
# repeated as a literal so that scripts/self-build.sh can ASK for it — it used to sed this
# file for a line ending in `or "N.N"`, which would silently build release artifacts against
# the wrong Python if the source moved (adversarial review 2026-09-11). Moved 3.12 -> 3.13
# on 2026-09-10; changing it here changes it everywhere.
DEFAULT_PYTHON = "3.13"



def _declarations(decl_dir: Path) -> dict:
    """Merge the project's build directives from both places it may declare them.

    Precedence, lowest first — the same shape `discovery`'s docstring already described:

        discovery  <  [tool.haru-pack] in pyproject.toml  <  haru_pack.toml  <  CLI flags

    `[tool.haru-pack]` exists because a project that is already a package has one obvious
    home for its own build configuration, and asking for a second file to say "this is how
    I am bundled" is friction for no gain. `haru_pack.toml` stays, wins where both speak,
    and remains what `haru-pack init` writes — it is the sidecar for a tree that has no
    pyproject.toml at all (a bare script, a folder of `.py` files), and the local override
    for one that does.

    The merge is per top-level key, not deep: a `[[bundle]]` list in `haru_pack.toml`
    REPLACES the one in pyproject.toml rather than appending to it. Concatenating would
    mean an operator could not remove an inherited step, only add to it, and "why is this
    build still running a step I deleted" is a bad afternoon.
    """
    merged: dict = {}
    pp = decl_dir / "pyproject.toml"
    if pp.exists():
        tool = (tomlio.load(pp).get("tool") or {})
        if "haru-pack" not in tool and "haru_pack" in tool:
            # Refuse rather than silently ignore. A config table that is read by nobody is
            # worse than a missing one: the operator believes it took effect.
            raise BuildError(
                f"{pp} has a [tool.haru_pack] table; haru-pack reads [tool.haru-pack] "
                f"(hyphen, matching the distribution name). Rename the table — it is "
                f"being ignored, and silently honouring both spellings would mean two "
                f"places to look when a directive does not apply.")
        merged.update(tool.get("haru-pack") or {})
    side = decl_dir / "haru_pack.toml"
    if side.exists():
        merged.update(tomlio.load(side))
    return merged


def _resolve(project: Path, tier: str, python_cli: str,
             expires, geo, machine, user, embed_secret, encrypt: bool = False,
             entry_point: str = "", log=None):
    """Discover + merge haru_pack.toml + CLI. Returns (manifest, enc, python_version)."""
    # The declaration is read FIRST. Discovery only has to succeed when nothing else says
    # what to run: refusing to guess (INV-BUILD-03) must never become refusing to obey.
    # This ordering was backwards, and the symptom was absurd — a project with an explicit
    # `entrypoint` in haru_pack.toml was rejected with advice telling the operator to set
    # `entrypoint` in haru_pack.toml.
    decl_dir = project if project.is_dir() else project.parent
    decl = _declarations(decl_dir)
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
    # A `module:callable` becomes a `python -c "from module import attr"` argv and nothing
    # used to check that the import resolves, so a typo built cleanly, exited 0, and failed
    # on the customer's machine at first run (INV-BUILD-04). Checked statically — parsing
    # the module rather than importing it, so nothing of the project executes on the build
    # host and the check works for cross-compiled targets too. Silent unless it is certain.
    if isinstance(ep, str):
        problem = verify_object_ref(ep, decl_dir) or verify_script_file(ep, decl_dir)
        if problem:
            raise EntryPointError(problem)
        # A bare console-script name cannot be checked for certain without an environment —
        # the launcher runs `uv run <name>`, which also resolves scripts provided by
        # DEPENDENCIES. So say what could not be verified rather than refusing a build that
        # is probably fine; `assemble_payload` upgrades this to a refusal at thick, where
        # there is a real environment to look in.
        if not is_object_ref(ep) and not ep.endswith(".py"):
            level, msg = verify_console_script(ep, decl_dir)
            if level == "warn" and log:
                log(f"WARNING: {msg}")
    ep = resolve_entrypoint(ep, name=decl.get("name", disc["name"]),
                            kind=decl.get("kind", disc["kind"]))
    manifest = {
        "name": decl.get("name", disc["name"]),
        "kind": decl.get("kind", disc["kind"]),
        "app_subdir": decl.get("app_subdir", disc["app_subdir"]),
        "entrypoint": ep,
        "cwd_policy": decl.get("cwd_policy", "launch"),
        "verbose_uv": decl.get("verbose_uv", False),
        # stage-dir retention: the launcher evicts trees unused for keep_days, but never drops
        # the keep_max most recent. keep_days = 0 disables eviction. Defaults mirror the
        # launcher's stage.DefaultKeepDays / DefaultKeepMax (30 / 3).
        "keep_days": int(decl.get("keep_days", 30)),
        "keep_max": int(decl.get("keep_max", 3)),
        # PEP 723 inline dependencies, so the thick tier can stage them (INV-TIER-01).
        "script_dependencies": list(disc.get("dependencies") or []),
        # `[shake]` — how to OBSERVE this project, and what to keep regardless. Carried
        # here (and popped before the manifest is written) for the same reason
        # script_dependencies is: it is build-time input, not something the launcher reads.
        "shake_declared": dict(decl.get("shake") or {}),
        # `writable = [...]` — build-DECLARED app data files that may change on reuse (#4). A
        # haru_pack.toml / [tool.haru-pack] list, merged with the repeatable `--writable` CLI flag
        # in orchestrate.build. Build-time input only (resolved to the stub-config's writable set,
        # never written into the payload manifest the launcher reads); popped in assemble_payload.
        "writable_declared": list(decl.get("writable") or []),
    }
    for k in ("bundle", "pre_install", "post_install", "uv_run_args"):
        if k in decl:
            manifest[k] = decl[k]
    pyver = (python_cli or decl.get("python", "") or disc.get("python", "")
         or DEFAULT_PYTHON)
    e = decl.get("encryption", {})
    # `geo` arrives as the assembled gate object (build_geo_policy) or {}; fall back to a
    # haru_pack.toml `[encryption] geo = [...]` country list, normalized to the same object
    # shape (INV-GEO-01). Resolve it ONCE and use the SAME object for both the enabled test and
    # the policy value — otherwise a geo declared only in TOML sets no enabled bit and is
    # silently dropped (ships plaintext, no gate: the SILENT-WEDGE class, INV-CHAOS-07).
    geo_obj = _normalize_geo(geo) if geo else _normalize_geo(e.get("geo", []))
    exp = expires or e.get("expires", "")
    mach = machine or e.get("machine", "")
    usr = user or e.get("user", "")
    embed = embed_secret or bool(e.get("embed_secret"))
    enc = {
        # INV-BUILD-02: an explicit --encrypt must enable encryption on its own. It was
        # previously dropped here, so `--encrypt --secret X` with no policy flag attached a
        # PLAINTEXT payload and exited 0. Every policy field — from CLI OR haru_pack.toml —
        # forces encryption, so a declared licence/gate can never silently ship unenforced;
        # a missing secret then fails LOUDLY at the `enabled and secret is None` guard below.
        "enabled": bool(encrypt) or bool(e.get("enabled"))
                   or any([exp, geo_obj.get("allow"), mach, usr, embed]),
        "expires": exp,
        "geo": geo_obj,
        "machine": mach,
        "user": usr,
        "embed_secret": embed,
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


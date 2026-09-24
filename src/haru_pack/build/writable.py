"""`--writable`: declaring which BUNDLED app data files may change on reuse (#4).

By default the launcher re-hashes every staged file on every run and refuses any mismatch
(INV-STAGE-01). That is exactly right for code, and exactly wrong for a bundled data file the
app opens read-write — a seed `data/app.db` the app mutates would fail verification on the
second run. `--writable <glob>` lets the packager DECLARE such files: the launcher records them
as `mutable:` (presence/kind checked, bytes deliberately not pinned) instead of by sha256.

The load-bearing safety is the BACKSTOP here, and it fails the BUILD, not the customer: it
REFUSES to declare writable anything importable or executable, because a writable code path is
a same-uid code-execution primitive that would re-cut the exact holes stage.nim's "NOT exempt,
deliberately" comment block documents (a writable `.pyc`/`.so`/`.pth` is code the manifest no
longer pins; site executes a `.pth`'s `import` lines at interpreter startup, so `.pth` is a hard
refuse). The refusal covers, on any target OS:
  * importable/executable EXTENSIONS — Python/native (`.py .pyc .pyo .so .pyd .dll .dylib .zip
    .whl .egg .pth .pyw .pyz`) AND shell/Windows executables (`.sh .bash .bat .cmd .ps1 .com
    .scr .vbs .exe .msi .jar`), since a pre/post-install step or the app can invoke a bundled one;
  * CONTENT magic — a file whose first bytes are a shebang, ELF, PE/`MZ`, or Mach-O, so a renamed
    or extensionless executable cannot slip the name checks (content beats name);
  * the interpreter tree (`vendor/python/**`), the bundled `uv`;
  * the entrypoint and EVERY pre/post-install `run` token (whatever the extension);
  * ANY file that carries the POSIX executable bit.

Globs are resolved against the ASSEMBLED payload tree to the EXACT stage-relative members they
match (the same `rel` the launcher's `recordTree` walks), so the launcher does exact set
membership — no glob engine in the launcher — and the relaxed set that rides the
signature-covered stub-config is a concrete, auditable list.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

from .errors import BuildError

# Importable/executable by EXTENSION — code, or a container of code, that the manifest must keep
# pinned. `.pth` is pure code: `site` executes any line beginning `import` at interpreter startup.
# Beyond the Python/native set, shell + Windows-executable suffixes are here too: a pre/post-install
# step or the app can invoke a bundled `setup.sh`/`.bat`/`.ps1`/`.exe`, so a writable one is the same
# same-uid RCE primitive as a writable `.py` (adversarial review #1/#2).
_CODE_SUFFIXES = frozenset({
    ".py", ".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib",
    ".zip", ".whl", ".egg", ".pth", ".pyw", ".pyz",
    ".sh", ".bash", ".bat", ".cmd", ".ps1", ".com", ".scr", ".vbs", ".exe", ".msi", ".jar",
})
# Importable/executable by BASENAME regardless of extension.
_CODE_NAMES = frozenset({"sitecustomize.py", "usercustomize.py", "uv", "uv.exe"})
# Magic-byte prefixes of executable/script formats — CONTENT beats name, so a renamed or
# extensionless executable (`app/helper` that is really an ELF, or a `#!`-script) cannot slip the
# suffix/name checks (adversarial review #2). Mach-O thin (both endian/width) + fat/Java-class.
_CODE_MAGICS = (
    b"#!",                                   # any shebang script
    b"\x7fELF",                              # ELF
    b"MZ",                                   # PE / DOS (.exe/.dll/.scr/…)
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # Mach-O 32/64 big-endian
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",  # Mach-O 32/64 little-endian
    b"\xca\xfe\xba\xbe",                     # Mach-O universal / Java .class
)


def _entry_targets(manifest: dict) -> set[str]:
    """Stage-relative paths that are the entrypoint or a pre/post-install target.

    EVERY string token of `entrypoint` and of every `pre_install`/`post_install` `run` list is
    added — NOT only `.py` ones. A non-`.py` install target (`run = ["sh", "setup.sh"]`, a
    `.bat`/`.ps1`/`.exe`) is a file the launcher EXECUTES out of the stage, so it must never be
    declarable writable whatever its extension (adversarial review #1). Non-file tokens (`python`,
    `-m`, a `module:callable`) simply match no bundled member and cost nothing."""
    rels: set[str] = set()
    app_subdir = (manifest.get("app_subdir") or "app").strip("/")

    def _add(tok: str) -> None:
        t = tok.replace("\\", "/").lstrip("/")
        rels.add(t)
        if app_subdir and not t.startswith(app_subdir + "/"):
            rels.add(f"{app_subdir}/{t}")

    for tok in manifest.get("entrypoint") or []:
        if isinstance(tok, str):
            _add(tok)
    for key in ("pre_install", "post_install"):
        for step in manifest.get(key) or []:
            run = step.get("run") if isinstance(step, dict) else step
            toks = run if isinstance(run, list) else [run]
            for t in toks:
                if isinstance(t, str):
                    _add(t)
    return rels


def _has_code_magic(path: Path) -> bool:
    """True if the file's first bytes are an executable/script magic (CONTENT, not name)."""
    try:
        head = path.read_bytes()[:4]
    except OSError:
        return False
    return any(head.startswith(m) for m in _CODE_MAGICS)


def _backstop_reason(rel: str, path: Path, entry_rels: set[str]) -> str:
    """Why `rel` may NOT be declared writable, or "" if it may. Fails the BUILD (docs/PRINCIPLES.md:
    every refusal that can be made before a binary exists is made before one exists)."""
    name = rel.rsplit("/", 1)[-1]
    low = name.lower()
    suffix = ("." + low.rsplit(".", 1)[-1]) if "." in low else ""
    if path.is_symlink():
        return "it is a symlink; a declared-writable path must be a regular data file, never a link"
    if low in _CODE_NAMES:
        return f"`{name}` is executable/importable and must stay byte-verified"
    if suffix in _CODE_SUFFIXES:
        why = ("site executes its `import` lines at interpreter startup — it is pure code"
               if suffix == ".pth" else "it is importable/executable code")
        return f"`{suffix}` is a code extension ({why}); a writable code path is a same-uid RCE primitive"
    if rel == "vendor/python" or rel.startswith("vendor/python/"):
        return "it lives under the bundled interpreter tree (vendor/python/**)"
    if rel == "vendor/uv" or rel.startswith("vendor/uv"):
        return "it is the bundled uv (main.findUv executes it)"
    if rel in entry_rels:
        return "it is the build entrypoint or a pre/post-install target"
    if _has_code_magic(path):
        return ("its content is an executable/script (shebang, ELF, PE/MZ, or Mach-O) — a renamed "
                "or extensionless executable is still a same-uid RCE primitive")
    try:
        if path.stat().st_mode & 0o111:
            return "it carries the POSIX executable bit"
    except OSError:
        pass
    return ""


def resolve_writable(payload_dir: Path, cli_globs, manifest: dict, log=None) -> list[str]:
    """Resolve the `--writable` globs (CLI `cli_globs` + a `haru_pack.toml` `writable = [...]`
    carried on `manifest['writable_declared']`) against the assembled `payload_dir` to the EXACT
    stage-relative members they match, applying the build-time backstop. Returns a sorted list (or []).

    Raises `BuildError` naming every path that the backstop refuses. A glob that matches nothing
    is warned about (likely a typo) but is not fatal: an undeclared-because-absent path simply is
    not recorded, and the launcher ignores unrecorded files."""
    globs = [g.strip() for g in [*(cli_globs or []), *(manifest.get("writable_declared") or [])]
             if g and g.strip()]
    if not globs:
        return []
    say = log or (lambda _m: None)
    files = [p for p in sorted(payload_dir.rglob("*")) if p.is_file() or p.is_symlink()]
    rel_of = {p: p.relative_to(payload_dir).as_posix() for p in files}
    matched: dict[str, Path] = {}
    for g in globs:
        gnorm = g.replace("\\", "/").lstrip("/")
        hits = [p for p in files if fnmatch.fnmatchcase(rel_of[p], gnorm)]
        if not hits:
            say(f"WARNING: --writable {g!r} matched no bundled file; it will not be recorded "
                f"(a data file created only at runtime needs no declaration — the launcher "
                f"ignores files it never staged).")
            continue
        for p in hits:
            matched[rel_of[p]] = p
    entry_rels = _entry_targets(manifest)
    offenders = []
    for rel, path in sorted(matched.items()):
        reason = _backstop_reason(rel, path, entry_rels)
        if reason:
            offenders.append(f"  {rel}: {reason}")
    if offenders:
        raise BuildError(
            "--writable refuses to declare these bundled paths writable — a writable code or "
            "interpreter file would let a same-uid attacker rewrite something the launcher no "
            "longer verifies (INV-STAGE-01). Only app DATA files may be declared writable:\n"
            + "\n".join(offenders))
    return sorted(matched)

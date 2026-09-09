"""Generate a commented haru_pack.toml pre-filled from project discovery."""
from __future__ import annotations
import os, re
from pathlib import Path
from . import tomlio

def _dep_name(spec: str) -> str:
    return re.split(r"[<>=!~;\[ ]", spec.strip(), 1)[0].lower()

def project_deps(path: Path, disc: dict) -> list[str]:
    path = Path(path)
    if disc["kind"] == "project":
        pp = path / "pyproject.toml"
        if pp.exists():
            deps = tomlio.load(pp).get("project", {}).get("dependencies", [])
            return [_dep_name(d) for d in deps]
    else:  # PEP 723 script
        src = disc.get("source")
        if src and Path(src).exists():
            m = re.search(r"# /// script\s*(.*?)# ///", Path(src).read_text(), re.S)
            if m:
                body = "\n".join(l[2:] if l.startswith("# ") else l.lstrip("#")
                                 for l in m.group(1).splitlines())
                try:
                    return [_dep_name(d) for d in tomlio._toml.loads(body).get("dependencies", [])]
                except Exception:
                    pass
    return []

def find_venv(path: Path) -> Path | None:
    """Locate a usable venv: $VIRTUAL_ENV, then <project>/.venv, <project>/venv."""
    cands = [Path(path) / ".venv", Path(path) / "venv", os.environ.get("VIRTUAL_ENV")]
    for c in cands:
        if c and (Path(c) / "pyvenv.cfg").exists():
            return Path(c)
    return None

def venv_info(venv: Path) -> tuple[str, list[str]]:
    """Return (python_version, installed_package_names) learned from a venv."""
    ver = ""
    cfg = venv / "pyvenv.cfg"
    for line in cfg.read_text().splitlines() if cfg.exists() else []:
        if line.lower().split("=")[0].strip() in ("version", "version_info"):
            m = re.search(r"(\d+\.\d+)", line); ver = m.group(1) if m else ver
    pkgs = []
    sites = list(venv.glob("lib/python*/site-packages")) + [venv / "Lib" / "site-packages"]
    for sp in sites:
        if sp.exists():
            for d in list(sp.glob("*.dist-info")) + list(sp.glob("*.egg-info")):
                pkgs.append(d.name.split("-")[0].lower().replace("_", "-"))
    return ver, sorted(set(pkgs))

def render(disc: dict, deps: list[str], learned_from_venv: bool = False) -> str:
    ep = disc["entrypoint"]
    ep_toml = '"%s"' % ep[0] if len(ep) == 1 else "[" + ", ".join('"%s"' % x for x in ep) + "]"
    py = disc.get("python") or "3.12"
    L = [
        "# haru_pack.toml — declarations for `haru-pack build`.",
        "# Most fields are auto-discovered; keep only what you want to override.",
        "# Precedence: discovery < this file < CLI flags.",
        ("# (package hints below learned from an available venv)" if learned_from_venv else "#"),
        "",
        f'# name = "{disc["name"]}"            # discovered',
        f'# kind = "{disc["kind"]}"            # discovered (script | project)',
        f"# entrypoint = {ep_toml}   # discovered",
        f'# python = "{py}"              # discovered from requires-python/.python-version',
        "",
        'cwd_policy = "launch"          # "launch" (native cwd) | "exe" (always exe-adjacent)',
        "# verbose_uv = false",
        "",
    ]
    if "playwright" in deps:
        L += [
            "# Detected Playwright — bundle a browser for offline (thick) builds:",
            "[[bundle]]",
            '  run = ["playwright", "install", "firefox"]',
            '  into = "vendor/ms-playwright"',
            "  [bundle.env]",
            '    PLAYWRIGHT_BROWSERS_PATH = "{into}"',
            '    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1"',
            "",
            "# ...or fetch on first run instead (thin/default), per-OS:",
            "# [[post_install]]",
            '# os = ["windows"]',
            '# run = ["playwright", "install", "firefox"]',
            "",
        ]
    if any(d in deps for d in ("spacy", "nltk", "transformers", "torch")):
        L += [
            "# Detected an ML package — it likely needs a model download on first run:",
            "# [[post_install]]",
            '# run = ["python", "-m", "spacy", "download", "en_core_web_sm"]',
            "",
        ]
    if not deps or "playwright" not in deps:
        L += [
            "# Build-time bundling (thick) — bake a command's output into the exe:",
            "# [[bundle]]",
            '# run = ["mytool", "fetch-assets"]',
            '# into = "vendor/assets"',
            "# [bundle.env]",
            '#   MYTOOL_DATA = "{into}"',
            "",
            "# Run-once on the target (thin/default), OS-filtered by the stager:",
            "# [[post_install]]",
            '# os = ["all"]',
            '# run = ["python", "-c", "import mypkg; mypkg.setup()"]',
            "",
        ]
    L += [
        "# Optional encryption + license checks (secret is supplied via CLI/env, never here):",
        "# [encryption]",
        "# enabled = true",
        '# expires = "2027-01-01"',
        '# geo = ["US", "CA"]',
        '# machine = "<machine-id>"   # `haru-pack machine-id` on the target',
        '# user = "alice"',
        "# embed_secret = false",
        "",
    ]
    return "\n".join(L)

"""Generate a commented haru_pack.toml pre-filled from project discovery."""
from __future__ import annotations
import os, re
from pathlib import Path
from . import tomlio


# package -> what extra step it needs beyond `uv pip install`.
KNOWN = {
    "playwright": {
        "kind": "bundle",
        "why": "installs browser binaries separately (playwright install)",
        "bundle": ('[[bundle]]\n'
                   '  run = ["playwright", "install", "firefox"]\n'
                   '  into = "vendor/ms-playwright"\n'
                   '  [bundle.env]\n'
                   '    PLAYWRIGHT_BROWSERS_PATH = "{into}"\n'
                   '    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1"'),
        "post_install": ('[[post_install]]\n'
                         '  run = ["playwright", "install", "firefox"]'),
    },
    "spacy": {"kind": "post_install", "why": "language models are downloaded, not in the wheel",
              "post_install": '[[post_install]]\n  run = ["python", "-m", "spacy", "download", "en_core_web_sm"]'},
    "nltk": {"kind": "post_install", "why": "corpora are downloaded at runtime",
             "post_install": '[[post_install]]\n  run = ["python", "-m", "nltk.downloader", "punkt"]'},
    "transformers": {"kind": "post_install", "why": "model weights download on first use (large)",
                     "post_install": '# pre-fetch your model in a post_install step to stay offline'},
    "torch": {"kind": "note", "why": "large native wheels; pick the right CUDA/CPU index at build"},
    "selenium": {"kind": "note", "why": "Selenium Manager fetches drivers at runtime (needs network)"},
    "tiktoken": {"kind": "post_install", "why": "downloads BPE vocab files on first use",
                 "post_install": '# warm the tiktoken cache in a post_install step'},
    "weasyprint": {"kind": "note", "why": "needs system libs (pango/cairo) — not pip-bundlable"},
}

def detect(deps):
    """Return [{package, kind, why, bundle?, post_install?}] for known packages in deps."""
    out = []
    for d in deps:
        k = KNOWN.get(d)
        if k:
            out.append({"package": d, **k})
    return out

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
    """A project-local venv (<project>/.venv or venv), or $VIRTUAL_ENV only if it lives
    inside the project — never a random ambient venv that isn't this project's."""
    path = Path(path).resolve()
    root = path if path.is_dir() else path.parent
    for c in (root / ".venv", root / "venv"):
        if (c / "pyvenv.cfg").exists():
            return c
    ve = os.environ.get("VIRTUAL_ENV")
    if ve:
        ve = Path(ve).resolve()
        if (ve / "pyvenv.cfg").exists() and (ve == root or root in ve.parents):
            return ve
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
        "# keep_days = 30               # evict stage dirs unused this long; 0 = never",
        "# keep_max = 3                 # always keep this many most-recent stage dirs",
        "",
    ]
    hints = detect(deps)
    for h in hints:
        L.append(f"# Detected {h['package']} — {h['why']}:")
        if h.get("bundle"):
            L += h["bundle"].split("\n")
            L.append("# ...or fetch on first run instead (thin/default): " +
                     h.get("post_install", "").replace(chr(10), " "))
        elif h.get("post_install"):
            L += h["post_install"].split("\n")
        L.append("")
    if not hints:
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

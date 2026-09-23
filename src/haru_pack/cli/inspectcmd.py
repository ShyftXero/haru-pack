"""The small commands: version, verify, init, hostname.

Grouped by size rather than by subject, deliberately. Each is a handful of lines with no
shared state, and four one-screen modules would be four files nobody can tell apart.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from pathlib import Path

import typer

from .. import __version__
from ..overlay import verify as verify_exe
from ..ui import fields, print
from .root import app


@app.command()
def version():
    """Show the haru-pack version."""
    print(f"haru-pack {__version__}")


@app.command()
def verify(exe: Path,
           pin: str = typer.Option("", "--pin", metavar="SPEC",
               help="anchor the build's EMBEDDED --self-signed key to a published key set and "
                    "fail (nonzero) unless it matches. SPEC is github:<user> (fetches "
                    "https://github.com/<user>.keys over TLS) or keys-url:<https-url>. A match "
                    "upgrades edit-detection to identity-anchored provenance (INV-SIGN-02) — but "
                    "trust then reduces to GitHub-account + TLS trust; account takeover or a "
                    "mis-issued cert forges it. Fails closed on any network/parse error.")):
    """Inspect a built launcher's footer + confirm payload integrity.

    With --pin, also anchor the embedded signing key to a published identity (see docs/SIGNING.md
    'Publishing your fingerprint'). A pin mismatch fails the command alongside a digest failure.
    """
    info = verify_exe(exe)
    # Aligned on a terminal, `key: value` lines when piped — `ui.table` decides, because
    # this is the command a CI job runs and its output has to stay greppable.
    fields(info.items(), title=str(exe))
    ok = info["sha_ok"]
    print("payload integrity: OK" if ok else "payload integrity: FAILED",
          style="ok" if ok else "error")
    pin_ok = _check_pin(info, pin) if pin else True
    raise typer.Exit(0 if (ok and pin_ok) else 1)


def _check_pin(info: dict, spec: str) -> bool:
    """Anchor the build's embedded signing key against a published key set. Returns True only on
    a clean match; prints why and returns False on anything else (fail-closed)."""
    from ..anchor import AnchorError, check_embedded_pubkey
    pubkey = info.get("pubkey")
    if not info.get("self_signed") or not pubkey:
        print("--pin: this build carries no embedded --self-signed key (not a v3 footer); there "
              "is nothing to anchor. Refusing (fail-closed).", style="error")
        return False
    try:
        res = check_embedded_pubkey(pubkey, spec)
    except AnchorError as e:
        print(f"anchor: FAILED — {e}", style="error")
        return False
    if res.matched:
        print(f"anchor: OK — embedded key is published at {res.url} "
              f"({res.n_keys} ed25519 key(s) checked). Trust = GitHub-account + TLS trust only "
              f"(INV-SIGN-02).", style="ok")
        return True
    print(f"anchor: FAILED — embedded key is NOT among the {res.n_keys} ed25519 key(s) at "
          f"{res.url}. This binary was signed by a key the pinned identity does not publish.",
          style="error")
    return False

@app.command()
def init(path: Path = typer.Argument(Path("."), help="project dir or script"),
         force: bool = typer.Option(False, "--force", help="overwrite an existing haru_pack.toml")):
    """Scaffold a haru_pack.toml, pre-filled from discovery + any available venv."""
    from .. import scaffold
    from ..discovery import discover
    out_dir = path if path.is_dir() else path.parent
    out = out_dir / "haru_pack.toml"
    if out.exists() and not force:
        print(f"{out} already exists (use --force)", style="warn"); raise typer.Exit(1)
    try:
        disc = discover(path)
    except Exception as e:
        print(f"discovery failed: {e}", style="error"); raise typer.Exit(2)
    deps = set(scaffold.project_deps(path, disc))
    learned = False
    venv = scaffold.find_venv(out_dir)
    if venv:
        vver, vpkgs = scaffold.venv_info(venv)
        if vpkgs: deps |= set(vpkgs); learned = True
        if vver and not disc.get("python"): disc["python"] = vver
        print(f"learned from venv: {venv}  ({len(vpkgs)} packages, python {vver or '?'})", style="info")
    out.write_text(scaffold.render(disc, sorted(deps), learned_from_venv=learned))
    print(f"wrote {out}  (kind={disc['kind']}, entrypoint={disc['entrypoint']}, python={disc.get('python') or 'auto'})", style="ok")

@app.command("hostname")
def hostname_cmd():
    """Print this machine's canonical hostname (give it to a vendor to bind an --encrypt
    license with --machine). It is ASCII-lowercased with any trailing dot stripped — the same
    canonicalization the launcher applies — so what you send is exactly what gets bound."""
    from ..crypto import hostname
    print(hostname())


@app.command()
def keygen(project: Path = typer.Argument(Path("."),
               help="project the key is for (its default keystore path is derived from this)"),
           key: str = typer.Option("", "--key", metavar="PATH",
               help="write the key here instead of the per-project keystore"),
           force: bool = typer.Option(False, "--force",
               help="overwrite an existing key (rotates it — recipients who pinned the old "
                    "fingerprint will no longer verify)")):
    """Generate an Ed25519 signing key for `--self-signed`, then print its fingerprint.

    A build never mints a key itself (that would rotate it on every ephemeral CI home); this
    is the deliberate one-time act. Record and PUBLISH the printed fingerprint out of band —
    without that pin, `--self-signed` is only edit-detection, not tamper-evidence.
    """
    from ..build import signing
    path = Path(key) if key else signing.default_key_path(project)
    try:
        _, fp = signing.generate_key(path, overwrite=force)
    except signing.SigningError as e:
        print(str(e), style="error"); raise typer.Exit(2)
    print(f"wrote signing key: {path}", style="ok")
    print(f"public-key fingerprint (sha256): {fp}")
    print("PUBLISH this fingerprint out of band so recipients can pin it — otherwise "
          "--self-signed is edit-detection only, not tamper-evidence. Easiest: GPG- or "
          "SSH-sign it with a key people already associate with you (e.g. served at "
          "github.com/<you>.gpg or github.com/<you>.keys). See docs/SIGNING.md "
          "'Publishing your fingerprint'.", style="warn")

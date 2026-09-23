"""`haru-pack build` — the option surface, and nothing else.

Sixty-odd typer declarations, which is what a tool with this many knobs looks like. They
live apart from `builddriver` on purpose: this file changes when a FLAG changes, that one
when a BUILD changes, and keeping them together meant every new option enlarged the module
that also held the build logic.

Split out of cli.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import typer

from ..targets import KNOWN_TARGETS
from .builddriver import _run_build
from .root import app


@app.command()
def build(project: Path = typer.Argument(..., help="payload dir (contains manifest.json + app/)"),
          out: Path = typer.Option(None, "--out", "-o", help="output exe path"),
          target: str = typer.Option("host",
              help="'host', or <os>-<arch>: " + ", ".join(KNOWN_TARGETS)),
          tier: str = typer.Option("default", help="thin | default | thick"),
          thin: bool = typer.Option(False, "--thin", help="bundle NOTHING; fetch uv+python+deps on target"),
          thick: bool = typer.Option(False, "--thick", help="bundle EVERYTHING; download nothing (offline)"),
          chonky: bool = typer.Option(False, "--chonky", hidden=True),
          encrypt: bool = typer.Option(False, "--encrypt", help="AES-256-GCM encrypt the payload"),
          secret: str = typer.Option(None, "--secret", help="secret literal (key material)"),
          secret_env: str = typer.Option(None, "--secret-env", help="env var to read the secret from (build)"),
          secret_prompt: bool = typer.Option(False, "--secret-prompt", help="prompt for the secret"),
          embed_secret: bool = typer.Option(False, "--embed-secret", help="embed the secret in the exe (weakest)"),
          expires: str = typer.Option("", "--expires", help="license expiry YYYY-MM-DD"),
          machine: str = typer.Option("", "--machine",
              help="bind to this OS hostname (cryptographic; canonicalized to ASCII-lowercase "
                   "with a trailing dot stripped). The customer runs `haru-pack hostname` on "
                   "the target and sends you the value. FQDN preferred, short name on off-domain "
                   "boxes — exact-match, so short != FQDN"),
          user: str = typer.Option("", "--user",
              help="bind to this OS login username (cryptographic). A second passphrase "
                   "component, NOT an identity check — it binds to a login string on a machine "
                   "the licensee controls, not to a person"),
          geo: str = typer.Option("", "--geo",
              help="allowed country codes, comma-separated (sugar for --geo-restrict "
                   "country_code=XX). Resolved online at runtime; fail-closed; needs --encrypt"),
          geo_restrict: list[str] = typer.Option(None, "--geo-restrict", metavar="FIELD=VALUE,...",
              help="one allow-rule against the resolver JSON, e.g. country_code=US,region=Texas "
                   "(AND within a rule). Repeatable — rules are OR'd. Any field works, so "
                   "ip=1.2.3.4 is an ip gate. Runs online, fail-closed; needs --encrypt"),
          geo_restrict_api_url: list[str] = typer.Option(None, "--geo-restrict-api-url",
              metavar="URL", help="resolver endpoint returning IP+geo JSON (default "
                   "https://ipwho.is/). Repeatable for an N-endpoint consensus"),
          geo_restrict_consensus: int = typer.Option(1, "--geo-restrict-consensus", metavar="K",
              help="require K endpoints to resolve AND agree the caller is allowed (default 1). "
                   "Fewer resolving/agreeing = fail-closed"),
          python: str = typer.Option("", "--python", help="Python version to stage (e.g. 3.13); default auto/3.13"),
          entry_point: str = typer.Option("", "--entry-point", "-e",
              help="what to run: a script (app.py), a console script (lotek), or "
                   "module:callable (app.cli:main) — same spelling as [project.scripts]"),
          wine: bool = typer.Option(False, "--wine", help="run execute-required bundle steps under wine (thick cross)"),
          obfuscate: str = typer.Option("none", "--obfuscate", help="obfuscate the source before packing: none | pyarmor (default engine when a value is omitted). Independent of --encrypt."),
          obfuscate_args: str = typer.Option("", "--obfuscate-args", help="extra args passed through to the obfuscation engine, quoted"),
          shake: bool = typer.Option(False, "--shake",
              help="thick only: run the project's tests under a file tracer and drop bundled "
                   "files nothing touched; refuses to ship if the suite then fails"),
          shake_keep: List[str] = typer.Option(None, "--shake-keep", metavar="GLOB",
              help="never prune paths matching GLOB (repeatable)"),
          slim_python: bool = typer.Option(False, "--slim-python",
              help="thick only: after the interpreter is fetched and digest-verified, remove "
                   "a fixed known-unused set from it — pip, ensurepip, tkinter/tcl-tk, "
                   "idlelib, pydoc_data, C headers and man pages (terminfo is kept). No test "
                   "suite required, unlike --shake. TRAP: a project that imports tkinter, or "
                   "shells out to pip/ensurepip at runtime, must NOT use this — it is opt-in "
                   "because that safety cannot be proven statically. Every removed path is "
                   "recorded on the build receipt. See docs/SLIM.md"),
          env_canary: str = typer.Option("", "--env-canary", metavar="TOKEN",
              help="canary prefix for ALL stub knobs (default HARU); knob K is read at runtime "
                   "as <TOKEN>_<K> (e.g. HARU_SECRET). Must match ^[A-Za-z_][A-Za-z0-9_]*$"),
          env_canary_random: bool = typer.Option(False, "--env-canary-random",
              help="pick a random [A-Z][A-Z0-9]{7} canary for all knobs and PRINT it — record "
                   "it; you set the secret at runtime as <TOKEN>_SECRET"),
          stub_env_secret_canary: str = typer.Option("", "--stub-env-secret-canary",
              metavar="TOKEN", help="override the SECRET knob's canary only"),
          stub_env_uv_ver_canary: str = typer.Option("", "--stub-env-uv-ver-canary",
              metavar="TOKEN", help="override the UV_VER knob's canary only"),
          stub_env_source_url_canary: str = typer.Option("", "--stub-env-source-url-canary",
              metavar="TOKEN", help="override the SOURCE_URL knob's canary only"),
          stub_env_base_path_canary: str = typer.Option("", "--stub-env-base-path-canary",
              metavar="TOKEN", help="override the BASE_PATH knob's canary only"),
          stub_env_ephemeral_canary: str = typer.Option("", "--stub-env-ephemeral-canary",
              metavar="TOKEN", help="override the EPHEMERAL knob's canary only"),
          reap: bool = typer.Option(False, "--reap",
              help="after the app exits, spawn a DETACHED process that deletes the staged "
                   "subtree, then exit without waiting (fire-and-forget cleanup). Implied by "
                   "--ephemeral"),
          ephemeral: bool = typer.Option(False, "--ephemeral",
              help="best-effort RAM-backed (ephemeral) staging: Linux stages under /dev/shm when "
                   "available AND the payload fits free RAM (else falls back to the cache with a "
                   "note) - truly RAM-only ONLY on Linux. Windows/macOS have no unprivileged RAM "
                   "disk, so it is best-effort there. Implies --reap (opt out with --no-reap). "
                   "Runtime knob is 2-STATE, not 3: <canary>_EPHEMERAL=1 forces RAM (skips the "
                   "fit-check; also enables RAM on a binary not built --ephemeral). Unset is auto "
                   "(a --ephemeral binary runs the RAM-fit check, else stages to the persistent "
                   "cache) - there is NO value that forces disk. Governs only where the STUB "
                   "stages, not the app's own disk writes"),
          ram_only: bool = typer.Option(False, "--ram-only", hidden=True,
              help="deprecated alias for --ephemeral (kept working for one release)"),
          no_reap: bool = typer.Option(False, "--no-reap",
              help="opt out of the --reap that --ephemeral implies (keep the staged tree after "
                   "exit, e.g. to reuse a RAM stage across restarts)"),
          overwrite: bool = typer.Option(False, "--overwrite",
              help="shred-on-reap: the detached reaper overwrites each staged file with "
                   "matching-length random data and fsyncs before unlinking, so a plaintext blob "
                   "on disk resists SIMPLE undelete. Requires --reap. NOT a secure erase - SSD "
                   "wear-leveling, copy-on-write filesystems, snapshots/VSS and swap can retain "
                   "the bytes (see THREAT_MODEL.md)"),
          base_path: str = typer.Option("", "--base-path", metavar="DIR",
              help="staging-root default baked into the stub-config (a canary-named BASE_PATH "
                   "env var overrides it at runtime). Refused if it is a root/drive/home path"),
          source_url: str = typer.Option("", "--source-url", metavar="URL",
              help="remote-fetch delivery: the payload is fetched from URL at runtime instead of "
                   "appended. The binary carries only the launcher + a build-baked digest; the "
                   "build writes a .haru-payload sidecar you host at URL. Fetched bytes are "
                   "verified against that digest, so the URL is not trusted (INV-REMOTE-01). "
                   "A canary-named SOURCE_URL env var overrides it at runtime (mirror/failover)"),
          env_append: list[str] = typer.Option(None, "--env-append", metavar="KEY=VALUE",
              help="inject KEY=VALUE into the child env before uv AND the app (repeatable). "
                   "Lives in the payload — use --encrypt to hide a secret value"),
          self_signed: bool = typer.Option(False, "--self-signed",
              help="sign the build with an Ed25519 key so the launcher detects a post-build "
                   "payload edit (v3 footer). DEFAULT OFF. HONEST LIMIT: the public key is "
                   "embedded in the binary, so this detects edits by anyone who does not ALSO "
                   "rewrite that key — it is NOT tamper-evidence unless you PIN the fingerprint "
                   "OUT OF BAND (the build prints it; it is on the receipt). The real Windows "
                   "tamper-evidence is --cert-file. See docs/SIGNING.md. Uses the per-project "
                   "keystore key (~/.config/haru-pack/<hash>/key); create it with `haru-pack "
                   "keygen`. Fails hard if the key is missing (never auto-rotates)"),
          sign_key: str = typer.Option("", "--sign-key", metavar="PATH",
              help="use this Ed25519 key file for --self-signed instead of the per-project "
                   "keystore key. Must be a raw 32-byte seed, mode 0600. Fails hard if missing"),
          cert_file: str = typer.Option("", "--cert-file", metavar="PATH",
              help="Windows only: request Authenticode signing (the REAL tamper-evidence on "
                   "Windows). Modern code-signing keys are non-exportable (HSM/token/cloud), so "
                   "haru-pack does not hold the key — it emits the exact osslsigncode/jsign "
                   "command to run against the produced PE and records the deferred intent on "
                   "the receipt. See docs/SIGNING.md. Refused on non-Windows targets"),
          emit_c: str = typer.Option("", "--emit-c", metavar="DIR",
              help="also write a self-contained C reproduction kit to DIR: the launcher stub "
                   "as C (recompiles with zig alone, no Nim), this build's payload + "
                   "stub-config, and a compile.sh that rebuilds the exact binary. For "
                   "inspecting, modifying, or manually compiling the stub"),
          emit_nim: str = typer.Option("", "--emit-nim", metavar="DIR",
              help="also write a Nim reproduction kit to DIR (the launcher's Nim source, this "
                   "build's payload + stub-config, a portable zig shim, and a compile.sh that "
                   "recompiles and reassembles the exact binary). The packed binary is still "
                   "produced. For inspecting, modifying, or manually compiling the stub")):
    """Build a single-file launcher from a project payload dir.

    Tiers: --thin (smallest, needs network) · default (uv bundled) · --thick/--chonky
    (uv + Python bundled, fully offline)."""
    _run_build(project=project, out=out, target=target, tier=tier, thin=thin, thick=thick,
               chonky=chonky, encrypt=encrypt, secret=secret, secret_env=secret_env,
               secret_prompt=secret_prompt, embed_secret=embed_secret, expires=expires,
               machine=machine, user=user, geo=geo, geo_restrict=geo_restrict,
               geo_restrict_api_url=geo_restrict_api_url,
               geo_restrict_consensus=geo_restrict_consensus, python=python,
               entry_point=entry_point,
               wine=wine, obfuscate=obfuscate, obfuscate_args=obfuscate_args,
               shake=shake, shake_keep=shake_keep, slim_python=slim_python,
               env_canary=env_canary,
               env_canary_random=env_canary_random,
               stub_env_secret_canary=stub_env_secret_canary,
               stub_env_uv_ver_canary=stub_env_uv_ver_canary,
               stub_env_source_url_canary=stub_env_source_url_canary,
               stub_env_base_path_canary=stub_env_base_path_canary,
               stub_env_ephemeral_canary=stub_env_ephemeral_canary,
               reap=reap, ephemeral=ephemeral, ram_only=ram_only, no_reap=no_reap,
               overwrite=overwrite, base_path=base_path, source_url=source_url,
               env_append=env_append, emit_c=emit_c, emit_nim=emit_nim,
               self_signed=self_signed, sign_key=sign_key, cert_file=cert_file)

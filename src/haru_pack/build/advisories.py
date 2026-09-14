"""What a build TELLS the operator about the staging knobs they set, and the two
contradictions between those knobs that it refuses outright.

Every paragraph in here exists because one of these flags does something narrower than its
name suggests — `--ephemeral` is best-effort outside Linux, `--overwrite` is not a secure
erase — and the repo's standing rule is that haru-pack says so at build time rather than
letting the packager find out from a customer (docs/PRINCIPLES.md, INV-BUILD-01,
INV-SECRET-02).

It is a great deal of prose for very little logic, which is exactly why it belongs in its
own module: mixed into the orchestrator it was most of that function by volume and almost
none of it by meaning, and it made `build()` look far more complicated than it is.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Text unchanged.
"""
from __future__ import annotations

from .errors import BuildError
from .geo import DEFAULT_GEO_ENDPOINT


def couple_staging_flags(*, reap: bool, overwrite: bool, ram_only: bool, no_reap: bool,
                         say) -> bool:
    """Resolve --ephemeral / --reap / --no-reap / --overwrite into the EFFECTIVE reap value.

    Returned rather than mutated in place so that every later stage — the stub-config, the
    launcher's behaviour, and the receipt — reads the same decision from one source. A
    contradiction raises instead of picking a winner.
    """
    # --ephemeral implies --reap (docs/adr/0007, INV-EPHEMERAL-02): "ephemeral" means "not
    # permanent", so a RAM/ephemeral stage cleans itself up by default. --no-reap opts out for a
    # restart-heavy service that wants to reuse the staged tree across runs. The coupling happens
    # BEFORE the overwrite check so --ephemeral --overwrite works without a separate --reap.
    if ram_only and not no_reap and not reap:
        reap = True
        say("--ephemeral implies --reap: the staged tree is deleted after the app exits. "
            "Pass --no-reap to keep it (e.g. to reuse a RAM stage across restarts).")
    if no_reap and reap:
        # An explicit --reap and --no-reap together is a contradiction; refuse rather than guess.
        raise BuildError("--reap and --no-reap conflict: pass one. --no-reap only opts out of the "
                         "reap that --ephemeral would otherwise imply.")
    # --overwrite is shred-ON-reap: the reaper is what runs the shred, so overwrite without reap
    # would silently do nothing. Refuse it at build rather than ship a binary that ignores a
    # security flag the packager asked for (INV-SHRED-01).
    if overwrite and not reap:
        raise BuildError("--overwrite is shred-on-reap and needs --reap to run: without --reap "
                         "nothing deletes the stage, so nothing shreds it. Add --reap (or drop "
                         "--no-reap if you passed it with --ephemeral), or drop --overwrite.")
    return reap


def announce_staging(*, enc: dict, reap: bool, overwrite: bool, ram_only: bool,
                     base_path: str, say) -> None:
    """Say out loud what each staging knob will, and will not, actually do."""
    if enc["geo"].get("allow"):
        gp = enc["geo"]
        say(f"--geo-restrict: online location gate — {len(gp['allow'])} allow-rule(s), "
            f"{len(gp.get('endpoints', [DEFAULT_GEO_ENDPOINT]))} resolver endpoint(s), consensus "
            f"{gp.get('consensus', 1)}. It resolves the caller's IP+geo at runtime and FAILS "
            f"CLOSED if fewer than the consensus resolve or agree — no env var can set or bypass "
            f"it (the old HARUPACK_GEO bypass is gone). HONEST LIMIT: this is an IP check, not a "
            f"presence check — a VPN/proxy whose exit IP is in an allowed location passes. Lives "
            f"inside the encrypted policy, so it needs --encrypt (and a secret).")
    if overwrite:
        say("--overwrite: shred-on-reap. The detached reaper overwrites each staged file with "
            "matching-length random data and fsyncs BEFORE unlinking, so a plaintext blob on disk "
            "resists SIMPLE file-undelete (Recuva/PhotoRec/TestDisk) on a non-CoW filesystem. This "
            "is NOT a secure erase: SSD wear-leveling (LBA != PBA), copy-on-write filesystems, "
            "snapshots/VSS, journals, and swap can all retain the original bytes (THREAT_MODEL.md). "
            "The durable defense is --encrypt + --ephemeral: decrypt only to RAM, nothing to shred.")
    if ram_only:
        say("--ephemeral: best-effort RAM-backed staging (wire key still `ram_only`). Linux stages "
            "under /dev/shm (tmpfs) when available, else falls back to the persistent cache with a "
            "note - truly RAM-only ONLY on Linux. Windows/macOS have no unprivileged RAM disk (no "
            "tmpfs; a RAM disk needs a signed kernel driver + admin), so it is best-effort there. "
            "It governs only where the STUB stages the payload tree - not the packed app's own "
            "disk writes.")
    # --encrypt + --ephemeral is often reached for as "nothing plaintext ever hits disk". It is
    # NOT absolute, and saying so at build time is the same honesty INV-SECRET-02 / INV-BUILD-01
    # require (adversarial review W1). On a low-RAM target the RAM stage FALLS BACK to the
    # persistent cache and the decrypted tree lands on disk. (There is no env value that forces
    # disk — the EPHEMERAL knob only enables RAM — so this is an availability fallback, not an
    # attacker-controlled downgrade.) That fallback is still reaped, but a plain unlink is
    # recoverable; --overwrite shreds it (INV-SHRED-01).
    if ram_only and enc["enabled"]:
        if overwrite:
            say("--encrypt + --ephemeral: on a low-RAM target the decrypted tree can fall back to "
                "disk; --overwrite is set, so that fallback is shredded on reap. Still not a secure "
                "erase (THREAT_MODEL.md).")
        else:
            say("WARNING: --encrypt + --ephemeral is NOT an absolute 'nothing reaches disk'. On a "
                "low-RAM target the decrypted tree FALLS BACK to the persistent cache; that fallback "
                "is reaped but a plain unlink is recoverable. Add --overwrite to shred the fallback, "
                "or accept the residual (THREAT_MODEL.md, docs/adr/0007 §5).")
    if reap:
        say("--reap: after the app exits the stub spawns a detached, fire-and-forget deletion "
            "of the staged subtree it created this run, then exits without waiting. Only that "
            "subtree is removed — never the base path itself.")
    if base_path:
        say(f"--base-path: staging root default baked into the stub-config as {base_path!r}. "
            "A canary-named BASE_PATH env var overrides it at runtime; the launcher refuses a "
            "root/drive/home path defensively.")


def announce_obfuscation_tier(*, obfuscate: str, tier: str, python: str, say) -> None:
    """Warn when obfuscation is bound to a Python the tier does not guarantee.

    Obfuscation binds the payload to an EXACT Python minor version: pyarmor's runtime .so
    references version-private symbols, so a payload obfuscated for 3.12 fails to import
    under 3.11 or 3.13 (measured 2026-09-10). Only the thick tier guarantees the staged
    interpreter is the one obfuscation targeted; thin/default resolve a Python on the
    target and may not land on the same minor. haru-pack CAN see this, so it says so
    (INV-OBF-01).
    """
    if not obfuscate or obfuscate == "none" or tier == "thick":
        return
    say(f"WARNING: --obfuscate with tier={tier}. Obfuscation is bound to Python "
        f"{python or '3.13'} EXACTLY, and only --thick bundles that interpreter. On "
        f"thin/default the target may resolve a different Python minor and the binary "
        f"will fail to start with an 'undefined symbol' import error. Use --thick, or "
        f"ensure the target has exactly Python {python or '3.13'}.")

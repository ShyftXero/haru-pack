from __future__ import annotations

TIERS = ("thin", "default", "thick")
CHONKY = "thick"  # easter-egg alias

def describe(tier: str) -> str:
    return {
        "thin":    "bundle nothing — fetch uv + Python + deps on target (smallest, needs network)",
        "default": "bundle uv — fetch Python + deps on first run (cached)",
        "thick":   "bundle uv + Python (+venv) — download NOTHING, fully offline (chonky)",
    }[tier]

def bundles_uv(tier: str) -> bool:
    """uv is bundled in every tier except `thin`.

    Never assume the target already has uv: no supported Ubuntu LTS ships it, Debian has no
    CLI package (only `python3-uv-build`), and NixOS documents it as problematic. `thin` is
    the sole opt-out and it pays for that with a first-run download. See `research/05` §4.9.
    """
    return tier != "thin"

# Single source of truth for tier-derived runtime settings. `fetch_uv` is derived from
# bundles_uv() rather than restated, so a new tier cannot claim to bundle uv here and be
# skipped by the bundler (or vice versa).
_OFFLINE = {"thin": False, "default": False, "thick": True}

def apply_tier(manifest: dict, tier: str) -> dict:
    """Augment a project manifest with tier-derived runtime settings."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r} (expected one of {', '.join(TIERS)})")
    m = dict(manifest)
    m["tier"] = tier
    m["offline"] = _OFFLINE[tier]
    m["fetch_uv"] = not bundles_uv(tier)
    # thick: the python path is filled in by the bundler once the interpreter is staged
    return m

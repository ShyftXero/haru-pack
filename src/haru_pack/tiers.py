from __future__ import annotations

TIERS = ("thin", "default", "thick")
CHONKY = "thick"  # easter-egg alias

def describe(tier: str) -> str:
    return {
        "thin":    "bundle nothing — fetch uv + Python + deps on target (smallest, needs network)",
        "default": "bundle uv — fetch Python + deps on first run (cached)",
        "thick":   "bundle uv + Python (+venv) — download NOTHING, fully offline (chonky)",
    }[tier]

def apply_tier(manifest: dict, tier: str) -> dict:
    """Augment a project manifest with tier-derived runtime settings."""
    m = dict(manifest)
    m["tier"] = tier
    if tier == "thin":
        m["offline"] = False
        m["fetch_uv"] = True
    elif tier == "default":
        m["offline"] = False
        m["fetch_uv"] = False
    elif tier == "thick":
        m["offline"] = True
        m["fetch_uv"] = False
        # python path is filled in by the bundler once the interpreter is staged
    return m

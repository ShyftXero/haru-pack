"""The Phase-4 online geo/ip execution gate policy (docs/adr/0006).

One mechanism, not a bespoke rule per gate: resolve the caller's IP+geo from a consensus of
online resolvers, match an allow-policy, fail closed.

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Unchanged otherwise.
"""
from __future__ import annotations

from .errors import BuildError


# ── Phase-4 execution gates: online geo/ip (docs/adr/0006, INV-GATE-01 / INV-GEO-01) ──
DEFAULT_GEO_ENDPOINT = "https://ipwho.is/"


def _normalize_geo(geo) -> dict:
    """Coerce a geo spec into the Phase-4 gate OBJECT {endpoints?, consensus?, allow[]}.

    {} / None -> {} (no gate); a dict -> as-is; a list of country codes (a haru_pack.toml
    `[encryption] geo = [...]` or a legacy caller) -> allow-rules on country_code. This keeps a
    declared-in-TOML country list working while the wire format is the uniform gate object."""
    if not geo:
        return {}
    if isinstance(geo, dict):
        return geo
    return {"allow": [{"country_code": str(g)} for g in geo if g]}


def build_geo_policy(countries, restrict, api_urls, consensus) -> dict:
    """Assemble the encrypted geo/ip execution-gate policy from CLI inputs (INV-GATE-01 /
    INV-GEO-01). Returns {} when no allow-rule is given (no gate). The gate is uniform: resolve
    the caller's IP+geo from a consensus of online resolvers, match an allow-policy, fail closed.

      * --geo US,CA            -> two rules {country_code: US} OR {country_code: CA}
      * --geo-restrict "a=1,b=2" -> one rule {a:1, b:2} (AND within), OR'd across repeats
      * --geo-restrict-api-url -> resolver endpoints (default ipwho.is)
      * --geo-restrict-consensus -> K endpoints must resolve AND agree (default 1)

    Any resolver field can be asserted (so ip=1.2.3.4 is an ip gate) — one mechanism, not a
    bespoke rule per gate. Refuses a consensus that can never be reached, and endpoints/consensus
    set with no rule (a gate that does nothing is the SILENT-WEDGE class, INV-CHAOS-07)."""
    allow: list[dict] = [{"country_code": c} for c in (countries or []) if c]
    for spec in (restrict or []):
        rule: dict = {}
        for pair in spec.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise BuildError(
                    f"--geo-restrict rule {spec!r} has a term without '=': {pair!r}. Use "
                    f"field=value[,field=value] (e.g. country_code=US,region=Texas).")
            k, v = (p.strip() for p in pair.split("=", 1))
            if not k or not v:
                raise BuildError(f"--geo-restrict rule {spec!r} has an empty field or value.")
            rule[k] = v
        if rule:
            allow.append(rule)
    if not allow:
        if api_urls or (consensus and consensus != 1):
            raise BuildError(
                "--geo-restrict-api-url / --geo-restrict-consensus configure a geo gate but no "
                "allow-rule was given, so nothing would be enforced. Add --geo or --geo-restrict, "
                "or drop the endpoint/consensus flags.")
        return {}
    # Dedup while preserving order: a consensus is only meaningful across DISTINCT resolvers.
    # Listing the same URL K times would otherwise let one server (or one on-path MITM that
    # intercepts it) satisfy the whole quorum — silently voiding "one endpoint lying doesn't
    # decide the gate". Consensus is checked against the UNIQUE count.
    seen: set = set()
    endpoints: list[str] = []
    for u in (api_urls or []):
        u = u.strip()
        if not u:
            continue
        if not (u.lower().startswith("http://") or u.lower().startswith("https://")):
            raise BuildError(f"--geo-restrict-api-url {u!r} must be an http:// or https:// URL.")
        if u not in seen:
            seen.add(u)
            endpoints.append(u)
    if not endpoints:
        endpoints = [DEFAULT_GEO_ENDPOINT]
    k = consensus or 1
    if k < 1:
        raise BuildError("--geo-restrict-consensus must be >= 1.")
    if k > len(endpoints):
        raise BuildError(
            f"--geo-restrict-consensus={k} exceeds the {len(endpoints)} DISTINCT resolver "
            f"endpoint(s) configured, so consensus can never be reached and the gate would "
            f"fail closed forever. Add more distinct --geo-restrict-api-url, or lower the "
            f"consensus.")
    return {"endpoints": endpoints, "consensus": k, "allow": allow}


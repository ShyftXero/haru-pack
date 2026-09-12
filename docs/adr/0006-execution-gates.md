# ADR 0006 — execution gates: uniform model + online geo/ip

Status: accepted (2026-09-12) · Implements Phase 4 · Invariants: INV-GATE-01, INV-GEO-01 · Issue #11

## Context

An encrypted build can carry license conditions. Before Phase 4 these were: `expires` (date),
`machine`/`user` (cryptographically bound via the KDF), and `geo` — a list of strings compared
against the `HARUPACK_GEO` **environment variable**. That geo check was theatre: any user could set
`HARUPACK_GEO` to an allowed value and pass. The ask was to make geo real (resolve it online) and,
while doing so, to make every rule-checked gate share one shape rather than growing a bespoke
mechanism per gate ("don't add a rule for one gate without adding it for them all — that's drift").

## Decision

### 1. One gate shape

A rule-checked gate: **resolve a current value → match an allow-policy → fail closed.** All gates
live INSIDE the encrypted policy (`cryptbox.checkPolicy` runs post-decrypt), so a reverse-engineer
sees nothing and no gate is env-overridable.

- `date` (expiry) — resolved from the clock, matched against `expires`.
- `geo` / `ip` — resolved online (below).
- `machine` / `user` — not re-checked here; a wrong value means the payload never decrypts, so
  reaching `checkPolicy` already proves them. Strictly stronger than a checked rule; declared in
  the same policy for uniformity.

### 2. Online geo/ip (`execgate.nim`)

Default resolver `https://ipwho.is/`: one bare TLS GET returns the caller's IP and geo in a single
JSON body (`success` must be true; fields snake_case `country_code` / `region` / `city` / `ip` …).

- The policy lists **N endpoints** (`--geo-restrict-api-url`, default ipwho.is) and a **consensus
  K** (`--geo-restrict-consensus`, default 1).
- The gate passes iff **≥ K endpoints resolve** (200, parseable, `success == true`, within the
  64 KB body cap) **AND ≥ K of the resolved ones agree** the caller is allowed. Otherwise it
  **fails closed** (`quit 3`). So a single down or lying endpoint does not decide the gate; raise K
  to defend against an endpoint that lies "allowed".
- **Allow-rules** are `field=value` assertions against the resolver JSON — AND within a rule, OR
  across rules (`--geo-restrict "country_code=US,region=Texas"`, repeatable). Because any field can
  be asserted, `ip=1.2.3.4` is an ip gate through the same code — one mechanism, not two.

### 3. No env bypass (the security gap this closes)

`HARUPACK_GEO` is removed. `cryptbox.checkPolicy` reads no environment variable for location. A
pre-Phase-4 array-form `geo` policy (which relied on that bypass) is **refused**, not silently
ignored — a dropped location restriction is a breach, not a no-op.

### 4. Build surface

`geo` policy rides inside the encrypted payload, so it **requires `--encrypt`** (and a secret) —
enforced because a geo flag sets `want_enc`, and a geo gate with no allow-rule, or endpoints/
consensus with no rule, is refused at build (the SILENT-WEDGE class, INV-CHAOS-07). `build_geo_policy`
also refuses a consensus larger than the endpoint count (unreachable forever).

## Honest limits

- **Local MITM defeats it (the load-bearing caveat).** The gate is an HTTP(S) call made on the END
  USER'S OWN MACHINE. A user with local privilege controls their proxy (`https_proxy`), CA trust
  (`SSL_CERT_FILE` / `SSL_CERT_DIR`), and DNS / `/etc/hosts`, so they can point the resolver
  hostname at a server they run and have it return `{"success":true,"country_code":"US"}`.
  N-endpoint consensus gives NO protection against this — one on-path position intercepts every
  endpoint identically. So the gate is real against a casual user and honest network faults, but
  **advisory** against a determined local adversary. Consensus defends only against a **minority of
  compromised or lying EXTERNAL resolvers**, and only when K ≥ 2 (the shipped default K=1 trusts a
  single response). The durable control against a hostile HOST is not client-side geo — it is not
  shipping to them. This is why INV-GEO-01's claim is scoped to "haru-pack reads no env," not "no
  one can bypass it."
- **Consensus needs distinct endpoints.** `build_geo_policy` deduplicates `--geo-restrict-api-url`
  and refuses a consensus larger than the distinct count, so a quorum cannot be faked by listing
  one URL K times. It cannot, however, tell that two different hostnames resolve to the same
  operator — diversity of endpoints is the packager's responsibility.
- **VPN / proxy.** IP-consensus defeats a down or lying endpoint; it does NOT defeat a user whose
  VPN/proxy exit IP sits in an allowed location. This is an IP check, not a presence check.
- **Latency.** Endpoints are queried serially, each with a 15 s timeout, on EVERY launch; a build
  with N endpoints on a slow network can block up to N × 15 s before deciding (fail-closed).
- **Body size.** The 64 KB resolver-body cap (and the 1 GiB remote-payload cap) is checked AFTER
  the body is buffered — puppy has no streaming API — so a hostile resolver/mirror can make the
  launcher buffer more than the cap before it is rejected. The outcome is a fail-closed crash on
  launch, never code execution.
- **Windows TLS.** puppy's HTTPS on Windows needs a `cacert.pem` beside the binary (same as
  thin-tier uv fetch). Without it the request fails to resolve — and the gate **fails closed**,
  never open.
- **Network required.** A geo-gated build needs network at every run; offline = fail closed.

## Consequences

- Geo is enforced by an authority the user does not control, not by their own env (INV-GEO-01).
- Every rule-checked gate fails closed on unresolved input (INV-GATE-01).
- The policy stays hidden inside the ciphertext; the resolver endpoints and rules are not visible
  to a reverse-engineer.

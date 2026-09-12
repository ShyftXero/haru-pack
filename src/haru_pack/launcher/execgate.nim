## execgate.nim — online execution gates (Phase 4, INV-GATE-01 / INV-GEO-01).
##
## Uniform gate shape: resolve a current value from a CONSENSUS of online resolvers, match it
## against an ALLOW-policy, and FAIL CLOSED. The gate lives entirely inside the encrypted policy
## (checkPolicy calls in post-decrypt), so a reverse-engineer sees nothing and NO environment
## variable can satisfy or bypass it — this is what replaces the retired HARUPACK_GEO env bypass.
##
## The resolver default is https://ipwho.is/ : a single bare TLS GET returns the caller's IP and
## geo in one JSON body (fields snake_case country_code / region / city, plus `success` which must
## be true). The packager may list N endpoints and require a consensus of K (default 1). A rule is
## a set of field=value assertions against the resolver JSON — AND within a rule, OR across rules —
## so the SAME mechanism gates geo (country_code=US) and ip (ip=1.2.3.4): fields, not bespoke code.
##
## HONEST LIMITS. (1) IP-consensus defeats a single down/lying endpoint; it does NOT defeat a user
## behind a VPN/proxy whose exit IP is in an allowed location — that is an IP check, not a presence
## check. (2) puppy has no streaming API, so a body is buffered before the size cap applies.
## (3) On Windows, puppy's HTTPS needs a `cacert.pem` beside the binary (same as thin-tier uv
## fetch); without it the request fails to resolve and the gate FAILS CLOSED, never open.
import std/[json, tables]
import puppy

const
  DefaultGeoEndpoint = "https://ipwho.is/"
  GeoTimeoutSecs = 15'f32
  MaxGeoBodyBytes = 64 * 1024      ## a resolver JSON body is ~1 KB; cap a hostile giant response

type
  GeoRule = Table[string, string]  ## field=value assertions, all ANDed
  GeoPolicy = object
    endpoints: seq[string]
    consensus: int
    allow: seq[GeoRule]
    allowDeclared: bool             ## an `allow` array was present with >=1 entry (parsed or not)

proc parseGeoPolicy(node: JsonNode): GeoPolicy =
  ## Read the geo object from the (already-decrypted) policy JSON, with safe defaults. Absent /
  ## malformed sub-fields degrade to the safe default (one endpoint, consensus 1), never to "no
  ## gate" once `allow` has rules.
  result.consensus = 1
  result.endpoints = @[]
  result.allow = @[]
  let cons = node{"consensus"}
  if cons != nil and cons.kind == JInt:
    result.consensus = cons.getInt()
  if result.consensus < 1: result.consensus = 1
  let eps = node{"endpoints"}
  if eps != nil and eps.kind == JArray:
    for e in eps:
      if e.kind == JString and e.getStr.len > 0: result.endpoints.add e.getStr
  if result.endpoints.len == 0: result.endpoints = @[DefaultGeoEndpoint]
  let allow = node{"allow"}
  if allow != nil and allow.kind == JArray:
    if allow.len > 0: result.allowDeclared = true
    for rule in allow:
      if rule.kind == JObject:
        var r: GeoRule = initTable[string, string]()
        for k, v in rule:
          if v.kind == JString: r[k] = v.getStr
        if r.len > 0: result.allow.add r

proc resolveEndpoint(url: string): JsonNode =
  ## Parsed resolver JSON, or nil on ANY failure (unreachable, non-200, empty/oversized body,
  ## unparseable, or `success` not explicitly true). nil = "did not resolve" for consensus.
  try:
    let res = get(url, timeout = GeoTimeoutSecs)
    if res.code != 200: return nil
    if res.body.len == 0 or res.body.len > MaxGeoBodyBytes: return nil
    let j = parseJson(res.body)
    if j.kind != JObject: return nil
    let ok = j{"success"}                       # ipwho.is marks a failed lookup success=false
    if ok == nil or ok.kind != JBool or not ok.getBool: return nil
    return j
  except CatchableError:
    return nil

proc ruleMatches(rule: GeoRule, data: JsonNode): bool =
  ## Every field=value in the rule must match a string field in the resolver JSON (AND).
  for field, want in rule:
    let got = data{field}
    if got == nil or got.kind != JString or got.getStr != want: return false
  return true

proc endpointAllows(data: JsonNode, allow: seq[GeoRule]): bool =
  for rule in allow:
    if ruleMatches(rule, data): return true     # OR across rules
  return false

proc checkGeoGate*(node: JsonNode) =
  ## Online geo/ip execution gate (INV-GATE-01 / INV-GEO-01). Returns normally ONLY when at least
  ## `consensus` endpoints resolve AND at least `consensus` of the resolved ones agree the caller
  ## is allowed. Otherwise it QUITS the process (fail closed). Consults no environment variable.
  let gp = parseGeoPolicy(node)
  if gp.allow.len == 0:
    # No usable allow-rules. Two very different cases, and the difference is fail-open vs
    # fail-closed: if NO `allow` array was declared, this build simply has no geo gate (an
    # encrypted expires-only policy, say) and must run. But if an `allow` array WAS declared
    # and every rule failed to parse into a usable assertion, the gate is malformed — refuse
    # rather than silently admit (a "fail closed" gate must not vanish on garbled input).
    if gp.allowDeclared:
      quit("haru-pack: location policy is present but unreadable — refusing to run " &
           "(fail-closed)", 3)
    return
  var resolved = 0
  var allowed = 0
  for url in gp.endpoints:
    let data = resolveEndpoint(url)
    if data == nil: continue
    inc resolved
    if endpointAllows(data, gp.allow): inc allowed
  if resolved < gp.consensus:
    quit("haru-pack: cannot verify this machine's location — only " & $resolved & " of " &
         $gp.endpoints.len & " location checks completed, need " & $gp.consensus &
         " to agree (fail-closed)", 3)
  if allowed < gp.consensus:
    quit("haru-pack: not licensed to run in this location", 3)

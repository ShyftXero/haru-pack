## haru-pack stub-config: the cleartext, signature-covered section the launcher reads
## BEFORE it decrypts or stages the payload. Phase 1 carries the per-knob CANARY MAP.
## Contract: docs/adr/0003-stub-config-and-canary.md §2/§3. Parsed with parsetoml (already
## linked by manifest.nim), so reading the stub before decryption adds NO new dependency,
## and the map stays human-auditable (a canary raises guessing cost; it is not secrecy).
##
## One resolution rule everywhere (INV-CANARY-01): knob K is read at runtime from the env
## var `envForKnob(sc, K)` = `<canary[K]>_<KNOB>`. The all-"HARU" default retires the legacy
## `HARUPACK_SECRET` in favour of `HARU_SECRET` (see cryptbox.resolveSecret).
import std/strutils
import parsetoml

type
  ## The closed knob catalogue. Adding a knob is a format change, on purpose.
  Knob* = enum
    kSecret, kUvVer, kSourceUrl, kBasePath
  StubConfig* = object
    version*: int
    canary*: array[Knob, string]
    ## Phase-2 optional staging knobs (docs/adr/0004-reap-ram-staging.md §2). Their ABSENCE
    ## is today's behaviour (persistent-cache staging, no reap), so they add NO new security
    ## decision on absence and ride at stub_config_version = 1 (INV-BASE-01 / INV-RAM-01 /
    ## INV-REAP-01). A Phase-1 launcher, which ignores unknown top-level keys, simply stages
    ## the normal way — a safe default, never a downgraded protection.
    reap*: bool          ## build-time --reap: detached on-exit cleanup of the staged subtree
    ramOnly*: bool       ## build-time --ram-only: best-effort RAM-backed staging root
    basePath*: string    ## build-time --base-path: staging-root default ("" = normal cache)

const
  SupportedStubConfigVersion* = 1
  DefaultCanary* = "HARU"

proc knobToken*(k: Knob): string =
  ## The <KNOB> half of the runtime env name `<canary>_<KNOB>`.
  case k
  of kSecret:    "SECRET"
  of kUvVer:     "UV_VER"
  of kSourceUrl: "SOURCE_URL"
  of kBasePath:  "BASE_PATH"

proc canaryKey(k: Knob): string =
  ## The `[canary]` TOML key for a knob (the lowercase of its token).
  case k
  of kSecret:    "secret"
  of kUvVer:     "uv_ver"
  of kSourceUrl: "source_url"
  of kBasePath:  "base_path"

proc defaultStubConfig*(): StubConfig =
  ## Every knob -> "HARU". Used for a v1 (single-payload) binary that carries no stub. The
  ## Phase-2 staging knobs default to today's behaviour: no reap, no RAM-only, normal cache.
  result.version = SupportedStubConfigVersion
  for k in Knob: result.canary[k] = DefaultCanary
  result.reap = false
  result.ramOnly = false
  result.basePath = ""

proc isValidCanary(tok: string): bool =
  ## ^[A-Za-z_][A-Za-z0-9_]*$ — a non-empty, valid env-name prefix. Enforced at build time
  ## (§3) and re-validated here so a hand-edited stub cannot smuggle in an odd env name.
  if tok.len == 0: return false
  if tok[0] notin {'A'..'Z', 'a'..'z', '_'}: return false
  for c in tok:
    if c notin {'A'..'Z', 'a'..'z', '0'..'9', '_'}: return false
  return true

proc parseStubConfig*(raw: string): StubConfig =
  ## §2.2 validation. Raises `ValueError` on any malformed / out-of-catalogue input; the
  ## caller (main.launch) maps that to `ExitBadStub`. Unknown TOP-LEVEL keys are RESERVED
  ## and ignored (the forward-extensibility seam for later phases); an unknown key INSIDE
  ## `[canary]` is an error, because the knob catalogue is closed.
  var t: TomlValueRef
  try:
    t = parsetoml.parseString(raw)
  except ValueError as e:
    # parsetoml raises TomlError (a ValueError); re-wrap so the launcher's one-line
    # diagnostic reads as a stub-config fault, not a bare parser location (INV-LAUNCH-06).
    raise newException(ValueError, "stub-config: invalid TOML: " & e.msg)
  if t.kind != TomlValueKind.Table:
    raise newException(ValueError, "stub-config: top level is not a TOML table")
  if not t.contains("stub_config_version"):
    raise newException(ValueError, "stub-config: missing stub_config_version")
  let vNode = t["stub_config_version"]
  if vNode.kind != TomlValueKind.Int:
    raise newException(ValueError, "stub-config: stub_config_version must be an integer")
  result.version = vNode.getInt()
  if result.version != SupportedStubConfigVersion:
    raise newException(ValueError, "stub-config: unsupported stub_config_version " &
      $result.version & " (this launcher supports " & $SupportedStubConfigVersion & ")")
  if not t.contains("canary"):
    raise newException(ValueError, "stub-config: missing [canary] table")
  let canaryNode = t["canary"]
  if canaryNode.kind != TomlValueKind.Table:
    raise newException(ValueError, "stub-config: [canary] must be a table")
  let tbl = canaryNode.getTable()[]
  # The catalogue is closed: reject any key that is not one of the four knobs.
  for key in tbl.keys:
    if key notin ["secret", "uv_ver", "source_url", "base_path"]:
      raise newException(ValueError, "stub-config: unknown key in [canary]: '" & key & "'")
  # Every knob MUST be present, a string, and a valid env-name prefix.
  for k in Knob:
    let key = canaryKey(k)
    if not tbl.hasKey(key):
      raise newException(ValueError, "stub-config: [canary] missing key '" & key & "'")
    let v = tbl[key]
    if v.kind != TomlValueKind.String:
      raise newException(ValueError, "stub-config: [canary]." & key & " must be a string")
    let tok = v.getStr()
    if not isValidCanary(tok):
      raise newException(ValueError, "stub-config: [canary]." & key &
        " is not a valid env-name prefix: '" & tok & "'")
    result.canary[k] = tok
  # Phase-2 optional staging knobs (docs/adr/0004 §2). Absent -> today's behaviour; present ->
  # typed and validated. These are distinct top-level keys, NOT canary entries; any OTHER
  # unknown top-level key stays reserved/ignored (§2.3 forward-extensibility seam). No version
  # bump: their absence changes no security decision, only where/whether the stub stages/reaps.
  result.reap = false
  result.ramOnly = false
  result.basePath = ""
  if t.contains("reap"):
    let n = t["reap"]
    if n.kind != TomlValueKind.Bool:
      raise newException(ValueError, "stub-config: reap must be a boolean")
    result.reap = n.getBool()
  if t.contains("ram_only"):
    let n = t["ram_only"]
    if n.kind != TomlValueKind.Bool:
      raise newException(ValueError, "stub-config: ram_only must be a boolean")
    result.ramOnly = n.getBool()
  if t.contains("base_path"):
    let n = t["base_path"]
    if n.kind != TomlValueKind.String:
      raise newException(ValueError, "stub-config: base_path must be a string")
    result.basePath = n.getStr()

proc envForKnob*(sc: StubConfig, k: Knob): string =
  ## The single runtime resolution rule (INV-CANARY-01): knob K is read from
  ## `<canary[K]>_<KNOB>` and nothing else.
  sc.canary[k] & "_" & knobToken(k)

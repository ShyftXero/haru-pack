## uvcannon manifest: describes how to run the staged payload.
import std/[json, os]

type
  AppKind* = enum akScript, akProject
  Manifest* = object
    name*: string
    kind*: AppKind
    appSubdir*: string          # payload subdir holding the app (default "app")
    entrypoint*: seq[string]    # script path (1 elem) OR a command argv
    uvRunArgs*: seq[string]     # extra args to `uv run`
    python*: string             # optional interpreter path, relative to stage root
    projectEnv*: string         # optional venv path, relative to stage root
    postInstall*: seq[seq[string]]  # commands run once (via uv run) after staging
    offline*: bool

proc jsSeq(n: JsonNode): seq[string] =
  if n.isNil: return @[]
  for x in n: result.add x.getStr

proc parseManifest*(path: string): Manifest =
  let j = parseJson(readFile(path))
  result.name = j{"name"}.getStr("app")
  result.kind = if j{"kind"}.getStr("script") == "project": akProject else: akScript
  result.appSubdir = j{"app_subdir"}.getStr("app")
  # entrypoint: string or array
  let ep = j{"entrypoint"}
  if not ep.isNil:
    if ep.kind == JString: result.entrypoint = @[ep.getStr]
    else: result.entrypoint = jsSeq(ep)
  result.uvRunArgs = jsSeq(j{"uv_run_args"})
  result.python = j{"python"}.getStr("")
  result.projectEnv = j{"project_env"}.getStr("")
  result.offline = j{"offline"}.getBool(false)
  let pi = j{"post_install"}
  if not pi.isNil:
    for cmd in pi: result.postInstall.add jsSeq(cmd)

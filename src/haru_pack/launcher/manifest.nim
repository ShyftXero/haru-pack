## haru-pack manifest (TOML): how to run the staged payload.
import std/[tables]
import parsetoml

type
  AppKind* = enum akScript, akProject
  InstallStep* = object
    os*: seq[string]            # ["linux"|"windows"|"macos"|"all"]; empty = all
    run*: seq[string]           # argv, run via `uv run` in the project env
  BundleStep* = object
    into*: string               # dir the step writes into (rel to stage), for {into}
    env*: seq[(string, string)] # env vars set at runtime ({into} -> stage path)
  Manifest* = object
    name*: string
    kind*: AppKind
    appSubdir*: string
    entrypoint*: seq[string]
    uvRunArgs*: seq[string]
    python*: string
    projectEnv*: string
    preInstall*: seq[InstallStep]
    postInstall*: seq[InstallStep]
    offline*: bool
    cwdPolicy*: string
    verboseUv*: bool
    tier*: string
    fetchUv*: bool
    uvVersion*: string
    cacheDir*: string
    keepDays*: int              # evict stage dirs unused this long; 0 disables
    keepMax*: int               # always retain this many most-recent stage dirs
    bundle*: seq[BundleStep]

proc gs(t: TomlValueRef, k, d: string): string =
  if t.contains(k): t[k].getStr(d) else: d
proc gb(t: TomlValueRef, k: string, d: bool): bool =
  if t.contains(k): t[k].getBool(d) else: d
proc gi(t: TomlValueRef, k: string, d: int): int =
  if t.contains(k): t[k].getInt(d) else: d
proc strSeq(t: TomlValueRef, k: string): seq[string] =
  if not t.contains(k): return
  let v = t[k]
  if v.kind == TomlValueKind.Array:
    for x in v.getElems: result.add x.getStr
  elif v.kind == TomlValueKind.String:
    result.add v.getStr

proc parseManifest*(path: string): Manifest =
  let t = parsetoml.parseFile(path)
  result.name = gs(t, "name", "app")
  result.kind = if gs(t, "kind", "script") == "project": akProject else: akScript
  result.appSubdir = gs(t, "app_subdir", "app")
  result.entrypoint = strSeq(t, "entrypoint")
  result.uvRunArgs = strSeq(t, "uv_run_args")
  result.python = gs(t, "python", "")
  result.projectEnv = gs(t, "project_env", "")
  result.offline = gb(t, "offline", false)
  result.cwdPolicy = gs(t, "cwd_policy", "launch")
  result.verboseUv = gb(t, "verbose_uv", false)
  result.tier = gs(t, "tier", "default")
  result.fetchUv = gb(t, "fetch_uv", false)
  result.uvVersion = gs(t, "uv_version", "0.10.4")
  result.cacheDir = gs(t, "cache_dir", "")
  result.keepDays = gi(t, "keep_days", 30)
  result.keepMax = gi(t, "keep_max", 3)
  proc installSteps(node: TomlValueRef): seq[InstallStep] =
    for step in node.getElems:
      result.add InstallStep(os: strSeq(step, "os"), run: strSeq(step, "run"))
  if t.contains("pre_install"):  result.preInstall  = installSteps(t["pre_install"])
  if t.contains("post_install"): result.postInstall = installSteps(t["post_install"])
  if t.contains("bundle"):
    for step in t["bundle"].getElems:
      var b: BundleStep
      b.into = gs(step, "into", "")
      if step.contains("env"):
        for k, v in step["env"].getTable()[].pairs:
          b.env.add (k, v.getStr)
      result.bundle.add b

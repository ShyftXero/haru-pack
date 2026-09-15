# ADR 0005 — the flex and exam harnesses run stranger code in a container, not on the host

- Status: accepted (contract)
- Date: 2026-09-14
- Scope: `tools/flex-run.py` and `tools/exam.py` — the two harnesses that fetch real
  packages from PyPI, build them, and then execute them. Adds one shared runner
  (`tools/sandbox.py`), one committed image (`docker/flex.Dockerfile`), and the
  `INV-SANDBOX` family. Does **not** cover `tools/busybody.py`, which keeps its own
  `_docker_run` for the quotamaster persona this round (§8), nor the pytest suite itself.
- Vocabulary: *host path* — the harness running directly on the developer's machine.
  *Sandboxed path* — the harness running each package's build and run inside its own
  throwaway container. *Build phase* / *run phase* — the two containers a single package
  gets (§4).
- Invariants: `INV-SANDBOX-01` (no execution path around the sandbox runner, and a container
  argv that keeps the host out of reach), `INV-SANDBOX-02` (asked for an offline run, the argv
  builder emits `--network none` and a cold cache). Both are claimed by tests in
  `tests/test_sandbox.py` whose Red-path was walked — but walked against the argv builder and
  the harnesses' AST, **not** against the call sites that choose a runner or a mode, so the
  headline "runs in a container" is design intent held up by code reading rather than a
  machine-checked fact (§10; `INVARIANTS.md` carries the exact wording). Partially answers
  `INV-TRUST-02`, which stays `proposed` — this ADR contains the blast radius of
  *haru-pack's own harnesses*, it does not make `haru-pack build` safe against an
  untrusted tree for an operator (§9).

---

## 1. The problem, in one paragraph

The flex matrix is a list of code written by strangers, and running it is the entire point
of the harness. `haru-pack build` runs `uv sync`, which builds sdists, which executes
arbitrary PEP 517 backends. The harness then runs the binary it just produced, which
imports the package, executes its `smoke` body, and `runpy.run_module`s anything with a
`python -m` entrypoint. `tools/exam.py` goes further and runs the package's **own test
suite**. `flex/packages.toml` additionally carries `[[bundle]]` and `[[post_install]]`
steps that run real installer commands. All of that has been executing on the maintainer's
workstation, as the maintainer, with `$HOME`, SSH keys, cloud credentials and this
repository's own working tree in scope. Nothing about the matrix is hostile today; nothing
about the matrix *guarantees* it will not be tomorrow, because the contents are chosen by
download rank, not by audit.

## 2. What changes

Both harnesses execute third-party code only inside a container, by default. The host path
still exists behind `--no-docker`, because a harness you cannot debug is a harness people
route around — but it announces exactly what it is about to do (§6).

That paragraph describes what the code does; it is not what the tests check. The claiming
tests cover the argv the runner builds and the absence of a second execution path, not the
call sites that select a runner — §10 is explicit about which half is which, and the
distinction matters because the unchecked half is where a regression would hide.

## 3. `tools/sandbox.py` — one runner, and a pure function at the center

The containment decision is made by a **pure function** that returns an argv list:

```python
def docker_argv(image, *, cmd, work, network, cache, uid, gid,
                repo=None, env=None, extra=(), workdir="/w") -> list[str]
```

This is the load-bearing design choice in the whole ADR. It means the properties that
matter — that a thick run gets `--network none`, that the shared cache is not mounted during
the run phase, that the docker socket is never mounted — are assertable by a unit test that runs
**offline, in CI, on a box with no docker installed**. A containment guarantee that can only
be checked by running docker is a guarantee that gets checked when someone remembers.

The rest of the module is thin:

| function | does |
|---|---|
| `available() -> str` | `""` if docker can run, else the reason |
| `rootless() -> bool` | whether the daemon is rootless (§7) |
| `ensure_image() -> str` | build the image if stale; return `image:tag` |
| `preflight(...) -> str` | availability + rootless check + image; raises rather than falling back |
| `run(...)` | `subprocess.run` over `docker_argv` |
| `container_env() -> dict` | HOME / cache variables, defined once for both phases |
| `host_warning(n, what) -> str` | the `--no-docker` banner text |
| `image_tag(*inputs) -> str` | the content-derived tag (§8) |

Every container gets `--rm`, `--cap-drop=ALL`, `--security-opt no-new-privileges` and
`-u <uid>:<gid>`. Exactly three things are mounted: the per-package work directory
(read-write — the only writable host path, and the only one results come back out of), the
cache volume, and the repository at `/src` **read-only**.

The repo mount is there because the harness must test the working tree rather than a copy
baked into the image; read-only is what makes that acceptable, since a hostile sdist build
backend runs with the repository in its filesystem namespace. The docker socket is never
mounted, and `$HOME` is never mounted.

`container_env()` exists because of a bug this ADR's first implementation shipped: the
runners set `HOME=/cache`, which moved HOME away from the path the image was built with and
silently orphaned the launcher's pinned nimble dependencies in `/opt/haru/.nimble`. It
surfaced four minutes into a build as `cannot open file: nimcrypto/sha2` — a message that
reads like a missing pin rather than a misrouted environment variable. One definition, used
by both phases and both harnesses.

## 4. Two containers per package

```
build:  docker run --network bridge  -v <work>:/w  -v haru-flex-cache:/cache  -v <repo>:/src:ro  <image>  haru-pack build /w/proj -o /w/exe --tier T
run:    docker run --network <N>     -v <work>:/w  -v /cache                                     <image>  /w/exe
```

Per-package rather than one container for the whole matrix: a package that corrupts its own
environment cannot carry that into the next package's result, and each run phase gets its
own network decision.

The two phases get **different caches**, and that is the point. The build phase gets the
shared named volume, because it is what stops a 25-package matrix downloading a toolchain 25
times. The run phase — where the package's own code executes — gets an **anonymous** volume
that docker creates empty and `--rm` destroys, so stranger code never sees the shared cache
in either direction.

**Correction to this ADR's first draft**, which gave the run phase the shared volume mounted
`:ro`. That is unimplementable: a thick binary stages into `$XDG_CACHE_HOME` before it can
execute, so the first real end-to-end run died with
`OSError: Read-only file system /cache/haru-pack/<hash>.tmp-1`. It was also weaker than it
looked — `:ro` still let a package read every other package's fetched artifacts. There is now
no read-only cache mode at all, and a test asserts its absence, because "mount the shared
cache read-only" reads as the cautious choice and would be reached for again.

`<N>` is the honest part, and it is not "always none":

| tier | run-phase network | why |
|---|---|---|
| `default`, `thin` | `bridge` | the dependency is **supposed** to be fetched on first run. Denying the network here would test nothing and fail everything. |
| `thick` | **`none`** | the payload is supposed to carry uv, the interpreter and every dependency. Network access during this run is the defect being tested for. |

## 5. `--offline-check` stops being approximate

`tools/flex-run.py` currently says of itself:

> Note this is not a network namespace (this box cannot create one). It forces uv offline
> and points the proxy variables at a dead port, which blocks the fetch path that matters;
> it does not stop a package from opening a raw socket of its own.

`--network none` plus a **cold** cache (a fresh anonymous volume, not the shared named one)
replaces that with a real network namespace. A package can open any socket it likes and
there is no interface for it to open one on.

This is the part of this ADR that makes an existing result *stronger*, not merely safer.

**Correction to this ADR's first draft**, which said `_offline_env()` would be *deleted*: it
is not, it is demoted. The host path cannot create a network namespace, so deleting it would
have made `--no-docker --offline-check` either a no-op or a lie. It survives as the host
runner's approximation, its docstring now says which of the two mechanisms it is, and results
produced under it print as `carried*` rather than `carried` in the summary. Two mechanisms
are a hazard only when the reader cannot tell which one produced the number in front of them.

## 6. Enforcement, and the escape hatch

- Sandboxed is the default for both tools.
- `--no-docker` runs on the host and prints, to stderr, a banner naming the package count and
  what is in scope. It is written to print before anything executes; what a test checks is the
  banner's *contents*, not when it is emitted (§10).
- Docker missing **without** `--no-docker` is a hard error that names the flag. There is no
  silent fallback to the host path: a silent fallback is how a safe default quietly stops
  being the default, and nobody finds out until they read the code.

## 7. Rootless docker: preferred, detected, warned about — not required

The target posture is a rootless daemon, where the container's root maps to an unprivileged
host uid and the socket is not a root-equivalent handle.

The daemon on the primary dev host is currently **rootful** (`DockerRootDir=/var/lib/docker`,
root-owned `/var/run/docker.sock`, docker 27.3.1), measured 2026-09-14. So:

- `sandbox.rootless()` detects the mode.
- A rootful daemon produces a loud, named warning and proceeds.
- `--require-rootless` makes it fatal, for CI and for anyone who wants the stronger line.

Warn rather than refuse, deliberately: refusing on the box this was written to protect would
send its own author to `--no-docker`, which is strictly worse than a rootful container.
`docs/ROOTLESS_DOCKER.md` documents the switch-over.

## 8. Why the image builds its toolchain through `haru bootstrap`

`docker/flex.Dockerfile` pins its base image by digest and then installs Nim, zig and uv by
running `haru bootstrap` **inside the image build**, rather than by a hand-written
`apt-get` + `curl` layer.

A Dockerfile that curls its own toolchain is a second acquisition path, with its own
versions and its own (absent) digest checks, sitting next to the pinned-and-verified one in
`pins.toml` that `INV-SUPPLY-01` covers. Two paths means the audited one is not the one that
runs.

uv is the one piece that cannot come from `haru bootstrap`, because a thick build shells out
to `uv sync` and so needs it on `PATH` before haru-pack runs at all. `docker/install-uv.py`
reads the same `pins.toml`, verifies the digest before use, and **refuses** an artifact with
no entry rather than downloading it — the same rule `haru_pack.pins` applies. It duplicates
thirty lines of that logic knowingly: it runs during `docker build`, before haru-pack is
importable, and a bootstrap step that imports the thing it is bootstrapping is the worse
problem.

**Correction to this ADR's first draft**, which claimed the bootstrap route made the image
"arch-agnostic for free". It does not. `haru_pack.toolchain` documents that choosenim
publishes binaries for linux x86_64, macOS x86_64/arm64 and Windows, and **nothing for linux
aarch64**.

**Resolved 2026-09-15 (issue #32).** The image now builds for linux/amd64 *and* linux/arm64,
and the way it gets a compiler is governed by `NIM_FROM`:

| `NIM_FROM` | what it does |
|---|---|
| `auto` (default) | choosenim where upstream publishes for it; otherwise our pinned prebuilt binary; otherwise compile from the pinned source |
| `binary` | a pinned binary only — **fails** rather than quietly compiling for an hour |
| `source` | compile from the pinned source; never run a Nim binary this project published |
| `system` | use the Nim already present; fetch and compile nothing |

Compiling is the **fallback**, not the plan. Bootstrapping Nim means compiling roughly eleven
thousand C files, and there is no reason an arm64 user should pay that when the platforms
choosenim covers do not. So `.github/workflows/nim-aarch64.yml` builds one, from the source
tarball already pinned in `pins.toml`.

The second half of that — pinning the result — has **not happened yet**, and `auto` therefore
still compiles on arm64. The workflow uploads the tarball and prints its sha256 with an
instruction to add the pin by hand; it does not write `pins.toml`, and `pins.toml` has no
`variant = "binary"` entry, only a comment saying where one goes. That is on purpose for now:
while this repository is private an unauthenticated fetch of a release asset cannot work, so a
pin pointing at one would be a pin nobody can use. The intended end state is a binary pin that
is the primary path, with compiling behind it.

Two of those modes exist for **opposite** reasons and both are legitimate: someone on a slow
arm64 box wants `binary` and would rather fail than wait, and someone who declines to execute
a compiler this project built wants `source` and would rather wait than trust it. A single
"offline" or "no-download" switch would have served only one of them.

**The provenance rule is different for an artifact we publish.** Pinning a third-party
artifact asserts "this is what the publisher published". Pinning our own asserts "this is what
*we* built" — a weaker claim, worth very little if the only evidence is that somebody ran a
command on hardware nobody else can see. So a `variant = "binary"` pin's `provenance` must be
the **workflow run URL**, and a test asserts it. Building it on a maintainer's Raspberry Pi
would have been faster and is specifically what this rules out.

The build runs under QEMU on an amd64 runner today, because free arm64 runners are
public-repo-only and this repository is not public yet. When it goes public, `runs-on` becomes
`ubuntu-24.04-arm`, the QEMU step goes, and the job takes minutes instead of an hour.

The image tag is a hash of `flex.Dockerfile` + `pins.toml`, so bumping a pin rebuilds the
image and a stale image cannot be silently reused.

## 9. What this does NOT claim

- **It does not make `haru-pack build` safe for an operator packing an untrusted tree.**
  `INV-TRUST-02` stays `proposed`. This ADR moves *haru-pack's own test harnesses* into a
  box; the tool's behaviour on a customer's machine is unchanged.
- **The shared cache is a real, stated residual risk — in the BUILD phase.** That phase needs
  the uv cache read-write, and it is shared across packages so that a 25-package run does not
  download a toolchain 25 times. A malicious sdist build backend therefore writes into a cache
  a later package's build reads. It is confined to a docker volume and never touches the host
  filesystem, but it is not zero. `docker volume rm haru-flex-cache` resets it; running
  one package at a time is the only way to avoid it entirely today.
  The **run** phase does not share this risk: it gets an anonymous volume and never sees the
  shared one.
- **A container is not a VM.** A kernel exploit leaves the box. Rootless narrows this; it
  does not close it.

## 10. Invariants

`INVARIANTS.md` is the source of truth for both of these and is narrower than this ADR's first
draft was. What follows is the narrowed form; where the two disagree, that file wins.

### INV-SANDBOX-01
`tools/flex-run.py` and `tools/exam.py` contain no path that executes a built artifact outside
the sandbox runner — the `subprocess.run([str(exe)], …)` shape appears only inside `HostRunner`
— and the container argv the runner builds never mounts the docker socket, mounts this
repository read-only or not at all, gives stranger code no writable host path but the
per-package work directory, and never mounts the shared cache into a phase where package code
runs. `sandbox.preflight` raises when docker is unavailable, naming `--no-docker`, rather than
returning a host fallback, and `sandbox.host_warning` names `$HOME`, SSH keys and credentials.

*Red-path:* mount the docker socket, drop `:ro` from the repository mount, mount the shared
cache into the run phase, or move the `subprocess.run([str(exe)], …)` line out of `HostRunner`
— a claiming test goes red on each.

**What is not covered: the call sites.** What is checked is the argv, the shape of two
functions' output, and the absence of a second execution path. Nothing asserts that the
harness calls `preflight` before it picks a runner, that the banner is printed before the
first build rather than after it, or that `DockerRunner` is what gets selected by default.
This ADR originally said the harnesses "execute third-party package code only inside a
container" and that the warning prints before anything is built or run. Both were ordinary
code reading wearing a machine-checked fact's clothes, and both are gone from the Statement.
Treat the gap as work outstanding, not as a nuance.

### INV-SANDBOX-02
Asked for a run with no network and a cold cache, `sandbox.docker_argv` produces an argv that
gives the container `--network none` — no interface at all, not a blocked one — and a fresh
anonymous cache volume rather than the warm shared one; asked for a networked run it produces
`--network bridge`, never `--network host`.

*Red-path:* replace the network expression **inside `docker_argv`** with a constant, or hand
back the warm named cache for a cold request. The claiming tests read the argv `docker_argv`
produces and go red on either.

**What is not covered: the call site.** Which runs are the offline ones is decided in
`tools/flex-run.py` — `network=not offline` and `cache=sandbox.CACHE_COLD` — and no test reads
either line. The claiming tests pass `network=False, cache=CACHE_COLD` in as their own fixture
and assert those values came back out, so what is proved is that `docker_argv` is faithful to
the mode it is handed, not that a thick run is ever handed the offline mode. Change
`not offline` to `True` and every test in this family stays green while `results.json` keeps
printing `carried`. Closing it needs a test that reads the call site — the shape
`test_no_harness_executes_a_built_binary_except_through_the_sandbox` already uses for a
different rule — or an end-to-end run that watches a thick binary fail to reach the network.

Both are claimed by `tests/test_sandbox.py`, which asserts over `docker_argv()` output and
needs neither docker nor a network. Exactly one rule in this section is checked anywhere other
than the argv builder: `test_no_harness_executes_a_built_binary_except_through_the_sandbox`
reads the harness files themselves and asserts none of them executes a built binary except
through `sandbox`. It is deliberately the one that matters most, and it is also the only one,
which is the shape of the gap described above.

# ADR 0005 — the flex and exam harnesses run stranger code in a container, not on the host

- Status: accepted (contract)
- Date: 2026-09-14
- Scope: `tools/flex-run.py` and `tools/exam.py` — the two harnesses that fetch real
  packages from PyPI, build them, and then execute them. Adds one shared runner
  (`tools/_sandbox.py`), one committed image (`docker/flex.Dockerfile`), and the
  `INV-SANDBOX` family. Does **not** cover `tools/busybody.py`, which keeps its own
  `_docker_run` for the quotamaster persona this round (§8), nor the pytest suite itself.
- Vocabulary: *host path* — the harness running directly on the developer's machine.
  *Sandboxed path* — the harness running each package's build and run inside its own
  throwaway container. *Build phase* / *run phase* — the two containers a single package
  gets (§4).
- Invariants: `INV-SANDBOX-01` (container by default, host path opt-in and announced),
  `INV-SANDBOX-02` (a thick verification run has no network interface). Both are claimed
  by tests in `tests/test_sandbox.py` whose Red-path was walked. Partially answers
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

## 3. `tools/_sandbox.py` — one runner, and a pure function at the center

The containment decision is made by a **pure function** that returns an argv list:

```python
def docker_argv(image, *, cmd, work, network, cache, uid, gid, extra=()) -> list[str]
```

This is the load-bearing design choice in the whole ADR. It means the properties that
matter — that a thick run gets `--network none`, that the cache is read-only during the run
phase, that the docker socket is never mounted — are assertable by a unit test that runs
**offline, in CI, on a box with no docker installed**. A containment guarantee that can only
be checked by running docker is a guarantee that gets checked when someone remembers.

The rest of the module is thin:

| function | does |
|---|---|
| `available() -> str` | `""` if docker can run, else the reason |
| `rootless() -> bool` | whether the daemon is rootless (§7) |
| `ensure_image() -> str` | build the image if stale; return `image:tag` |
| `run(...)` | `subprocess.run` over `docker_argv` |
| `host_warning(n) -> str` | the `--no-docker` banner text |

Every container gets `--rm`, `--cap-drop=ALL`, `--security-opt no-new-privileges`,
`-u <uid>:<gid>`, and no mounts except the per-package work directory and the cache volume.
The docker socket is never mounted; `$HOME` is never mounted.

## 4. Two containers per package

```
build:  docker run --network bridge  -v <work>:/w  -v haru-flex-cache:/cache     <image>  haru-pack build /w/proj -o /w/exe --tier T
run:    docker run --network <N>     -v <work>:/w  -v haru-flex-cache:/cache:ro  <image>  /w/exe
```

Per-package rather than one container for the whole matrix: a package that corrupts its own
environment cannot carry that into the next package's result, and each run phase gets its
own network decision.

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
there is no interface for it to open one on. `_offline_env()` and its dead-proxy trick are
deleted rather than kept as a belt: two mechanisms where one is real invites the reader to
assume the wrong one is doing the work.

This is the part of this ADR that makes an existing result *stronger*, not merely safer.

## 6. Enforcement, and the escape hatch

- Sandboxed is the default for both tools.
- `--no-docker` runs on the host and prints, to stderr, before anything executes, a banner
  naming the package count and what is in scope.
- Docker missing **without** `--no-docker` is a hard error that names the flag. There is no
  silent fallback to the host path: a silent fallback is how a safe default quietly stops
  being the default, and nobody finds out until they read the code.

## 7. Rootless docker: preferred, detected, warned about — not required

The target posture is a rootless daemon, where the container's root maps to an unprivileged
host uid and the socket is not a root-equivalent handle.

The daemon on the primary dev host is currently **rootful** (`DockerRootDir=/var/lib/docker`,
root-owned `/var/run/docker.sock`, docker 27.3.1), measured 2026-09-14. So:

- `_sandbox.rootless()` detects the mode.
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
runs. Going through `haru bootstrap` also makes the image arch-agnostic for free, which
matters because the long-run box is arm64.

The image tag is a hash of `flex.Dockerfile` + `pins.toml`, so bumping a pin rebuilds the
image and a stale image cannot be silently reused.

## 9. What this does NOT claim

- **It does not make `haru-pack build` safe for an operator packing an untrusted tree.**
  `INV-TRUST-02` stays `proposed`. This ADR moves *haru-pack's own test harnesses* into a
  box; the tool's behaviour on a customer's machine is unchanged.
- **The shared cache is a real, stated residual risk.** The build phase needs the uv cache
  read-write, and it is shared across packages so that a 25-package run does not download a
  toolchain 25 times. A malicious sdist build backend can therefore write into a cache a
  later package reads. It is confined to the volume, never touches the host filesystem, and
  the run phase mounts it `ro` — but it is not zero. `--cold-cache` forces a fresh volume
  per package for anyone who wants to pay for it.
- **A container is not a VM.** A kernel exploit leaves the box. Rootless narrows this; it
  does not close it.

## 10. Invariants

### INV-SANDBOX-01
The flex and exam harnesses execute third-party package code only inside a container. The
host path is opt-in via an explicit flag and prints, before executing anything, a warning
naming what is about to run and what is in scope.

*Red-path:* flip the default so the host path runs without the flag, or delete the banner —
the claiming test goes red on either.

### INV-SANDBOX-02
A thick binary's verification run is executed with no network interface at all, against a
cache that has never been used.

*Red-path:* change the run phase's `network=False` to `True` for the thick tier, or reuse
the warm named cache instead of a cold volume. The claiming test reads the argv `docker_argv`
produces and goes red on either.

Both are claimed by `tests/test_sandbox.py`, which asserts over `docker_argv()` output and
needs neither docker nor a network. A call-site test in the style of
`tests/test_stage_callsites.py` additionally asserts that no harness file executes a built
binary except through `_sandbox`.

# haru-pack — threat model

The reasoning layer. `INVARIANTS.md` is the checkable contract; this file is the argument
that produced it. Adopted from lotek's paired-file pattern.

Every claim carries a provenance marker:

- **[V]** — verified in this repo, by a test or by direct observation of the code.
- **[R]** — relayed: believed true from documentation or prior art, not checked here.

Mixing the two silently is how a "we handle that" ends up in a document with nothing
behind it. This project already did that twice; see the corrections in `docs/SIGNING.md`
and `docs/ENCRYPTION_LICENSING.md`.

## Worst case

A vendor signs a haru-pack binary with an EV certificate and ships it to their customers.
That binary is a **self-extracting stager that runs code from an appended blob**, resolves
tools from the environment, and — at the `thin` tier — downloads and executes an
interpreter and a package manager at runtime on the customer's machine.

If the blob or any of those downloads can be influenced, the attacker is executing code
under the vendor's signature, on the vendor's customers' machines, with the vendor's
reputation attached. haru-pack's failure mode is not "our tool breaks"; it is "our tool
becomes a distribution channel."

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| The payload | appended to the launcher | contains the application AND `pre_install`/`post_install` argv the launcher executes |
| The vendor's code-signing identity | the signed PE | the whole reason to buy an EV cert |
| The build host's toolchain | Nim, uv, mingw, python-build-standalone | compromise here contaminates every artifact built afterwards |
| The operator's own secrets | `.env`, keys, sitting in the project directory being packed | packaged and distributed by accident — the highest-likelihood incident in this list |
| The license secret | `--secret`, `HARU_SECRET` (default canary), or embedded | the only trust anchor; there is no PKI |
| The customer's machine | the staging cache, PATH, environment | where the launcher does its work |

## Actors

| Actor | Capability | Motivation |
|---|---|---|
| The licensee | full control of the machine, the binary, the clock, the environment | run the software outside the license terms |
| A tampering distributor | can modify the binary in transit or on a mirror | get code executed under the vendor's signature |
| A local attacker on the target | can write to the cache, PATH, or environment of the user running the launcher | hijack execution via the launcher |
| A compromised upstream | serves Nim, uv, or python-build-standalone releases | reach every build host, then every artifact |
| The operator | not hostile — busy | ships a `.env` by accident |
| **The project being packaged** | supplies the source tree, its `pyproject.toml`, its `haru_pack.toml`, its dependency list and the symlinks in it | get code executed on the build host, or bytes into the signed artifact |
| An AI agent working on this repo | writes code and the documentation that describes it | not hostile; produces confident text about work it did not do |

The packaged-project row was added 2026-09-11, after the `trojan` busybody persona
demonstrated six ways to use it. It had been missing on the assumption that the operator
writes what they pack — which holds for `haru-pack build .` in your own repository and
nowhere else. `haru-pack build` is run against clones from the internet, against branches
that arrive in CI, and against applications an agent wrote that nobody read line by line.
In all three the operator is trusting the tree, and nothing told them that is what they
were doing.

The AI row is deliberate too. It is the actor this repo has actual incident history with.

## Trust boundaries

| # | Boundary | Crossing | Status |
|---|---|---|---|
| B0 | project source → **build host** | `copytree`, `uv sync --project`, `[[bundle]]` argv | **[V]** *no boundary*: project-controlled code runs, `INV-TRUST-01`/`02` (proposed) |
| B1 | project source → payload | `shutil.copytree` with an exclusion list | **[V]** filtered by NAME only; symlinks are dereferenced, `INV-PAYLOAD-01` + `INV-TRUST-06` (proposed) |
| B2 | payload → launcher overlay | append + footer (68B v1, 116B v2) | **[V]** digest checked at build (`INV-PAYLOAD-02`) and again at launch (`INV-LAUNCH-01`); a footer, not a signature |
| B3 | overlay → running process | launcher reads its own image and stages it | **[V]** digest verified before staging or executing, `INV-LAUNCH-01`; recomputable from the same footer — `INV-LAUNCH-03` (proposed) is the fix |
| B4 | environment → launcher behavior | `HARUPACK_DEV_STAGE` (dev-only), the SECRET knob's per-build canary env name, PATH | **[V]** `INV-LAUNCH-02`/`04`, `INV-CANARY-01`/`03`; location reads no env at all (`INV-GEO-01`) |
| B5 | network → build host | Nim, uv, python-build-standalone downloads | **[V]** the choosenim installer, the zig archive, the uv asset and the interpreter are each pinned by digest in this repo, `INV-SUPPLY-01`; the Nim toolchain choosenim then fetches is verified by choosenim, not here |
| B6 | network → customer machine | `thin` tier fetches uv at runtime | **[V]** checked against the `uv_sha256` the build baked into the manifest, `INV-SUPPLY-05`/`INV-SUPPLY-01`; TLS unpinned |
| B7 | archive → filesystem | tar/zip extraction on both host and target | **[V]** host filtered (`INV-SUPPLY-03`); target entry paths refused by our own check before extraction (`INV-STAGE-02`), with `zippy`'s own check behind it |
| B8 | secret → key | PBKDF2-HMAC-SHA256, 200k iterations | **[V]** `crypto.derive_key`, `KDF_ITERS`; no invariant pins the KDF parameters, so this row is code observation, not contract |
| B9 | container → plaintext | AES-256-GCM, AAD = the whole header except the tag | **[V]** header and body both authenticated, `INV-CRYPTO-04` |
| B10 | staging cache → execution | `.ready` token + per-file digests, re-verified every launch | **[V]** `INV-STAGE-01`; no defence against an attacker already running as the same user |

## What the licensing feature actually does

Stated plainly because the sales-shaped version of this is easy to write and wrong.

- **Machine and user binding are both cryptographic, and they are not equally strong.**
  Each value is folded into the KDF, so a wrong value yields a wrong key and decryption fails
  outright rather than being checked and waved through. **[V]** `crypto.derive_key` appends
  each to the PBKDF2 password, and `INV-CRYPTO-03` is what makes a wrong key a hard
  authentication failure rather than a check something could skip. No invariant pins the KDF
  parameters themselves. What the two bind *to* is where they diverge, and until 2026-09-15
  this section hedged `/etc/machine-id` carefully and gave the weaker of the two no hedge at
  all, which is how a reader concluded the unhedged one was solid:
  - *Machine.* `/etc/machine-id` on Linux is a root-writable file; on Windows and macOS
    `cryptbox.machineId` shells out to `reg` and `ioreg` by bare name, so the answer is
    only as trustworthy as the target's PATH. **[V]** `launcher/cryptbox.nim`. It binds to
    a value the target *reports*, not to hardware — but reporting a different one takes
    deliberate work.
  - *User.* `cryptbox.currentUser()` is `getEnv("USER")` with a `USERNAME` fallback. **[V]**
    `launcher/cryptbox.nim:83`. That is a string the licensee types: `USER=alice ./app` is
    the whole attack, with no patching, no root and no debugger. `--user` is a label on the
    key, not a binding to a person.
- **Expiry is not enforcement. Geo is enforcement only against someone who is not trying.**
  Expiry reads the local clock, which belongs to the person being restricted, and runs after
  decryption inside a binary they control. **[V]** Geo no longer reads an environment
  variable at all: the `HARUPACK_GEO` bypass is gone, the policy travels inside the
  ciphertext, and `tests/test_canary.py` fails the build if a launcher source reads a plain
  `HARU…` env name again (the one whitelisted exception is the dev-only `HARUPACK_DEV_STAGE`,
  which is not in a release binary). **[V]** `INV-GEO-01`, `INV-CANARY-03`. It resolves online and
  fails closed offline, which is a real check — but the HTTP call happens on the end user's
  own machine, so their proxy, CA trust and DNS decide what it returns. Real against a casual
  user, advisory against a determined one; see `INV-GEO-01`'s honest limit, which is
  load-bearing. Neither field stops someone who is trying.
- **The embedded-secret mode is obfuscation.** The secret is XOR'd against a constant
  string published in this repo's source. **[V]** The code says so; make sure the sales
  page does too.
- **Local execution has a ceiling.** The machine must decrypt to run. Against a determined
  reverse-engineer with a debugger, none of this holds. For hard enforcement, add a server.

## What `--overwrite` (shred-on-reap) actually does

Stated plainly because "secure erase" is the sales-shaped version and it is wrong.

`--overwrite` makes the detached reaper overwrite each staged file's full logical extent with
matching-length random bytes and `fsync` BEFORE unlinking (`INV-SHRED-01`). What it BUYS is
narrow and real: it defeats **simple logical file-undelete** (Recuva/PhotoRec/TestDisk) on a
**non-copy-on-write filesystem on a spinning disk**. **[V]** the overwrite covers the whole
logical extent and is durable before the unlink (tests/test_shred.py).

What it does NOT do — and must never be labelled "secure erase" / "unrecoverable." Each caveat
hits the **overwrite itself**, not just the delete:

- **SSD FTL / wear-leveling.** In-place overwrite is a fiction: the controller writes to a fresh
  erase block and remaps the LBA; the old block (plaintext) sits in over-provisioning until GC.
  Matching byte count occupies the **logical** range, not the **physical** cells (LBA ≠ PBA).
  Recovery is chip-off / vendor forensics, not "simple tools." **[R]**
- **Copy-on-write filesystems and snapshots.** APFS (macOS default), Btrfs, ReFS, ZFS never
  overwrite a live block in place, so the original extent survives; and snapshots pin it
  regardless — APFS local snapshots, **Windows VSS** (commonly on), Time Machine, Btrfs
  snapshots can hand the plaintext back. macOS default APFS ⇒ largely ineffective. **[R]**
- **May never reach disk / may reach extra places.** `fsync` between overwrite and unlink is
  mandatory or the FS may drop the dirty overwrite. Journals (ext4 `data=journal`, NTFS
  `$LogFile`) may keep fragments. Swap / hibernation may hold the decrypted model — file
  shredding cannot reach it. **[R]**

**The stronger control (the recommended path).** The durable defense for "don't leave my model
recoverable" is to **never write plaintext to the block device**: ship the model **encrypted**
(cryptbox / AES-256-GCM, already present — `INV-CRYPTO-03`/`04`) and use `--ephemeral` so it
decrypts only to `/dev/shm` (Linux, RAM) — then there is **nothing to shred**, no FTL remnant,
no CoW extent, no VSS snapshot. `--overwrite` is belt-and-suspenders for plaintext that
unavoidably touches disk on Windows/macOS (where there is no unprivileged RAM disk). This is the
doctrine; `--overwrite` is not a substitute for it.

**But `--encrypt --ephemeral` is NOT an absolute "nothing plaintext reaches disk" (docs/adr/0007 §5).**
Two paths put the decrypted tree on disk despite the intent, and an operator who assumes otherwise
is wrong in exactly the way this document exists to prevent:

- **Low-RAM fallback.** `--ephemeral` stages to RAM only when the payload provably fits free
  memory (the fit check — `INV-EPHEMERAL-01`). On a small-RAM target — a 512 MB CI runner, a small
  VPS, a memory-capped container — it **falls back to the persistent cache on disk**, and the
  decrypted tree is then a plaintext blob on the block device. This is an *availability* fallback,
  not an attacker-controlled one: the `EPHEMERAL` runtime knob is 2-state and can only *enable* RAM
  (`=1`), never force disk, precisely so a target cannot downgrade an encrypted payload onto disk by
  setting an env var (`INV-EPHEMERAL-03`).

The fallback tree **is reaped**, but a plain unlink is recoverable; add **`--overwrite`** so the
fallback is shredded on reap (still bounded — not a secure erase, per the section above). The build
**warns** when `--encrypt` and `--ephemeral` are combined, naming the low-RAM fallback and
recommending `--overwrite`. The only way to guarantee no plaintext ever reaches disk is a target you
know has the RAM — which the packager cannot enforce from the build. **[R]**

## The AI-development threat

lotek's process retrospective names the defect precisely: *"the agent's failure mode in
this repo is monotonous: over-claiming verification."* haru-pack's first adversarial review
found the same pattern, uncontested — there was nothing in the repo capable of contradicting
a confident sentence.

The mitigations adopted here are deliberately cheap, because expensive controls get
bypassed (lotek measured a security gate overridden 54 times against 6 successful blocks):

1. **`INV-DOC-02`** — a dated "Verified"/"Validated" doc section must cite an invariant id.
   Prose evidence is satisfiable by a claim; a citation is not. **[V]** It failed against
   both of this repo's existing footers on the first run.
2. **`INV-DOC-01`** — every cited invariant id must resolve to a declared entry, so an
   agent cannot sprinkle plausible-looking invariant references around as decoration.
   **[V]** It caught an invented id in its own docstring on the first run, and another in
   the first draft of this very section. Both times the id was illustrative rather than
   dishonest, which is the point: the scanner does not need to guess intent.
3. **`Status: proposed`** — a gap gets an entry with zero claiming tests, rather than
   silence or an aspirational sentence. Fourteen of the 113 entries are proposed as of
   2026-09-15, seven of them the `INV-TRUST-*` family.
4. **Mandatory Red-path** — an invariant you cannot describe breaking is not an invariant.
   This is the field that converts "we test that" into "here is how you would see it fail."
5. **`TestGuardCanFail`** — the linkage checker is fed synthetic violating input, so a
   parser bug cannot make the whole contract pass vacuously.

None of this proves efficacy. The Red-path is walked by a human, or by an agent that then
pastes the red output. A green suite means the claims are *linked* to tests, which is
strictly more than this repo had, and strictly less than proof.

## Known gaps, ranked

Re-cut against the tree on 2026-09-15. Three entries that used to sit at the top of this list
described the repo as it stood before the fixes of 2026-09-09 and are gone: the launcher not
verifying its payload, a `HARUPACK_DEV_STAGE` bypass in release builds, and the launcher having
no error handling. `INV-LAUNCH-01`, `-02` and `-06` are all `active` with walked Red-paths. What
replaces them is narrower, and still real.

1. **The payload digest is not a MAC.** `INV-LAUNCH-01` is active — the launcher refuses to
   stage or execute a payload whose SHA-256 does not match the digest in its own footer — but
   that digest lives in the same footer an attacker would edit, so whoever rewrites the payload
   recomputes the 32 bytes and still executes. What the check buys is detection of corruption,
   truncation and naive edits, plus a precondition for the real fix. Tamper-evidence needs a
   signature (`INV-LAUNCH-03`, proposed) or Authenticode over the overlay on Windows; ELF output
   has no equivalent.
2. **The project being packaged is trusted absolutely.** Its build backend runs during
   dependency staging, its `[[bundle]]` argv runs unannounced, its symlinks are followed out of
   the tree, its `index-url` chooses where the shipped wheels come from, and an `app_subdir` of
   `.` puts its files where the launcher's control files live. `INV-TRUST-01` through `-07`, all
   proposed, six of the seven demonstrated on 2026-09-11 by the `trojan` busybody persona. This
   is the only gap on this list that has been walked end to end by an attacker.
3. **Digest pinning stops at the first hop.** `INV-SUPPLY-01` names what this repo pins — the
   choosenim installer, the zig archive, the uv release asset and the python-build-standalone
   interpreter — and `INV-SUPPLY-05` covers the thin tier's runtime `uv` fetch, so the blanket
   "nothing is digest-checked" is no longer true. Three things are still unverified *by this
   repository*, and two of them reach shipped artifacts:
   - **The Nim compiler, on a host build.** Only the choosenim *installer* is verified against
     `pins.toml` (`toolchain.py`); choosenim then downloads the whole toolchain on its own terms
     and verifies it on its own terms, and nothing here hashes what it wrote. Blast radius: that
     compiler builds the launcher in every binary shipped afterwards. The one exception is the
     aarch64 docker image, where `docker/install-nim-binary.py` / `install-nim-source.py` fetch a
     Nim pinned in `pins.toml` and refuse an unpinned one — it exists because choosenim publishes
     no `linux_arm64` asset at all.
   - **The nimble libraries linked into the launcher.** `bootstrap.NIM_DEPS` pins zippy, puppy,
     parsetoml and nimcrypto to exact versions via `nimble install pkg@ver`. A version is not a
     digest, and a compromised nimble package at the pinned version is fetched and linked.
   - **The PyPI sdists `tools/exam_fetch.py` downloads**, read straight off `urlopen` with no
     hash. This one is a dev tool and its bytes do not enter a customer deliverable.
4. **Those nimble pins are requested, not enforced.** `INV-SUPPLY-02` stays `proposed` for
   exactly this: `build.compile_launcher` runs a bare `nim c` with no `--nimblePath`, no lockfile
   and no project `.nimble`, so Nim resolves each import to the HIGHEST version present in the
   multi-version package directory. Pinning the installer controls which versions arrive, not
   which one links. Nothing verifies which nimcrypto is inside a shipped launcher, so any
   statement about the launcher's crypto implementation is about what was requested.
5. **The staging cache cannot defend against the same user.** `INV-STAGE-01` retired the
   trust-on-first-use short circuit: a stage is reused only if it is a user-owned, non-group-
   and non-world-writable directory whose `.ready` names this exact payload digest and whose
   every recorded file still hashes correctly. Residual and unclosable here — every input to
   that token is readable from the binary being attacked, so an attacker already running as the
   same user rewrites the tree and regenerates the token together. Closing it needs an OS
   boundary, not a checksum. Ownership and mode are POSIX-only; there is no Windows ACL
   equivalent in the check.
6. **The Nim side is now run by CI; what is left is how little of it the tests cover.**
   `tests/test_crypto_hardening.py` compiles `cryptbox.nim` and runs the real decryptor against
   Python-written containers, and `tests/test_geo_gate.py` compiles and runs the location gate.
   Both `pytest.skip` when `shutil.which("nim")` is None, which used to mean they skipped on CI.
   That is fixed: `.github/workflows/ci.yml` has an `install nim` step that runs `haru-pack
   bootstrap --minimal --yes`, resolves the compiler through `bootstrap.find_nim()`, fails the
   job if none is findable, and appends its directory to `$GITHUB_PATH`. **[V]** read off the
   workflow 2026-09-15. A regression to the old state cannot pass as green either:
   `tests/_invariant_execution.py` fails the session when every selected claimant of an active
   invariant skipped, and the workflow deliberately does not set `HARUPACK_INVARIANT_SKIPS_OK`.
   **[V]** Two residuals, neither of them the environment. First, that guard fires only when
   *all* of an invariant's selected claimants skipped, so one skipped test beside a sibling that
   ran is invisible to it. Second: what CI now runs is a set of per-behavior slices, not the
   launcher as a whole — these two files cover the container format, the decryptor and the
   location gate, and `test_stage_hardening.py`, `test_shred.py`, `test_remote_fetch.py`,
   `test_ephemeral_safe.py` and `test_launcher_integrity.py` each compile a launcher for their
   own. No test in the suite builds a binary and runs it end to end — that proof lives in
   `tools/flex-run.py`, which needs a toolchain and minutes and which CI does not run — and
   `INV-CRYPTO-02` is still a parse of byte offsets rather than an execution.

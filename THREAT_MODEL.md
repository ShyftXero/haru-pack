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
| B2 | payload → launcher overlay | append + 68-byte footer | **[V]** build-time digest only, `INV-PAYLOAD-02` |
| B3 | overlay → running process | launcher reads its own image and stages it | **[V]** *unverified at runtime*, `INV-LAUNCH-01` (proposed) |
| B4 | environment → launcher behavior | `HARUPACK_DEV_STAGE` (dev-only), `HARU_SECRET` (SECRET-knob canary), `HARUPACK_GEO`, PATH | **[V]** `INV-LAUNCH-02`/`04`, `INV-CANARY-01` |
| B5 | network → build host | Nim, uv, python-build-standalone downloads | **[V]** TLS only, no digest, `INV-SUPPLY-01` (proposed) |
| B6 | network → customer machine | `thin` tier fetches uv at runtime | **[V]** TLS only, no digest, `INV-SUPPLY-01` (proposed) |
| B7 | archive → filesystem | tar/zip extraction on both host and target | **[V]** host filtered (`INV-SUPPLY-03`); target relies on `zippy`, **[R]** unverified here |
| B8 | secret → key | PBKDF2-HMAC-SHA256, 200k iterations | **[V]** `INV-CRYPTO-03` |
| B9 | container → plaintext | AES-256-GCM, AAD = fixed magic | **[V]** body authenticated, header not: `INV-CRYPTO-04` (proposed) |
| B10 | staging cache → execution | `<cache>/<key>/.ready` short-circuit | **[V]** trust-on-first-use, no invariant yet |

## What the licensing feature actually does

Stated plainly because the sales-shaped version of this is easy to write and wrong.

- **Machine and user binding are real.** The identity is folded into the KDF, so a
  different machine id yields a different key and decryption fails. **[V]**
  `INV-CRYPTO-03`. Caveat: `/etc/machine-id` is a writable file. This binds to a value
  the target *reports*, not to hardware.
- **Expiry and geo are not enforcement.** Geo reads `HARUPACK_GEO` — the environment
  variable of the person being restricted. Expiry reads the local clock, also theirs.
  Both run after decryption, inside a binary they control. **[V]** They raise the effort
  bar and make accidental misuse visible. They stop nobody who is trying.
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
   silence or an aspirational sentence. Eight of the nineteen entries are proposed.
4. **Mandatory Red-path** — an invariant you cannot describe breaking is not an invariant.
   This is the field that converts "we test that" into "here is how you would see it fail."
5. **`TestGuardCanFail`** — the linkage checker is fed synthetic violating input, so a
   parser bug cannot make the whole contract pass vacuously.

None of this proves efficacy. The Red-path is walked by a human, or by an agent that then
pastes the red output. A green suite means the claims are *linked* to tests, which is
strictly more than this repo had, and strictly less than proof.

## Known gaps, ranked

1. The launcher does not verify its payload before executing it. `INV-LAUNCH-01`/`03`.
2. Nothing downloaded is digest-checked, on the build host or the target. `INV-SUPPLY-01`.
3. `HARUPACK_DEV_STAGE` bypasses staging, decryption, and licensing in release builds.
   `INV-LAUNCH-02`.
4. The staging cache is trust-on-first-use and keyed on 64 bits taken from the binary's own
   footer. No invariant yet.
5. The Nim launcher has no error handling; malformed manifests surface as raw tracebacks.
   No invariant yet.
6. Nim library versions are unpinned, so the shipped crypto implementation is whatever
   resolved on build day. `INV-SUPPLY-02`.
7. The project being packaged is trusted absolutely. Its build backend runs during
   dependency staging, its `[[bundle]]` argv runs unannounced, its symlinks are followed
   out of the tree, its `index-url` chooses where the shipped wheels come from, and an
   `app_subdir` of `.` puts its files where the launcher's control files live.
   `INV-TRUST-01` through `-07`, all proposed, six of the seven demonstrated on
   2026-09-11 by the `trojan` busybody persona.
8. No cross-implementation interop test — `INV-CRYPTO-02` compares parsed byte offsets,
   which catches drift but does not run the Nim decryptor. Needs Nim in CI.

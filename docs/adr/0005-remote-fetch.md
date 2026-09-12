# ADR 0005 — remote-fetch delivery (`--source-url`)

Status: accepted (2026-09-12) · Implements Phase 3 · Invariant: INV-REMOTE-01 · Issue #10

## Context

A payload is normally appended to the launcher binary. To keep the shipped binary small, or to
deliver a large payload from a CDN without embedding it, the packager wants the bytes to arrive
over the wire at runtime instead. This must not weaken anything: the network is untrusted, and
choosing a delivery mode must never let a pipeline step (digest-verify, decrypt, license, stage)
be skipped.

**Not for updates.** The footer digest pins the *exact* bytes, so a remote payload is immutable:
changing it means rebuilding the binary (new digest). Remote delivery decouples payload *size*
from the binary, not payload *version*.

## Decision

### 1. One pipeline, two byte-sources

`main.launch` resolves the payload bytes, then runs the SAME pipeline regardless of where they
came from:

```
bytes ──▶ verifyPayloadDigest(bytes, footer.payloadSha) ──▶ (decrypt) ──▶ (license) ──▶ stage
```

The build-baked footer digest (`payloadSha`) is the sole trust anchor. Appended and remote
builds differ only in how `bytes` is obtained.

### 2. Footer remote flag

A new footer flag bit (`FooterFlagRemote = 2`, matching `overlay.py FOOTER_FLAG_REMOTE`) marks a
remote build. Such a footer records `payloadLen = 0` and embeds NO payload bytes; the file is
`[launcher][stub-config][footer]`. `footerFault` skips the payload-extent checks when the remote
flag is set (the stub-config, mandatory for a remote build, still gets full validation).

**Delivery mode is fixed at build time by this flag.** An appended build never becomes a network
fetch because of an environment variable.

### 3. The SOURCE_URL knob supplies only the URL

`source_url` is a top-level stub-config key (build-time `--source-url`). At runtime the URL is
the SOURCE_URL knob: env `<canary>_SOURCE_URL` overrides the baked value (mirror / failover).
This is safe because the fetched bytes are digest-anchored — a repointed URL can change WHERE
bytes come from, never WHICH bytes are accepted. For an appended build there is nothing to
override and the env is ignored.

### 4. Fetch mechanics (`uvfetch.fetchPayload`)

Reuses the thin-tier HTTP path: puppy (native TLS — libcurl on Linux, WinHTTP/Schannel on
Windows, NSURLSession on macOS), a content-length HEAD preflight, a hard in-memory size cap
(`MaxPayloadBytes` = 1 GiB — puppy has no streaming API, so the body is buffered; larger payloads
must ship appended), and an explicit request timeout. Any failure (empty URL, non-200, over cap,
timeout, transport error) is fail-closed: `main.launch` dies with `ExitRemoteFetch (11)` and the
app never runs. A fetched-but-tampered payload is caught later by the digest check
(`ExitDigestMismatch (6)`).

### 5. Proxy

Honored transparently by the OS HTTP stack puppy uses: libcurl reads `http_proxy` / `https_proxy`
/ `no_proxy` on Linux; WinHTTP uses the Windows system/auto proxy; macOS uses the system proxy.
**Honest caveat:** Windows and macOS do not read the `*_proxy` env vars — they read the OS proxy
configuration.

### 6. Build output

A remote build writes a `<out>.haru-payload` sidecar: the exact container bytes the packager must
host at `source_url`. The build receipt records `source_url`, the sidecar path, and the digest.
The launcher serves nothing from the binary but the digest, so a mirror/CDN must serve these exact
bytes unchanged.

## Consequences

- Remote delivery is exactly as safe as appended delivery; a down or lying host degrades to a
  refusal, not to arbitrary code (INV-REMOTE-01).
- Orthogonal to tier and to `--encrypt`: a remote payload may be plaintext or an encrypted
  container; the digest covers whichever was built (an encrypted build's digest covers the
  container, as with appended builds).
- The 1 GiB in-memory cap is a real limit inherited from puppy's lack of streaming; it is checked
  AFTER the body is buffered (a hostile server can make the launcher buffer more before it is
  rejected → fail-closed crash, never code exec). Documented, not hidden.
- **Fetched every launch.** There is no local persistence of the fetched payload: a remote build
  pulls it on EACH run (into the stage cache, which `stageZip` still de-dupes by digest for the
  extract step). A remote build therefore needs network at every launch, not only the first. The
  runtime scheme is restricted to http/https even for the env-overridden URL.

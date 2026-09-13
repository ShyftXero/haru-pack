# Common critiques

Fair questions people ask (and I ask myself) about why haru-pack is shaped the way it is.
Kept here so each one is *answered once, with evidence*, rather than re-argued from scratch —
same spirit as [`UV_FREE_THICK.md`](UV_FREE_THICK.md): a costed decision you can re-check
instead of re-litigate. If your critique isn't here and you think it's a good one, it probably
is — open an issue.

---

## "Why Nim *and* the zig compiler? That's two languages. Zig is already there — port the launcher to Zig and have one dependency."

This is the sharpest version of the "where's the Rust / why so many moving parts" question, and
it's a good one. It even sounds free: `zig cc` is already a pinned download
([`ZIG_TOOLCHAIN.md`](ZIG_TOOLCHAIN.md)), so if the launcher were *written* in Zig you'd delete
Nim, delete `choosenim`, and collapse two toolchains into one. I looked at it seriously. I'm not
doing it, and here's the honest reasoning.

### The two tools do different jobs, and one of them is boring on purpose

Nim and zig aren't two picks for the same slot:

- **Nim is the source language.** It's stable (Nim 2.x), it compiles to C, and it brings the
  batteries the launcher actually leans on (see the table below).
- **`zig cc` is the C *backend* — a cross-compiler in one download.** That role is frozen and
  dull: it compiles C to every target with no sudo and no four system packages. It is good
  *because* it is boring.

The value of `zig cc` is precisely that it sits in a stable, mature role (compiling C, which
doesn't change). The moment Zig becomes the *source* language, it stops being boring: you're
now writing against a pre-1.0 standard library that reshuffles every release. That's the
opposite of what this project is optimizing for — tools that keep working when we can no longer
throw tokens at them. Even the 0.16 cycle moved the HTTP/TLS API out from under everyone
(`std.Io.Reader`/`Writer` interface rework; `tls.Client.Options` now demands `entropy` and
`realtime_now_seconds`). Riding that treadmill in the one component whose job is to *decrypt and
execute your code* is a maintenance liability, not a simplification.

### What a Zig-source rewrite would actually cost — the library gaps, checked

The launcher isn't 1,877 lines of arithmetic; it's 1,877 lines standing on a Nim library stack.
Here's each dependency and what replaces it in Zig, as of Zig 0.16 (2026-09):

| Nim dep (what it does) | Zig replacement | Verdict |
|---|---|---|
| `nimcrypto` — SHA-256, PBKDF2 | `std.crypto` has both | **fine.** Lateral, arguably better-audited |
| `nimcrypto` — AES **CBC** (`bcmode`/`rijndael`) | `std.crypto` ships the AES block + AEAD, **not CBC/OFB/CFB modes** (declined upstream, [ziglang/zig#5763](https://github.com/ziglang/zig/issues/5763)) | **design change.** You hand-roll CBC (security-sensitive, needs its own KAT) or move to AES-GCM — which is a *better* idea anyway, since GCM is authenticated and would give us the payload MAC `INV-LAUNCH-03` wants. But it's a re-do, not a port |
| `xzdec` (expand the XZ-compressed uv) | `std.compress.xz` exists | **not trustworthy for our one use.** [ziglang/zig#25121](https://github.com/ziglang/zig/issues/25121): `std.compress.xz` fails on *large* archives with `DecompressedSizeMismatch`. Our whole reason to use xz is a ~55 MB uv. So we'd keep vendoring the C decoder we already vendor, or add a third-party lib |
| `zippy` — zip + tar | `std.tar` is decent (`pipeToFileSystem`); `std.zip` is still being extended to stream / extract-to-memory ([ziglang/zig#21922](https://github.com/ziglang/zig/issues/21922)) | **partial.** Workable for tar, immature for zip → you reach for a third-party lib (e.g. archive.zig), and now you have a dependency again |
| `parsetoml` — TOML | `sam701/zig-toml` (v1.0.0, struct mapping) or `mattyhall/tomlz` (well-tested, encode+decode) | **closed, but third-party.** No TOML in zig stdlib; both libs are mature. Still an added dep to vet and pin |
| `puppy` — HTTP(S) fetch of uv (thin tier, **on the customer's machine**) | `std.http.Client` + `std.crypto.tls` | **the real problem — see below** |

So the score is: one clean win (hashes), one forced redesign (CBC), one stdlib feature that's
broken for our exact input (xz), two "use a third-party lib" (zip, TOML), and one genuine
hazard (HTTPS). "One language dependency" quietly becomes "Zig plus three or four third-party
Zig libraries," which is not obviously fewer moving parts than "Nim plus its batteries."

### The HTTPS/TLS gap is the one that would land on the third user

The launcher's thin tier fetches uv over HTTPS *on the recipient's machine* — the third user,
who gets no error message, only "it worked" or "it didn't" ([`PRINCIPLES.md`](PRINCIPLES.md)).
`puppy` handles that today by delegating TLS to whatever the OS already trusts (WinHTTP on
Windows — see [`TIERS.md`](TIERS.md), "the launcher links WinHTTP … no openssl"). It rides the
certificate store the target already maintains and updates.

Zig's client does not have that story yet, and the open issues are exactly in the seams a
cross-compiled stub on a stranger's box would hit:

- Windows root-CA auto-update isn't triggered ([ziglang/zig#30777](https://github.com/ziglang/zig/issues/30777));
- macOS reads the wrong keychain ([ziglang/zig#22700](https://github.com/ziglang/zig/issues/22700));
- `SSL_CERT_DIR` / `SSL_CERT_FILE` are ignored ([ziglang/zig#36288](https://github.com/ziglang/zig/issues/36288));
- shipping a bundled root set is still just a proposal ([ziglang/zig#14168](https://github.com/ziglang/zig/issues/14168)).

The alternative — httpx.zig, which carries its own TLS 1.2/1.3 + CA handling — means one
maintainer's library sitting on the download path of every thin binary. Either way, "the fetch
failed on the customer's Windows machine because zig couldn't find a root CA" is the single
worst failure this project has, by its own principle.

**Caveat that cuts the other way:** everything haru-pack downloads is **digest-pinned**
(`pins.toml`, `INV-SUPPLY-01/05`), so TLS here is transport integrity, not the trust root — a
hostile or broken TLS session yields a *failed pin*, not a compromise. That genuinely lowers the
stakes of getting TLS perfect. It does not lower the stakes of the fetch simply *failing* on a
machine we'll never see.

### Issues we've already hit even using zig only as the C backend

These are real, measured, and documented — and they're a preview of the friction a full port
would multiply, because they come from zig's toolchain not being a drop-in even in its
*easy* role:

- **The arm64 NEON shim.** `nimcrypto`'s `sha2_neon.nim` passes `-march=armv8-a+crypto`, which
  zig's clang reads as a CPU *name* and rejects. We generate a per-build shim rewriting it to
  `-mcpu=baseline+aes+sha2`. SHA-256 then matches the GCC build byte-for-byte on real hardware —
  but the NEON-accelerated path isn't actually enabled, so ARM runs the reference SHA and pays a
  modest startup cost on every launch. The correct feature spelling hasn't been found yet.
  ([`ZIG_TOOLCHAIN.md`](ZIG_TOOLCHAIN.md).)
- **macOS is out of reach with bundled zig.** zig's bundled macOS headers lack `fstore_t`, which
  Nim's posix module needs, so a macOS target requires `--cc system` and the real Apple SDK.
  A Zig-source launcher inherits this same header gap, not less of it.
- **Cross cfg keys.** Nim needs `--<cpu>.<os>.gcc.exe` per target, not the generic `--gcc.exe`
  (that cost an hour to find). Different plumbing, same lesson: the toolchain is not free even
  where it's supposed to be easy.

### The part that isn't technical

I like Nim. That's a real input, not a joke — developer ergonomics is one of the three users
this project answers to, and for the person maintaining haru-pack, that person is me, and I
enjoy writing it. A rewrite that's a net wash on dependencies, a step *backward* on stability,
and less pleasant to maintain is not a trade I'll make for the aesthetic of a one-word answer to
"what's it written in."

### When I'd reconsider

- **Zig hits 1.0** and the stdlib stops moving — the stability objection mostly evaporates.
- **`std.compress.xz` fixes large inputs** and **`std.http.Client` grows a real cross-platform
  system-trust story** (or bundles roots) — the two hard gaps close.

Until then: Nim for the source, `zig cc` for the cross-compile. Two tools, two stable jobs.

---

## "Where's the Rust? How is this a modern Python project written mostly in something else?"

Answered in the README intro ("Why is this even here") — short version: uv does the Python part,
the launcher is a ~500-line signable native stub, and Nim compiles-to-C + cross-compiles from
Linux without a Windows machine, which is the actual requirement. Not everything needs to be Rust.

## "Why not just use PyInstaller / Nuitka?"

They're prior art I respect and borrow from (README, "Prior art"). haru-pack's difference is
that the interpreter and dependencies are delegated to `uv` rather than reimplemented, the
launcher is a thin signable stub instead of a bundled runtime, and you choose per build how much
ships vs. fetches on the target ([`TIERS.md`](TIERS.md)).

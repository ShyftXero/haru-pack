# haru-pack — guiding principles

there's really only one, and everything else in here is downstream of it.

> **User ergonomics is of the utmost importance.**

the sharp corners of other packaging tools are exactly why this project exists, so "it
works if you hold it right" is not a standard I get to use.

The word *user* is doing a lot of work in that sentence, so it is worth spelling out. It
means three different entities, and they are ranked when they conflict.

## The three users

### 1. Us — whoever is working on haru-pack
Readable code, invariants with a mandatory red-path, tests that fail for the *right* reason,
commit messages that say why rather than what. `INVARIANTS.md` exists because prose evidence
is satisfiable by a claim; this audience is the reason it is machine-checked.

### 2. The developer running `haru-pack build`
They should be able to point the tool at a project and get a binary. When that is not
possible, the tool has to say what to type next.

- Discovery works with no config; config is for overriding, not for getting started.
- A refusal names the candidates and prints the exact flag. `haru-pack` refuses to guess,
  and a refusal that does not tell you how to proceed is just a wall.
- Never silently ignore configuration. A table nobody reads is worse than a missing one,
  because the operator believes it took effect.

### 3. The person who receives the packed executable
**The one that is easy to forget, and the one that matters most.** They have never heard of
uv, Python, or haru-pack. They double-click a file. They get no error message — only "it
worked" or "it didn't", and if it didn't they do not file a bug, they stop using it.

This audience is why the repo's standing rule is *refuse instead of guessing*: a wrong guess
builds cleanly, exits 0, and fails on **their** machine, which is the worst possible place to
find out. It is also why:

- nothing may be required to be preinstalled on their machine — no curl, no PowerShell, no
  system `tar`, no OpenSSL, no libzstd;
- they never pay for a build-side convenience. The bundled `uv` is compressed rather than
  UPX-packed partly because packing would cost them decompression on *every* launch and trip
  their antivirus (`INV-PAYLOAD-04`);
- the artifact is signable and its payload integrity is checkable, because "is this safe to
  run" is a question they are entitled to have answered.

## How this cashes out in practice

**A build-time refusal beats a runtime failure. Always.** But make the refusal
copy-pasteable.

**Warn when uncertain; refuse only when certain.** A false refusal blocks a correct build,
which is its own ergonomic failure. Both entrypoint checks are built this way: the
`module:callable` verifier stays silent when the module is not in the project tree, because
it may legitimately come from a dependency, and the console-script check warns rather than
refuses unless there is an environment to prove absence against.

**Order of preference when a check is possible:**

1. make the wrong thing impossible;
2. else refuse at build time, naming the fix;
3. else warn at build time, saying what could not be verified;
4. never let it surface first on the recipient's machine.

**When two audiences conflict, the later number wins.** A little more work for us, or one
more flag for the operator, is worth almost any reduction in the chance that the recipient's
double-click does nothing.

## No god modules

This one is downstream of user 1, and it should have been written down on day one instead
of on the day four of them had to be taken apart.

A god module is not just a long file. It is the long file *everything goes through* — the
widest and heaviest thing in the tree at the same time, that no change can route around.
By 2026-09-13 haru-pack had four: `build.py` at 735 statements importing sixteen of the
package's twenty-two modules, `tools/busybody.py` at 3393, `shake.py` at 536, `cli.py` at
483. None of them got that way by anyone deciding to write a 1177-line file. They got that
way one reasonable addition at a time, because nothing was counting.

The rule, and it is machine-checked as `INV-MODULARITY-01/02/03` rather than left as
advice:

> **A module may be the hub, or it may hold the work. Not both.**

300 statements per module, 80 per function, and a module that imports more than eight
first-party modules gets 150. Statements, not lines — comments and docstrings are free,
because the comments here are the audit trail for why a refusal exists and a line cap would
make deleting an explanation the cheapest way to pass. Write as much prose as the decision
deserves.

There is no allowlist, and there must not be one. An allowlist is how a budget becomes a
formality: the first exception is always justified, the tenth is never questioned, and the
module it excuses is the one that got too big precisely because nobody was counting.

The reason this matters for the other two audiences, who never read the source: a module
nobody can hold in their head is where a silent bug lives. Every refusal in this file
depends on someone being able to see that it is still wired up.

Splitting them was not free, and the honest version of the cost is worth recording. Moving
a file into a subpackage silently changes what `from . import x` means, and it broke seven
relative imports across three files. None of them raised at import: the ones that hurt were
late-bound, inside a function, so nothing ran them until someone ran that exact command —
and one landed inside a `try/except Exception` where an ImportError is indistinguishable
from a malformed config. That is now a static check
(`tests/test_imports_resolve.py`), which is the shape every finding on this page should
take: not "we were careful", but "the next one cannot get past here".

**What to do when the check fires.** Almost never "shorten it". Name the second
responsibility the module grew and move that out; if it is a subsystem, make it a package
and re-export the entry points so no caller changes. For a long function, the phases are
usually already there and simply have no names — give them names and the caller becomes the
readable summary of what happens.

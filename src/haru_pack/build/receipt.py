"""The build receipt: the dict `haru-pack build` returns and the CLI prints.

An operator auditing a signed artifact should not have to guess whether a mirror was in
play, whether the binary reaps its stage, or whether the encryption they asked for was
actually applied. Two rules govern everything recorded here:

* **Nothing secret.** The canary map is env-name prefixes, the staging knobs are policy,
  and the sources are URLs. The secret VALUE lands in no artifact the build produces,
  this receipt included (INV-SECRET-03). That citation said INV-SECRET-02 until
  2026-09-15, when two entries that had been sharing the id were split apart:
  INV-SECRET-02 is now the claim about what a customer who RUNS the binary can recover
  from their own staging cache, which says nothing about what the build writes on the
  packager's disk — which is what a receipt is.
* **Effective values only.** `reap` is the value after the `--ephemeral` coupling, not the
  flag the operator typed, so the receipt can never claim a cleanup the binary will not do
  (INV-EPHEMERAL-02, INV-BUILD-01).

Split out of build.py 2026-09-13 (INV-MODULARITY-01). Behaviour unchanged.
"""
from __future__ import annotations

from pathlib import Path

from .. import shake as shake_mod

# The subset of a shake report that belongs on the receipt. The full report is written to
# its own file beside the binary; this is the summary an auditor reads first.
_SHAKE_KEYS = ("tracer", "dropped_files", "freed_bytes",
               "payload_bytes_before", "payload_bytes_after")


def finish(info: dict, *, sources, provider: str, tier: str, tgt, nim: str, compiler: str,
           out: Path, enc: dict, manifest: dict, pyver: str, canary: dict, reap: bool,
           overwrite: bool, ram_only: bool, base_path: str, source_url: str,
           unpacked_bytes: int, shake_report: dict,
           slim_report: dict | None = None) -> dict:
    """Fold every recorded fact about this build into the receipt and return it."""
    # The receipt records WHERE this build's third-party bytes came from. An operator
    # auditing a signed artifact should not have to guess whether a mirror was in play.
    info.update(sources=sources.describe(), cc=provider,
                tier=tier, target=str(tgt), nim=nim, compiler=compiler, out=str(out),
                encrypted=bool(enc["enabled"]), kind=manifest["kind"], python=pyver,
                canary=canary,
                staging={"reap": bool(reap), "overwrite": bool(overwrite),
                         "ram_only": bool(ram_only), "base_path": base_path,
                         "source_url": source_url,
                         "unpacked_bytes": int(unpacked_bytes)},
                obfuscation=manifest.get("obfuscation", {"engine": "none",
                                                         "applied": False}))
    if shake_report:
        info["shake"] = {k: shake_report[k] for k in _SHAKE_KEYS}
        info["shake"]["report"] = str(shake_mod.write_report(shake_report, out))
    if slim_report:
        # Provenance, not a saving: the receipt names EVERY path `--slim-python` removed from
        # the verified PBS interpreter, so the chain reads "verified artifact, then these N
        # files removed by haru-pack" rather than "some tree we assembled" (INV-SHAKE-05).
        info["slim_python"] = {
            "removed_files": slim_report["removed_files"],
            "freed_bytes": slim_report["freed_bytes"],
            "removed_paths": list(slim_report["removed_paths"]),
        }
    return info

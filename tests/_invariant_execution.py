"""A pytest plugin: an invariant claimed only by tests that never ran is not claimed.

`_invariants.py` reads test SOURCE, so it cannot tell a claim that runs from one that is
skipped away. Every test claiming INV-CRYPTO-06, INV-GATE-01, INV-GEO-01, INV-REMOTE-01
and INV-EPHEMERAL-03 compiles the launcher and skips itself when nim is absent, and CI
installed no nim — so `pytest -m invariant` exited 0 with five active invariants defended
by nothing at all. Skips are not failures, and nothing in the gate could see it.

These hooks record which selected claimants reached their call phase and fail the session
when an active invariant's claimants all skipped. `HARUPACK_INVARIANT_SKIPS_OK=1` downgrades
that to a warning, loudly, for a developer on a machine with no toolchain.

It lives beside `_invariants.py` rather than inside it so that pytest imports it fresh as a
plugin; `_invariants` is already imported by the time the registration runs, which makes
pytest warn that it can no longer rewrite its asserts. Registered from
`test_invariants_enforced.py` (`pytest_plugins`), which is also where the guard that notices
if that registration stops working lives.
"""
from __future__ import annotations

import os

import pytest

from _invariants import ID_RE, Invariant, load_invariants

SKIP_OPT_OUT_ENV = "HARUPACK_INVARIANT_SKIPS_OK"

_SELECTED_CLAIMANTS: dict[str, set[str]] = {}   # invariant id -> node ids selected this run
_EXECUTED: set[str] = set()                     # node ids that reached the call phase


def unexecuted_active_claims(claimants: dict[str, set[str]], executed: set[str],
                             invariants: dict[str, Invariant]) -> dict[str, list[str]]:
    """Active invariants whose every selected claimant failed to run.

    Pure, so the guard-of-guards can drive it without nesting a pytest session inside a
    test: the hooks below are bookkeeping, this is the rule that can be wrong.

    Only invariants with at least one claimant SELECTED are judged, so that
    `pytest tests/test_ui.py` does not fail over the hundred invariants that run never
    intended to touch. The cost of that choice is a blind spot: a module that skips itself
    at import with `allow_module_level=True` contributes no items at all, so its invariants
    go unjudged rather than reported. No test module in this repo does that today; if one
    starts, this check quietly stops covering it.
    """
    out: dict[str, list[str]] = {}
    for inv_id, nodeids in claimants.items():
        inv = invariants.get(inv_id)
        if inv is None or not inv.is_active:
            continue
        if not (nodeids & executed):
            out[inv_id] = sorted(nodeids)
    return out


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    # trylast because `-m` and `-k` deselection is itself a pytest_collection_modifyitems
    # implementation that rewrites `items` in place. Running before it would record
    # claimants this session deliberately deselected, then "detect" that they never ran.
    _SELECTED_CLAIMANTS.clear()
    _EXECUTED.clear()
    for item in items:
        for mark in item.iter_markers("invariant"):
            for arg in mark.args:
                if isinstance(arg, str) and ID_RE.fullmatch(arg):
                    _SELECTED_CLAIMANTS.setdefault(arg, set()).add(item.nodeid)


def pytest_runtest_logreport(report):
    # The call phase specifically. A skipif, or a fixture that calls pytest.skip, produces a
    # SETUP report and no call report at all; an xfail produces a call report whose outcome
    # is "skipped" with `wasxfail` attached. Neither one exercised the invariant.
    # A FAILED call counts as executed on purpose: it ran, and the session is already red,
    # so re-reporting it here would only bury the real failure.
    if report.when == "call" and not report.skipped and not hasattr(report, "wasxfail"):
        _EXECUTED.add(report.nodeid)


def pytest_sessionfinish(session, exitstatus):
    if session.config.option.collectonly or getattr(session, "shouldstop", False):
        return
    try:
        invariants = load_invariants(allow_duplicates=True)
    except OSError:
        return                  # no INVARIANTS.md to judge against; the contract test says so
    offenders = unexecuted_active_claims(_SELECTED_CLAIMANTS, _EXECUTED, invariants)
    if not offenders:
        return

    opted_out = os.environ.get(SKIP_OPT_OUT_ENV, "") not in ("", "0")
    lines = [f"{len(offenders)} active invariant(s) were claimed only by tests that did not run.",
             "A skipped claimant defends nothing. Without this check the run exits 0 and the",
             "invariant contract reads as satisfied."]
    for inv_id, nodeids in sorted(offenders.items()):
        lines.append(f"  {inv_id}")
        lines += [f"      did not run: {n}" for n in nodeids]
    if opted_out:
        lines.append(f"{SKIP_OPT_OUT_ENV} is set, so this is a warning and the run is not failed.")
        lines.append("Those invariants were not checked by this run. Do not set it in CI.")
    else:
        lines.append("Install the toolchain these need (`haru-pack bootstrap --minimal`), or set")
        lines.append(f"{SKIP_OPT_OUT_ENV}=1 to downgrade this to a warning on a machine that cannot")
        lines.append("run them — and accept that those invariants are then unchecked.")

    title = ("invariant contract: UNVERIFIED (skips permitted)" if opted_out
             else "invariant contract: claimed, never executed")
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if tr is None:
        print(title); print("\n".join(lines))
    else:
        tr.write_sep("=", title, bold=True, red=not opted_out, yellow=opted_out)
        for line in lines:
            tr.write_line(line)
    if not opted_out and exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED

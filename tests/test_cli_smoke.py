"""Run the CLI exactly as the README documents it, in a subprocess.

WHY THIS FILE EXISTS
--------------------
On 2026-08-19 `python -m entrovouch.no_egress_auditor <dir>` — the first command
the README shows — crashed with UnicodeEncodeError on a Windows cp1252 console,
while **146 tests passed**. The tests never caught it because they call the
functions directly; nothing in the suite went through a console encoder. The
defect lived in the gap between "the library works" and "the documented command
works", and only running the documented command could see it.

So these tests spawn a real subprocess with a deliberately hostile stdout
encoding, and assert the two things a first-time user actually experiences:
the command does not crash, and the tool passes its own audit.

That second one is load-bearing. The module docstring tells readers this auditor
"performs zero network operations itself, which is a property you can check by
running it on its own source", and the README says "clone it and check our
work". If a reader does exactly that and gets findings, the invitation becomes
the indictment.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _run(module: str, *args: str, encoding: str = "cp1252"):
    """Invoke a module as the README does, with a hostile console encoding."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = encoding
    env["PYTHONPATH"] = str(REPO)
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        cwd=REPO, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )


@pytest.mark.parametrize("module", ["entrovouch.no_egress_auditor", "entrovouch.cbom"])
def test_documented_cli_does_not_crash_on_a_cp1252_console(module):
    r = _run(module, str(REPO))
    assert "UnicodeEncodeError" not in (r.stderr or ""), (
        f"{module} crashed on a cp1252 console:\n{r.stderr[-1500:]}"
    )
    assert "Traceback" not in (r.stderr or ""), (
        f"{module} raised:\n{r.stderr[-1500:]}"
    )
    # 0 = CLEAN, 1 = FINDINGS. Both are documented outcomes; anything else is a crash.
    assert r.returncode in (0, 1), f"{module} exited {r.returncode}\n{r.stderr[-1500:]}"


def test_the_shipped_package_passes_its_own_audit():
    """The README invites the reader to do exactly this. It must come back clean.

    SCOPED TO `entrovouch/`, THE SHIPPED PACKAGE - changed 2026-08-30 when
    `examples/sample_service/` was added. That fixture contains a real network
    import ON PURPOSE, so a repo-root audit now finds it and correctly exits 1.

    The tempting fix was to teach the auditor to skip `examples/`. Rejected: a
    scanner with a built-in blind spot for one directory is exactly the hidden
    exemption this package argues against, and it would have made the tool lie
    about any tree that happened to contain that path. Scope the CLAIM instead of
    blinding the instrument - and pin the fixture separately, below.
    """
    r = _run("entrovouch.no_egress_auditor", str(REPO / "entrovouch"))
    assert r.returncode == 0, (
        "The auditor reported findings against its own shipped source. The README "
        "tells readers to clone it and check our work, so this must be CLEAN. "
        + r.stdout[-2000:]
    )
    assert "Findings:** 0" in r.stdout or "CLEAN" in r.stdout


def test_the_only_egress_in_this_repo_is_the_deliberate_fixture():
    """The other half, and it is the half that keeps the claim honest.

    Auditing the whole repository must find findings - and every one must come
    from `examples/`. If real egress ever lands in the shipped package or the
    tests, this fails, which is what stops the scoped test above from becoming a
    place for a genuine finding to hide.
    """
    r = _run("entrovouch.no_egress_auditor", str(REPO))
    assert r.returncode == 1, (
        "A repo-root audit came back CLEAN. The examples fixture is supposed to "
        "contain a deliberate network import - if it no longer does, the demo in "
        "examples/ is showing a reader nothing."
    )
    offenders = [
        line for line in r.stdout.splitlines()
        if line.startswith("| `") and "examples" not in line
    ]
    assert not offenders, (
        "egress found OUTSIDE examples/ - a real finding in the shipped package "
        "or the test suite, not the fixture: " + " || ".join(offenders)
    )


def test_help_works_for_both_tools():
    for module in ("entrovouch.no_egress_auditor", "entrovouch.cbom"):
        r = _run(module, "--help")
        assert r.returncode == 0, f"{module} --help exited {r.returncode}"
        assert "usage" in (r.stdout or "").lower()

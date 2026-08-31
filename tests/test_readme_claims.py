"""The README's checkable claims must match reality.

WHY THIS FILE EXISTS
--------------------
The README said "# 33 tests" when there were 146. On 2026-08-19 that was corrected
to 146, then to 151, then to 155 — stale again twice within the hour, each time by
the person fixing it. A number written by hand in prose and maintained by memory
goes stale on the next commit, every time.

So the number is asserted instead of remembered. If you add a test and do not
update the README, this fails and tells you the new figure.

Scope note, stated because it is the honest limit: this checks the claims a
machine can settle — the test count and the module paths the README tells a reader
to run. It cannot check whether the prose is *true*, only whether it is
*consistent with the code beside it*.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = (REPO / "README.md").read_text(encoding="utf-8")


def _collected_test_count() -> int:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", r.stdout or "")
    assert m, f"could not read a collected count from pytest:\n{r.stdout[-800:]}"
    return int(m.group(1))


def _hypothesis_available() -> bool:
    """Is the optional extra USABLE? Not: does the name import.

    🔴 The first version of this asked `import hypothesis`, and that is the exact
    defect it exists to detect, committed one level up. A leftover empty directory
    imports fine as an implicit namespace package (`__file__ is None`) while
    `from hypothesis import given` still fails — so this reported AVAILABLE, the
    caller expected the with-extras count, and the suite failed for a reason that
    had nothing to do with the README.

    ⭐ Ask for what the code actually needs. A guard that checks something cheaper
    than the real requirement will pass in exactly the states you wrote it for.
    """
    return (
        subprocess.run([sys.executable, "-c", "from hypothesis import given"],
                       capture_output=True).returncode == 0
    )


def test_readme_test_count_is_current():
    """The README states TWO counts, and this asserts the one that applies here.

    🔴 WHY THIS IS NOT A SINGLE NUMBER — the defect it replaces, 2026-08-30.
    It was `claimed == actual` against the single figure `# 261 tests`, which is
    the count *with* the optional `hypothesis` extra. The pyproject deliberately
    makes that extra optional so a sceptical reader can clone and run with no
    installs — so **the documented path failed**, and failed by reporting
    "README claims 261 tests; pytest collects 255", i.e. accusing the document of
    the environment's shortfall.

    ⭐ That is the CANT-RUN-vs-FAIL distinction, in the one repository where a red
    suite is most expensive: this package's whole argument is *re-run it yourself*.
    A guard that cannot separate "this is wrong" from "this could not be checked
    here" will eventually report the second as the first.

    The cause underneath it: `tests/test_properties.py` calls `importorskip` at
    MODULE level, so without `hypothesis` the entire file contributes **zero**
    tests and says nothing. Only the count noticed.
    """
    base = re.search(r"#\s*(\d+)\s+tests, no installs", README)
    full = re.search(r"re-run for \*\*(\d+)\*\*", README)
    assert base and full, (
        "README must state BOTH counts — the clean-clone figure as "
        "'# N tests, no installs' and the with-extras figure as 're-run for **N**'"
    )
    base_n, full_n = int(base.group(1)), int(full.group(1))
    assert full_n > base_n, (
        f"the with-extras count ({full_n}) must exceed the clean-clone count "
        f"({base_n}); optional tests can only add"
    )

    have = _hypothesis_available()
    expected = full_n if have else base_n
    actual = _collected_test_count()
    assert expected == actual, (
        f"hypothesis {'IS' if have else 'is NOT'} installed, so the README's "
        f"{'with-extras' if have else 'clean-clone'} figure applies: it claims "
        f"{expected} tests and pytest collects {actual}. Update that figure — and "
        f"if the OTHER figure moved too, update both."
    )


def test_optional_suites_are_not_silently_empty():
    """A module-level `importorskip` removes a whole FILE with no notice.

    This is the check that would have caught the defect above at its source rather
    than three steps downstream in a count. It asserts the two numbers differ by
    exactly the number of tests the optional file actually contains, so a property
    suite that quietly stops contributing anything cannot pass unnoticed.

    ⛔ It can only run when the extra IS installed — when it is not, the tests it
    counts do not exist to be counted. It skips rather than passing, because a
    check that reports success without running is the thing this file exists about.
    """
    if not _hypothesis_available():
        import pytest
        pytest.skip("hypothesis absent — the optional tests cannot be counted here")

    # ⚠️ GENERALISED 2026-08-30: this counted `tests/test_properties.py` ALONE,
    # because when it was written that was the only suite behind an optional
    # extra. Adding the SARIF schema suite made a THIRD, and the guard failed
    # while both the README and the repository were correct — it was the guard's
    # model of the repository that had gone stale.
    #
    # ⭐ The reusable form: a check that hardcodes the members of a set silently
    # becomes wrong when the set grows. Derive the set instead. Any suite that
    # skips at module level for a missing extra belongs here automatically.
    OPTIONAL_SUITES = [
        "tests/test_properties.py",        # hypothesis
        "tests/test_cyclonedx_schema.py",  # jsonschema
        "tests/test_sarif_schema.py",      # jsonschema
    ]
    optional_n = 0
    for suite in OPTIONAL_SUITES:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", suite],
            cwd=REPO, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=300,
        )
        m = re.search(r"(\d+)\s+tests?\s+collected", r.stdout or "")
        assert m, f"could not collect {suite}; pytest said: " + (r.stdout or "")[-500:]
        n = int(m.group(1))
        assert n > 0, (
            f"{suite} collected ZERO tests while its extra is installed — "
            "the file is contributing nothing and saying nothing"
        )
        optional_n += n

    base = int(re.search(r"#\s*(\d+)\s+tests, no installs", README).group(1))
    full = int(re.search(r"re-run for \*\*(\d+)\*\*", README).group(1))
    assert full - base == optional_n, (
        f"the README's two counts differ by {full - base}, but the optional suite "
        f"holds {optional_n} tests. One of the three numbers is stale."
    )


def test_readme_module_paths_are_runnable():
    """Every `python -m X` the README shows must name a real module."""
    modules = set(re.findall(r"python -m ([a-z_][\w.]*)", README)) - {"pytest"}
    assert modules, "README shows no `python -m` invocations — did the usage section move?"
    for mod in sorted(modules):
        r = subprocess.run(
            [sys.executable, "-m", mod, "--help"],
            cwd=REPO, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )
        assert r.returncode == 0, (
            f"README documents `python -m {mod}` but it exits {r.returncode}:\n"
            f"{r.stderr[-800:]}"
        )


def test_every_runnable_module_is_documented():
    """The OTHER direction — and it is the one that was missing.

    The guard above asserts every DOCUMENTED command exists. It never asserted
    that every command is DOCUMENTED, so a tool could ship complete, tested and
    invisible. On 2026-08-21 that was live: `key_provenance` had a row in the
    README's tool table and no `python -m` line anywhere, making it 1 of 6
    CLI-capable modules a reader is never told how to run.

    ⭐ The gap was NAMED in the 2026-08-20 session record ("it asserts every
    documented command exists, not that every command is documented") and left
    open. A predicted defect that nobody converted into a check is just a
    defect with better paperwork. This is the check.

    It landed on `key_provenance` — the detector that found the forgeable
    signature in this package's own predecessor, so of the six it was the worst
    one to hide.
    """
    documented = set(re.findall(r"python -m ([a-z_][\w.]*)", README))
    pkg = REPO / "entrovouch"
    runnable = {
        f"entrovouch.{p.stem}"
        for p in pkg.glob("*.py")
        if p.stem != "__init__" and "__main__" in p.read_text(encoding="utf-8")
    }
    missing = sorted(runnable - documented)
    assert not missing, (
        "these modules have a CLI entry point and no `python -m` line in the "
        f"README: {missing}. Document them, or drop their `__main__` block."
    )


def test_readme_imports_resolve():
    """Every `from X import Y` the README shows must actually import."""
    pairs = re.findall(r"from (entrovouch[\w.]*) import ([\w, ]+)", README)
    assert pairs, "README shows no entrovouch imports — did the usage section move?"
    for mod, names in pairs:
        for name in [n.strip() for n in names.split(",") if n.strip()]:
            r = subprocess.run(
                [sys.executable, "-c", f"from {mod} import {name}"],
                cwd=REPO, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=120,
            )
            assert r.returncode == 0, (
                f"README documents `from {mod} import {name}` but it fails:\n"
                f"{r.stderr[-800:]}"
            )

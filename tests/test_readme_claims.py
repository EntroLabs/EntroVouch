"""The README's checkable claims must match reality.

WHY THIS FILE EXISTS
--------------------
A number written by hand in prose and maintained by memory goes stale on the
next commit. So the README's test count is asserted instead of remembered. If
you add a test and do not update the README, this fails and tells you the new
figure.

Scope note, stated because it is the honest limit: this checks the claims a
machine can settle: the test count and the module paths the README tells a reader
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


def _module_usable(stmt: str) -> bool:
    return (
        subprocess.run(
            [sys.executable, "-c", stmt],
            capture_output=True,
        ).returncode
        == 0
    )


def _hypothesis_available() -> bool:
    """Is the optional extra USABLE? Not: does the name import.

    `import hypothesis` is not enough. A leftover empty directory imports fine as
    an implicit namespace package (`__file__ is None`) while
    `from hypothesis import given` still fails. Asking for the bare name would
    report AVAILABLE, the caller would expect the with-extras count, and the
    suite would fail for a reason that has nothing to do with the README.

    Ask for what the code actually needs. A guard that checks something cheaper
    than the real requirement passes in states where the requirement is not met.
    """
    return _module_usable("from hypothesis import given")


def _jsonschema_available() -> bool:
    return _module_usable("import jsonschema")


def _collect_suite(rel: str) -> int:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", rel],
        cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", r.stdout or "")
    if m:
        return int(m.group(1))
    if "no tests collected" in (r.stdout or "").lower() + (r.stderr or "").lower():
        return 0
    raise AssertionError(f"could not collect {rel}; pytest said: " + (r.stdout or "")[-500:])


def test_readme_test_count_is_current():
    """The README states TWO counts, and this asserts the one that applies here.

    WHY THIS IS NOT A SINGLE NUMBER. The pyproject deliberately makes the
    `hypothesis` and `jsonschema` extras optional so a sceptical reader can clone
    and run with only pytest. A single figure compared with `claimed == actual`
    would be the with-extras count, so the documented clean-clone path would
    fail, and fail by accusing the document of the environment's shortfall.

    This package's whole argument is *re-run it yourself*, so the guard must
    separate "this is wrong" from "this could not be checked here".

    The mechanism: the optional suites call `importorskip` at MODULE level, so
    without the extra the entire file contributes **zero** tests and says
    nothing. Only the count notices.
    """
    base = re.search(r"#\s*(\d+)\s+tests, pytest only", README)
    full = re.search(r"re-run for (\d+)\b", README)
    assert base and full, (
        "README must state BOTH counts: the clean-clone figure as "
        "'# N tests, pytest only' and the with-extras figure as 're-run for N'"
    )
    base_n, full_n = int(base.group(1)), int(full.group(1))
    assert full_n > base_n, (
        f"the with-extras count ({full_n}) must exceed the clean-clone count "
        f"({base_n}); optional tests can only add"
    )

    have_hyp = _hypothesis_available()
    have_js = _jsonschema_available()
    actual = _collected_test_count()
    loaded = 0
    if have_hyp:
        loaded += _collect_suite("tests/test_properties.py")
    if have_js:
        loaded += _collect_suite("tests/test_cyclonedx_schema.py")
        loaded += _collect_suite("tests/test_sarif_schema.py")
    expected = base_n + loaded
    assert actual == expected, (
        f"this environment has hypothesis={'yes' if have_hyp else 'no'} "
        f"jsonschema={'yes' if have_js else 'no'}: README clean-clone is {base_n}, "
        f"optional tests loaded here {loaded}, so pytest should collect {expected}; "
        f"it collected {actual}."
    )


def test_optional_suites_are_not_silently_empty():
    """A module-level `importorskip` removes a whole FILE with no notice.

    This checks that at its source rather than downstream in a total. It asserts
    the README's two numbers differ by exactly the number of tests the optional
    files actually contain, so an optional suite that quietly stops contributing
    anything cannot pass unnoticed.

    It can only run when the extra IS installed: when it is not, the tests it
    counts do not exist to be counted. It skips rather than passing, because a
    check that reports success without running is the thing this file guards
    against.
    """
    import pytest
    OPTIONAL = [
        ("tests/test_properties.py", _hypothesis_available()),
        ("tests/test_cyclonedx_schema.py", _jsonschema_available() and _module_usable("import referencing")),
        ("tests/test_sarif_schema.py", _jsonschema_available()),
    ]
    if not any(ok for _s, ok in OPTIONAL):
        pytest.skip("no optional extras: cannot count the extra suites here")

    # Every suite that skips at module level for a missing extra is listed in
    # OPTIONAL and checked the same way. A check that covers one member of the
    # set becomes wrong when the set grows, so a new optional suite belongs in
    # that list.
    for suite, extra_ok in OPTIONAL:
        n = _collect_suite(suite)
        if extra_ok:
            assert n > 0, (
                f"{suite} collected ZERO tests while its extra is installed"
            )
        else:
            assert n == 0, (
                f"{suite} collected {n} tests while its extra is missing"
            )

    # Count what pytest COLLECTS, the number a reader sees, not `^def test_` lines: a regex over source misses
    # parametrized expansions, so it undercounts.
    if not all(ok for _s, ok in OPTIONAL):
        pytest.skip("not every optional extra is installed: the full optional count cannot be measured here")
    src_n = sum(_collect_suite(suite) for suite, _ok in OPTIONAL)

    base = int(re.search(r"#\s*(\d+)\s+tests, pytest only", README).group(1))
    full = int(re.search(r"re-run for (\d+)\b", README).group(1))
    assert full - base == src_n, (
        f"the README's two counts differ by {full - base}, but the optional "
        f"files declare {src_n} tests. One of the three numbers is stale."
    )


def test_readme_module_paths_are_runnable():
    """Every `python -m entrovouch...` the README shows must name a real module. (The README also names commands the
    auditor recognises in the code it reads, `python -m build` among them: those are not this package's to run.)"""
    modules = set(re.findall(r"python -m (entrovouch[\w.]*)", README))
    assert modules, "README shows no `python -m` invocations: did the usage section move?"
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
    """The OTHER direction: every runnable module is documented.

    The guard above asserts every DOCUMENTED command exists. It does not assert
    that every command is DOCUMENTED, so on its own a tool could ship complete,
    tested and invisible: a reader is never told how to run it. This asserts
    that every module with a `__main__` entry point has a `python -m` line in
    the README.
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
    assert pairs, "README shows no entrovouch imports: did the usage section move?"
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


def _headings(text: str) -> list[str]:
    """Markdown headings OUTSIDE fenced code blocks.

    The fences matter: this README's shell examples contain comment lines that
    start with `#`, and counting those as headings would make the guard below
    fail for reasons that have nothing to do with a missing section.
    """
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced and line.startswith("#"):
            out.append(line.rstrip())
    return out


# The README's sections, pinned. Order is part of the assertion.
EXPECTED_HEADINGS = [
    "# ENTROVOUCH",
    "## Try it",
    "## Use",
    "### Adapters",
    "### Reproducing a report",
    "### Exit codes",
    "## What a result means",
    "### What kind of assurance this is",
    "### How often is it wrong?",
    "### How often does it miss?",
    "## Signing",
    "### The publisher's public root",
    "## Independently issued audits",
    "## License",
]


def test_readme_sections_are_all_present_and_in_order():
    """The README's section structure is pinned, heading by heading, in order.

    The sections include the page's load-bearing disclosures: "And how often
    does it MISS?" (the recall measurement and the named blind spots) and "What
    kind of assurance this is" (the limited-assurance statement). An edit that
    drops one of them must fail a test.

    A SUBSTRING IS NOT A STRUCTURE. Checking that a word such as
    "underapproximat" still appears cannot tell you a section still exists,
    because the word can survive elsewhere on the page. This asserts the
    structure instead.

    If you are legitimately adding or renaming a section, update this list in
    the same commit: that is the point, not an obstacle: it makes removing a
    disclosure a deliberate, reviewable act rather than a side effect.
    """
    actual = _headings(README)
    assert actual == EXPECTED_HEADINGS, (
        "README section structure changed.\n"
        f"  missing: {[h for h in EXPECTED_HEADINGS if h not in actual]}\n"
        f"  added:   {[h for h in actual if h not in EXPECTED_HEADINGS]}\n"
        "If this was intentional, update EXPECTED_HEADINGS in the same commit."
    )


def test_readme_keeps_the_disclosures_that_carry_the_measurements():
    """The structure guard above proves a HEADING exists. This proves the
    numbers under it survived, because a section can be emptied without losing
    its title."""
    for needle in (
        "0/59",                    # tier A' held-out recall
        "7/10",                    # tier C adversarial recall, pinned by test_detection_scope
        "limited assurance",       # the assurance level, in the profession's words
        "nothing came to our attention",
        "REVIEW` means review",
    ):
        assert needle in README, f"README no longer states: {needle!r}"

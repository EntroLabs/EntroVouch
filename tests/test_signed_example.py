"""The one signed example report: it verifies against the root the README publishes, and it is the same audit as
the unsigned example beside it.

`examples/signed/egress.json` is the no-egress audit of `examples/sample_service`, signed with the publisher's key.
The key is not in this repository, so `examples/regenerate.py` cannot re-sign it. When the version or the findings
change, the second test fails on purpose: the signed report is then stale and the publisher has to sign it again.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from entrovouch import __version__
from entrovouch.no_egress_auditor import verify_report

REPO = Path(__file__).resolve().parents[1]
SIGNED = REPO / "examples" / "signed" / "egress.json"
UNSIGNED = REPO / "examples" / "reports" / "egress.json"


def _published_root() -> str:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    section = readme.split("### The publisher's public root", 1)[1]
    m = re.search(r"```\s*\n([0-9a-f]{64})\s*\n```", section)
    assert m, "the README's public-root section no longer holds a 64-hex root in a code block"
    return m.group(1)


def test_the_signed_example_is_attested_by_the_published_root():
    report = json.loads(SIGNED.read_text(encoding="utf-8"))
    assert verify_report(report, expected_root=_published_root()) == (True, "ATTESTED")
    assert verify_report(report) == (False, "UNVERIFIED")
    assert verify_report(report, expected_root="0" * 64) == (False, "TAMPERED")
    edited = copy.deepcopy(report)
    edited["findings"][0]["detail"] += " "
    assert verify_report(edited, expected_root=_published_root()) == (False, "TAMPERED")


def test_the_examples_page_pins_the_same_root():
    page = (REPO / "examples" / "README.md").read_text(encoding="utf-8")
    assert f"examples/signed/egress.json --root {_published_root()}" in page


def test_the_signed_example_is_the_current_unsigned_audit():
    signed = json.loads(SIGNED.read_text(encoding="utf-8"))
    unsigned = json.loads(UNSIGNED.read_text(encoding="utf-8"))
    assert signed["tool_version"] == __version__, "the signed example is from another version: sign it again"
    assert signed["findings_digest"] == unsigned["findings_digest"], (
        "the signed example no longer matches the regenerated audit: sign it again")
    assert signed["target"] == unsigned["target"] and signed["subject_digest"] == unsigned["subject_digest"]


def test_a_root_that_is_not_64_hex_digits_is_refused_not_called_tampered():
    """A malformed root is the caller's mistake: the API refuses it as the command line does. A well-formed root that
    did not sign the report is still TAMPERED, and the published one still ATTESTED."""
    import pytest
    report = json.loads(SIGNED.read_text(encoding="utf-8"))
    root = _published_root()
    for bad in (root[:20] + "\u2026", "<the root above>", root[:63], root + "0", "g" * 64):
        with pytest.raises(ValueError):
            verify_report(report, expected_root=bad)
    assert verify_report(report, expected_root=root.upper()) == (True, "ATTESTED")
    assert verify_report(report, expected_root=" " + root + "\n") == (True, "ATTESTED")
    assert verify_report(report, expected_root="f" * 64) == (False, "TAMPERED")

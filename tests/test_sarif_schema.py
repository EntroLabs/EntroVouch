"""SARIF output validated against the OFFICIAL OASIS schema.

This repository named `SARIF 2.1.0` in its README four times and had never once
checked the output against the schema OASIS publishes. What existed was a string
comparison:

    assert s["$schema"].endswith("sarif-2.1.0.json")

That asserts we wrote the right URL. **It does not assert the document conforms to
what is at that URL** — it would pass for a document whose every other field was
wrong, or absent.

⚠️ **The estate's own gate did not catch this, and the reason is worth recording.**
A conformance guard that looks for *signals* near a standards claim can be
satisfied by conformance machinery belonging to a **different** standard, and then
it returns the right verdict for the wrong reason. **Only a test against this
standard's own schema settles this standard's claim.**

**Naming a standard is a CHECKABLE claim.** The rule this repository holds itself
to has two options and no third: either a test runs against that standard's own
published schema or vectors, or the standard is not named. This file is the first
option, taken.

SCHEMA PROVENANCE
-----------------
`tests/schemas/sarif-2.1.0.schema.json` is the OASIS SARIF Technical Committee's
published JSON Schema for SARIF 2.1.0, vendored verbatim and **pinned by SHA-256**
below so a future edit to the fixture cannot silently weaken the check. It is
draft-04, which is why `Draft4Validator` is selected explicitly rather than by
auto-detection.

⛔ The validator is not hand-rolled, deliberately: a bespoke schema checker can be
wrong in the same direction as the generator it checks.

DEPENDENCY NOTE
---------------
`jsonschema` is **test-only**. The runtime stays pure standard library, which is a
property a reader can verify rather than a claim they must accept.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

# Guard on what the test actually USES, not on the module name: a leftover
# directory imports as a namespace package and the `from x import y` below would
# then raise, aborting collection for the entire run.
try:
    from jsonschema import Draft4Validator
except ImportError:  # pragma: no cover
    pytest.skip("jsonschema not installed (test-only extra)", allow_module_level=True)

from dataclasses import asdict

from entrovouch.no_egress_auditor import audit
from entrovouch.sarif import to_sarif

SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-2.1.0.schema.json"

# Pinned so an edit to the vendored fixture is a test failure, not a silent
# weakening of every assertion below.
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"

REPO_ROOT = Path(__file__).resolve().parents[1]


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_vendored_schema_is_the_pinned_one():
    """The reference must be the reference. An unpinned fixture can be edited into
    agreement with whatever it is meant to be checking."""
    actual = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    assert actual == SCHEMA_SHA256, (
        f"vendored SARIF schema changed: {actual}\n"
        "If this was deliberate, re-pin it AND re-run the negative tests below - "
        "a schema that no longer rejects malformed input proves nothing."
    )


def _sarif_for(target: Path) -> dict:
    return to_sarif(asdict(audit(target, label="entrovouch/self@test")))


def test_our_sarif_validates_against_the_official_schema():
    """The claim the README makes, tested against the document the README names."""
    validator = Draft4Validator(_schema())
    doc = _sarif_for(REPO_ROOT / "examples")
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "SARIF schema errors:\n" + "\n".join(
        f"  {list(e.path)}: {e.message}" for e in errors[:10]
    )


def test_a_clean_scan_also_validates():
    """A findings-free run takes a different code path (empty `results`), and an
    empty array is exactly the shape a generator is most likely to get wrong."""
    validator = Draft4Validator(_schema())
    doc = _sarif_for(REPO_ROOT / "entrovouch")
    assert not list(validator.iter_errors(doc))


# ---------------------------------------------------------------------------
# NEGATIVE TESTS — a guard that has never fired is not evidence.
#
# A validator returning zero errors is only meaningful if it is capable of
# returning errors. Each case below is a document the schema MUST reject; if any
# of them passes, the green above means nothing.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,mutate", [
    ("missing runs",        lambda d: d.pop("runs")),
    ("runs is not a list",  lambda d: d.__setitem__("runs", {})),
    ("missing version",     lambda d: d.pop("version")),
    ("wrong version value", lambda d: d.__setitem__("version", "9.9")),
    ("tool is not an object", lambda d: d["runs"][0].__setitem__("tool", "acme")),
    ("result level not in enum",
     lambda d: (d["runs"][0].setdefault("results", [{}]),
                d["runs"][0]["results"][0].__setitem__("level", "catastrophic"))),
])
def test_validator_rejects_malformed_documents(name, mutate):
    validator = Draft4Validator(_schema())
    doc = _sarif_for(REPO_ROOT / "examples")
    mutate(doc)
    assert list(validator.iter_errors(doc)), (
        f"schema accepted a document it must reject ({name}) - "
        "the passing tests above are therefore not evidence of anything"
    )


def test_version_field_says_what_we_think_it_says():
    """SARIF, unlike CycloneDX 1.6, DOES constrain its own version field.

    Recorded because the CycloneDX case went the other way: `specVersion` there is
    declared as a plain string with "1.6" only as an *example*, so a document
    claiming "9.9" validates cleanly. **An external reference is necessary and not
    automatically sufficient, and which of the two applies is a per-standard fact
    that has to be checked rather than assumed.** Here it is constrained, so
    passing this schema does establish the version - and that is a finding about
    SARIF, not a general property of schemas.
    """
    doc = _sarif_for(REPO_ROOT / "examples")
    assert doc["version"] == "2.1.0"
    bad = _sarif_for(REPO_ROOT / "examples")
    bad["version"] = "9.9"
    assert list(Draft4Validator(_schema()).iter_errors(bad)), (
        "SARIF's schema does NOT constrain `version` - if this ever fails, the "
        "README's '2.1.0' claim rests on our own assertion and must say so"
    )

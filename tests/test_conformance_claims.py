"""CONFORMANCE.md must describe the tests that actually exist.

A conformance file that still says SARIF is unvalidated, after
`tests/test_sarif_schema.py` was added, is the same defect as three version
strings that disagree: the document a hostile reader checks first is the one
that is stale. This file pins the claims that were already settled by tests.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = (REPO / "CONFORMANCE.md").read_text(encoding="utf-8")


def _section(heading: str) -> str:
    """Text from `### heading` up to the next `###` or `## `."""
    marker = f"### {heading}"
    start = DOC.find(marker)
    assert start != -1, f"CONFORMANCE.md has no section {heading!r}"
    rest = DOC[start + len(marker):]
    nxt = len(rest)
    for needle in ("\n### ", "\n## "):
        i = rest.find(needle)
        if i != -1:
            nxt = min(nxt, i)
    return rest[:nxt]


def test_sarif_is_listed_as_schema_validated():
    """The 2026-08-30 text said SCHEMA NOT VALIDATED. The test exists now."""
    assert "SCHEMA NOT VALIDATED" not in DOC
    sarif = _section("SARIF 2.1.0")
    assert "VALIDATED" in sarif
    assert "test_sarif_schema.py" in sarif


def test_cyclonedx_still_validated_and_1_7_not_claimed():
    cdx = _section("CycloneDX 1.6")
    assert "VALIDATED" in cdx
    assert "1.7 is NOT claimed" in cdx or "NOT claimed" in cdx


def test_rfc3161_and_vex_and_lamport_are_named_with_disclaimers():
    assert "### RFC 3161" in DOC
    ts = _section("RFC 3161 (trusted timestamps)")
    assert "NOT VERIFIED" in ts or "not validate" in ts.lower()
    vex = _section("VEX (CycloneDX-native)")
    assert "in_triage" in vex
    assert "CWE-" in vex
    assert "CVE-" in vex
    lamport = _section("Lamport-Merkle SHA3-256 (this package's signer)")
    assert "NOT A PUBLISHED STANDARD" in lamport
    assert "FIPS 205" in lamport


def test_fips_names_are_detector_tokens_not_our_signer():
    fips = _section("FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA)")
    assert "DETECTOR TOKENS ONLY" in fips


def test_cisa_2026_sbom_elements_are_not_claimed():
    """We emit a source-manifest SBOM. We do not claim CISA 2026 completeness."""
    assert "### CISA 2026 Minimum Elements for an SBOM" in DOC
    sec = _section("CISA 2026 Minimum Elements for an SBOM")
    assert "NOT CLAIMED" in sec
    assert "entrovouch.sbom" in sec or "sbom.py" in sec


def test_eo14412_cbom_elements_still_unpublished_and_not_claimed():
    sec = _section("CISA / NIST CBOM minimum elements (EO 14412 §5(d))")
    assert "NOT CLAIMED" in sec
    assert "unpublished" in sec.lower()


def test_last_verified_is_not_older_than_the_sarif_schema_test():
    """A date sitting above a stale SARIF paragraph is how this bit us."""
    assert "Last verified 2026-09-01" in DOC or "Last verified 2026-09-" in DOC


def test_source_does_not_claim_the_covenant_is_the_signing_key():
    """The HMAC was removed. A comment that still says otherwise is a lie
    sitting above the live signer, which is the first thing a sceptical
    reader will believe."""
    src = (REPO / "entrovouch" / "no_egress_auditor.py").read_text(encoding="utf-8")
    assert "Covenant text IS the key" not in src
    assert "IGNORED" in src or "ignores the argument" in src.lower() or "NOT a key" in src

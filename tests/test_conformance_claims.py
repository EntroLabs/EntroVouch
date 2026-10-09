"""CONFORMANCE.md must describe the tests that actually exist.

CONFORMANCE.md is the document a hostile reader checks first, so each status it
states must agree with the tests beside it: a standard validated by a test is
listed as validated and names that test, and a standard that is not claimed
says so. This file pins those statements.
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
    """SARIF output is schema-validated by a test, and the document names it."""
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


def test_last_verified_is_a_real_date_no_older_than_the_sarif_paragraph():
    """The date at the top must be a date, and not older than the SARIF paragraph it sits above."""
    import datetime
    import re
    m = re.search(r"Last verified (\d{4}-\d{2}-\d{2})", DOC)
    assert m, "CONFORMANCE.md must carry a 'Last verified YYYY-MM-DD' line"
    assert datetime.date.fromisoformat(m.group(1)) >= datetime.date(2026, 9, 1)


def test_source_does_not_claim_the_covenant_is_the_signing_key():
    """The Covenant text is not a signing key. The source must not say it is:
    a comment above the live signer is the first thing a sceptical reader
    will believe."""
    src = (REPO / "entrovouch" / "no_egress_auditor.py").read_text(encoding="utf-8")
    assert "Covenant text IS the key" not in src
    assert "proves nothing about origin" in src      # the source says what a MAC keyed by published text is worth


def test_csaf_is_listed_as_schema_validated_and_scoped():
    """CSAF output is schema-validated by a test; the document names it and says what is not run."""
    sec = _section("CSAF 2.0 (VEX profile)")
    assert "SCHEMA VALIDATED" in sec
    assert "test_csaf.py" in sec
    assert "NO CONFORMANCE CHECKER RUN" in sec
    assert "under_investigation" in sec
    assert (REPO / "tests" / "test_csaf.py").is_file()


# The term each section names, and every file its "Named in" line points to must contain it.
_NAMED_TERMS = {
    "CycloneDX 1.6": "CycloneDX", "SARIF 2.1.0": "SARIF", "in-toto Statement": "in-toto",
    "RFC 3161 (trusted timestamps)": "RFC 3161", "VEX (CycloneDX-native)": "VEX", "CSAF 2.0 (VEX profile)": "CSAF",
    "Lamport-Merkle SHA3-256 (this package's signer)": "Lamport", "FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA)": "FIPS",
    "CISA 2026 Minimum Elements for an SBOM": "CISA", "CISA / NIST CBOM minimum elements (EO 14412 §5(d))": "EO 14412",
}


def test_every_named_in_file_names_the_standard():
    import re
    for heading, term in _NAMED_TERMS.items():
        m = re.search(r"<sub>Named in: (.*?)</sub>", _section(heading))
        assert m, heading
        for f in re.findall(r"`([^`]+)`", m.group(1)):
            assert term in (REPO / f).read_text(encoding="utf-8"), f"{heading}: {f} does not name {term}"

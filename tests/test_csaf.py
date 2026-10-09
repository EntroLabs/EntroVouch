"""CSAF 2.0 VEX output, validated against the schema OASIS publishes.

The schema is the external reference. It cannot express everything the standard
requires: CSAF 2.0 section 6.1 lists mandatory tests on top of it. No CSAF
conformance checker runs here, so the mandatory tests this output could break
are asserted one by one below, each named by its section number.

`jsonschema` is test-only. The package's runtime stays standard library.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from entrovouch import csaf

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "tests" / "schemas" / "csaf-2.0.schema.json"
SCHEMA_SHA256_16 = "29c114b35b0a3083"
WHEN = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _cbom(*statuses):
    return {"target": "example-tree", "components": [
        {"file": "f.py", "line": i, "primitive": f"P{i}", "category": "hash", "quantum": s}
        for i, s in enumerate(statuses, 1)]}


def _cbom_report(*statuses):
    """The same components as a report the CLI accepts: it names the tool that wrote it and carries its hash."""
    from entrovouch.no_egress_auditor import CBOM_TOOL, canonical_body
    d = dict(_cbom(*statuses), tool=CBOM_TOOL)
    d["content_hash"] = hashlib.sha3_256(canonical_body(d)).hexdigest()
    return d


def _doc(*statuses, key_findings=None, **kw):
    kw.setdefault("publisher_name", "Example Ltd")
    kw.setdefault("publisher_namespace", "https://example.com")
    return csaf.to_csaf(_cbom(*statuses), key_findings=key_findings, now=WHEN, **kw)


# ---------------------------------------------------------------------------
# The external reference
# ---------------------------------------------------------------------------
def test_the_schema_file_is_the_pinned_one():
    assert hashlib.sha256(SCHEMA.read_bytes()).hexdigest()[:16] == SCHEMA_SHA256_16
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$id"] == "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"


def _validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    assert cls is jsonschema.Draft202012Validator
    return cls(schema, format_checker=jsonschema.FormatChecker())


def test_output_validates_against_the_official_schema():
    doc = _doc("BROKEN", "WEAK-RNG", "VULNERABLE", key_findings=[{"kind": "literal-key"}])
    assert len(doc["vulnerabilities"]) == 4
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:6])


@pytest.mark.parametrize("break_it", [
    lambda d: d["document"].pop("publisher"),
    lambda d: d["document"].__setitem__("csaf_version", "9.9"),
    lambda d: d["document"]["tracking"].__setitem__("status", "published"),
    lambda d: d["vulnerabilities"][0]["cwe"].__setitem__("id", "327"),
    lambda d: d["vulnerabilities"][0]["product_status"].__setitem__("under_investigation", []),
    lambda d: d.__setitem__("vulnerabilities", []),
])
def test_the_validator_rejects_a_broken_document(break_it):
    """A check that cannot fail checks nothing: each of these must be refused."""
    doc = _doc("BROKEN")
    break_it(doc)
    assert list(_validator().iter_errors(doc))


# ---------------------------------------------------------------------------
# What the schema cannot express (CSAF 2.0 section 6.1), asserted here
# ---------------------------------------------------------------------------
def test_6_1_1_every_product_id_used_is_defined():
    doc = _doc("BROKEN", "WEAK-RNG")
    defined = {p["product_id"] for p in doc["product_tree"]["full_product_names"]}
    used = {pid for v in doc["vulnerabilities"] for ids in v["product_status"].values() for pid in ids}
    assert used and used <= defined and len(defined) == len(doc["product_tree"]["full_product_names"])


def test_6_1_11_cwe_names_are_the_cwe_lists_own():
    doc = _doc("BROKEN", "WEAK-RNG", key_findings=[{"kind": "literal-key"}])
    got = {v["cwe"]["id"]: v["cwe"]["name"] for v in doc["vulnerabilities"]}
    assert got == {
        "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
        "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        "CWE-798": "Use of Hard-coded Credentials",
    }


def test_6_1_16_and_6_1_18_version_matches_the_one_released_revision():
    t = _doc("BROKEN")["document"]["tracking"]
    assert t["status"] in ("interim", "final")
    assert [r["number"] for r in t["revision_history"]] == [t["version"]] == ["1"]
    assert t["initial_release_date"] == t["current_release_date"] == t["revision_history"][0]["date"] == "2026-01-02T03:04:05Z"


def test_6_1_27_vex_profile_each_statement_has_a_status_and_an_identifier():
    doc = _doc("BROKEN", "WEAK-RNG", "VULNERABLE")
    assert doc["document"]["category"] == "csaf_vex"
    assert doc["vulnerabilities"]
    statuses = {"fixed", "known_affected", "known_not_affected", "under_investigation"}
    for v in doc["vulnerabilities"]:
        assert statuses & set(v["product_status"])
        assert "cve" in v or v.get("ids")


# ---------------------------------------------------------------------------
# What the document says
# ---------------------------------------------------------------------------
def test_every_status_is_under_investigation_and_no_cve_is_named():
    doc = _doc("BROKEN", "WEAK-RNG", "VULNERABLE", key_findings=[{"kind": "literal-key"}])
    for v in doc["vulnerabilities"]:
        assert list(v["product_status"]) == ["under_investigation"]
        assert "cve" not in v
    assert "CVE-" not in json.dumps(doc["vulnerabilities"])


def test_nothing_to_state_is_refused_rather_than_written_empty():
    with pytest.raises(csaf.NothingToState):
        _doc("SAFE", "GROVER-REDUCED", "REVIEW")


def test_the_publisher_is_never_filled_in():
    with pytest.raises(ValueError):
        _doc("BROKEN", publisher_name="  ")
    with pytest.raises(ValueError):
        _doc("BROKEN", publisher_namespace="example.com")
    with pytest.raises(ValueError):
        _doc("BROKEN", publisher_category="issuer")
    doc = _doc("BROKEN")
    assert doc["document"]["publisher"] == {"category": "other", "name": "Example Ltd", "namespace": "https://example.com"}
    assert doc["document"]["tracking"]["generator"]["engine"]["name"] == "entrovouch"


def test_the_tracking_id_follows_the_content_not_the_clock():
    a = _doc("BROKEN")
    b = csaf.to_csaf(_cbom("BROKEN"), publisher_name="Example Ltd", publisher_namespace="https://example.com",
                     now=datetime(2027, 5, 6, tzinfo=timezone.utc))
    c = _doc("BROKEN", "WEAK-RNG")
    ida, idb, idc = (d["document"]["tracking"]["id"] for d in (a, b, c))
    assert ida == idb and ida != idc
    assert csaf.csaf_filename(ida) == ida.lower() + ".json"
    assert csaf.csaf_filename("Example Co: VEX/2026 #1") == "example_co_vex_2026_1.json"


def test_cli_writes_a_valid_document_and_names_the_csaf_file(tmp_path, capsys):
    src = tmp_path / "cbom.json"
    src.write_text(json.dumps(_cbom_report("BROKEN")), encoding="utf-8")
    out = tmp_path / "vex.csaf.json"
    rc = csaf.main([str(src), "--out", str(out), "--publisher-name", "Example Ltd",
                    "--publisher-namespace", "https://example.com"])
    said = capsys.readouterr().out
    assert rc == 0 and "under_investigation" in said and "entrovouch-vex-" in said
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert not list(_validator().iter_errors(doc))


def test_cli_exit_codes(tmp_path, capsys):
    safe = tmp_path / "safe.json"
    safe.write_text(json.dumps(_cbom_report("SAFE")), encoding="utf-8")
    out = tmp_path / "o.json"
    base = ["--out", str(out), "--publisher-name", "Example Ltd"]
    assert csaf.main([str(safe), *base, "--publisher-namespace", "https://example.com"]) == 0
    assert not out.exists() and "nothing written" in capsys.readouterr().out
    assert csaf.main([str(tmp_path / "missing.json"), *base, "--publisher-namespace", "https://example.com"]) == 2
    broken = tmp_path / "b.json"
    broken.write_text(json.dumps(_cbom_report("BROKEN")), encoding="utf-8")
    assert csaf.main([str(broken), *base, "--publisher-namespace", "not-a-uri"]) == 2
    assert not out.exists()


def test_the_module_is_zero_egress():
    from dataclasses import asdict
    from entrovouch.no_egress_auditor import audit
    rep = asdict(audit(REPO / "entrovouch", label="self"))
    offenders = [f for f in rep["findings"] if Path(str(f["file"])).name == "csaf.py"]
    assert not offenders, f"csaf.py acquired network capability: {offenders}"

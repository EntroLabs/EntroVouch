"""SARIF 2.1.0 and in-toto Statement export.

These two formats are how this tool reaches consumers who will never read its
README. The tests therefore check the things a CONSUMER depends on — required
keys, stable identity, and honest labelling of what we do not sign — rather
than only that the functions return something.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entrovouch.attestation import (  # noqa: E402
    PREDICATE_TYPE_AUDIT, PREDICATE_TYPE_CBOM, STATEMENT_TYPE, to_statement,
)
from entrovouch.no_egress_auditor import audit  # noqa: E402
from entrovouch.sarif import RULES, SARIF_VERSION, to_sarif  # noqa: E402
from entrovouch.signer import MerkleSigner  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def dirty_report(tmp_path_factory):
    """A tree with real findings — an empty result set proves very little."""
    d = tmp_path_factory.mktemp("dirty")
    (d / "leaky.py").write_text(
        "import requests\n"
        "import os\n"
        "def go():\n"
        "    os.system('curl https://example.invalid')\n",
        encoding="utf-8")
    (d / "page.html").write_text(
        '<img src="https://cdn.example.invalid/x.png">\n', encoding="utf-8")
    return asdict(audit(d, label="acme/leaky@v1"))


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------
def test_sarif_top_level_shape(dirty_report):
    s = to_sarif(dirty_report)
    assert s["version"] == SARIF_VERSION == "2.1.0"
    assert s["$schema"].endswith("sarif-2.1.0.json")
    assert len(s["runs"]) == 1
    driver = s["runs"][0]["tool"]["driver"]
    assert driver["name"] and driver["version"] and driver["informationUri"]


def test_sarif_has_results_and_they_are_well_formed(dirty_report):
    s = to_sarif(dirty_report)
    results = s["runs"][0]["results"]
    assert results, "fixture must produce findings or this proves nothing"
    for r in results:
        assert r["ruleId"] in RULES
        assert r["level"] in ("none", "note", "warning", "error")
        assert r["message"]["text"]
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1


def test_every_emitted_rule_is_declared(dirty_report):
    """GitHub renders `ruleId`; an undeclared rule shows as a bare string."""
    s = to_sarif(dirty_report)
    declared = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
    used = {r["ruleId"] for r in s["runs"][0]["results"]}
    assert used <= declared, f"undeclared rules emitted: {used - declared}"


def test_fingerprint_survives_a_line_shift(tmp_path):
    """A comment inserted above a finding must not re-open every alert.

    This is the failure that makes a code-scanning integration into noise and
    gets it muted: line-based identity closes N alerts and opens N identical
    ones on a cosmetic edit.
    """
    src = tmp_path / "m.py"
    src.write_text("import socket\n", encoding="utf-8")
    before = to_sarif(asdict(audit(tmp_path, label="x")))

    src.write_text("# a newly added comment line\nimport socket\n", encoding="utf-8")
    after = to_sarif(asdict(audit(tmp_path, label="x")))

    fp = lambda s: {r["partialFingerprints"]["entrovouchFindingV1"]  # noqa: E731
                    for r in s["runs"][0]["results"]}
    line = lambda s: {r["locations"][0]["physicalLocation"]["region"]["startLine"]  # noqa: E731
                      for r in s["runs"][0]["results"]}

    assert line(before) != line(after), "the line genuinely moved"
    assert fp(before) == fp(after), "fingerprint must NOT move with the line"


def test_sarif_carries_scope_and_binding(dirty_report):
    """A findings list without its scope statement is the overclaim we avoid."""
    props = to_sarif(dirty_report)["runs"][0]["properties"]
    assert props["scopeStatement"], "scope must travel with the findings"
    assert props["subjectDigest"] and props["findingsDigest"]
    assert props["verdict"] in ("CLEAN", "FINDINGS")


def test_sarif_level_is_not_inferred(dirty_report):
    """Severity is the consumer's policy, not ours — but it is overridable."""
    assert all(r["level"] == "warning" for r in to_sarif(dirty_report)["runs"][0]["results"])
    strict = to_sarif(dirty_report, level="error")
    assert all(r["level"] == "error" for r in strict["runs"][0]["results"])
    with pytest.raises(ValueError):
        to_sarif(dirty_report, level="catastrophic")


def test_sarif_is_json_serialisable(dirty_report):
    json.loads(json.dumps(to_sarif(dirty_report)))


# ---------------------------------------------------------------------------
# in-toto Statement
# ---------------------------------------------------------------------------
def test_statement_shape(dirty_report):
    st = to_statement(dirty_report)
    assert st["_type"] == STATEMENT_TYPE == "https://in-toto.io/Statement/v1"
    assert st["predicateType"] == PREDICATE_TYPE_AUDIT
    assert st["subject"] == dirty_report["subject"]
    assert st["subject"][0]["digest"]["sha3-256"]


def test_predicate_excludes_envelope_fields(dirty_report):
    """The predicate is the claim; the envelope is not part of the claim."""
    pred = to_statement(dirty_report)["predicate"]
    for k in ("signature", "signature_algorithm", "public_root",
              "content_hash", "subject"):
        assert k not in pred, f"{k} belongs to the envelope, not the predicate"
    assert pred["verdict"] and "findings" in pred
    assert pred["scope_statement"], "limits travel with the claim"


def test_unbound_report_refuses_to_become_a_statement():
    """Rather than inventing a subject from free text."""
    legacy = {"target": "acme/thing@v1", "verdict": "CLEAN", "findings": []}
    with pytest.raises(ValueError, match="nothing"):
        to_statement(legacy)


def test_signed_statement_says_dsse_cannot_check_it():
    """The honesty requirement, asserted in the artifact rather than the docs."""
    signer = MerkleSigner(seed=b"\x07" * 32, height=3, next_index=0, path=None)
    rep = asdict(audit(REPO / "entrovouch", label="self", signer=signer))
    st = to_statement(rep)
    assert st["signature"]["public_root"] == signer.public_root
    note = st["signature"]["note"].lower()
    assert "dsse" in note and "cannot" in note
    assert "unverified" in note


def test_unsigned_statement_signature_is_none(dirty_report):
    assert to_statement(dirty_report)["signature"] is None


def test_cbom_predicate_type_is_distinct():
    assert PREDICATE_TYPE_CBOM != PREDICATE_TYPE_AUDIT
    assert PREDICATE_TYPE_AUDIT.endswith("/v1"), "predicate types must be versioned"


# ---------------------------------------------------------------------------
# The new modules must not weaken the package's own properties
# ---------------------------------------------------------------------------
def test_new_modules_do_not_break_the_self_audit():
    rep = audit(REPO / "entrovouch", label="self")
    assert rep.verdict == "CLEAN", (
        f"sarif.py/attestation.py introduced egress findings: {rep.findings}"
    )


def test_new_modules_import_nothing_outside_stdlib():
    """Zero dependencies is the property that makes the no-egress claim checkable.

    Uses the AST, not line matching — the same discipline the auditor itself
    applies. The first version of this test scanned lines and FAILED on its own
    module docstring, because a sentence in `sarif.py` wraps such that a line
    begins "from nobody." That is precisely the false-positive class the
    README claims the tool avoids ("a docstring that mentions `requests` does
    not fire"), reproduced in a test written to check that tool. A scanner that
    reads prose as code is the thing being guarded against.
    """
    import ast

    allowed = {"argparse", "hashlib", "json", "sys", "pathlib", "__future__"}
    for mod in ("sarif", "attestation"):
        src = (REPO / "entrovouch" / f"{mod}.py").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Import):
                for a in node.names:
                    root = a.name.split(".")[0]
                    assert root in allowed, f"{mod}.py imports non-stdlib {root!r}"
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue                       # relative: our own package
                root = (node.module or "").split(".")[0]
                assert root in allowed, f"{mod}.py imports non-stdlib {root!r}"


@pytest.mark.parametrize("mod", ["sarif", "attestation"])
def test_cli_round_trips(mod, tmp_path):
    src = tmp_path / "s.py"
    src.write_text("import socket\n", encoding="utf-8")
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(asdict(audit(tmp_path, label="t"))), encoding="utf-8")

    out = tmp_path / f"{mod}.out.json"
    r = subprocess.run(
        [sys.executable, "-m", f"entrovouch.{mod}", str(rep), "--out", str(out)],
        capture_output=True, text=True, cwd=str(REPO), timeout=180,
        encoding="utf-8", errors="replace",
    )
    assert r.returncode == 0, r.stderr
    json.loads(out.read_text(encoding="utf-8"))

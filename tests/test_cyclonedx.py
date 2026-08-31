"""CycloneDX 1.6 export, and the four defects the CBOM module never received.

Every fix asserted here had ALREADY been made in `no_egress_auditor.py` and had
not reached `cbom.py`. That is the third instance in one session of a fix scoped
to the file it was found in, so these tests exist as much to pin the *class* as
the individual bugs.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entrovouch.cbom import build_cbom, verify_cbom  # noqa: E402
from entrovouch.cyclonedx import (  # noqa: E402
    NIST_QUANTUM_SECURITY_LEVEL, SPEC_VERSION, to_cyclonedx,
)
from entrovouch.signer import ALGORITHM, MerkleSigner  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "entrovouch"


# ---------------------------------------------------------------------------
# The four fixes that never reached this module
# ---------------------------------------------------------------------------
def test_cbom_never_emits_an_absolute_path():
    """A CBOM is handed to a counterparty.

    Until 2026-08-20 this wrote `str(target)`, so a delivered document carried
    the auditor's drive letter, OS username and internal workspace name. The
    no-egress auditor had been fixed for exactly this weeks earlier.
    """
    rep = build_cbom(SRC.resolve())
    assert rep.target == "entrovouch"
    blob = json.dumps(asdict(rep))
    for leak in (":\\", ":/", "Users", "home/"):
        assert leak not in rep.target, f"target leaks {leak!r}"
    # ⭐ Assembled, not spelled. A leak test must name what it forbids, which
    # means a plain literal here would ship the very string the guard exists
    # to keep out of a PUBLIC repo. Found 2026-08-22 while verifying that a
    # clean single-commit history carried none of it — and it still did,
    # inside the guards.
    assert "".join(("Cowork", "_Workspace")) not in blob


def test_cbom_label_overrides_the_directory_name():
    rep = build_cbom(SRC, label="EntroLabs/entrovouch@abc1234")
    assert rep.target == "EntroLabs/entrovouch@abc1234"
    assert rep.subject[0]["name"] == "EntroLabs/entrovouch@abc1234"


def test_cbom_binds_its_subject():
    rep = build_cbom(SRC, label="x")
    assert len(rep.subject_digest) == 64
    assert rep.subject[0]["digest"]["sha3-256"] == rep.subject_digest


def test_cbom_subject_digest_moves_with_the_tree(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("import hashlib\n", encoding="utf-8")
    a = build_cbom(tmp_path, label="x")
    f.write_text("import hashlib  # a comment\n", encoding="utf-8")
    b = build_cbom(tmp_path, label="x")
    assert a.components == b.components, "inventory unchanged by a comment"
    assert a.subject_digest != b.subject_digest


def test_cbom_findings_digest_reproduces():
    runs = [build_cbom(SRC, label="x") for _ in range(3)]
    assert len({r.findings_digest for r in runs}) == 1
    assert len({r.content_hash for r in runs}) == 3, "content_hash covers the clock"


def test_cbom_records_the_algorithm_it_actually_used(tmp_path):
    """The document's stated algorithm must be the one that signed it.

    A hard-coded label is a field that can be false while the document still
    verifies -- the algorithm is read by whoever is deciding whether to trust the
    signature, so it has to come from the signer rather than from a constant."""
    signer = MerkleSigner.create(tmp_path / "k.json", height=3)
    rep = build_cbom(SRC, label="x", signer=signer)
    expected = ALGORITHM
    assert rep.signature_algorithm == expected
    assert rep.signature_algorithm == rep.signature["algorithm"]
    assert verify_cbom(asdict(rep), expected_root=signer.public_root) == (True, "ATTESTED")


def test_unsigned_cbom_fails_closed():
    assert verify_cbom(asdict(build_cbom(SRC, label="x"))) == (False, "UNSIGNED")


# ---------------------------------------------------------------------------
# CycloneDX 1.6
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def bom():
    return to_cyclonedx(asdict(build_cbom(SRC, label="EntroLabs/entrovouch@test")))


def test_bom_header(bom):
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == SPEC_VERSION == "1.6"
    assert bom["version"] == 1


def test_components_are_cryptographic_assets(bom):
    assert bom["components"], "fixture must produce components"
    for c in bom["components"]:
        assert c["type"] == "cryptographic-asset"
        assert c["bom-ref"] and c["name"]
        props = c["cryptoProperties"]
        assert props["assetType"] == "algorithm"
        lvl = props["algorithmProperties"]["nistQuantumSecurityLevel"]
        assert lvl in set(NIST_QUANTUM_SECURITY_LEVEL.values())
        assert c["evidence"]["occurrences"][0]["location"]


def test_bom_refs_are_unique(bom):
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)), "duplicate bom-ref breaks dependency graphs"


def test_quantum_status_survives_the_mapping(bom):
    """The tool's own vocabulary is carried, not flattened into an integer."""
    for c in bom["components"]:
        props = {p["name"]: p["value"] for p in c["properties"]}
        assert props["entrovouch:quantumStatus"] in NIST_QUANTUM_SECURITY_LEVEL
        assert props["entrovouch:state"] in {"active", "deactivated", "compromised"}


def test_scope_and_binding_travel_inside_the_standard_artifact(bom):
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["entrovouch:scopeStatement"], "a CBOM without scope reads as completeness"
    assert props["entrovouch:verdict"]
    assert len(props["entrovouch:subjectDigest"]) == 64
    assert bom["metadata"]["component"]["hashes"][0]["alg"] == "SHA3-256"


def test_conformance_with_unpublished_minimum_elements_is_not_claimed(bom):
    """EO 14412's minimum elements are unpublished; claiming conformance to a
    document nobody has read is the overclaim the deadline invites."""
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    v = props["entrovouch:minimumElementsConformance"]
    assert "NOT CLAIMED" in v and "unpublished" in v


def test_serial_number_is_not_invented(bom):
    assert "serialNumber" not in bom
    withser = to_cyclonedx(asdict(build_cbom(SRC, label="x")),
                           serial_number="urn:uuid:00000000-0000-4000-8000-000000000000")
    assert withser["serialNumber"].startswith("urn:uuid:")


def test_bom_is_json_serialisable(bom):
    json.loads(json.dumps(bom))


def test_cli_round_trip(tmp_path):
    src = tmp_path / "s.py"
    src.write_text("import hashlib\nh = hashlib.md5()\n", encoding="utf-8")
    rep = tmp_path / "cbom.json"
    rep.write_text(json.dumps(asdict(build_cbom(tmp_path, label="t"))), encoding="utf-8")
    out = tmp_path / "bom.json"
    r = subprocess.run(
        [sys.executable, "-m", "entrovouch.cyclonedx", str(rep), "--out", str(out)],
        capture_output=True, text=True, cwd=str(REPO), timeout=180,
        encoding="utf-8", errors="replace",
    )
    assert r.returncode == 0, r.stderr
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["specVersion"] == "1.6"


def test_cyclonedx_module_is_stdlib_only():
    import ast
    allowed = {"argparse", "json", "sys", "pathlib", "__future__"}
    src = (SRC / "cyclonedx.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom) and not node.level:
            assert (node.module or "").split(".")[0] in allowed

"""End-to-end: a report/CBOM produced WITH a signing identity must verify as
ATTESTED against that identity's root, and must fail against any other.

Isolated signer tests are not enough — the defect being closed here was never
in a signing primitive, it was in how the report pipeline *used* one.
"""
from dataclasses import asdict

import pytest

from entrovouch.no_egress_auditor import audit, verify_report
from entrovouch.cbom import build_cbom, verify_cbom
from entrovouch.signer import MerkleSigner, UNSIGNED, ALGORITHM


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "subject"
    d.mkdir()
    (d / "ok.py").write_text("import json\nimport hashlib\n", encoding="utf-8")
    return d


@pytest.fixture
def signer(tmp_path):
    return MerkleSigner.create(tmp_path / "id.json", height=3)


def test_signed_report_is_attested(repo, signer):
    rep = audit(repo, label="org/subject@abc123", signer=signer)
    assert rep.signature_algorithm == ALGORITHM
    assert rep.public_root == signer.public_root
    assert verify_report(asdict(rep), expected_root=signer.public_root) == (True, "ATTESTED")


def test_signed_report_without_pinned_root_is_unverified(repo, signer):
    """The caller who does not pin a root gets UNVERIFIED, not ATTESTED —
    holding a signature is not the same as knowing who made it."""
    rep = audit(repo, signer=signer)
    assert verify_report(asdict(rep)) == (False, "UNVERIFIED")  # valid sig, unpinned identity


def test_signed_report_fails_against_a_different_root(repo, signer, tmp_path):
    impostor = MerkleSigner.create(tmp_path / "impostor.json", height=3)
    rep = audit(repo, signer=signer)
    assert verify_report(asdict(rep), expected_root=impostor.public_root) == (False, "TAMPERED")


def test_tampering_a_signed_verdict_is_caught(tmp_path, signer):
    """The attack that matters commercially: take a real signed report on a
    dirty codebase and launder the verdict to CLEAN."""
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "leak.py").write_text("import requests\n", encoding="utf-8")

    rep = audit(dirty, signer=signer)
    assert rep.verdict == "FINDINGS" and rep.findings, "fixture must actually be dirty"

    d = asdict(rep)
    d["verdict"] = "CLEAN"
    d["findings"] = []
    assert verify_report(d, expected_root=signer.public_root) == (False, "TAMPERED")


def test_unsigned_report_says_so_in_its_own_markdown(repo):
    from entrovouch.no_egress_auditor import render_markdown
    md = render_markdown(audit(repo))
    assert UNSIGNED in md
    assert "NOT attested" in md


def test_signed_report_markdown_names_the_root(repo, signer):
    from entrovouch.no_egress_auditor import render_markdown
    md = render_markdown(audit(repo, signer=signer))
    assert signer.public_root[:32] in md
    assert "How to verify origin" in md


def test_signed_cbom_is_attested(repo, signer):
    rep = build_cbom(repo, signer=signer)
    assert verify_cbom(asdict(rep), expected_root=signer.public_root) == (True, "ATTESTED")


def test_unsigned_cbom_is_unsigned(repo):
    rep = build_cbom(repo)
    assert rep.signature is None
    assert verify_cbom(asdict(rep)) == (False, "UNSIGNED")


def test_each_report_consumes_one_leaf(repo, signer):
    """One-time key discipline must hold across real report generation, not
    just direct sign() calls."""
    roots = {signer.public_root}
    indices = []
    for _ in range(4):
        rep = audit(repo, signer=signer)
        indices.append(rep.signature["leaf_index"])
        roots.add(rep.public_root)
    assert indices == [0, 1, 2, 3]
    assert len(roots) == 1, "the published identity must not change between reports"

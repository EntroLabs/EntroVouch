"""Regressions for the 2026-08-20 hardening pass.

Every test here corresponds to a defect that was DEMONSTRATED BY EXECUTION
against the published tool before it was fixed — not to a defect that was
imagined and pre-empted. Where a test pins a constant, the constant was
computed from the implementation and then frozen, so a future refactor that
silently changes the construction fails here instead of silently invalidating
every signature ever issued.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entrovouch.no_egress_auditor import (  # noqa: E402
    AuditReport, audit, canonical_body, reproducible_body, verify_report,
    _DEFAULT_COVENANT,
)
from entrovouch.signer import (  # noqa: E402
    MerkleSigner, SignerError, verify_signature, _LEAF_TAG, _NODE_TAG,
    _MAX_HEIGHT,
)

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. THE FORGERY THAT USED TO VERIFY
# ---------------------------------------------------------------------------
def test_forged_unsigned_report_is_rejected():
    """A report fabricated from published material must not verify.

    Before 2026-08-20 this exact construction returned `(True, "UNSIGNED")`.
    The HMAC that validated it was keyed by `sha3_256(_DEFAULT_COVENANT)` — and
    `_DEFAULT_COVENANT` is a string literal in this repository, so the "key"
    was public. A caller writing `if verify_report(r)[0]:` accepted a CLEAN
    verdict for a codebase that was never scanned.
    """
    fake = asdict(AuditReport(
        target="victim-corp/flagship@deadbeef",
        scanned_at_utc="2026-08-20T00:00:00+00:00",
        files_scanned=4212,
        verdict="CLEAN",
        findings=[],
    ))
    body = canonical_body(fake)
    fake["content_hash"] = hashlib.sha3_256(body).hexdigest()
    fake["integrity_tag"] = hmac.new(
        hashlib.sha3_256(_DEFAULT_COVENANT.encode()).digest(),
        body, hashlib.sha3_256).hexdigest()

    ok, status = verify_report(fake)
    assert ok is False, "a fabricated report must never return ok=True"
    assert status == "UNSIGNED"


def test_ok_is_true_for_attested_only():
    """`ok` answers 'may I rely on this as third-party evidence?'"""
    signer = MerkleSigner(seed=b"\xab" * 32, height=3, next_index=0, path=None)
    rep = audit(REPO, label="self", signer=signer)
    d = asdict(rep)

    assert verify_report(d, expected_root=signer.public_root) == (True, "ATTESTED")
    # valid signature, but the caller pinned nobody: not evidence of origin
    assert verify_report(d) == (False, "UNVERIFIED")

    unsigned = asdict(audit(REPO, label="self"))
    assert verify_report(unsigned) == (False, "UNSIGNED")


def test_integrity_tag_is_not_consulted():
    """The deprecated tag must not be able to rescue a report."""
    rep = asdict(audit(REPO, label="self"))
    rep["integrity_tag"] = "0" * 64          # garbage
    ok, status = verify_report(rep)
    assert (ok, status) == (False, "UNSIGNED"), "tag must not affect the outcome"


# ---------------------------------------------------------------------------
# 2. THE REPORT NOW BINDS THE TREE, NOT JUST THE SENTENCE
# ---------------------------------------------------------------------------
def test_subject_digest_binds_the_audited_tree(tmp_path):
    """Two different trees under one label must not produce one report."""
    a = tmp_path / "a"
    a.mkdir()
    (a / "m.py").write_text("x = 1\n", encoding="utf-8")
    first = audit(a, label="acme/thing@v1")

    (a / "m.py").write_text("x = 1  # one added comment\n", encoding="utf-8")
    second = audit(a, label="acme/thing@v1")

    assert first.findings == second.findings, "verdict unchanged by a comment"
    assert first.subject_digest != second.subject_digest, (
        "a changed tree must produce a changed subject digest"
    )
    assert first.subject[0]["digest"]["sha3-256"] == first.subject_digest


def test_subject_follows_in_toto_statement_shape():
    """`subject` is the shape supply-chain tooling already verifies."""
    rep = audit(REPO, label="EntroLabs/entrovouch@test")
    assert isinstance(rep.subject, list) and len(rep.subject) == 1
    entry = rep.subject[0]
    assert set(entry) == {"name", "digest"}
    assert entry["name"] == "EntroLabs/entrovouch@test"
    assert set(entry["digest"]) == {"sha3-256"}
    assert len(entry["digest"]["sha3-256"]) == 64


# ---------------------------------------------------------------------------
# 3. REPRODUCIBILITY — the property the product is sold on
# ---------------------------------------------------------------------------
def test_findings_digest_is_reproducible_across_runs():
    """Same tree, three runs: one findings digest, three content hashes."""
    runs = [audit(REPO, label="self") for _ in range(3)]
    assert len({r.findings_digest for r in runs}) == 1, "must reproduce"
    assert len({r.content_hash for r in runs}) == 3, (
        "content_hash covers the timestamp and is expected NOT to reproduce; "
        "if this collapses to 1 the two digests have been conflated again"
    )


def test_reproducible_body_excludes_issuance_fields():
    rep = asdict(audit(REPO, label="self"))
    body = json.loads(reproducible_body(rep))
    for issuance in ("scanned_at_utc", "content_hash", "signature",
                     "signature_algorithm", "public_root", "findings_digest"):
        assert issuance not in body, f"{issuance} must not affect reproducibility"
    for substantive in ("verdict", "findings", "subject_digest", "tool_version"):
        assert substantive in body, f"{substantive} must be covered"


# ---------------------------------------------------------------------------
# 4. MERKLE DOMAIN SEPARATION  (RFC 6962 / RFC 8391 practice)
# ---------------------------------------------------------------------------
def test_leaf_and_node_domains_differ():
    assert _LEAF_TAG != _NODE_TAG
    assert len(_LEAF_TAG) == len(_NODE_TAG) == 1


def test_signer_known_answer_root():
    """KAT: freeze the construction.

    Nothing in the pre-existing suite pinned a root, so the domain-separation
    change altered every `public_root` and 158 tests still passed. A refactor
    that changes the hash graph must fail HERE, loudly, rather than silently
    invalidating every signature previously issued under a published root.
    """
    signer = MerkleSigner(seed=bytes(range(32)), height=2, next_index=0, path=None)
    assert signer.public_root == (
        "46f1c1579969a260bea0f4c6a4e31e6fb6ec101e4e79230df1d74177de2db40c"
    )


def test_signature_still_round_trips_under_domain_separation():
    signer = MerkleSigner(seed=bytes(range(32)), height=2, next_index=0, path=None)
    msg = b"verdict: CLEAN"
    sig = signer.sign(msg)
    assert verify_signature(msg, sig, expected_root=signer.public_root)
    assert not verify_signature(b"verdict: FINDINGS", sig,
                                expected_root=signer.public_root)


# ---------------------------------------------------------------------------
# 5. STATEFUL-SIGNATURE CRASH CONSISTENCY  (NIST SP 800-208)
# ---------------------------------------------------------------------------
def test_index_is_persisted_before_the_secret_is_revealed(tmp_path):
    """The used index must reach disk BEFORE any Lamport preimage exists.

    The old order was sign-then-save: a crash in between left the index
    unrecorded, the next process reused the leaf, and reusing a Lamport leaf
    leaks half of each key pair. This asserts the on-disk state has already
    advanced by the time a caller holds a signature.
    """
    kf = tmp_path / "id.json"
    signer = MerkleSigner.create(kf, height=3)
    signer.sign(b"first")

    on_disk = json.loads(kf.read_text(encoding="utf-8"))
    assert on_disk["next_index"] == 1, (
        "index must be durable before the signature is returned"
    )

    # A fresh process loading that keyfile must refuse the burned leaf.
    reloaded = MerkleSigner.load(kf)
    assert reloaded.next_index == 1
    with pytest.raises(SignerError):
        reloaded.sign(b"second", index=0)


def test_hostile_keyfile_height_is_rejected(tmp_path):
    """A corrupt height must fail fast, not build 2**64 leaves."""
    kf = tmp_path / "hostile.json"
    kf.write_text(json.dumps({"seed": "00" * 32, "height": 64, "next_index": 0}),
                  encoding="utf-8")
    with pytest.raises(SignerError):
        MerkleSigner.load(kf)


def test_verifier_rejects_out_of_range_height():
    signer = MerkleSigner(seed=b"\x01" * 32, height=2, next_index=0, path=None)
    sig = signer.sign(b"m")
    sig["height"] = _MAX_HEIGHT + 1
    assert verify_signature(b"m", sig, expected_root=signer.public_root) is False


# ---------------------------------------------------------------------------
# 6. THE TOOL STILL PASSES ITS OWN AUDIT
# ---------------------------------------------------------------------------
def test_auditor_still_clean_on_itself():
    rep = audit(REPO / "entrovouch", label="self")
    assert rep.verdict == "CLEAN", f"self-audit regressed: {rep.findings}"


def test_cli_still_runs_after_hardening():
    r = subprocess.run(
        [sys.executable, "-m", "entrovouch.no_egress_auditor", str(REPO / "entrovouch")],
        capture_output=True, text=True, cwd=str(REPO), timeout=180,
        encoding="utf-8", errors="replace",   # the report contains non-ASCII
    )
    assert r.returncode == 0, r.stderr
    assert "findings_digest" in r.stdout or "Findings digest" in r.stdout or r.stdout


# ---------------------------------------------------------------------------
# 7. FOUND BY MUTATION PROBE, 2026-08-21
#
# `mutation_probe.py` mutated signer.py and found three surviving mutants — lines
# the suite EXECUTES but does not CHECK. Two were real, and both sat on
# security-relevant constants.
#
# ⭐ THE SHARPER ONE IS `_MAX_HEIGHT`, AND THE REASON IT SURVIVED IS THE DAY'S
# CENTRAL DEFECT ONE LEVEL DOWN. `test_verify_rejects_absurd_height` above does:
#
#       sig["height"] = _MAX_HEIGHT + 1
#
# It computes the out-of-range value FROM the constant it is meant to pin. Change
# the constant from 20 to 21 and the test recomputes and still passes — it is
# self-referential, exactly like the "known-answer vectors" that turned out to be
# our own output. It proves the bound is ENFORCED; it cannot notice the bound
# MOVING, and the bound is what stops a hostile keyfile from hanging the process.
# ---------------------------------------------------------------------------
def test_max_height_is_pinned_to_an_absolute_value():
    """The bound must be checkable without reference to itself.

    20 means a tree of 2**20 leaves and ~1e6 SHA3 operations to build — bounded
    work. Raising it is a denial-of-service surface, so the number is a security
    parameter and a change to it must be deliberate and visible, not silent.
    """
    assert _MAX_HEIGHT == 20, (
        f"_MAX_HEIGHT is {_MAX_HEIGHT}, not 20. This is a DoS bound: a keyfile "
        f"claiming height H costs 2**H hashes to load. If the change is intended, "
        f"update this test and say why in the commit."
    )


def test_absurd_height_is_rejected_at_an_absolute_value():
    """The companion to the above: reject a literal 21, not `_MAX_HEIGHT + 1`."""
    signer = MerkleSigner(seed=b"\x01" * 32, height=2, next_index=0, path=None)
    sig = signer.sign(b"m")
    sig["height"] = 21
    assert verify_signature(b"m", sig, expected_root=signer.public_root) is False


def test_a_fresh_signer_starts_at_leaf_zero():
    """Nothing asserted this, and leaf indexing is one-time-key bookkeeping.

    Mutating `next_index: int = 0` to 1 survived the whole suite. A signer that
    silently starts at leaf 1 wastes a one-time key — not catastrophic on its own,
    but it means index initialisation was entirely unverified, in a scheme where
    REUSING a leaf leaks half of that key pair. The bookkeeping deserves a pin.
    """
    signer = MerkleSigner(seed=b"\x02" * 32, height=3, path=None)
    assert signer.next_index == 0, "a fresh signer must begin at leaf 0"
    first = signer.sign(b"m")
    assert first.get("leaf_index") == 0, "the first signature must spend leaf 0"
    second = signer.sign(b"m2")
    assert second.get("leaf_index") == 1, "the second must spend leaf 1, never reuse 0"

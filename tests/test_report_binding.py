"""The identity fields must be INSIDE the bytes they describe.

`signature_algorithm` and `public_root` are covered by the signed body. If
`canonical_body()` dropped them, a report could DISPLAY one signature scheme
while carrying another and still verify, and that displayed string is precisely
what a counterparty reads to satisfy a contract clause. A value can be
cryptographically correct and semantically unbound, so these tests execute the
attack: alter each identity field and require verification to fail.

Only fields that cannot be inside the thing they describe (the signature, the
content hash, the integrity tag) are excluded from the signed body, and that
set is pinned here.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import tempfile

import pytest

from entrovouch.no_egress_auditor import (
    _ISSUANCE_FIELDS,
    _SIG_FIELDS,
    audit,
    canonical_body,
    reproducible_body,
    verify_report,
)
from entrovouch.signer import MerkleSigner

SIGNERS = [MerkleSigner]


def _signed(tmp_path, maker, target="entrovouch"):
    d = pathlib.Path(tmp_path)
    d.mkdir(parents=True, exist_ok=True)
    signer = maker.create(d / "k.json")
    rep = audit(pathlib.Path(target), signer=signer, label="org/repo@deadbeef")
    return dataclasses.asdict(rep)


# ---------------------------------------------------------------------------
# The attack itself, one test per signer.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("maker", SIGNERS, ids=lambda m: m.__name__)
def test_swapping_the_algorithm_name_is_detected(tmp_path, maker):
    """The exact attack: a renamed scheme must give (False, 'TAMPERED')."""
    d = _signed(tmp_path, maker)
    root = d["public_root"]
    assert verify_report(d, expected_root=root) == (True, "ATTESTED")

    forged = dict(d)
    forged["signature_algorithm"] = "SomeOtherScheme-512 (post-quantum)"
    if forged["signature_algorithm"] == d["signature_algorithm"]:
        forged["signature_algorithm"] = "Lamport-Merkle-SHA3-256 (hash-based, post-quantum)"

    ok, status = verify_report(forged, expected_root=root)
    assert (ok, status) == (False, "TAMPERED"), (
        "a report that misnames its own signature scheme verified as genuine"
    )


@pytest.mark.parametrize("maker", SIGNERS, ids=lambda m: m.__name__)
def test_swapping_the_public_root_is_detected(tmp_path, maker):
    """The DISPLAYED root is what a human reads off the page. Bind it."""
    d = _signed(tmp_path, maker)
    forged = dict(d)
    forged["public_root"] = "0" * 64
    assert verify_report(forged, expected_root=d["public_root"]) == (False, "TAMPERED")


@pytest.mark.parametrize("maker", SIGNERS, ids=lambda m: m.__name__)
def test_identity_fields_are_actually_in_the_signed_bytes(tmp_path, maker):
    """Structural, not behavioural: prove the bytes contain the claim.

    The behavioural tests above could pass for the wrong reason (some unrelated
    field shifting). This one reads the signed body directly.
    """
    d = _signed(tmp_path, maker)
    body = json.loads(canonical_body(d))
    assert body["signature_algorithm"] == d["signature_algorithm"]
    assert body["public_root"] == d["public_root"]
    assert "signature" not in body, "a signature cannot be inside what it signs"
    assert "content_hash" not in body


def test_sig_fields_holds_only_the_self_referential_three():
    """A guard on the SET, so re-widening it is a loud failure.

    `_SIG_FIELDS` may contain only fields that genuinely cannot be inside the
    thing they describe. Anything else added here silently leaves a
    reader-visible claim unauthenticated.
    """
    assert _SIG_FIELDS == {"signature", "content_hash", "integrity_tag"}


# ---------------------------------------------------------------------------
# ...without breaking the property `findings_digest` exists to provide.
# ---------------------------------------------------------------------------
def test_findings_digest_is_independent_of_who_signed(tmp_path):
    """Signer identity must NOT enter the reproducible digest.

    If it did, the same audit of the same tree would reproduce differently
    depending on the signer, and 'clone it and compare' would stop working.
    """
    # NOTE: the same LABEL throughout. `target` is deliberately inside the
    # reproducible body -- two audits of one tree under different labels are
    # different claims and must not collide. Only the SIGNER is varied here.
    unsigned = dataclasses.asdict(
        audit(pathlib.Path("entrovouch"), label="org/repo@deadbeef"))
    merkle = _signed(tmp_path / "a", MerkleSigner)

    # Same tree, same label, signed and unsigned, one digest.
    assert unsigned["findings_digest"] == merkle["findings_digest"]

    for name in ("signature_algorithm", "public_root"):
        assert name in _ISSUANCE_FIELDS
        assert name not in json.loads(reproducible_body(merkle))


def test_content_hash_still_differs_per_issuance(tmp_path):
    """The timestamp must still make each issuance distinguishable."""
    a = _signed(tmp_path / "a", MerkleSigner)
    b = _signed(tmp_path / "b", MerkleSigner)
    assert a["content_hash"] != b["content_hash"]
    assert a["findings_digest"] == b["findings_digest"]


# ---------------------------------------------------------------------------
# The subject name for `.`, the most natural invocation there is.
# ---------------------------------------------------------------------------
def test_dot_target_does_not_produce_an_empty_subject():
    """`Path(".").name` is "", so the target is resolved before it is named.

    An in-toto Statement whose subject has no name defeats the very
    interoperability the subject field was added for.
    """
    d = dataclasses.asdict(audit(pathlib.Path(".")))
    assert d["target"], "auditing '.' produced a report with a blank target"
    assert d["subject"][0]["name"] == d["target"]
    assert d["subject"][0]["name"] != ""


def test_dot_target_still_leaks_no_absolute_path():
    """Naming `.` resolves a relative path. The resolved absolute path must
    not reach the report: only the directory's own name does."""
    d = dataclasses.asdict(audit(pathlib.Path(".")))
    here = pathlib.Path(".").resolve()
    assert d["target"] == here.name
    assert str(here.parent) not in json.dumps(d)
    assert ":" not in d["target"] and "/" not in d["target"] and "\\" not in d["target"]


# ---------------------------------------------------------------------------
# Reader-facing: the digests that reproduce must be ON THE PAGE.
# ---------------------------------------------------------------------------
def test_markdown_shows_the_digest_that_reproduces():
    """The markdown a human reads must show `findings_digest` and
    `subject_digest`, not only `content_hash`. `content_hash` is the one value
    guaranteed to differ between two honest runs, so a reader shown only that
    would compare it, see a mismatch, and conclude forgery. It is shown with
    its caveat.
    """
    from entrovouch.no_egress_auditor import render_markdown

    rep = audit(pathlib.Path("entrovouch"))
    md = render_markdown(rep)
    assert rep.findings_digest[:32] in md, "the reproducing digest is not on the page"
    assert rep.subject_digest[:32] in md, "the code-binding digest is not on the page"
    assert "does NOT reproduce" in md, "content hash is shown without its caveat"

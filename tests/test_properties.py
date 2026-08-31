"""Property-based tests — the instrument this package was missing, now built.

WHY THESE EXIST
---------------
**Zero egress means zero early warning**: this package ships with no
telemetry by construction, so there is no channel through which a field failure reports itself.
Everything a telemetry channel would have caught has to be caught before release instead.

Example-based tests check the cases their author thought of. **A generator only emits what its
author already believes**, which is exactly why the estate's self-generated "known-answer vectors"
could not detect a non-conformant signer. Property-based testing attacks that by generating inputs
nobody chose — including the empty, the enormous, and the adversarially shaped.

⚠️ **SKIPS CLEANLY IF `hypothesis` IS ABSENT, DELIBERATELY.** ENTROVOUCH's product claim is *clone
it and run it*, and a hard test dependency would put a `pip install` between a sceptical reader and
reproducing our results. A reader without hypothesis still gets the full example-based suite; a
developer with it gets these too.

⚠️ **AND THE LIMIT, SO THIS IS NOT OVERSOLD: properties are still OUR assumptions.** These check
that the code is internally coherent under adversarial input. They cannot tell us the algorithm is
right — only an external reference does that (see `test_sarif_schema.py`, where the answer
was 0 of 79).
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import sys

import pytest

# 🔴 GUARD ON WHAT IS ACTUALLY USED, NOT ON THE MODULE NAME — 2026-08-30.
#
# This was `importorskip("hypothesis")` followed directly by the `from hypothesis
# import ...` below. `importorskip` succeeds as soon as the NAME imports, and the
# line after it needs the module's CONTENTS. A leftover empty directory — from a
# partial uninstall, an interrupted install, a stale wheel — imports as an implicit
# namespace package with `__file__ = None`, so the guard passes and the very next
# line raises `ImportError: cannot import name 'given'`.
#
# ⭐ And the consequence was not "skip this file". A module-level ImportError
# ABORTS COLLECTION FOR THE WHOLE RUN: `pytest -q` exited 2 with **zero tests
# executed**, in the one repository whose entire argument is *re-run it yourself*.
# Measured by execution, not reasoned about.
#
# The estate already had this lesson written down — **a guard in front of a
# property hides whether the property holds** — because the guard checks something
# cheaper than what the code needs. Here the honest guard is: try the real import,
# and skip the file if it does not work.
pytest.importorskip(
    "hypothesis",
    reason="hypothesis not installed; example-based suite still covers this package fully",
)
try:
    from hypothesis import given, settings, HealthCheck, strategies as st  # noqa: E402
except ImportError as exc:  # present but unusable — skip the FILE, never the run
    pytest.skip(
        f"hypothesis imports but is unusable ({exc}); reinstall it or remove the "
        f"leftover directory. The example-based suite still covers this package.",
        allow_module_level=True,
    )

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from entrovouch.no_egress_auditor import (  # noqa: E402
    audit, canonical_body, reproducible_body, verify_report, _subject_name,
)
from entrovouch.signer import MerkleSigner, verify_signature  # noqa: E402

SLOW = settings(max_examples=40, deadline=None,
                suppress_health_check=[HealthCheck.function_scoped_fixture])


# ---------------------------------------------------------------------------
# The verifier must never CRASH. A verifier that raises on hostile input is a
# denial-of-service surface, and "it threw an exception" is not "it rejected".
# ---------------------------------------------------------------------------
@given(st.dictionaries(st.text(max_size=20), st.text(max_size=40), max_size=8))
@SLOW
def test_verify_report_never_raises_on_arbitrary_dicts(d):
    """Garbage in must produce a verdict, never a traceback."""
    ok, status = verify_report(d)
    assert ok is False, "no arbitrary dict may verify as attested"
    assert status in {"TAMPERED", "UNSIGNED", "UNVERIFIED", "ATTESTED"}


@given(st.binary(max_size=64), st.binary(max_size=64), st.text(max_size=80))
@SLOW
def test_verify_signature_never_raises(msg, blob, root):
    """The signature verifier is the most hostile-facing function here."""
    fake = {"algorithm": "whatever", "sig": blob.hex(), "leaf_index": 0, "height": 2}
    assert verify_signature(msg, fake, expected_root=root) is False


# ---------------------------------------------------------------------------
# Reproducibility is the PRODUCT CLAIM, so it gets a property, not an example.
# ---------------------------------------------------------------------------
@given(st.text(min_size=1, max_size=60).filter(lambda s: s.strip()))
@SLOW
def test_findings_digest_ignores_issuance_but_label_still_binds(label):
    """`findings_digest` must exclude issuance fields and include the label.

    Two audits of the same tree under the SAME label must agree; under DIFFERENT
    labels they must not, because the label is part of the claim being made.
    """
    a = dataclasses.asdict(audit(pathlib.Path("entrovouch"), label=label))
    b = dataclasses.asdict(audit(pathlib.Path("entrovouch"), label=label))
    assert a["findings_digest"] == b["findings_digest"], "same label must reproduce"
    assert a["content_hash"] != b["content_hash"], "issuance must stay distinguishable"
    body = json.loads(reproducible_body(a))
    assert body["target"] == label


@given(st.integers(min_value=1, max_value=4))
@SLOW
def test_signing_never_reuses_a_leaf(n):
    """One-time keys: reusing a leaf leaks half the key pair. Never allow it."""
    signer = MerkleSigner(seed=b"\x11" * 32, height=3, path=None)
    seen = set()
    for i in range(n):
        sig = signer.sign(b"m%d" % i)
        idx = sig.get("leaf_index")
        assert idx not in seen, f"leaf {idx} reused — this leaks key material"
        seen.add(idx)
    assert seen == set(range(n)), "leaves must be spent in order from 0"


# ---------------------------------------------------------------------------
# Canonicalisation must be a FUNCTION of content, or signatures mean nothing.
# ---------------------------------------------------------------------------
@given(st.dictionaries(
    st.sampled_from(["target", "verdict", "files_scanned", "scope_statement"]),
    st.one_of(st.text(max_size=30), st.integers(min_value=0, max_value=999)),
    min_size=1))
@SLOW
def test_canonical_body_is_order_independent(d):
    """Key insertion order must not change the signed bytes.

    If it did, the same report could produce two different signatures depending
    on how a dict happened to be built — and a verifier would reject an honest
    report at random.
    """
    forward = canonical_body(dict(d))
    backward = canonical_body({k: d[k] for k in reversed(list(d))})
    assert forward == backward


# ---------------------------------------------------------------------------
# The subject name: `.` produced an EMPTY in-toto subject until 2026-08-21.
# ---------------------------------------------------------------------------
@given(st.sampled_from([".", "./", ".\\", "entrovouch", "./entrovouch"]))
@SLOW
def test_subject_name_is_never_empty(rel):
    """An in-toto Statement with a blank subject name defeats its own purpose."""
    name = _subject_name(pathlib.Path(rel))
    assert name, f"{rel!r} produced an empty subject name"
    assert "/" not in name and "\\" not in name, "only the final component may appear"

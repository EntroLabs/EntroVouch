#!/usr/bin/env python3
"""
ENTROVOUCH — in-toto Statement envelope.

WHY THIS EXISTS, AND WHAT IT DELIBERATELY DOES NOT DO
-----------------------------------------------------
The in-toto Attestation Framework separates two things this package had
conflated:

  * the STATEMENT — a subject (artifacts, identified by digest) plus a
    predicate (a typed claim about them);
  * the ENVELOPE — how that statement is signed, which in the reference
    ecosystem is DSSE.

Those are separable, and separating them is what makes this module possible.
**This module adopts the STATEMENT and not the ENVELOPE.**

That is a deliberate decision with a stated cost.

  ADOPTING the statement buys interoperability of the payload: `subject` with a
  digest map is the shape supply-chain tooling already knows how to verify, and
  a consumer does not have to be taught a bespoke schema to learn WHICH
  artifact a claim is about.

  DECLINING DSSE preserves the property this package values more: signatures
  are Lamport-Merkle over SHA3-256 — post-quantum by construction, resting on
  no lattice or number-theoretic assumption, and pure standard library, so the
  zero-dependency claim survives. DSSE itself is only an envelope format, but
  adopting the ecosystem's signing path in practice means adopting its
  algorithms and its libraries, and that trade runs the wrong way here.

⚠️ SAY THE COST PLAINLY: a verifier built for DSSE CANNOT check our signature.
It can read our statement, identify our subject, and parse our predicate — and
then it must obtain the public root out of band and use `verify_signature` from
this package. **We are interoperable at the payload and sovereign at the
signature. That is a genuine trade, not a free lunch, and anyone told otherwise
is being sold something.**

The predicate type is versioned. A consumer pinning
`.../no-egress-audit/v1` will not be silently handed a v2 with different
semantics.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

__all__ = [
    "to_statement", "statement_subject", "STATEMENT_TYPE",
    "PREDICATE_TYPE_AUDIT", "PREDICATE_TYPE_CBOM",
]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# ⚠️ These two are in-toto `predicateType` URIs — IDENTIFIERS, not links.
# The spec requires a URI that names the predicate schema; it does not require
# that the URI resolve, and as of 2026-08-23 these return 404.
#
# ⭐ Said out loud because this package's whole claim is "go check it yourself",
# and a reader who clicks a vendor URL and gets a 404 is entitled to wonder what
# else was asserted without being checked. It is spec-conformant and it is still
# worth knowing before you click.
PREDICATE_TYPE_AUDIT = "https://entroverse.com/attestation/no-egress-audit/v1"
PREDICATE_TYPE_CBOM = "https://entroverse.com/attestation/cbom/v1"

# Report keys that describe THE ENVELOPE rather than the claim. They move out of
# the predicate and into `signature`, so the predicate is the audit result and
# nothing else.
_ENVELOPE_KEYS = {"signature", "signature_algorithm", "public_root",
                  "content_hash", "integrity_tag", "subject"}


def statement_subject(report_dict: dict) -> list[dict]:
    """The in-toto `subject` array for a report.

    Reports produced from 2026-08-20 carry `subject` directly. Older reports do
    not — and rather than fabricate one from `target` (which is free text and
    binds nothing, the exact defect this field was added to fix), this RAISES.
    A statement whose subject was invented is worse than no statement.
    """
    subject = report_dict.get("subject")
    if subject:
        return subject

    digest = report_dict.get("subject_digest")
    if digest:
        return [{"name": report_dict.get("target", "unknown"),
                 "digest": {"sha3-256": digest}}]

    raise ValueError(
        "report carries no `subject` or `subject_digest`, so there is nothing "
        "to bind a statement to. It predates the 2026-08-20 subject-binding "
        "fix; re-run the audit rather than attesting an unbound claim."
    )


def to_statement(report_dict: dict,
                 predicate_type: str = PREDICATE_TYPE_AUDIT) -> dict:
    """Wrap an audit report or CBOM as an in-toto Statement.

    The signature travels alongside the statement rather than inside a DSSE
    envelope, in a `signature` field, with the algorithm named. A reader who
    does not recognise the algorithm can still parse the subject and predicate
    — and, importantly, can tell that they are NOT verifying it, rather than
    assuming they are.
    """
    predicate = {k: v for k, v in report_dict.items() if k not in _ENVELOPE_KEYS}

    statement: dict = {
        "_type": STATEMENT_TYPE,
        "subject": statement_subject(report_dict),
        "predicateType": predicate_type,
        "predicate": predicate,
    }

    sig = report_dict.get("signature")
    if sig:
        statement["signature"] = {
            "algorithm": report_dict.get("signature_algorithm", ""),
            "public_root": report_dict.get("public_root", ""),
            "value": sig,
            # Said in the artifact, not only in the docs: a DSSE verifier will
            # not check this, and must not report it as verified.
            "note": (
                "Lamport-Merkle over SHA3-256, not DSSE. A DSSE verifier "
                "cannot check this signature and must treat it as unverified "
                "rather than absent. Verify with entrovouch.signer."
            ),
        }
    else:
        statement["signature"] = None

    return statement


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Wrap an ENTROVOUCH report as an in-toto Statement.")
    ap.add_argument("report", type=Path, help="report .json")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--cbom", action="store_true",
                    help="use the CBOM predicate type")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    stmt = to_statement(
        json.loads(args.report.read_text(encoding="utf-8")),
        predicate_type=PREDICATE_TYPE_CBOM if args.cbom else PREDICATE_TYPE_AUDIT,
    )
    text = json.dumps(stmt, indent=2)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

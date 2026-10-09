#!/usr/bin/env python3
"""
ENTROVOUCH: in-toto Statement envelope.

WHY THIS EXISTS, AND WHAT IT DELIBERATELY DOES NOT DO
-----------------------------------------------------
The in-toto Attestation Framework separates two things this package had
conflated:

  * the STATEMENT: a subject (artifacts, identified by digest) plus a
    predicate (a typed claim about them);
  * the ENVELOPE: how that statement is signed, which in the reference
    ecosystem is DSSE.

Those are separable, and separating them is what makes this module possible.
**This module adopts the STATEMENT and not the ENVELOPE.**

That is a deliberate decision with a stated cost.

  ADOPTING the statement buys interoperability of the payload: `subject` with a
  digest map is the shape supply-chain tooling already knows how to verify, and
  a consumer does not have to be taught a bespoke schema to learn WHICH
  artifact a claim is about.

  DECLINING DSSE preserves the property this package values more: signatures
  are Lamport-Merkle over SHA3-256: post-quantum by construction, resting on
  no lattice or number-theoretic assumption, and pure standard library, so the
  zero-dependency claim survives. DSSE itself is only an envelope format, but
  adopting the ecosystem's signing path in practice means adopting its
  algorithms and its libraries, and that trade runs the wrong way here.

SAY THE COST PLAINLY: a verifier built for DSSE CANNOT check our signature.
It can read our statement, identify our subject, and parse our predicate: and
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

from .no_egress_auditor import CBOM_TOOL, NO_EGRESS_TOOL, ReportError, load_report
from ._cli import missing_folder, run, write_text

__all__ = [
    "to_statement", "statement_subject", "STATEMENT_TYPE",
    "PREDICATE_TYPE_AUDIT", "PREDICATE_TYPE_CBOM",
]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# These two are in-toto `predicateType` URIs: identifiers, not links. The spec
# requires a URI that names the predicate schema; it does not require that the
# URI resolve, and these may not. Spec-conformant, and worth knowing before you click.
PREDICATE_TYPE_AUDIT = "https://entroverse.com/attestation/no-egress-audit/v1"
PREDICATE_TYPE_CBOM = "https://entroverse.com/attestation/cbom/v1"

# Report keys that describe THE ENVELOPE rather than the claim. They move out of
# the predicate and into `signature`, so the predicate is the audit result and
# nothing else.
_ENVELOPE_KEYS = {"signature", "signature_algorithm", "public_root",
                  "content_hash", "integrity_tag", "subject"}


def statement_subject(report_dict: dict) -> list[dict]:
    """The in-toto `subject` array for a report.

    Current reports carry `subject` directly. A report without one is not given a
    subject fabricated from `target` (free text that binds nothing); this raises.
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
        "to bind a statement to. Re-run the audit with the current tool rather "
        "than attesting an unbound claim."
    )


# in-toto's DigestSet names the algorithm `sha3_256`; the reports name it `sha3-256`
_INTOTO_NAMES = {"sha3-256": "sha3_256"}
_REPORT_NAMES = {"sha3_256": "sha3-256"}


def _digest_names(subject, names: dict) -> list:
    """The subject with each digest's algorithm renamed by `names`; anything that is not a subject entry is kept as
    it is, for the check that follows to refuse."""
    if not isinstance(subject, list):
        return subject
    out = []
    for entry in subject:
        if isinstance(entry, dict) and isinstance(entry.get("digest"), dict):
            entry = dict(entry, digest={names.get(k, k): v for k, v in entry["digest"].items()})
        out.append(entry)
    return out


SIGNATURE_NOTE = ("Lamport-Merkle over SHA3-256, not DSSE. A DSSE verifier cannot check this signature and must "
                  "treat it as unverified rather than absent. Verify with python -m entrovouch.verify <statement> "
                  "--root <issuer's root>.")
_PREDICATE_TYPES = {NO_EGRESS_TOOL: PREDICATE_TYPE_AUDIT, CBOM_TOOL: PREDICATE_TYPE_CBOM}


def to_statement(report_dict: dict,
                 predicate_type: str = PREDICATE_TYPE_AUDIT) -> dict:
    """Wrap an audit report or CBOM as an in-toto Statement.

    The signature travels alongside the statement rather than inside a DSSE
    envelope, in a `signature` field, with the algorithm named. A reader who
    does not recognise the algorithm can still parse the subject and predicate
   : and, importantly, can tell that they are NOT verifying it, rather than
    assuming they are.
    """
    predicate = {k: v for k, v in report_dict.items() if k not in _ENVELOPE_KEYS}

    statement: dict = {
        "_type": STATEMENT_TYPE,
        "subject": _digest_names(statement_subject(report_dict), _INTOTO_NAMES),
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
            "note": SIGNATURE_NOTE,
        }
    else:
        statement["signature"] = None

    return statement


def verify_statement(statement: dict, expected_root: str | None = None) -> tuple[bool, str]:
    """Check a Statement this module wrote: the report it carries is rebuilt (the predicate, with the subject and the
    signer the `signature` field names put back) and checked as that report is. Returns `(ok, status)` with the
    statuses of `verify_report`; `ok` only for ATTESTED."""
    from .no_egress_auditor import (_identity_matches, canonical_body, findings_digest_matches, subject_matches,
                                    verify_any)
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
        return False, "TAMPERED"
    predicate, subject, sig = statement.get("predicate"), statement.get("subject"), statement.get("signature")
    if not isinstance(predicate, dict) or not isinstance(subject, list) \
            or not isinstance(predicate.get("tool"), str) or predicate["tool"] not in _PREDICATE_TYPES:
        return False, "TAMPERED"
    # the subject's digests by the reports' names (a Statement made before the in-toto name was used carries the
    # reports' name already); an entry naming SHA3-256 both ways is not one this module wrote
    if any(isinstance(e, dict) and isinstance(e.get("digest"), dict) and {"sha3_256", "sha3-256"} <= set(e["digest"])
           for e in subject):
        return False, "TAMPERED"
    subject = _digest_names(subject, _REPORT_NAMES)
    # Only what `to_statement` writes: the Statement's own five fields, a predicate holding no envelope field (the
    # signer, the subject, a hash or a tag written there would travel unsigned beside the signed claim), the
    # predicate type of the predicate's own kind, and a signature block of four fields with this tool's note.
    if set(statement) - {"_type", "subject", "predicateType", "predicate", "signature"} \
            or set(predicate) & _ENVELOPE_KEYS \
            or statement.get("predicateType") != _PREDICATE_TYPES[predicate["tool"]]:
        return False, "TAMPERED"
    if sig is not None and (not isinstance(sig, dict) or set(sig) != {"algorithm", "public_root", "value", "note"}
                            or sig.get("note") != SIGNATURE_NOTE):
        return False, "TAMPERED"
    report = dict(predicate)
    report["subject"] = subject
    if not findings_digest_matches(report) or not subject_matches(report):
        return False, "TAMPERED"
    if sig is None:
        return False, "UNSIGNED"
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), dict):
        return False, "TAMPERED"
    report["signature_algorithm"] = sig.get("algorithm", "")
    report["public_root"] = sig.get("public_root", "")
    if not _identity_matches(report, sig["value"]):
        return False, "TAMPERED"
    if isinstance(expected_root, str):
        expected_root = expected_root.strip().lower()
    if not verify_any(canonical_body(report), sig["value"], expected_root=expected_root):
        return False, "TAMPERED"
    return (True, "ATTESTED") if expected_root else (False, "UNVERIFIED")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Wrap an ENTROVOUCH report as an in-toto Statement.")
    ap.add_argument("report", type=Path, help="report .json")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--cbom", action="store_true",
                    help="use the CBOM predicate type")
    args = ap.parse_args(argv)
    if getattr(args, 'out', None) is not None:
        clash = missing_folder(args.out, inputs=(args.report,))
        if clash and 'reads' in clash:
            print(clash, file=sys.stderr)       # a report converted onto itself would be destroyed
            return 2

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    try:
        report = load_report(args.report, kind=CBOM_TOOL if args.cbom else NO_EGRESS_TOOL)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    stmt = to_statement(
        report,
        predicate_type=PREDICATE_TYPE_CBOM if args.cbom else PREDICATE_TYPE_AUDIT,
    )
    text = json.dumps(stmt, indent=2)
    if args.out:
        write_text(args.out, text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(run(main))

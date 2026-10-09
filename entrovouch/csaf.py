#!/usr/bin/env python3
"""
CSAF 2.0 output, VEX profile: the same statements as `entrovouch.vex`, in the
format advisory tooling reads.

WHAT THIS SAYS, AND WHAT IT DOES NOT
------------------------------------
Every statement carries the product status `under_investigation`. That is CSAF's
word for what `entrovouch.vex` calls `in_triage`: identified, and a person has to
decide. This tool does not establish reachability, so it never writes
`known_affected` and never writes `known_not_affected`.

Identifiers are CWE weakness classes. This tool has no vulnerability database, so
no statement carries a `cve`. The VEX profile requires `cve` or `ids`; each
statement carries an `ids` entry naming the weakness class and the primitive.

THE PUBLISHER IS YOURS TO NAME
------------------------------
A CSAF document names its publisher and a namespace URI the publisher controls.
The tool that wrote the file is not the publisher, so both are required arguments
and nothing is filled in for you. The tool is named under `tracking.generator`.

WHAT IS CHECKED
---------------
The output is validated against the CSAF 2.0 JSON schema published by OASIS, by a
test. The standard also defines mandatory tests that a schema cannot express
(section 6.1). No CSAF conformance checker is run here; the ones this output can
break are asserted one by one in `tests/test_csaf.py` and listed in
CONFORMANCE.md.

Usage:
    python -m entrovouch.cbom /path/to/project --json cbom.json
    python -m entrovouch.csaf cbom.json --publisher-name "Example Ltd" \\
        --publisher-namespace https://example.com --out vex.csaf.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from ._version import __version__
from .no_egress_auditor import ReportError, load_report, CBOM_TOOL, KEY_PROVENANCE_TOOL
from ._cli import missing_folder, run, write_text
from .vex import coverage_problem, coverage_properties, to_vex

# The CWE names exactly as the CWE list writes them. CSAF requires the name to
# match the identifier, so these are not this package's own wording.
CWE_NAMES: dict[int, str] = {
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    338: "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
    798: "Use of Hard-coded Credentials",
}
PUBLISHER_CATEGORIES = ("coordinator", "discoverer", "other", "translator", "user", "vendor")
PRODUCT_ID = "ENTROVOUCH-SUBJECT-1"
IDS_SYSTEM_NAME = "ENTROVOUCH weakness statement"
_NOTE = (
    "Each statement names a weakness class (CWE) found in the audited source tree. "
    "None names a CVE: the tool that wrote this file has no vulnerability database. "
    "Every status is under_investigation because exploitability depends on whether "
    "the code is reached, and static analysis does not establish that."
)
# An RFC 3986 http(s) URI with an ASCII host name (an internationalised name in its xn-- form), an optional port,
# and a path, query and fragment of URI characters only: the schema's `format: uri`.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_URI_CHARS = r"[A-Za-z0-9\-._~!$&'()*+,;=:@%/]"
_URI_RE = re.compile(rf"https?://{_LABEL}(?:\.{_LABEL})*(?::\d{{1,5}})?(?:/{_URI_CHARS}*)?(?:\?{_URI_CHARS}*)?"
                     rf"(?:#{_URI_CHARS}*)?", re.IGNORECASE)


class NothingToState(ValueError):
    """The CBOM holds no weakness this tool makes a statement about."""


def csaf_filename(tracking_id: str) -> str:
    """The file name CSAF 2.0 section 5.1 derives from a tracking id."""
    return re.sub(r"[^+\-a-z0-9]+", "_", tracking_id.lower()) + ".json"


def to_csaf(cbom_dict: dict, *, publisher_name: str, publisher_namespace: str,
            publisher_category: str = "other", key_findings: list | None = None,
            now: datetime | None = None) -> dict:
    """A CSAF 2.0 document in the VEX profile (`csaf_vex`).

    Raises `NothingToState` when there is no statement to make: the VEX profile
    requires at least one vulnerability entry, and an empty document would read
    as "looked and found nothing to say", which the schema does not allow and
    this tool does not claim.
    """
    if not publisher_name or not publisher_name.strip():
        raise ValueError("a CSAF document names its publisher: publisher_name is empty")
    if not _URI_RE.fullmatch(publisher_namespace or ""):
        raise ValueError("publisher_namespace must be an http or https URI the publisher controls")
    if publisher_category not in PUBLISHER_CATEGORIES:
        raise ValueError(f"publisher_category must be one of {', '.join(PUBLISHER_CATEGORIES)}")

    statements = to_vex(cbom_dict, key_findings=key_findings)["vulnerabilities"]
    if not statements:
        raise NothingToState("no weakness statement to make from this CBOM")

    label = str(cbom_dict.get("target") or "audited source tree")
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    when = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    # The id is bound to everything the document says and to the tree it was made from, not to when it was written:
    # different content is a different document, so each id has one content and its version 1 never changes
    basis = json.dumps([label, cbom_dict.get("subject_digest", ""), statements], sort_keys=True, default=str)
    tracking_id = "ENTROVOUCH-VEX-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    vulnerabilities = []
    for s in statements:
        cwe = int(s["cwes"][0])
        vulnerabilities.append({
            "title": s["description"],
            "cwe": {"id": f"CWE-{cwe}", "name": CWE_NAMES[cwe]},
            "ids": [{"system_name": IDS_SYSTEM_NAME, "text": s["bom-ref"]}],
            "notes": [
                # the statement's note names CycloneDX's state; CSAF's word for it is under_investigation
                {"category": "description", "text": s["detail"].replace("in_triage", "under_investigation")},
                {"category": "details", "title": "Where", "text": s["properties"][0]["value"]},
            ],
            "product_status": {"under_investigation": [PRODUCT_ID]},
        })

    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "lang": "en",
            "title": f"Weakness statements for {label}",
            "publisher": {
                "category": publisher_category,
                "name": publisher_name.strip(),
                "namespace": publisher_namespace,
            },
            "notes": [{"category": "general", "title": "What these statements are", "text": _NOTE},
                      {"category": "general", "title": "What was read",
                       "text": "; ".join(f"{p['name'].split(':', 1)[1]}: {p['value']}"
                                         for p in coverage_properties(cbom_dict))}],
            "tracking": {
                "id": tracking_id,
                "status": "interim",
                "version": "1",
                "initial_release_date": when,
                "current_release_date": when,
                "revision_history": [{"number": "1", "date": when, "summary": "First issue."}],
                "generator": {"date": when, "engine": {"name": "entrovouch", "version": __version__}},
            },
        },
        "product_tree": {
            "full_product_names": [{"product_id": PRODUCT_ID, "name": label}],
        },
        "vulnerabilities": vulnerabilities,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m entrovouch.csaf",
        description="CSAF 2.0 VEX from a CBOM. CWE weakness classes, every status under_investigation.")
    ap.add_argument("--version", action="version", version=f"entrovouch {__version__}")
    ap.add_argument("cbom", type=Path, help="a CBOM produced by `python -m entrovouch.cbom --json`")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--publisher-name", required=True, help="who issues this document")
    ap.add_argument("--publisher-namespace", required=True, help="an http or https URI the publisher controls")
    ap.add_argument("--publisher-category", default="other", choices=PUBLISHER_CATEGORIES)
    ap.add_argument("--key-provenance", type=Path, default=None,
                    help="optional key_provenance JSON, to add a CWE-798 statement")
    args = ap.parse_args(argv)
    if getattr(args, 'out', None) is not None:
        clash = missing_folder(args.out, inputs=(args.cbom, args.key_provenance))
        if clash and 'reads' in clash:
            print(clash, file=sys.stderr)       # a report converted onto itself would be destroyed
            return 2

    if not args.cbom.is_file():
        print(f"error: no such CBOM: {args.cbom}", file=sys.stderr)
        return 2
    try:
        cbom = load_report(args.cbom, kind=CBOM_TOOL)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    kf = None
    kp = None
    if args.key_provenance is not None:          # named and missing is an error, never a silent omission
        try:
            kp = load_report(args.key_provenance, kind=KEY_PROVENANCE_TOOL)
            if kp.get("target") != cbom.get("target"):
                raise ReportError(f"the key-provenance report is for {kp.get('target')!r} and the CBOM for "
                                  f"{cbom.get('target')!r}: statements about one tree cannot be made from another")
            if not cbom.get("tree_listing_digest") or kp.get("tree_listing_digest") != cbom.get("tree_listing_digest"):
                raise ReportError("the key-provenance report and the CBOM were not made from the same files (their "
                                  "tree_listing_digest values differ, or one report has none): statements about one "
                                  "tree cannot be made from another")
            kf = kp.get("findings") or []
        except ReportError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    problem = coverage_problem(cbom, kp)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    try:
        try:
            issued = datetime.fromisoformat(str(cbom.get("scanned_at_utc", "")))
        except ValueError:
            issued = None
        doc = to_csaf(cbom, publisher_name=args.publisher_name, publisher_namespace=args.publisher_namespace,
                      publisher_category=args.publisher_category, key_findings=kf, now=issued)
    except NothingToState:
        print("nothing written: this CBOM holds no weakness this tool makes a statement about, and a CSAF "
              "VEX document must carry at least one.")
        for p in coverage_properties(cbom)[1:]:
            print(f"note: {p['value']}", file=sys.stderr)
        if args.out.exists():
            # a document at the output path is an earlier run's: left as it is, a step that publishes the output
            # would publish that one
            print(f"error: {args.out} holds a document this run did not write (nothing was written); it was left as "
                  "it is and must not be taken for this run's", file=sys.stderr)
            return 2
        return 0
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    write_text(args.out, json.dumps(doc, indent=2, sort_keys=False) + "\n")
    n = len(doc["vulnerabilities"])
    print(f"wrote {args.out} :  {n} CSAF VEX statement(s), all under_investigation")
    wanted = csaf_filename(doc["document"]["tracking"]["id"])
    if args.out.name != wanted:
        print(f"To publish it, CSAF 2.0 section 5.1 names the file after its tracking id: {wanted}")
    print("Identifiers are CWE weakness classes. This tool has no CVE data and")
    print("does not infer exploitability, which is a reachability question.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run(main))

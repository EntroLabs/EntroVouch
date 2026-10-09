#!/usr/bin/env python3
"""
VEX output: CycloneDX-native, and honest about the one question it cannot answer.

An SBOM says what is present. **VEX says whether what is present is exploitable**,
and that second question is the one a buyer actually asks: a dependency list with
forty findings is not forty problems.

THE TRAP IN THIS FORMAT, AND WHY THE OUTPUT LOOKS CAUTIOUS
--------------------------------------------------------------
CycloneDX 1.6 offers six impact states: `resolved`, `resolved_with_pedigree`,
`exploitable`, `in_triage`, `false_positive`, `not_affected`.

**Exploitability is a property of REACHABILITY, and static analysis cannot
establish reachability.** Knowing a module references MD5 does not tell you whether
that call site runs, on what data, or whether the result is security-bearing.

So every statement here is emitted as **`in_triage`**. That is not timidity and it
is not a placeholder: it is the format's own vocabulary for *"identified, and a
human has to decide."* Emitting `exploitable` would claim a reachability analysis
that never ran. Emitting `not_affected` would be worse: it would clear a finding on
the strength of not having looked.

This is `REVIEW means review` written in a standard the recipient's tooling
already parses, which is the entire reason to emit VEX rather than prose.

THESE ARE WEAKNESS CLASSES (CWE), NOT VULNERABILITIES (CVE)
---------------------------------------------------------------
This tool does not know about CVEs. It has no vulnerability database, does no
version resolution, and makes no network call to acquire either. What it produces
is grounded in **CWE weakness classes** that follow from the primitive itself:
MD5 is a broken hash wherever it appears, independent of any advisory.

**Every `id` below is therefore prefixed `CWE-`, never `CVE-`.** A consumer that
expects CVE identifiers will find none, and that is a deliberate absence rather
than a gap: inventing or guessing CVE identifiers to fill the field would be the
same defect as naming a standard nothing tests.

Usage:
    python -m entrovouch.cbom /path/to/project --json cbom.json
    python -m entrovouch.vex cbom.json --out vex.cdx.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ._version import __version__
from .no_egress_auditor import ReportError, load_report, CBOM_TOOL, KEY_PROVENANCE_TOOL
from ._cli import missing_folder, run, write_text

# Primitive -> (CWE id, title, why it is a weakness independent of any advisory).
#
# Deliberately SMALL. Each entry is a weakness that follows from the primitive
# itself; nothing here depends on a version, a platform or an advisory feed,
# because this tool has access to none of those.
CWE_MAP: dict[str, tuple[int, str, str]] = {
    "BROKEN": (327, "Use of a Broken or Risky Cryptographic Algorithm",
               "The primitive is classically broken. Collision or preimage attacks are "
               "published and practical; its presence is a weakness wherever it is "
               "security-bearing."),
    "WEAK-RNG": (338, "Use of Cryptographically Weak Pseudo-Random Number Generator",
                 "A non-cryptographic PRNG is predictable from observed output. It is a "
                 "weakness only if it keys, seeds or identifies something: which source "
                 "alone cannot establish."),
    "VULNERABLE": (327, "Use of a Broken or Risky Cryptographic Algorithm",
                   "Shor-breakable public-key cryptography. Not broken today; the weakness "
                   "is the migration obligation and the harvest-now-decrypt-later exposure, "
                   "which is a timeline question rather than a present compromise."),
}
# key_provenance findings map to a different class entirely.
CWE_HARDCODED = (798, "Use of Hard-coded Credentials",
                 "Key material that originates in the source tree is reproducible by anyone "
                 "holding the source. Whether that is a defect depends on who receives the "
                 "artifact, which source cannot show.")

_STATE = "in_triage"
_JUSTIFICATION_NOTE = (
    "Emitted as in_triage because exploitability is a property of reachability, and "
    "static analysis does not establish reachability. This is an identification, not "
    "a severity judgement."
)


def coverage_problem(cbom: dict, kp: dict | None = None) -> str | None:
    """An error line when a report read nothing: a statement document made from it would say nothing about a tree
    that was not read, and an empty one reads as a clean one."""
    if cbom.get("verdict") == "NOT-ANALYSED":
        return "the CBOM read nothing (NOT-ANALYSED): no statement can be made about a tree that was not read"
    if kp is not None and kp.get("verdict") == "NOT-ANALYSED":
        return "the key-provenance report read nothing (NOT-ANALYSED): no statement can be made from it"
    return None


def coverage_properties(cbom: dict) -> list[dict]:
    """The CBOM's verdict and the files it could not parse, carried into the statement document so a reader of the
    document alone learns what it does not cover."""
    props = [{"name": "entrovouch:verdict", "value": str(cbom.get("verdict", ""))}]
    unparsed = sorted({str(f.get("file")) for f in cbom.get("files_not_parsed") or [] if isinstance(f, dict)})
    if unparsed:
        props.append({"name": "entrovouch:filesNotParsed",
                      "value": f"{len(unparsed)} file(s) not parsed, their cryptography NOT inventoried: "
                               + ", ".join(unparsed[:20]) + (" ..." if len(unparsed) > 20 else "")})
    return props


def to_vex(cbom_dict: dict, *, key_findings: list | None = None) -> dict:
    """A CycloneDX 1.6 document carrying `vulnerabilities` VEX statements.

    One statement per distinct (weakness class, primitive) pair rather than one per
    finding: forty MD5 call sites are one weakness in forty places, and a document
    that inflates the second into the first misstates the risk.
    """
    comps = cbom_dict.get("components", []) or []
    subject = str(cbom_dict.get("target") or "audited source tree")
    subject_ref = "subject"
    by_class: dict[tuple[int, str], list[dict]] = {}
    for c in comps:
        status = c.get("quantum")
        entry = CWE_MAP.get(status)
        if not entry:
            continue
        cwe, title, detail = entry
        by_class.setdefault((cwe, c.get("primitive", "?")), []).append(c)

    vulns = []
    for (cwe, primitive), hits in sorted(by_class.items()):
        _, title, detail = next(v for k, v in CWE_MAP.items()
                                if v[0] == cwe and k in {h.get("quantum") for h in hits})
        files = sorted({str(h.get("file")) for h in hits})
        vulns.append({
            "bom-ref": f"cwe-{cwe}-{primitive.lower().replace(' ', '-').replace('/', '-')}",
            "id": f"CWE-{cwe}",
            "cwes": [cwe],
            "description": f"{title}: {primitive}",
            "detail": f"{detail}\n\n{_JUSTIFICATION_NOTE}",
            "analysis": {"state": _STATE},
            "affects": [{"ref": subject_ref}],
            "properties": [{"name": "entrovouch:sites",
                            "value": f"{primitive} ({len(hits)} site(s) in {len(files)} file(s))"}],
        })

    for f in (key_findings or []):
        cwe, title, detail = CWE_HARDCODED
        vulns.append({
            "bom-ref": f"cwe-{cwe}-key-provenance",
            "id": f"CWE-{cwe}",
            "cwes": [cwe],
            "description": f"{title}: key material originating in the source tree",
            "detail": f"{detail}\n\n{_JUSTIFICATION_NOTE}",
            "analysis": {"state": _STATE},
            "affects": [{"ref": subject_ref}],
            "properties": [{"name": "entrovouch:sites", "value": "key material in source"}],
        })
        break   # one statement for the class, not one per site

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": cbom_dict.get("scanned_at_utc") or datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{
                "type": "application", "name": "entrovouch", "version": __version__,
            }]},
            # what the statements are about; each statement's `affects` names this bom-ref
            "component": {"type": "application", "bom-ref": subject_ref, "name": subject},
            "properties": [
                {"name": "entrovouch:vex:identifier-scheme", "value": "CWE weakness classes only; no CVE data"},
                {"name": "entrovouch:vex:state-rationale", "value": _JUSTIFICATION_NOTE},
                *coverage_properties(cbom_dict),
            ],
        },
        "vulnerabilities": vulns,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m entrovouch.vex",
        description="CycloneDX-native VEX from a CBOM. CWE weakness classes, never CVEs.")
    ap.add_argument("--version", action="version", version=f"entrovouch {__version__}")
    ap.add_argument("cbom", type=Path, help="a CBOM produced by `python -m entrovouch.cbom --json`")
    ap.add_argument("--out", type=Path, required=True)
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
    doc = to_vex(cbom, key_findings=kf)
    write_text(args.out, json.dumps(doc, indent=2, sort_keys=False) + "\n")
    n = len(doc["vulnerabilities"])
    print(f"wrote {args.out} :  {n} VEX statement(s), all state=in_triage")
    for p in coverage_properties(cbom)[1:]:
        print(f"note: {p['value']}", file=sys.stderr)
    print("Identifiers are CWE weakness classes. This tool has no CVE data and")
    print("does not infer exploitability, which is a reachability question.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run(main))

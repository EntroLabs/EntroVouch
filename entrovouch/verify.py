#!/usr/bin/env python3
"""Check a report's signature from the command line.

    python -m entrovouch.verify report.json --root <public root you trust>

Reads a no-egress report, a CBOM, an SBOM or an in-toto Statement made from one, picks the verifier for its kind,
and prints one of four statuses:

    ATTESTED    the body is unchanged and was signed by the key whose root you pinned
    UNVERIFIED  the body is unchanged and signed, but you pinned no root, so who signed it is not checked
    UNSIGNED    the report carries no signature and names no signer
    TAMPERED    the body changed after signing, the signature is not from the root you pinned, or the
                signature was removed from a report that names a signer

The root to pin comes from the issuer, through a channel you trust: never from the report itself.
Exit 0 for ATTESTED, 1 for any other status, 2 when the file cannot be read as a report.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ._cli import run
from ._version import __version__
from .attestation import STATEMENT_TYPE, verify_statement
from .no_egress_auditor import ReportError, load_report, verify_report

_TOOLS = {
    "ENTROVOUCH no-egress auditor": "ENTROVOUCH no-egress auditor",
    "ENTROVOUCH CBOM generator": "ENTROVOUCH CBOM generator",
    "ENTROVOUCH SBOM": "ENTROVOUCH SBOM",
}

_MEANING = {
    "ATTESTED": "unchanged, and signed by the key whose root you pinned",
    "UNVERIFIED": "unchanged and signed, but no root was pinned, so WHO signed it is not checked",
    "UNSIGNED": "no signature: this report says nothing about who issued it",
    "TAMPERED": "changed after signing, signed by a key other than the root you pinned, or its signature was removed",
}


def _shown(value) -> str:
    """Text from outside this program (a file name), with its control characters written as escapes, so a line ending
    or a terminal code in it cannot start a line of its own or hide one."""
    return "".join(c if c.isprintable() or c == " " else repr(c)[1:-1] for c in str(value))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m entrovouch.verify",
                                 description="Verify a signed ENTROVOUCH report. Performs NO network operations.")
    ap.add_argument("--version", action="version", version=f"entrovouch {__version__}")
    ap.add_argument("report", type=Path)
    ap.add_argument("--root", default=None, help="the issuer's public root (64 hex digits), obtained from the issuer")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if not args.report.is_file():
        print(f"error: no such report: {_shown(args.report)}", file=sys.stderr)
        return 2
    try:
        report = load_report(args.report, check=False)
    except ReportError as exc:
        print(f"error: {_shown(exc)}", file=sys.stderr)
        return 2
    if args.root is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", args.root.strip()):
        print(f"error: {args.root!r} is not a public root (64 hex digits)", file=sys.stderr)
        return 2
    if report.get("_type") == STATEMENT_TYPE:
        # an in-toto Statement `entrovouch.attestation` wrote: the report it carries is checked
        ok, status = verify_statement(report, expected_root=args.root)
        predicate = report.get("predicate")
        named = predicate.get("tool") if isinstance(predicate, dict) else None
        # only a tool this command knows is named: the field is the document's, and is not printed as it stands
        print(f"report : {_shown(args.report)}")
        print("kind   : in-toto Statement, " + (named if isinstance(named, str) and named in _TOOLS
                                                 else "of no tool this command knows"))
        print(f"status : {status}: {_MEANING[status]}")
        return 0 if ok else 1
    tool = report.get("tool")
    if not isinstance(tool, str) or tool not in _TOOLS:
        print(f"error: {_shown(args.report)} is not a report this tool signs (tool: {tool!r})", file=sys.stderr)
        return 2
    ok, status = verify_report(report, expected_root=args.root, expected_tool=_TOOLS[tool])
    print(f"report : {_shown(args.report)}")
    print(f"kind   : {tool}")
    print(f"status : {status}: {_MEANING[status]}")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run(main))

#!/usr/bin/env python3
"""
ENTROVOUCH — SARIF 2.1.0 export.

WHY THIS EXISTS
---------------
SARIF (Static Analysis Results Interchange Format) 2.1.0 is an OASIS standard
and the format GitHub code scanning ingests natively. A tool that emits SARIF
appears in the security tab of every repository that runs it, with zero
integration work by the consumer and no account, contract or API on our side.

That matters here for a specific reason: this estate's own analysis concluded
that of four attack surfaces — IP, operator, stack, distribution — the first
three are sealed and DISTRIBUTION is the one still open. SARIF is a
distribution mechanism that costs one output adapter and requires permission
from nobody.

IT DOES NOT WEAKEN THE NO-EGRESS PROPERTY. This module writes a file. It opens
no socket, contacts no service, and imports nothing outside the standard
library. The ecosystem comes to the file; the tool never reaches out. That is
the Covenant-compatible shape of distribution, and it is the only shape this
package will accept.

SEVERITY IS DELIBERATELY NOT INFERRED
-------------------------------------
Every result is emitted at `warning`. The tool detects that an egress
capability is PRESENT; whether that is a defect depends on what the operator
claimed about their own software, which is not knowable from source. Marking a
`socket` import as `error` would be this tool asserting a policy it was never
given. `--level` exists for a consumer who does know their policy.

This is the same discipline as `REVIEW means review` in the CBOM: report the
observation, refuse to invent the verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from ._version import __version__

__all__ = ["to_sarif", "SARIF_VERSION", "RULES"]

SARIF_VERSION = "2.1.0"
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# One rule per finding kind the auditor can emit. Descriptions state what was
# detected and what it does NOT prove — a reader meeting this tool for the
# first time in a code-scanning tab has no other context to go on.
RULES: dict[str, dict[str, str]] = {
    "network-import": {
        "name": "NetworkCapableImport",
        "short": "A network-capable module is imported",
        "full": (
            "The file imports a module able to open a network connection "
            "(HTTP client, socket, mail/FTP, gRPC, websocket) or a "
            "telemetry/APM/cloud SDK. Importing is not proof of transmission, "
            "but it is proof that the capability is present in the shipped "
            "code, which is the claim a 'no telemetry' statement is about."
        ),
    },
    "git-remote": {
        "name": "GitRemoteSubcommand",
        "short": "A git subcommand that contacts a remote",
        "full": (
            "Invocation of a git subcommand that reaches a remote host "
            "(push/pull/fetch/clone/ls-remote). Relevant to any claim that a "
            "tool operates purely locally."
        ),
    },
    "subprocess-shell": {
        "name": "ShellExecution",
        "short": "Shell execution of a non-literal command",
        "full": (
            "Use of shell=True, os.system or os.popen. The command string is "
            "not statically resolvable in general, so egress cannot be ruled "
            "out by reading the source."
        ),
    },
    "subprocess-net-binary": {
        "name": "NetworkBinarySpawn",
        "short": "A network binary is spawned via argv",
        "full": (
            "A network-capable binary (curl, wget, nc and similar) invoked as "
            "an argv list. This path evades shell=True detection and is "
            "checked separately for exactly that reason."
        ),
    },
    "dynamic-exec": {
        "name": "DynamicExecution",
        "short": "Dynamic code execution or import",
        "full": (
            "eval, exec, compile or a dynamic import. Static analysis cannot "
            "see what such a call will run, so this marks a boundary of the "
            "audit rather than a defect in itself."
        ),
    },
    "html-external": {
        "name": "ExternalResourceReference",
        "short": "An external resource is referenced",
        "full": (
            "A markup or script file references an off-host URL or src/href. "
            "Loading an external resource is an outbound request made by the "
            "user's browser on the page's behalf."
        ),
    },
    "declared-network-dependency": {
        "name": "DeclaredNetworkDependency",
        "short": "A manifest names a known network package",
        "full": (
            "pyproject.toml, requirements.txt, setup.cfg or package.json "
            "declares a dependency that this tool knows as network-capable. "
            "That is evidence the tree depends on the package, not a claim "
            "that a call site in source opens a socket."
        ),
    },
    "network-dependency": {
        "name": "NetworkPackageSubmodule",
        "short": "A non-network submodule of a network package is imported",
        "full": (
            "The file imports a submodule of a network-capable package that "
            "does not itself open a socket (for example urllib.parse). "
            "Reported as dependency evidence, not as a network call."
        ),
    },
    "unparseable-source": {
        "name": "UnparseableSource",
        "short": "A file could not be parsed and was not analysed",
        "full": (
            "The scanner could not parse this file. An unanalysed region is a "
            "gap in coverage, not an absence of findings."
        ),
    },
}

_LEVELS = ("none", "note", "warning", "error")


def _fingerprint(kind: str, file: str, detail: str) -> str:
    """Stable identity for a result across runs.

    Deliberately EXCLUDES the line number. Inserting a comment at the top of a
    file shifts every line below it; a fingerprint that included the line would
    close every existing alert and open an identical set of new ones, which is
    how a code-scanning integration becomes noise and gets muted.
    """
    h = hashlib.sha256()
    for part in (kind, file.replace("\\", "/"), detail):
        h.update(part.encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()[:32]


def to_sarif(report_dict: dict, level: str = "warning") -> dict:
    """Convert an audit report (as a dict) into a SARIF 2.1.0 log."""
    if level not in _LEVELS:
        raise ValueError(f"level must be one of {_LEVELS}, got {level!r}")

    findings = report_dict.get("findings") or []
    kinds_present = {f.get("kind", "") for f in findings}

    rules = []
    for kind in sorted(k for k in kinds_present if k in RULES):
        spec = RULES[kind]
        rules.append({
            "id": kind,
            "name": spec["name"],
            "shortDescription": {"text": spec["short"]},
            "fullDescription": {"text": spec["full"]},
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "supply-chain", "egress"]},
        })

    results = []
    for f in findings:
        kind = f.get("kind", "unknown")
        uri = str(f.get("file", "")).replace("\\", "/")
        results.append({
            "ruleId": kind,
            "level": level,
            "message": {"text": f.get("detail", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, int(f.get("line", 1)))},
                }
            }],
            "partialFingerprints": {
                "entrovouchFindingV1": _fingerprint(kind, uri, f.get("detail", "")),
            },
        })

    driver = {
        "name": "ENTROVOUCH no-egress auditor",
        "version": report_dict.get("tool_version", __version__),
        "informationUri": "https://github.com/EntroLabs/entrovouch",
        "rules": rules,
    }

    run = {
        "tool": {"driver": driver},
        "results": results,
        "properties": {
            # Carried so a consumer reading only the SARIF still receives the
            # scope limits and the binding. A findings list without its scope
            # statement is the overclaim this package exists to avoid.
            "verdict": report_dict.get("verdict", ""),
            "filesScanned": report_dict.get("files_scanned", 0),
            "scopeStatement": report_dict.get("scope_statement", ""),
            "subjectDigest": report_dict.get("subject_digest", ""),
            "findingsDigest": report_dict.get("findings_digest", ""),
        },
    }

    return {"$schema": _SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Convert an ENTROVOUCH audit report (JSON) to SARIF 2.1.0.")
    ap.add_argument("report", type=Path, help="audit report .json")
    ap.add_argument("--out", type=Path, default=None, help="write here (else stdout)")
    ap.add_argument("--level", default="warning", choices=_LEVELS,
                    help="severity for every result (default: warning; the tool "
                         "does not infer your policy)")
    args = ap.parse_args(argv)

    try:  # non-ASCII must not crash a cp1252 console
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    sarif = to_sarif(json.loads(args.report.read_text(encoding="utf-8")),
                     level=args.level)
    text = json.dumps(sarif, indent=2)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(sarif['runs'][0]['results'])} results)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

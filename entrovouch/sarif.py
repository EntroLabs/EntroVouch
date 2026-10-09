#!/usr/bin/env python3
"""
ENTROVOUCH: SARIF 2.1.0 export.

WHY THIS EXISTS
---------------
SARIF (Static Analysis Results Interchange Format) 2.1.0 is an OASIS standard
and the format GitHub code scanning ingests natively. A tool that emits SARIF
appears in the security tab of every repository that runs it, with zero
integration work by the consumer and no account, contract or API on our side.

SARIF is a distribution mechanism that costs one output adapter and requires
permission from nobody.

IT DOES NOT WEAKEN THE NO-EGRESS PROPERTY. This module writes a file. It opens
no socket, contacts no service, and imports nothing outside the standard
library. The ecosystem comes to the file; the tool never reaches out. That is
the only shape of distribution this package will accept.

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
from .no_egress_auditor import ReportError, load_report, NO_EGRESS_TOOL
from ._cli import missing_folder, run, write_text

__all__ = ["to_sarif", "SARIF_VERSION", "RULES"]

SARIF_VERSION = "2.1.0"
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# One rule per finding kind the auditor can emit. Descriptions state what was
# detected and what it does NOT prove: a reader meeting this tool for the
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
    "startup-exec": {
        "name": "StartupExecution",
        "short": "A .pth line that Python executes at interpreter start",
        "full": (
            "Python's site module executes every line of a .pth file that "
            "begins with import, at every interpreter start, when the file is "
            "in a site directory. The line is analysed like Python source; "
            "modules it imports from outside the audited tree are not."
        ),
    },
    "network-call": {
        "name": "NetworkCall",
        "short": "A call that opens a connection or fetches a URL",
        "full": (
            "A socket, asyncio or logging-handler call that reaches the network, "
            "or a URL literal handed to something that fetches it. The target "
            "may be same-origin; the capability is present."
        ),
    },
    "inbound-listener": {
        "name": "InboundListener",
        "short": "A listening socket is bound",
        "full": (
            "A server or a bound socket. Inbound, not egress, and reported "
            "separately so a reader can tell the two apart."
        ),
    },
    "external-url": {
        "name": "ExternalUrlInCode",
        "short": "A URL in script source",
        "full": (
            "A URL literal inside JavaScript or TypeScript source (comments "
            "excluded). Whether it is fetched depends on the surrounding code."
        ),
    },
    "external-link": {
        "name": "ExternalLink",
        "short": "A link the user must click",
        "full": (
            "An anchor to an external URL. Loading the page fetches nothing from "
            "it; following the link does."
        ),
    },
    "method-named-exec": {
        "name": "MethodNamedExecOrEval",
        "short": "A method named exec or eval, not the builtin",
        "full": (
            "A call to a method named exec or eval on some object. Most are not "
            "code execution (a model's inference mode, a database cursor, a "
            "container client). Whether this one runs code is not resolved."
        ),
    },
    "script-network-word": {
        "name": "NetworkProgramNamedOutsideACommand",
        "short": "A network program named where no command starts",
        "full": (
            "A script, recipe or pipeline line names a program that reaches the "
            "network (curl, ssh, git fetch) somewhere other than the start of a "
            "command: an argument, a value, a word in text. Whether it runs is not "
            "shown by the line."
        ),
    },
    "unresolved-call": {
        "name": "FetchNamedCallOnUnresolvedObject",
        "short": "A fetch-named call on an object that was not resolved",
        "full": (
            "A method such as get or post is given a URL literal, and the object it "
            "is called on was not traced to a network package. It may be a client, "
            "a cache, a mapping or a helper of the project's own. Whether this line "
            "reaches the network is not shown."
        ),
    },
    "native-call": {
        "name": "NativeLibraryCall",
        "short": "A call into a native library",
        "full": (
            "ctypes or cffi loads a native library. What that library does, "
            "including whether it opens a socket, is outside static analysis."
        ),
    },
    "unanalysed-artifact": {
        "name": "UnanalysedArtifact",
        "short": "Compiled or archived content that was not read",
        "full": (
            "A compiled module, shared library, wheel, zip or Cython source in "
            "the tree. It may contain executable code; this tool does not read it."
        ),
    },
    "loopback-call": {
        "name": "CallToThisMachine",
        "short": "A call or a command is aimed at an address on this machine",
        "full": (
            "A request, a socket connection or a download command whose literal address is the "
            "loopback interface (localhost, 127.0.0.1, ::1). It is network code and nothing leaves "
            "the machine at that line. A different address supplied at run time is not seen."
        ),
    },
    "network-target": {
        "name": "NetworkTargetBuilt",
        "short": "A request or client object is built for a literal address",
        "full": (
            "A call builds a request object from a URL literal, or a client or connection pool "
            "from a connection string that names a host. The address is in the source; nothing "
            "is sent at this line, and whether and where the object is used is not resolved."
        ),
    },
    "script-network-command": {
        "name": "ScriptNetworkCommand",
        "short": "A script, build recipe or pipeline file runs a command that reaches the network",
        "full": (
            "A line of a shell, PowerShell or batch script, a Dockerfile, a Makefile or a "
            "pipeline definition runs a download tool, a package installer or a remote "
            "git command. The match is on the command word in the line: no shell is "
            "parsed and no variable is expanded, so a command built at run time is not "
            "seen, and a matched command inside a branch that never runs is still reported."
        ),
    },
    "declared-remote-source": {
        "name": "DeclaredRemoteSource",
        "short": "A manifest or a Dockerfile names a source to fetch from",
        "full": (
            "A package index, a requirement installed from a URL or a "
            "repository, a registry setting, an install-time script that "
            "runs a network binary, or a base image a Dockerfile builds from. "
            "Not a call site in the code; a fetch the file declares."
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


def _fingerprint(kind: str, file: str, detail: str, occurrence: int = 0) -> str:
    """Stable identity for a result across runs.

    Deliberately EXCLUDES the line number. Inserting a comment at the top of a
    file shifts every line below it; a fingerprint that included the line would
    close every existing alert and open an identical set of new ones, which is
    how a code-scanning integration becomes noise and gets muted. Two results with
    the same rule, file and message are told apart by their order in the file
    (`occurrence`, counted from 0), so neither is merged into the other.
    """
    h = hashlib.sha256()
    for part in (kind, file.replace("\\", "/"), detail):
        h.update(part.encode("utf-8"))
        h.update(b"\x1f")
    if occurrence:
        h.update(f"#{occurrence}".encode("ascii"))
    return h.hexdigest()[:32]


_URI_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/")


def _uri_reference(path: str) -> str:
    """A relative path as a URI reference (RFC 3986): every byte outside the unreserved set and `/` is
    percent-encoded, so a space, `#`, `%` or a non-ASCII letter in a file name stays part of the path."""
    # A byte that is not valid UTF-8 in a POSIX file name is held by Python as an escape surrogate (U+DC80 to
    # U+DCFF): it is encoded as that byte. Any other lone surrogate (a Windows name) is encoded as UTF-8 would
    # spell it, so every name still gives one reference.
    def one(c: str) -> bytes:
        try:
            return c.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError:
            return c.encode("utf-8", "surrogatepass")
    return "".join(c if c in _URI_SAFE else "".join(f"%{b:02X}" for b in one(c)) for c in path)


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
    seen: dict[tuple[str, str, str], int] = {}
    ordered = sorted(findings, key=lambda f: int(f.get("line", 0) or 0))     # stable: equal lines keep report order
    occurrence_of = {}
    for f in ordered:
        key = (f.get("kind", "unknown"), str(f.get("file", "")).replace("\\", "/"), f.get("detail", ""))
        occurrence_of[id(f)] = seen.get(key, 0)
        seen[key] = seen.get(key, 0) + 1
    for f in findings:
        kind = f.get("kind", "unknown")
        rel = str(f.get("file", "")).replace("\\", "/")
        # a relative URI reference: a space, `#`, `%` or a non-ASCII letter in a path is percent-encoded
        uri = _uri_reference(rel)
        line = int(f.get("line", 0) or 0)
        physical: dict = {"artifactLocation": {"uri": uri}}
        result: dict = {"ruleId": kind, "level": level, "message": {"text": f.get("detail", "")}}
        if rel.lower().endswith(".ipynb"):
            # a notebook finding is reported at a cell number, not a line of the file's JSON: no region, the cell
            # as a property
            if line:
                result["properties"] = {"notebookCell": line}
        elif line:
            physical["region"] = {"startLine": line}
        result["locations"] = [{"physicalLocation": physical}]
        result["partialFingerprints"] = {
            "entrovouchFindingV1": _fingerprint(kind, uri, f.get("detail", ""), occurrence_of[id(f)]),
        }
        results.append(result)

    driver = {
        "name": "ENTROVOUCH no-egress auditor",
        "version": report_dict.get("tool_version", __version__),
        "informationUri": "https://github.com/EntroLabs/EntroVouch",
        "rules": rules,
    }

    # A code-scanning view shows results and invocations, not run properties: a report that read nothing is an
    # unsuccessful run with a notification, never a run with zero alerts.
    read_nothing = report_dict.get("verdict") == "NOT-ANALYSED"
    invocation: dict = {"executionSuccessful": not read_nothing}
    if read_nothing:
        invocation["toolExecutionNotifications"] = [{
            "level": "error",
            "message": {"text": "NOT-ANALYSED: no file in the tree was read, so this run says nothing about egress"},
        }]
    run = {
        "tool": {"driver": driver},
        "invocations": [invocation],
        "results": results,
        "properties": {
            # Carried so a consumer reading only the SARIF still receives the
            # scope limits and the binding. A findings list without its scope
            # statement is the overclaim this package exists to avoid.
            "verdict": report_dict.get("verdict", ""),
            # an unsigned report's hash has no key: anyone can edit it and recompute it. A signature is evidence of
            # who issued the report only when its root is one the reader pinned: the root is carried, never a bare
            # "signed", and the signature is not checked against any root here
            "signed": bool(report_dict.get("signature")),
            "signedBy": (str(report_dict.get("public_root") or "") or None) if report_dict.get("signature") else None,
            "signatureChecked": "against the report body only; check the signer with "
                                "`python -m entrovouch.verify <report> --root <the root you pinned>`",
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
    if getattr(args, 'out', None) is not None:
        clash = missing_folder(args.out, inputs=(args.report,))
        if clash and 'reads' in clash:
            print(clash, file=sys.stderr)       # a report converted onto itself would be destroyed
            return 2

    try:  # non-ASCII must not crash a cp1252 console
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

    try:
        report = load_report(args.report, kind=NO_EGRESS_TOOL)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    sarif = to_sarif(report, level=args.level)
    text = json.dumps(sarif, indent=2)
    if args.out:
        write_text(args.out, text)
        print(f"wrote {args.out} ({len(sarif['runs'][0]['results'])} results)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(run(main))

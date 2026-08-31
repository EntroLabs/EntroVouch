#!/usr/bin/env python3
"""
ENTROVOUCH — No-Egress / Sovereign Supply-Chain Auditor

Proves, mechanically and repeatably, that a target codebase makes ZERO
unauthorized network calls: no telemetry, no exfiltration, no hidden remote.
Produces a signed, third-party-verifiable audit report.

Generalized from a local-only verification gate written to enforce a
zero-remotes rule on a single codebase, so it now audits ANY directory tree.
Pure stdlib — this auditor performs zero network operations itself, which is a
property you can check by running it on its own source.

HONEST SCOPE — this travels with every report, not just this docstring: static
analysis of a Turing-complete language cannot catch every obfuscated
exfiltration path (e.g. getattr(subprocess, chr(114)+...)(...)). This tool
catches the entire class of realistic and accidental egress plus the common
deliberate patterns. It does NOT mathematically prove zero egress, and the
report says so in those words. A report that names what it cannot prove is
worth more to someone answering a regulator than one that overclaims and
collapses on the first hard question.

What it is for: it protects a buyer's ability to substantiate an "on-prem, no
telemetry" claim with something reproducible rather than a policy document.
It extracts nothing from the codebase it audits and sends nothing anywhere.

Usage:
    python -m entrovouch.no_egress_auditor <target_dir> [--json out.json] [--md out.md]
Exit code 0 = CLEAN. Exit code 1 = FINDINGS (also written to the report).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import hmac
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from ._version import __version__
from .signer import (ALGORITHM, UNSIGNED, MerkleSigner, SignerError,
                     verify_signature)

# ---------------------------------------------------------------------------
# Policy — the same lists the hardened dashboard checker uses, generalized.
# ---------------------------------------------------------------------------
FORBIDDEN_IMPORT_MODULES = {
    "urllib", "urllib.request", "urllib.error", "requests", "httpx",
    "aiohttp", "http.client", "httplib", "socket", "ftplib", "smtplib",
    "telnetlib", "poplib", "imaplib", "websocket", "websockets",
    "grpc", "paramiko", "pycurl",
    # Telemetry / analytics / APM — egress by definition, and the category a
    # "no telemetry" claim is actually ABOUT. Closes G1: the JS blocklist has
    # carried these since the TypeScript pass; the Python one never did, so the
    # auditor could pass a tree that ships user data to a vendor on import.
    "sentry_sdk", "posthog", "mixpanel", "analytics", "segment",
    "datadog", "ddtrace", "newrelic", "bugsnag", "rollbar",
    "opentelemetry", "elasticapm", "amplitude", "scout_apm", "statsd",
    # Cloud SDKs — a client object is a network client whether or not it is called
    "boto3", "botocore", "google.cloud", "googleapiclient", "azure",
    "firebase_admin", "supabase",
    # HTTP transports. `requests` was blocked and the library it is BUILT ON was
    # not, so `import urllib3` passed a no-egress audit clean. Same for the
    # transports under httpx.
    "urllib3", "httpcore", "h11", "h2", "hpack", "hyperframe",
    # stdlib network surface that is not obfuscated in any way and was simply
    # absent from the list.
    "xmlrpc.client", "xmlrpc", "webbrowser", "asyncore", "asynchat",
    "multiprocessing.connection",
    # Message buses, brokers and database drivers. "Where does my data go" is
    # the question this tool answers, and a database client is an answer to it.
    "zmq", "pyzmq", "pika", "kafka", "confluent_kafka", "redis", "pymongo",
    "psycopg2", "psycopg", "mysql", "MySQLdb", "cassandra", "elasticsearch",
    "clickhouse_driver", "paho", "stomp", "nats",
    # Async network frameworks.
    "tornado", "twisted", "gevent", "eventlet", "trio",
    # Hosted-model API clients — egress is their entire purpose.
    "openai", "anthropic", "cohere", "replicate", "together", "groq", "mistralai",
    # Model/artifact hubs and experiment trackers: these fetch or upload on
    # default code paths, which is precisely the non-obvious egress a "no
    # telemetry" claim is about.
    "huggingface_hub", "transformers", "datasets", "timm",
    "wandb", "mlflow", "comet_ml", "neptune", "clearml",
}

# Submodules that are PURE even though their parent package is network-capable.
#
# Matching was `name.split(".")[0] in FORBIDDEN`, so `from urllib.parse import
# urlparse` matched on the `urllib` root and was reported as a network import.
# urllib.parse is string manipulation; it cannot open a socket. Parsing a URL is
# ordinary in almost any codebase, so this was a false positive on common code —
# and a false positive costs more than the finding is worth (see the same
# reasoning in key_provenance._KEY_ARG). Exact matches here are never reported.
NON_NETWORK_SUBMODULES = {
    "urllib.parse",
}

# INBOUND network surface — a bound, listening socket.
#
# Kept SEPARATE from egress on purpose. Strictly, a server is not exfiltration,
# so calling it "egress" would be wrong. But a buyer asking for "on-prem, no
# telemetry" means something that a listening port is squarely part of, and
# silently omitting it because the tool's name says "egress" would answer the
# narrow question while missing the one actually being asked. Reported under its
# own kind, with its own scope line, so the reader sees which is which.
INBOUND_IMPORT_MODULES = {
    "socketserver", "wsgiref", "http.server", "xmlrpc.server",
    "uvicorn", "gunicorn", "waitress", "hypercorn", "daphne",
}

# asyncio is deliberately NOT an import-level finding.
#
# It appears in 47 files of this estate alone and is overwhelmingly used for
# concurrency, not sockets. Flagging `import asyncio` would manufacture exactly
# the false-positive problem this pass exists to remove. The network CALLS are
# unambiguous, so those are what get flagged.
ASYNCIO_NET_CALLS = {
    "open_connection", "start_server", "create_connection", "create_server",
    "open_unix_connection", "start_unix_server", "sock_connect", "connect_write_pipe",
}
FORBIDDEN_GIT_SUBCOMMANDS = {"fetch", "pull", "push", "clone", "remote", "submodule"}

# Network binaries reachable through an argv list with NO shell=True — the exact
# gap the TypeScript checker already measured and named at _JS_NET_BINARY_RE.
# `subprocess.run(["curl", url])` spawns no shell, so the shell=True test never
# fires and the call was invisible to this auditor. Matched on the basename, so
# "/usr/bin/curl" and "curl.exe" both hit.
PY_NET_BINARIES = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
    "rsync", "ftp", "telnet", "git", "pip", "pip3", "npm", "yarn",
    "apt", "apt-get", "docker", "kubectl", "aws", "gcloud", "az",
}


def _classify_module(name: str) -> str | None:
    """'network' | 'dependency' | 'inbound' | None for a dotted module name.

    ⭐ THE DISTINCTION THIS FUNCTION EXISTS TO MAKE: importing a network package
    and importing one of its pure submodules are DIFFERENT CLAIMS, and conflating
    them is a false positive.

        from requests.structures import CaseInsensitiveDict

    tells you requests is a dependency. It is not a network call: that module is a
    dict subclass with zero network tokens in its source. Reporting it as
    `network-import` says a socket may open at that line, and no socket can.

    Measured over 20 well-known Python repositories (2026-08-30): **32 of 257
    non-dynamic findings were this one defect class, a 12.5% false-positive rate,
    and every single false positive was a submodule of a network package.**
    `requests.structures`, `requests.compat`, `urllib3.exceptions`, `urllib3.util`,
    `trio.testing` and eight others.

    ⛔ THE FIX IS STRUCTURAL, NOT A LONGER ALLOWLIST. `NON_NETWORK_SUBMODULES`
    below names `urllib.parse` because a stdlib case was found first, and
    enumerating every pure submodule of every network package on PyPI is not a
    thing anyone can finish. The rule instead:

      * the module is listed EXACTLY  -> `network` (a real entry point:
        `urllib.request`, `http.client`, `requests`, `urllib3`)
      * only its ROOT is listed       -> `dependency` (evidence the package is
        present; not a claim that this line reaches the network)

    Recall is preserved: a reader still learns the package is there. What changes
    is that the tool stops asserting a network call it cannot support.
    """
    if not name:
        return None
    if name in NON_NETWORK_SUBMODULES:
        return None
    root = name.split(".")[0]
    if name in FORBIDDEN_IMPORT_MODULES:
        return "network"
    if name in INBOUND_IMPORT_MODULES:
        return "inbound"
    if root in FORBIDDEN_IMPORT_MODULES:
        return "dependency"
    if root in INBOUND_IMPORT_MODULES:
        return "inbound"
    return None


def _argv_basename(s: str) -> str:
    """Basename of an argv[0], normalized. '/usr/bin/curl' and 'curl.exe' -> 'curl'."""
    base = s.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return base[:-4] if base.endswith(".exe") else base
SUBPROCESS_CALLERS = {"run", "call", "check_call", "check_output", "Popen"}
OS_SHELL_CALLERS = {"system", "popen"}

# HTML/JS external-reference patterns (case-insensitive).
URL_RE = re.compile(r"""https?://""", re.IGNORECASE)
DATA_URI_RE = re.compile(r"""data:[^;'"\s]*;base64""", re.IGNORECASE)
ENTITY_SCHEME_RE = re.compile(r"""&#x?0*(104|68);t?tp""", re.IGNORECASE)  # entity-encoded http
NET_CALL_RE = re.compile(r"""\b(fetch|XMLHttpRequest|WebSocket|navigator\.sendBeacon)\s*\(""")
SRC_HREF_RE = re.compile(r"""(?:src|href)\s*=\s*['"]https?://""", re.IGNORECASE)

TEXT_EXTS = {".py", ".pyw"}
MARKUP_EXTS = {".html", ".htm", ".js", ".mjs", ".jsx", ".vue", ".svelte"}
# TypeScript gets its own source-aware checker (see _check_ecmascript), NOT the
# HTML regex path. Routing .ts through MARKUP_EXTS would fire URL_RE on every
# comment, JSDoc @see link and licence header in the tree -- unusable noise on a
# real TypeScript codebase, and the same false-positive class that made a 118-
# finding audit contain only 7 that touched shipped code.
TS_EXTS = {".ts", ".tsx", ".mts", ".cts"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}

# ---------------------------------------------------------------------------
# ECMAScript / TypeScript egress surface
#
# Bare module specifiers that can reach the network. Matched on the package
# ROOT, so "@sentry/node" matches the "@sentry" scope entry and
# "axios/lib/adapters/http" matches "axios".
# ---------------------------------------------------------------------------
JS_NET_MODULES = {
    # Node builtins
    "http", "https", "http2", "net", "tls", "dgram", "dns", "cluster",
    "node:http", "node:https", "node:http2", "node:net", "node:tls",
    "node:dgram", "node:dns",
    # HTTP clients
    "axios", "node-fetch", "got", "superagent", "request", "undici", "ky",
    "phin", "needle", "bent", "wretch",
    # Realtime / sockets
    "ws", "socket.io", "socket.io-client", "sockjs", "sockjs-client",
    "eventsource", "pusher-js", "ably",
    # GraphQL / RPC clients
    "apollo-client", "@apollo", "graphql-request", "urql", "grpc", "@grpc",
    # Telemetry / analytics -- the category the Python blocklist misses too
    "@sentry", "posthog-js", "posthog-node", "mixpanel", "mixpanel-browser",
    "@segment", "analytics-node", "@datadog", "dd-trace", "newrelic",
    "bugsnag", "@bugsnag", "rollbar", "@opentelemetry", "elastic-apm-node",
    "@amplitude", "amplitude-js", "logrocket", "@sentry/browser",
    # Cloud SDKs (egress by definition)
    "aws-sdk", "@aws-sdk", "@google-cloud", "googleapis", "@azure",
    "firebase", "@firebase", "@supabase",
}

# child_process is the JS analogue of Python's subprocess: a shell string or an
# argv list can invoke curl/wget/nc and leave the process entirely.
JS_PROCESS_MODULES = {"child_process", "node:child_process"}

# import/require detection. Covers: import x from 'm'; import 'm';
# import * as x from 'm'; import {a} from 'm'; export ... from 'm';
# require('m'); await import('m').
_JS_IMPORT_RE = re.compile(
    r"""(?:\bimport\b[^;'"]*?\bfrom\s*|\bimport\s*|\bexport\b[^;'"]*?\bfrom\s*|"""
    r"""\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"]+)['"]""",
    re.MULTILINE,
)

# Direct network call expressions.
# NOTE the \b placement: it anchors ONLY the identifier-initial alternatives,
# so `prefetchData(` does not match `fetch(`. It deliberately does NOT wrap the
# jQuery branch -- `$` is a non-word character, so a leading \b would require a
# word boundary that ` $.ajax(` never provides, and the pattern would silently
# never fire. Caught by test_detects_network_call_expressions[$.ajax].
_JS_NET_CALL_RE = re.compile(
    r"""(?:\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon"""
    r"""|axios(?:\.(?:get|post|put|patch|delete|head|request|all))?"""
    r"""|https?\.(?:get|request)|net\.(?:connect|createConnection))"""
    r"""|\$\.(?:ajax|get|post|getJSON))\s*\(""",
)

# child_process invocations.
_JS_PROCESS_CALL_RE = re.compile(
    r"""\b(?:child_process\s*\.\s*)?(?:exec|execSync|execFile|execFileSync"""
    r"""|spawn|spawnSync|fork)\s*\(""",
)

# Dynamic code execution -- undecidable payload, flagged unconditionally.
_JS_DYNAMIC_RE = re.compile(r"""(?:\beval\s*\(|\bnew\s+Function\s*\()""")

# A network binary invoked through child_process -- the exact gap measured in
# the Python auditor (argv-list form without shell=True is invisible there).
_JS_NET_BINARY_RE = re.compile(
    r"""['"](?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|ftp|telnet)['"\s]""",
)


def _js_module_root(spec: str) -> str:
    """Package root of a bare specifier. '@scope/pkg/sub' -> '@scope'."""
    if spec.startswith("@"):
        return spec.split("/")[0]
    return spec.split("/")[0]


def _strip_js_comments(src: str) -> str:
    """Blank out comments, PRESERVING string literals and line numbers.

    Strings are kept deliberately: a hardcoded URL inside a string literal is
    real egress evidence, while the same URL in a JSDoc block is not. Blanking
    comments to spaces (and keeping newlines) means reported line numbers still
    point at the real line.

    Known limit, stated rather than hidden: a regex literal beginning `/*`
    would be misread as a block comment. That is rare enough to accept and
    cheap enough to notice, and the alternative is shipping a full ECMAScript
    tokeniser, which this tool deliberately is not.
    """
    out: list[str] = []
    i, n = 0, len(src)
    in_line = in_block = False
    quote: str | None = None
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                in_block = False
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
        else:
            if c == "/" and nxt == "/":
                out.append("  ")
                in_line = True
                i += 2
            elif c == "/" and nxt == "*":
                out.append("  ")
                in_block = True
                i += 2
            elif c in "\"'`":
                quote = c
                out.append(c)
                i += 1
            else:
                out.append(c)
                i += 1
    return "".join(out)


def _check_ecmascript(path: Path, rel: str) -> list[Finding]:
    """Source-aware egress check for TypeScript (and TS-family) files.

    Deliberately NOT the HTML regex path: comments are stripped first, so a
    licence header or a JSDoc @see link does not become a finding, while a URL
    in a string literal still does.
    """
    out: list[Finding] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    src = _strip_js_comments(raw)

    # Module-level: imports and requires of network-capable packages.
    for m in _JS_IMPORT_RE.finditer(src):
        spec = m.group(1)
        if spec.startswith(".") or spec.startswith("/"):
            continue  # relative/absolute local import
        root = _js_module_root(spec)
        line = src.count("\n", 0, m.start()) + 1
        if root in JS_NET_MODULES or spec in JS_NET_MODULES:
            out.append(Finding(rel, line, "network-import", f"imports {spec!r}"))
        elif root in JS_PROCESS_MODULES or spec in JS_PROCESS_MODULES:
            out.append(Finding(rel, line, "subprocess-shell",
                               f"imports {spec!r} — can invoke a network binary"))

    # Expression-level.
    for i, line in enumerate(src.splitlines(), 1):
        if _JS_NET_CALL_RE.search(line):
            out.append(Finding(rel, i, "network-call", "network call expression"))
        if _JS_PROCESS_CALL_RE.search(line):
            detail = "child_process invocation"
            if _JS_NET_BINARY_RE.search(line):
                detail += " of a network binary (curl/wget/nc/ssh/...)"
            out.append(Finding(rel, i, "subprocess-shell", detail))
        if _JS_DYNAMIC_RE.search(line):
            out.append(Finding(rel, i, "dynamic-exec", "eval / new Function"))
        if URL_RE.search(line):
            out.append(Finding(rel, i, "external-url", "external URL in code or string"))
    return out


@dataclass
class Finding:
    file: str
    line: int
    kind: str          # network-import | git-remote | subprocess-shell | subprocess-net-binary | dynamic-exec | html-external
    detail: str


@dataclass
class AuditReport:
    tool: str = "ENTROVOUCH no-egress auditor"
    # 1.1.0 adds TypeScript (.ts/.tsx/.mts/.cts) via a source-aware checker.
    # Bumped deliberately: a report signed by 1.1.0 can legitimately differ
    # from one signed by 1.0.0 on the same tree, because the tree may contain
    # TypeScript that 1.0.0 never looked at. The version is what lets a reader
    # tell "the code changed" from "the tool got better".
    tool_version: str = __version__
    target: str = ""
    scanned_at_utc: str = ""
    files_scanned: int = 0
    verdict: str = "CLEAN"                       # CLEAN | FINDINGS
    findings: list = field(default_factory=list)
    scope_statement: str = (
        "Static analysis of Python, TypeScript and HTML/JS. Catches the "
        "realistic/accidental egress class plus common deliberate patterns "
        "(network-capable imports, git remote subcommands, shell=True and "
        "os.system/popen, child_process, dynamic import/exec/eval, external "
        "references, network binaries spawned via argv list, telemetry/APM and "
        "cloud SDK imports). Does NOT mathematically prove zero egress in a "
        "Turing-complete language. Known blind spots, stated rather than "
        "implied: detection is BLOCKLIST-BASED, so it is complete only against "
        "names it knows -- a renamed, vendored or dynamically-constructed module "
        "or argv entry is invisible, and a blocklist can never be complete by "
        "construction. Non-literal arguments (variables, f-strings, lists built "
        "at runtime) are not resolved. This report is therefore DETECTION-grade "
        "evidence and does not support an unqualified claim of absence."
    )
    # WHAT WAS AUDITED, not merely what it was called. `target` is a free-text
    # label the auditor supplies; two entirely different trees can produce
    # byte-identical reports under the same label, so a signature over the body
    # alone attests the SENTENCE and not the SUBJECT. `subject` follows the
    # in-toto Statement shape ({name, digest{alg: hex}}) so the binding is the
    # one the supply-chain ecosystem already verifies, rather than a bespoke
    # field a consumer would have to be taught.
    subject: list = field(default_factory=list)
    # Order-independent digest over every file the audit actually read.
    subject_digest: str = ""
    # THE REPRODUCIBLE VALUE. Covers tool, version, subject, verdict and
    # findings -- and deliberately EXCLUDES `scanned_at_utc`, which is why it is
    # bit-identical across runs while `content_hash` is not. "Reproduce it
    # yourself" is this package's entire pitch, and until now nothing in the
    # artifact reproduced: the reader was told to eyeball the findings instead.
    findings_digest: str = ""
    content_hash: str = ""
    # An UNKEYED digest of the canonical body. It detects accidental corruption
    # and nothing else: anyone can recompute it, so it is integrity, not origin.
    # Named for what it is -- the field it replaced was called a "signature"
    # while being exactly this (see signer.py's header for the demonstration).
    # DEPRECATED 2026-08-20, still emitted so old readers do not crash. It is an
    # HMAC keyed by PUBLIC text: redundant with `content_hash`, never evidence.
    # `verify_report` no longer consults it. Do not add a new consumer.
    integrity_tag: str = ""
    signature_algorithm: str = UNSIGNED
    signature: dict | None = None
    public_root: str = ""


# ---------------------------------------------------------------------------
# Python source checks (AST — a comment/docstring mentioning a module never fires)
# ---------------------------------------------------------------------------
def _check_python(path: Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src, filename=str(path))
    except (SyntaxError, ValueError):
        return out  # unparseable file — not our job to lint syntax

    for node in ast.walk(tree):
        # network-capable imports
        if isinstance(node, ast.Import):
            for a in node.names:
                if _classify_module(a.name) == "network":
                    out.append(Finding(rel, node.lineno, "network-import", f"import {a.name}"))
                elif _classify_module(a.name) == "dependency":
                    out.append(Finding(rel, node.lineno, "network-dependency",
                                       f"import {a.name} — submodule of a network-capable package; "
                                       "evidence the dependency is present, NOT a network call here"))
                elif _classify_module(a.name) == "inbound":
                    out.append(Finding(rel, node.lineno, "inbound-listener",
                                       f"import {a.name} — binds a listening socket (INBOUND, not egress)"))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _classify_module(mod) == "network":
                out.append(Finding(rel, node.lineno, "network-import", f"from {mod} import ..."))
            elif _classify_module(mod) == "dependency":
                out.append(Finding(rel, node.lineno, "network-dependency",
                                   f"from {mod} import ... — submodule of a network-capable package; "
                                   "evidence the dependency is present, NOT a network call here"))
            elif _classify_module(mod) == "inbound":
                out.append(Finding(rel, node.lineno, "inbound-listener",
                                   f"from {mod} import ... — binds a listening socket (INBOUND, not egress)"))

        # subprocess / os shell calls + git remote subcommands
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            # asyncio network calls — flagged at the CALL, never at the import.
            # `asyncio.open_connection(...)` and `loop.create_connection(...)`
            # both land here; a bare `import asyncio` for concurrency does not.
            if isinstance(fn, ast.Attribute) and fn.attr in ASYNCIO_NET_CALLS:
                out.append(Finding(rel, node.lineno, "network-call",
                                   f"{fn.attr}(...) — asyncio network connection"))
            # shell=True on any subprocess call is flagged unconditionally
            if name in SUBPROCESS_CALLERS:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        out.append(Finding(rel, node.lineno, "subprocess-shell",
                                           f"{name}(shell=True) — shell string can encode remote egress"))
                # argv-list forms — no shell, so the shell=True test above never fires
                for arg in node.args:
                    if isinstance(arg, (ast.List, ast.Tuple)):
                        elts = [e.value for e in arg.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                        if not elts:
                            continue
                        exe = _argv_basename(elts[0])
                        # literal git remote subcommand in an argv list
                        if exe == "git":
                            for sub in elts[1:]:
                                if sub in FORBIDDEN_GIT_SUBCOMMANDS:
                                    out.append(Finding(rel, node.lineno, "git-remote", f"git {sub}"))
                                    break
                        # G1: any OTHER network binary spawned as an argv list.
                        # git is excluded here because its network use is decided by
                        # the subcommand above — flagging bare `git status` would be
                        # a false positive, and false positives are what made an
                        # earlier 118-finding audit contain only 7 real ones.
                        elif exe in PY_NET_BINARIES:
                            out.append(Finding(
                                rel, node.lineno, "subprocess-net-binary",
                                f"{name}([{exe!r}, ...]) — network binary via argv list, "
                                f"no shell=True so it evades the shell check"))
            if name in OS_SHELL_CALLERS and isinstance(fn, ast.Attribute):
                root = fn.value
                if isinstance(root, ast.Name) and root.id == "os":
                    out.append(Finding(rel, node.lineno, "subprocess-shell", f"os.{name}(...) — shell string"))
            # dynamic exec/eval/import — undecidable payloads, flagged unconditionally
            if name in {"exec", "eval"} or (isinstance(fn, ast.Name) and fn.id in {"exec", "eval", "__import__"}):
                out.append(Finding(rel, node.lineno, "dynamic-exec", f"{name}(...) — dynamic code execution"))
            if name == "import_module":
                out.append(Finding(rel, node.lineno, "dynamic-exec", "importlib.import_module(...)"))
    return out


# ---------------------------------------------------------------------------
# Markup / JS checks (regex — external refs and network calls)
# ---------------------------------------------------------------------------
def _check_markup(path: Path, rel: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for i, line in enumerate(text.splitlines(), 1):
        if SRC_HREF_RE.search(line) or URL_RE.search(line):
            out.append(Finding(rel, i, "html-external", "external URL / src / href"))
        elif DATA_URI_RE.search(line):
            out.append(Finding(rel, i, "html-external", "base64 data: URI"))
        elif ENTITY_SCHEME_RE.search(line):
            out.append(Finding(rel, i, "html-external", "entity-encoded http scheme"))
        elif NET_CALL_RE.search(line):
            out.append(Finding(rel, i, "html-external", "fetch/XHR/WebSocket/sendBeacon call"))
    return out


# ---------------------------------------------------------------------------
# Signing — mirrors ENTROATTEST: the Covenant text IS the key. No secret needed;
# authenticity comes from Covenant-binding + content-binding, not key secrecy.
# ---------------------------------------------------------------------------
_DEFAULT_COVENANT = "Optimize systems for people, not margin extraction. One Covenant. Always."


# Fields excluded from the SIGNED body. This set is deliberately minimal: it
# holds ONLY the three fields that cannot be inside the thing they describe.
#
# `signature_algorithm` and `public_root` are INSIDE the signed body, not merely
# displayed beside it. A field a reader relies on to judge a signature has to be
# covered by that signature, or it is decoration: editing either one yields
# TAMPERED rather than a quietly different claim. The displayed algorithm is
# exactly what a counterparty reads to satisfy a cryptography clause, so an
# unauthenticated one would be worse than none at all.
_SIG_FIELDS = {"signature", "content_hash", "integrity_tag"}

# Fields that are properties of THIS ISSUANCE rather than of the audit result.
# Excluding them is what makes `findings_digest` reproducible.
#
# `signature_algorithm` and `public_root` are named here EXPLICITLY rather than
# inherited from `_SIG_FIELDS`. They are now signed, but they must still not
# reach `findings_digest`, or the same audit of the same tree would reproduce
# differently depending on who signed it -- which is the one property
# `findings_digest` exists to provide.
_ISSUANCE_FIELDS = _SIG_FIELDS | {"signature_algorithm", "public_root",
                                  "scanned_at_utc", "findings_digest",
                                  "subject"}

_FILE_TAG = bytes([0])   # domain separation, same discipline as signer.py
_TREE_TAG = bytes([1])


def _subject_name(target: Path) -> str:
    """The final path component, resolving relative forms to a real name.

    ⚠️ `Path(".").name` is the EMPTY STRING, and `.` is the single most natural
    way anyone runs this ("audit my repo"). That produced a report whose
    `target` was blank and, worse, an in-toto Statement whose `subject.name`
    was `""` -- the one field that makes the interoperability claim true.

    Resolving is safe here and does NOT reintroduce the 2026-07-31 path leak:
    only the final component is ever returned, never the absolute path.
    """
    # 🔴 COERCE, do not assume. `build_cbom(".")` passes a str and this raised
    # AttributeError -- found 2026-08-22 by calling the public API the way the
    # README documents it, which no test did. ⭐ The defect was introduced the
    # same day by the fix for the empty-name bug: a correction that narrowed the
    # accepted input, unnoticed because both in-package callers pass a Path.
    # ⚠️ Kept even though both callers now coerce: this is a module-private
    # helper that any future caller may reach directly, and the cost is one
    # no-op constructor. Redundant guards at a boundary are cheap; the
    # missing one cost a public-API crash.
    target = Path(target)
    name = target.name or target.resolve().name
    # A drive root ("D:\\") resolves to an empty name too. Say so rather than
    # emitting an empty string that reads as a missing field.
    return name or "<filesystem-root>"


def _file_digest(path: Path) -> str:
    """SHA3-256 of a file's raw bytes. Content, never path metadata."""
    h = hashlib.sha3_256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _tree_digest(entries: list[tuple[str, str]]) -> str:
    """Order-independent digest over (relative_path, file_digest) pairs.

    Sorted before hashing, so filesystem iteration order cannot change the
    result. Covers exactly the files the audit READ -- a digest over files the
    tool never opened would assert coverage the report does not have.
    """
    h = hashlib.sha3_256()
    h.update(_TREE_TAG)
    for rel, dig in sorted(entries):
        h.update(_FILE_TAG)
        h.update(rel.replace("\\", "/").encode("utf-8"))
        h.update(bytes.fromhex(dig))
    return h.hexdigest()


def reproducible_body(report_dict: dict) -> bytes:
    """The bytes behind `findings_digest` -- stable across runs and machines."""
    clean = {k: v for k, v in report_dict.items() if k not in _ISSUANCE_FIELDS}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_body(report_dict: dict) -> bytes:
    """The exact bytes that are hashed and signed. Stable across processes."""
    clean = {k: v for k, v in report_dict.items() if k not in _SIG_FIELDS}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(report_dict: dict, covenant_text: str = "") -> tuple[str, str]:
    """Compute the unkeyed content hash. The second element is always "".

    ⚠️ THE COVENANT-KEYED HMAC WAS REMOVED 2026-08-20 and `covenant_text` is
    ignored. It was kept for six days after `verify_report` stopped consulting
    it, on the reasoning that an unused field is harmless -- and this package's
    OWN `key_provenance` detector disagreed, flagging it REVIEW on every
    self-audit as `derived-from-parameter`. It was right: the field cost a
    permanent REVIEW finding and bought nothing, because an HMAC keyed by
    published text detects exactly what the unkeyed hash beside it detects.

    ⭐ The tool found this in its own source. That is the argument for shipping
    detectors you actually run against yourself.

    Origin attestation is `signer.MerkleSigner`, via `audit(..., signer=...)`.
    """
    ch = hashlib.sha3_256(canonical_body(report_dict)).hexdigest()
    return ch, ""


def verify_any(message: bytes, sig: dict,
               expected_root: str | None = None) -> bool:
    """Verify a signature under whichever scheme produced it.

    Dispatch is on the signature's own `algorithm` field, and an ALGORITHM THIS
    BUILD DOES NOT KNOW RETURNS FALSE rather than raising or, worse, falling
    through to a default verifier. A verifier that quietly picks a scheme when
    it does not recognise the one it was handed is how a downgrade happens.

    One scheme ships: Lamport-Merkle SHA3-256. It is hash-based, so it rests on
    no lattice or discrete-log assumption, and it claims conformance to no
    published standard - there is nothing here to fail a conformance test
    against.
    """
    algorithm = sig.get("algorithm")
    if algorithm == ALGORITHM:
        return verify_signature(message, sig, expected_root=expected_root)
    return False


def verify_report(report_dict: dict, expected_root: str | None = None,
                  covenant_text: str = _DEFAULT_COVENANT) -> tuple[bool, str]:
    """Verify a report. Returns `(ok, status)` -- never a bare bool.

    A bare `True` was the old API's second defect: a caller could not tell
    "cryptographically attested by a pinned identity" from "the bytes hash to
    what they say they hash to", and the function returned True for both.

    ⚠️ `ok` IS TRUE FOR EXACTLY ONE STATUS: `ATTESTED`. It answers *"may I rely
    on this as third-party evidence?"*, and only a signature checked against an
    identity the caller pinned can answer yes. Everything else is False.

    This is a deliberate FAIL-CLOSED change, made because the previous version
    returned `(True, "UNSIGNED")` for a report anyone could fabricate -- the
    unsigned branch was validated against an HMAC keyed by a string literal
    published in this repository, so a fabricated CLEAN verdict for a codebase
    that was never scanned verified True. That is the SAME defect class the
    2026-08-14 retraction was written about, surviving in the branch the
    retraction did not cover: the signature was fixed and the fallback was not.
    Demonstrated by execution before this fix, not inferred.

    An unsigned report is not evidence of origin and now cannot be mistaken for
    it by a caller who checks the boolean and ignores the status.

    status is one of:
      ATTESTED  - signed by `expected_root`; origin and integrity both proven.
                  THE ONLY STATUS FOR WHICH `ok` IS TRUE.
      UNVERIFIED- signature is internally valid but the caller pinned no
                  identity, so anyone could have produced it. Not evidence.
      UNSIGNED  - well-formed, self-consistent, and carries NO origin claim.
      TAMPERED  - body does not match its own hash, or the signature is invalid.
    """
    ch = hashlib.sha3_256(canonical_body(report_dict)).hexdigest()
    if not hmac.compare_digest(ch, report_dict.get("content_hash", "")):
        return False, "TAMPERED"

    sig = report_dict.get("signature")
    if not sig:
        # `integrity_tag` is DELIBERATELY NOT CONSULTED. It is an HMAC keyed by
        # public material, so it is computable by anyone and detects exactly
        # what the unkeyed `content_hash` above already detects -- it was never
        # weak evidence, it was REDUNDANT evidence wearing a cryptographic name.
        return False, "UNSIGNED"

    body = canonical_body(report_dict)
    if not verify_any(body, sig, expected_root=expected_root):
        return False, "TAMPERED"
    return (True, "ATTESTED") if expected_root else (False, "UNVERIFIED")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def audit(target: Path | str, covenant_text: str = _DEFAULT_COVENANT,
          label: str | None = None, signer: "MerkleSigner | None" = None) -> AuditReport:
    """Audit `target`. `label` names the subject in the signed report.

    The report is handed to the audited party, so `target` must never carry the
    auditor's absolute local path. It previously did: a report delivered on
    2026-07-31 shipped the full local path of the scanned tree inside the signed
    JSON — carrying the auditor's OS username, an internal directory name and a
    session UUID, none of which mean anything to the recipient and all of which
    are pure downside. It was not caught because the leak scan ran against the
    report DOCX and the signed JSON was a separate attachment.

    ⭐ The example path that used to sit in this docstring has been removed too
    (2026-08-22): a comment explaining a path leak does not need to reproduce
    the path. **Describing the shape is enough; quoting it re-ships a fragment
    of the thing being warned about.**

    So: pass `label` as the checkable identity of what was audited
    (`org/repo@commit`). With no label, only the final path component is
    recorded — never the absolute path. There is no way to get the full local
    path into a report any more, which is the point.
    """
    # 🔴 Coerce at the boundary. `build_cbom(".")` / `audit(".")` -- the form the
    # README documents -- raised AttributeError, because every in-package caller
    # happened to pass a Path and no test called the public API as a stranger
    # would. ⭐ A public entry point takes what its users type, not what its
    # neighbours pass; annotations are documentation, never coercion.
    target = Path(target)
    rep = AuditReport(target=label or _subject_name(target),
                      scanned_at_utc=datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = []
    scanned = 0
    tree: list[tuple[str, str]] = []
    for p in sorted(target.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        rel = str(p.relative_to(target))
        if p.suffix in TEXT_EXTS:
            scanned += 1
            tree.append((rel, _file_digest(p)))
            findings += _check_python(p, rel)
        elif p.suffix in TS_EXTS:
            scanned += 1
            tree.append((rel, _file_digest(p)))
            findings += _check_ecmascript(p, rel)
        elif p.suffix in MARKUP_EXTS:
            scanned += 1
            tree.append((rel, _file_digest(p)))
            findings += _check_markup(p, rel)
    rep.files_scanned = scanned
    rep.findings = [asdict(f) for f in findings]
    rep.verdict = "FINDINGS" if findings else "CLEAN"
    rep.subject_digest = _tree_digest(tree)
    rep.subject = [{"name": rep.target, "digest": {"sha3-256": rep.subject_digest}}]
    rep.findings_digest = hashlib.sha3_256(
        reproducible_body(asdict(rep))).hexdigest()
    # ORDER IS LOAD-BEARING. Identity fields are written BEFORE the body is
    # hashed and signed, so they are covered by both. Read from the signer's
    # own `algorithm` property -- never hard-coded, which would mislabel every
    # report from the other signer.
    if signer is not None:
        rep.signature_algorithm = signer.algorithm
        rep.public_root = signer.public_root
    ch, tag = _sign(asdict(rep), covenant_text)
    rep.content_hash = ch
    rep.integrity_tag = tag
    if signer is not None:
        rep.signature = signer.sign(canonical_body(asdict(rep)))
        # Belt and braces: the signature reports its own algorithm, and it must
        # agree with what we just signed. A mismatch means the signer lied
        # about itself, which is a bug, not a report to hand anyone.
        if rep.signature.get("algorithm", rep.signature_algorithm) != rep.signature_algorithm:
            raise SignerError(
                "signer.algorithm disagrees with the algorithm in its own "
                "signature; refusing to issue a report that misnames its scheme")
    return rep


def render_markdown(rep: AuditReport) -> str:
    lines = [
        f"# ENTROVOUCH No-Egress Audit — {rep.verdict}",
        "",
        f"- **Target:** `{rep.target}`",
        f"- **Scanned:** {rep.scanned_at_utc}",
        f"- **Files scanned:** {rep.files_scanned}",
        f"- **Findings:** {len(rep.findings)}",
        # ⚠️ ORDER AND LABELS ARE DELIBERATE. Until 2026-08-21 this block showed
        # `content_hash` ALONE -- the one digest that provably never reproduces,
        # because it covers `scanned_at_utc`. A reader holding only the markdown
        # would naturally compare it, see a mismatch, and conclude the report was
        # forged. That is not hypothetical: it is the defect that was found in
        # the 2026-08-10 outreach pack, fixed in the data model on 2026-08-20,
        # and never carried through to the artifact a human actually reads.
        f"- **Findings digest (reproduces):** `{rep.findings_digest[:32]}…`",
        f"- **Subject digest (binds the code):** `{rep.subject_digest[:32]}…`",
        f"- **Content hash (this issuance only, does NOT reproduce):** "
        f"`{rep.content_hash[:32]}…`",
    ]
    if rep.signature:
        lines += [
            f"- **Signed by:** `{rep.public_root[:32]}…` ({rep.signature_algorithm})",
        ]
        # ⚠️ Only STATEFUL schemes have a one-time index. Printing
        # "One-time key index: None" for ML-DSA (which is stateless, and is the
        # default) invented a concept that does not apply and quietly implied
        # the reader should care about key exhaustion that cannot happen.
        # Found 2026-08-21 by generating the production identity and reading
        # the report it actually produced — not by reading the renderer.
        leaf = rep.signature.get("leaf_index")
        if leaf is not None:
            lines.append(f"- **One-time key index:** {leaf}  "
                         f"(stateful scheme; this leaf is now spent)")
        lines += [
            "",
            "> **How to verify origin:** pin the publisher's root out of band, then "
            "`verify_report(json.load(f), expected_root=<root>)`. A status of "
            "`ATTESTED` means this report came from the holder of that root; "
            "`UNVERIFIED` means you did not pin one and origin is unproven.",
        ]
    else:
        lines += [
            f"- **Signature:** {UNSIGNED}",
            "",
            "> ⚠️ **This report is NOT attested.** The content hash proves the body "
            "matches its own digest; it proves nothing about who produced it, "
            "because anyone can recompute it. Do not rely on this document as "
            "evidence of source.",
        ]
    lines += [
        "",
        "> **How to reproduce this report:** re-run the same tool version "
        "against the same tree and compare **`findings digest`** — it is "
        "bit-identical across runs, processes and machines. Do NOT compare the "
        "content hash: it covers the issuance timestamp and is *expected* to "
        "differ on every run. A different content hash with an identical "
        "findings digest is the same result, issued twice.",
        "",
        f"> **Scope:** {rep.scope_statement}",
        "",
    ]
    if rep.findings:
        lines += ["## Findings", "", "| File | Line | Kind | Detail |", "|---|---|---|---|"]
        for f in rep.findings:
            lines.append(f"| `{f['file']}` | {f['line']} | {f['kind']} | {f['detail']} |")
    else:
        lines.append("**No unauthorized network egress patterns found in scope.**")
    lines += ["", "*ENTROVOUCH — Covenant-attested. For the People.*"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ENTROVOUCH no-egress / sovereign supply-chain auditor")
    ap.add_argument("target", type=Path, nargs="?", help="directory to audit")
    ap.add_argument("--json", type=Path, default=None, help="write JSON report")
    ap.add_argument("--md", type=Path, default=None, help="write markdown report")
    ap.add_argument("--covenant", type=Path, default=None, help="path to Covenant text (else default)")
    ap.add_argument("--key", type=Path, default=None,
                    help="signing identity (see --init-key). WITHOUT THIS THE REPORT IS "
                         "UNSIGNED and attests nothing about its origin.")
    ap.add_argument("--hash-based", action="store_true",
                    help="(the only signer; flag kept for compatibility) Lamport-Merkle. "
                         "Signatures are ~16 KB and the key is STATEFUL "
                         "(one-time leaves that must never be reused).")
    ap.add_argument("--init-key", type=Path, default=None, metavar="PATH",
                    help="create a new signing identity at PATH, print its public root, exit. "
                         "Keep PATH secret; publish only the root.")
    ap.add_argument("--label", default=None,
                    help="identity of the audited subject in the report, e.g. 'org/repo@commit'. "
                         "Defaults to the directory name. The auditor's absolute local path is "
                         "never recorded.")
    args = ap.parse_args(argv)
    try:  # non-ASCII in the markdown must not crash a cp1252 console
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if args.init_key:
        signer = MerkleSigner.create(args.init_key)
        print(f"signing identity written to {args.init_key} (KEEP SECRET)")
        print(f"algorithm: {ALGORITHM}")
        print(f"public root (publish this): {signer.public_root}")
        print("")
        print("BACK THIS FILE UP. It is the only copy of this identity, and it")
        print("cannot be regenerated. Anyone holding it can sign as you; losing")
        print("it means every reader who pinned the root above must re-pin.")
        return 0

    if args.target is None:
        print("error: target directory required (or use --init-key)", file=sys.stderr)
        return 2
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    cov = args.covenant.read_text(encoding="utf-8") if args.covenant else _DEFAULT_COVENANT
    # The keyfile names its own algorithm, so the loader is chosen from the FILE
    signer = MerkleSigner.load(args.key) if args.key else None
    if signer is None:
        print("warning: no --key given; report will be UNSIGNED", file=sys.stderr)
    rep = audit(args.target, cov, label=args.label, signer=signer)
    if args.json:
        args.json.write_text(json.dumps(asdict(rep), indent=2), encoding="utf-8")
    if args.md:
        args.md.write_text(render_markdown(rep), encoding="utf-8")
    print(render_markdown(rep))
    return 0 if rep.verdict == "CLEAN" else 1


if __name__ == "__main__":
    raise SystemExit(main())

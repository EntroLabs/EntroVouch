"""What a report says about itself must be true, and what a tool could not read must be said.

Each test asserts both halves: the false thing is refused or reported, and the true neighbour still passes.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom
from entrovouch.manifests import tree_files
from entrovouch.no_egress_auditor import (
    ReportError, audit, canonical_body, load_report, render_markdown, report_problem, verify_report,
)
from entrovouch.signer import MerkleSigner, SignerError
from entrovouch.timestamp import _der_int, _der_octet, _der_seq, report_digest

REPO = Path(__file__).resolve().parents[1]
PY2 = 'import hashlib\nfrom Crypto.Cipher import DES\nprint "legacy"\nh = hashlib.md5("x")\nSIGNING_KEY = "4f2a9c1e7b3d5f60"\n'


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _cli(module: str, *args, env=None):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=REPO, capture_output=True, text=True, encoding="utf-8", env=env)


def _rehash(d: dict) -> dict:
    d = dict(d)
    d["content_hash"] = hashlib.sha3_256(canonical_body(d)).hexdigest()
    return d


@pytest.fixture
def signer(tmp_path):
    (tmp_path / "keys").mkdir()
    return MerkleSigner.create(tmp_path / "keys" / "k.json", height=4)


# ---------------------------------------------------------------- a file that will not parse is never clean
def test_cbom_lists_a_python_file_it_could_not_parse_and_is_not_clean(tmp_path):
    _write(tmp_path, "legacy.py", PY2)
    rep = cbom.build_cbom(tmp_path, label="t")
    assert rep.verdict == "REVIEW-NEEDED"
    assert [d["file"] for d in rep.files_not_parsed] == ["legacy.py"]
    assert "Files not parsed" in cbom.render_markdown(rep)
    # the neighbour that parses is still inventoried, and outranks the review
    _write(tmp_path, "ok.py", "import hashlib\nhashlib.md5(b'x')\n")
    rep = cbom.build_cbom(tmp_path, label="t")
    assert rep.verdict == "BROKEN-CRYPTO" and [d["file"] for d in rep.files_not_parsed] == ["legacy.py"]


def test_cbom_on_a_tree_that_parses_lists_nothing_unparsed(tmp_path):
    _write(tmp_path, "ok.py", "x = 1\n")
    rep = cbom.build_cbom(tmp_path, label="t")
    assert (rep.verdict, rep.files_not_parsed) == ("NOTHING-VULNERABLE-FOUND", [])


def test_a_binary_file_named_py_is_not_parsed_and_is_said(tmp_path):
    (tmp_path / "blob.py").write_bytes(bytes(range(256)) * 4)
    assert cbom.build_cbom(tmp_path, label="t").verdict == "REVIEW-NEEDED"
    assert key_provenance.scan_key_provenance(tmp_path, label="t").verdict == "REVIEW"


def test_key_provenance_lists_a_python_file_it_could_not_parse(tmp_path):
    _write(tmp_path, "legacy.py", PY2)
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert rep.verdict == "REVIEW" and rep.findings == []
    assert [d["file"] for d in rep.files_not_parsed] == ["legacy.py"]
    r = _cli("key_provenance", tmp_path)
    assert r.returncode == 1 and "Files not parsed" in r.stdout
    # a parsed neighbour's literal key is still found
    _write(tmp_path, "ok.py", 'SIGNING_KEY = "4f2a9c1e7b3d5f60a1b2"\n')
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert [f["file"] for f in rep.findings] == ["ok.py"]


def test_key_provenance_on_a_clean_tree_is_still_nothing_found(tmp_path):
    _write(tmp_path, "ok.py", "x = 1\n")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert (rep.verdict, rep.files_not_parsed) == ("NOTHING-FOUND", [])
    assert _cli("key_provenance", tmp_path).returncode == 0


# ---------------------------------------------------------------- key_provenance command line and report
def test_key_provenance_writes_markdown_and_names_the_target(tmp_path):
    proj = tmp_path / "proj"
    _write(proj, "ok.py", "x = 1\n")
    md = tmp_path / "kp.md"
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "entrovouch.key_provenance", ".", "--md", str(md)],
                       cwd=proj, capture_output=True, text=True, encoding="utf-8", env=dict(os.environ, PYTHONPATH=str(REPO)))
    assert r.returncode == 0, r.stderr
    assert "- **Target:** `proj`" in md.read_text(encoding="utf-8")


def test_key_provenance_survives_a_non_ascii_path_with_redirected_output(tmp_path):
    proj = tmp_path / "my app ünïcödé 日本"
    _write(proj, "k.py", 'SIGNING_KEY = "4f2a9c1e7b3d5f60a1b2"\n')
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "entrovouch.key_provenance", str(proj)],
                       cwd=REPO, capture_output=True, env=env)
    assert r.returncode == 1, r.stderr.decode("utf-8", "replace")


def test_key_provenance_report_carries_a_hash_and_an_edit_is_refused(tmp_path):
    _write(tmp_path / "p", "k.py", 'SIGNING_KEY = "4f2a9c1e7b3d5f60a1b2"\n')
    kp = tmp_path / "kp.json"
    assert _cli("key_provenance", tmp_path / "p", "--json", kp).returncode == 1
    d = json.loads(kp.read_text(encoding="utf-8"))
    assert report_problem(d) is None and d["tool"] == "ENTROVOUCH key-provenance detector"
    c = tmp_path / "c.json"
    _cli("cbom", tmp_path / "p", "--json", c)
    assert _cli("vex", c, "--key-provenance", kp, "--out", tmp_path / "v1.json").returncode == 0
    d["findings"] = []
    kp.write_text(json.dumps(d), encoding="utf-8")
    r = _cli("vex", c, "--key-provenance", kp, "--out", tmp_path / "v2.json")
    assert r.returncode == 2 and not (tmp_path / "v2.json").exists()


def test_a_key_written_twice_in_json_is_reported_at_each_line(tmp_path):
    text = '{\n  "a": {"api_key": "Zq8vK2mN4pR7sT1w"},\n  "pad": 1,\n  "b": {"api_key": "Zq8vK2mN4pR7sT1w"}\n}\n'
    _write(tmp_path, "settings.json", text)
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert sorted(f["line"] for f in rep.findings) == [2, 4]


def test_table_cells_hold_no_line_break_or_bar():
    rep = cbom.CBOM(target="t", components=[{"quantum": "REVIEW", "primitive": "x", "category": "library",
                                              "file": "a.py", "line": 1, "detail": "one\ntwo|three"}])
    row = [ln for ln in cbom.render_markdown(rep).splitlines() if ln.startswith("| REVIEW")]
    assert row == ["| REVIEW | x | library | `a.py` | 1 | one two\\|three |"]


# ---------------------------------------------------------------- links and junctions are not followed
def _junction(link: Path, target: Path) -> None:
    from _junction import make_junction
    if not make_junction(link, target):
        pytest.skip("could not create a junction here")


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows feature")
def test_a_junction_loop_is_counted_and_not_followed(tmp_path):
    proj = tmp_path / "proj"
    _write(proj, "a.py", "x = 1\n")
    _write(tmp_path / "outside", "secret.py", "import requests\n")
    (proj / "sub").mkdir()
    _junction(proj / "loop", proj)
    _junction(proj / "sub" / "up", proj)
    _junction(proj / "out", tmp_path / "outside")
    start = time.monotonic()
    walk = tree_files(proj)
    assert time.monotonic() - start < 10
    assert [r for r, _ in walk.files] == ["a.py"] and walk.symlinks == 3
    rep = audit(proj, label="t")
    assert (rep.verdict, rep.files_scanned, rep.files_not_read) == ("CLEAN", 1, 3)
    assert cbom.build_cbom(proj, label="t").files_scanned == 1


def test_a_directory_symlink_loop_is_counted_and_not_followed(tmp_path):
    proj = tmp_path / "proj"
    _write(proj, "a.py", "x = 1\n")
    try:
        os.symlink(proj, proj / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no right to create a symbolic link here")
    walk = tree_files(proj)
    assert [r for r, _ in walk.files] == ["a.py"] and walk.symlinks == 1


# ---------------------------------------------------------------- the body names the signer that signed it
def _forged_identity(tmp_path, attacker, victim_root):
    _write(tmp_path / "p", "a.py", "import socket\n")
    rep = audit(tmp_path / "p", label="t")
    rep.signature_algorithm = attacker.algorithm
    rep.public_root = victim_root
    d = _rehash(asdict(rep))
    d["signature"] = attacker.sign(canonical_body(d))
    return d


def test_a_signature_from_another_key_than_the_body_names_is_tampered(tmp_path, signer):
    (tmp_path / "v").mkdir()
    victim = MerkleSigner.create(tmp_path / "v" / "k.json", height=4)
    d = _forged_identity(tmp_path, signer, victim.public_root)
    assert verify_report(d) == (False, "TAMPERED")
    assert verify_report(d, expected_root=victim.public_root) == (False, "TAMPERED")
    assert verify_report(d, expected_root=signer.public_root) == (False, "TAMPERED")
    p = tmp_path / "f.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    assert _cli("attestation", p).returncode == 2
    # the honest report from the same key verifies
    good = asdict(audit(tmp_path / "p", signer=signer, label="t"))
    assert verify_report(good, expected_root=signer.public_root) == (True, "ATTESTED")


def test_a_report_of_another_kind_is_not_this_kind(tmp_path, signer):
    _write(tmp_path / "p", "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    c = asdict(cbom.build_cbom(tmp_path / "p", signer=signer, label="t"))
    assert verify_report(c, expected_root=signer.public_root) == (False, "TAMPERED")
    assert cbom.verify_cbom(c, expected_root=signer.public_root) == (True, "ATTESTED")
    _write(tmp_path / "p", "requirements.txt", "requests==2.31.0\n")
    s = asdict(sbom.build_sbom(tmp_path / "p", signer=signer, label="t"))
    assert sbom.verify_sbom(s, expected_root=signer.public_root) == (True, "ATTESTED")
    assert cbom.verify_cbom(s, expected_root=signer.public_root) == (False, "TAMPERED")


def test_removing_the_signature_from_a_signed_report_is_tampered(tmp_path, signer):
    _write(tmp_path / "p", "a.py", "import socket\n")
    d = asdict(audit(tmp_path / "p", signer=signer, label="t"))
    d["signature"] = None
    assert verify_report(_rehash(d)) == (False, "TAMPERED")
    assert report_problem(_rehash(d)) is not None
    unsigned = asdict(audit(tmp_path / "p", label="t"))
    assert verify_report(unsigned) == (False, "UNSIGNED") and report_problem(unsigned) is None


def test_an_edited_and_rehashed_signed_report_is_refused_by_every_adapter(tmp_path, signer):
    _write(tmp_path / "p", "a.py", "import socket\nsocket.create_connection(('evil.example', 80))\n")
    d = asdict(audit(tmp_path / "p", signer=signer, label="t"))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(d), encoding="utf-8")
    d["verdict"], d["findings"] = "CLEAN", []
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(_rehash(d)), encoding="utf-8")
    for module, extra in (("sarif", []), ("attestation", []), ("timestamp", ["request"])):
        out_good, out_bad = tmp_path / f"{module}_g", tmp_path / f"{module}_b"
        assert _cli(module, *extra, good, "--out", out_good).returncode == 0, module
        r = _cli(module, *extra, bad, "--out", out_bad)
        # refused: the findings digest no longer describes the findings, and the signature no longer verifies
        assert r.returncode == 2 and ("signature" in r.stderr or "findings_digest" in r.stderr) \
            and not out_bad.exists(), module


# ---------------------------------------------------------------- the JSON itself
def test_a_key_given_twice_is_refused(tmp_path):
    _write(tmp_path / "p", "a.py", "import socket\n")
    d = asdict(audit(tmp_path / "p", label="t"))
    text = json.dumps(d)
    dup = text[:-1] + ', "verdict": "CLEAN"}'
    p = tmp_path / "dup.json"
    p.write_text(dup, encoding="utf-8")
    with pytest.raises(ReportError, match="twice"):
        load_report(p)
    assert _cli("sarif", p, "--out", tmp_path / "s.json").returncode == 2
    p.write_text(text, encoding="utf-8")
    assert load_report(p)["verdict"] == "FINDINGS"


def test_deep_nesting_is_refused_not_a_crash(tmp_path):
    p = tmp_path / "deep.json"
    p.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    with pytest.raises(ReportError):
        load_report(p)
    r = _cli("attestation", p)
    assert r.returncode == 2 and "Traceback" not in r.stderr


def test_not_a_number_cannot_enter_a_report():
    with pytest.raises(ValueError):
        canonical_body({"findings": [{"line": float("nan")}]})
    assert report_problem({"content_hash": "x", "line": float("nan")}) is not None


# ---------------------------------------------------------------- the one-time key
def test_a_signing_state_with_two_names_is_refused(tmp_path, signer):
    second = tmp_path / "keys" / "alias.json"
    try:
        os.link(signer.path, second)
    except (OSError, NotImplementedError):
        pytest.skip("no hard links here")
    with pytest.raises(SignerError, match="more than one name"):
        signer.sign(b"x")
    os.unlink(second)
    assert signer.sign(b"x")["leaf_index"] == 0


# ---------------------------------------------------------------- the PEM search stays linear
def test_blank_lines_do_not_make_the_armour_search_slow(tmp_path):
    from entrovouch._pem import armour_with_key
    import re
    armour = re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")
    text = "-----BEGIN RSA PRIVATE KEY-----\n" + " + KEYBODY\n" + "\n" * 40000
    start = time.monotonic()
    assert armour_with_key(text, armour) is None
    assert time.monotonic() - start < 2
    joined = 'KEYBODY = "' + "A" * 64 + '"\nx = "-----BEGIN RSA PRIVATE KEY-----\\n" + KEYBODY\n'
    assert armour_with_key(joined, armour) is not None


# ---------------------------------------------------------------- the timestamp nonce
def test_the_timestamp_check_requires_the_nonce_it_is_given(tmp_path):
    _write(tmp_path / "p", "a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    assert _cli("no_egress_auditor", tmp_path / "p", "--json", rep).returncode == 0
    digest = report_digest(rep)
    token = tmp_path / "t.tsr"
    token.write_bytes(_der_seq(_der_octet(digest), _der_int(123456789)))
    assert _cli("timestamp", "check", rep, "--token", token, "--nonce", 123456789).returncode == 0
    r = _cli("timestamp", "check", rep, "--token", token, "--nonce", 987654321)
    assert r.returncode == 1 and "does NOT echo the nonce" in r.stdout
    r = _cli("timestamp", "check", rep, "--token", token)
    assert r.returncode == 0 and "nonce was not checked" in r.stdout


# ---------------------------------------------------------------- smaller statements made true
def test_a_file_that_only_holds_the_digest_is_not_a_timestamp(tmp_path):
    _write(tmp_path / "p", "a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    fake = tmp_path / "fake.tsr"
    fake.write_bytes(b"hash:" + report_digest(rep))
    r = _cli("timestamp", "check", rep, "--token", fake)
    assert r.returncode == 1 and "not a timestamp response" in r.stdout


@pytest.mark.parametrize("line,kind", [
    ("ADD https://example.com/tool.tar.gz /opt/", "script-network-command"),
    ("ADD --chmod=644 https://example.com/f /f", "script-network-command"),
    ('ADD ["https://example.com/f", "/f"]', "script-network-command"),
    ("ADD git@github.com:org/repo.git /src", "script-network-command"),
    ("ADD http://localhost:8000/f /f", "loopback-call"),
])
def test_a_dockerfile_add_of_an_address_is_a_download(tmp_path, line, kind):
    _write(tmp_path, "Dockerfile", f"FROM scratch\n{line}\n")
    rep = audit(tmp_path, label="t")
    assert [(f["kind"], f["line"]) for f in asdict(rep)["findings"]] == [(kind, 2)]


def test_a_dockerfile_add_of_a_local_path_is_not_reported(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM scratch\nADD app.tar.gz /opt/\nCOPY . /src\n")
    assert audit(tmp_path, label="t").verdict == "CLEAN"


def test_a_temporary_copy_left_by_a_killed_writer_is_removed(tmp_path, signer):
    stale = signer.path.parent / (signer.path.name + ".abcd1234.tmp")
    stale.write_text("seed", encoding="utf-8")
    other = signer.path.parent / "unrelated.tmp"
    other.write_text("keep", encoding="utf-8")
    signer.sign(b"x")
    assert not stale.exists() and other.exists()


def test_markdown_prints_whole_digests(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    rep = audit(tmp_path, label="t")
    md = render_markdown(rep)
    assert rep.findings_digest in md and rep.subject_digest in md


def test_warnings_as_errors_do_not_stop_a_run(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    for module in ("no_egress_auditor", "cbom", "key_provenance", "sbom"):
        r = subprocess.run([sys.executable, "-W", "error", "-m", f"entrovouch.{module}", str(tmp_path)],
                           cwd=REPO, capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 0 and "Traceback" not in r.stderr, (module, r.stderr)


def test_a_requirement_from_a_repository_gets_no_index_package_url(tmp_path):
    _write(tmp_path, "requirements.txt",
           "-e git+https://git.example.com/org/internal-lib.git#egg=internal-lib\n"
           "requests==2.31.0  # pinned for reasons\n"
           "tool @ https://files.example.com/tool-1.0.whl\n")
    comps = {c["name"]: c for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert comps["internal-lib"]["purl"] == "" and comps["tool"]["purl"] == ""
    assert comps["requests"]["purl"] == "pkg:pypi/requests@2.31.0"
    assert comps["requests"]["spec"] == "requests==2.31.0"
    assert comps["internal-lib"]["spec"].endswith("#egg=internal-lib")
    cdx = sbom.to_cyclonedx(asdict(sbom.build_sbom(tmp_path, label="t")))
    by_name = {c["name"]: c for c in cdx["components"]}
    assert "purl" not in by_name["internal-lib"] and by_name["requests"]["purl"] == "pkg:pypi/requests@2.31.0"


def test_the_verify_command_states_each_status(tmp_path, signer):
    _write(tmp_path / "p", "a.py", "import socket\n")
    signed, unsigned = tmp_path / "s.json", tmp_path / "u.json"
    signed.write_text(json.dumps(asdict(audit(tmp_path / "p", signer=signer, label="t"))), encoding="utf-8")
    unsigned.write_text(json.dumps(asdict(audit(tmp_path / "p", label="t"))), encoding="utf-8")
    r = _cli("verify", signed, "--root", signer.public_root)
    assert r.returncode == 0 and "status : ATTESTED" in r.stdout
    assert "status : UNVERIFIED" in _cli("verify", signed).stdout
    assert "status : TAMPERED" in _cli("verify", signed, "--root", "ab" * 32).stdout
    assert "status : UNSIGNED" in _cli("verify", unsigned).stdout
    d = json.loads(signed.read_text(encoding="utf-8"))
    d["verdict"] = "CLEAN"
    signed.write_text(json.dumps(_rehash(d)), encoding="utf-8")
    r = _cli("verify", signed, "--root", signer.public_root)
    assert r.returncode == 1 and "status : TAMPERED" in r.stdout
    c = tmp_path / "c.json"
    c.write_text(json.dumps(asdict(cbom.build_cbom(tmp_path / "p", signer=signer, label="t"))), encoding="utf-8")
    assert "status : ATTESTED" in _cli("verify", c, "--root", signer.public_root).stdout
    (tmp_path / "x.json").write_text("[1]", encoding="utf-8")
    assert _cli("verify", tmp_path / "x.json").returncode == 2

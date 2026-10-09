"""Each converter takes one kind of report, each run reads one version of each file, and a file counted as a link
can hide nothing. Each test asserts both halves: the false thing is refused, the true neighbour still passes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import _reads, cbom, key_provenance, sbom
from entrovouch.no_egress_auditor import (
    ReportError, audit, load_report, markdown_cell, markdown_code, render_markdown, strict_json_loads,
    verify_report,
)
from entrovouch.signer import MerkleSigner
from entrovouch.timestamp import _der_int, _der_octet, _der_seq, report_digest

REPO = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _cli(module: str, *args):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=REPO, capture_output=True, text=True, encoding="utf-8")


@pytest.fixture
def signer(tmp_path):
    (tmp_path / "keys").mkdir()
    return MerkleSigner.create(tmp_path / "keys" / "k.json", height=4)


# ---------------------------------------------------------------- a file counted as a link hides nothing
def test_code_that_names_a_sibling_file_is_read_not_counted_as_a_link(tmp_path):
    payload = "__import__('socket').create_connection(('203.0.113.9',80))"
    (tmp_path / "app.py").write_text(payload, encoding="utf-8")
    try:
        (tmp_path / payload).write_text("x", encoding="utf-8")
    except OSError:
        pytest.skip("this file system does not allow that name")
    _write(tmp_path, "main.py", "print(1)\n")
    rep = audit(tmp_path, label="t")
    assert rep.verdict == "FINDINGS" and "app.py" in {f["file"] for f in rep.findings}
    assert rep.not_scanned["symbolic_links"] == 0


def test_a_link_checked_out_as_text_is_still_counted_as_a_link(tmp_path):
    _write(tmp_path, "app/config.py", "import requests\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "config.py").write_text("../app/config.py", encoding="utf-8")
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["symbolic_links"] == 1
    assert {f["file"] for f in rep.findings} == {"app/config.py"}


# ---------------------------------------------------------------- one version of each file per run
SHELL = "#!/bin/sh\necho hello\n"
PY_NET = "#!/usr/bin/env python\nimport socket\nsocket.create_connection(('203.0.113.9', 80))\n"
PTH_NET = "import socket; socket.create_connection(('203.0.113.9', 80))\n"

# (file name, first version, second version): each pair changes what kind of file it is, or what it holds
RACES = [
    ("tool", (SHELL + "# pad\n" * 300).encode(), (PY_NET + "# pad\n" * 300).encode()),  # shell becomes Python
    ("small", SHELL.encode(), PY_NET.encode()),                                 # the same, under 1 KB
    ("x.pth", bytes(range(256)) * 8, PTH_NET.encode()),                         # a binary .pth becomes start-up code
    ("m.pyc", b"\x00\x01\x02" * 700, PY_NET.encode()),                          # an artifact becomes text
    ("a.py", b"x = 1\n" * 300, PY_NET.encode() * 30),                           # source changes
    ("requirements.txt", b"attrs==23.1.0\n" * 100, b"requests==2.31.0\n" * 100),  # a manifest changes
    ("notes.html", b"<p>hello</p>\n" * 200, b'<script src="https://cdn.example/x.js"></script>\n' * 50),
]


def _tree(root: Path, name: str, data: bytes) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "clean.py").write_text("x = 1\n", encoding="utf-8")
    f = root / name
    f.write_bytes(data)
    return f


@pytest.mark.parametrize("build", ["audit", "cbom", "sbom"])
@pytest.mark.parametrize("name,first,second", RACES, ids=[r[0] for r in RACES])
def test_a_rewrite_at_any_read_gives_one_version_or_stops_the_run(tmp_path, monkeypatch, build, name, first, second):
    """Rewrite the file just before its k-th read, for every k the run makes. Before the first read the run describes
    the new version exactly or stops; before any later read it stops. Never a report of two versions."""
    run = {"audit": lambda t: audit(t, label="t").findings_digest,
           "cbom": lambda t: cbom.build_cbom(t, label="t").findings_digest,
           "sbom": lambda t: sbom.build_sbom(t, label="t").findings_digest}[build]
    expected_new = run(_tree(tmp_path / "new", name, second).parent)
    real = _reads._read
    k = 1
    while True:
        target = _tree(tmp_path / f"r{k}", name, first)
        calls = {"n": 0}

        def rewriting(path, target=target, calls=calls, k=k):
            if Path(path).name == name:
                calls["n"] += 1
                if calls["n"] == k:
                    target.write_bytes(second)
            return real(path)
        monkeypatch.setattr(_reads, "_read", rewriting)
        try:
            got = run(target.parent)
        except _reads.FileChangedDuringRun:
            got = "stopped"
        finally:
            monkeypatch.setattr(_reads, "_read", real)
        if calls["n"] < k:
            break                                   # the run read the file fewer than k times: every k is done
        # before the first read: the new version, or a stop when the walk already judged the file by its size;
        # before any later read: a stop. Never a report of two versions.
        assert got in ((expected_new, "stopped") if k == 1 else ("stopped",)), (build, name, k, got)
        k += 1
    if build == "audit":
        assert k > 1                                # the auditor reads every one of these files


def test_a_changed_file_stops_the_command_with_exit_2(tmp_path):
    f = _write(tmp_path, "a.py", "x = 1\n")
    other = _write(tmp_path, "b.py", "y = 2\n")
    with _reads.one_read_per_file():
        data = _reads.read_bytes(f)
        _reads.read_bytes(other)
        assert _reads.read_bytes(f) == data          # unchanged: read again from disk and checked
        f.write_text("import socket\n", encoding="utf-8")
        _reads.read_bytes(other)
        with pytest.raises(_reads.FileChangedDuringRun):
            _reads.read_bytes(f)


def test_a_run_keeps_a_hash_per_file_not_the_file(tmp_path):
    f = _write(tmp_path, "a.py", "x = 1\n" * 10000)
    with _reads.one_read_per_file():
        _reads.read_bytes(f)
        held = list(_reads._SEEN.get().values())
        assert held and all(isinstance(h, bytes) and len(h) == 32 for h in held)


# ---------------------------------------------------------------- each converter takes one kind of report
@pytest.fixture
def reports(tmp_path, signer):
    _write(tmp_path / "p", "a.py", "import hashlib\nimport requests\nhashlib.md5(b'x')\nSIGNING_KEY = 'q8vK2mN4pR7sT1w9'\n")
    _write(tmp_path / "p", "requirements.txt", "requests==2.31.0\n")
    out = {}
    for name, rep in (("egress", audit(tmp_path / "p", signer=signer, label="t")),
                      ("cbom", cbom.build_cbom(tmp_path / "p", signer=signer, label="t")),
                      ("sbom", sbom.build_sbom(tmp_path / "p", signer=signer, label="t")),
                      ("kp", key_provenance.scan_key_provenance(tmp_path / "p", label="t"))):
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(asdict(rep)), encoding="utf-8")
        out[name] = p
    return out


@pytest.mark.parametrize("module,right,wrong", [
    ("sarif", "egress", "cbom"), ("attestation", "egress", "cbom"), ("cyclonedx", "cbom", "sbom"),
    ("vex", "cbom", "egress"), ("csaf", "cbom", "egress"),
])
def test_a_converter_refuses_a_report_of_another_kind(tmp_path, reports, module, right, wrong):
    extra = ["--publisher-name", "X", "--publisher-namespace", "https://x.example"] if module == "csaf" else []
    assert _cli(module, reports[right], "--out", tmp_path / "ok.json", *extra).returncode == 0
    r = _cli(module, reports[wrong], "--out", tmp_path / "no.json", *extra)
    assert r.returncode == 2 and "not a report from" in r.stderr and not (tmp_path / "no.json").exists()


def test_key_provenance_input_must_be_a_key_provenance_report(tmp_path, reports):
    for module in ("vex", "csaf"):
        extra = ["--publisher-name", "X", "--publisher-namespace", "https://x.example"] if module == "csaf" else []
        assert _cli(module, reports["cbom"], "--key-provenance", reports["kp"], "--out", tmp_path / "a.json",
                    *extra).returncode == 0
        r = _cli(module, reports["cbom"], "--key-provenance", reports["egress"], "--out", tmp_path / "b.json", *extra)
        assert r.returncode == 2 and not (tmp_path / "b.json").exists()


def test_a_key_provenance_report_that_names_no_tool_is_refused(tmp_path, reports):
    d = json.loads(reports["kp"].read_text(encoding="utf-8"))
    for k in ("tool", "tool_version", "content_hash", "files_not_parsed"):
        d.pop(k)
    old = tmp_path / "old_kp.json"
    old.write_text(json.dumps(d), encoding="utf-8")
    r = _cli("vex", reports["cbom"], "--key-provenance", old, "--out", tmp_path / "v.json")
    assert r.returncode == 2 and "run key_provenance again" in r.stderr and not (tmp_path / "v.json").exists()


def test_a_named_key_provenance_file_that_is_missing_is_an_error(tmp_path, reports):
    for module in ("vex", "csaf"):
        extra = ["--publisher-name", "X", "--publisher-namespace", "https://x.example"] if module == "csaf" else []
        r = _cli(module, reports["cbom"], "--key-provenance", tmp_path / "nope.json", "--out", tmp_path / "o.json",
                 *extra)
        assert r.returncode == 2 and not (tmp_path / "o.json").exists(), module


def test_a_report_with_its_content_hash_removed_is_refused(tmp_path, reports):
    d = json.loads(reports["kp"].read_text(encoding="utf-8"))
    d.pop("content_hash")
    d["findings"] = []
    bad = tmp_path / "kp_nohash.json"
    bad.write_text(json.dumps(d), encoding="utf-8")
    r = _cli("vex", reports["cbom"], "--key-provenance", bad, "--out", tmp_path / "v.json")
    assert r.returncode == 2 and "no content hash" in r.stderr


# ---------------------------------------------------------------- verify
def test_verify_takes_a_root_in_either_case_and_refuses_one_that_is_not_a_root(reports, signer):
    root = signer.public_root
    for given in (root, root.upper(), f"  {root} "):
        r = _cli("verify", reports["egress"], "--root", given)
        assert r.returncode == 0 and "status : ATTESTED" in r.stdout, given
    d = json.loads(reports["egress"].read_text(encoding="utf-8"))
    assert verify_report(d, expected_root=root.upper()) == (True, "ATTESTED")
    r = _cli("verify", reports["egress"], "--root", "ZZ")
    assert r.returncode == 2 and "not a public root" in r.stderr
    assert "status : TAMPERED" in _cli("verify", reports["egress"], "--root", "ab" * 32).stdout


def test_verify_answers_a_tool_field_that_is_not_text(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"tool": ["x"]}', encoding="utf-8")
    r = _cli("verify", p)
    assert r.returncode == 2 and "did not complete" not in r.stderr


# ---------------------------------------------------------------- the one-time key
def test_stale_temporary_copies_are_matched_by_shape_not_by_pattern(tmp_path):
    (tmp_path / "k").mkdir()
    s = MerkleSigner.create(tmp_path / "k" / "k[12].json", height=4)
    own = tmp_path / "k" / "k[12].json.abcd1234.tmp"
    others = [tmp_path / "k" / "k1.json.abcd1234.tmp", tmp_path / "k" / "k2.json.zzzzzzzz.tmp",
              tmp_path / "k" / "k[12].json.notmine.tmp", tmp_path / "k" / "k[12].json.other.abcd1234.tmp"]
    for f in [own, *others]:
        f.write_text("seed", encoding="utf-8")
    s.sign(b"hello")
    assert not own.exists() and all(f.exists() for f in others)


# ---------------------------------------------------------------- key provenance in large JSON
def test_json_line_numbers_stay_fast_on_a_large_file(tmp_path):
    entries = ",\n".join(f'  "e{i}": {{"password": "Zq8vK2mN4pR7sT1w"}}' for i in range(6000))
    _write(tmp_path, "settings.json", "{\n" + entries + "\n}\n")
    start = time.monotonic()
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert time.monotonic() - start < 10
    assert sorted(f["line"] for f in rep.findings) == list(range(2, 6002))


# ---------------------------------------------------------------- SBOM
def test_a_requirement_from_a_local_file_gets_no_index_package_url(tmp_path):
    _write(tmp_path, "requirements.txt", "pkg @ file:///opt/wheels/pkg-1.0.whl\nother @ file:../local\nrequests==2.31.0\n")
    comps = {c["name"]: c for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert comps["pkg"]["purl"] == "" and comps["other"]["purl"] == ""
    assert comps["requests"]["purl"] == "pkg:pypi/requests@2.31.0"


def test_markdown_rows_survive_a_bar_in_a_value(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"foo": "^1.0.0 || ^2.0.0"}}')
    md = sbom.render_markdown(sbom.build_sbom(tmp_path, label="t"))
    row = [ln for ln in md.splitlines() if ln.startswith("| `foo`")][0]
    assert "^1.0.0 \\|\\| ^2.0.0" in row
    assert markdown_cell("a|b\nc") == "a\\|b c"


# ---------------------------------------------------------------- Dockerfile instructions in any case
@pytest.mark.parametrize("line", [
    "add https://example.com/f /f", "Add https://example.com/f /f", "ONBUILD ADD https://example.com/f /f",
    "onbuild add https://example.com/f /f", "run curl -fsSL https://example.com/x", "ADD \\\n  https://example.com/f /f",
])
def test_dockerfile_instructions_are_read_in_any_case(tmp_path, line):
    _write(tmp_path, "Dockerfile", f"FROM scratch\n{line}\n")
    kinds = {f["kind"] for f in audit(tmp_path, label="t").findings}
    assert kinds == {"script-network-command"}, kinds


def test_a_lower_case_dockerfile_copy_is_still_not_a_download(tmp_path):
    _write(tmp_path, "Dockerfile", "from scratch\nadd app.tar.gz /opt/\ncopy . /src\nrun make\n")
    assert audit(tmp_path, label="t").verdict == "CLEAN"


# ---------------------------------------------------------------- the timestamp nonce
def test_the_nonce_must_follow_the_imprint(tmp_path):
    _write(tmp_path / "p", "a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    digest = report_digest(rep)
    token = tmp_path / "t.tsr"
    # shaped as a response: a status first (a SEQUENCE), then the imprint
    token.write_bytes(_der_seq(_der_seq(_der_int(0)), _der_octet(digest)))     # no nonce
    r = _cli("timestamp", "check", rep, "--token", token, "--nonce", 1)
    assert r.returncode == 1 and "does NOT echo the nonce" in r.stdout
    token.write_bytes(_der_seq(_der_seq(_der_int(0)), _der_octet(digest), _der_int(77)))
    assert _cli("timestamp", "check", rep, "--token", token, "--nonce", 77).returncode == 0
    r = _cli("timestamp", "check", rep, "--token", token, "--nonce", -5)
    assert r.returncode == 2 and "did not complete" not in r.stderr


# ---------------------------------------------------------------- small statements
def test_init_key_under_a_file_says_so(tmp_path):
    (tmp_path / "f.txt").write_text("x", encoding="utf-8")
    r = _cli("no_egress_auditor", "--init-key", tmp_path / "f.txt" / "k.json")
    assert r.returncode == 2 and "is a file, not a folder" in r.stderr


def test_a_number_too_large_for_a_float_is_not_json_this_tool_reads(tmp_path):
    with pytest.raises(ValueError):
        strict_json_loads('{"line": 1e999}')
    assert strict_json_loads('{"line": 1.5e3}') == {"line": 1500.0}
    p = tmp_path / "r.json"
    p.write_text('{"line": 1e999}', encoding="utf-8")
    with pytest.raises(ReportError):
        load_report(p)


# ---------------------------------------------------------------- manifests: a bare word is a declaration
def test_a_one_word_requirements_file_is_a_declaration_not_a_link(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests", encoding="utf-8")      # no line break
    (tmp_path / "requests").mkdir()
    _write(tmp_path, "app.py", "x = 1\n")
    rep = audit(tmp_path, label="t")
    assert "declared-network-dependency" in {f["kind"] for f in rep.findings}
    assert rep.not_scanned["symbolic_links"] == 0
    assert [c["name"] for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]] == ["requests"]


def test_a_requirements_link_checked_out_as_text_is_still_a_link(tmp_path):
    _write(tmp_path, "requirements/base.txt", "requests==2.31.0\n")
    (tmp_path / "requirements.txt").write_text("requirements/base.txt", encoding="utf-8")
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["symbolic_links"] == 1
    comps = asdict(sbom.build_sbom(tmp_path, label="t"))["components"]
    assert [(c["name"], c["file"]) for c in comps] == [("requests", "requirements/base.txt")]


def test_an_include_is_followed_only_to_a_file_the_walk_reads(tmp_path):
    _write(tmp_path, "base.txt", "attrs==23.1.0\n")
    _write(tmp_path, "venv/inside.txt", "requests==2.31.0\n")
    (tmp_path / "linked.txt").write_text("base.txt", encoding="utf-8")        # a link stand-in
    _write(tmp_path, "requirements.txt", "-r base.txt\n-r venv/inside.txt\n-r linked.txt\n-r ../outside.txt\n")
    scan = sbom.build_sbom(tmp_path, label="t")
    assert sorted(c["name"] for c in asdict(scan)["components"]) == ["attrs"]
    not_read = [u for u in scan.unknown_fields if "was not read" in u]
    assert not_read and all(x in not_read[0] for x in ("venv/inside.txt", "linked.txt", "../outside.txt"))


def test_a_requirement_written_as_a_path_names_no_package(tmp_path):
    from entrovouch.manifests import requirement_name
    assert requirement_name("libs/pkg") is None and requirement_name("requirements/base.txt") is None
    assert requirement_name("requests>=2") == "requests" and requirement_name("pkg @ https://h/x.whl") == "pkg"
    # a pip-compile line continued onto its hashes is still the requirement it names
    assert requirement_name("requests==2.31.0 \\") == "requests"
    assert requirement_name("urllib3==2.0.7 ; python_version >= '3.8' \\") == "urllib3"


# ---------------------------------------------------------------- timestamp: a JSON report must be one exactly
def test_timestamp_refuses_a_report_that_is_not_strict_json(tmp_path):
    _write(tmp_path / "p", "a.py", "import requests\n")
    rep = tmp_path / "r.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    good = rep.read_bytes()
    edited = json.loads(good)
    edited["verdict"], edited["findings"] = "CLEAN", []
    cases = {
        "bom": b"\xef\xbb\xbf" + json.dumps(edited).encode(),
        "twice": good.rstrip()[:-1] + b', "verdict": "CLEAN"}',
        "trailing": json.dumps(edited).encode() + b"\n}junk",
    }
    for name, data in cases.items():
        f = tmp_path / f"{name}.json"
        f.write_bytes(data)
        r = _cli("timestamp", "request", f, "--out", tmp_path / f"{name}.tsq")
        assert r.returncode == 2 and not (tmp_path / f"{name}.tsq").exists(), name
    assert _cli("timestamp", "request", rep, "--out", tmp_path / "ok.tsq").returncode == 0
    # an intact report behind a byte-order mark is refused, as `verify` and every converter refuse it
    bom_intact = tmp_path / "bom_intact.json"
    bom_intact.write_bytes(b"\xef\xbb\xbf" + good)
    r = _cli("timestamp", "request", bom_intact, "--out", tmp_path / "ok2.tsq")
    assert r.returncode == 2 and "byte-order mark" in r.stderr
    other = tmp_path / "notes.txt"
    other.write_text("not a report at all", encoding="utf-8")
    assert _cli("timestamp", "request", other, "--out", tmp_path / "ok3.tsq").returncode == 0


# ---------------------------------------------------------------- npm: only the registry gets a registry purl
def test_npm_dependencies_not_from_the_registry_get_no_purl_and_no_version(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {
        "k": "file:../k", "n": "git+https://x.example/n.git", "p": "https://x.example/p.tgz", "m": "github:u/m",
        "l": "link:../l", "o": "npm:other@1.2.3", "s": "u/repo", "w": "workspace:*", "r": "1.2.3",
        "@scope/q": "4.5.6"}}))
    comps = {c["name"]: c for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    for name in ("k", "n", "p", "m", "l", "o", "s", "w"):
        assert comps[name]["purl"] == "" and comps[name]["version_status"] == "unknown", name
    assert comps["r"]["purl"] == "pkg:npm/r@1.2.3" and comps["r"]["version_status"] == "pinned"
    assert comps["@scope/q"]["purl"] == "pkg:npm/%40scope/q@4.5.6"


# ---------------------------------------------------------------- HEALTHCHECK runs its command
def test_a_healthcheck_command_is_read_as_a_command(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM scratch\nHEALTHCHECK --interval=30s CMD curl -f https://example.com/up\n"
                                   "HEALTHCHECK CMD curl -f http://localhost:8000/up\nHEALTHCHECK NONE\n")
    kinds = [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings]
    assert kinds == [(2, "script-network-command"), (3, "loopback-call")]


# ---------------------------------------------------------------- markdown cannot be injected through the tree
def test_text_from_the_tree_cannot_become_markup_in_a_report(tmp_path):
    _write(tmp_path, "a.pth", "import x; '![t](https://tracker.example/q.png) <img src=https://tracker.example/r.png>'\n")
    md = render_markdown(audit(tmp_path, label="t"))
    import re
    assert not re.search(r"(?<!\\)!\[", md) and not re.search(r"(?<!\\)<img", md)
    assert "\\<img" in md                                 # still shown, as text
    _write(tmp_path / "s", "package.json", json.dumps({"dependencies": {"left-pad`<img src=x>": "1.0.0"}}))
    smd = sbom.render_markdown(sbom.build_sbom(tmp_path / "s", label="t"))
    row = [ln for ln in smd.splitlines() if ln.startswith("| ``")][0]
    assert row.startswith("| `` left-pad`<img src=x> `` |")
    assert markdown_code("plain") == "`plain`" and markdown_cell("a_b") == "a\\_b"

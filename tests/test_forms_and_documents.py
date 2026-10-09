"""Every form of Python each scanner reads, the commands scripts are written with, and documents that say only
what holds. Each test asserts both halves: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tracemalloc
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import _reads, cbom, key_provenance, sbom
from entrovouch.no_egress_auditor import audit
from entrovouch.signer import MerkleSigner

REPO = Path(__file__).resolve().parents[1]
B = chr(92)


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _kinds(root: Path) -> set[str]:
    return {f["kind"] for f in audit(root, label="t").findings}


def _cli(module: str, *args, cwd=REPO):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                          env=dict(os.environ, PYTHONPATH=str(REPO)))


def _notebook(*cells: str) -> str:
    return json.dumps({"cells": [{"cell_type": "code", "source": [c]} for c in cells],
                       "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


# ---------------------------------------------------------------- one folder, one report, however it is typed
def test_the_same_folder_typed_in_another_case_gives_one_report(tmp_path):
    proj = tmp_path / "requests"
    _write(proj, "__init__.py", "")
    _write(proj, "x.py", "import requests\n")
    upper = tmp_path / "REQUESTS"
    if not upper.exists():
        pytest.skip("this file system tells case apart")
    a, b = audit(proj, label="same"), audit(upper, label="same")
    assert (a.verdict, a.findings_digest) == (b.verdict, b.findings_digest)
    assert a.verdict == "CLEAN" and "requests" in a.shadowed_imports


def test_the_stored_name_comes_from_the_folder_listing_not_from_resolve(tmp_path):
    """macOS's `resolve` keeps the case that was typed, so the stored name is read from the parent's listing. Called on
    the typed path here, unresolved, so the listing does the work on every system that ignores case."""
    from entrovouch.no_egress_auditor import _stored_name
    (tmp_path / "requests").mkdir()
    typed = tmp_path / "REQUESTS"
    if not typed.exists():
        pytest.skip("this file system tells case apart")
    assert _stored_name(typed) == "requests"
    assert _stored_name(tmp_path / "requests") == "requests"


def test_a_name_that_is_not_there_is_kept_as_typed(tmp_path):
    from entrovouch.no_egress_auditor import _stored_name
    (tmp_path / "requests").mkdir()
    assert _stored_name(tmp_path / "other") == "other"


# ---------------------------------------------------------------- cbom: only its own bytes are its own source
CRYPTO = 'import jwt\nALG = "TripleDES"\njwt.encode({}, "k", algorithm="RS256")\n'


def test_a_file_named_cbom_py_in_another_tree_is_inventoried(tmp_path):
    _write(tmp_path / "a", "vendor/lib/cbom.py", CRYPTO)
    _write(tmp_path / "b", "other.py", CRYPTO)
    a, b = cbom.build_cbom(tmp_path / "a", label="t"), cbom.build_cbom(tmp_path / "b", label="t")
    assert not a.self_scan_suppressed
    assert {c["primitive"] for c in a.components} == {c["primitive"] for c in b.components}
    own = cbom.build_cbom(REPO / "entrovouch", label="t")
    assert own.self_scan_suppressed


# ---------------------------------------------------------------- cbom and key_provenance read every Python form
def test_cbom_and_key_provenance_read_notebooks_scripts_and_pth(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "n.ipynb", _notebook("x = 1\n", "import hashlib\nhashlib.md5(b'x')\nSIGNING_KEY = 'q8vK2mN4pR7sT1w9'\n"))
    _write(tmp_path, "tool", "#!/usr/bin/env python3\nimport hashlib\nhashlib.sha1(b'x')\n")
    _write(tmp_path, "start.pth", "import hashlib; hashlib.md5(b'y')\n")
    c = cbom.build_cbom(tmp_path, label="t")
    found = {(u["file"], u["line"], u["primitive"]) for u in c.components}
    assert ("n.ipynb", 2, "MD5") in found and any(f == "tool" for f, _, _ in found)
    assert any(f == "start.pth" for f, _, _ in found)
    assert c.verdict == "BROKEN-CRYPTO" and c.files_scanned == 4
    k = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert [(f["file"], f["line"]) for f in k.findings] == [("n.ipynb", 2)]


def test_a_notebook_that_is_not_json_is_listed_as_not_read(tmp_path):
    _write(tmp_path, "n.ipynb", "{not json")
    assert cbom.build_cbom(tmp_path, label="t").files_not_parsed[0]["file"] == "n.ipynb"
    assert key_provenance.scan_key_provenance(tmp_path, label="t").verdict == "REVIEW"


def test_key_provenance_reads_one_version_and_counts_config_files(tmp_path, monkeypatch):
    _write(tmp_path, ".env", "DEBUG=1\n")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert (rep.verdict, rep.files_scanned) == ("NOTHING-FOUND", 1)
    _write(tmp_path, "settings.py", "x = 1\n")
    seen = []
    real = _reads.read_bytes
    monkeypatch.setattr(_reads, "read_bytes", lambda p: seen.append(_reads._SEEN.get() is not None) or real(p))
    key_provenance.scan_key_provenance(tmp_path, label="t")
    assert seen and all(seen)            # every read inside one run


# ---------------------------------------------------------------- scripts written the way people write them
@pytest.mark.parametrize("name,line", [
    ("a.sh", '/usr/bin/curl "$URL"'), ("a.sh", '/usr/bin/wget "$URL"'), ("a.ps1", "curl.exe $u -o a"),
    ("Makefile", "x:\n\t-curl -o x $(URL)"), ("a.sh", "git -C vendor/lib pull"),
    ("a.sh", 'git -c core.autocrlf=false clone "$REPO"'), ("a.sh", "git --git-dir=.git fetch --all"),
    ("a.sh", "${VENV}/bin/pip install attrs"), ("a.sh", "$venv/bin/curl -O https://x.example/f"),
    ("roll.ps1", "& $venv_dir\\$bin_path\\pip install build"),
])
def test_commands_by_path_and_with_options_are_commands(tmp_path, name, line):
    _write(tmp_path, name, line + "\n")
    assert "script-network-command" in _kinds(tmp_path)


@pytest.mark.parametrize("name,line", [
    ("a.sh", "cat docs/ssh/notes"), ("a.sh", "ls ./curl/"), ("a.sh", "python foo.py --with-curl"),
    ("a.sh", "git -C x log"), ("a.sh", "git status"),
    ("Dockerfile", "COPY --from=ghcr.io/astral-sh/uv:0.6.0 /uv /uvx /bin/"),     # copies a file
    (".gitlab-ci.yml", "job:\n  image: curlimages/curl:7.79.1"),                  # an image name
    ("config.yml", "steps:\n  - run: sudo /etc/init.d/ssh start"),               # starts the SSH server
    ("a.sh", 'sed -i "s#./ssh-server-config#/tmp/ssh#g" x'),                    # a path in a pattern
    ("a.sh", "if [[ ! -x /usr/bin/wget ]]; then"),                              # a file test
    ("a.ps1", "throw 'ssh.exe is required. Install it'"),                       # a message
])
def test_a_folder_a_path_or_a_word_is_still_not_a_command(tmp_path, name, line):
    _write(tmp_path, name, line + "\n")
    # `COPY --from=<image>` declares the image it copies from; no program on the line is run
    assert _kinds(tmp_path) - {"external-url", "declared-remote-source"} == set()


# ---------------------------------------------------------------- unlisted imports
def test_a_same_named_file_elsewhere_does_not_hide_an_import(tmp_path):
    _write(tmp_path, "myapp/integrations/asyncssh.py", "x = 1\n")
    _write(tmp_path, "myapp/integrations/telethon/__init__.py", "")
    _write(tmp_path, "myapp/client.py", "import asyncssh\nimport telethon\n")
    _write(tmp_path, "src/mypkg/__init__.py", "")
    _write(tmp_path, "src/mypkg/core.py", "import mypkg\n")
    _write(tmp_path, "tests/helpers.py", "x = 1\n")
    _write(tmp_path, "tests/test_a.py", "import helpers\n")
    rep = audit(tmp_path, label="t")
    assert "telethon" in rep.unlisted_imports
    assert ("myapp/client.py", 1, "network-import") in [(f["file"], f["line"], f["kind"]) for f in rep.findings]
    assert not {"mypkg", "helpers"} & set(rep.unlisted_imports)


def test_a_package_in_its_own_project_folder_is_the_trees_own(tmp_path):
    # a repository of several projects: psycopg/pyproject.toml beside psycopg/psycopg/
    _write(tmp_path, "psycopg/pyproject.toml", "[project]\nname = 'psycopg'\n")
    _write(tmp_path, "psycopg/psycopg/__init__.py", "")
    _write(tmp_path, "tests/test_conn.py", "import psycopg\n")
    rep = audit(tmp_path, label="t")
    assert "psycopg" not in rep.unlisted_imports and rep.verdict == "CLEAN"


def test_a_test_folder_named_after_a_library_shadows_nothing(tmp_path):
    # tests/integrations/socket/ is a folder of tests about socket, not a module named socket
    _write(tmp_path, "tests/__init__.py", "")
    _write(tmp_path, "tests/integrations/socket/__init__.py", "")
    _write(tmp_path, "sdk/client.py", "import socket\n")
    rep = audit(tmp_path, label="t")
    assert "socket" not in rep.shadowed_imports
    assert "network-import" in {f["kind"] for f in rep.findings}


# ---------------------------------------------------------------- SBOM documents
def test_a_pipfile_inline_table_gives_its_version(tmp_path):
    _write(tmp_path, "Pipfile", '[packages]\nrequests = {extras = ["socks"], version = "==2.31.0"}\n'
                                'flask = {version="==3.0.0", index="pypi"}\nattrs = "*"\n')
    comps = {c["name"]: c for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert comps["requests"]["purl"] == "pkg:pypi/requests@2.31.0" and comps["flask"]["version"] == "3.0.0"
    assert comps["attrs"]["version_status"] == "unknown"


def test_bom_refs_are_unique_and_keys_are_found_as_keys(tmp_path):
    _write(tmp_path / "n", "package.json", json.dumps({"dependencies": {"a": "1.0.0"}, "peerDependencies": {"a": "1.0.0"}}))
    _write(tmp_path / "p", "pyproject.toml",
           '[tool.poetry]\nname = "x"\ndescription = "uses requests"\n\n[tool.poetry.dependencies]\n'
           'python = "^3.11"\nrequests = "^2.31"\n')
    cdx = sbom.to_cyclonedx(asdict(sbom.build_sbom(tmp_path / "n", label="t")))
    refs = [c["bom-ref"] for c in cdx["components"]]
    assert len(refs) == len(set(refs)) == 2
    comps = asdict(sbom.build_sbom(tmp_path / "p", label="t"))["components"]
    assert [(c["name"], c["line"]) for c in comps] == [("requests", 7)]


def test_a_continued_line_pip_cannot_read_invents_nothing(tmp_path):
    _write(tmp_path, "requirements.txt", "flask " + B + "\n  requests==2.31.0\nattrs==23.1.0\n")
    s = asdict(sbom.build_sbom(tmp_path, label="t"))
    assert [(c["name"], c["version"]) for c in s["components"]] == [("attrs", "23.1.0")]
    assert any("cannot read as one requirement" in u for u in s["unknown_fields"])
    assert audit(tmp_path, label="t").verdict != "CLEAN"


@pytest.mark.parametrize("line", ["--index https://pkgs.example/simple", "--extra https://pkgs.example/simple",
                                  "--find https://pkgs.example/wheels", "--trusted pkgs.example",
                                  "-ihttps://pkgs.example/simple"])
def test_abbreviated_package_source_options_are_reported(tmp_path, line):
    _write(tmp_path, "requirements.txt", line + "\nattrs==23.1.0\n")
    assert any("package index" in f["detail"] for f in audit(tmp_path, label="t").findings)


def test_a_file_url_include_is_a_path_not_a_remote(tmp_path):
    _write(tmp_path, "requirements.txt", "-r file:///etc/passwd\n")
    details = [f["detail"] for f in audit(tmp_path, label="t").findings]
    assert not any("fetched from a URL" in d for d in details)


def test_a_conda_flow_list_with_a_pip_mapping_is_read(tmp_path):
    _write(tmp_path, "environment.yml", "dependencies: [python, {pip: [requests, 'httpx>=0.27']}]\n")
    comps = {(c["name"], c["ecosystem"]) for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert comps == {("python", "conda"), ("requests", "pypi"), ("httpx", "pypi")}


def test_npm_leading_zeros_are_not_a_version(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"a": "01.2.3", "b": "0.2.3"}}))
    comps = {c["name"]: c for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert comps["a"]["version_status"] == "unknown" and comps["b"]["version"] == "0.2.3"


# ---------------------------------------------------------------- notebooks and exported notebooks
def test_exported_notebook_magics_and_load_are_read(tmp_path):
    nl = B + "n"
    _write(tmp_path, "export.py",
           "get_ipython().run_cell_magic('bash', '', 'curl https://example.com/x" + nl + "')\n"
           "get_ipython().run_line_magic('system', 'curl https://example.com/y')\n"
           "get_ipython().run_line_magic('pip', 'install requests')\n"
           "get_ipython().system_raw('curl https://example.com/w')\n"
           "get_ipython().run_line_magic('load', 'https://example.com/code.py')\n"
           "get_ipython().run_line_magic('timeit', 'x = 1')\n")
    found = sorted((f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings)
    assert found == [(1, "subprocess-shell"), (2, "subprocess-shell"), (3, "subprocess-net-binary"),
                     (4, "subprocess-shell"), (5, "network-call")]


def test_a_writefile_cell_is_marked_as_written_not_run(tmp_path):
    _write(tmp_path, "n.ipynb", _notebook("%%writefile helper.py\nimport requests\n", "%load https://example.com/a.py\n"))
    findings = audit(tmp_path, label="t").findings
    assert any(f["kind"] == "network-import" and "written to a file" in f["detail"] for f in findings)
    assert any(f["kind"] == "network-call" and f["line"] == 2 for f in findings)


# ---------------------------------------------------------------- JavaScript and private modules
def test_javascript_types_strings_and_template_literals(tmp_path):
    bt = chr(96)
    _write(tmp_path / "a", "a.ts", "import type { Agent } from 'https';\nconst s = \"import x from 'https'\";\n")
    _write(tmp_path / "b", "b.js", "const h = require(" + bt + "https" + bt + ");\n")
    assert _kinds(tmp_path / "a") == set() and _kinds(tmp_path / "b") == {"network-import"}


def test_private_modules_that_start_processes_are_reported(tmp_path):
    _write(tmp_path / "a", "a.py", "import _winapi\n")
    _write(tmp_path / "b", "b.py", "from _posixsubprocess import fork_exec\n")
    _write(tmp_path / "c", "c.py", "import _overlapped\n")
    assert _kinds(tmp_path / "a") == _kinds(tmp_path / "b") == {"native-call"}
    assert _kinds(tmp_path / "c") == set()        # _overlapped waits on pipes and events; it is not a network module


def test_a_large_artifact_is_hashed_without_being_held(tmp_path):
    with open(tmp_path / "model.pt", "wb") as f:
        for _ in range(40):
            f.write(os.urandom(1 << 20))
    _write(tmp_path, "a.py", "x = 1\n")
    tracemalloc.start()
    try:
        audit(tmp_path, label="t")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 20 * 2 ** 20


# ---------------------------------------------------------------- documents built from reports
def test_vex_names_its_subject_and_refuses_key_provenance_from_another_tree(tmp_path):
    _write(tmp_path / "a", "a.py", "import hashlib\nhashlib.md5(b'x')\nSIGNING_KEY = 'q8vK2mN4pR7sT1w9'\n")
    c, k, other = tmp_path / "c.json", tmp_path / "k.json", tmp_path / "other.json"
    _cli("cbom", tmp_path / "a", "--json", c, "--label", "tree-a")
    _cli("key_provenance", tmp_path / "a", "--json", k, "--label", "tree-a")
    _cli("key_provenance", REPO / "examples" / "sample_service", "--json", other)
    assert _cli("vex", c, "--key-provenance", k, "--out", tmp_path / "v.json").returncode == 0
    doc = json.loads((tmp_path / "v.json").read_text(encoding="utf-8"))
    ref = doc["metadata"]["component"]["bom-ref"]
    assert doc["metadata"]["component"]["name"] == "tree-a"
    assert all(v["affects"] == [{"ref": ref}] for v in doc["vulnerabilities"])
    r = _cli("vex", c, "--key-provenance", other, "--out", tmp_path / "v2.json")
    assert r.returncode == 2 and "cannot be made from another" in r.stderr


def test_csaf_is_one_document_per_cbom_and_checks_its_namespace(tmp_path):
    _write(tmp_path / "a", "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    c = tmp_path / "c.json"
    _cli("cbom", tmp_path / "a", "--json", c, "--label", "tree-a")
    base = ["--publisher-name", "X", "--publisher-namespace", "https://x.example"]
    assert _cli("csaf", c, "--out", tmp_path / "1.json", *base).returncode == 0
    assert _cli("csaf", c, "--out", tmp_path / "2.json", *base).returncode == 0
    assert (tmp_path / "1.json").read_bytes() == (tmp_path / "2.json").read_bytes()
    r = _cli("csaf", c, "--out", tmp_path / "3.json", "--publisher-name", "X", "--publisher-namespace",
             "https://exa mple.com")
    assert r.returncode == 2


def test_sarif_uris_are_percent_encoded(tmp_path):
    _write(tmp_path / "p", "a b/ü #1%.py", "import requests\n")
    rep, out = tmp_path / "r.json", tmp_path / "s.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    assert _cli("sarif", rep, "--out", out).returncode == 0
    uri = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"]
    assert uri == "a%20b/%C3%BC%20%231%25.py"


def test_cbom_takes_a_label_so_the_digest_does_not_depend_on_the_folder_name(tmp_path):
    for name in ("sample_service", "other_name"):
        _write(tmp_path / name, "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    _cli("cbom", tmp_path / "sample_service", "--json", a, "--label", "same")
    _cli("cbom", tmp_path / "other_name", "--json", b, "--label", "same")
    digest = lambda p: json.loads(p.read_text(encoding="utf-8"))["findings_digest"]
    assert digest(a) == digest(b)


def test_timestamp_refuses_a_json_report_in_utf16(tmp_path):
    _write(tmp_path / "p", "a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    wide = tmp_path / "wide.json"
    wide.write_bytes(rep.read_text(encoding="utf-8").encode("utf-16"))
    r = _cli("timestamp", "request", wide, "--out", tmp_path / "w.tsq")
    assert r.returncode == 2 and "UTF-16" in r.stderr
    assert _cli("timestamp", "request", rep, "--out", tmp_path / "ok.tsq").returncode == 0


# ---------------------------------------------------------------- the command line says only what holds
def test_command_line_options_do_what_their_help_says(tmp_path):
    _write(tmp_path / "p", "a.py", "x = 1\n")
    r = _cli("no_egress_auditor", tmp_path / "p", "--covenant", tmp_path / "missing.txt")
    assert r.returncode == 2 and "unrecognized arguments" in r.stderr     # the flag does not exist
    (tmp_path / "dir").mkdir()
    r = _cli("no_egress_auditor", tmp_path / "p", "--key", tmp_path / "dir")
    assert r.returncode == 2 and "is a folder" in r.stderr
    key = tmp_path / "k.json"
    assert _cli("no_egress_auditor", "--init-key", key).returncode == 0
    r = _cli("no_egress_auditor", tmp_path / "p", "--key", key, "--json", tmp_path / "nope" / "r.json")
    assert r.returncode == 2 and json.loads(key.read_text(encoding="utf-8"))["next_index"] == 0
    r = _cli("no_egress_auditor", "--init-key", tmp_path / "k2.json", "--advance-key", "3")
    assert r.returncode == 2 and not (tmp_path / "k2.json").exists()


def test_reports_are_written_with_lf_line_endings(tmp_path):
    _write(tmp_path / "p", "a.py", "import requests\n")
    rep, md = tmp_path / "r.json", tmp_path / "r.md"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep, "--md", md)
    assert b"\r\n" not in rep.read_bytes() and b"\r\n" not in md.read_bytes()

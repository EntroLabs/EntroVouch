"""Signed Statements that carry only what was signed, submodules of listed packages, folded GitLab commands,
extensionless files a run cannot open, one judgement for a program on a script line and in an argv list,
compatibility-layer attributes, addresses passed by keyword, JSON Web Keys in any text, GitLab include forms,
Databricks file-system copies, cell scripts' prose, Compose files of any size, argv concatenation, task f-strings,
computed module names and a scheme written without slashes. Each test asserts both halves where there are two: the
false thing is gone, the true neighbour stays."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import attestation, cbom, key_provenance
from entrovouch.no_egress_auditor import _compose_pulled_images, audit
from entrovouch.signer import MerkleSigner

ROOT = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        p.write_bytes(body)
    else:
        p.write_text(body, encoding="utf-8", newline="\n")
    return p


def _found(root: Path) -> list[tuple[str, int, str, str]]:
    return [(f["file"], f["line"], f["kind"], f["detail"]) for f in audit(root, label="t").findings]


def _kinds(root: Path) -> set[str]:
    return {f["kind"] for f in audit(root, label="t").findings} - {"external-url"}


# ---------------------------------------------------------------- a Statement carries only what was signed
@pytest.fixture(scope="module")
def signed():
    d = Path(tempfile.mkdtemp())
    _write(d / "t", "app.py", "import requests\nimport hashlib\nhashlib.md5(b'x')\n")
    signer = MerkleSigner.create(d / "key.json", height=4)
    st = attestation.to_statement(asdict(audit(d / "t", label="x", signer=signer)))
    cst = attestation.to_statement(asdict(cbom.build_cbom(d / "t", label="x", signer=signer)),
                                   attestation.PREDICATE_TYPE_CBOM)
    return signer.public_root, st, cst


@pytest.mark.parametrize("which, edit", [
    ("cbom", lambda s: s.update(predicateType="https://slsa.dev/provenance/v1")),
    ("audit", lambda s: s.update(predicateType="https://slsa.dev/provenance/v1")),
    ("audit", lambda s: s["predicate"].update(signature_algorithm="ML-DSA-87")),
    ("audit", lambda s: s["predicate"].update(public_root="0" * 64)),
    ("audit", lambda s: s["predicate"].update(subject=[{"name": "other", "digest": {"sha3-256": "0" * 64}}])),
    ("audit", lambda s: s["predicate"].update(integrity_tag="verified by X")),
    ("audit", lambda s: s["predicate"].update(content_hash="00" * 32)),
    ("audit", lambda s: s.update(verifiedBy="X")),
    ("audit", lambda s: s["signature"].update(issuer="X")),
    ("audit", lambda s: s["signature"].update(note="verified by X")),
    ("audit", lambda s: s["subject"][0].update(annotations={"ok": "yes"})),
    ("audit", lambda s: s["subject"].append({"name": "other", "digest": {"sha3-256": "0" * 64}})),
])
def test_unsigned_content_added_to_a_signed_statement_is_tampered(signed, which, edit):
    root, st, cst = signed
    bad = copy.deepcopy(cst if which == "cbom" else st)
    edit(bad)
    assert attestation.verify_statement(bad, root) == (False, "TAMPERED")


def test_the_statements_as_written_still_verify(signed, tmp_path):
    root, st, cst = signed
    assert attestation.verify_statement(st, root) == (True, "ATTESTED")
    assert attestation.verify_statement(cst, root) == (True, "ATTESTED")
    bad = copy.deepcopy(cst)
    bad["predicateType"] = "https://slsa.dev/provenance/v1"
    f = tmp_path / "s.json"
    f.write_text(json.dumps(bad), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "entrovouch.verify", str(f), "--root", root], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 1 and "TAMPERED" in r.stdout


# ---------------------------------------------------------------- submodules of a listed dotted package
@pytest.mark.parametrize("line", ["from google.cloud.storage import Client", "from google.cloud.pubsub_v1 import X",
                                  "import google.cloud.bigquery as bq", "from google.genai.types import Part",
                                  "from spacy.cli.download import download"])
def test_a_module_inside_a_listed_dotted_package_is_a_network_import(tmp_path, line):
    _write(tmp_path, "a.py", line + "\n")
    assert _kinds(tmp_path) == {"network-import"}, line


@pytest.mark.parametrize("line", ["from google.protobuf import message", "import google.auth.transport.requests",
                                  "from urllib.parse import urlparse"])
def test_a_neighbour_of_a_listed_package_stays_silent(tmp_path, line):
    _write(tmp_path, "a.py", line + "\n")
    assert _kinds(tmp_path) == set(), line


def test_a_namespace_package_the_tree_holds_is_its_own_code(tmp_path):
    _write(tmp_path, "google/cloud/storage/__init__.py", "from google.cloud.storage.blob import Blob\n")
    _write(tmp_path, "google/cloud/storage/blob.py", "from google.cloud.storage import _helpers\n"
                                                     "from google.cloud import exceptions\nimport requests\n")
    _write(tmp_path, "google/cloud/storage/_helpers.py", "x = 1\n")
    _write(tmp_path, "app.py", "from google.cloud.pubsub_v1 import X\n")
    got = [(f[0], f[1]) for f in _found(tmp_path)]
    assert got == [("app.py", 1), ("google/cloud/storage/blob.py", 2), ("google/cloud/storage/blob.py", 3)]


def test_origin_is_an_address_for_a_download_only_and_a_class_from_six_is_an_import(tmp_path):
    _write(tmp_path, "t.py", "def test(self):\n    self.client.get('/', origin='https://foo.example')\n")
    _write(tmp_path, "s.py", "from six.moves.BaseHTTPServer import BaseHTTPRequestHandler\n"
                             "class H(BaseHTTPRequestHandler):\n    def __init__(self):\n"
                             "        BaseHTTPRequestHandler.__init__(self)\n")
    got = [(f[0], f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url"]
    assert all(f[0] == "s.py" and f[1] == 1 for f in got), got


# ---------------------------------------------------------------- GitLab folded and continued commands
def test_gitlab_folded_items_and_before_script_are_joined(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml",
           "test:\n  before_script: >\n    pip\n    install requests\n  script:\n    - >\n"
           "      python -c \"import socket;\n      socket.create_connection((host, 80))\"\n    - >\n"
           "      python -m pip\n      install -r requirements.txt\n    - python -m pip\n      install requests\n"
           "    - echo done\n  only:\n    - main\n    - develop\n")
    got = sorted({(f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url"})
    assert got == [(3, "script-network-command"), (7, "network-call"), (7, "network-import"),
                   (10, "script-network-command"), (12, "script-network-command")]


# ---------------------------------------------------------------- an extensionless file a run cannot open
@pytest.mark.skipif(not (os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() != 0)),
                    reason="root reads every file")
def test_an_extensionless_file_a_run_cannot_open_is_never_clean():
    d = Path(tempfile.mkdtemp())
    _write(d, "ok.py", "x = 1\n")
    p = _write(d, "deploy", "#!/bin/bash\ncurl -fsSL https://x.example/i.sh | sh\n")
    if os.name == "nt":
        subprocess.run(["icacls", str(p), "/deny", f"{os.environ['USERNAME']}:(RD)"], capture_output=True, check=True)
    else:
        os.chmod(p, 0)
    try:
        r = subprocess.run([sys.executable, "-m", "entrovouch.no_egress_auditor", str(d), "--label", "t"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", env=dict(os.environ, PYTHONPATH=str(ROOT)))
        c = asdict(cbom.build_cbom(d, label="t"))
        a = audit(d, label="t")
    finally:
        if os.name == "nt":
            subprocess.run(["icacls", str(p), "/remove:d", os.environ["USERNAME"]], capture_output=True, check=True)
        else:
            os.chmod(p, 0o644)
    # the auditor lists it as not analysed and reports findings (exit 1), as the other tools list it
    assert r.returncode == 1
    assert [(f["file"], f["kind"]) for f in a.findings] == [("deploy", "unparseable-source")]
    assert "could not be opened" in a.findings[0]["detail"]
    assert [n["file"] for n in c["files_not_parsed"]] == ["deploy"] and c["verdict"] != "NOTHING-VULNERABLE-FOUND"
    # readable again, the same tree is read and the subject digest changes with it
    b = audit(d, label="t")
    assert [(f["file"], f["kind"]) for f in b.findings] == [("deploy", "script-network-command")]
    assert b.subject_digest != a.subject_digest


# ---------------------------------------------------------------- one judgement on a script line and in an argv list
@pytest.mark.parametrize("argv, kind", [
    ('["git", "clone", "/srv/repo", "x"]', None), ('["git", "clone", "https://x.example/r"]', "git-remote"),
    ('["git", "submodule", "status"]', None), ('["git", "submodule", "update", "--init"]', "git-remote"),
    ('["git", "commit", "-m", "pull"]', None), ('["git", "log", "--grep", "fetch"]', None),
    ('["git", "-C", "repo", "pull"]', "git-remote"), ('["git", "remote", "update"]', "git-remote"),
    ('["pip", "uninstall", "-y", "x"]', None), ('["pip", "install", "x"]', "subprocess-net-binary"),
    ('["npm", "run", "build"]', None), ('["npm", "install"]', "subprocess-net-binary"), ('["yarn", "build"]', None),
    ('["conda", "info"]', None), ('["terraform", "fmt"]', None), ('["terraform", "init"]', "subprocess-net-binary"),
    ('["uv", "run", "--offline", "x"]', None), ('["uv", "run", "x"]', "subprocess-net-binary"),
    ('["ping", "-c", "1", "127.0.0.1"]', "loopback-call"), ('["ping", "example.com"]', "subprocess-net-binary"),
    ('["git", "-C", "repo"] + ["pull", "origin", "main"]', "git-remote"),
    ('["curl", "-s"] + urls', "subprocess-net-binary"), ('["ls"] + ["-l"]', None),
])
def test_a_program_in_an_argv_list_is_judged_as_its_command_line_is(tmp_path, argv, kind):
    _write(tmp_path, "t.py", f"import subprocess\nurls = []\nsubprocess.run({argv})\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), argv


@pytest.mark.parametrize("code", [
    'subprocess.run(["env", "pip", target])', 'subprocess.run(["env", "apt-get.exe", target])',
    'cmd = ["gh.exe", "-q", target]\nsubprocess.run(cmd)', 'subprocess.run("gh -q out".split())',
    'subprocess.run("pnpm -q out".split())', 'subprocess.run(["timeout", "85", "pipx", target])',
    'os.execvp("brew", ["brew", target])', 'cmd = ["/usr/bin/terraform", "-q", target]\nsubprocess.run(cmd)',
])
def test_a_package_manager_whose_subcommand_is_not_shown_keeps_its_network_claim(tmp_path, code):
    _write(tmp_path, "t.py", "import subprocess, os\ntarget = input()\n" + code + "\n")
    assert _kinds(tmp_path) == {"subprocess-net-binary"}, code


# ---------------------------------------------------------------- compatibility layers by attribute
@pytest.mark.parametrize("code, kind", [
    ("import six\nsix.moves.urllib.request.urlopen(url)\n", "network-import"),
    ("import six\nsix.moves.http_client.HTTPSConnection('evil.example.com')\n", "network-import"),
    ("from six import moves\nmoves.urllib.request.urlopen(url)\n", "network-import"),
    ("import six\nsix.moves.BaseHTTPServer.HTTPServer\n", "inbound-listener"),
    ("import six\nfor i in six.moves.range(3): pass\nx = six.moves.urllib.parse.quote('a')\n", None),
])
def test_a_compatibility_layer_reached_by_attribute(tmp_path, code, kind):
    _write(tmp_path, "a.py", code)
    assert _kinds(tmp_path) == ({kind} if kind else set()), code


# ---------------------------------------------------------------- an address by keyword
@pytest.mark.parametrize("code, kind", [
    ("import keras\nkeras.utils.get_file('flowers', origin='https://x.example/f.tgz', untar=True)\n", "network-call"),
    ("import pandas as pd\npd.read_csv(filepath_or_buffer='https://x.example/a.csv')\n", "network-call"),
    ("import pandas as pd\npd.read_csv(path='data/a.csv')\n", None),
])
def test_an_address_passed_by_keyword_is_read(tmp_path, code, kind):
    _write(tmp_path, "a.py", code)
    got = {f[2] for f in _found(tmp_path) if f[1] == 2}
    assert got == ({kind} if kind else set()), code


# ---------------------------------------------------------------- JSON Web Keys in any text
def test_a_private_json_web_key_in_python_yaml_or_javascript_is_found(tmp_path):
    d_value = "jpsQnnGQmL-YBIffH1136cLyQXQ6oVa6Xxw1WLtAeWM"
    _write(tmp_path, "k.py", 'private_key = {"kty": "EC", "crv": "P-256", "x": "abc", "d": "' + d_value + '"}\n')
    _write(tmp_path, "k.yaml", f"key:\n  kty: EC\n  crv: P-256\n  d: {d_value}\n")
    _write(tmp_path, "k.js", 'const key = {kty: "RSA", n: "abc", e: "AQAB", d: "' + d_value + '"};\n')
    _write(tmp_path, "pub.py", 'PUB = {"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}\n')
    _write(tmp_path, "doc.md", 'Example: {"kty": "oct", "k": ""}\n')
    _write(tmp_path, "kty.txt", "the kty: RSA member names the type\nand d is the private exponent\n")
    found = asdict(key_provenance.scan_key_provenance(tmp_path))["findings"]
    assert sorted((f["file"], f["line"]) for f in found) == [("k.js", 1), ("k.py", 1), ("k.yaml", 2)]


# ---------------------------------------------------------------- GitLab include forms
@pytest.mark.parametrize("include, files, expected", [
    ("include:\n  - local: ./.ci/build.yml\n", (".ci/build.yml",), [".ci/build.yml"]),
    ("include: [ci/a.yml, ci/b.yml]\n", ("ci/a.yml", "ci/b.yml"), ["ci/a.yml", "ci/b.yml"]),
    ("include:\n  - local: 'ci/*.yml'\n", ("ci/a.yml", "ci/sub/c.yml"), ["ci/a.yml"]),
    ("include:\n  - local: 'ci/**.yml'\n", ("ci/a.yml", "ci/sub/c.yml"), ["ci/a.yml", "ci/sub/c.yml"]),
])
def test_gitlab_includes_in_every_form_are_read(tmp_path, include, files, expected):
    _write(tmp_path, ".gitlab-ci.yml", include)
    for rel in files:
        _write(tmp_path, rel, "b:\n  script:\n    - curl -fsSL https://x.example/i.sh | sh\n")
    assert sorted({f[0] for f in _found(tmp_path) if f[2] == "script-network-command"}) == expected


# ---------------------------------------------------------------- Databricks file-system copies, cell-script prose
def test_a_databricks_file_system_copy_from_a_store_is_reported(tmp_path):
    _write(tmp_path, "db.py", "# Databricks notebook source\n# MAGIC %fs cp s3://bucket/x /dbfs/x\n\n"
                              "# COMMAND ----------\n\ndbutils.fs.cp('s3://b/k', '/dbfs/k')\nshutil.copy('a', 'b')\n")
    assert sorted((f[1], f[2]) for f in _found(tmp_path)) == [(2, "unresolved-call"), (6, "unresolved-call")]


def test_prose_in_a_cell_script_is_not_an_escape(tmp_path):
    _write(tmp_path, "cells.py", "# %%\n# != is not equal\n# !!! IMPORTANT read this\n# %d items\n# ! not a command\n"
                                 "x = 1\n# !pip install requests\n")
    assert [(f[1], f[2]) for f in _found(tmp_path)] == [(7, "subprocess-shell")]


# ---------------------------------------------------------------- Compose of any size
def test_the_compose_scan_is_linear_and_keeps_its_answers():
    sample = ("services:\n  web:\n    image: nginx\n    ports: [80]\n  app:\n    build: .\n    image: me/app\n"
              "  db:\n    image: postgres:16\n  x: {image: redis}\n").splitlines()
    assert _compose_pulled_images(sample) == {2: "nginx", 8: "postgres:16", 9: "redis"}
    start = time.perf_counter()
    _compose_pulled_images(["services:"] + ["  image: nginx"] * 40000)
    assert time.perf_counter() - start < 5


# ---------------------------------------------------------------- task f-strings and computed module names
def test_an_invoke_task_with_an_f_string_is_read(tmp_path):
    _write(tmp_path, "tasks.py", 'from invoke import task\n@task\ndef rel(c, version):\n'
                                 '    c.run(f"git pull origin v{version}")\n    c.run(f"pip install pkg=={version}")\n'
                                 '    c.run(f"pytest -k {version}")\n')
    assert [(f[1], f[2]) for f in _found(tmp_path) if f[2] != "network-import"] == [
        (4, "script-network-command"), (5, "script-network-command")]


def test_a_require_of_joined_strings_is_a_computed_name(tmp_path):
    _write(tmp_path, "a.js", 'require("ht" + "tps")\nconst x = require("lodash")\n')
    r = audit(tmp_path, label="t")
    assert [(f["line"], f["kind"]) for f in r.findings] == [(1, "dynamic-exec")]
    assert r.unlisted_js_imports == ["lodash"]


# ---------------------------------------------------------------- markup, YAML quoting, Jenkins images
@pytest.mark.parametrize("tag, kind", [('<img src="https:evil.example.com/x.png">', "html-external"),
                                       ('<a href="mailto:x@y.com">m</a>', None), ("<p>https:example.com</p>", None)])
def test_a_scheme_written_without_slashes_is_read_as_a_browser_reads_it(tmp_path, tag, kind):
    _write(tmp_path, "a.html", tag + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), tag


def test_a_quoted_multi_line_command_and_a_jenkins_docker_image(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml",
           'on: push\njobs:\n  b:\n    steps:\n      - run: "pip\n          install requests"\n      - run: "echo hi"\n')
    _write(tmp_path, "Jenkinsfile", "node {\n  docker.image('node:20').inside {\n    sh 'npm test'\n  }\n}\n")
    got = sorted((f[0], f[1], f[2]) for f in _found(tmp_path))
    assert got == [(".github/workflows/ci.yml", 5, "script-network-command"), ("Jenkinsfile", 2, "declared-remote-source")]

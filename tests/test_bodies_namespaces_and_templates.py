"""Here-documents inside pipeline blocks and recipes, nested here-document openers, YAML steps that a trailing
backslash does not join, namespace packages Python would not import from the tree, Azure templates and GitLab flow
maps, JSON Web Key values that are code or prose, Statements under in-toto's digest name, database clients given
several hosts, programs whose local form depends on an argument, xargs, IPython help, the HTML alias, Cloud Build
images, ensurepip and robots.txt. Each test asserts both halves where there are two: the false thing is gone, the
true neighbour stays."""
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

from entrovouch import attestation, key_provenance
from entrovouch.no_egress_auditor import audit
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


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _indented(body: str, pad: str) -> str:
    return "".join(pad + ln + "\n" for ln in body.splitlines())


# ---------------------------------------------------------------- here-documents inside blocks and recipes
_PY_BODY = "python - <<EOF\nimport requests\nrequests.get(API)\nEOF"


@pytest.mark.parametrize("rel, head, pad, line", [
    (".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n", " " * 10, 8),
    (".gitlab-ci.yml", "b:\n  script:\n    - |\n", " " * 6, 5),
    (".circleci/config.yml", "version: 2.1\njobs:\n  b:\n    steps:\n      - run:\n          command: |\n", " " * 12, 8),
    ("azure-pipelines.yml", "steps:\n- script: |\n", " " * 4, 4),
    ("justfile", "fetch:\n", " " * 4, 3),
    ("Makefile", "fetch:\n", "\t", 3),
    ("x.sh", "", "", 2),
])
def test_python_in_a_here_document_inside_a_block_or_recipe_is_read_as_python(tmp_path, rel, head, pad, line):
    _write(tmp_path, rel, head + _indented(_PY_BODY, pad))
    assert (rel, line, "network-import") in _found(tmp_path)
    # the same block with a body that reaches nothing stays clean
    _write(tmp_path, rel, head + _indented(_PY_BODY.replace("requests", "json").replace("json.get(API)", "json.dumps(1)"), pad))
    assert [f for f in _found(tmp_path) if f[0] == rel] == []


def test_a_python_file_a_here_document_writes_inside_a_run_block_is_read(tmp_path):
    body = "cat > fetch.py <<EOF\nimport socket\nsocket.create_connection((HOST, 443))\nEOF\npython fetch.py"
    _write(tmp_path, ".github/workflows/ci.yml",
           "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n" + _indented(body, " " * 10))
    assert [k for _, _, k in _found(tmp_path)] == ["network-import", "network-call"]


# ---------------------------------------------------------------- openers inside an open body
def test_repeated_here_document_openers_take_linear_time_and_keep_the_real_one(tmp_path):
    _write(tmp_path, "x.sh", "python - <<EOF\n" * 40000 + "EOF\n")
    start = time.perf_counter()
    assert _found(tmp_path) == []
    assert time.perf_counter() - start < 20
    # an opener inside a shell's body with its own terminator before the outer one is still a here-document
    _write(tmp_path, "x.sh", "bash <<'OUT'\npython - <<PY\nimport requests\nPY\nOUT\n")
    assert _found(tmp_path) == [("x.sh", 3, "network-import")]


def test_an_opener_with_no_terminator_inside_its_enclosing_body_reads_to_that_bodys_end(tmp_path):
    # The shell ends the outer body at the first EOF, so the inner `cat <<EOF` finds no terminator in what it reads and
    # `cat` prints the curl line. A body with no terminator hides nothing here, so text taken for an opener by mistake
    # cannot swallow commands: the curl line stays a command line (a claim larger than bash's, never smaller).
    _write(tmp_path, "x.sh", "bash <<EOF\ncat <<EOF\ncurl https://e.example.com/x\nEOF\n")
    assert [k for _, _, k in _found(tmp_path)] == ["script-network-command"]
    # an inner Python body whose terminator comes after the outer one is Python up to the outer terminator
    _write(tmp_path, "x.sh", "bash <<OUT\npython3 - <<PY\nimport requests\nOUT\nPY\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(3, "network-import")]
    # and a body with no terminator at all runs to the end of the file
    _write(tmp_path, "x.sh", "python3 - <<EOF\nimport requests\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(2, "network-import")]


# ---------------------------------------------------------------- a trailing backslash in a YAML step
@pytest.mark.parametrize("rel, text, expected", [
    (".github/workflows/ci.yml",
     "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo C:\\\n      - run: npm ci\n",
     [(7, "script-network-command")]),
    (".github/workflows/ci.yml",
     "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n          ls \\\n"
     "      - run: curl https://e.example.com/notify\n", [(8, "script-network-command")]),
    (".gitlab-ci.yml", "b:\n  script:\n    - echo done \\\n    - wget https://e.example.com/x\n",
     [(4, "script-network-command")]),
    # within one block a continued command still joins its next line
    (".github/workflows/ci.yml",
     "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n          pip \\\n            install requests\n",
     [(7, "script-network-command")]),
])
def test_a_trailing_backslash_does_not_join_the_next_yaml_step(tmp_path, rel, text, expected):
    _write(tmp_path, rel, text)
    assert [(ln, k) for _, ln, k in _found(tmp_path) if k != "external-url"] == expected


# ---------------------------------------------------------------- namespace packages
_EXTEND = "from pkgutil import extend_path\n__path__ = extend_path(__path__, __name__)\n"


def test_a_namespace_init_that_extends_its_path_does_not_own_the_installed_modules(tmp_path):
    _write(tmp_path, "azure/__init__.py", _EXTEND)
    _write(tmp_path, "azure/myext/__init__.py", "")
    _write(tmp_path, "azure/myext/client.py", "x = 1\n")
    _write(tmp_path, "tools/upload.py", "from azure.storage.blob import BlobServiceClient\nimport azure.myext.client\n")
    r = audit(tmp_path, label="t")
    assert [(f["file"], f["line"], f["kind"]) for f in r.findings] == [("tools/upload.py", 1, "network-dependency")]
    assert r.shadowed_imports == ["azure"]                  # the tree's own module, set aside and named


def test_a_project_that_installs_a_namespace_owns_the_modules_it_holds(tmp_path):
    # a repository of several projects sharing one namespace (`nats-core/src/nats/client/`, with no `nats/__init__.py`
    # there) and an older one whose `nats/__init__.py` extends its path: their own modules are their own code
    _write(tmp_path, "nats-core/pyproject.toml", "[project]\nname = 'nats-core'\n")
    _write(tmp_path, "nats-core/src/nats/client/__init__.py", "")
    _write(tmp_path, "nats/pyproject.toml", "[project]\nname = 'nats-py'\n")
    _write(tmp_path, "nats/src/nats/__init__.py", _EXTEND)
    _write(tmp_path, "nats/src/nats/aio/__init__.py", "")
    _write(tmp_path, "nats/src/nats/ext/tools/__init__.py", "")       # `ext/` a namespace folder inside it
    _write(tmp_path, "examples/a.py", "import nats\nfrom nats.client import connect\nfrom nats.aio.client import Client\n"
                                      "from nats.ext import tools\n")
    r = audit(tmp_path, label="t")
    assert r.findings == [] and r.shadowed_imports == ["nats"]
    # a plugin module lying loose in another package's namespace folders (`src/twisted/plugins/x.py`, no
    # `__init__.py`) is reached through that package as installed, not through the tree
    _write(tmp_path, "src/twisted/plugins/my_endpoints.py", "")
    _write(tmp_path, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(tmp_path, "tests/test_plugins.py", "from twisted.plugins import my_endpoints\n")
    assert [(f["file"], f["kind"]) for f in audit(tmp_path, label="t").findings] == [
        ("tests/test_plugins.py", "network-dependency")]
    # without a project, a namespace folder under src/ does not make an installed package the tree's
    _write(tmp_path, "solo/src/boto3/s3/transfer.py", "")
    _write(tmp_path, "solo/app.py", "import boto3.s3.transfer\n")
    assert [(f["file"], f["kind"]) for f in audit(tmp_path / "solo", label="t").findings] == [
        ("app.py", "network-dependency")]


def test_an_ordinary_init_at_the_root_still_owns_its_name(tmp_path):
    _write(tmp_path, "azure/__init__.py", "")
    _write(tmp_path, "tools/upload.py", "from azure.storage.blob import BlobServiceClient\n")
    r = audit(tmp_path, label="t")
    assert r.findings == [] and r.shadowed_imports == ["azure"]


def test_a_namespace_folder_beside_an_installed_ordinary_package_is_not_the_trees(tmp_path):
    _write(tmp_path, "src/boto3/s3/transfer.py", "")
    _write(tmp_path, "app.py", "import boto3.s3.transfer\n")
    assert [(f[0], f[2]) for f in _found(tmp_path)] == [("app.py", "network-dependency")]
    # under a namespace several distributions share, the tree's module is the tree's
    _write(tmp_path, "src/google/cloud/mylib/__init__.py", "")
    _write(tmp_path, "app.py", "from google.cloud.mylib import x\n")
    r = audit(tmp_path, label="t")
    assert r.findings == [] and "google" not in r.unlisted_imports


# ---------------------------------------------------------------- pipeline files a pipeline names
@pytest.mark.parametrize("files, expected", [
    ({"azure-pipelines.yml": "steps:\n- template: templates/build-steps.yml\n",
      "templates/build-steps.yml": "steps:\n- script: curl -fsSL https://e.example.com/i.sh | bash\n"},
     [("templates/build-steps.yml", "script-network-command")]),
    # relative to the file that names it, a nested template, and `/` from the repository root
    ({"ci/azure-pipelines.yml": "extends:\n  template: stages.yml\n",
      "ci/stages.yml": "stages:\n- stage: b\n  jobs:\n  - template: /jobs/fetch.yml@self\n",
      "jobs/fetch.yml": "steps:\n- script: wget https://e.example.com/x\n"},
     [("jobs/fetch.yml", "script-network-command")]),
    # a template in another repository is not in the tree
    ({"azure-pipelines.yml": "steps:\n- template: steps.yml@shared\n",
      "steps.yml": "steps:\n- script: curl https://e.example.com/x\n"}, []),
    ({".gitlab-ci.yml": "include:\n  - { local: ci/build.yml, rules: [{if: $X}] }\n",
      "ci/build.yml": "b:\n  script:\n    - curl https://e.example.com/x\n"},
     [("ci/build.yml", "script-network-command")]),
])
def test_azure_templates_and_gitlab_flow_maps_are_followed(tmp_path, files, expected):
    for rel, text in files.items():
        _write(tmp_path, rel, text)
    assert [(f, k) for f, _, k in _found(tmp_path) if k != "external-url"] == expected


# ---------------------------------------------------------------- JSON Web Keys: values, not code or prose
_D = "jpsQnnGQmL-YBIffH1136cLyQXQ6oVa6Xxw1WLtAeWM"


@pytest.mark.parametrize("rel, text, found", [
    ("keys.py", 'def f(n):\n    return {"kty": "RSA", "n": to_b64(n.n), "d": to_base64url_uint(numbers.private_d)}\n', False),
    ("sym.py", 'def f(s):\n    return {"kty": "oct", "k": base64url_encode_the_secret(s)}\n', False),
    ("README.md", "| `kty` | key type, `kty: RSA` |\n| `d` | d = modular_inverse_of_e_mod_lambda |\n", False),
    ("conf.yaml", "signing:\n  kty: EC\n  d: JWT_PRIVATE_D_FROM_VAULT\n", False),
    ("conf.yaml", f"signing:\n  kty: EC\n  d: {_D}\n", True),
    ("README.md", f'Example: {{"kty": "oct", "k": "{_D}"}}.\n', True),
    ("k.py", f'KEY = {{"kty": "EC", "d": "{_D}"}}\n', True),
])
def test_a_json_web_key_value_must_look_like_key_material(tmp_path, rel, text, found):
    _write(tmp_path, rel, text)
    k = asdict(key_provenance.scan_key_provenance(tmp_path, label="t"))
    assert bool(k["findings"]) is found, text


def test_repeated_key_types_take_linear_time(tmp_path):
    _write(tmp_path, "README.md", '{"kty": "RSA", ' * 32000 + "\n")
    start = time.perf_counter()
    assert asdict(key_provenance.scan_key_provenance(tmp_path, label="t"))["findings"] == []
    assert time.perf_counter() - start < 20


# ---------------------------------------------------------------- Statements under in-toto's digest name
@pytest.fixture(scope="module")
def statement():
    d = Path(tempfile.mkdtemp())
    _write(d / "t", "app.py", "import requests\n")
    signer = MerkleSigner.create(d / "key.json", height=3)
    return signer.public_root, attestation.to_statement(asdict(audit(d / "t", label="x", signer=signer)))


def test_a_statement_names_sha3_as_in_toto_does_and_verifies(statement):
    root, st = statement
    assert set(st["subject"][0]["digest"]) == {"sha3_256"}
    assert attestation.verify_statement(st, root) == (True, "ATTESTED")
    # one written with the reports' name (an earlier release) verifies the same
    old = copy.deepcopy(st)
    old["subject"] = [dict(e, digest={"sha3-256": e["digest"]["sha3_256"]}) for e in old["subject"]]
    assert attestation.verify_statement(old, root) == (True, "ATTESTED")
    # naming it both ways is not what this module writes
    both = copy.deepcopy(st)
    both["subject"][0]["digest"]["sha3-256"] = both["subject"][0]["digest"]["sha3_256"]
    assert attestation.verify_statement(both, root) == (False, "TAMPERED")


@pytest.mark.parametrize("tool", [["no_egress_auditor"], {"x": 1}, 7, None])
def test_a_statement_whose_tool_is_not_a_name_is_tampered_not_an_error(statement, tmp_path, tool):
    root, st = statement
    bad = copy.deepcopy(st)
    bad["predicate"]["tool"] = tool
    assert attestation.verify_statement(bad, root) == (False, "TAMPERED")
    f = tmp_path / "s.json"
    f.write_text(json.dumps(bad), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "entrovouch.verify", str(f), "--root", root], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 1, r.stderr


# ---------------------------------------------------------------- programs judged by every argument
@pytest.mark.parametrize("argv, kind", [
    ('["psql", "-h", "127.0.0.1", "-d", "postgresql://db.example.com/x"]', "subprocess-net-binary"),
    ('["mysql", "-h", "localhost", "--host=db.example.com"]', "subprocess-net-binary"),
    ('["psql", "-h", "localhost", "-c", "select * from t where host = x"]', "loopback-call"),
    ('["mysql", "--host=db.example.com", "-h", "localhost"]', "subprocess-net-binary"),
    ('["kubectl", "version"]', "subprocess-net-binary"), ('["kubectl", "version", "--client"]', None),
    ('["kubectl", "--context", "prod", "version"]', "subprocess-net-binary"),
    ('["openssl", "ocsp", "-issuer", "ca.pem", "-cert", "c.pem", "-url", "http://ocsp.example.com"]',
     "subprocess-net-binary"),
    ('["openssl", "ocsp", "-index", "index.txt", "-port", "8888"]', "inbound-listener"),
    ('["svn", "info", "https://svn.example.com/repo"]', "subprocess-net-binary"), ('["svn", "info"]', None),
    ('["svn", "diff", "^/trunk"]', "subprocess-net-binary"), ('["svn", "info", "file:///srv/repo"]', None),
])
def test_a_program_whose_reach_depends_on_an_argument(tmp_path, argv, kind):
    _write(tmp_path, "t.py", f"import subprocess\nsubprocess.run({argv})\n")
    assert {k for _, _, k in _found(tmp_path)} - {"external-url"} == ({kind} if kind else set()), argv


@pytest.mark.parametrize("line, found", [
    ("cat urls.txt | xargs -n1 wget", True), ("xargs -a urls.txt wget", True), ("cat u | xargs -0 curl", True),
    ("xargs -I {} curl -sO {}", True), ("xargs -I{} curl -sO {}", True), ("echo tools: curl, wget", False), ("apt-get remove -y curl", False),
])
def test_the_program_xargs_runs_is_a_command(tmp_path, line, found):
    _write(tmp_path, "x.sh", line + "\n")
    assert ("script-network-command" in {k for _, _, k in _found(tmp_path)}) is found, line


# ---------------------------------------------------------------- notebooks and Cloud Build
def _notebook(*cells: str) -> str:
    return json.dumps({"nbformat": 4, "nbformat_minor": 5,
                       "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
                       "cells": [{"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
                                  "source": c} for c in cells]})


def test_an_ipython_help_request_runs_nothing_and_the_cell_is_still_read(tmp_path):
    _write(tmp_path, "n.ipynb", _notebook("requests.get?\nimport requests\n", "socket.create_connection??\n",
                                          "?np.load\nx = 1\n"))
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(1, "network-import")]


def test_the_html_alias_cell_is_read_as_markup(tmp_path):
    _write(tmp_path, "n.ipynb", _notebook("%%HTML\n<script src='https://e.example.com/x.js'></script>\n"))
    assert [k for _, _, k in _found(tmp_path)] == ["html-external"]


def test_a_cloud_build_step_runs_in_the_image_it_names(tmp_path):
    _write(tmp_path, "cloudbuild.yaml", "steps:\n- name: gcr.io/cloud-builders/curl\n  args: ['https://e.example.com/x']\n"
                                        "- name: 'gcr.io/cloud-builders/docker'\n  args: ['build', '.']\n"
                                        "substitutions:\n  name: not-an-image\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path) if k != "external-url"] == [
        (2, "declared-remote-source"), (4, "declared-remote-source")]


# ---------------------------------------------------------------- the standard library's reach
def test_ensurepip_is_offline_and_robots_txt_is_fetched(tmp_path):
    _write(tmp_path, "a.py", "import ensurepip\nensurepip.bootstrap()\n")
    _write(tmp_path, "b.py", "from urllib.robotparser import RobotFileParser\nRobotFileParser(url).read()\n")
    _write(tmp_path, "c.sh", "python -m ensurepip --upgrade\n")
    assert [(f, k) for f, _, k in _found(tmp_path)] == [("b.py", "network-import")]

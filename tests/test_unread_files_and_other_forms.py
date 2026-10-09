"""Files a run cannot open, notebooks saved as Python, programs that deploy, publish or make an environment, line
endings git converts, CSAF ids, CI container aliases, page loads by a base address and by module import, YAML folded
commands, argv built from lists and `which`, task runners, signed Statements, included CI files, JSON Web Keys,
modules loaded by computed name, Jenkins steps, indented notebook escapes and `v`-prefixed versions. Each test asserts
both halves where there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import copy
import json
import os
import pickle
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import attestation, cbom, csaf, key_provenance, sbom
from entrovouch.manifests import pinned_pypi_version
from entrovouch.no_egress_auditor import _git_text, audit
from entrovouch.signer import MerkleSigner

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")
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


# ---------------------------------------------------------------- files a run cannot open
class _Unreadable:
    """Make files unreadable for the duration (an ACL deny on Windows, mode 000 elsewhere), and restore them."""

    def __init__(self, paths):
        self.paths = list(paths)

    def __enter__(self):
        for p in self.paths:
            if os.name == "nt":
                # read-data only: the ACL itself stays readable, so it can be put back
                subprocess.run(["icacls", str(p), "/deny", f"{os.environ['USERNAME']}:(RD)"], capture_output=True,
                               check=True)
            else:
                os.chmod(p, 0)
        return self

    def __exit__(self, *exc):
        for p in self.paths:
            if os.name == "nt":
                subprocess.run(["icacls", str(p), "/remove:d", os.environ["USERNAME"]], capture_output=True, check=True)
            else:
                os.chmod(p, 0o644)


def _can_lock_out() -> bool:
    return os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() != 0)


@pytest.mark.skipif(not _can_lock_out(), reason="root reads every file")
def test_every_tool_lists_a_file_it_cannot_open_and_reports_nothing_clean():
    import tempfile
    tmp_path = Path(tempfile.mkdtemp())      # a folder whose ACL the test may change on every system
    files = {"app.py": "print('hello')\n", "requirements.txt": "requests==2.31.0\n",
             "package.json": '{"dependencies": {"left-pad": "1"}}\n',
             "crypto_use.py": "import hashlib\nhashlib.md5(b'x')\n", "id_rsa": PEM}
    for rel, t in files.items():
        _write(tmp_path, rel, t)
    with _Unreadable([tmp_path / "requirements.txt", tmp_path / "package.json"]):
        found = _found(tmp_path)
    assert sorted((f[0], f[2]) for f in found) == [("package.json", "unparseable-source"),
                                                  ("requirements.txt", "unparseable-source")]
    assert all("could not be opened" in f[3] for f in found)
    # a source file, a script and a page the auditor cannot open are listed the same way, never passed over as clean
    _write(tmp_path, "run.sh", "echo hi\n")
    _write(tmp_path, "page.html", "<p>hi</p>\n")
    with _Unreadable([tmp_path / "app.py", tmp_path / "run.sh", tmp_path / "page.html"]):
        r = audit(tmp_path, label="t")
    assert sorted((f["file"], f["kind"]) for f in r.findings if f["file"] in ("app.py", "run.sh", "page.html")) == [
        ("app.py", "unparseable-source"), ("page.html", "unparseable-source"), ("run.sh", "unparseable-source")]
    assert r.verdict == "FINDINGS"
    with _Unreadable([tmp_path / rel for rel in ("requirements.txt", "package.json", "crypto_use.py", "id_rsa")]):
        c = asdict(cbom.build_cbom(tmp_path, label="t"))
        k = asdict(key_provenance.scan_key_provenance(tmp_path, label="t"))
        s = asdict(sbom.build_sbom(tmp_path, label="t"))
    # `id_rsa` has no extension: whether it is a Python script cannot be told without opening it, so it is listed too
    assert c["verdict"] == "REVIEW-NEEDED" and [n["file"] for n in c["files_not_parsed"]] == ["crypto_use.py", "id_rsa"]
    assert c["not_scanned"]["files_not_python"] == 4          # with run.sh and page.html
    assert k["verdict"] == "REVIEW" and {"id_rsa", "requirements.txt"} <= {n["file"] for n in k["files_not_parsed"]}
    assert [(f["file"], f["kind"]) for f in k["findings"]] == [("id_rsa", "key-file-in-tree")]
    assert s["verdict"] == "INCOMPLETE" and any("requirements.txt" in u for u in s["unknown_fields"])
    # readable again: every result is what it was
    c = asdict(cbom.build_cbom(tmp_path, label="t"))
    assert c["files_not_parsed"] == [] and asdict(sbom.build_sbom(tmp_path, label="t"))["verdict"] == "DECLARED"


# ---------------------------------------------------------------- notebooks saved as Python
DATABRICKS = ("# Databricks notebook source\n# MAGIC %pip install requests==2.31.0\n\n# COMMAND ----------\n\n"
              "# MAGIC %sh\n# MAGIC wget -q https://example.com/data.csv -O /dbfs/tmp/data.csv\n\n"
              "# COMMAND ----------\n\n# MAGIC %md\n# MAGIC see https://example.com\n\n# COMMAND ----------\n\n"
              "df = spark.read.csv('s3a://example-bucket/raw/data.csv')\n")


def test_a_databricks_notebook_saved_as_python_has_its_magic_cells_read(tmp_path):
    _write(tmp_path, "notebooks/ingest.py", DATABRICKS)
    got = sorted((f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url")
    assert got == [(2, "subprocess-net-binary"), (6, "subprocess-shell"), (16, "unresolved-call")]


def test_a_databricks_cell_in_another_language_is_named_as_not_read(tmp_path):
    _write(tmp_path, "nb.py", "# Databricks notebook source\n# MAGIC %sql\n# MAGIC SELECT 1\n")
    assert [f[2] for f in _found(tmp_path)] == ["unparseable-source"]


@pytest.mark.parametrize("text, lines", [
    ("# %%\n# !curl https://x.example\nimport os\n", [2]),
    ("# ---\n# jupyter:\n#   jupytext:\n#     text_representation:\n#       format_name: percent\n# ---\n\n# %%\n"
     "# %%bash\n# wget https://example.com/x\n\n# %%\n# %pip install requests\n", [9, 13]),
])
def test_a_jupytext_notebook_has_its_commented_magics_read(tmp_path, text, lines):
    _write(tmp_path, "nb.py", text)
    assert sorted({f[1] for f in _found(tmp_path) if f[2] != "external-url"}) == lines


def test_a_jupytext_markdown_cell_is_text(tmp_path):
    _write(tmp_path, "q.py", "# %%\nx = 1\n\n# %% [markdown] ctype=\"q\"\n# ![fig1](media/image1.png)\n"
                             "# !not a command here\n\n# %%\n# !curl https://x.example\n")
    assert [(f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url"] == [(9, "subprocess-shell")]


def test_a_nox_argument_is_one_argv_word(tmp_path):
    _write(tmp_path, "noxfile.py", 'import nox\n@nox.session\ndef t(session):\n'
                                   '    session.run("python", "-c", "import json\\nprint(json.dumps({}))")\n'
                                   '    session.run("python", "-c", "import socket\\nsocket.create_connection((\'x.example\', 80))")\n')
    assert sorted({(f[1], f[2]) for f in _found(tmp_path)}) == [(5, "network-call"), (5, "network-import")]


@pytest.mark.parametrize("text", ["# This module explains ! and % in comments\n# %d formats\nimport os\n",
                                  "# %%\nimport os\n# % of total\nx = 1\n", "# MAGIC %sh\n# MAGIC curl x\n"])
def test_comments_in_a_plain_script_are_comments(tmp_path, text):
    _write(tmp_path, "a.py", text)
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- programs that deploy, publish or make an environment
@pytest.mark.parametrize("line", [
    "vercel --prod", "netlify deploy --prod", "firebase login", "fly deploy", "sam deploy --guided", "cdk deploy",
    "serverless deploy", "heroku container:push web", "hatch publish", "flit publish", "python setup.py sdist upload",
    "playwright install chromium", "uv run pytest", "hatch run test", "pixi run test", "uvx ruff check",
    "ansible-playbook -i hosts site.yml", "Rscript -e 'install.packages(\"x\")'", "julia -e 'using Pkg; Pkg.add(\"X\")'",
    "host example.com", "ping example.com",
])
def test_a_program_that_deploys_publishes_or_makes_an_environment_is_a_command(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert "script-network-command" in _kinds(tmp_path), line


@pytest.mark.parametrize("line", ["vercel dev", "heroku local", "uv run --no-sync pytest", "pdm run pytest",
                                  "pipenv run pytest", "poetry run pytest", "echo vercel", "host -t A db.local"])
def test_the_same_programs_acting_here_or_only_named_are_silent(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == set(), line


def test_a_program_suffix_is_set_aside_on_the_program_only(tmp_path):
    _write(tmp_path, "a.ps1", "git.exe pull\nping example.com\n")
    assert [(f[1], f[2]) for f in _found(tmp_path)] == [(1, "script-network-command"), (2, "script-network-command")]


# ---------------------------------------------------------------- line endings git converts
def test_a_text_artifact_git_converts_gives_one_digest_for_lf_and_crlf(tmp_path):
    data = pickle.dumps({"name": "caf\u00e9", "rows": [1, 2, 3]}, protocol=0)
    assert b"\xe9" in data and _git_text(data)
    digests = set()
    for tag, body in (("lf", data), ("crlf", data.replace(b"\n", b"\r\n"))):
        _write(tmp_path / tag, "model.pkl", body)
        _write(tmp_path / tag, "app.py", "x = 1\n")
        r = audit(tmp_path / tag, label="t")
        digests.add((r.subject_digest, r.findings_digest))
    assert len(digests) == 1


@pytest.mark.parametrize("data, text", [(b"plain text\n", True), (b"caf\xe9\n", True), (b"a\x00b", False),
                                        (b"lone\rcr\n", False), (bytes(range(1, 32)) * 4, False),
                                        (b"x" * 128 + b"\x01", True), (b"x" * 127 + b"\x01", False)])
def test_git_text_is_git_s_rule(data, text):
    assert _git_text(data) is text


# ---------------------------------------------------------------- CSAF tracking ids
def test_one_label_two_trees_give_two_csaf_tracking_ids(tmp_path):
    _write(tmp_path / "a", "x.py", "import hashlib\nhashlib.md5(b'x')\n")
    _write(tmp_path / "b", "x.py", "import hashlib\nhashlib.md5(b'x')\nhashlib.md5(b'y')\n")
    _write(tmp_path / "b", "y.py", "import hashlib\nhashlib.md5(b'z')\n")
    ids = set()
    for tree in ("a", "b", "a"):
        doc = csaf.to_csaf(asdict(cbom.build_cbom(tmp_path / tree, label="same")), publisher_name="P",
                           publisher_namespace="https://example.com")
        ids.add((tree, doc["document"]["tracking"]["id"]))
    assert len({i for _, i in ids}) == 2


# ---------------------------------------------------------------- CI containers
def test_an_azure_container_alias_is_not_an_image(tmp_path):
    _write(tmp_path, "azure-pipelines.yml",
           "resources:\n  containers:\n    - container: py\n      image: python:3.12\njobs:\n- job: a\n  container: py\n"
           "  steps:\n  - script: echo hi\n- job: b\n  container: ubuntu:22.04\n")
    got = [(f[1], f[3].split(": the")[0]) for f in _found(tmp_path) if f[2] == "declared-remote-source"]
    assert got == [(4, "image: python:3.12"), (11, "image: ubuntu:22.04")]


def test_a_gitlab_file_included_by_path_and_an_action_image_are_read(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", "include:\n  - local: ci/build.gitlab-ci.yml\n  - local: /ci/test.yml\n")
    _write(tmp_path, "ci/build.gitlab-ci.yml", "build:\n  script:\n    - curl -fsSL https://example.com/i.sh | sh\n")
    _write(tmp_path, "ci/test.yml", "t:\n  image: python:3.12\n  script:\n    - pip install x\n")
    _write(tmp_path, "ci/unused.yml", "t:\n  script:\n    - pip install y\n")
    _write(tmp_path, "action.yml", "name: x\nruns:\n  using: docker\n  image: docker://ghcr.io/example/tool:1\n")
    _write(tmp_path, "local/action.yml", "name: y\nruns:\n  using: docker\n  image: Dockerfile\n")
    got = sorted((f[0], f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url")
    assert got == [("action.yml", 4, "declared-remote-source"), ("ci/build.gitlab-ci.yml", 3, "script-network-command"),
                   ("ci/test.yml", 2, "declared-remote-source"), ("ci/test.yml", 4, "script-network-command")]


# ---------------------------------------------------------------- pages and modules
@pytest.mark.parametrize("rel, text, kind", [
    ("index.html", '<base href="https://cdn.example.com/"><img src="logo.png">\n', "html-external"),
    ("index.html", "<base href='https://h.example/'>\n", None),
    ("index.html", "<script type=\"module\">import confetti from 'https://cdn.example.com/c.js';</script>\n",
     "network-import"),
    ("main.ts", "import { serve } from 'https://deno.land/std@0.200.0/http/server.ts';\n", "network-import"),
    ("l.js", "import x from 'http://localhost:8000/m.js';\n", "loopback-call"),
])
def test_a_base_address_and_a_module_imported_by_address_are_loads(tmp_path, rel, text, kind):
    _write(tmp_path, rel, text)
    kinds = _kinds(tmp_path)
    assert (kind in kinds) if kind else not ({"html-external", "network-import"} & kinds), text


@pytest.mark.parametrize("line, kind", [
    ("for (const name of config.plugins) { require(name); }", "dynamic-exec"),
    ("const r = require(`./locale/${lang}`)", "dynamic-exec"),
    ("const x = require('fs');", None), ("require.resolve(p)", None), ("function require(x) {}", None),
    ("const x = require(`fs`)", None),
])
def test_a_module_loaded_by_a_computed_name_is_reported(tmp_path, line, kind):
    _write(tmp_path, "a.js", line + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), line


# ---------------------------------------------------------------- YAML folded commands
@pytest.mark.parametrize("step, kind", [
    ("      - run: pip\n          install requests\n", "script-network-command"),
    ("      - run: >-\n          npm\n          install\n", "script-network-command"),
    ("      - run: |\n          npm\n          install\n", None),
    ("      - run: echo hi\n        name: x\n", None),
])
def test_a_folded_or_continued_command_is_read_as_yaml_joins_it(tmp_path, step, kind):
    _write(tmp_path, ".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n" + step)
    assert _kinds(tmp_path) == ({kind} if kind else set()), step


# ---------------------------------------------------------------- argv lists and task runners
@pytest.mark.parametrize("code, kind", [
    ("import subprocess\nCURL = ['curl', '-fsSL']\nsubprocess.run([*CURL, 'https://example.com/i.sh'])\n",
     "subprocess-net-binary"),
    ("import shutil, subprocess\nGIT = shutil.which('git')\nsubprocess.run([GIT, 'clone', 'https://x.example/r'])\n",
     "git-remote"),
    ("import shutil, subprocess\nsubprocess.run([shutil.which('git'), 'clone', 'https://x.example/r'])\n", "git-remote"),
    ("import subprocess\nOPTS = ['-x']\nsubprocess.run(['ls', *OPTS])\n", None),
])
def test_an_argv_built_from_a_list_or_from_which_is_read(tmp_path, code, kind):
    _write(tmp_path, "a.py", code)
    assert _kinds(tmp_path) == ({kind} if kind else set()), code


def test_nox_and_invoke_tasks_run_commands(tmp_path):
    _write(tmp_path, "noxfile.py", "import nox\n@nox.session\ndef docs(session):\n"
                                   "    session.run('git', 'clone', 'https://x.example/theme', external=True)\n"
                                   "    session.run('curl', '-O', 'https://x.example/d.zip', external=True)\n"
                                   "    session.run('pytest')\n")
    _write(tmp_path, "tasks.py", "from invoke import task\n@task\ndef fetch(c):\n"
                                 "    c.run('curl -fsSL https://x.example/d.zip -o d.zip')\n    c.run('pytest -q')\n")
    _write(tmp_path, "other.py", "def f(session):\n    session.run('curl', 'x')\n")
    got = sorted((f[0], f[1], f[2]) for f in _found(tmp_path) if f[2] not in ("external-url", "network-import"))
    assert got == [("noxfile.py", 4, "git-remote"), ("noxfile.py", 5, "subprocess-net-binary"),
                   ("tasks.py", 4, "script-network-command")]


# ---------------------------------------------------------------- signed Statements
def test_a_signed_statement_is_checked_by_verify(tmp_path):
    _write(tmp_path / "t", "app.py", "import requests\n")
    signer = MerkleSigner.create(tmp_path / "key.json", height=3)
    root = signer.public_root
    st = attestation.to_statement(asdict(audit(tmp_path / "t", label="x", signer=signer)))
    assert attestation.verify_statement(st, root) == (True, "ATTESTED")
    assert attestation.verify_statement(st) == (False, "UNVERIFIED")
    assert attestation.verify_statement(st, "0" * 64) == (False, "TAMPERED")
    for edit in (lambda s: s["predicate"].update(verdict="CLEAN", findings=[]),
                 lambda s: s["subject"][0]["digest"].update({"sha3_256": "0" * 64}),
                 lambda s: s.update(predicateType=attestation.PREDICATE_TYPE_CBOM)):
        bad = copy.deepcopy(st)
        edit(bad)
        assert attestation.verify_statement(bad, root) == (False, "TAMPERED")
    unsigned = attestation.to_statement(asdict(audit(tmp_path / "t", label="x")))
    assert attestation.verify_statement(unsigned, root) == (False, "UNSIGNED")
    f = tmp_path / "s.json"
    f.write_text(json.dumps(st), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "entrovouch.verify", str(f), "--root", root], cwd=ROOT,
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 0 and "ATTESTED" in r.stdout


# ---------------------------------------------------------------- JSON Web Keys
def test_a_private_or_symmetric_json_web_key_is_found_and_a_public_one_is_not(tmp_path):
    _write(tmp_path, "jwks.json", json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "s"}]},
                                             indent=1))
    _write(tmp_path, "k.jwk", json.dumps({"kty": "oct", "k": "c2VjcmV0"}))
    _write(tmp_path, "public.jwks", json.dumps({"keys": [{"kty": "RSA", "n": "abc", "e": "AQAB"}]}))
    found = asdict(key_provenance.scan_key_provenance(tmp_path))["findings"]
    assert sorted(f["file"] for f in found) == ["jwks.json", "k.jwk"]


# ---------------------------------------------------------------- Jenkins, notebooks, versions, help
def test_a_jenkins_step_runs_its_string(tmp_path):
    _write(tmp_path, "Jenkinsfile", "pipeline { agent any\n stages { stage('get') { steps {\n"
                                    "  sh 'curl -fsSL https://example.com/i.sh -o i.sh'\n  bat \"pip install x\"\n"
                                    "  sh(script: 'echo hi')\n  echo 'curl is used'\n } } } }\n")
    assert [(f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url"] == [
        (3, "script-network-command"), (4, "script-network-command")]


def test_an_indented_escape_in_a_notebook_function_is_read_and_the_cell_parses(tmp_path):
    nb = {"cells": [{"cell_type": "code", "metadata": {}, "source": "def f():\n    !curl https://x.example\n",
                     "outputs": [], "execution_count": None}],
          "metadata": {"kernelspec": {"language": "python", "name": "python3"}}, "nbformat": 4, "nbformat_minor": 5}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    assert _kinds(tmp_path) == {"subprocess-shell"}


@pytest.mark.parametrize("spec, version", [("six==v1.16.0", "1.16.0"), ("six==1.16.0", "1.16.0"), ("six==vX", None)])
def test_a_v_prefixed_pin_is_the_version_pep_440_reads(spec, version):
    assert pinned_pypi_version(spec) == version


def test_storage_readers_of_spark_take_store_addresses(tmp_path):
    _write(tmp_path, "a.py", "df = spark.read.csv('s3a://b/raw.csv')\ndf.write.parquet('s3://b/out')\n"
                             "spark.read.csv('data/x.csv')\n")
    assert [(f[1], f[2]) for f in _found(tmp_path)] == [(1, "unresolved-call"), (2, "unresolved-call")]

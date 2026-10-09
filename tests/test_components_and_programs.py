"""Imports in component files, PowerShell's .NET clients, Python that a Dockerfile, a container or a pipeline step
runs, programs judged by their arguments on a script line, notebook cells in other languages, archives read to the
end or named, and digests that do not depend on line endings or on the Python's Unicode version. Each test asserts
both halves where there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import base64
import bz2
import gzip
import io
import json
import lzma
import tarfile
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import csaf, key_provenance, sarif, timestamp
from entrovouch.no_egress_auditor import _strip_js_comments, audit, tree_listing_digest

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    return p


def _kinds(root: Path) -> list[tuple[int, str]]:
    return [(f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _kp_report(root: Path) -> dict:
    return asdict(key_provenance.scan_key_provenance(root, label="t"))


# ---------------------------------------------------------------- components: their imports are imports
@pytest.mark.parametrize("name, text", [
    ("Api.vue", '<template><p>x</p></template>\n<script>\nimport axios from "axios";\n</script>\n'),
    ("Api.svelte", '<script>\n  import axios from "axios";\n</script>\n<p>x</p>\n'),
    ("page.astro", '---\nimport pg from "pg";\nconst c = new pg.Client();\n---\n<p>ok</p>\n'),
    ("doc.mdx", 'import { request } from "undici";\n\n# Title\n'),
])
def test_an_import_in_a_component_file_is_read(tmp_path, name, text):
    _write(tmp_path, name, text)
    assert any(kind == "network-import" for _, kind in _kinds(tmp_path))


def test_a_component_import_no_list_names_is_listed_and_fenced_code_is_text(tmp_path):
    _write(tmp_path, "A.vue", '<script setup>\nimport thing from "some-unknown-pkg";\n</script>\n')
    _write(tmp_path, "b.mdx", '# Docs\n\n```js\nimport axios from "axios";\n```\n')
    rep = audit(tmp_path, label="t")
    assert rep.unlisted_js_imports == ["some-unknown-pkg"]
    assert not any(f["kind"] == "network-import" for f in rep.findings)


# ---------------------------------------------------------------- JavaScript neighbours
def test_minified_imports_and_a_lone_backquote_hide_no_code(tmp_path):
    _write(tmp_path, "bundle.mjs", 'import{serve as s}from"https://deno.land/std/http/server.ts";'
                                   'const h=require("https");h.get(process.env.U)\n')
    _write(tmp_path, "Help.jsx", "export const Help = () => <p>Press the ` key.</p>;\n"
                                 "const net = require(\"net\");\n")
    found = audit(tmp_path, label="t").findings
    assert {(f["file"], f["kind"]) for f in found} >= {("bundle.mjs", "network-import"), ("Help.jsx", "network-import")}
    # a real template literal still holds its text: nothing inside it is code
    _write(tmp_path / "t", "t.js", "const s = `require(\"net\")`;\n")
    assert _kinds(tmp_path / "t") == []


def test_a_letter_beyond_ascii_is_read_the_same_way_under_every_python():
    # U+1C89 is a letter to Python 3.14 and unassigned to 3.11-3.13; U+E0080 is unassigned everywhere
    for ch in ("\u1c89", "\U000e0080"):
        assert _strip_js_comments(f"const u = {ch}' fetch(x) ';\n") == f"const u = {ch}' fetch(x) ';\n"
        assert "fetch" in _strip_js_comments(f"const u = {ch}' fetch(x) ';\n", blank_strings=True)


@pytest.mark.parametrize("code", [
    'Deno.connect({hostname: "h", port: 443})', 'Bun.connect({hostname: "h", port: 1})',
    "globalThis?.fetch?.(u)", "window[`fetch`](u)", "const {fetch: f} = globalThis; f(u)",
    "const t = new WebTransport(u)", "const p = new RTCPeerConnection(c)",
])
def test_runtime_clients_and_other_spellings_of_fetch_are_calls(tmp_path, code):
    _write(tmp_path, "a.js", code + "\n")
    assert (1, "network-call") in _kinds(tmp_path)


def test_loaders_and_code_from_strings(tmp_path):
    _write(tmp_path, "a.js", 'import { createRequire } from "module";\ncreateRequire(import.meta.url)("https");\n'
                             'require.call(null, "net");\nvm.runInThisContext(code);\nnew Worker(c, {eval: true});\n')
    found = _kinds(tmp_path)
    assert (2, "network-import") in found and (3, "network-import") in found
    assert (4, "dynamic-exec") in found and (5, "dynamic-exec") in found


def test_src_on_a_created_element_is_reported_and_a_config_src_is_not(tmp_path):
    _write(tmp_path, "a.js", "const i = new Image();\ni.src = cfg.pixel;\n")
    _write(tmp_path / "b", "gulpfile.js", 'const config = {};\nconfig.src = "src/";\n')
    assert (2, "unresolved-call") in _kinds(tmp_path)
    assert _kinds(tmp_path / "b") == []


# ---------------------------------------------------------------- PowerShell's .NET clients
@pytest.mark.parametrize("text", [
    '(New-Object System.Net.WebClient).DownloadFile($env:URL, "payload.zip")\n',
    "$wc.DownloadString($u)\n",
    "$c = [System.Net.WebClient]::new()\n",
    "$t = New-Object System.Net.Sockets.TcpClient\n",
])
def test_dotnet_network_clients_are_commands(tmp_path, text):
    _write(tmp_path, "get.ps1", text)
    assert _kinds(tmp_path) == [(1, "script-network-command")]


def test_a_file_object_opened_for_reading_is_not_a_download(tmp_path):
    _write(tmp_path, "local.ps1", "$s = (Get-Item a.txt).OpenRead()\n$t = [System.IO.File]::ReadAllText('a.txt')\n")
    assert _kinds(tmp_path) == []


def test_an_encoded_command_is_decoded_and_read(tmp_path):
    enc = base64.b64encode("Invoke-WebRequest $u".encode("utf-16-le")).decode()
    plain = base64.b64encode("Get-ChildItem .".encode("utf-16-le")).decode()
    _write(tmp_path, "e.ps1", f"powershell -EncodedCommand {enc}\npwsh -enc {plain}\n")
    assert _kinds(tmp_path) == [(1, "script-network-command")]


# ---------------------------------------------------------------- Python a Dockerfile, a container, a step runs
PY = 'import urllib.request, os\nurllib.request.urlopen(os.environ["U"])\n'


@pytest.mark.parametrize("name, text", [
    ("Dockerfile", "RUN python3 <<EOF\n" + PY + "EOF\n"),
    ("Dockerfile", "RUN <<EOF\n#!/usr/bin/env python3\n" + PY + "EOF\n"),
    ("a.sh", "docker exec -i app python - <<EOF\n" + PY + "EOF\n"),
    ("b.sh", "kubectl exec -i pod -- python3 - <<EOF\n" + PY + "EOF\n"),
    ("c.sh", "<<EOF python3\n" + PY + "EOF\n"),
    ("d.sh", "cat <<A; python3 - <<B\nhello\nA\n" + PY + "B\n"),
])
def test_python_handed_over_in_more_shapes_is_read(tmp_path, name, text):
    _write(tmp_path, name, text)
    assert any(kind == "network-import" for _, kind in _kinds(tmp_path))


def test_another_program_in_the_container_still_reads_the_body_as_commands(tmp_path):
    _write(tmp_path, "a.sh", "docker run -i python bash <<EOF\ncurl -s $U\nEOF\n")
    # line 1 runs a container (pulled when absent); line 2 is bash's command, not Python
    assert _kinds(tmp_path) == [(1, "script-network-command"), (2, "script-network-command")]


@pytest.mark.parametrize("name, line", [
    ("c.sh", "python3 <<< 'import urllib.request, os; urllib.request.urlopen(os.environ[\"U\"])'\n"),
    ("setup.cmd", "py -3 -c \"import urllib.request,os; urllib.request.urlopen(os.environ['U'])\"\n"),
    ("setup2.cmd", "py -3.12 -c \"import urllib.request,os; urllib.request.urlopen(os.environ['U'])\"\n"),
    ("e.sh", "env PYTHONPATH=" + "x" * 2400 + " python3 -c \"import socket; socket.create_connection(('h', 1))\"\n"),
    ("q.sh", 'python3 -c $"import socket"\n'),
    ("q2.sh", "python3 -c import\\ socket\n"),
])
def test_inline_python_in_more_spellings_is_read(tmp_path, name, line):
    _write(tmp_path, name, line)
    assert any(kind == "network-import" for _, kind in _kinds(tmp_path))


@pytest.mark.parametrize("opener", ['"${SHELL:-/bin/sh}"', '"$BASH"', '"$0"'])
def test_a_shell_named_by_a_variable_reads_its_body_as_commands(tmp_path, opener):
    _write(tmp_path, "f.sh", f"{opener} <<EOF\ncurl -fsSL \"$U\" -o /tmp/x\nEOF\n")
    assert _kinds(tmp_path) == [(2, "script-network-command")]


def test_a_shell_python_step_is_read_as_python(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml",
           "jobs:\n  b:\n    steps:\n      - shell: python\n        run: |\n          " + PY.replace("\n", "\n          ")
           + "\n      - run: |\n          curl -s $U\n")
    found = _kinds(tmp_path)
    assert (6, "network-import") in found and (10, "script-network-command") in found


# ---------------------------------------------------------------- programs judged by their arguments
@pytest.mark.parametrize("line", [
    "aws s3 cp s3://bucket/model.bin ./model.bin", "gsutil ls gs://bucket", "kubectl apply -f deploy.yaml",
    "docker run --rm alpine:3 true", 'psql -h db.prod.internal -U app -c "select 1"',
    "openssl s_client -connect $HOST:443", "hg clone $R", "svn checkout $R", "git remote update",
    "socat - TCP:$HOST:80", "pip3.11 install -r extra.txt", "exec 3<>/dev/tcp/$HOST/80",
])
def test_a_network_program_on_a_script_line_is_a_command(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == [(1, "script-network-command")]


@pytest.mark.parametrize("line", [
    "kubectl config use-context dev", "docker logs app", "svn status", "socat - UNIX-CONNECT:/tmp/s",
    "aws --version", "openssl genrsa -out k.pem 2048",
])
def test_the_same_programs_acting_on_this_machine_are_not(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == []


def test_a_program_named_alone_in_a_list_is_not_run(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", "services:\n  - docker\n")
    assert _kinds(tmp_path) == []


@pytest.mark.parametrize("line", [
    "pip install --no-index --find-links ./wheels -r requirements.txt",
    "pip install --no-deps ./dist/pkg-1.0-py3-none-any.whl", "uv sync --offline", "npm ci --offline",
    "conda install --offline ./pkg.tar.bz2", "python -m pip install --no-index --no-build-isolation -e .",
])
def test_an_offline_install_reaches_nothing(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == []


@pytest.mark.parametrize("line", ["pip install --no-deps requests", "pip install --no-deps -e ."])
def test_an_install_that_may_still_fetch_is_reported(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == [(1, "script-network-command")]


@pytest.mark.parametrize("name, line", [
    ("Makefile", "X := $(shell curl -s $(U))"), ("Makefile", "X != curl -s $(U)"),
    ("l.sh", "env X=" + "y" * 2100 + " curl -s $U"), ("r.sh", ">/dev/null curl -s $U"),
    ("r2.sh", "2>/dev/null curl -s $U"), ("co.sh", "coproc curl -s $U"),
    ("w.cmd", "if exist x curl -sL %U%"), ("w2.cmd", 'start "" curl -s %U%'),
])
def test_commands_that_run_are_reported_as_run(tmp_path, name, line):
    _write(tmp_path, name, line + "\n")
    assert _kinds(tmp_path) == [(1, "script-network-command")]


def test_a_make_variable_that_only_holds_a_command_is_a_word(tmp_path):
    _write(tmp_path, "Makefile", "FETCH = curl -s $(U)\n")
    assert _kinds(tmp_path) == [(1, "script-network-word")]


def test_a_base_image_is_pulled_and_a_stage_is_not(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM ghcr.io/org/img:1 AS build\nFROM scratch\nCOPY --from=build /a /a\n"
                                   "COPY --from=nginx:1 /etc/nginx /etc/nginx\n")
    assert _kinds(tmp_path) == [(1, "declared-remote-source"), (4, "declared-remote-source")]


# ---------------------------------------------------------------- notebooks
def _nb(root: Path, cells: list[tuple[str, str]], meta: dict | None = None) -> None:
    data = {"nbformat": 4, "nbformat_minor": 5, "metadata": meta or {},
            "cells": [{"cell_type": t, "metadata": {}, "source": s, **({"outputs": [], "execution_count": None}
                                                                        if t == "code" else {})} for t, s in cells]}
    _write(root, "n.ipynb", json.dumps(data))


def test_notebook_magics_and_shell_calls(tmp_path):
    _nb(tmp_path, [("code", "%uv pip install requests"), ("code", "%sql postgresql://user@db.example.com/x"),
                   ("code", "ip = get_ipython()\nip.system('curl -s $U')"), ("code", "get_ipython().ex('import socket')"),
                   ("code", "%loadpy https://e.example/x.py"), ("code", "%load $u")])
    found = _kinds(tmp_path)
    assert {(1, "subprocess-net-binary"), (2, "network-call"), (3, "subprocess-shell"), (4, "network-import"),
            (5, "network-call"), (6, "unresolved-call")} <= set(found)


def test_display_and_other_language_cells(tmp_path):
    _nb(tmp_path, [("code", "%%markdown\n![x](https://e.example/a.png)"), ("code", "%%javascript\nfetch(window.U)"),
                   ("code", "%%R\ndownload.file(Sys.getenv('U'), 'x')"), ("code", "%%latex\n$x^2$")])
    found = _kinds(tmp_path)
    assert (1, "html-external") in found and (2, "network-call") in found and (3, "unparseable-source") in found
    assert not any(kind == "subprocess-shell" for _, kind in found) and not any(line == 4 for line, _ in found)


def test_a_logging_configuration_naming_a_network_handler(tmp_path):
    _write(tmp_path, "settings.py", "LOGGING = {'handlers': {'h': {'class': 'logging.handlers.HTTPHandler'}}}\n"
                                    "OTHER = {'class': 'logging.handlers.RotatingFileHandler'}\n")
    assert _kinds(tmp_path) == [(1, "network-call")]


# ---------------------------------------------------------------- manifests
def test_manifest_sections_that_name_sources_and_packages(tmp_path):
    _write(tmp_path, "pyproject.toml",
           "[project]\nname = 'x'\n[[tool.pdm.source]]\nname = 'e'\nurl = 'https://pypi.evil.example/simple'\n"
           "[tool.pixi.pypi-dependencies]\nrequests = '*'\n[tool.hatch.envs.default]\ndependencies = ['httpx']\n")
    _write(tmp_path, "setup.cfg", "[easy_install]\nindex_url = https://idx.example/simple\n")
    _write(tmp_path, "package.json", '{"name": "x", "overrides": {"left-pad": "https://evil.example/x.tgz"}}\n')
    found = {(f["file"], f["kind"]) for f in audit(tmp_path, label="t").findings}
    assert {("pyproject.toml", "declared-remote-source"), ("pyproject.toml", "declared-network-dependency"),
            ("setup.cfg", "declared-remote-source"), ("package.json", "declared-remote-source")} <= found


# ---------------------------------------------------------------- what a used checkout leaves
def test_coverage_and_documentation_output_is_skipped(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, "htmlcov/index.html", '<a href="https://coverage.readthedocs.io">coverage.py</a>\n')
    _write(tmp_path, "docs/_build/html/index.html", '<script src="https://cdn.example/a.js"></script>\n')
    _write(tmp_path, ".eggs/x/setup.py", "import requests\n")
    rep = audit(tmp_path, label="t")
    assert rep.verdict == "CLEAN"
    assert set(rep.not_scanned["skipped_directories"]) == {"htmlcov/", "docs/_build/", ".eggs/"}


# ---------------------------------------------------------------- key_provenance: archives to the end
def _tar(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, body in members:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members:
            zf.writestr(name, body)
    return buf.getvalue()


@pytest.mark.parametrize("name, blob", [
    ("backup.tar.gz", gzip.compress(_tar([("var/log/app.log", b"line of a log\n" * 1_500_000),
                                          ("home/u/.ssh/id_rsa", PEM.encode())]))),
    ("two.gz", gzip.compress(b"hello\n") + gzip.compress(PEM.encode())),
    ("two.bz2", bz2.compress(b"hello\n") + bz2.compress(PEM.encode())),
    ("two.xz", lzma.compress(b"hello\n") + lzma.compress(PEM.encode())),
    ("nested.zip", _zip([("inner.zip", _zip([("k.pem.txt", PEM.encode())]))])),
    ("gz-in.zip", _zip([("k.gz", gzip.compress(PEM.encode()))])),
    ("lone.lzma", lzma.compress(PEM.encode(), format=lzma.FORMAT_ALONE)),
], ids=["tar-gz-past-16MiB", "gzip-members", "bzip2-streams", "xz-streams", "zip-in-zip", "gzip-in-zip", "lzma"])
def test_keys_anywhere_in_an_archive_are_found(tmp_path, name, blob):
    (tmp_path / name).write_bytes(blob)
    rep = _kp_report(tmp_path)
    assert any(f["kind"] == "key-file-in-tree" for f in rep["findings"]), rep["findings"]


def test_an_archive_cut_short_by_a_limit_is_named(tmp_path, monkeypatch):
    monkeypatch.setattr(key_provenance, "_ARCHIVE_TOTAL_LIMIT", 1 << 16)
    (tmp_path / "big.gz").write_bytes(gzip.compress(b"x" * (1 << 18) + PEM.encode()))
    rep = _kp_report(tmp_path)
    assert rep["not_scanned"]["archives_not_fully_read"] == ["big.gz"]


def test_base64_armour_and_a_notebook_attachment_are_keys(tmp_path):
    b64 = base64.b64encode(PEM.encode()).decode()
    _write(tmp_path, "secret.yaml", f"apiVersion: v1\nkind: Secret\ndata:\n  tls.key: {b64}\n")
    _nb(tmp_path, [("markdown", "![k](attachment:k.txt)")], meta={"note": b64})
    found = _kp_report(tmp_path)["findings"]
    assert {f["file"] for f in found if f["kind"] == "key-file-in-tree"} == {"secret.yaml", "n.ipynb"}


# ---------------------------------------------------------------- the CBOM listing digest and line endings
def test_a_large_text_file_gives_one_listing_digest_with_either_line_ending(tmp_path):
    row = b"2026-10-06,12345,some text value,another column,3.14159\n"
    lf, crlf = tmp_path / "lf.csv", tmp_path / "crlf.csv"
    lf.write_bytes(row * 300_000)
    crlf.write_bytes(row.replace(b"\n", b"\r\n") * 300_000)
    assert lf.stat().st_size > 16 << 20 and crlf.stat().st_size > 16 << 20
    assert tree_listing_digest([("d.csv", lf)]) == tree_listing_digest([("d.csv", crlf)])
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\x00" + row.replace(b"\n", b"\r\n") * 300_000)
    assert tree_listing_digest([("d.csv", binary)]) != tree_listing_digest([("d.csv", lf)])


# ---------------------------------------------------------------- timestamps, SARIF, CSAF
def test_the_request_is_not_accepted_as_the_token(tmp_path):
    digest = bytes(range(32))
    req, _ = timestamp.build_request(digest, nonce=7)
    assert timestamp.token_contains_digest(req, digest) is False
    response = timestamp._der_seq(timestamp._der_seq(timestamp._der_int(0)), timestamp._der_octet(digest))
    assert timestamp.token_contains_digest(response, digest) is True


def test_a_name_that_is_not_utf8_is_encoded_as_its_bytes():
    name = b"caf\xff.py".decode("utf-8", "surrogateescape")
    assert sarif._uri_reference(name) == "caf%FF.py"
    assert sarif._uri_reference("\ud800.py") == "%ED%A0%80.py"


def test_csaf_notes_use_csaf_words():
    cbom = {"target": "t", "components": [{"file": "f.py", "line": 1, "primitive": "MD5", "category": "hash",
                                           "quantum": "BROKEN"}]}
    text = json.dumps(csaf.to_csaf(cbom, publisher_name="Example Ltd", publisher_namespace="https://example.com"))
    assert "in_triage" not in text and "under_investigation" in text


# ---------------------------------------------------------------- the same programs where they act here
@pytest.mark.parametrize("line", [
    "docker volume rm cache", "docker network create net1", "docker container rm --force app", "docker buildx use b",
    "docker logout", "podman network exists n", "mysql -h127.0.0.1 -uroot -e 'select 1'", "psql peewee_test -c 'x'",
    "psql -h localhost -U postgres -c 'x'", "mongosh --quiet --eval 'rs.status().ok'",
    "openssl s_client -connect localhost:9090", "aws --profile p configure get aws_access_key_id",
    "gcloud auth list", "uv run --no-sync --group aws --with-editable . python x.py", "DB=mysql bash ci/db.sh",
])
def test_programs_acting_here_or_named_as_values_are_not_network_commands(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert not any(kind == "script-network-command" for _, kind in _kinds(tmp_path)), line


@pytest.mark.parametrize("line", [
    "docker buildx build -t x .", "docker manifest push x", "mysql -hmysql-primary -uroot -e 'select 1'",
    "psql -d postgres://u@db.example.com/x -c 'x'", "aws --profile p s3 ls",
])
def test_the_same_programs_reaching_elsewhere_are(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == [(1, "script-network-command")], line


def test_a_key_named_like_a_program_is_not_one(tmp_path):
    _write(tmp_path, "tox.ini", "[testenv]\ndocker =\n    postgres\n")
    assert _kinds(tmp_path) == []


def test_dev_tcp_to_this_machine_is_loopback(tmp_path):
    _write(tmp_path, "a.sh", "bash -c 'echo > /dev/tcp/127.0.0.1/11211'\n(echo > /dev/tcp/$HOST/$PORT)\n")
    assert _kinds(tmp_path) == [(1, "loopback-call"), (2, "script-network-command")]


def test_an_image_made_from_data_loads_nothing(tmp_path):
    _write(tmp_path, "a.js", 'const i = new Image();\ni.src = "data:image/png;base64," + s;\n'
                             'i.src = canvas.toDataURL("image/png");\ni.src = href;\n')
    assert _kinds(tmp_path) == [(4, "unresolved-call")]


def test_make_shell_with_a_wrapper_runs_now(tmp_path):
    _write(tmp_path, "Makefile", "V=$(shell sudo docker run -it img python3 -c 'print(1)')\nW=$(shell echo curl x)\n")
    # line 2 only prints the name: the smaller claim
    assert _kinds(tmp_path) == [(1, "script-network-command"), (2, "script-network-word")]


# ---------------------------------------------------------------- a database host held in a variable is not known
@pytest.mark.parametrize("src", [
    "import subprocess\nsubprocess.run(['psql', target])\n",
    "import subprocess\nsubprocess.run(['timeout', '30', 'mongosh.exe', target])\n",
    "import subprocess\nsubprocess.run(('mysql.exe', '-x', target))\n",
    "import asyncio\nasync def go():\n    await asyncio.create_subprocess_exec('psql', target)\n",
])
def test_a_database_client_given_a_variable_may_reach_anywhere(tmp_path, src):
    _write(tmp_path, "a.py", src)
    assert not any(kind == "loopback-call" for _, kind in _kinds(tmp_path))
    assert any(kind == "subprocess-net-binary" for _, kind in _kinds(tmp_path))


@pytest.mark.parametrize("line, kind", [
    ('psql "$DATABASE_URL" -c "select 1"', "script-network-command"),
    ("mongosh $MONGO_URI --eval 'x'", "script-network-command"),
    ('mysql -e "create database $DB;" -u$USER -p$PW', "loopback-call"),
    ('psql -U "$PGUSER" -c "select 1"', "loopback-call"),
])
def test_a_variable_is_a_host_only_where_a_host_can_be(tmp_path, line, kind):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == [(1, kind)], line

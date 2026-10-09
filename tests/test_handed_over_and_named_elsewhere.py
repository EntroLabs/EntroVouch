"""Python and JavaScript handed over in the shapes scripts use, dependencies named by their distribution, build tools
and package managers of other ecosystems on a script line and in an argv list, what an audit names as unknown,
addresses of object stores and streams, manifests that do not parse, container images in CI files, commands that stay
on this machine, compatibility-layer imports and file names Windows shortens. Each test asserts both halves where
there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import gzip
import io
import json
import os
import time
import zipfile
from dataclasses import asdict
from pathlib import Path, PurePath

import pytest

from entrovouch import key_provenance, manifests, sbom
from entrovouch import _reads
from entrovouch.no_egress_auditor import audit

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
       + "-----END RSA PRIVATE KEY-----\n")


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


# ---------------------------------------------------------------- Python handed over in common shapes
def test_a_python_c_program_over_several_lines_is_read_at_its_own_lines(tmp_path):
    _write(tmp_path, "wait.sh", "#!/bin/sh\npython3 -c '\nimport socket, os\n"
                                "socket.create_connection((os.environ[\"DB_HOST\"], 5432), timeout=2)\n'\necho done\n")
    found = _found(tmp_path)
    assert ("wait.sh", 3, "network-import") in [f[:3] for f in found]
    assert all("inline" in f[3] for f in found if f[2] in ("network-import", "network-call"))


def test_a_python_c_program_in_a_workflow_block_is_read(tmp_path):
    _write(tmp_path, ".github/workflows/notify.yml",
           "on: push\njobs:\n  n:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          python -c \"\n"
           "          import json, os, urllib.request\n"
           "          urllib.request.urlopen(os.environ['SLACK_WEBHOOK'])\n          \"\n")
    lines = {f[1] for f in _found(tmp_path) if f[2] == "network-import"}
    assert lines == {8}


def test_a_multi_line_python_c_that_imports_nothing_is_silent_and_the_command_after_it_is_read(tmp_path):
    _write(tmp_path, "a.sh", "python3 -c \"\nimport json\nprint(json.dumps({}))\n\" && curl -s https://example.com\n")
    found = _found(tmp_path)
    assert [f[2] for f in found] == ["script-network-command"]


def test_python_through_a_wrapper_written_as_a_path(tmp_path):
    _write(tmp_path, "a.sh", "/usr/bin/env python3 -c 'import socket, os; "
                             "socket.create_connection((os.environ[\"H\"], 80))'\n/usr/bin/env curl -s https://x.example\n")
    kinds = [f[2] for f in _found(tmp_path)]
    assert "network-import" in kinds and "script-network-command" in kinds


@pytest.mark.parametrize("opening, closing", [
    ("until python3 - <<'EOF'", "do sleep 1; done"),
    ("if ! python3 <<'EOF'", "then exit 1; fi"),
    ("OUT=$(python3 <<'EOF'", ")"),
    ("while ! python3 - <<'EOF'", "do sleep 1; done"),
])
def test_a_here_document_after_a_shell_keyword_or_inside_a_substitution_is_python(tmp_path, opening, closing):
    _write(tmp_path, "a.sh", f"{opening}\nimport socket, os\nsocket.create_connection((os.environ['H'], 80))\nEOF\n"
                             f"{closing}\n")
    found = _found(tmp_path)
    assert ("a.sh", 2, "network-import") in [f[:3] for f in found], opening


def test_a_here_document_inside_a_substitution_handed_to_cat_is_text(tmp_path):
    _write(tmp_path, "a.sh", "OUT=$(cat <<'EOF'\nimport socket\nEOF\n)\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- dependencies by their distribution name
@pytest.mark.parametrize("dist", [
    "grpcio", "psycopg2-binary", "google-cloud-storage", "azure-storage-blob", "kafka-python",
    "opentelemetry-exporter-otlp", "websocket-client", "python-socketio", "paho-mqtt", "elastic-apm", "dnspython",
    "mysql-connector-python", "mysqlclient", "python-telegram-bot", "PyGithub", "python-gitlab", "discord.py",
    "snowflake-connector-python", "influxdb-client", "O365",
])
def test_a_python_distribution_is_matched_to_the_module_it_installs(tmp_path, dist):
    _write(tmp_path, "requirements.txt", dist + "\n")
    assert _kinds(tmp_path) == {"declared-network-dependency"}, dist


@pytest.mark.parametrize("dist", ["numpy", "google-auth", "grpcio-tools", "googletrans", "azurx", "opentelemetry-api",
                                  "opentelemetry-sdk", "opentelemetry-instrumentation-requests"])
def test_a_distribution_that_is_not_a_network_client_stays_silent(tmp_path, dist):
    _write(tmp_path, "requirements.txt", dist + "\n")
    assert _kinds(tmp_path) == set(), dist


def test_a_scoped_npm_package_is_matched_by_its_scope(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {
        "@sentry/node": "^8", "@aws-sdk/client-s3": "^3", "@slack/web-api": "^7", "@types/node": "^20"}}, indent=1))
    named = {f[3].split("'")[1] for f in _found(tmp_path) if f[2] == "declared-network-dependency"}
    assert named == {"@sentry/node", "@aws-sdk/client-s3", "@slack/web-api"}


# ---------------------------------------------------------------- build tools and package managers
@pytest.mark.parametrize("line", [
    "go build ./...", "go test ./...", "go run ./cmd/x", "flutter pub get", "dart pub get", "pod install",
    "swift package resolve", "mix deps.get", "bazel build //...", "sbt compile", "conan install .", "vcpkg install zlib",
    "cabal update", "stack build", "apt-get upgrade -y", "yum update -y", "brew update", "gem update",
    "pip wheel -r r.txt", "pip-compile requirements.in", "tox -e py311", "nox -s tests", "pre-commit run --all-files",
    "huggingface-cli download gpt2", "kaggle datasets download -d x/y", "dvc pull", "ollama pull llama3",
    "dotnet run", "dotnet add package X", "wasm-pack build", "lein deps", "elm install", "opam install x",
    "luarocks install x", "cpanm Foo", "rebar3 get-deps", "pulumi up", "vagrant up", "packer build x",
])
def test_a_build_tool_or_package_manager_that_downloads_is_a_command(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert "script-network-command" in _kinds(tmp_path), line


@pytest.mark.parametrize("line", [
    "yarn --version", "yarn -v", "yarn --help", "dotnet build --no-restore", "dotnet test --no-restore --no-build",
    "dotnet build --source ./packages", "cargo test --frozen", "GOFLAGS=-mod=vendor go build ./...",
    "go build -mod=vendor ./...", "GOPROXY=off go test ./...", "go mod verify", "pre-commit install", "mix compile",
    "sbt --version", "tox --version",
])
def test_the_same_tools_told_to_stay_here_or_asked_about_themselves_are_silent(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == set(), line


@pytest.mark.parametrize("argv, reported", [
    ("['go', 'get', 'example.com/mod@latest']", True), ("['cargo', 'install', 'ripgrep']", True),
    ("['gem', 'install', 'bundler']", True), ("['mvn', 'package']", True), ("['poetry', 'install']", True),
    ("['bundle', 'install']", True), ("['flutter', 'pub', 'get']", True), ("['whois', 'example.com']", True),
    ("['mvn', '-o', 'package']", False), ("['dotnet', 'build', '--no-restore']", False),
    ("['cargo', '--version']", False), ("['go', 'version']", False), ("['make', 'all']", False),
])
def test_a_package_manager_in_a_python_argv_list(tmp_path, argv, reported):
    _write(tmp_path, "tools.py", f"import subprocess\nsubprocess.run({argv}, check=True)\n")
    assert ("subprocess-net-binary" in _kinds(tmp_path)) is reported, argv


# ---------------------------------------------------------------- unlisted imports from every place Python is read
def test_unknown_imports_in_embedded_python_and_in_classes_loaded_by_name_are_named(tmp_path):
    _write(tmp_path, "fetch.sh", "#!/bin/sh\npython3 -c 'import treq, os; treq.get(os.environ[\"URL\"])'\n")
    _write(tmp_path, "settings.py", "LOGGING = {'handlers': {'h': {'class': 'acme_logs.handlers.ShipHandler'}}}\n"
                                    "MIDDLEWARE = ['mylocal.mw.X']\n")
    _write(tmp_path, "mylocal/mw.py", "X = 1\n")
    assert audit(tmp_path, label="t").unlisted_imports == ["acme_logs", "treq"]


# ---------------------------------------------------------------- one report for LF and CRLF at the size limit
def test_a_text_artifact_at_the_size_limit_reads_the_same_with_either_line_ending(tmp_path):
    line = "whois sample record line with plain ascii text\n"
    lf = (line * ((1 << 20) // len(line) - 10)).encode()
    digests = set()
    for tag, data in (("lf", lf), ("crlf", lf.replace(b"\n", b"\r\n"))):
        root = tmp_path / tag
        _write(root, "app.py", "x = 1\n")
        _write(root, "google.so", data)
        r = asdict(audit(root, label="t"))
        digests.add((r["findings_digest"], r["subject_digest"], json.dumps(r["not_scanned"], sort_keys=True)))
    assert len(digests) == 1


# ---------------------------------------------------------------- one extension rule on every interpreter
def test_a_name_ending_in_a_dot_has_no_extension_on_every_interpreter():
    assert _reads.suffix_of(PurePath("run.")) == ""
    assert _reads.suffix_of(PurePath("a.b.")) == ""
    assert _reads.suffix_of(PurePath("run.py")) == ".py"
    assert _reads.suffix_of(PurePath("Makefile")) == ""


# ---------------------------------------------------------------- archives under any name
@pytest.mark.parametrize("name", ["backup", "backup.txt", "keys.json", "id_rsa", "notes.md"])
def test_key_provenance_opens_an_archive_whatever_it_is_named(tmp_path, name):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("k.pem", PEM)
    _write(tmp_path, name, b.getvalue())
    _write(tmp_path, "plain.txt", "hello\n")
    found = asdict(key_provenance.scan_key_provenance(tmp_path))["findings"]
    assert [(f["file"], "inside this archive" in f["detail"]) for f in found] == [(name, True)]


def test_key_provenance_opens_a_compressed_file_under_a_config_name(tmp_path):
    _write(tmp_path, "conf.yaml", gzip.compress(PEM.encode()))
    found = asdict(key_provenance.scan_key_provenance(tmp_path))["findings"]
    assert [f["file"] for f in found] == ["conf.yaml"]


# ---------------------------------------------------------------- addresses of stores, hubs and streams
@pytest.mark.parametrize("code, kind", [
    ("import pandas as pd\npd.read_csv('s3://acme/x.csv')\n", "network-call"),
    ("import pandas as pd\npd.read_parquet('gs://b/x.parquet')\n", "network-call"),
    ("import cv2\ncv2.VideoCapture('rtsp://cam.example/stream')\n", "network-call"),
    ("import git\ngit.Repo.clone_from('https://example.com/acme/r', 'r')\n", "network-call"),
    ("import keras\nkeras.utils.get_file('m.h5', 'https://x.example/m.h5')\n", "network-call"),
    ("import pandas as pd\npd.read_csv('hdfs://localhost:8020/x')\n", "loopback-call"),
    ("cfg.load('s3://b/k')\n", "unresolved-call"),
])
def test_an_address_written_in_the_file_and_handed_to_a_reader_is_reported(tmp_path, code, kind):
    _write(tmp_path, "load.py", code)
    lines = [f for f in _found(tmp_path) if f[1] == code.count("\n")]
    assert [f[2] for f in lines] == [kind], code


@pytest.mark.parametrize("code", [
    "x = 's3://bucket/key'\n", "open('s3://x/y')\n", "import pandas as pd\npd.read_csv('data/s3://x')\n",
    "import cv2\ncv2.VideoCapture(0)\n",
])
def test_an_address_not_handed_to_a_reader_is_not_a_call(tmp_path, code):
    _write(tmp_path, "load.py", code)
    assert [f for f in _found(tmp_path) if f[2] in ("network-call", "unresolved-call", "loopback-call")] == []


# ---------------------------------------------------------------- manifests: line lookup and parse errors
def test_manifest_line_lookups_scale_with_the_file(tmp_path):
    big = "[project]\n" + "".join(f"p{i} = '1'\n" for i in range(20000))
    start = time.perf_counter()
    for i in range(0, 20000, 5):
        assert manifests._line_of_key(big, f"p{i}") == i + 2
    assert time.perf_counter() - start < 5
    assert manifests._line_of("a\n# requests\nrequests\n", "requests") == 3
    assert manifests._line_of_key("[a]\nx = 1\n[b]\nx = 2\n", "x", section="b") == 4


@pytest.mark.parametrize("name, text", [
    ("Pipfile", "[packages\nrequests = '*'\n"), ("setup.cfg", "install_requires = requests\n"),
    ("tox.ini", "deps = requests\n"),
])
def test_a_manifest_that_does_not_parse_is_reported(tmp_path, name, text):
    _write(tmp_path, name, text)
    assert [(f[0], f[2]) for f in _found(tmp_path)] == [(name, "unparseable-source")]


def test_a_manifest_that_parses_reports_no_parse_error(tmp_path):
    _write(tmp_path, "tox.ini", "[testenv]\ndeps = pytest\n")
    _write(tmp_path, "setup.cfg", "[metadata]\nname = x\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- JavaScript handed over on a script line
@pytest.mark.parametrize("line, kind", [
    ("node -e \"fetch('https://x.example/a')\"", "network-call"),
    ("bun -e \"require('https').get(process.env.U)\"", "network-import"),
    ("deno eval \"await fetch(Deno.env.get('U'))\"", "network-call"),
    ("node --input-type=module -e \"import net from 'node:net'\"", "network-import"),
])
def test_javascript_passed_inline_is_read(tmp_path, line, kind):
    _write(tmp_path, "a.sh", line + "\n")
    assert kind in _kinds(tmp_path), line


@pytest.mark.parametrize("line", ["node -e \"console.log(1)\"", "echo node -e \"fetch(1)\"", "node script.js",
                                  "node -p \"process.version\""])
def test_javascript_that_reaches_nothing_or_is_only_printed_is_silent(tmp_path, line):
    _write(tmp_path, "a.sh", line + "\n")
    assert _kinds(tmp_path) == set(), line


# ---------------------------------------------------------------- notebook assignments from the shell
def _nb(src: str) -> str:
    return json.dumps({"cells": [{"cell_type": "code", "metadata": {}, "source": src, "outputs": [],
                                  "execution_count": None}],
                       "metadata": {"kernelspec": {"language": "python", "name": "python3"}},
                       "nbformat": 4, "nbformat_minor": 5})


@pytest.mark.parametrize("src", ["x = !curl -s https://example.com\nprint(x)\n",
                                 "files = %sx wget http://example.com/f\n", "a, b = !ls\n"])
def test_a_shell_escape_assigned_to_a_name_is_a_shell_escape(tmp_path, src):
    _write(tmp_path, "n.ipynb", _nb(src))
    assert _kinds(tmp_path) == {"subprocess-shell"}, src


@pytest.mark.parametrize("src", ["a = b != c\n", "z = %time 1+1\n"])
def test_a_comparison_or_a_python_magic_assigned_is_not_a_shell_escape(tmp_path, src):
    _write(tmp_path, "n.ipynb", _nb(src))
    assert _kinds(tmp_path) == set(), src


# ---------------------------------------------------------------- commands that stay on this machine
@pytest.mark.parametrize("rel, line, kind", [
    ("a.ps1", "copy \\\\wsl.localhost\\Ubuntu\\x.txt .", "loopback-call"),
    ("a.ps1", "copy \\\\localhost\\c$\\x.txt .", "loopback-call"),
    ("a.ps1", "copy \\\\server\\share\\x .", "script-network-command"),
    ("a.sh", "helm repo list", None), ("a.sh", "helm search repo nginx", None),
    ("a.sh", "helm search hub nginx", "script-network-command"),
    ("a.sh", "kubectl create deployment web --image=nginx --dry-run=client -o yaml", None),
    ("a.sh", "kubectl apply --dry-run=client -f x.yaml", "script-network-command"),
    ("a.sh", "curl -h", None), ("a.sh", "curl file:///etc/hosts", None),
    ("a.sh", "curl file:///x https://e.example", "script-network-command"),
    ("a.sh", "dig @127.0.0.1 example.com", "loopback-call"), ("a.sh", "nslookup example.com 127.0.0.1", "loopback-call"),
    ("a.sh", "nslookup localhost", "script-network-command"), ("a.sh", "sftp localhost", "loopback-call"),
    ("a.sh", "sftp user@example.com", "script-network-command"),
])
def test_a_command_is_judged_by_where_it_connects(tmp_path, rel, line, kind):
    _write(tmp_path, rel, line + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), line


@pytest.mark.parametrize("host, kind", [("127.0.0.1", "loopback-call"), ("::1", "loopback-call"), ("10.0.0.5", None),
                                        ("example.com", "network-call")])
def test_a_numeric_address_is_parsed_not_looked_up(tmp_path, host, kind):
    _write(tmp_path, "a.py", f"import socket\nsocket.getaddrinfo({host!r}, 80)\n")
    assert _kinds(tmp_path) - {"network-import"} == ({kind} if kind else set()), host


# ---------------------------------------------------------------- container images in CI files
def test_container_images_in_ci_files_are_declared_remote_sources(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", "image: python:3.12\nservices:\n  - postgres:16\n  - name: redis:7\n"
                                       "    alias: cache\ntest:\n  image:\n    name: node:20\n  script:\n    - pytest\n")
    _write(tmp_path, ".github/workflows/ci.yml",
           "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    container: node:20\n    services:\n      pg:\n"
           "        image: postgres:16\n    steps:\n      - uses: docker://alpine:3.19\n"
           "      - uses: docker/build-push-action@v5\n        with:\n          image: myorg/app\n")
    _write(tmp_path, ".circleci/config.yml", "version: 2.1\njobs:\n  b:\n    docker:\n      - image: cimg/python:3.12\n")
    _write(tmp_path, "compose.yaml", "services:\n  web: {image: nginx:1.27}\n  app: {build: ., image: me/app}\n")
    _write(tmp_path, "k8s/deploy.yaml", "spec:\n  containers:\n    - image: nginx\n")
    got = {(f[0], f[1]) for f in _found(tmp_path) if f[2] == "declared-remote-source"}
    assert got == {(".gitlab-ci.yml", 1), (".gitlab-ci.yml", 3), (".gitlab-ci.yml", 4), (".gitlab-ci.yml", 8),
                   (".github/workflows/ci.yml", 5), (".github/workflows/ci.yml", 8), (".github/workflows/ci.yml", 10),
                   (".circleci/config.yml", 5), ("compose.yaml", 2)}


def test_a_ci_image_is_read_whole_and_a_runner_name_or_an_alias_is_not_an_image(tmp_path):
    _write(tmp_path, ".github/workflows/c.yml",
           "jobs:\n  t:\n    strategy:\n      matrix:\n        include:\n          - image: macos-15\n"
           "    container: ${{ matrix.c }}\n    services:\n      r:\n        image: \"redis:7\"\n")
    _write(tmp_path, ".circleci/config.yml",
           "defaults: &py\n  - image: &pyimg cimg/python:3.12\njobs:\n  b:\n    docker:\n      - image: *pyimg\n"
           "      - image: cimg/python:<< parameters.v >>\n")
    got = sorted((f[0], f[1], f[3].split(": the image")[0]) for f in _found(tmp_path)
                 if f[2] == "declared-remote-source")
    assert got == [(".circleci/config.yml", 2, "image: cimg/python:3.12"),
                   (".circleci/config.yml", 7, "image: cimg/python:<< parameters.v >>"),
                   (".github/workflows/c.yml", 7, "image: ${{ matrix.c }}"),
                   (".github/workflows/c.yml", 10, "image: redis:7")]


def test_a_tool_is_named_without_its_options(tmp_path):
    _write(tmp_path, "a.sh", "apt-get -y upgrade\n")
    assert [f[3].split(",")[0] for f in _found(tmp_path)] == ["runs 'apt-get upgrade'"]


# ---------------------------------------------------------------- PowerShell
def test_test_connection_and_an_encoded_command_started_as_a_process(tmp_path):
    import base64
    enc = base64.b64encode("Invoke-WebRequest https://example.com".encode("utf-16-le")).decode()
    quiet = base64.b64encode("echo hi".encode("utf-16-le")).decode()
    _write(tmp_path, "a.ps1", "Test-Connection example.com\nTest-Connection -ComputerName localhost\n"
                              f"Start-Process powershell -ArgumentList '-enc','{enc}'\n"
                              f"Start-Process powershell -ArgumentList '-enc','{quiet}'\nStart-Process notepad\n")
    got = [(f[1], f[2]) for f in _found(tmp_path)]
    assert got == [(1, "script-network-command"), (2, "loopback-call"), (3, "script-network-command")]


# ---------------------------------------------------------------- markup
@pytest.mark.parametrize("tag, kind", [
    ('<link rel="alternate stylesheet" href="https://cdn.example/a.css">', "html-external"),
    ('<link rel="alternate" href="https://e.example/fr">', None),
    ('<script src="https:&#47;&#47;cdn.example/x.js"></script>', "html-external"),
    ('<img src="https:&#x2F;&#x2F;cdn.example/x.png">', "html-external"),
    ('<img src="https&colon;//cdn.example/x.png">', "html-external"),
    ('<script>var u = "https:&#47;&#47;x.example";</script>', None),
    ("<p>5&#47;10 items</p>", None),
])
def test_markup_loads_written_with_entities_or_alternate_stylesheets(tmp_path, tag, kind):
    _write(tmp_path, "a.html", tag + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set()), tag


def test_set_attribute_src_on_a_created_element_is_the_same_as_assigning_src(tmp_path):
    _write(tmp_path, "a.js", "const s = document.createElement('img'); s.setAttribute('src', 'https://e.example/p.gif');\n"
                             "el.setAttribute('src', u);\n")
    found = [(f[1], f[2]) for f in _found(tmp_path) if f[2] != "external-url"]
    assert found == [(1, "unresolved-call")]
    assert "an image, a script, a frame or media" in [f for f in _found(tmp_path) if f[1] == 1 and f[2] ==
                                                      "unresolved-call"][0][3]


# ---------------------------------------------------------------- compatibility layers
@pytest.mark.parametrize("code, kind", [
    ("from six.moves.urllib.request import urlopen\n", "network-import"),
    ("from six.moves import http_client\n", "network-import"),
    ("from six.moves import xmlrpc_client\n", "network-import"),
    ("from future.moves.urllib.request import urlopen\n", "network-import"),
    ("import six.moves.urllib.request\n", "network-import"),
    ("from six.moves import socketserver\n", "inbound-listener"),
    ("from six.moves.urllib.parse import urlparse\n", None),
    ("from six.moves import range, zip\n", None),
    ("from six.moves import urllib\n", None),
])
def test_a_compatibility_layer_name_is_the_module_it_stands_for(tmp_path, code, kind):
    _write(tmp_path, "a.py", code)
    assert _kinds(tmp_path) == ({kind} if kind else set()), code


# ---------------------------------------------------------------- SBOM and Windows names
def test_one_declaration_read_twice_is_one_component(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"peerDependencies": {"react": "18"},
                                                 "optionalDependencies": {"react": "18"}}))
    assert len(asdict(sbom.build_sbom(tmp_path))["components"]) == 1


@pytest.mark.skipif(os.name != "nt", reason="a name ending in a dot is shortened only by Windows")
def test_a_windows_name_ending_in_a_dot_is_read_or_listed(tmp_path):
    base = "\\\\?\\" + str(tmp_path)
    with open(base + "\\run.", "w") as f:
        f.write("#!/usr/bin/env python3\nimport requests\n")
    os.mkdir(base + "\\pkg.")
    with open(base + "\\pkg.\\m.py", "w") as f:
        f.write("import socket\n")
    r = asdict(audit(tmp_path, label="t"))
    assert [(f["file"], f["kind"]) for f in r["findings"]] == [("run.", "network-import")]
    assert r["not_scanned"]["skipped_directories"] == {"pkg./": 1}

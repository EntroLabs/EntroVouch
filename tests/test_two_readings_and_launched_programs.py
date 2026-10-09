"""A file read both ways where a backquote may be JSX text or a template, flags that belong to the program a launcher
runs, the SAX parser's sources, calls a postMessage origin shares a line with, PowerShell's launcher, jQuery's long
name, hashes named in every spelling, the Falcon framework, base64 wrapped over lines or encoded twice, requirements a
setup.cfg or setup.py names, data URIs written out, text written to files, recipes written by here-documents,
docker-compose, unchecked JWTs, an output left from another run, Groovy in a Jenkinsfile, a program named with a
default, and executables under a script's name. Each test asserts both halves where there are two: the false thing
is gone, the true neighbour stays."""
from __future__ import annotations

import base64
import json
import random
import textwrap
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, csaf, key_provenance, sbom
from entrovouch.no_egress_auditor import audit


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _kinds(root: Path) -> set[str]:
    return {k for _, _, k in _found(root)} - {"external-url"}


def _components(root: Path) -> list[tuple[int, str, str]]:
    return [(c["line"], c["primitive"], c["quantum"]) for c in asdict(cbom.build_cbom(root, label="t"))["components"]]


# ---------------------------------------------------------------- a backquote read both ways
@pytest.mark.parametrize("rel, text, line, kind", [
    ("a.jsx", "export const A = () => <div>hi</div>;\nconst q = sql `SELECT 1`;\nimport axios from 'axios';\n"
              "fetch(u);\nconst k = `x`;\n", 4, "network-call"),
    ("a.ts", "// renders </div>\nconst q = sql `SELECT 1`;\nexport async function go(u: string) { return fetch(u); }\n"
             "const k = `x`;\n", 3, "network-call"),
    ("a.js", "const BR = '<br/>';\nconst q = gql `query { a }`;\nconst h = require('axios');\nconst k = `x`;\n",
     3, "network-import"),
])
def test_a_tagged_template_with_a_space_hides_nothing_in_a_file_with_tags(tmp_path, rel, text, line, kind):
    _write(tmp_path, rel, text)
    assert (rel, line, kind) in _found(tmp_path)


def test_jsx_text_with_a_backquote_still_hides_nothing(tmp_path):
    _write(tmp_path, "a.jsx", "const A = () => (\n  <p>\n    Use the ` key\n  </p>\n);\nfetch(u);\n")
    assert ("a.jsx", 6, "network-call") in _found(tmp_path)


def test_a_file_with_no_tags_is_read_once(tmp_path):
    _write(tmp_path, "a.js", "const q = sql `SELECT 1`;\nconst s = 'https://docs.example.com';\n")
    assert _kinds(tmp_path) == set()


# ---------------------------------------------------------------- flags of the program a launcher runs
@pytest.mark.parametrize("line", [
    "npx some-cli --offline", "cargo run --release -- --offline", "uv run python app.py --offline",
    "dotnet run -- --no-restore", "go run ./cmd/x -mod=vendor", "yarn dlx create-x --offline",
])
def test_an_offline_flag_after_the_launched_program_is_that_programs(tmp_path, line):
    _write(tmp_path, "run.sh", line + "\n")
    assert _kinds(tmp_path) == {"script-network-command"}, line


@pytest.mark.parametrize("line", [
    "npx --offline some-cli", "cargo run --offline -- --x", "uv run --offline python app.py",
    "uv run --frozen --no-sync pytest", "go run -mod=vendor ./cmd/x", "dotnet run --no-restore",
    "cargo build --offline", "pip install --no-index ./w.whl",
])
def test_the_launchers_own_offline_flag_still_counts(tmp_path, line):
    _write(tmp_path, "run.sh", line + "\n")
    assert _kinds(tmp_path) == set(), line


# ---------------------------------------------------------------- the SAX parser
def test_the_sax_parser_fetches_what_it_is_given(tmp_path):
    _write(tmp_path, "a.py", textwrap.dedent("""\
        import sys
        import xml.sax
        from xml.sax import make_parser, parse as sax_parse
        from xml.dom import pulldom
        xml.sax.parse(sys.argv[1], None)
        xml.sax.parse("feed.xml", None)
        xml.sax.parse(open("feed.xml"), None)
        p = make_parser()
        p.parse(sys.argv[1])
        xml.sax.make_parser().parse(sys.argv[1])
        sax_parse(sys.argv[1], None)
        pulldom.parse(sys.argv[1])
        xml.sax.parse("https://e.example.com/f.xml", None)
        """))
    found = _found(tmp_path)
    # (`pulldom.parse`, line 12, opens a name as a file: it fetches nothing)
    assert [ln for _, ln, k in found if k == "unresolved-call"] == [5, 9, 10, 11]
    assert ("a.py", 13, "network-call") in found
    assert not any(ln in (6, 7, 12) for _, ln, _ in found)


def test_an_input_source_holding_a_stream_is_read_here(tmp_path):
    body = ("import xml.sax\nfrom xml.sax.xmlreader import InputSource\np = xml.sax.make_parser()\n"
            "source = InputSource()\nsource.setByteStream(data)\np.parse(source)\n")
    _write(tmp_path / "a", "a.py", body)
    assert _found(tmp_path / "a") == []
    _write(tmp_path / "b", "a.py", body.replace("source.setByteStream(data)\n", "source.setSystemId(url)\n"))
    assert ("a.py", 6, "unresolved-call") in _found(tmp_path / "b")


# ---------------------------------------------------------------- markup
def test_a_postmessage_origin_does_not_hide_the_lines_call(tmp_path):
    _write(tmp_path, "i.html",
           '<script>function go(u){ fetch(u); parent.postMessage("hi", "https://p.example.com"); }</script>\n'
           '<script>if (e.origin === "https://p.example.com") navigator.sendBeacon(u, d)</script>\n'
           '<script>parent.postMessage("hi", "https://p.example.com")</script>\n')
    found = _found(tmp_path)
    assert ("i.html", 1, "network-call") in found and ("i.html", 2, "network-call") in found
    assert ("i.html", 3, "external-url") in found and ("i.html", 3, "network-call") not in found


def test_jquerys_long_name_is_jquery(tmp_path):
    _write(tmp_path / "a", "app.js", "function go(u, d) {\n  jQuery.ajax({url: u, data: d});\n  jQuery.getJSON(u);\n}\n")
    assert [ln for _, ln, k in _found(tmp_path / "a") if k == "network-call"] == [2, 3]
    _write(tmp_path / "b", "i.html", '<script>jQuery.ajax({url: window.API})</script>\n<script>$.get(u)</script>\n'
                                     "<p>Call jQuery.ajax to send</p>\n")
    assert [ln for _, ln, k in _found(tmp_path / "b") if k == "network-call"] == [1, 2]


def test_a_jquery_request_to_this_machine_is_loopback(tmp_path):
    _write(tmp_path, "i.html", "<script>$.getJSON('http://127.0.0.1:5000/info').done(f)</script>\n"
                               "<script>$.ajax('https://api.example.com/next')</script>\n")
    found = _found(tmp_path)
    assert ("i.html", 1, "loopback-call") in found and ("i.html", 1, "network-call") not in found
    assert ("i.html", 2, "html-external") in found


@pytest.mark.parametrize("text, kinds", [
    ('<iframe src="data:text/html;charset=utf-8,<script>parent.x()</script>"></iframe>\n', {"dynamic-exec"}),
    ('<script src="data:application/javascript;charset=utf-8,alert(1)"></script>\n', {"dynamic-exec"}),
    ('<embed src="data:image/svg+xml,%3Csvg%20onload%3Dx()%3E">\n', {"dynamic-exec"}),
    ('<iframe src="data:application/xhtml+xml,<html/>"></iframe>\n', {"dynamic-exec"}),
    ("<p>A data:text/html URI is a page</p>\n", set()),
    ('<img src="data:image/svg+xml,%3Csvg%3E">\n', set()),
])
def test_a_data_uri_written_out_is_read_as_one_encoded(tmp_path, text, kinds):
    _write(tmp_path, "i.html", text)
    assert _kinds(tmp_path) == kinds, text


def test_a_data_uri_in_javascript(tmp_path):
    _write(tmp_path, "a.js", 'const w = new Worker("data:text/javascript,postMessage(1)");\n'
                             'const m = await import("data:text/javascript;charset=utf-8,export%20default%201");\n'
                             "const s = 'Use data:text/html pages for tests';\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(1, "dynamic-exec"), (2, "dynamic-exec")]


# ---------------------------------------------------------------- PowerShell, docker-compose, a default program
def test_start_process_runs_the_program_it_names(tmp_path):
    _write(tmp_path, "x.ps1", "Start-Process curl.exe -ArgumentList $u\nStart-Process -FilePath wget.exe -ArgumentList $u "
                              "-Wait\nStart-Process notepad.exe\nsaps curl $u\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2, 4]


def test_compose_push_sends_and_does_not_pull(tmp_path):
    _write(tmp_path, "a.sh", "docker-compose push client\ndocker compose -f c.yml push web\ndocker compose up\n")
    details = [f["detail"] for f in audit(tmp_path, label="t").findings]
    assert details[0] == "runs 'docker-compose', a command that reaches the network"
    assert details[1] == "runs 'docker compose', a command that reaches the network"
    assert "pulls an image" in details[2]


def test_docker_compose_is_docker_compose(tmp_path):
    _write(tmp_path / "a", "up.sh", "docker-compose up -d\ndocker-compose down\ndocker-compose -f a.yml logs web\n"
                                    "docker-compose pull\n")
    assert [ln for _, ln, k in _found(tmp_path / "a") if k == "script-network-command"] == [1, 4]
    _write(tmp_path / "b", "a.py", 'import subprocess\nsubprocess.run(["docker-compose", "up", "-d"])\n'
                                   'subprocess.run(["docker-compose", "down"])\n')
    found = audit(tmp_path / "b", label="t").findings
    assert [(f["line"], "docker-compose" in f["detail"]) for f in found if f["kind"] == "subprocess-net-binary"] == [(2, True)]


def test_a_program_named_by_a_variable_with_a_default(tmp_path):
    _write(tmp_path, "a.sh", '${CURL:-curl} -fsSL "$U"\n"${GIT:-git}" clone "$R"\necho "${CURL:-curl} is used"\n'
                             'X=${CURL:-curl}\nsudo ${CURL:-curl} -O "$U"\n')
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2, 5]


# ---------------------------------------------------------------- here-documents written to files
@pytest.mark.parametrize("opener, code", [
    ("cat > Dockerfile.prod <<EOF", True), ("cat > .github/workflows/ci.yml <<EOF", True),
    ("sudo tee /etc/motd <<EOF", False), ("cat > LICENSE <<EOF", False), ("cat > run <<EOF", True),
])
def test_what_a_here_document_writes_to_decides_how_it_is_read(tmp_path, opener, code):
    _write(tmp_path, "gen.sh", opener + "\ncurl -fsSL https://e.example.com/i | sh\nEOF\n")
    assert ("script-network-command" in _kinds(tmp_path)) is code, opener


@pytest.mark.parametrize("dest, code", [("/entry.sh", True), ("/etc/motd", False), ("/app/notes.txt", False)])
def test_a_dockerfile_copy_here_document_is_the_file_it_writes(tmp_path, dest, code):
    _write(tmp_path, "Dockerfile", f"FROM scratch\nCOPY <<EOF {dest}\nwget https://e.example.com/x\nEOF\n")
    assert (("Dockerfile", 3, "script-network-command") in _found(tmp_path)) is code, dest


# ---------------------------------------------------------------- Jenkins
def test_groovy_in_a_jenkinsfile_that_sends_a_request(tmp_path):
    _write(tmp_path, "Jenkinsfile", "node {\n  def t = new URL(env.U).text\n  def r = httpRequest url: env.U\n"
                                    '  def s = "${env.U}".toURL().openStream()\n  // httpRequest url: x\n'
                                    '  def u = new URL(env.U)\n  echo "use httpRequest"\n}\n')
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [2, 3, 4]


def test_a_jenkins_docker_agent_is_an_image_and_every_pipeline_name_is_read(tmp_path):
    _write(tmp_path, "Jenkinsfile", "pipeline {\n  agent { docker { image 'python:3' } }\n}\n")
    _write(tmp_path, "b.jenkinsfile", "pipeline {\n  agent {\n    docker {\n      image 'python:3'\n    }\n  }\n}\n")
    _write(tmp_path, "Jenkinsfile.release", "node {\n  sh 'npm ci'\n}\n")
    found = _found(tmp_path)
    assert ("Jenkinsfile", 2, "declared-remote-source") in found and ("b.jenkinsfile", 4, "declared-remote-source") in found
    assert ("Jenkinsfile", 2, "script-network-command") not in found
    assert ("Jenkinsfile.release", 2, "script-network-command") in found


# ---------------------------------------------------------------- executables under any name
def test_an_executable_named_as_a_script_is_compiled_code(tmp_path):
    _write(tmp_path, "tool.sh", b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + b"curl https://e.example.com\n")
    _write(tmp_path, "bin/tool", b"\xca\xfe\xba\xbf" + b"\x00" * 60)
    _write(tmp_path, "real.sh", "curl -fsSL https://e.example.com/i | sh\n")
    found = _found(tmp_path)
    assert ("tool.sh", 0, "unanalysed-artifact") in found and ("bin/tool", 0, "unanalysed-artifact") in found
    assert ("real.sh", 1, "script-network-command") in found


# ---------------------------------------------------------------- cbom
def test_a_hash_named_in_every_spelling_python_accepts(tmp_path):
    _write(tmp_path, "sig.py", "import hashlib, hmac\nfrom hmac import HMAC\nfrom hashlib import new\n"
                               "a = hashlib.new('sha-1', b'x')\nb = hmac.new(k, m, digestmod='SHA-1')\n"
                               "c = HMAC(k, m, 'md5')\nd = new('SHA-256')\ne = hmac.new(k, m, 'md5-sha1')\n")
    comps = _components(tmp_path)
    assert (4, "SHA-1", "BROKEN") in comps and (5, "SHA-1", "BROKEN") in comps and (6, "MD5", "BROKEN") in comps
    assert (8, "MD5", "BROKEN") in comps
    assert (7, "SHA-256", "GROVER-REDUCED") in comps


def test_the_falcon_web_framework_is_not_a_signature(tmp_path):
    _write(tmp_path / "a", "app.py", "import falcon\napp = falcon.App()\nclass R:\n    def on_get(self, req, resp):\n"
                                     "        resp.status = falcon.HTTP_200\n")
    assert _components(tmp_path / "a") == []
    _write(tmp_path / "b", "pq.py", "import oqs\nsig = oqs.Signature('Falcon-512')\n")
    assert (2, "Falcon", "SAFE") in _components(tmp_path / "b")


def test_a_jwt_decoded_unchecked_under_any_name(tmp_path):
    _write(tmp_path, "a.py", "import jwt as j\nj.decode(t, options={'verify_signature': False})\n"
                             "from jwt import decode\ndecode(t, options={'verify_signature': False})\n"
                             "import jose\njose.jwt.decode(t, k, options={'verify_signature': False})\n"
                             "import jwt\nopts = {'verify_signature': False}\njwt.decode(t, options=opts)\n"
                             "jwt.decode(t, k, algorithms=['HS256'])\n")
    unchecked = [ln for ln, p, _ in _components(tmp_path) if p == "JWT signature verification disabled (options)"]
    assert unchecked == [2, 4, 6, 9]


def test_compare_digest_and_a_rebound_system_random(tmp_path):
    _write(tmp_path / "a", "a.py", "import hmac\nimport random\nrandom = random.SystemRandom()\n"
                                   "x = random.getrandbits(128)\nok = hmac.compare_digest(a, b)\n")
    comps = _components(tmp_path / "a")
    assert not any(ln == 5 for ln, _, _ in comps)
    assert not any(q == "WEAK-RNG" for _, _, q in comps)
    _write(tmp_path / "b", "a.py", "import random\nx = random.random()\n")
    assert (1, "random-MersenneTwister", "WEAK-RNG") in _components(tmp_path / "b")


# ---------------------------------------------------------------- key armour wrapped or encoded twice
_RNG = random.Random(7)
_BODY = "MIIEowIBAAKCAQEA" + base64.b64encode(bytes(_RNG.randrange(256) for _ in range(900))).decode()
_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(textwrap.wrap(_BODY, 64)) + "\n-----END RSA PRIVATE KEY-----\n"


@pytest.mark.parametrize("pid", range(3))
@pytest.mark.parametrize("form", ["w76", "w64", "crlf", "twice"])
def test_base64_key_armour_wrapped_over_lines_or_encoded_twice(tmp_path, pid, form):
    sa = json.dumps({"type": "service_account", "project_id": "proj-" + "x" * pid, "private_key_id": "abc",
                     "private_key": _PEM, "client_email": "x@p.iam.gserviceaccount.com"}, indent=2)
    b = base64.b64encode(sa.encode()).decode()
    text = {"w76": "\n".join(textwrap.wrap(b, 76)) + "\n", "w64": "\n".join(textwrap.wrap(b, 64)) + "\n",
            "crlf": "\r\n".join(textwrap.wrap(b, 76)) + "\r\n",
            "twice": "\n".join(textwrap.wrap(base64.b64encode(b.encode()).decode(), 76)) + "\n"}[form]
    _write(tmp_path, "sa.b64", text)
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings


def test_wrapped_base64_holding_no_key_is_nothing(tmp_path):
    _write(tmp_path, "data.b64", "\n".join(textwrap.wrap(base64.b64encode(bytes(range(256)) * 20).decode(), 76)) + "\n")
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings == []


# ---------------------------------------------------------------- requirements a manifest names
def _sbom(root: Path):
    return asdict(sbom.build_sbom(root, label="t"))


def test_setup_cfg_file_requirements_are_read(tmp_path):
    _write(tmp_path, "setup.cfg", "[metadata]\nname=a\n[options]\ninstall_requires = file: deps.in\n")
    _write(tmp_path, "deps.in", "requests\n")
    rep = _sbom(tmp_path)
    assert rep["verdict"] == "DECLARED" and [c["name"] for c in rep["components"]] == ["requests"]
    assert ("deps.in", 1, "declared-network-dependency") in _found(tmp_path)


def test_a_computed_install_requires_reads_the_file_it_names_or_says_it_was_not_read(tmp_path):
    _write(tmp_path / "a", "setup.py", "from setuptools import setup\n\ndef reqs():\n    with open('install.reqs') as f:\n"
                                       "        return f.read().splitlines()\n\nsetup(name='a', install_requires=reqs())\n")
    _write(tmp_path / "a", "install.reqs", "requests\nboto3\n")
    assert sorted(c["name"] for c in _sbom(tmp_path / "a")["components"]) == ["boto3", "requests"]
    _write(tmp_path / "b", "setup.py", "from setuptools import setup\nimport os\n"
                                       "setup(name='a', install_requires=os.environ.get('X', '').split())\n")
    rep = _sbom(tmp_path / "b")
    assert rep["verdict"] != "EMPTY" and any("computed when setup.py runs" in u for u in rep["unknown_fields"])
    _write(tmp_path / "c", "setup.py", "from setuptools import setup\nREQ = ['click']\nsetup(name='a', install_requires=REQ)\n")
    rep = _sbom(tmp_path / "c")
    assert rep["verdict"] == "DECLARED" and not any("computed" in u for u in rep["unknown_fields"])


def test_how_a_setup_py_computes_its_requirements(tmp_path):
    # a file inside a folder the script names
    _write(tmp_path / "a", "setup.py", "import os\nfrom setuptools import setup\n\ndef reqs(*f):\n"
                                       "    return open(os.path.join('requirements', *f)).read().splitlines()\n\n"
                                       "setup(name='a', install_requires=reqs('default.txt'))\n")
    _write(tmp_path / "a", "requirements/default.txt", "kombu\n")
    rep = _sbom(tmp_path / "a")
    assert [c["name"] for c in rep["components"]] == ["kombu"]
    assert not any("computed" in u for u in rep["unknown_fields"])
    # a function returning a list literal
    _write(tmp_path / "b", "setup.py", "from setuptools import setup\n\ndef get_requires():\n"
                                       "    deps = ['python_http_client>=3.2.1', 'cryptography']\n    return deps\n\n"
                                       "setup(name='a', install_requires=get_requires())\n")
    assert sorted(c["name"] for c in _sbom(tmp_path / "b")["components"]) == ["cryptography", "python_http_client"]
    # `None` declares nothing
    _write(tmp_path / "c", "setup.py", "from setuptools import setup\nsetup(name='a', install_requires=None)\n")
    rep = _sbom(tmp_path / "c")
    assert rep["verdict"] == "EMPTY" and not any("computed" in u for u in rep["unknown_fields"])
    # a file the script opens that the tree does not hold
    _write(tmp_path / "d", "setup.py", "from setuptools import setup\n"
                                       "setup(name='a', install_requires=open('requirements.txt').read().split())\n")
    assert any("computed when setup.py runs" in u for u in _sbom(tmp_path / "d")["unknown_fields"])


def test_dynamic_optional_dependencies_and_a_file_named_like_a_dev_file(tmp_path):
    _write(tmp_path / "a", "pyproject.toml", '[project]\nname="app"\nversion="1"\ndependencies=["click"]\n'
                                             'dynamic=["optional-dependencies"]\n')
    assert any("optional dependencies are dynamic" in u for u in _sbom(tmp_path / "a")["unknown_fields"])
    _write(tmp_path / "b", "pyproject.toml", '[project]\nname="a"\nversion="1"\ndynamic=["dependencies"]\n'
                                             '[tool.setuptools.dynamic]\ndependencies={file=["requirements-dev.txt"]}\n')
    _write(tmp_path / "b", "requirements-dev.txt", "requests\n")
    assert [c["name"] for c in _sbom(tmp_path / "b")["components"]] == ["requests"]
    _write(tmp_path / "c", "requirements-dev.txt", "pytest\n")
    assert _sbom(tmp_path / "c")["components"] == []


# ---------------------------------------------------------------- an output another run left
def test_csaf_with_nothing_to_write_does_not_leave_another_runs_output_as_this_ones(tmp_path, capsys):
    rep = tmp_path / "c.json"
    _write(tmp_path / "tree", "a.py", "x = 1\n")
    _write(tmp_path / "tree", "b.py", "import hashlib\nh = hashlib.sha256(b'x')\n")
    rep.write_text(json.dumps(asdict(cbom.build_cbom(tmp_path / "tree", label="t"))), encoding="utf-8")
    out = tmp_path / "out.json"
    args = [str(rep), "--publisher-name", "Ex", "--publisher-namespace", "https://example.com", "--out", str(out)]
    assert csaf.main(args) == 0 and not out.exists()
    out.write_text('{"stale": true}\n', encoding="utf-8")
    assert csaf.main(args) == 2
    assert out.read_text(encoding="utf-8") == '{"stale": true}\n'

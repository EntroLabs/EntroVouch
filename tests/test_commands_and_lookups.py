"""A command that asks a program about itself is not a download, a value looked up in a mapping is
not a request, and a package this tool has never heard of is named, in JavaScript as in Python."""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit, render_markdown


def _audit(tmp_path: Path, name: str, text: str):
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_bytes(text.encode("utf-8"))
    return audit(tmp_path, label="t")


def _kinds(tmp_path: Path, name: str, text: str) -> set:
    return {f["kind"] for f in _audit(tmp_path, name, text).findings}


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("call,kinds", [
    ('subprocess.run(["pwsh", "--version"])', set()),                      # a shell given only its own flags
    ('subprocess.run(["bash", "--login"])', set()),
    ('subprocess.run(["bash", "-c", "curl https://h.example/x"])', {"subprocess-shell"}),
    ('subprocess.run(["bash", "setup.sh"])', {"subprocess-shell"}),        # a script handed to a shell
    ('subprocess.run(["cmd", "/c", "curl https://h.example/x"])', {"subprocess-shell"}),
    ('subprocess.run([sys.executable, "-m", "pip", "cache", "purge"])', set()),
    ('subprocess.run(["python", "-m", "pip", "--version"])', set()),
    ('subprocess.run(["python", "-m", "pip", "install", "x"])', {"subprocess-net-binary"}),
    ('subprocess.run(["yarn", "application", "-kill", "app_1"])', set()),  # Hadoop's yarn
    ('subprocess.run(["yarn", "install"])', {"subprocess-net-binary"}),
    ('subprocess.run(["yarn", "add", "left-pad"])', {"subprocess-net-binary"}),
    ('subprocess.Popen("docker")', set()),                                 # a program with no arguments
    ('subprocess.Popen("curl")', set()),
    ('subprocess.Popen(["docker"])', {"subprocess-net-binary"}),           # a list may be added to
    ('subprocess.Popen("docker pull x", shell=True)', {"subprocess-shell"}),
])
def test_a_command_is_reported_for_what_it_is_handed(tmp_path, call, kinds):
    assert _kinds(tmp_path, "a.py", "import subprocess, sys\n" + call + "\n") == kinds, call


@pytest.mark.parametrize("line,reported", [
    ('echo "git fetch origin"', False),                       # printed for a person to read
    ("echo 'pip install requests'", False),
    ('printf "run: curl https://h.example/install.sh\\n"', False),
    ('Write-Host "npm ci"', False),
    ('echo "$TOKEN" | docker login -u me --password-stdin', True),   # handed on to a command
    ('echo "$(curl -s https://h.example/v)"', True),                 # a substitution runs
    ('echo ok && pip install requests', True),
    ('echo done; git fetch origin', True),
    ('echo "curl https://h.example/x" > run.sh', "word"),            # written to a file that may run later
    ('git fetch origin', True),
])
def test_a_command_that_is_only_printed_is_not_run(tmp_path, line, reported):
    kinds = _kinds(tmp_path, "build.sh", "#!/bin/sh\n" + line + "\n")
    if reported == "word":      # named, and not run at this line: reported with the smaller claim
        assert "script-network-word" in kinds and "script-network-command" not in kinds, line
    else:
        assert ("script-network-command" in kinds) is reported, line


def test_a_printed_command_in_a_pipeline_step_is_not_run(tmp_path):
    report = _audit(tmp_path, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: |\n          echo \"git fetch origin\"\n"
                                         "          git fetch origin\n")
    assert [(f["kind"], f["line"]) for f in report.findings] == [("script-network-command", 6)]


# ---------------------------------------------------------------------------
# Names that look like addresses
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,text,clean", [
    ("a.js", 'const e = document.createElementNS("http://www.w3.org/2000/svg", "path");\n', True),
    ("a.js", 'el.setAttributeNS("http://www.w3.org/1999/xlink", "href", "#a");\n', True),
    ("a.js", 'const NS = "http://www.w3.org/XML/1998/namespace";\n', True),
    ("page.html", '<script>var x = document.createElementNS("http://www.w3.org/2000/svg", "g");</script>\n', True),
    ("a.js", 'const u = "https://www.w3.org/TR/css-color-4/";\n', False),          # a document, not a namespace name
    ("a.js", 'const u = "http://www.w3.org.h.example/2000/svg";\n', False),        # another host
    ("page.html", '<script src="https://www.w3.org/scripts/a.js"></script>\n', False),
])
def test_a_namespace_name_is_not_an_address(tmp_path, name, text, clean):
    assert (_audit(tmp_path, name, text).verdict == "CLEAN") is clean, text


@pytest.mark.parametrize("src,kind", [
    ("from wsgiref import validate\n", "network-dependency"),
    ("from wsgiref import util, headers\n", "network-dependency"),
    ("from wsgiref import simple_server\n", "inbound-listener"),
    ("from wsgiref.simple_server import make_server\n", "inbound-listener"),
    ("from wsgiref import *\n", "inbound-listener"),
])
def test_only_the_part_of_wsgiref_that_serves_is_a_listener(tmp_path, src, kind):
    assert _kinds(tmp_path, "a.py", src) == {kind}, src


@pytest.mark.parametrize("src,reported", [
    ("def f(node):\n    return node.get('{http://www.w3.org/XML/1998/namespace}base')\n", False),     # an XML qualified name
    ("def f(node):\n    return node.find('{http://purl.org/dc/elements/1.1/}title')\n", False),
    ("def f(node):\n    return node.get('http://www.w3.org/2000/svg')\n", False),                     # a bare namespace name
    ("def f(session):\n    return session.get('http://h.example/{id}')\n", True),                     # an address with a placeholder
    ("def f(session):\n    return session.get('{http://h.example/x}')\n", False),
    ("def f(session):\n    return session.get('https://www.w3.org/TR/css-color-4/')\n", True),        # a document on that host
])
def test_an_xml_qualified_name_is_not_a_request(tmp_path, src, reported):
    assert bool(_kinds(tmp_path, "a.py", src)) is reported, src


@pytest.mark.parametrize("text,kinds", [
    # a service named ssh is no command; its image is pulled, a source the file declares
    ("services:\n  ssh:\n    image: example/sshd\n", {"declared-remote-source"}),
    ("services:\n  curl:\n    image: example/curl\n", {"declared-remote-source"}),
    ("jobs:\n  a:\n    steps:\n      - run: ssh host.example uptime\n", {"script-network-command"}),
    ("jobs:\n  a:\n    steps:\n      - run: |\n          ssh host.example uptime\n", {"script-network-command"}),
])
def test_a_key_with_no_value_is_a_name_not_a_command(tmp_path, text, kinds):
    assert _kinds(tmp_path, "docker-compose.yml", text) == kinds, text


@pytest.mark.parametrize("src,kind", [
    ("from http.server import BaseHTTPRequestHandler\n", "network-dependency"),
    ("from socketserver import ThreadingMixIn\n", "network-dependency"),
    ("from socketserver import BaseRequestHandler, StreamRequestHandler\n", "network-dependency"),
    ("from http.server import HTTPServer\n", "inbound-listener"),
    ("from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n", "inbound-listener"),
    ("from socketserver import TCPServer\n", "inbound-listener"),
    ("from http.server import *\n", "inbound-listener"),
    ("from http.server import test\n", "inbound-listener"),
    ("import http.server\n", "inbound-listener"),
    ("import socketserver\n", "inbound-listener"),
])
def test_a_handler_or_a_mix_in_is_not_a_bound_socket(tmp_path, src, kind):
    assert _kinds(tmp_path, "a.py", src) == {kind}, src


# ---------------------------------------------------------------------------
# This machine, and a server the file gives no asyncio evidence for
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("src,kinds", [
    ('def t(client):\n    client.get("http://localhost:8041/_memory.json")\n', {"loopback-call"}),
    ('import urllib.request\nurllib.request.urlopen("http://127.0.0.1:9191")\n', {"network-import", "loopback-call"}),
    ('import socket\nsocket.create_connection(("127.0.0.1", 8080), timeout=1)\n', {"network-import", "loopback-call"}),
    ('import socket\nsocket.create_connection(("localhost", 8080))\n', {"network-import", "loopback-call"}),
    ('import socket\nsocket.create_connection(("h.example", 8080))\n', {"network-import", "network-call"}),
    ('import socket\nsocket.create_connection((host, 8080))\n', {"network-import", "network-call"}),     # not a literal
    ('def t(client):\n    client.get("https://h.example/x")\n', {"unresolved-call"}),          # receiver not traced
    ('def t(client):\n    client.get("http://localhost.h.example/x")\n', {"unresolved-call"}),       # not this machine
    ('import httpx\ndef t(client: httpx.Client):\n    client.get("https://h.example/x")\n', {"network-import", "network-call"}),
])
def test_a_call_to_this_machine_is_its_own_kind(tmp_path, src, kinds):
    assert _kinds(tmp_path, "a.py", src) == kinds, src


@pytest.mark.parametrize("line,kind", [
    ("curl -s http://localhost:8086/ping", "loopback-call"),
    ("wget http://127.0.0.1:9000/health", "loopback-call"),
    ("curl -s https://h.example/install.sh", "script-network-command"),
    ('curl "$URL"', "script-network-command"),                                # no address to read
    ("curl http://localhost:1/a https://h.example/b", "script-network-command"),
])
def test_a_download_tool_pointed_at_this_machine_is_its_own_kind(tmp_path, line, kind):
    assert _kinds(tmp_path, "check.sh", "#!/bin/sh\n" + line + "\n") == {kind}, line


@pytest.mark.parametrize("src,kind", [
    ("def main(loop, factory):\n    return loop.create_server(factory, host='0.0.0.0', port=25)\n", "inbound-listener"),
    ("def main(t, ev, s):\n    t.start_server(ev, s)\n", "unresolved-call"),   # `t` is not traced
    ("def main(loop, f):\n    return loop.create_connection(f, 'h.example', 25)\n", "network-call"),
])
def test_a_server_call_is_a_listener_even_when_asyncio_is_not_imported(tmp_path, src, kind):
    assert _kinds(tmp_path, "a.py", src) == {kind}, src


def test_the_new_kind_has_a_rule_in_the_sarif_output(tmp_path):
    from entrovouch.sarif import to_sarif
    import dataclasses
    report = _audit(tmp_path, "a.py", 'def t(c):\n    c.get("http://localhost:1/x")\n')
    doc = to_sarif(dataclasses.asdict(report))
    rules = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "loopback-call" in rules


@pytest.mark.parametrize("src,kinds", [
    ('import clickhouse_connect\nc = connect("clickhouse://localhost")\n', {"loopback-call"}),
    ('def f():\n    return connect("postgresql://user:pw@127.0.0.1:5432/db")\n', {"loopback-call"}),
    ('def f():\n    return connect("postgresql://user:pw@db.h.example:5432/db")\n', {"network-call"}),
    ('def f():\n    return connect("postgresql://localhost.h.example/db")\n', {"network-call"}),
    ("import asyncio\n\n\nasync def f():\n    return await asyncio.open_connection('localhost', 5678)\n", {"loopback-call"}),
    ("import asyncio\n\n\nasync def f():\n    return await asyncio.open_connection(host='127.0.0.1', port=1)\n", {"loopback-call"}),
    ("import asyncio\n\n\nasync def f():\n    return await asyncio.open_connection('h.example', 5678)\n", {"network-call"}),
    ("import asyncio\n\n\nasync def f(h):\n    return await asyncio.open_connection(h, 5678)\n", {"network-call"}),
])
def test_a_connection_string_or_host_naming_this_machine_is_a_loopback_call(tmp_path, src, kinds):
    assert _kinds(tmp_path, "a.py", src) - {"network-import", "network-dependency"} == kinds, src


@pytest.mark.parametrize("line,kind", [
    ("nc -z localhost 4100", "loopback-call"),
    ("ssh -o StrictHostKeyChecking=no user@127.0.0.1 -p 2223 uptime", "loopback-call"),
    ("nc -z db.h.example 4100", "script-network-command"),
    ("ssh user@h.example uptime", "script-network-command"),
    ("ssh localhost 'curl https://h.example/x'", "script-network-command"),      # an outside address on the line
])
def test_a_port_check_or_a_shell_on_this_machine_is_a_loopback_call(tmp_path, line, kind):
    assert _kinds(tmp_path, "check.sh", "#!/bin/sh\n" + line + "\n") == {kind}, line


@pytest.mark.parametrize("src,reported", [
    ("def t(client):\n    client.post('/login?next=http://example.com')\n", False),   # a path on the app under test
    ("def t(client):\n    client.get('?redirect=https://h.example/')\n", False),
    ("def t(client):\n    client.post('http://h.example/login?next=/home')\n", True),
])
def test_a_path_with_a_url_in_its_query_is_a_path(tmp_path, src, reported):
    assert bool(_kinds(tmp_path, "a.py", src)) is reported, src


@pytest.mark.parametrize("src,kind", [
    ('def t(ws, PORT):\n    return ws.create_connection(f"ws://127.0.0.1:{PORT}")\n', "loopback-call"),
    ('def t(ws, p):\n    return ws.create_connection(f"ws://localhost/{p}")\n', "loopback-call"),
    ('def t(ws):\n    return ws.create_connection("ws://127.0.0.1:8765")\n', "loopback-call"),
    ('def t(ws, tail):\n    return ws.create_connection(f"ws://127.0.0.1{tail}")\n', "network-call"),     # the host is not closed
    ('def t(ws, host):\n    return ws.create_connection(f"ws://{host}:8765")\n', "network-call"),
    ('def t(ws):\n    return ws.create_connection("wss://api.h.example/ws/2")\n', "network-call"),
])
def test_an_address_that_starts_with_this_machine_is_a_loopback_call(tmp_path, src, kind):
    assert _kinds(tmp_path, "a.py", src) == {kind}, src


def test_the_same_call_on_the_websocket_module_is_a_network_call(tmp_path):
    src = 'import websocket\ndef t():\n    return websocket.create_connection("wss://api.h.example/ws/2")\n'
    assert _kinds(tmp_path, "a.py", src) == {"network-import", "network-call"}


@pytest.mark.parametrize("line,reported", [
    ('RE="https://github.com/([^/?#]+)/([^/?#]+)(/tree/(.+))?"', False),          # a pattern that matches addresses
    ("grep -E '(https://github\\.com/|git@github\\.com:)' remotes.txt", False),
    ('URL="https://h.example/releases/download/v1/tool.zip"', True),              # an address
    ('API="https://h.example/api?q=a.b"', True),
    ('echo "see https://h.example/guide"', True),
])
def test_a_pattern_that_begins_like_an_address_is_not_one(tmp_path, line, reported):
    assert ("external-url" in _kinds(tmp_path, "tool.sh", "#!/bin/sh\n" + line + "\n")) is reported, line


@pytest.mark.parametrize("src,detail_has", [
    ("from x import Request\nr = Request('https://a.h.example/path', body='grant_type=code')\n", "builds a request"),
    ("from x import Request\nr = Request('https://a.h.example/path')\n", "builds a request"),
    ("def t(factory):\n    return factory.get('https://a.h.example/authorize')\n", "builds a request"),
    ("def t(rf):\n    return rf.post('https://a.h.example/token')\n", "builds a request"),
    ("def t(self):\n    return self.request_factory.get('https://a.h.example/x')\n", "is given a URL literal"),   # not a plain name
    ("def t(requests_mock):\n    requests_mock.get('https://a.h.example/x', text='ok')\n", "canned reply"),
])
def test_a_request_object_and_a_request_factory_send_nothing(tmp_path, src, detail_has):
    findings = [f for f in _audit(tmp_path, "a.py", src).findings
                if f["kind"] in ("network-target", "network-call", "unresolved-call")]
    assert len(findings) == 1 and detail_has in findings[0]["detail"], findings
    assert findings[0]["kind"] == ("unresolved-call" if detail_has == "is given a URL literal" else "network-target")


@pytest.mark.parametrize("name,text,reported", [
    ("tox.ini", "; https://docs.h.example/faq/install/\n[tox]\nenvlist = py\n", False),      # `;` starts a comment
    ("setup.cfg", "; see https://h.example/x\n[metadata]\nname = a\n", False),
    ("tox.ini", "[testenv]\ndeps =\n    djmain: https://h.example/archive/main.tar.gz\n", True),
    ("build.sh", "#!/bin/sh\nX=1; URL=https://h.example/x\n", True),                          # in a shell `;` separates commands
])
def test_a_semicolon_comment_in_an_ini_file_is_a_comment(tmp_path, name, text, reported):
    assert bool(_kinds(tmp_path, name, text)) is reported, text


@pytest.mark.parametrize("call,kinds", [
    ('subprocess.check_output(["docker", "logs", "web"])', set()),
    ('subprocess.run(["docker", "compose", "-f", "c.yml", "down", "-t", "0"])', set()),      # compose's own flags come first
    ('subprocess.run(["docker", "compose", "--file=c.yml", "logs"])', set()),
    ('subprocess.run(["docker", "compose", "-f", "c.yml", "up", "-d"])', {"subprocess-net-binary"}),
    ('subprocess.run(["docker", "compose", "down"])', set()),
    ('subprocess.run(["docker", "ps", "-a"])', set()),
    ('subprocess.run(["podman", "inspect", "web"])', set()),
    ('subprocess.run(["docker", "pull", "h.example/image"])', {"subprocess-net-binary"}),
    ('subprocess.run(["docker", "run", "image"])', {"subprocess-net-binary"}),           # may pull the image
    ('subprocess.run(["docker", "compose", "up", "-d"])', {"subprocess-net-binary"}),
    ('subprocess.run(["docker", "push", "h.example/image"])', {"subprocess-net-binary"}),
])
def test_a_docker_command_that_acts_on_what_is_here_is_not_a_network_command(tmp_path, call, kinds):
    assert _kinds(tmp_path, "a.py", "import subprocess\n" + call + "\n") == kinds, call


@pytest.mark.parametrize("name,text,kinds", [
    ("activate.ps1", "<#\n.LINK\nhttps://h.example/fwlink/?LinkID=1\n#>\nWrite-Host 'ok'\n", set()),
    ("activate.ps1", "<# see https://h.example/x #>\nInvoke-WebRequest -Uri $u -OutFile f\n", {"script-network-command"}),
    ("setup.ps1", "$url = 'https://h.example/tool.zip'\n", {"external-url"}),
    ("build.sh", "#!/bin/sh\necho '<# https://h.example/x #>'\n", {"external-url"}),          # not PowerShell
])
def test_a_powershell_block_comment_is_a_comment(tmp_path, name, text, kinds):
    assert _kinds(tmp_path, name, text) == kinds, text


def test_the_line_after_a_powershell_block_comment_keeps_its_number(tmp_path):
    report = _audit(tmp_path, "a.ps1", "<#\nhttps://h.example/a\n#>\n$u = 'https://h.example/b'\n")
    assert [(f["kind"], f["line"]) for f in report.findings] == [("external-url", 4)]


@pytest.mark.parametrize("name", ["Page.svelte", "Page.vue", "Page.astro"])
def test_an_anchor_over_several_lines_in_a_component_is_a_link(tmp_path, name):
    text = '<div>\n  <a\n    class="link"\n    href="https://h.example/docs"\n  >docs</a>\n</div>\n'
    assert [(f["kind"], f["line"]) for f in _audit(tmp_path, name, text).findings] == [("external-link", 2)]


def test_a_load_in_a_component_is_still_a_load(tmp_path):
    text = '<img\n  alt="x"\n  src="https://h.example/p.png"\n/>\n<a href="https://h.example/docs">docs</a>\n'
    kinds = {f["kind"] for f in _audit(tmp_path, "Page.svelte", text).findings}
    assert kinds == {"html-external", "external-link"}


# ---------------------------------------------------------------------------
# Forms from the families the precision sets kept surfacing, tried before a set finds them
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,text,kinds", [
    ("build.cmd", "@REM https://h.example/docs\n@echo off\n", set()),                       # a batch comment
    ("build.bat", "rem https://h.example/docs\n", set()),
    ("build.bat", "curl https://h.example/tool.zip -o tool.zip\n", {"script-network-command"}),
    ("p.html", '<area shape="rect" href="https://h.example/a">\n', {"external-link"}),      # an image-map link
    ("p.html", '<button formaction="https://h.example/submit">go</button>\n', {"external-link"}),
    ("p.html", '<input type="image" src="https://h.example/b.png">\n', {"html-external"}),  # an input that loads
    ("p.html", '<blockquote cite="https://h.example/source">x</blockquote>\n', set()),      # a source named, not fetched
    ("p.html", '<q cite="https://h.example/source">x</q>\n', set()),
    ("p.html", '<img src="https://h.example/p.png" longdesc="/d.html">\n', {"html-external"}),
])
def test_more_markup_and_batch_forms(tmp_path, name, text, kinds):
    assert _kinds(tmp_path, name, text) == kinds, text


def test_text_shown_by_cat_is_not_a_command_run(tmp_path):
    script = ("#!/bin/sh\n"
              "cat <<EOF\n"
              "To install, run: curl https://h.example/install.sh | sh\n"
              "Then: pip install thing\n"
              "EOF\n"
              "pip install real-thing\n")
    report = _audit(tmp_path, "usage.sh", script)
    assert [(f["kind"], f["line"]) for f in report.findings] == [("external-url", 3), ("script-network-command", 6)]


@pytest.mark.parametrize("script,kinds", [
    ("#!/bin/sh\ncat > install.sh <<EOF\ncurl https://h.example/x | sh\nEOF\n", {"script-network-command"}),   # written to a file
    ("#!/bin/sh\nsh <<EOF\ncurl https://h.example/x | sh\nEOF\n", {"script-network-command"}),                 # fed to a shell
    ("#!/bin/sh\ncat <<'EOF'\npip install thing\nEOF\n", set()),
    ("#!/bin/sh\ncat <<-EOF\n\tgit clone https://h.example/r.git\n\tEOF\n", {"external-url"}),
])
def test_only_a_heredoc_that_is_shown_is_set_aside(tmp_path, script, kinds):
    assert _kinds(tmp_path, "s.sh", script) == kinds, script


@pytest.mark.parametrize("src,kind", [
    ("from unittest import mock\nm = mock.Mock()\nm.get('https://h.example/x')\n", "network-target"),
    ("from unittest.mock import MagicMock\nsession = MagicMock()\nsession.post('https://h.example/x')\n", "network-target"),
    ("from unittest.mock import AsyncMock\nclient = AsyncMock()\nclient.get('https://h.example/x')\n", "network-target"),
    ("import requests\nsession = requests.Session()\nsession.get('https://h.example/x')\n", "network-call"),
    ("from unittest import mock\nm = mock.Mock()\nm = make_real_client()\nm.get('https://h.example/x')\n", "unresolved-call"),   # bound twice
])
def test_a_name_bound_once_to_a_mock_is_a_test_double(tmp_path, src, kind):
    kinds = _kinds(tmp_path, "a.py", src) - {"network-import"}
    assert kinds == {kind}, src


# ---------------------------------------------------------------------------
# The audited file's own warnings
# ---------------------------------------------------------------------------
_ESCAPE_SOURCE = 'import re\nm = re.match("(\\d+):(\\d+)", "1:2")\nimport requests\n'


def test_a_warning_in_the_audited_file_is_not_printed_by_the_auditor(tmp_path):
    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        report = _audit(tmp_path, "a.py", _ESCAPE_SOURCE)
    assert [str(w.message) for w in caught] == []
    assert [(f["kind"], f["line"]) for f in report.findings] == [("network-import", 3)]


def test_warnings_as_errors_do_not_change_the_report(tmp_path):
    """Run with warnings turned into errors, a file with an invalid escape used to be reported as
    unparseable. The report must not depend on how the interpreter was started."""
    import warnings
    plain = _audit(tmp_path, "a.py", _ESCAPE_SOURCE)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        strict = _audit(tmp_path, "a.py", _ESCAPE_SOURCE)
    assert strict.findings == plain.findings
    assert strict.findings_digest == plain.findings_digest
    assert "unparseable-source" not in {f["kind"] for f in strict.findings}


def test_the_other_tools_read_such_a_file_too(tmp_path):
    import warnings
    from entrovouch import cbom, key_provenance
    (tmp_path / "a.py").write_bytes(_ESCAPE_SOURCE.encode() + b"import hashlib\nh = hashlib.md5(b'x')\n")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        c = cbom.build_cbom(tmp_path, label="t")
        k = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert c.verdict != "NOT-ANALYSED" and k.verdict != "NOT-ANALYSED"


# ---------------------------------------------------------------------------
# A link checked out as a text file
# ---------------------------------------------------------------------------
def _tree_with(tmp_path: Path, make_link) -> Path:
    root = tmp_path / "t"
    (root / "app").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "app" / "config.py").write_bytes(b"import requests\n")
    make_link(root / "docs" / "config.py", "../app/config.py")
    return root


def test_a_link_checked_out_as_text_is_counted_as_a_link(tmp_path):
    root = _tree_with(tmp_path, lambda p, target: p.write_bytes(target.encode()))
    report = audit(root, label="t")
    assert report.not_scanned["symbolic_links"] == 1
    assert [(f["file"], f["kind"]) for f in report.findings] == [("app/config.py", "network-import")]


@pytest.mark.parametrize("content", [
    b"../app/config.py\n",            # ends with a line break: an ordinary file
    b"../app/missing.py",             # names nothing that exists
    b"import os",                     # has a space
    b"",                              # empty
])
def test_an_ordinary_short_file_is_still_read(tmp_path, content):
    root = _tree_with(tmp_path, lambda p, target: p.write_bytes(content))
    report = audit(root, label="t")
    assert report.not_scanned["symbolic_links"] == 0
    assert report.files_scanned == 2


def test_a_real_link_and_its_text_stand_in_give_the_same_report(tmp_path):
    """The same repository checked out with and without link support. Needs permission to make a
    link, which Windows often withholds; where it is withheld this test is skipped."""
    import os
    real = _tree_with(tmp_path / "real", lambda p, target: None)
    try:
        os.symlink("../app/config.py", real / "docs" / "config.py")
    except (OSError, NotImplementedError):
        pytest.skip("this system does not let the test create a symbolic link")
    text = _tree_with(tmp_path / "text", lambda p, target: p.write_bytes(target.encode()))
    a, b = audit(real, label="t"), audit(text, label="t")
    assert a.findings_digest == b.findings_digest
    assert a.subject_digest == b.subject_digest
    assert a.not_scanned["symbolic_links"] == b.not_scanned["symbolic_links"] == 1


# ---------------------------------------------------------------------------
# Data, selectors and shown text in a page
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,text,kinds", [
    ("page.html", '<script type="application/ld+json">\n{"@context": "http://schema.org", "url": "https://h.example/"}\n</script>\n', set()),
    ("page.html", '<script type="application/json" id="cfg">{"api": "https://h.example/v1"}</script>\n', set()),
    ("page.html", '<script type="text/javascript">fetch("https://h.example/v1")</script>\n', {"html-external"}),
    ("page.html", '<script>\nvar u = "https://h.example/v1"; load(u);\n</script>\n', {"external-url"}),
    ("page.html", '<script>\nvar u = "https://h.example/v1"; fetch(u);\n</script>\n', {"html-external"}),
    ("site.css", "a[href^='https://docs.h.example/'] { color: red; }\n", set()),
    ("site.css", 'a[href*="://"] { color: red; }\n', set()),
    ("site.css", "@import url(https://fonts.h.example/css?family=X);\n", {"html-external"}),
    ("site.css", "a[href^='https://docs.h.example/'] { background: url(https://h.example/i.png); }\n", {"html-external"}),
    ("page.html", "<style>a[href^='https://docs.h.example/'] { color: red; }</style>\n", set()),
    ("page.html", '<img class="logo" src="/static/logo.png" title="https://h.example/tattoos"/>\n', set()),
    ("page.html", '<img src="/static/logo.png" alt="see https://h.example/x">\n', set()),
    ("page.html", '<img src="https://h.example/logo.png" title="logo">\n', {"html-external"}),
    ("page.html", '<form action="https://pay.h.example/cgi-bin/webscr" method="post">\n', {"external-link"}),
    ("page.html", '<form action="/submit" method="post">\n', set()),
    # a template comment inside a script block is removed before a browser sees the script
    ("page.html", "<script>\nwindow.d = {\n  {#- see `https://h.example/blob/x.py#L6` #}\n  user: \"{{ name }}\",\n};\n</script>\n", set()),
    ("page.html", "<script>\n{# note #}\nfetch(\"https://h.example/v1\");\n</script>\n", {"html-external"}),
    ("page.html", "<script>\nclass A { #x = 1; get() { return this.#x } }\nvar u = \"https://h.example/v1\";\n</script>\n", {"external-url"}),
])
def test_data_blocks_selectors_shown_text_and_form_targets(tmp_path, name, text, kinds):
    assert _kinds(tmp_path, name, text) == kinds, text


# ---------------------------------------------------------------------------
# What a page's script calls, and what it only mentions
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("script,kinds", [
    ('const data = {"lines": ["from ws4py.websocket import WebSocket(x)", "def fetch(self):"]};', set()),
    ('const msg = "call fetch(url) to load it";', set()),
    ('fetch("/api/items");', {"network-call"}),
    ('const s = new WebSocket(url);', {"network-call"}),
    ('const t = `${fetch(url)}`;', {"network-call"}),                        # code inside a template literal
    ('window["fetch"]("/api");', {"network-call"}),                          # the call is named in a string
    ('throw new Error("Unsupported core-js use. Try https://npms.io/search?q=ponyfill.");', set()),
    ('const u = "https://api.h.example/v1"; load(u);', {"external-url"}),    # an address, not a sentence; no fetch shown
    ('const u = "https://api.h.example/v1"; fetch(u);', {"html-external"}),
    ('fetch("https://api.h.example/v1");', {"html-external"}),
    ('const m = "Docs https://h.example/guide";', {"external-url"}),         # one word is not a sentence
])
def test_in_a_pages_script_a_call_is_code_and_a_sentence_is_not_an_address(tmp_path, script, kinds):
    assert _kinds(tmp_path, "page.html", "<html><body><script>\n" + script + "\n</script></body></html>\n") == kinds, script


@pytest.mark.parametrize("src,reported", [
    ('const data = ["new WebSocket(x)", "fetch(y)"];\n', False),
    ('const help = "use $.ajax(opts) here";\n', False),
    ('fetch(url).then(r => r.json());\n', True),
    ('const w = window["fetch"];\n', True),
    ("const s = `prefix ${new WebSocket(u)} suffix`;\n", True),
    ('const a = "it\'s"; fetch(u);\n', True),                                # an escaped quote does not end the string
])
def test_in_a_javascript_file_a_call_name_inside_a_string_calls_nothing(tmp_path, src, reported):
    assert ("network-call" in _kinds(tmp_path, "a.js", src)) is reported, src


# ---------------------------------------------------------------------------
# Lookups and test doubles
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("src,kinds", [
    ('import os\nREPO = os.environ.get("REPO", "https://h.example/r.git")\n', set()),
    ('cfg = {}\nu = cfg.get("url", "https://h.example/r")\n', set()),
    ('def f(settings):\n    return settings.get("endpoint", "https://h.example/r")\n', set()),
    ('def f(self):\n    return self.config.get("endpoint", "https://h.example/r")\n', set()),
    ('def f(session):\n    session.get("https://h.example/r")\n', {"unresolved-call"}),
    ('import requests\ndef f(session: requests.Session):\n    session.get("https://h.example/r")\n',
     {"network-import", "network-call"}),
    ('import requests\nrequests.get("https://h.example/r")\n', {"network-import", "network-call"}),
    ('def test_x(requests_mock):\n    requests_mock.get("https://h.example/r", text="ok")\n', {"network-target"}),
    ('def test_x(requests_mock):\n    requests_mock.post("https://h.example/r")\n', {"network-target"}),
    ('def test_x(mock_api):\n    mock_api.get("https://h.example/r")\n', {"network-target"}),
])
def test_a_lookup_is_not_a_request_and_a_double_is_not_a_client(tmp_path, src, kinds):
    assert _kinds(tmp_path, "a.py", src) == kinds, src


# ---------------------------------------------------------------------------
# The page's own host
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("src,external", [
    ("const s = new WebSocket(`ws://${location.host}/ws`);\n", False),
    ("const s = new WebSocket(`wss://${window.location.hostname}:8080/ws`);\n", False),
    ("const s = new WebSocket(`wss://${document.location.host}/ws`);\n", False),
    ('const s = new WebSocket("wss://h.example/ws");\n', True),
    ("const s = new WebSocket(`wss://${remoteHost}/ws`);\n", True),
])
def test_a_socket_to_the_pages_own_host_names_no_outside_address(tmp_path, src, external):
    kinds = _kinds(tmp_path, "a.js", src)
    assert "network-call" in kinds            # it is still a socket
    assert ("external-url" in kinds) is external, src


# ---------------------------------------------------------------------------
# JavaScript packages the lists have no entry for
# ---------------------------------------------------------------------------
def test_javascript_packages_not_on_any_list_are_named(tmp_path):
    report = _audit(tmp_path, "a.js",
                    'import React from "react";\n'
                    'import x from "./x";\n'
                    'import up from "../up/index.js";\n'
                    'import fs from "node:fs";\n'
                    'import p from "path";\n'
                    'import a from "@scope/pkg/sub";\n'
                    'const l = require("lodash/merge");\n'
                    'import y from "@/local";\n'
                    'import z from "~/local";\n'
                    'import ax from "axios";\n')
    assert report.unlisted_js_imports == ["@scope/pkg", "lodash", "react"]
    assert [f["kind"] for f in report.findings] == ["network-import"]     # axios, and only axios


def test_typescript_and_dynamic_imports_are_named_too(tmp_path):
    report = _audit(tmp_path, "a.ts", 'import type { A } from "vue";\nexport * from "~/x";\nconst m = await import("left-pad");\n')
    assert report.unlisted_js_imports == ["left-pad", "vue"]
    assert report.verdict == "CLEAN"


def test_a_tree_with_no_javascript_names_none(tmp_path):
    report = _audit(tmp_path, "a.py", "import json\n")
    assert report.unlisted_js_imports == []
    assert "JavaScript packages imported" not in render_markdown(report)


def test_the_named_packages_are_in_the_written_report(tmp_path):
    report = _audit(tmp_path, "a.js", 'import React from "react";\n')
    text = render_markdown(report)
    assert "JavaScript packages imported, and not known to this tool (1):" in text
    assert "`react`" in text


def test_naming_a_package_changes_the_reproducible_digest(tmp_path):
    """What the report names is part of what it says, so it is part of what is compared."""
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    (one / "a.js").write_bytes(b'import a from "alpha";\n')
    (two / "a.js").write_bytes(b'import a from "bravo";\n')
    a, b = audit(one, label="t"), audit(two, label="t")
    assert a.unlisted_js_imports == ["alpha"] and b.unlisted_js_imports == ["bravo"]
    assert a.findings_digest != b.findings_digest


def test_a_lookup_with_a_key_and_a_url_default_is_not_a_call(tmp_path):
    """`schema.get("$id", "http://localhost/schema.json")` looks a key up; the address is its default."""
    report = _audit(tmp_path, "a.py",
                    'schema = {}\n'
                    'a = schema.get("$id", "http://localhost/schema.json")\n'
                    'b = schema.get("$id", "https://example.com/schema.json")\n')
    assert report.findings == []


def test_a_client_get_keeps_its_finding_beside_a_lookup(tmp_path):
    """The true neighbours: an address first, a network module as receiver, keywords of a request."""
    report = _audit(tmp_path, "a.py",
                    'import requests\n'
                    'session = requests.Session()\n'
                    'session.get("https://example.com/a", "x")\n'
                    'requests.get("key", "https://example.com/b")\n'
                    'session.get("key", "https://example.com/c", timeout=5)\n'
                    'session.get("http://localhost:8000/d", "x")\n')
    kinds = [(f["line"], f["kind"]) for f in report.findings if f["kind"] in ("network-call", "loopback-call")]
    assert kinds == [(3, "network-call"), (4, "network-call"), (5, "network-call"), (6, "loopback-call")]


def test_uv_pip_subcommands_that_fetch_nothing_are_not_reported(tmp_path):
    """`uv pip uninstall`, `list`, `freeze` and `show` act on what is already installed."""
    report = _audit(tmp_path, "a.sh",
                    "uv pip uninstall flask werkzeug\n"
                    "uv pip list\n"
                    "uv pip freeze\n"
                    "uv pip show flask\n")
    assert report.findings == []


def test_uv_pip_subcommands_that_fetch_are_still_reported(tmp_path):
    report = _audit(tmp_path, "a.sh",
                    "uv pip install flask\n"
                    "uv pip sync requirements.txt\n"
                    "uv pip compile requirements.in\n"
                    "uv sync --locked\n"
                    "uv add httpx\n")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(n, "script-network-command") for n in (1, 2, 3, 4, 5)]
    assert report.findings[0]["detail"].startswith("runs 'uv pip'")


def test_a_tool_named_as_an_option_value_is_not_a_command(tmp_path):
    """`--run-optional-tests=ssh,sudo` hands a word to an option; nothing named ssh is run."""
    report = _audit(tmp_path, ".github/workflows/ci.yml", """jobs:
  t:
    steps:
      - run: uv run pytest --cov --run-optional-tests=ssh,sudo
      - run: tox -e py,curl,docs
""")
    # `uv run` syncs the project and tox builds environments, both installing what is missing; `ssh`, `sudo` and
    # `curl` are names handed to options
    assert [(f["line"], f["detail"].split(",")[0]) for f in report.findings] == [(4, "runs 'uv run'"), (5, "runs 'tox'")]


def test_a_tool_that_is_run_is_still_reported_beside_an_option_value(tmp_path):
    report = _audit(tmp_path, ".github/workflows/ci.yml", """jobs:
  t:
    steps:
      - run: ssh deploy@example.com uptime
      - run: OUT=$(curl -s https://example.com/x)
""")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(4, "script-network-command"), (5, "script-network-command")]


def test_get_on_a_cache_object_is_a_lookup(tmp_path):
    """A name bound only to a `...Cache(...)` object: `get(url)` reads a key and fetches nothing."""
    report = _audit(tmp_path, "a.py", """import cache
c = cache.SqliteCache(path="x.db")
c.add("http://tests.example.org/example.wsdl", b"content")
result = c.get("http://tests.example.org/example.wsdl")
""")
    assert [f["kind"] for f in report.findings] == []


def test_get_on_a_session_is_still_a_call_beside_a_cache(tmp_path):
    report = _audit(tmp_path, "a.py", """import requests
c = requests.Session()
c.get("https://example.com/a")
d = make()
d = InMemoryCache()
d.get("https://example.com/b")
""")
    # `d` is bound once to an unknown call and once to a cache: still reported, as a call whose receiver is not resolved
    assert [(f["line"], f["kind"]) for f in report.findings if f["kind"] in ("network-call", "unresolved-call")] == [
        (3, "network-call"), (6, "unresolved-call")]


def test_a_name_bound_by_with_to_a_test_double_registers_replies(tmp_path):
    """`with requests_mock.mock() as m: m.post(url, content=...)` describes a reply; nothing is sent."""
    report = _audit(tmp_path, "a.py", """import requests_mock
with requests_mock.mock() as m:
    m.post("http://tests.example.org/test", content=b"x", headers={"A": "b"})
""")
    assert [f["kind"] for f in report.findings] == ["network-target"]


def test_a_name_bound_by_with_to_a_client_still_calls(tmp_path):
    report = _audit(tmp_path, "a.py", """import httpx
with httpx.Client() as m:
    m.post("https://example.com/test", content=b"x")
""")
    assert [f["kind"] for f in report.findings if f["line"] == 3] == ["network-call"]


def test_a_tool_named_in_text_that_is_shown_before_a_joined_command_is_not_run(tmp_path):
    """`echo "Cisco SSH tests" && pytest ...`: the word is in text that is printed."""
    report = _audit(tmp_path, "a.sh", """#!/bin/sh
echo "Cisco IOS-XE SSH (including SCP)" && pytest test_show.py
echo "done" ; echo "ssh was tested"
""")
    assert report.findings == []


def test_a_tool_run_after_text_that_is_shown_is_still_reported(tmp_path):
    report = _audit(tmp_path, "a.sh", """#!/bin/sh
echo "fetching" && curl -s https://example.com/x
echo "copying" ; scp a.txt deploy@example.com:/tmp/
""")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(2, "script-network-command"), (3, "script-network-command")]


def test_a_pipe_and_a_unix_socket_are_not_network_connections(tmp_path):
    """`connect_write_pipe` attaches a file object; asyncio's own Unix socket calls stay on this machine."""
    report = _audit(tmp_path, "a.py", """import asyncio

async def main(loop, path, pipe):
    await loop.connect_write_pipe(asyncio.Protocol, pipe)
    r, w = await asyncio.open_unix_connection(path)
    await loop.create_unix_connection(asyncio.Protocol, path)
""")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(5, "loopback-call"), (6, "loopback-call")]


def test_a_network_connection_is_still_reported_beside_a_unix_socket(tmp_path):
    """The same method name on another object (an SSH connection) can reach a far host."""
    report = _audit(tmp_path, "a.py", """import asyncio

async def main(loop, conn, host):
    await asyncio.open_connection(host, 80)
    await loop.create_connection(asyncio.Protocol, host, 80)
    await conn.open_unix_connection("/echo")
""")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(4, "network-call"), (5, "network-call"), (6, "network-call")]


def test_git_ls_remote_asks_a_remote_and_is_reported(tmp_path):
    report = _audit(tmp_path, "a.sh", """#!/bin/sh
git ls-remote --tags origin
git ls-files
""")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(2, "script-network-command")]
    report = _audit(tmp_path, "b.py", """import subprocess
subprocess.run(["git", "ls-remote", "--tags", "origin"])
subprocess.run(["git", "ls-files"])
""")
    assert [(f["file"], f["line"], f["kind"]) for f in report.findings if f["file"] == "b.py"] == [("b.py", 2, "git-remote")]


def test_a_literal_list_with_more_added_at_run_time_still_names_its_program(tmp_path):
    """`["curl", "-s"] + urls`: the program is spelled out, so it is reported."""
    report = _audit(tmp_path, "a.py", """import subprocess
urls = make()
subprocess.run(["curl", "-s"] + urls)
subprocess.check_output(["git", "fetch"] + remotes)
""")
    assert [(f["line"], f["kind"]) for f in report.findings] == [(3, "subprocess-net-binary"), (4, "git-remote")]


def test_a_list_built_only_at_run_time_or_a_harmless_program_is_not_reported(tmp_path):
    report = _audit(tmp_path, "a.py", """import subprocess
subprocess.run(prefix + ["curl"])
subprocess.run(["ls", "-l"] + names)
subprocess.run(["git", "status"] + paths)
""")
    assert report.findings == []

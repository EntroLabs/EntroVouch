"""A finding says only what the line supports. An identifier is not an address, displayed text is
not a load, a built object is not a request sent, a package in an install list is not a command
run, and a library that only encodes a protocol is not a connection."""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))
    return p


def _findings(root: Path) -> list:
    return [(f["kind"], f["line"]) for f in audit(root, label="t").findings]


# ---------------------------------------------------------------------------
# Markup: identifiers and displayed text
# ---------------------------------------------------------------------------
QUIET_MARKUP = [
    '<div class="q" itemscope itemtype="http://schema.org/CreativeWork">text</div>\n',
    '<svg><metadata><dc:type rdf:resource="http://purl.org/dc/dcmitype/StillImage" /></metadata></svg>\n',
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n<p>x</p>\n',
    '<meta name="generator" content="Docutils 0.21: https://docutils.sourceforge.io/">\n',
    '<p>Read the guide at https://example.org/guide before you start.</p>\n',
    '<pre>\ncurl https://example.org/install.sh | sh\nimport requests\n</pre>\n',
    '<pre>&lt;script src="http://cdn.example.org/a.js"&gt;&lt;/script&gt;</pre>\n',
    '<code>fetch("https://api.example.org/v1")</code>\n',
    '<html xmlns="http://www.w3.org/1999/xhtml" vocab="http://schema.org/" typeof="Article"><body></body></html>\n',
]


@pytest.mark.parametrize("page", QUIET_MARKUP)
def test_identifiers_and_displayed_text_load_nothing(tmp_path, page):
    _write(tmp_path, "page.html", page)
    assert audit(tmp_path, label="t").verdict == "CLEAN", page


LOUD_MARKUP = [
    ('<pre><img src="http://h.example/p.gif"></pre>\n', "html-external"),                   # a real tag inside <pre>
    ('<div itemtype="http://schema.org/X"><img src="http://h.example/p.gif"></div>\n', "html-external"),
    ('<p>see docs</p>\n<script>fetch("https://api.h.example/v1")</script>\n', "html-external"),
    ('<img\n  alt="x"\n  src="https://h.example/p.png">\n', "html-external"),                # a tag over several lines
    ('<a href="{{ url }}">x</a>{% set url = "https://h.example/x" %}\n', "external-url"),    # a template expression
    ('<p style="background:url(https://h.example/b.png)">x</p>\n', "html-external"),
    ('<button onclick="fetch(\'/api\')">go</button>\n', "network-call"),
]


@pytest.mark.parametrize("page,kind", LOUD_MARKUP)
def test_what_a_browser_acts_on_is_still_reported(tmp_path, page, kind):
    _write(tmp_path, "page.html", page)
    assert kind in {k for k, _ in _findings(tmp_path)}, page


def test_line_numbers_survive_the_blanking_of_displayed_text(tmp_path):
    _write(tmp_path, "page.html", "<p>one https://a.example</p>\n<pre>\ntwo https://b.example\n</pre>\n"
                                  '<img src="http://h.example/p.gif">\n')
    assert _findings(tmp_path) == [("html-external", 5)]


# ---------------------------------------------------------------------------
# A scheme alone is a prefix
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,line,clean", [
    ("a.js", 'var url = "ws://" + location.host + "/chat";\n', True),
    ("a.js", 'const p = (location.protocol == "https:" && "wss://" || "ws://");\n', True),
    ("a.js", 'var url = "wss://live.h.example/chat";\n', False),
    ("a.js", "const u = `https://${host}/v1`;\n", False),
    ("a.py", 'import webhelper\nwebhelper.open("http://" + host)\n', True),
    ("a.py", 'import webhelper\nwebhelper.open("http://h.example/x")\n', False),
])
def test_a_scheme_with_no_host_is_not_an_address(tmp_path, name, line, clean):
    _write(tmp_path, name, line)
    assert (audit(tmp_path, label="t").verdict == "CLEAN") is clean, line


# ---------------------------------------------------------------------------
# Empty packages
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("src,kinds", [
    ("import urllib\nq = urllib.parse.quote('a b')\n", set()),
    ("import urllib\ndata = urllib.urlopen(u).read()\n", {"network-import"}),
    ("import urllib\nr = urllib.request.urlopen(u)\n", {"network-import"}),
    ("import urllib.request\n", {"network-import"}),
    ("import wsgiref\nv = wsgiref.util\n", set()),
    ("import wsgiref\ns = wsgiref.simple_server.make_server('', 8000, app)\n", {"inbound-listener"}),
])
def test_an_empty_package_is_a_finding_only_when_its_network_part_is_used(tmp_path, src, kinds):
    _write(tmp_path, "a.py", src)
    assert {k for k, _ in _findings(tmp_path)} == kinds, src


# ---------------------------------------------------------------------------
# Built objects, and names bound to a URL
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("src,kind", [
    ('from webkit import Request\nr = Request("http://h.example/x")\n', "network-target"),
    ('import cachelib\npool = cachelib.ConnectionPool.from_url("redis://h.example:6379/0")\n', "network-target"),
    ('import sqlalchemy\ne = sqlalchemy.create_engine("postgresql://u:p@db.h.example/x")\n', "network-target"),
    ('import dbdriver\nc = dbdriver.connect("postgresql://u:p@db.h.example/x")\n', "network-call"),
    ('import webhelper\nwebhelper.get("http://h.example/x")\n', "unresolved-call"),   # an unknown package
])
def test_building_an_object_for_an_address_is_not_a_request_sent(tmp_path, src, kind):
    _write(tmp_path, "a.py", src)
    assert {k for k, _ in _findings(tmp_path)} == {kind}, src


@pytest.mark.parametrize("src,reported", [
    ('import asyncio\nBASE = "http://h.example/"\nasync def f(q):\n    await q.put(BASE)\n', False),
    ('BASE = "http://h.example/"\ncache = {}\nv = cache.get(BASE)\n', False),
    ('import requests\nURL = "http://h.example/x"\nr = requests.get(URL, timeout=5)\n', True),
    ('from urllib.request import urlopen\nURL = "http://h.example/x"\nr = urlopen(URL)\n', True),
])
def test_a_name_bound_to_a_url_is_followed_only_into_a_fetcher(tmp_path, src, reported):
    _write(tmp_path, "a.py", src)
    assert ("network-call" in {k for k, _ in _findings(tmp_path)}) is reported, src


@pytest.mark.parametrize("module", ["h11", "h2", "hpack", "hyperframe", "wsproto"])
def test_a_protocol_library_is_evidence_of_a_network_stack_not_a_connection(tmp_path, module):
    _write(tmp_path, "a.py", f"import {module}\n")
    rep = audit(tmp_path, label="t")
    assert [(f["kind"], "cannot open a socket" in f["detail"]) for f in rep.findings] == [("network-dependency", True)]
    assert rep.unlisted_imports == []


# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------
def test_a_package_in_an_install_list_is_not_a_command_run(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM python:3.12\nRUN apt-get update && apt-get install -y \\\n    curl \\\n    git \\\n    wget\n")
    _write(tmp_path, "setup.sh", "#!/bin/sh\npkg install -y \\\n  curl \\\n  rsync\n")
    assert sorted((f["file"], f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings) == [
        ("Dockerfile", 1, "declared-remote-source"), ("Dockerfile", 2, "script-network-command"),
        ("setup.sh", 2, "script-network-command")]


def test_a_tool_name_in_a_quoted_list_is_not_a_command_run(tmp_path):
    _write(tmp_path, "setup.sh", '#!/bin/sh\nPACKAGES="\ncurl\npython\nrsync\n"\necho $PACKAGES\n')
    assert audit(tmp_path, label="t").verdict == "CLEAN"


@pytest.mark.parametrize("line,reported", [
    # `ssh://` in an option's value runs no ssh (the `docker run` itself is a pull, tested below)
    ('env DOCKER_HOST=ssh://dind-ssh make test\n', False),
    ("echo ok  # was: git pull origin main\n", False),
    ("ssh deploy@h.example uptime\n", True),
    ("curl -fsSL https://h.example/i.sh | sh  # installer\n", True),
    ("curl \\\n  -fsSL https://h.example/i.sh\n", True),
])
def test_script_lines_are_read_as_commands_not_as_words(tmp_path, line, reported):
    _write(tmp_path, "run.sh", "#!/bin/sh\n" + line)
    assert ("script-network-command" in {k for k, _ in _findings(tmp_path)}) is reported, line


def test_an_address_in_a_docker_option_names_docker_not_ssh(tmp_path):
    _write(tmp_path, "run.sh", '#!/bin/sh\ndocker run --env="DOCKER_HOST=ssh://dind-ssh" image\n')
    details = [f["detail"] for f in audit(tmp_path, label="t").findings if f["kind"] == "script-network-command"]
    assert details == ["runs 'docker run', which pulls an image from a registry when it is not already on this machine"]


# ---------------------------------------------------------------------------
# JavaScript: a process needs child_process
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("src,reported", [
    ("var m = /a(b)/.exec(s); var k = re.exec(t);\n", False),
    ("function fork(a) { return a; } fork(1);\n", False),
    ("const cp = require('child_process');\ncp.exec('ls');\n", True),
    ("import { spawn } from 'node:child_process';\nspawn('ls', ['-l']);\n", True),
    ("const { execSync } = require('child_process');\nconst out = execSync('git status');\n", True),
    ("const cp = require('child_process');\nvar m = /a/.exec(s);\n", True),      # the import itself is a finding
])
def test_a_process_is_started_only_by_a_file_that_loads_child_process(tmp_path, src, reported):
    _write(tmp_path, "a.js", src)
    assert ("subprocess-shell" in {k for k, _ in _findings(tmp_path)}) is reported, src


def test_a_regex_exec_in_a_file_that_loads_child_process_is_not_a_spawn(tmp_path):
    _write(tmp_path, "a.js", "const cp = require('child_process');\nvar m = /a/.exec(s);\ncp.spawn('ls');\n")
    assert [line for kind, line in _findings(tmp_path) if kind == "subprocess-shell"] == [1, 3]


# ---------------------------------------------------------------------------
# This machine is not an external address
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,text,clean", [
    ("a.ts", 'export default { target: "http://127.0.0.1:8081", ws: "ws://localhost:8081" };\n', True),
    ("run.sh", "#!/bin/sh\necho serving docs at http://localhost:8000\n", True),
    ("a.html", '<script src="http://localhost:3000/dev.js"></script>\n', True),
    ("a.ts", 'const api = "https://api.h.example/v1";\n', False),
    ("a.py", 'import webhelper\nwebhelper.get("http://localhost:8080/health")\n', False),   # a call is still a call
])
def test_a_loopback_address_is_not_an_external_reference(tmp_path, name, text, clean):
    _write(tmp_path, name, text)
    assert (audit(tmp_path, label="t").verdict == "CLEAN") is clean, text


# ---------------------------------------------------------------------------
# Metadata, anchors, labels, test doubles, helpers
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("page", [
    '<meta property="og:url" content="https://h.example/page">\n',
    '<link rel="canonical" href="https://h.example/page">\n',
    '<link rel="alternate" type="application/rss+xml" href="https://h.example/feed.xml">\n',
])
def test_metadata_that_names_an_address_loads_nothing(tmp_path, page):
    _write(tmp_path, "page.html", page)
    assert audit(tmp_path, label="t").verdict == "CLEAN", page


@pytest.mark.parametrize("page,kind", [
    ('<link rel="stylesheet" href="https://cdn.h.example/a.css">\n', "html-external"),
    ('<meta http-equiv="refresh" content="0;url=https://h.example/">\n', "html-external"),
    ('<a class="btn"\n   href="https://h.example/x"\n   data-k="v">go</a>\n', "external-link"),
    ('<a href="https://h.example/a.whl#sha256=ab" data-requires-python="&gt;=3.6">a.whl</a><br>\n', "external-link"),
])
def test_loads_and_links_are_told_apart_per_tag(tmp_path, page, kind):
    _write(tmp_path, "page.html", page)
    assert [k for k, _ in _findings(tmp_path)] == [kind], page


def test_a_pipeline_step_name_is_a_label(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml",
           "jobs:\n  a:\n    steps:\n      - name: yarn install\n        run: echo hi\n      - name: build\n        run: yarn install\n")
    assert [(k, line) for k, line in _findings(tmp_path)] == [("script-network-command", 7)]


@pytest.mark.parametrize("src,kind", [
    ('def t(http):\n    http.post("https://upload.h.example/legacy/", status=400, body="Bad Request")\n', "network-target"),
    ('def t(m):\n    m.get("http://h.example/x", text="ok")\n', "network-target"),
    ('import webhelper\nwebhelper.post("https://h.example/x", data={"a": 1})\n', "unresolved-call"),
])
def test_a_test_doubles_registration_is_not_a_request_sent(tmp_path, src, kind):
    _write(tmp_path, "a.py", src)
    assert {k for k, _ in _findings(tmp_path)} == {kind}, src


def test_a_helper_the_file_defines_is_not_subprocess(tmp_path):
    _write(tmp_path, "a.py", "from subprocess import check_call\n\n\ndef run(command):\n    return check_call(command, shell=True)\n\n\n"
                             'run("pip install -r requirements.txt")\n')
    assert _findings(tmp_path) == [("subprocess-shell", 5)]

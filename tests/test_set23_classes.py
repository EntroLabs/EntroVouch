"""Set 23's classes, decided by the rules their neighbours already follow.

A here-document handed to a program that is not a shell or an interpreter is text it reads. A call into a listed
network package other than asyncio is named as that package's. Each case asserts both halves.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _rows(tmp_path: Path, name: str, src: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return [(f["line"], f["kind"]) for f in audit(tmp_path).findings]


NOTES = ("#!/bin/sh\ncat <<EOF | gh release create v1 --notes-file=-\nInstall with:\n\n"
         "    pip install 'pkg==1'\n\nSee https://h.example/notes\nEOF\ncurl -fsS https://h.example/after\n")


def test_release_notes_piped_into_a_program_are_text(tmp_path):
    rows = _rows(tmp_path, "release.sh", NOTES)
    assert (2, "script-network-command") in rows            # the opening line runs `gh release`
    assert (5, "script-network-command") not in rows        # `pip install` in the notes is text
    assert (7, "external-url") in rows                      # the address in the notes is still reported
    assert (9, "script-network-command") in rows            # the line after the terminator is a command again


def test_a_quoted_delimiter_or_an_arithmetic_shift_is_no_here_document(tmp_path):
    """`echo 'OUT<<OUT_EOF'` is a CI output's delimiter; the commands after it are still commands."""
    src = ("jobs:\n  a:\n    steps:\n      - run: |\n          echo 'NOTES<<NOTES_EOF' >> \"$GITHUB_OUTPUT\"\n"
           "          echo 'NOTES_EOF' >> \"$GITHUB_OUTPUT\"\n          gh release create v1\n"
           "          curl -fsSL https://h.example/x -o x\n")
    rows = _rows(tmp_path, ".github/workflows/r.yml", src)
    assert (7, "script-network-command") in rows and (8, "script-network-command") in rows, rows
    rows = _rows(tmp_path, "b.sh", "#!/bin/sh\nx=$((1 << 2))\ncurl -fsS https://h.example/x\n")
    assert (3, "script-network-command") in rows, rows


def test_a_dockerfile_run_here_document_is_a_script(tmp_path):
    rows = _rows(tmp_path, "Dockerfile", "FROM x\nRUN <<EOR\nset -e\napt-get update\napk add --no-cache curl\nEOR\n")
    assert (4, "script-network-command") in rows and (5, "script-network-command") in rows, rows


def test_a_line_closing_a_quote_opened_earlier_still_runs_what_follows(tmp_path):
    src = "#!/bin/sh\nsha=$(jq -n '{\n  a: 1\n}' | gh api \"repos/x/git/trees\" --input - --jq .sha)\n"
    rows = _rows(tmp_path, "b.sh", src)
    assert any(kind == "script-network-command" for _, kind in rows), rows


@pytest.mark.parametrize("opener", ["bash <<EOF", "cat <<EOF | sh", "ssh host <<EOF", "python3 - <<'EOF'",
                                    "cat <<EOF > run.sh"])
def test_a_here_document_a_shell_runs_or_a_file_keeps_is_still_code(tmp_path, opener):
    rows = _rows(tmp_path, "b.sh", f"#!/bin/sh\n{opener}\ncurl -fsS https://h.example/x\nEOF\n")
    assert (3, "script-network-command") in rows, opener


@pytest.mark.parametrize("src,detail_has", [
    ("import websocket\nws = websocket.create_connection('wss://h.example/ws')\n", "network package websocket"),
    ("import asyncio\nimport websocket\nws = websocket.create_connection('wss://h.example/ws')\n",
     "network package websocket"),
    ("import asyncio\nasync def f():\n    await asyncio.open_connection('h.example', 80)\n", "asyncio network connection"),
])
def test_a_shared_method_name_is_described_by_its_package(tmp_path, src, detail_has):
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    calls = [f for f in audit(tmp_path).findings if f["kind"] == "network-call"]
    assert calls and detail_has in calls[0]["detail"], calls


@pytest.mark.parametrize("files,expect", [
    # the project's own method, defined in the same file, that builds a client (set 23, opensearch-py)
    ({"pkg/connections.py": "import pkg\nclass Connections:\n    def create_connection(self, alias, **kw):\n"
                            "        return pkg.Client(**kw)\n    def get(self, alias):\n"
                            "        return self.create_connection(alias)\n"}, "unresolved-call"),
    # an object built from the project's own code
    ({"pkg/__init__.py": "", "tests/test_c.py": "from pkg.connections import Connections\nc = Connections()\n"
                                                 "c.create_connection('testing', hosts=['h.example'])\n"}, "unresolved-call"),
    # a handler of unknown origin keeps the old claim, which a measured set ruled true (kazoo)
    ({"a.py": "def f(handler):\n    return handler.create_connection(('h.example', 2181))\n"}, "network-call"),
])
def test_a_projects_own_connection_method_is_not_called_a_connection(tmp_path, files, expect):
    for name, src in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
    kinds = [f["kind"] for f in audit(tmp_path).findings if f["kind"] in ("network-call", "unresolved-call")]
    assert kinds == [expect], kinds


def test_a_call_while_the_socket_is_patched_out_reaches_nothing(tmp_path):
    src = ("from unittest import mock\nfrom pkgx.http import HTTPPolicy\n\ndef test_x():\n    policy = make()\n"
           "    with mock.patch('socket.socket') as s:\n        policy.create_connection('h.example', 443)\n"
           "    policy.create_connection('h.example', 443)\n")
    (tmp_path / "test_p.py").write_text(src, encoding="utf-8")
    rows = sorted((f["line"], f["kind"]) for f in audit(tmp_path).findings if f["kind"] != "network-import")
    assert rows == [(7, "network-target"), (8, "network-call")], rows


@pytest.mark.parametrize("src,kind", [
    ("from SimpleHTTPServer import SimpleHTTPRequestHandler\n", "network-dependency"),   # set 25: Python 2's name
    ("from CGIHTTPServer import CGIHTTPRequestHandler\n", "network-dependency"),
    ("import SocketServer\nSocketServer.TCPServer(('', 8000), None).serve_forever()\n", "inbound-listener"),
])
def test_python_2_server_modules_follow_the_handler_rule(tmp_path, src, kind):
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    assert kind in {f["kind"] for f in audit(tmp_path).findings}, src

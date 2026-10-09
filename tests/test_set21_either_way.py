"""Two either-way classes from set 21, decided by the same rule as their neighbours.

Mercurial is judged like git: by the subcommand that reaches another repository. An import from
`wsgiref.simple_server` binds a socket only when it takes the server, as with `http.server`.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, src: str) -> set:
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    return {f["kind"] for f in audit(tmp_path).findings}


@pytest.mark.parametrize("argv,reported", [
    ('["hg", "status"]', False),
    ('["hg", "add", "x"]', False),
    ('["hg", "commit", "-m", "x"]', False),
    ('["hg", "-R", "repo", "branches"]', False),
    ('["hg", "rm"] + names', False),
    ('["hg", "pull"]', True),
    ('["hg", "clone", "https://h.example/r"]', True),
    ('["hg", "push", "-f"]', True),
    ('["hg", "incoming"]', True),
    ('["hg"] + args', True),                     # the subcommand is not spelled out
])
def test_mercurial_is_judged_by_its_subcommand(tmp_path, argv, reported):
    kinds = _kinds(tmp_path, f"import subprocess\nnames = []\nargs = []\nsubprocess.run({argv})\n")
    assert ("subprocess-net-binary" in kinds) is reported, argv


@pytest.mark.parametrize("call,reported", [
    ("os.execvp('/usr/bin/hg', ['/usr/bin/hg', target])", True),       # argv[0] repeats the program
    ("os.execvp('hg', ['hg', 'status'])", False),
    ("os.execvp('hg', ['hg', 'pull'])", True),
])
def test_an_exec_call_repeating_the_program_is_still_judged_by_its_subcommand(tmp_path, call, reported):
    kinds = _kinds(tmp_path, f"import os\ntarget = input()\n{call}\n")
    assert ("subprocess-net-binary" in kinds) is reported, call


@pytest.mark.parametrize("src,kind", [
    ("from wsgiref.simple_server import demo_app\n", "network-dependency"),
    ("from wsgiref.simple_server import make_server\n", "inbound-listener"),
    ("from wsgiref.simple_server import WSGIServer\n", "inbound-listener"),
])
def test_an_application_from_simple_server_binds_nothing(tmp_path, src, kind):
    assert _kinds(tmp_path, src) == {kind}, src

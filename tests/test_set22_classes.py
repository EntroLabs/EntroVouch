"""Set 22's classes, decided by the rule their neighbours already follow.

`git remote` is judged by its subcommand, as git and Mercurial are. A URL with no host names neither this machine
nor another one. A method named like asyncio's server or connection call is judged by what it is called on.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, src: str) -> set:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return {f["kind"] for f in audit(tmp_path).findings}


@pytest.mark.parametrize("argv,reported", [
    ('["git", "remote"]', False),                              # lists the remotes
    ('["git", "remote", "-v"]', False),
    ('["git", "remote", "add", "u", url]', False),             # writes local configuration
    ('["git", "remote", "set-url", "origin", url]', False),
    ('["git", "remote", "update"]', True),                     # fetches every remote
    ('["git", "remote", "prune", "origin"]', True),
    ('["git", "remote", "show", "origin"]', True),
    ('["git", "fetch", "u"]', True),
])
def test_git_remote_is_judged_by_its_subcommand(tmp_path, argv, reported):
    kinds = _kinds(tmp_path, "a.py", f"import subprocess\nurl = input()\nsubprocess.check_call({argv})\n")
    assert ("git-remote" in kinds) is reported, argv


@pytest.mark.parametrize("src,kind", [
    ('import fsspec\ndef f(host):\n    fsspec.open("ftp:///archive.zip", "wb", host=host)\n', "unresolved-call"),
    ('import smart_open\nsmart_open.open("http:///blah.txt", "w")\n', "unresolved-call"),
    ('import requests\nrequests.get("http://localhost:8000/x")\n', "loopback-call"),
    ('import requests\nrequests.get("https://h.example/x")\n', "network-call"),
])
def test_a_url_with_no_host_is_not_this_machine(tmp_path, src, kind):
    kinds = _kinds(tmp_path, "a.py", src) - {"network-import"}
    assert kinds == {kind}, src


@pytest.mark.parametrize("src,kind", [
    # paramiko's Transport negotiates as an SSH server on a socket accepted elsewhere
    ("def f(transport, server):\n    transport.start_server(server=server)\n", "unresolved-call"),
    # in a file that imports asyncio the name is taken as asyncio's (set 20 ruled an SSH connection's either way)
    ("import asyncio\nasync def f(conn):\n    await conn.start_server(lambda: None, '', 8022)\n", "inbound-listener"),
    # asyncio's own, and an event loop's
    ("import asyncio\nasync def f():\n    await asyncio.start_server(lambda r, w: None, 'h.example', 80)\n",
     "inbound-listener"),
    ("import asyncio\nloop = asyncio.get_event_loop()\nloop.create_server(lambda: None, '0.0.0.0', 25)\n",
     "inbound-listener"),
    ("import asyncio\nasync def f(loop):\n    await loop.create_connection(asyncio.Protocol, 'h.example', 80)\n",
     "network-call"),
    # a connection call on an object traced to a network package
    ("import paramiko\nt = paramiko.Transport(('h.example', 22))\nt.open_connection('h.example', 22)\n",
     "network-call"),
])
def test_an_asyncio_named_method_is_judged_by_its_receiver(tmp_path, src, kind):
    kinds = _kinds(tmp_path, "a.py", src) - {"network-import"}
    assert kind in kinds, (src, kinds)

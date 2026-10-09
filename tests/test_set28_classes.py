"""Forms read in set 28, each with its true neighbour still reported.

A network call given an address on this machine: an asyncio connection whose host is its second argument, and a
browser WebSocket or fetch given a written-out loopback address.
"""
from pathlib import Path

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if not f["kind"].startswith("network-import")]


def test_an_event_loop_connection_to_this_machine_is_a_loopback_call(tmp_path):
    src = ("import asyncio\nasync def go():\n    loop = asyncio.get_event_loop()\n"
           "    await loop.create_connection(lambda: P(), '127.0.0.1', 9000)\n"
           "    await loop.create_datagram_endpoint(lambda: P(), remote_addr=('localhost', 9999))\n")
    kinds = _kinds(tmp_path, "client.py", src)
    assert ("loopback-call", 4) in kinds and ("loopback-call", 5) in kinds


def test_an_event_loop_connection_to_another_host_is_still_a_network_call(tmp_path):
    src = ("import asyncio\nasync def go():\n    loop = asyncio.get_event_loop()\n"
           "    await loop.create_connection(lambda: P(), 'h.example', 9000)\n"
           "    await loop.create_connection(lambda: P(), host, port)\n")
    kinds = _kinds(tmp_path, "client.py", src)
    assert ("network-call", 4) in kinds and ("network-call", 5) in kinds


def test_a_page_socket_to_this_machine_is_a_loopback_call(tmp_path):
    page = '<script>\nvar sock = new WebSocket("ws://127.0.0.1:9000");\n</script>\n'
    assert ("loopback-call", 2) in _kinds(tmp_path, "client.html", page)
    assert ("loopback-call", 1) in _kinds(tmp_path, "a.js", 'const ws = new WebSocket("ws://localhost:17523");\n')


def test_a_page_socket_elsewhere_or_unwritten_is_still_a_network_call(tmp_path):
    page = ('<script>\nvar a = new WebSocket("wss://h.example/ws");\nvar b = new WebSocket(wsuri);\n'
            'var c = new WebSocket(`ws://127.0.0.1${path}`);\n</script>\n')
    kinds = _kinds(tmp_path, "client.html", page)
    assert ("network-call", 3) in kinds
    assert not [k for k in kinds if k[0] == "loopback-call"]       # a filled-in address is not taken for this machine
    mixed = 'fetch("http://127.0.0.1:8000/a"); fetch("https://h.example/b");\n'
    assert ("network-call", 1) in _kinds(tmp_path, "b.js", mixed)

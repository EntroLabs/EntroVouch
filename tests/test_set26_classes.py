"""Forms read in set 26, each with its true neighbour still reported.

A reply keyword on a network client's own call; a connection attached to a socket made elsewhere; a text file
whose name ends like an artifact type; a call made while a library replaces the socket; a Make variable inside a
conditional or a `define` block.
"""
import pickle
import zipfile
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _run(tmp_path: Path, name: str, text: str):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return audit(tmp_path)


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    return [(f["kind"], f["line"]) for f in _run(tmp_path, name, text).findings
            if not f["kind"].startswith(("network-import", "network-dependency"))]


# -- a reply keyword on a network client's call is the request's own body

def test_a_client_request_with_a_body_is_a_request(tmp_path):
    src = ("import httplib2\n"
           "headers, body = httplib2.Http().request('http://api.example.com', 'POST', body='{}')\n")
    assert ("network-call", 2) in _kinds(tmp_path, "a.py", src)


def test_a_registration_with_a_body_is_still_a_registration(tmp_path):
    for src in ("import responses\nresponses.post('http://api.example.com/', body='{}', status=201)\n",
                "import requests_mock\nwith requests_mock.Mocker() as m:\n"
                "    m.post('http://api.example.com/', text='ok')\n"):
        kinds = [k for k, _ in _kinds(tmp_path, "a.py", src)]
        assert "network-target" in kinds and "network-call" not in kinds, src


# -- a connection attached to a socket made elsewhere

def test_an_endpoint_on_a_socket_made_elsewhere_is_not_resolved(tmp_path):
    src = ("import asyncio\n"
           "class S:\n"
           "    async def setup(self):\n"
           "        await self.event_loop.create_datagram_endpoint(lambda: P(), sock=self.socket)\n")
    assert ("unresolved-call", 4) in _kinds(tmp_path, "a.py", src)


def test_an_endpoint_on_an_internet_socket_made_in_the_file_is_a_network_call(tmp_path):
    src = ("import asyncio, socket\n"
           "async def go(loop):\n"
           "    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\n"
           "    await loop.create_datagram_endpoint(lambda: P(), sock=sock)\n")
    assert ("network-call", 4) in _kinds(tmp_path, "a.py", src)


def test_connecting_a_given_socket_to_an_address_is_still_a_network_call(tmp_path):
    src = ("import asyncio\n"
           "async def go(loop, s):\n"
           "    await loop.sock_connect(sock=s, address=('api.example.com', 443))\n")
    assert ("network-call", 3) in _kinds(tmp_path, "a.py", src)


def test_a_server_on_a_given_socket_is_still_a_listener(tmp_path):
    src = ("import asyncio\n"
           "async def go(loop, s):\n"
           "    await loop.create_server(lambda: P(), sock=s)\n")
    assert ("inbound-listener", 3) in _kinds(tmp_path, "a.py", src)


# -- a file named like an artifact type

def test_a_text_file_named_for_a_domain_is_not_an_artifact(tmp_path):
    rep = _run(tmp_path, "samples/sapo.pt", "Domain: sapo.pt\nDomain Status: Registered\n")
    assert not rep.findings
    assert rep.files_not_read == 1


@pytest.mark.parametrize("protocol", [0, 4])
def test_a_pickle_named_pt_is_an_artifact_whatever_its_protocol(tmp_path, protocol):
    (tmp_path / "model.pt").write_bytes(pickle.dumps({"w": [1, 2, 3]}, protocol=protocol))
    assert [f["kind"] for f in audit(tmp_path).findings] == ["unanalysed-artifact"]


def test_a_zip_checkpoint_is_an_artifact(tmp_path):
    with zipfile.ZipFile(tmp_path / "model.pt", "w") as z:
        z.writestr("archive/data.pkl", "text inside")
    assert [f["kind"] for f in audit(tmp_path).findings] == ["unanalysed-artifact"]


def test_cython_source_stays_an_artifact(tmp_path):
    assert [f["kind"] for f in _run(tmp_path, "fast.pyx", "def f():\n    return 1\n").findings] \
        == ["unanalysed-artifact"]


def test_a_text_file_named_like_a_library_is_not_an_artifact(tmp_path):
    assert not _run(tmp_path, "whois/google.so", "Domain Name: google.so\n").findings


# -- a call made while a library replaces the socket

REFUSING = [
    "import httpretty, requests\n@httpretty.activate(allow_net_connect=False)\ndef t():\n"
    "    requests.get('https://api.example.com/x')\n",
    "import httpretty, requests\ndef t():\n    httpretty.enable(allow_net_connect=False)\n"
    "    requests.get('https://api.example.com/x')\n",
    "import requests\nfrom mocket import mocketize\n@mocketize(strict_mode=True)\ndef t():\n"
    "    requests.get('https://api.example.com/x')\n",
]


@pytest.mark.parametrize("src", REFUSING)
def test_a_call_under_a_double_that_refuses_real_connections_reaches_nothing(tmp_path, src):
    kinds = [k for k, _ in _kinds(tmp_path, "test_a.py", src)]
    assert "network-target" in kinds and "network-call" not in kinds


def test_a_call_under_a_double_that_passes_others_through_says_so(tmp_path):
    src = ("import requests\nfrom httpretty import httprettified\n@httprettified\ndef t():\n"
           "    requests.get('https://api.example.com/x')\n")
    hit = [f for f in _run(tmp_path, "test_a.py", src).findings if f["kind"] == "network-call"]
    assert hit and "passes others to the network" in hit[0]["detail"]


def test_the_same_call_outside_any_double_is_a_plain_network_call(tmp_path):
    src = "import requests\ndef t():\n    requests.get('https://api.example.com/x')\n"
    hit = [f for f in _run(tmp_path, "a.py", src).findings if f["kind"] == "network-call"]
    assert hit and "replaces the socket" not in hit[0]["detail"]


# -- a Make variable inside a conditional or a define block holds a command; a recipe runs one

def test_a_variable_inside_a_conditional_holds_the_command(tmp_path):
    src = "ifeq ($(OS),Linux)\n\tFETCH = curl -fsS https://h.example/x -o x\nendif\nall:\n\t$(FETCH)\n"
    kinds = [k for k, _ in _kinds(tmp_path, "Makefile", src)]
    assert "script-network-word" in kinds and "script-network-command" not in kinds


def test_a_define_block_holds_the_command(tmp_path):
    src = "define boot\n\tpip install --upgrade pip;\\\n\tpip install nox\nendef\nall:\n\t$(call boot)\n"
    kinds = [k for k, _ in _kinds(tmp_path, "Makefile", src)]
    assert "script-network-word" in kinds and "script-network-command" not in kinds


def test_a_recipe_inside_a_conditional_still_runs(tmp_path):
    src = "all:\nifeq ($(CI),1)\n\tcurl -fsS https://h.example/x -o x\nendif\n"
    assert ("script-network-command", 3) in _kinds(tmp_path, "Makefile", src)

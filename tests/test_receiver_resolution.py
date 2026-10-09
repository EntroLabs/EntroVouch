"""A fetch-named call is a network call only when what it is called on traces back to a network package.

`.get(url)` on a requests session and `.get(url)` on a cache, a mapping or the project's own helper share
a name. The name is evidence of nothing; the receiver is. Calls whose receiver is traced are reported as
`network-call`. Calls whose receiver is not traced are still reported, as `unresolved-call`, with a
sentence that claims only what the line shows. Each case below asserts both halves.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _calls(tmp_path: Path, src: str) -> list:
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    return [f["kind"] for f in audit(tmp_path).findings if f["kind"] in ("network-call", "unresolved-call")]


@pytest.mark.parametrize("src", [
    'import requests\nrequests.get("https://h.example/x")\n',
    'import requests as rq\nrq.post("https://h.example/x")\n',
    'from requests import get\nget("https://h.example/x")\n',
    'import requests\ns = requests.Session()\ns.get("https://h.example/x")\n',
    'from requests import Session\ns = Session()\ns.get("https://h.example/x")\n',
    'import requests\nrequests.Session().get("https://h.example/x")\n',
    'import httpx\nwith httpx.Client() as c:\n    c.get("https://h.example/x")\n',
    'import aiohttp\nasync def f():\n    async with aiohttp.ClientSession() as s:\n        await s.get("https://h.example/x")\n',
    'import httpx\ndef f(c: httpx.Client):\n    c.get("https://h.example/x")\n',
    'import httpx\ndef f(c: "httpx.AsyncClient"):\n    c.get("https://h.example/x")\n',
    'import httpx\nfrom typing import Optional\ndef f(c: Optional[httpx.Client]):\n    c.get("https://h.example/x")\n',
    'import requests\nclass A:\n    def __init__(self):\n        self.s = requests.Session()\n'
    '    def f(self):\n        self.s.get("https://h.example/x")\n',
    'import urllib3\npool = urllib3.PoolManager()\npool.request("GET", "https://h.example/x")\n',
    'import requests\ns = requests.Session()\nt = s\nt.get("https://h.example/x")\n',
    'import pytest\nrequests = pytest.importorskip("requests")\nrequests.get("https://h.example/x")\n',
])
def test_a_traced_receiver_is_a_network_call(tmp_path, src):
    assert _calls(tmp_path, src) == ["network-call"], src


@pytest.mark.parametrize("src", [
    'def f(client):\n    client.get("https://h.example/x")\n',                       # a parameter with no type
    'def get_repo(u):\n    return u\nget = get_repo\nget("https://h.example/x")\n',    # the project's own helper
    'class C:\n    def f(self):\n        self.client.get("https://h.example/x")\n',  # attribute never assigned here
    'import webhelper\nwebhelper.get("https://h.example/x")\n',                      # a package the tool does not list
    'c = make_store()\nc.get("https://h.example/x")\n',                             # a store of unknown kind
    'import requests\ndef f(c):\n    c.get("https://h.example/x")\n',                # requests imported, c not from it
])
def test_an_untraced_receiver_is_still_reported_and_claims_less(tmp_path, src):
    (tmp_path / "a.py").write_text(src, encoding="utf-8")
    found = [f for f in audit(tmp_path).findings if f["kind"] in ("network-call", "unresolved-call")]
    assert [f["kind"] for f in found] == ["unresolved-call"], src
    assert "NOT resolved" in found[0]["detail"] and "not shown" in found[0]["detail"]


def test_a_project_module_with_a_network_name_is_not_traced_as_one(tmp_path):
    """A tree that supplies its own `requests.py` is not using the requests package."""
    (tmp_path / "requests.py").write_text("def get(u):\n    return u\n", encoding="utf-8")
    (tmp_path / "b.py").write_text('import requests\ns = requests.Session()\ns.get("https://h.example/x")\n',
                                   encoding="utf-8")
    assert _calls(tmp_path, 'import requests\nrequests.get("https://h.example/x")\n') == [
        "unresolved-call", "unresolved-call"]
    # the same files without the project's own module: both calls are traced
    (tmp_path / "requests.py").rename(tmp_path / "helpers.py")
    assert [f["kind"] for f in audit(tmp_path).findings if f["kind"] in ("network-call", "unresolved-call")] == [
        "network-call", "network-call"]


def test_the_verdict_counts_an_unresolved_call(tmp_path):
    """Nothing is dropped: a tree whose only finding is an untraced call is not CLEAN."""
    (tmp_path / "a.py").write_text('def f(client):\n    client.get("https://h.example/x")\n', encoding="utf-8")
    rep = audit(tmp_path)
    assert rep.verdict == "FINDINGS" and [f["kind"] for f in rep.findings] == ["unresolved-call"]

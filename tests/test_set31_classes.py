"""The form read in set 31, with its true neighbours still reported.

A request object built from a URL literal and sent in the same expression is a network call; one built and sent
later stays a request object at the line that builds it.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, text: str) -> list:
    (tmp_path / "a.py").write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if not f["kind"].startswith("network-import")]


@pytest.mark.parametrize("line", [
    "r = request.urlopen(request.Request('https://h.example/login', data=b'x'))",
    "r = urllib.request.urlopen(urllib.request.Request('https://h.example/api'))",
    "urllib.request.urlretrieve(urllib.request.Request('https://h.example/f.zip'), 'f.zip')",
])
def test_a_request_built_and_sent_in_one_expression_is_a_network_call(tmp_path, line):
    src = f"import urllib.request\nfrom urllib import request\n{line}\n"
    assert ("network-call", 3) in _kinds(tmp_path, src), line
    assert ("network-target", 3) not in _kinds(tmp_path, src), line


def test_an_opener_from_urllib_sends_the_request_it_is_given(tmp_path):
    src = ("import urllib.request\nopener = urllib.request.build_opener()\n"
           "r = opener.open(urllib.request.Request('https://h.example/x'))\n")
    assert ("network-call", 3) in _kinds(tmp_path, src)


def test_a_request_built_and_sent_later_is_a_request_object_where_it_is_built(tmp_path):
    src = ("import urllib.request\nreq = urllib.request.Request('https://h.example/api', b'data')\n"
           "resp = urllib.request.urlopen(req)\n")
    assert ("network-target", 2) in _kinds(tmp_path, src)


def test_a_request_handed_to_a_queue_is_not_sent(tmp_path):
    src = "import urllib.request\njobs.put(urllib.request.Request('https://h.example/api'))\n"
    assert ("network-target", 2) in _kinds(tmp_path, src)

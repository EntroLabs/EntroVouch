"""The form read in set 32, with its true neighbours still reported.

A request to this machine's address routed through a proxy that is not this machine leaves the machine; one with no
proxy, or with a proxy on this machine, does not.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, text: str) -> list:
    (tmp_path / "a.py").write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if not f["kind"].startswith("network-import")]


@pytest.mark.parametrize("call", [
    'requests.get("http://localhost:1", proxies={"http": "non-resolvable-address"})',
    'requests.get("http://127.0.0.1:8080/x", proxies={"https": "http://proxy.example:3128"})',
    'requests.get("http://localhost:8080/x", proxies=PROXIES)',
])
def test_a_local_address_through_an_outside_proxy_is_not_a_loopback_call(tmp_path, call):
    kinds = _kinds(tmp_path, f"import requests\n{call}\n")
    assert ("unresolved-call", 2) in kinds and ("loopback-call", 2) not in kinds, call


@pytest.mark.parametrize("call", [
    'requests.get("http://localhost:8080/x")',
    'requests.get("http://localhost:8080/x", proxies={"http": "http://127.0.0.1:3128"})',
    'requests.get("http://localhost:8080/x", proxies={"http": None})',
])
def test_a_local_address_with_no_outside_proxy_is_still_a_loopback_call(tmp_path, call):
    assert ("loopback-call", 2) in _kinds(tmp_path, f"import requests\n{call}\n"), call

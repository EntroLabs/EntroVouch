"""Detection scope: what the auditors must catch, and what they must stay silent about.

Every case here was found by RUNNING the tools against purpose-built fixtures, not
by reading them. The suite has two halves and both matter equally:

  RECALL   — unobfuscated network surface that was invisible because it was simply
             absent from the blocklist. `import urllib3` is not a clever evasion;
             it is the transport `requests` is built on, and it passed clean.

  PRECISION — ordinary code that was reported as a finding. `hashlib.blake2b(data)`
             has no key argument at all and was named as literal key material.

The precision half is the more important one. This product's claim is that REVIEW
means review; published work puts static-analysis tool abandonment at false-positive
rates above 20-30%, so a false positive on common code costs more than the finding
is ever worth. A recall fix that manufactures false positives is not a fix, which is
why both halves are asserted in the same file.
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, no_egress_auditor


def _get(obj, field):
    """Reports carry findings as dicts or dataclasses depending on entry point."""
    return obj[field] if isinstance(obj, dict) else getattr(obj, field)


def _write(tmp_path: Path, name: str, src: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(src).lstrip(), encoding="utf-8")
    return p


def _egress_kinds(tmp_path: Path) -> set[str]:
    rep = no_egress_auditor.audit(tmp_path)
    return {_get(f, "kind") for f in rep.findings}


# --------------------------------------------------------------------------
# RECALL — plain, unobfuscated network modules that were previously invisible
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("urllib3", "import urllib3\nurllib3.PoolManager().request('GET','http://x')"),
    ("httpcore", "import httpcore"),
    ("h11", "import h11"),
    ("webbrowser", "import webbrowser\nwebbrowser.open('http://x/beacon')"),
    ("xmlrpc_client", "import xmlrpc.client"),
    ("mp_connection", "from multiprocessing.connection import Client"),
    ("asyncore", "import asyncore"),
    ("zmq", "import zmq"),
    ("redis", "import redis"),
    ("pymongo", "import pymongo"),
    ("psycopg2", "import psycopg2"),
    ("pika", "import pika"),
    ("kafka", "import kafka"),
    ("paho", "import paho"),
    ("tornado", "import tornado"),
    ("openai", "import openai"),
    ("anthropic", "import anthropic"),
    ("huggingface_hub", "import huggingface_hub"),
    ("transformers", "from transformers import AutoModel"),
    ("wandb", "import wandb"),
])
def test_plain_network_import_is_caught(tmp_path, name, src):
    """No obfuscation. A linter reads these without effort; so must we."""
    _write(tmp_path, f"{name}.py", src)
    assert "network-import" in _egress_kinds(tmp_path), \
        f"{name}: unobfuscated network module reported CLEAN"


def test_asyncio_network_call_is_caught(tmp_path):
    _write(tmp_path, "a.py", """
        import asyncio
        async def go():
            r, w = await asyncio.open_connection('host', 80)
    """)
    assert "network-call" in _egress_kinds(tmp_path)


def test_asyncio_import_alone_is_not_a_finding(tmp_path):
    """The precision half of the asyncio decision.

    asyncio appears in 47 files of the authoring estate and is overwhelmingly
    concurrency, not sockets. Flagging the bare import would have traded one
    recall gap for a far larger false-positive problem.
    """
    _write(tmp_path, "a.py", """
        import asyncio
        async def main():
            await asyncio.sleep(0)
            await asyncio.gather(*[])
    """)
    assert _egress_kinds(tmp_path) == set()


# --------------------------------------------------------------------------
# INBOUND is reported, and reported SEPARATELY
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("socketserver", "import socketserver"),
    ("wsgiref", "from wsgiref.simple_server import make_server"),
    ("http_server", "import http.server"),
])
def test_listening_socket_is_inbound_not_egress(tmp_path, name, src):
    """A bound port is not exfiltration, but it IS part of what a buyer means by
    'on-prem, no telemetry'. Answering the narrow question while missing the one
    actually asked is the failure this separation exists to prevent."""
    _write(tmp_path, f"{name}.py", src)
    kinds = _egress_kinds(tmp_path)
    assert "inbound-listener" in kinds
    assert "network-import" not in kinds, "inbound must not be reported as egress"


# --------------------------------------------------------------------------
# PRECISION — ordinary code that must stay silent
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("urllib_parse", "from urllib.parse import urlparse\nurlparse('http://x')"),
    ("selectors", "import selectors\nselectors.DefaultSelector()"),
    ("uuid", "import uuid\nuuid.uuid4()"),
    ("ipaddress", "import ipaddress\nipaddress.ip_address('1.2.3.4')"),
    ("pickle", "import pickle"),
    ("plain", "def add(a, b):\n    return a + b"),
])
def test_non_network_code_is_silent(tmp_path, name, src):
    """urllib.parse is the headline case: it is string manipulation and cannot
    open a socket, but matching on the `urllib` package ROOT reported it as a
    network import. Parsing a URL is ordinary in almost any codebase."""
    _write(tmp_path, f"{name}.py", src)
    assert _egress_kinds(tmp_path) == set(), f"{name}: false positive on ordinary code"


# --------------------------------------------------------------------------
# key_provenance — positional vs keyword is the whole defect
# --------------------------------------------------------------------------
def _kp(tmp_path: Path) -> list:
    return key_provenance.scan_key_provenance(tmp_path).findings


def test_blake2b_hashing_data_is_not_a_key(tmp_path):
    """THE false positive. blake2b's signature is (data, *, key=b''): the key is
    KEYWORD-ONLY, so positional argument 0 is data. Reading it as key material
    reported `hashlib.blake2b(b"...")` -- hashing a byte string -- as a literal
    key, inside the tool whose claim is that it does not cry wolf."""
    _write(tmp_path, "h.py", 'import hashlib\nd = hashlib.blake2b(b"just hashing data")\n')
    assert _kp(tmp_path) == [], "plain blake2b hash reported as key material"


def test_blake2b_with_real_keyword_key_is_caught(tmp_path):
    """The recall side of the same fix: the keyword form was never checked at all,
    so a genuinely keyed blake2b was MISSED before this."""
    _write(tmp_path, "h.py", 'import hashlib\nhashlib.blake2b(b"m", key=b"hardcoded")\n')
    assert len(_kp(tmp_path)) == 1


@pytest.mark.parametrize("name,src", [
    ("hmac", 'import hmac, hashlib\nhmac.new(b"lit", b"m", hashlib.sha256)\n'),
    ("pbkdf2", 'import hashlib\nhashlib.pbkdf2_hmac("sha256", b"lit", b"s", 1000)\n'),
    ("scrypt", 'import hashlib\nhashlib.scrypt(b"lit", salt=b"s", n=2, r=8, p=1)\n'),
])
def test_real_literal_key_material_is_still_caught(tmp_path, name, src):
    """Each of these takes key material at a DIFFERENT position: hmac at 0,
    pbkdf2_hmac at 1, scrypt at 0. A single shared rule cannot express that,
    which is how the blake2b defect was built."""
    _write(tmp_path, f"{name}.py", src)
    assert len(_kp(tmp_path)) == 1, f"{name}: real literal key material missed"


# --------------------------------------------------------------------------
# CBOM — the three structural holes
# --------------------------------------------------------------------------
def _primitives(tmp_path: Path) -> set[str]:
    return {_get(c, 'primitive') for c in cbom.build_cbom(tmp_path).components}


def test_jwt_rs256_is_inventoried(tmp_path):
    """A CBOM exists to find the quantum-vulnerable signatures a PQC migration
    must replace. In a web service those live in a JWT, and `algorithm="RS256"`
    produced ZERO components before this."""
    _write(tmp_path, "j.py", 'import jwt\njwt.encode({"a": 1}, "k", algorithm="RS256")\n')
    prims = _primitives(tmp_path)
    assert any("RSASSA" in p for p in prims), prims


def test_pem_private_key_in_source_is_inventoried(tmp_path):
    """An actual private key in the tree yielded no component at all: the
    inventory named algorithms a codebase referenced and stayed silent about
    key material sitting in front of it."""
    _write(tmp_path, "k.py", 'PEM = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow..."\n')
    assert any("private key" in p for p in _primitives(tmp_path))


@pytest.mark.parametrize("name,src,want", [
    ("pbkdf2", 'import hashlib\nhashlib.pbkdf2_hmac("sha256", b"p", b"s", 1)\n', "PBKDF2"),
    ("scrypt", 'import hashlib\nhashlib.scrypt(b"p", salt=b"s", n=2, r=8, p=1)\n', "scrypt"),
    ("bcrypt", "import bcrypt\n", "bcrypt"),
    ("argon2", "import argon2\n", "Argon2"),
])
def test_kdfs_are_inventoried(tmp_path, name, src, want):
    _write(tmp_path, f"{name}.py", src)
    assert any(want.lower() in p.lower() for p in _primitives(tmp_path))


def test_os_urandom_is_recognised_as_csprng(tmp_path):
    """`secrets` was SAFE and `os.urandom` was nothing, despite an identical
    guarantee -- a recall asymmetry inside a single category."""
    _write(tmp_path, "r.py", "import os\nos.urandom(32)\n")
    assert any("urandom" in p for p in _primitives(tmp_path))


# --------------------------------------------------------------------------
# The scope statement must keep saying the honest word
# --------------------------------------------------------------------------
def test_readme_states_underapproximation():
    """A permanent property of the tool, not a correction log entry.

    The shipped scope statement already disclosed obfuscation and dynamically
    constructed names. A reader finishes that sentence believing the PLAIN cases
    are covered -- and `import urllib3` was a plain case that was invisible. The
    stated scope and the perceived scope were different sets. This asserts the
    README closes that gap in the analyser's own vocabulary.
    """
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "underapproximat" in readme.lower(), \
        "README must state that the analyser underapproximates"


# --------------------------------------------------------------------------
# DEPENDENCY EVIDENCE vs A NETWORK CALL — two different claims
#
# Measured over 20 well-known Python repositories: this one conflation produced
# 32 of 257 non-dynamic findings, a 12.5% false-positive rate, and every single
# false positive was a submodule of a network package. Reclassifying them took
# it to 0% with no loss of recall - the finding survives, it just stops
# asserting a network call at a line that cannot make one.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("requests_structures", "from requests.structures import CaseInsensitiveDict"),
    ("requests_compat",     "from requests.compat import urlparse"),
    ("urllib3_exceptions",  "from urllib3.exceptions import HTTPError"),
    ("urllib3_util",        "from urllib3.util import Retry"),
    ("trio_testing",        "from trio.testing import wait_all_tasks_blocked"),
])
def test_pure_submodule_is_dependency_evidence_not_a_network_call(tmp_path, name, src):
    """`requests.structures` is a dict subclass with no network tokens in its
    source. Reporting it as `network-import` claims a socket may open at that
    line, and none can."""
    _write(tmp_path, f"{name}.py", src)
    kinds = _egress_kinds(tmp_path)
    assert "network-dependency" in kinds, f"{name}: dependency evidence was lost"
    assert "network-import" not in kinds, f"{name}: still claimed as a network call"


@pytest.mark.parametrize("name,src", [
    ("root",        "import requests"),
    ("real_entry",  "from urllib.request import urlopen"),
    ("urllib3root", "import urllib3"),
    ("api_client",  "from openai import OpenAI"),
])
def test_real_entry_points_are_still_network_imports(tmp_path, name, src):
    """The recall side. A module listed EXACTLY is an entry point, not evidence -
    `urllib.request` is a submodule too, and it opens sockets."""
    _write(tmp_path, f"{name}.py", src)
    assert "network-import" in _egress_kinds(tmp_path), f"{name}: real entry point downgraded"


# --------------------------------------------------------------------------
# HOSTILE-CODEBASE RECALL — the measured tiers, pinned.
#
# The README publishes 100% / 100% / 20% across three tiers. These assert the
# two that must not regress. Tier C is deliberately NOT asserted at 20%: most
# of it is undecidable, and pinning a number we hope to improve would turn a
# future improvement into a test failure.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("plain_requests", "import requests\nrequests.post('http://e/x')"),
    ("plain_socket",   "import socket\nsocket.socket().connect(('e',80))"),
    ("lazy_in_func",   "def s(d):\n    import http.client\n    http.client.HTTPConnection('e')"),
])
def test_tier_a_plain_egress_is_always_caught(tmp_path, name, src):
    """100% is the only acceptable number here. A developer who is not hiding
    must never slip past."""
    _write(tmp_path, f"{name}.py", src)
    assert _egress_kinds(tmp_path), f"tier A miss: {name}"


@pytest.mark.parametrize("name,src", [
    ("alias",       "import socket as _s\n_s.socket()"),
    ("conditional", "try:\n    import requests as _r\nexcept ImportError:\n    _r = None"),
    ("importlib",   "import importlib\nimportlib.import_module('socket')"),
    ("split_name",  "import importlib\nimportlib.import_module('soc' + 'ket')"),
    ("curl_argv",   "import subprocess\nsubprocess.run(['curl','http://e'])"),
    ("shell_true",  "import subprocess\nsubprocess.run('wget http://e', shell=True)"),
])
def test_tier_b_light_obfuscation_is_always_caught(tmp_path, name, src):
    """Avoiding a linter is not evasion. 100% is the measured and expected number."""
    _write(tmp_path, f"{name}.py", src)
    assert _egress_kinds(tmp_path), f"tier B miss: {name}"


def test_the_interpreter_relay_is_a_named_blind_spot(tmp_path):
    """🔴 A MISS ASSERTED AS A MISS, which is unusual and deliberate.

    `subprocess.run([sys.executable, "-c", "...urlopen..."])` is real egress and
    is NOT caught. Catching it means treating the Python interpreter as a network
    binary, and `sys.executable` appears 457 times across 247 files in the
    20-repository corpus - almost all test runners and build scripts.

    ⭐ The fix would trade one miss for hundreds of false positives, so it was
    measured and declined. This test exists so that a future session that "fixes"
    it has to delete an explanation first, rather than discovering the cost after
    shipping.
    """
    _write(tmp_path, "relay.py",
           "import subprocess, sys\n"
           "subprocess.run([sys.executable, '-c', \"import urllib.request\"])\n")
    assert _egress_kinds(tmp_path) == set(), \
        "the interpreter relay is now caught - re-measure the false-positive cost on real repositories before keeping this"

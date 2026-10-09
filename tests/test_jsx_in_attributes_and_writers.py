"""An element inside an opening tag's attribute and a fragment's closing tag, a generic function type in TSX, pandas
writers and SQL runners, names rebound by an import, a function or a `case` pattern, cbom refusal names as words and
OpenSSL DES names, more UNC spellings, `setdefault` in setup.py, one requirement reached many ways, a database client
after a sourced file, pycryptodome keys, Python files by convention and CGI shebangs, a URL's user information, `dotnet
--no-build`, and a notebook cell opening with a blank line. Each test asserts both halves where there are two: the
false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom
from entrovouch.no_egress_auditor import _URL_HOST_RE, audit


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _sbom(root: Path):
    return asdict(sbom.build_sbom(root, label="t"))


# ---------------------------------------------------------------- JSX
@pytest.mark.parametrize("element", [
    'title={<span>Press ` to <code>**/*.log</code> open</span>}',
    'extra={<>See /* docs</>}',
    'renderItem={(i) => <li>Don\'t ` {i}</li>}',
])
def test_an_element_inside_an_attribute_is_followed(tmp_path, element):
    _write(tmp_path, "a.jsx", f"export const L = () => <Card {element} />;\n"
                              "fetch('https://api.example.com/z', {method: 'POST'});\n/** end */\n")
    assert ("a.jsx", 2, "network-call") in _found(tmp_path)


def test_a_generic_function_type_is_not_an_element(tmp_path):
    _write(tmp_path, "a.tsx", "export const H = () => <p>Press ` here</p>;\nconst pick: <T>(xs: T[]) => T = (xs) => xs[0];\n"
                              'const axios = require("axios");\naxios.post("https://api.example.com/x");\n')
    found = _found(tmp_path)
    assert ("a.tsx", 3, "network-import") in found and ("a.tsx", 4, "network-call") in found


# ---------------------------------------------------------------- pandas
def test_pandas_writers_and_sql(tmp_path):
    _write(tmp_path, "p.py", 'import pandas as pd\ndf = pd.DataFrame()\ndf.to_csv("s3://bucket/x.csv")\n'
                             'df.to_parquet("gs://b/y.parquet")\npd.read_sql("select 1", "postgresql://db.example.com/x")\n'
                             'df.to_sql("t", "mysql://localhost/x")\ndf.to_csv("out.csv")\npd.read_sql("select 1", conn)\n')
    assert _found(tmp_path) == [("p.py", 3, "network-call"), ("p.py", 4, "network-call"), ("p.py", 5, "network-call"),
                                ("p.py", 6, "loopback-call")]


# ---------------------------------------------------------------- names rebound
@pytest.mark.parametrize("rebind", ["try:\n    from local_settings import HOST\nexcept ImportError:\n    pass\n",
                                    "from settings import API as HOST\n", "def HOST():\n    return 'https://x.example.com'\n",
                                    "import sys\nmatch sys.argv:\n    case [_, HOST]:\n        pass\n"])
def test_a_name_rebound_is_not_its_literal(tmp_path, rebind):
    _write(tmp_path, "c.py", 'import requests\nHOST = "http://localhost:8000/api"\n' + rebind + "requests.get(HOST)\n")
    assert [k for _, _, k in _found(tmp_path) if k in ("loopback-call", "network-call")] == []


# ---------------------------------------------------------------- cbom
def test_refusal_names_are_words(tmp_path):
    _write(tmp_path / "a", "a.py", 'BLOCKCHAIN_CURVES = ["secp256k1"]\nBLOCK_CIPHERS = ["DES-CBC3-SHA"]\n'
                                   'LEGACY_ALGORITHMS = ["RS256"]\n')
    prims = sorted({c["primitive"] for c in asdict(cbom.build_cbom(tmp_path / "a", label="t"))["components"]})
    assert "ECDSA/EC" in prims and "DES/3DES" in prims and any("RS256" in p or "RSA" in p for p in prims), prims
    _write(tmp_path / "b", "a.py", 'WEAK_CIPHERS = ["RC4", "DES-CBC3-SHA"]\ndef is_insecure(a):\n    return a in ("MD5",)\n')
    assert asdict(cbom.build_cbom(tmp_path / "b", label="t"))["components"] == []


@pytest.mark.parametrize("name", ["DES-CBC3-SHA", "des-ede3-cbc", "des-cbc"])
def test_openssl_des_names(tmp_path, name):
    _write(tmp_path, "a.py", f'import ssl\nc = ssl.create_default_context()\nc.set_ciphers("{name}")\n')
    assert "DES/3DES" in [c["primitive"] for c in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]]


# ---------------------------------------------------------------- UNC
def test_more_unc_spellings(tmp_path):
    _write(tmp_path / "py", "u.py", "open(r'\\\\?\\UNC\\srv\\share\\x')\nopen(r'\\\\host@SSL\\DavWWWRoot\\x')\n"
                                    "open(r'\\\\?\\C:\\x')\n")
    assert _found(tmp_path / "py") == [("u.py", 1, "network-call"), ("u.py", 2, "network-call")]
    _write(tmp_path / "ps", "a.ps1", "Copy-Item \\\\?\\UNC\\srv\\share\\x .\n")
    assert [k for _, _, k in _found(tmp_path / "ps")] == ["script-network-command"]


# ---------------------------------------------------------------- setup.py
def test_setdefault_and_one_requirement_many_ways(tmp_path):
    _write(tmp_path / "a", "setup.py", "from setuptools import setup\ndeps = ['click']\nkw = {}\n"
                                       "kw.setdefault('install_requires', deps)\ndeps.append('requests')\nsetup(name='x', **kw)\n")
    assert sorted(c["name"] for c in _sbom(tmp_path / "a")["components"]) == ["click", "requests"]
    _write(tmp_path / "b", "setup.py", "from setuptools import setup\nA0 = ['requests']\n" + "".join(
        f"A{k} = A{k - 1} + A{k - 1}\n" for k in range(1, 20)) + "setup(name='x', install_requires=A19)\n")
    found = _found(tmp_path / "b")
    assert found.count(("setup.py", 2, "declared-network-dependency")) == 1


# ---------------------------------------------------------------- scripts
def test_a_database_client_after_a_sourced_file(tmp_path):
    _write(tmp_path / "a", "run.sh", '#!/bin/sh\n. ./prod.env\nmysql -e "select 1"\n')
    assert [k for _, _, k in _found(tmp_path / "a")] == ["script-network-command"]
    _write(tmp_path / "b", "run.sh", '#!/bin/sh\nmysql -e "select 1"\n')
    assert [k for _, _, k in _found(tmp_path / "b")] == ["loopback-call"]


def test_dotnet_without_a_build_restores_nothing(tmp_path):
    _write(tmp_path, "ci.sh", "dotnet test --no-build\ndotnet publish --no-build -o out\ndotnet test\n")
    assert [ln for _, ln, _ in _found(tmp_path)] == [3]


# ---------------------------------------------------------------- keys
def test_pycryptodome_keys(tmp_path):
    _write(tmp_path, "m.py", 'from Crypto.Cipher import AES, ChaCha20\nimport os\nc = AES.new(b"0123456789abcdef", AES.MODE_GCM)\n'
                             'd = ChaCha20.new(key=b"k" * 32, nonce=os.urandom(8))\ne = AES.new(os.urandom(16), AES.MODE_GCM)\n')
    found = [(f["line"], f["kind"]) if isinstance(f, dict) else (f.line, f.kind)
             for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings]
    assert sorted(found) == [(3, "literal-key"), (4, "literal-key")]


# ---------------------------------------------------------------- what is Python
def test_python_by_convention_and_cgi_shebangs(tmp_path):
    _write(tmp_path, "app.cgi", "#!/usr/bin/env python3\nimport requests\n")
    _write(tmp_path, "app.wsgi", "import socket\n")
    _write(tmp_path, "SConstruct", "import urllib.request\n")
    _write(tmp_path, "x.cgi", "#!/usr/bin/perl\nuse LWP;\n")
    assert sorted(f for f, _, _ in _found(tmp_path)) == ["SConstruct", "app.cgi", "app.wsgi"]


# ---------------------------------------------------------------- URLs
@pytest.mark.parametrize("url, host", [("http://evil.example.com#@localhost", "evil.example.com"),
                                       ("http://localhost?x=@evil.com", "localhost"),
                                       ("http://a@b@localhost/", "localhost"),
                                       ("http://user:pw@localhost:8000/x", "localhost")])
def test_a_urls_host_is_after_its_last_at_and_before_its_path(url, host):
    assert _URL_HOST_RE.match(url).group(1) == host


# ---------------------------------------------------------------- notebooks
def test_a_notebook_cell_opening_with_a_blank_line(tmp_path):
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": 1, "outputs": [],
                     "source": "\n    import requests\n    x = 1\n"}]}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    assert [k for _, _, k in _found(tmp_path)] == ["network-import"]

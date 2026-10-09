"""JSX text that opens with `(`, a TSX element with type arguments, and a fixed-seed generator of ordinary JSX that must
never hide a call after it; connection strings that name a driver; pandas paths by keyword and names bound to a
connection string; Makefile programs named by a variable; settings files loaded into a script's environment;
star imports and `globals()`; allow-lists; Unix-socket connection strings; a tab inside a URL; bidi characters in
markdown; `\\\\.\\UNC\\`; a cipher key's wording. Each test asserts both halves where there are two: the false thing is
gone, the true neighbour stays."""
from __future__ import annotations

import json
import random
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance
from entrovouch.no_egress_auditor import _check_ecmascript, audit, markdown_code


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


# ---------------------------------------------------------------- JSX
@pytest.mark.parametrize("rel, body", [
    ("Hint.jsx", "export const H = () => <small>(matches src/**/*.ts)</small>;\n"),
    ("Hint.jsx", "export function H() {\n  return (\n    <div>\n      <Text>\n        (see /* here)\n      </Text>\n"
                 "    </div>\n  );\n}\n"),
    ("F.tsx", "export const F = () => <Field<Values> name=\"x\">Match /* files</Field>;\n"),
])
def test_jsx_text_opening_with_a_bracket_hides_no_code(tmp_path, rel, body):
    _write(tmp_path, rel, body + "export const save = () => fetch('https://api.example.com/save', {method: 'POST'});\n"
                                 "/** end */\n")
    assert (rel, body.count("\n") + 1, "network-call") in _found(tmp_path)


def test_a_type_parameter_list_still_hides_no_code(tmp_path):
    _write(tmp_path, "a.tsx", "export const H = () => <p>Press ` here</p>;\nconst pick: <T>(xs: T[]) => T = (xs) => xs[0];\n"
                              'const axios = require("axios");\naxios.post("https://api.example.com/x");\n')
    found = _found(tmp_path)
    assert ("a.tsx", 3, "network-import") in found and ("a.tsx", 4, "network-call") in found


_TAGS = ["p", "div", "span", "li", "Foo", "Bar.Baz", "small", "td", "code", "kbd", "a"]
_WORDS = ["hello", "(beta)", "(", "src/**/*.ts", "`", "/*", "Don't", "x", "(note: /* here)", "a < b", "it's", "*/"]
_ATTRS = ['className="x"', "id='y'", "onClick={() => go(1)}", "style={{ color: 'red' }}", "disabled",
          "title={`t ${a}`}", 'data-x="/*"', 'href="https://example.com/a"', "render={(i) => <li>{i}</li>}",
          "label={<span>it's</span>}", "{...props}", "value={a > b ? 1 : 2}", "re={/a\\/b/}"]


def _jsx(rng: random.Random, depth: int = 0) -> str:
    def text(d):
        parts = []
        for _ in range(rng.randint(1, 5)):
            r = rng.random()
            if r < 0.55:
                parts.append(rng.choice(_WORDS))
            elif r < 0.75 and d < 3:
                parts.append(_jsx(rng, d + 1))
            elif r < 0.85:
                parts.append("{" + rng.choice(["x", "a.b", "'s'", "`t`", "f(1)", "c ? 'a' : 'b'", "/* c */"]) + "}")
            else:
                parts.append("\n" + "  " * d)
        return rng.choice(["", " ", "\n"]).join(parts)
    tag = rng.choice(_TAGS)
    attrs = " ".join(rng.sample(_ATTRS, rng.randint(0, 2)))
    opening = f"<{tag}{' ' + attrs if attrs else ''}"
    if rng.random() < 0.15:
        return opening + " />"
    if rng.random() < 0.1:
        return "<>" + text(depth) + "</>"
    return opening + ">" + text(depth) + f"</{tag}>"


def test_ordinary_jsx_never_hides_the_call_after_it(tmp_path):
    rng = random.Random(20261007)
    forms = ["export const C = () => {el};", "export function C() {{ return {el}; }}",
             "export function C() {{\n  return (\n    {el}\n  );\n}}", "export const C = (p) => cond ? {el} : null;",
             "const list = items.map((i) => {el});", "const pick: <T>(xs: T[]) => T = (xs) => xs[0];\nconst D = () => {el};"]
    tail = ("\nexport const send = () => fetch('https://api.example.com/x');\nconst z = `q`;\n"
            "/** Calls fetch('https://doc.example.com/y') once. */\nexport default C;\n")
    missed, invented = [], []
    for k in range(300):
        src = "\n".join(rng.choice(forms).format(el=_jsx(rng)) for _ in range(rng.randint(1, 3))) + tail
        p = _write(tmp_path, f"c{k}.jsx", src)
        call = src.count("\n", 0, src.index("fetch(")) + 1
        found = _check_ecmascript(p, p.name)
        if not any(f.line == call and f.kind == "network-call" for f in found):
            missed.append(k)
        if any(f.line == call + 2 and f.kind == "network-call" for f in found):
            invented.append(k)              # the doc comment's words read as a call
    assert missed == [] and invented == []


# ---------------------------------------------------------------- connection strings
@pytest.mark.parametrize("dsn", ["postgresql+psycopg2://app:pw@db.prod.example.com/orders",
                                 "mssql+pyodbc://u@db2.example.com/x", "oracle+oracledb://u@ora.example.com/x",
                                 "cockroachdb://u@crdb.example.com:26257/x", "trino://u@trino.example.com:443/x"])
def test_a_connection_string_naming_a_driver(tmp_path, dsn):
    _write(tmp_path, "x.py", f'from sqlalchemy import create_engine\neng = create_engine("{dsn}")\n')
    assert ("x.py", 2, "network-target") in _found(tmp_path)


def test_sql_magics_naming_a_driver(tmp_path):
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": k + 1, "outputs": [], "source": src}
                    for k, src in enumerate(["%sql postgresql+psycopg2://u:p@db.example.com/x\n",
                                             "%%sql mssql+pyodbc://u@db2.example.com/x\nSELECT 1\n"])]}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    assert [(ln, k) for _, ln, k in _found(tmp_path) if k == "network-call"] == [(1, "network-call"), (2, "network-call")]


def test_pandas_paths_by_keyword_and_bound_connection_strings(tmp_path):
    _write(tmp_path, "p.py", 'import pandas as pd\ndf = pd.DataFrame()\ndf.to_parquet(path="gs://b/y.parquet")\n'
                             'df.to_excel(excel_writer="s3://b/x.xlsx")\npd.read_pickle("s3://b/p.pkl")\n'
                             'ENG = "postgresql://u@db2.example.com/x"\npd.read_sql("select 1", ENG)\n'
                             'pd.read_sql("select 1", "postgresql:///local")\n'
                             'pd.read_sql("select 1", "postgresql://%2Fvar%2Frun%2Fpostgresql/x")\n')
    assert _found(tmp_path) == [("p.py", 3, "network-call"), ("p.py", 4, "network-call"), ("p.py", 5, "network-call"),
                                ("p.py", 7, "network-call"), ("p.py", 8, "loopback-call"), ("p.py", 9, "loopback-call")]


# ---------------------------------------------------------------- scripts
def test_a_makefile_program_named_by_a_variable(tmp_path):
    _write(tmp_path / "a", "Makefile", "PIP = pip\nNPM := npm\ninstall:\n\t$(PIP) install requests\n\t${NPM} ci\n")
    assert [ln for _, ln, k in _found(tmp_path / "a") if k == "script-network-command"] == [4, 5]
    _write(tmp_path / "b", "Makefile", "VENV = .venv\ninstall:\n\t$(VENV)/bin/pip install -r requirements.txt\n")
    assert [k for _, _, k in _found(tmp_path / "b")] == ["script-network-command"]
    _write(tmp_path / "c", "Makefile", "TOOL = pip\nTOOL = echo\nx:\n\t$(TOOL) install requests\n")
    assert [k for _, _, k in _found(tmp_path / "c") if k == "script-network-command"] == []


@pytest.mark.parametrize("load", ["set -a; . /etc/app.env; set +a", 'eval "$(cat prod.env)"',
                                  'export $(grep -v "^#" .env | xargs)'])
def test_a_settings_file_loaded_into_the_environment(tmp_path, load):
    _write(tmp_path, "run.sh", f'#!/bin/sh\n{load}\npsql -c "select 1"\n')
    assert [k for _, _, k in _found(tmp_path)] == ["script-network-command"]


# ---------------------------------------------------------------- names bound once
@pytest.mark.parametrize("rebind", ["from settings import *\n", "globals()['URL'] = load()\n"])
def test_a_star_import_or_globals_may_rebind_an_address(tmp_path, rebind):
    _write(tmp_path, "app.py", 'import requests\nURL = "http://localhost:8000/x"\n' + rebind + "requests.get(URL)\n")
    assert [k for _, _, k in _found(tmp_path) if k in ("loopback-call", "network-call")] == []


# ---------------------------------------------------------------- cbom and keys
def test_an_allow_list_is_used(tmp_path):
    _write(tmp_path, "a.py", 'ALLOW_WEAK_HASHES = ["md5", "sha1"]\nINSECURE_ALGORITHMS_ENABLED = ["RC4"]\n'
                             'WEAK_CIPHERS = ["DES-CBC3-SHA"]\n')
    prims = {c["primitive"] for c in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]}
    assert "RC4" in prims and "DES/3DES" not in prims, prims


def test_a_cipher_key_is_said_to_expose_what_it_encrypts(tmp_path):
    _write(tmp_path, "m.py", 'import hmac\nfrom Crypto.Cipher import AES\nc = AES.new(b"0123456789abcdef", AES.MODE_GCM)\n'
                             'h = hmac.new(b"0123456789abcdef", b"m", "sha256")\n')
    details = {(f["line"] if isinstance(f, dict) else f.line): (f["detail"] if isinstance(f, dict) else f.detail)
               for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings}
    assert "readable by anyone holding the source" in details[3] and "proves integrity, NOT origin" in details[4]


# ---------------------------------------------------------------- URLs, paths, markdown
def test_a_tab_inside_a_urls_host(tmp_path):
    _write(tmp_path, "a.py", 'import urllib.request\nurllib.request.urlopen("http://localhost\\t.evil.example.com/x")\n'
                             'urllib.request.urlopen("http://localhost:8000/x")\n')
    assert [(ln, k) for _, ln, k in _found(tmp_path) if ln > 1] == [(2, "network-call"), (3, "loopback-call")]


def test_a_unc_path_through_the_device_namespace(tmp_path):
    _write(tmp_path, "u.py", "open(r'\\\\.\\UNC\\srv\\share\\x')\nopen(r'\\\\.\\pipe\\x')\n")
    assert _found(tmp_path) == [("u.py", 1, "network-call")]


def test_bidi_characters_in_a_name_are_shown_as_escapes():
    assert markdown_code("evil‮gnp.py") == "`evil\\u202egnp.py`"

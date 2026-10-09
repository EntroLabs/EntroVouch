"""The JSX reading following the elements (their text is text whatever it holds, a self-closing tag ends the
expression), one long identifier, a setup.py item built from its own dict, keyword order, removals after setup() or
of one equal entry, names bound more than one way, cipher exclusion lists, UNC paths in Python, an output through a
hard link, an indented notebook cell, Poetry's optional and a project naming itself, CircleCI run maps, imports under
TYPE_CHECKING, control characters in markdown, an all-zero key, a Dockerfile syntax directive, and an SBOM of a
missing folder. Each test asserts both halves where there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, no_egress_auditor, sbom
from entrovouch.no_egress_auditor import _strip_js_comments, audit, markdown_code


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _sbom(root: Path):
    return asdict(sbom.build_sbom(root, label="t"))


# ---------------------------------------------------------------- JSX elements
@pytest.mark.parametrize("text", [
    "You'll find it under Help. Press Ctrl+` to open the terminal.",
    "Don't close the editor. Open the terminal with Ctrl+` and run the command shown below.",
    "\n".join(f"line {k} of a long paragraph about the editor and its panes" for k in range(12)) + "\nPress Ctrl+` now.",
    "Use /* and */ for a block comment, // for a line, and ` for a template.",
])
def test_an_elements_text_hides_no_code(tmp_path, text):
    _write(tmp_path, "Help.jsx", f"export function Help() {{\n  return (\n    <p>\n{text}\n    </p>\n  );\n}}\n"
                                 "export function report(endpoint, payload) {\n"
                                 "  navigator.sendBeacon(endpoint, JSON.stringify(payload));\n}\n"
                                 "export const footer = `v1`;\n")
    line = 9 + text.count("\n")
    assert ("Help.jsx", line, "network-call") in _found(tmp_path)


@pytest.mark.parametrize("after", ['/**\n * Calls fetch("https://api.example.com") once loaded.\n */\nexport const x = 1;\n',
                                   "export const doc = `\n  fetch('https://api.example.com/v1')\n`;\n"])
def test_a_self_closing_tag_ends_the_expression(tmp_path, after):
    _write(tmp_path, "Logo.jsx", 'export const Logo = () => <img src="/logo.svg" alt="logo" />\n\n' + after)
    # (an address inside a template literal is an address written in a string, as anywhere else)
    assert [k for _, _, k in _found(tmp_path) if k == "network-call"] == []
    if after.startswith("/**"):
        assert _found(tmp_path) == []


def test_code_inside_an_elements_braces_is_code(tmp_path):
    _write(tmp_path, "B.jsx", 'export const B = () => (\n  <>\n    <button onClick={() => fetch("https://x.example.com/a")}>\n'
                              "      Don't `click` twice\n    </button>\n  </>\n);\n")
    assert ("B.jsx", 3, "network-call") in _found(tmp_path)


def test_a_type_parameter_is_not_an_element(tmp_path):
    _write(tmp_path, "g.tsx", "export const A = () => <div/>;\nexport const id = <T,>(x: T): T => x;\n"
                              "export function f<T extends object>(o: T) { return fetch(String(o)); }\n")
    assert ("g.tsx", 3, "network-call") in _found(tmp_path)


def test_one_long_identifier_costs_linear_time():
    # sixteen times the text: linear time is about sixteen times as long, quadratic about 256
    small, large = "a" * 25_000 + "\n", "a" * 400_000 + "\n"
    start = time.perf_counter()
    _strip_js_comments(small + "<p/>")
    t_small = time.perf_counter() - start
    start = time.perf_counter()
    _strip_js_comments(large + "<p/>")
    t_large = time.perf_counter() - start
    assert t_large < max(30 * t_small, 1.5), (t_small, t_large)


# ---------------------------------------------------------------- setup.py
@pytest.mark.parametrize("body, names", [
    ('from setuptools import setup\nR = {"base": ["requests", "click"]}\nR["install"] = R["base"] + ["rich"]\n'
     'setup(name="t", install_requires=R["install"])\n', [("click", "required"), ("requests", "required"),
                                                         ("rich", "required")]),
    ('from setuptools import setup\nextras = {"s3": ["boto3"]}\nextras["all"] = extras["s3"] + ["paramiko"]\n'
     'setup(name="t", install_requires=["click"], extras_require=extras)\n',
     [("boto3", "optional"), ("click", "required"), ("paramiko", "optional")]),
    ('from setuptools import setup\ndeps = ["requests"]\nsetup(name="x", install_requires=deps)\ndeps.remove("requests")\n',
     [("requests", "required")]),
    ('from setuptools import setup\ndeps = ["requests", "requests"]\ndeps.remove("requests")\n'
     'setup(name="x", install_requires=deps)\n', [("requests", "required")]),
])
def test_setup_py_items_and_removals(tmp_path, body, names):
    _write(tmp_path, "setup.py", body)
    rep = _sbom(tmp_path)
    assert sorted({(c["name"], c["scope"]) for c in rep["components"]}) == names, body
    assert not any("NOT" in u for u in rep["unknown_fields"]), body


def test_setup_py_keyword_order_does_not_change_the_inventory(tmp_path):
    head = 'from setuptools import setup\na = ["click"]\nb = a + ["boto3"]\na = b\n'
    _write(tmp_path / "one", "setup.py", head + 'setup(name="x", tests_require=b, install_requires=a)\n')
    _write(tmp_path / "two", "setup.py", head + 'setup(name="x", install_requires=a, tests_require=b)\n')
    one, two = (sorted((c["name"], c["scope"]) for c in _sbom(tmp_path / d)["components"]) for d in ("one", "two"))
    assert one == two and ("boto3", "required") in one


def test_setup_py_cycles_that_double_cost_a_bounded_time(tmp_path):
    _write(tmp_path, "setup.py", "from setuptools import setup\n" + "".join(
        f"a{k} = b{k} + b{k}\nb{k} = a{k + 1} + a{k + 1} + ['p{k}']\n" for k in range(60))
        + "a60 = a0\nsetup(name='x', install_requires=a0)\n")
    start = time.perf_counter()
    _sbom(tmp_path)
    assert time.perf_counter() - start < 30


def test_a_list_read_to_the_limit_is_incomplete(tmp_path):
    _write(tmp_path, "setup.py", "from setuptools import setup\nsetup(name='x', install_requires=["
           + ", ".join(f"'p{k}'" for k in range(10_001)) + "])\n")
    rep = _sbom(tmp_path)
    assert rep["verdict"] == "INCOMPLETE" and any("more than 10,000" in u for u in rep["unknown_fields"])
    assert not any("computed when setup.py runs" in u for u in rep["unknown_fields"])


def test_an_sbom_of_a_missing_folder_is_refused(tmp_path):
    with pytest.raises(NotADirectoryError):
        sbom.build_sbom(tmp_path / "missing", label="t")


# ---------------------------------------------------------------- names bound more than one way
def test_a_name_bound_more_than_one_way_is_not_its_literal(tmp_path):
    _write(tmp_path / "a", "client.py", 'import requests\n\ndef fetch(url):\n    return requests.get(url, timeout=5)\n\n'
                                        'def health():\n    url = "http://localhost:8080/health"\n    print(url)\n')
    assert [k for _, _, k in _found(tmp_path / "a")] == ["network-import"]
    _write(tmp_path / "b", "p.py", 'import xml.sax\n\ndef load(h):\n    with open("data.xml", "rb") as src:\n'
                                   '        xml.sax.parse(src, h)\n\ndef describe():\n    src = "https://example.com/d"\n')
    assert _found(tmp_path / "b") == [("p.py", 5, "unresolved-call")]
    # the neighbour: a name bound once to an address is still that address
    _write(tmp_path / "c", "p.py", 'import xml.sax\nFEED = "https://feeds.example.com/n.xml"\nxml.sax.parse(FEED, None)\n')
    assert _found(tmp_path / "c") == [("p.py", 3, "network-call")]


# ---------------------------------------------------------------- cbom
def test_an_algorithm_named_to_refuse_it_is_not_used(tmp_path):
    _write(tmp_path / "a", "a.py", 'import ssl\nfrom enum import Enum\n'
                                   'CIPHERS = "ECDHE+AESGCM:!aNULL:!MD5:!RC4:!3DES"\n'
                                   'def ctx():\n    c = ssl.create_default_context()\n'
                                   '    c.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES:-3DES")\n    return c\n'
                                   'def is_weak(alg):\n    return alg.upper() in ("DES", "3DES", "RC4", "MD5")\n'
                                   'WEAK_CIPHERS = ["RC4", "DES"]\nclass Mode(Enum):\n    RC4 = "release candidate 4"\n')
    prims = [c["primitive"] for c in asdict(cbom.build_cbom(tmp_path / "a", label="t"))["components"]]
    assert not {"RC4", "DES/3DES", "MD5"} & set(prims), prims
    _write(tmp_path / "b", "a.py", 'import ssl\nc = ssl.create_default_context()\nc.set_ciphers("RC4-SHA:HIGH")\n')
    prims = [c["primitive"] for c in asdict(cbom.build_cbom(tmp_path / "b", label="t"))["components"]]
    assert "RC4" in prims


# ---------------------------------------------------------------- UNC paths in Python
def test_a_unc_path_is_another_machine(tmp_path):
    _write(tmp_path, "load.py", "import shutil\nfrom pathlib import Path\nSHARE = r'\\\\fileserver\\exports\\daily.csv'\n"
                                "shutil.copy(SHARE, 'daily.csv')\nPath(r'\\\\nas\\data\\a.txt').read_text()\n"
                                "open(r'\\\\localhost\\c$\\x')\nprint(r'\\\\fs01\\share\\x')\nopen(r'C:\\a\\b')\n")
    assert _found(tmp_path) == [("load.py", 4, "network-call"), ("load.py", 5, "network-call"),
                                ("load.py", 6, "loopback-call")]


# ---------------------------------------------------------------- outputs
@pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links here")
def test_an_output_through_a_hard_link_to_a_tree_file_is_refused(tmp_path):
    tree = tmp_path / "tree"
    src = _write(tree, "b.py", "import requests\n")
    os.link(src, tmp_path / "hl.json")
    assert no_egress_auditor.main([str(tree), "--json", str(tmp_path / "hl.json")]) == 2
    assert src.read_text(encoding="utf-8") == "import requests\n"


# ---------------------------------------------------------------- notebooks
def test_an_indented_notebook_cell_is_read(tmp_path):
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": 1, "outputs": [],
                     "source": "  !git clone https://github.com/x/y\n  import requests\n"}]}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    kinds = sorted(k for _, _, k in _found(tmp_path))
    assert kinds == ["network-import", "subprocess-shell"], kinds


# ---------------------------------------------------------------- manifests
def test_poetry_optional_and_a_project_naming_itself(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "demo"\nversion = "1"\ndependencies = ["requests"]\n'
                                       '[project.optional-dependencies]\naws = ["boto3==1.34.0"]\nall = ["demo[aws]", "paramiko"]\n'
                                       '[tool.poetry.dependencies]\npython = "^3.10"\n'
                                       'websockets = {version = "^12", optional = true}\ngrpcio = "1.62.0"\n')
    comps = sorted((c["name"], c["scope"]) for c in _sbom(tmp_path)["components"])
    assert comps == [("boto3", "optional"), ("grpcio", "required"), ("paramiko", "optional"),
                     ("requests", "required"), ("websockets", "optional")]


def test_a_circleci_run_map_runs_its_command(tmp_path):
    _write(tmp_path, ".circleci/config.yml", "version: 2.1\njobs:\n  b:\n    steps:\n"
                                             '      - run: { name: fetch, command: "curl -fsSL https://example.com/x -o x" }\n'
                                             '      - run: { name: "echo command: here", command: "make" }\n')
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(5, "script-network-command")]


def test_a_dockerfile_syntax_directive_names_a_frontend_image(tmp_path):
    _write(tmp_path / "a", "Dockerfile", "# syntax=docker/dockerfile:1.7\n# escape=`\nFROM scratch\nCOPY a /a\n")
    assert _found(tmp_path / "a") == [("Dockerfile", 1, "declared-remote-source")]
    _write(tmp_path / "b", "Dockerfile", "FROM scratch\n# syntax=docker/dockerfile:1\nCOPY a /a\n")
    assert _found(tmp_path / "b") == []


# ---------------------------------------------------------------- Python imports, keys, markdown
def test_an_import_under_type_checking_is_said_not_to_run(tmp_path):
    _write(tmp_path, "t.py", "from typing import TYPE_CHECKING\nimport typing\nif TYPE_CHECKING:\n    import requests\n"
                             "if typing.TYPE_CHECKING:\n    from httpx import Client\nelse:\n    import urllib3\n")
    said = {f["line"]: "type checkers" in f["detail"] for f in audit(tmp_path, label="t").findings}
    assert said == {4: True, 6: True, 8: False}


def test_an_all_zero_key_is_written_in_the_source(tmp_path):
    _write(tmp_path, "m.py", "import hmac, hashlib, os\nh = hmac.new(bytes(32), b'm', hashlib.sha256)\n"
                             "g = hmac.new(os.urandom(32), b'm', hashlib.sha256)\n")
    found = [(f["line"], f["kind"]) if isinstance(f, dict) else (f.line, f.kind)
             for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings]
    assert found == [(2, "literal-key")]


def test_a_control_character_in_a_name_is_shown_as_its_escape():
    assert markdown_code("x\ny.py") == "`x\\x0ay.py`"
    assert markdown_code("a|b") == "`a\\|b`"

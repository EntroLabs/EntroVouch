"""JSX text that runs back to its tag over a word, a line of its own or a self-closing tag, a `/*` in JSX text, the
module name the merge keeps, the JSX look-back on a minified bundle, a setup.py that does not parse, changes to a
setup.py list in a branch or through an item, the cost and size of a setup.py, Start-Process by PowerShell's own
parameter table, a program only named before the command that runs it, a flow sequence of commands, os.exec argv[0]
and keywords, PEP 440 normal forms, a key built by repetition and `hmac.HMAC`, a SAX file opened by `with`, docker's
own options, an output written over a file of the tree, and a notebook web server. Each test asserts both halves
where there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import key_provenance, no_egress_auditor, sbom
from entrovouch.no_egress_auditor import _strip_js_comments, audit
from entrovouch.sbom import pep440_normal


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _sbom(root: Path):
    return asdict(sbom.build_sbom(root, label="t"))


CALLS = ("export async function load(id) {\n  const res = await fetch(`/api/items/${id}`);\n  return res.json();\n}\n"
         "export function track(e) {\n  navigator.sendBeacon(process.env.U, JSON.stringify(e));\n}\n")


# ---------------------------------------------------------------- a backquote in JSX text
@pytest.mark.parametrize("rel, jsx", [
    ("Terminal.jsx", "export const Hint = () => <p>Press <kbd>Ctrl+`</kbd> to open the terminal.</p>;\n"),
    ("Terminal.tsx", "export const Hint = () => <p>Press <kbd>Ctrl+`</kbd> to open the terminal.</p>;\n"),
    ("Hint.jsx", 'export function Hint() {\n  return (\n    <p className="hint">\n'
                 "      Press Ctrl+` to open the terminal, then run the command below.\n    </p>\n  );\n}\n"),
    ("Br.jsx", "export const Br = () => <p>One<br/> then ` on its own</p>;\n"),
])
def test_a_backquote_in_jsx_text_hides_no_code(tmp_path, rel, jsx):
    _write(tmp_path, rel, jsx + CALLS)
    first = jsx.count("\n") + 1
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(first + 1, "network-call"), (first + 5, "network-call")]


def test_a_type_argument_is_still_not_a_tag(tmp_path):
    _write(tmp_path, "api.tsx", "export const New = () => <span>new</span>;\n"
                                "export const get = (id) => client.get<User>(`https://api.example.com/users/${id}`);\n")
    assert ("api.tsx", 2, "external-url") in _found(tmp_path)


@pytest.mark.parametrize("module", ["nodemailer", "@aws-sdk/client-s3", "node-fetch"])
@pytest.mark.parametrize("tip", ["Type `/*` to begin a block comment.", "A block comment opens with /* in C."])
def test_jsx_text_that_reads_as_a_comment_keeps_the_module_name(tmp_path, module, tip):
    _write(tmp_path, "Tips.jsx", f"export function Tips() {{\n  return <p>{tip}</p>;\n}}\n\n"
                                 f'const client = require("{module}");\n\n/** Send it. */\n'
                                 "export const send = (m) => client.send(m);\n")
    assert ("Tips.jsx", 5, "network-import") in _found(tmp_path)


def test_a_real_comment_after_jsx_stays_a_comment(tmp_path):
    _write(tmp_path, "T.jsx", 'export const T = () => <p>Type `/*` to begin</p>;\n/** const s = require("nodemailer") */\n'
                              'export const U = () => <p>hi</p>;\n/* fetch("https://x.example.com") */\n')
    assert _found(tmp_path) == []


def test_the_jsx_look_back_costs_linear_time_on_a_bundle():
    def bundle(n):
        return 'var t="</div>";' + "".join(f"a{k}=>`x${{a}}`;" for k in range(n)) + "\n"
    small, large = bundle(4000), bundle(32000)
    start = time.perf_counter()
    _strip_js_comments(small + "<p/>")
    t_small = time.perf_counter() - start
    start = time.perf_counter()
    _strip_js_comments(large + "<p/>")
    t_large = time.perf_counter() - start
    assert t_large < max(20 * t_small, 2.0), (t_small, t_large)


# ---------------------------------------------------------------- setup.py
@pytest.mark.parametrize("body", [b'from setuptools import setup\nprint "building"\nsetup(install_requires=["requests"])\n',
                                  b"from setuptools import setup\x00\nsetup(install_requires=['requests'])\n"])
def test_a_setup_py_that_does_not_parse_is_incomplete(tmp_path, body):
    _write(tmp_path, "setup.py", body)
    rep = _sbom(tmp_path)
    assert rep["verdict"] == "INCOMPLETE" and any("does not parse" in u for u in rep["unknown_fields"])
    # the auditor reports the file once, from its Python pass
    assert [k for _, _, k in _found(tmp_path)] == ["unparseable-source"]
    assert sbom.main([str(tmp_path), "--json", str(tmp_path.parent / f"{tmp_path.name}.json")]) == 1


@pytest.mark.parametrize("body", [
    "import sys\nfrom setuptools import setup\ndeps = ['requests', 'click']\nif sys.platform == 'emscripten':\n"
    "    deps.remove('requests')\nsetup(name='x', install_requires=deps)\n",
    "from setuptools import setup\ndeps = ['requests', 'click']\ndeps.remove('requests')\ndeps.append('requests')\n"
    "setup(name='x', install_requires=deps)\n",
    "from setuptools import setup\nkw = {'install_requires': ['click']}\nkw['install_requires'].append('requests')\n"
    "setup(name='x', **kw)\n",
    "from setuptools import setup\nkw = {'install_requires': ['click']}\nkw['install_requires'] += ['requests']\n"
    "setup(name='x', **kw)\n",
    "from setuptools import setup\ndeps = {'click'}\ndeps.add('requests')\nsetup(name='x', install_requires=sorted(deps))\n",
    "from setuptools import setup\ndeps = ['click']\ndeps[:0] = ['requests']\nsetup(name='x', install_requires=deps)\n",
    "from setuptools import setup\nextras = {'aws': ['click']}\nextras['aws'].append('requests')\n"
    "setup(name='x', extras_require=extras)\n",
    "from setuptools import setup\nextras = {}\nextras.setdefault('aws', ['click']).append('requests')\n"
    "setup(name='x', extras_require=extras)\n",
])
def test_a_change_to_a_setup_py_list_keeps_what_it_may_install(tmp_path, body):
    _write(tmp_path, "setup.py", body)
    rep = _sbom(tmp_path)
    assert sorted({c["name"] for c in rep["components"]}) == ["click", "requests"], body
    assert not any("NOT" in u for u in rep["unknown_fields"]), body


def test_a_removal_that_always_runs_still_removes(tmp_path):
    _write(tmp_path, "setup.py", "from setuptools import setup\ndeps = ['requests', 'click']\ndeps.append('boto3')\n"
                                 "deps.remove('requests')\nsetup(name='x', install_requires=deps)\n")
    assert sorted(c["name"] for c in _sbom(tmp_path)["components"]) == ["boto3", "click"]


@pytest.mark.parametrize("body", [
    "from setuptools import setup\nE0 = {'a': ['requests']}\n" + "".join(
        f"E{k} = {{'a': E{k - 1}['a'] + E{k - 1}['a']}}\n" for k in range(1, 41)) + "setup(install_requires=E40['a'])\n",
    "from setuptools import setup\nD0 = {" + ", ".join(f"'k{k}': ['p{k}']" for k in range(300)) + "}\n" + "".join(
        f"D{k} = {{**D{k - 1}, **D{k - 1}}}\n" for k in range(1, 14)) + "setup(extras_require=D13)\n",
    "from setuptools import setup\nL = []\n" + "".join(f"L.append('p{k}')\n" for k in range(6000))
    + "setup(install_requires=L)\n",
], ids=["subscripts-double", "dicts-double", "six-thousand-appends"])
def test_a_setup_py_costs_a_bounded_time(tmp_path, body):
    _write(tmp_path, "setup.py", body)
    start = time.perf_counter()
    _sbom(tmp_path)
    assert time.perf_counter() - start < 30


def test_a_setup_py_is_read_to_ten_thousand_requirements(tmp_path):
    _write(tmp_path, "setup.py", "from setuptools import setup\nBIG = [" + ", ".join(f"'p{k}'" for k in range(2000))
           + "]\nEX = {" + ", ".join(f"'e{k}': BIG" for k in range(50)) + "}\nsetup(extras_require=EX)\n")
    rep = _sbom(tmp_path)
    assert len(rep["components"]) <= 10_000 and rep["verdict"] == "INCOMPLETE"
    assert any("more than 10,000" in u for u in rep["unknown_fields"])


def test_a_setup_py_nested_too_deep_is_not_read_not_a_crash(tmp_path):
    _write(tmp_path, "setup.py", "from setuptools import setup\nsetup(install_requires=['requests'] + "
           + " + ".join(["['p']"] * 3000) + ")\n")
    assert sbom.main([str(tmp_path), "--json", str(tmp_path.parent / f"{tmp_path.name}.json")]) == 1


# ---------------------------------------------------------------- PowerShell Start-Process
@pytest.mark.parametrize("line", [
    "Start-Process -Verbose git pull", 'Start-Process -Debug curl.exe "-o out.zip https://example.com/a.zip"',
    "Start-Process -Verbose:$true git pull", "Start-Process -F git -A pull",
    "Start-Process -FilePath:git -ArgumentList:pull", 'Start-Process -Environment @{A="b"; C="d"} git pull',
    "Start-Process -ErrorAction Stop -FilePath git -ArgumentList pull",
])
def test_start_process_by_its_own_parameters(tmp_path, line):
    _write(tmp_path, "run.ps1", line + "\n")
    assert [k for _, _, k in _found(tmp_path)] == ["script-network-command"], line


def test_start_process_of_a_local_program_after_a_switch_is_nothing(tmp_path):
    _write(tmp_path, "run.ps1", "Start-Process -Verbose notepad a.txt\nStart-Process -Wait -FilePath:notepad\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- one line, several commands
def test_a_program_only_named_does_not_decide_the_line(tmp_path):
    _write(tmp_path, "install.sh", "#!/bin/sh\nmytool curl x; curl -fsSL https://example.com/i.sh | sh\n"
                                   "hash curl 2>/dev/null && curl -fsSL https://example.com/i.sh | sh\n"
                                   "if command -v curl >/dev/null; then curl -fsSL https://example.com/i.sh | sh; fi\n"
                                   "hash curl 2>/dev/null\nscp a host:/b && ssh host deploy\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [
        (2, "script-network-command"), (3, "script-network-command"), (4, "script-network-command"),
        (5, "script-network-word"), (6, "script-network-command")]


def test_a_flow_sequence_of_commands(tmp_path):
    _write(tmp_path, ".gitlab-ci.yml", "deploy:\n  script: [echo deploying, git fetch origin]\n"
                                       "build:\n  script: [\"make\", 'make test']\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(2, "script-network-command")]


# ---------------------------------------------------------------- os.exec argv
def test_exec_argv0_and_keywords(tmp_path):
    _write(tmp_path, "m.py", 'import os\nos.execlp("git", "git-sync", "pull")\nos.execvp(file="git", args=["git", "pull"])\n'
                             'os.execlp("git", "anything", "status")\n')
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(2, "git-remote"), (3, "git-remote")]


# ---------------------------------------------------------------- PEP 440
@pytest.mark.parametrize("given, normal", [
    ("1.0-1", "1.0.post1"), ("1.0_post1", "1.0.post1"), ("1.0-r1", "1.0.post1"), ("1.0alpha1", "1.0a1"),
    ("1.0c1", "1.0rc1"), ("1.0preview2", "1.0rc2"), ("1.0-dev", "1.0.dev0"), ("1.0a", "1.0a0"), ("v01.02", "1.2"),
    ("1.0+Ubuntu-1", "1.0+ubuntu.1"), ("0!1.0", "1.0"), ("1!2.0.post3.dev4", "1!2.0.post3.dev4"),
    ("1.0.0-beta.2", "1.0.0b2"), ("2.0RC1", "2.0rc1"), ("not-a-version", "not-a-version"),
])
def test_pep440_normal_forms(given, normal):
    assert pep440_normal(given) == normal


def test_a_package_url_carries_the_normal_form(tmp_path):
    _write(tmp_path, "requirements.txt", "post==1.0-1\n")
    assert [c["purl"] for c in _sbom(tmp_path)["components"]] == ["pkg:pypi/post@1.0.post1"]


# ---------------------------------------------------------------- key material
@pytest.mark.parametrize("src", ['SECRET = "hunter2-signing"\nsig = hmac.HMAC(SECRET.encode(), b"m", "sha256")\n',
                                 'SECRET = "x" * 32\nsig = hmac.new(SECRET.encode(), b"m", "sha256")\n'])
def test_a_key_from_a_constant(tmp_path, src):
    _write(tmp_path, "m.py", "import hmac\n" + src)
    kinds = [f["kind"] if isinstance(f, dict) else f.kind
             for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings]
    assert "derived-from-constant" in kinds


def test_a_repeated_string_that_keys_nothing_is_nothing(tmp_path):
    _write(tmp_path, "m.py", 'SEP = "-" * 40\nprint(SEP)\n')
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings == []


# ---------------------------------------------------------------- SAX
def test_a_sax_file_opened_by_with_is_this_machine(tmp_path):
    _write(tmp_path, "a.py", "import xml.sax\ndef load(f):\n    xml.sax.parse(f, None)\n"
                             "with open('a.xml') as g:\n    xml.sax.parse(g, None)\n")
    assert _found(tmp_path) == [("a.py", 3, "unresolved-call")]


# ---------------------------------------------------------------- docker's own options
def test_docker_options_before_the_subcommand(tmp_path):
    _write(tmp_path, "run.sh", "docker --debug run --pull never alpine:3 true\ndocker -H ssh://deploy@prod ps\n"
                               "docker --debug ps\ndocker --debug run alpine:3 true\ndocker -H unix:///var/run/docker.sock ps\n")
    assert [ln for _, ln, k in _found(tmp_path)] == [2, 4]


# ---------------------------------------------------------------- outputs
@pytest.mark.parametrize("module", [no_egress_auditor, sbom])
def test_an_output_over_a_file_of_the_tree_is_refused(tmp_path, module, capsys):
    tree = tmp_path / "tree"
    src = _write(tree, "src/a.js", 'export const x = () => fetch("https://example.com");\n')
    mention = _write(tree, "src/n.py", 'print("ENTROVOUCH")\n')
    for target in (src, mention):
        before = target.read_bytes()
        assert module.main([str(tree), "--json", str(target)]) == 2
        assert target.read_bytes() == before
    # a report it wrote there itself may be written again
    assert module.main([str(tree), "--json", str(tree / "r.json")]) in (0, 1)
    assert module.main([str(tree), "--json", str(tree / "r.json")]) in (0, 1)


# ---------------------------------------------------------------- notebooks
def test_a_notebook_web_server_is_said(tmp_path):
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": 1, "outputs": [],
                     "source": "!python -m http.server 8000\n"}]}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    (f,) = audit(tmp_path, label="t").findings
    assert f["kind"] == "subprocess-shell" and "a web server for this folder (INBOUND)" in f["detail"]

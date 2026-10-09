"""TypeScript type arguments are not tags, the JSX reading as the base of the merge, Start-Process however its
parameters are written, os.exec* and os.spawn* argv, bounded setup.py resolution and setup.py forms, the JavaScript
scanner on one long line, `--pull never` after the image, a key passed as bytes, a hard-linked output, a placeholder
followed by a certificate, a malformed notebook output, compare_digest imports, a name bound to a feed address, a
flow-map pipeline step, `%%writefile` to a script, and `python -m` servers and builds. Each test asserts both halves
where there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import os
import textwrap
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sarif, sbom
from entrovouch.no_egress_auditor import _strip_js_comments, audit


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _sbom(root: Path):
    return asdict(sbom.build_sbom(root, label="t"))


# ---------------------------------------------------------------- JSX and TypeScript
@pytest.mark.parametrize("rel, text, line, kind", [
    ("App.tsx", "export const Title = () => <h1>Reports</h1>;\n\nconst sources: Array<string> = [`src/**/*.csv`];\n\n"
                'import axios from "axios";\nexport const api = axios.create({});\n\n/* helpers */\n', 5, "network-import"),
    ("api.tsx", "export const New = () => <span>new</span>;\n"
                "export const get = (id) => client.get<User>(`https://api.example.com/users/${id}`);\n", 2, "external-url"),
    ("Help.jsx", "export function Help() {\n  return <p>Press ` to open the console</p>;\n}\nconst files = `src/**/*.js`;\n"
                 'const axios = require("axios");\n/* end */\n', 5, "network-import"),
])
def test_type_arguments_and_globs_hide_nothing(tmp_path, rel, text, line, kind):
    _write(tmp_path, rel, text)
    assert (rel, line, kind) in _found(tmp_path)


def test_the_jsx_reading_keeps_comments_comments(tmp_path):
    _write(tmp_path, "Help.jsx", "export const Help = () => <p>Press ` to open the console</p>;\n"
                                 "// import axios from 'axios';\n// new WebSocket('wss://old.example.com/socket');\n"
                                 "/* see https://internal.example.com/wiki */\nexport const t = `x`;\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- PowerShell Start-Process
@pytest.mark.parametrize("line", [
    'Start-Process pip.exe -ArgumentList "install","requests"',
    'Start-Process -FilePath "npm.cmd" -ArgumentList "ci" -PassThru -Wait',
    '-FilePath "C:\\Program Files\\Git\\bin\\git.exe" -ArgumentList "fetch"',
    "Start-Process git -Wait -ArgumentList 'pull'",
    "Start-Process -ArgumentList 'pull' -FilePath git",
    "Start-Process git 'pull'",
    "Start-Process git -WorkingDirectory C:\\repo -ArgumentList pull",
    'Start-Process -FilePath git -ArgumentList ("pull")',
    "Start-Process -FilePath git -ArgumentList @('fetch', '--all')",
    "$p = Start-Process -Verb RunAs -FilePath winget -ArgumentList \"install Git.Git\"",
])
def test_start_process_however_written(tmp_path, line):
    if line.startswith("-FilePath"):
        line = "Start-Process -NoNewWindow " + line
    _write(tmp_path, "x.ps1", line + "\n")
    assert [k for _, _, k in _found(tmp_path)] == ["script-network-command"], line


@pytest.mark.parametrize("line", ["Start-Process notepad.exe -ArgumentList 'a.txt'", "Start-Process git -ArgumentList '--version'",
                                  "Start-Process $tool -ArgumentList 'x'"])
def test_start_process_of_a_local_program_is_nothing(tmp_path, line):
    _write(tmp_path, "x.ps1", line + "\n")
    assert [k for _, _, k in _found(tmp_path) if k == "script-network-command"] == []


# ---------------------------------------------------------------- os.exec* and os.spawn*
@pytest.mark.parametrize("call, kind", [
    ('os.execvp("git", ["git", "pull"])', "git-remote"),
    ('os.spawnlp(os.P_WAIT, "git", "git", "pull")', "git-remote"),
    ('os.spawnvp(os.P_WAIT, "git", ["git", "pull"])', "git-remote"),
    ('os.posix_spawn("/usr/bin/git", ["git", "pull"], os.environ)', "git-remote"),
    ('os.execve("/usr/bin/git", ["git", "fetch"], os.environ)', "git-remote"),
    ('os.execvp("npm", ["npm", "ci"])', "subprocess-net-binary"),
    ('os.spawnlp(os.P_WAIT, "pip", "pip", "install", "x")', "subprocess-net-binary"),
])
def test_exec_and_spawn_run_their_program(tmp_path, call, kind):
    _write(tmp_path, "m.py", "import os\n" + call + "\n")
    found = audit(tmp_path, label="t").findings
    assert [f["kind"] for f in found] == [kind], call
    assert "runs" in found[0]["detail"] or kind == "git-remote"


def test_exec_of_a_local_program_is_nothing(tmp_path):
    _write(tmp_path, "m.py", 'import os\nos.execvp("ls", ["ls", "-l"])\nos.execvp("git", ["git", "status"])\n')
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- setup.py: bounded, and its forms
def test_setup_py_names_that_double_cost_a_bounded_time(tmp_path):
    body = "from setuptools import setup\nA0 = ['requests']\n" + "".join(
        f"A{k} = A{k - 1} + A{k - 1}\n" for k in range(1, 41)) + "setup(name='x', install_requires=A40)\n"
    _write(tmp_path, "setup.py", body)
    start = time.perf_counter()
    rep = _sbom(tmp_path)
    assert time.perf_counter() - start < 30
    assert [c["name"] for c in rep["components"]] and rep["verdict"] == "INCOMPLETE"


@pytest.mark.parametrize("body, names", [
    ("from setuptools import setup as s\ns(name='x', install_requires=['requests'])\n", ["requests"]),
    ("from setuptools import setup\nkw = {}\nkw.update(install_requires=['requests'])\nsetup(name='x', **kw)\n",
     ["requests"]),
    ("from setuptools import setup\ndef reqs():\n    r = ['requests']\n    r.append('boto3')\n    return r\n"
     "setup(name='x', install_requires=reqs())\n", ["boto3", "requests"]),
    ('from setuptools import setup\nsetup(name="x", install_requires="""\nrequests\nboto3\n""")\n', ["boto3", "requests"]),
    ("from setuptools import setup\ndeps = ['requests', 'boto3']\ndeps.remove('boto3')\n"
     "setup(name='x', install_requires=deps)\n", ["requests"]),
    ("import sys\nfrom setuptools import setup\n"
     "setup(name='x', install_requires=['requests'] + (['pywin32'] if sys.platform == 'win32' else []))\n",
     ["pywin32", "requests"]),
    ("from setuptools import setup\nsetup(name='x', install_requires=[p for p in ['requests', 'boto3']])\n",
     ["boto3", "requests"]),
    ("from setuptools import setup\nsetup(name='x', install_requires='requests boto3'.split())\n", ["boto3", "requests"]),
])
def test_setup_py_forms(tmp_path, body, names):
    _write(tmp_path, "setup.py", body)
    rep = _sbom(tmp_path)
    assert sorted(c["name"] for c in rep["components"]) == names, body
    assert not any("NOT" in u for u in rep["unknown_fields"]), body


# ---------------------------------------------------------------- one long line
@pytest.mark.parametrize("unit", ['"\\', "/["])
def test_one_long_line_costs_linear_time(tmp_path, unit):
    small, large = unit * 8000, unit * 64000
    start = time.perf_counter()
    _strip_js_comments(small)
    t_small = time.perf_counter() - start
    start = time.perf_counter()
    _strip_js_comments(large)
    t_large = time.perf_counter() - start
    assert t_large < max(20 * t_small, 2.0), (t_small, t_large)
    _write(tmp_path, "a.js", large + "\n")
    _write(tmp_path, "b.html", "<script>" + large + "</script>\n")
    start = time.perf_counter()
    audit(tmp_path, label="t")
    assert time.perf_counter() - start < 60


# ---------------------------------------------------------------- docker
def test_pull_never_counts_only_before_the_image(tmp_path):
    _write(tmp_path, "a.sh", "docker run --pull never img\ndocker run --rm -it -v a:/b --pull=never img\n"
                             "docker run registry.example.com/team/img:1 --pull never\ndocker run --rm img sync --pull never\n"
                             "docker create --name x --pull never img\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [3, 4]


# ---------------------------------------------------------------- key material
@pytest.mark.parametrize("call", ['hmac.new(KEY.encode(), b"m", "sha256")', 'hmac.new(KEY.encode("utf-8"), b"m", "sha256")',
                                  'hmac.new(key=KEY.encode(), msg=b"m", digestmod="sha256")',
                                  'hmac.new(bytes(KEY, "utf-8"), b"m", "sha256")'])
def test_a_key_passed_as_bytes_is_the_literal(tmp_path, call):
    _write(tmp_path, "m.py", 'import hmac\nKEY = "s3cr3t-signing-key-material-1234567890"\n' + call + "\n")
    kinds = [f["kind"] if isinstance(f, dict) else f.kind for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings]
    assert "derived-from-constant" in kinds, call


def test_a_placeholder_followed_by_a_certificate_is_no_key(tmp_path):
    cert = "\n".join(["MIIC+TCCAeGgAwIBAgIUDvkT4o2Tntvy4jAZueLOtwyXGmwwDQYJKoZIhvcNAQEL"] * 6)
    _write(tmp_path, "values.yaml", "key: |\n  -----BEGIN PRIVATE KEY-----\n  <paste your key here>\n  -----END PRIVATE KEY-----\n"
                                    "cert: |\n  -----BEGIN CERTIFICATE-----\n" + textwrap.indent(cert, "  ")
                                    + "\n  -----END CERTIFICATE-----\n")
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings == []


# ---------------------------------------------------------------- adapters
@pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links here")
def test_an_adapter_does_not_write_through_a_hard_link_to_its_input(tmp_path, capsys):
    _write(tmp_path / "tree", "a.py", "import requests\n")
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(asdict(audit(tmp_path / "tree", label="t"))), encoding="utf-8")
    before = rep.read_bytes()
    os.link(rep, tmp_path / "hl.json")
    assert sarif.main([str(rep), "--out", str(tmp_path / "hl.json")]) == 2
    assert rep.read_bytes() == before


# ---------------------------------------------------------------- notebooks
def test_a_malformed_notebook_output_is_read_not_a_crash(tmp_path):
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": 1, "source": "x = 1",
                     "outputs": [{"output_type": "display_data", "metadata": {},
                                  "data": {"application/javascript": ["fetch(1)", None]}}]}]}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    assert ("n.ipynb", 1, "network-call") in _found(tmp_path)


def test_writefile_to_a_script_is_read_as_one(tmp_path):
    cells = [("%%writefile setup.sh\ncurl -fsSL https://e.example.com/i | sh\nif [ x ]; then echo; fi\n"),
             "%%writefile notes.txt\nthis is not python\n", "%%writefile app.py\nimport requests\n"]
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": k + 1, "source": s, "outputs": []}
                    for k, s in enumerate(cells)]}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    assert sorted((ln, k) for _, ln, k in _found(tmp_path)) == [(1, "script-network-command"), (3, "network-import")]


# ---------------------------------------------------------------- cbom
def test_compare_digest_imports_and_named_hashes(tmp_path):
    _write(tmp_path / "a", "a.py", "import hmac\nok = hmac.compare_digest(a, b)\n")
    _write(tmp_path / "b", "a.py", "from secrets import compare_digest\nok = compare_digest(a, b)\n")
    _write(tmp_path / "c", "a.py", 'import hashlib\nk = hashlib.pbkdf2_hmac("sha1", pw, salt, 1000)\n')
    for d in ("a", "b"):
        assert asdict(cbom.build_cbom(tmp_path / d, label="t"))["components"] == [], d
    comps = [(c["primitive"], c["quantum"]) for c in asdict(cbom.build_cbom(tmp_path / "c", label="t"))["components"]]
    assert ("SHA-1", "BROKEN") in comps and ("PBKDF2-HMAC", "REVIEW") in comps


# ---------------------------------------------------------------- the SAX parser, pipelines, python -m
def test_a_sax_source_bound_to_an_address(tmp_path):
    _write(tmp_path, "a.py", 'import xml.sax\nFEED = "https://feeds.example.com/n.xml"\nLOCAL = "feed.xml"\n'
                             "xml.sax.parse(FEED, None)\nxml.sax.parse(LOCAL, None)\n")
    assert _found(tmp_path) == [("a.py", 4, "network-call")]


def test_a_flow_map_step_runs_its_command(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
                                                 "      - {name: x, run: \"pip install requests\"}\n"
                                                 "      - {name: \"echo run: here\", uses: actions/checkout@v4}\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(6, "script-network-command")]


def test_python_m_servers_and_builds(tmp_path):
    _write(tmp_path, "a.sh", "python3 -m http.server 8000\npython -m build\npython -m build --no-isolation\n"
                             'echo "python -m build later"\n')
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(1, "inbound-listener"), (2, "script-network-command")]

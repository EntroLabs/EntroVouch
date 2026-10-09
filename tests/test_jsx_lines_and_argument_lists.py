"""JSX text a line runs back to a tag through, the merge of two readings, Start-Process's argument list, the SAX parser
by keyword and through an attribute, pulldom, quoted attributes in markup, base64 wrapped or joined in many ways,
armour headers with no key, requirements added to as setup.py runs, defaults given as paths, quoted commands, `--pull
never`, adapters aimed at their input, cbom's hash calls, Jenkins checkouts, Invoke-Expression, more programs, XML in a
frame, executables under source names, and a report with a byte-order mark. Each test asserts both halves where there
are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import base64
import json
import random
import textwrap
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sarif, sbom, verify
from entrovouch.no_egress_auditor import audit


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _kinds(root: Path) -> set[str]:
    return {k for _, _, k in _found(root)} - {"external-url"}


# ---------------------------------------------------------------- JSX text and the merge
@pytest.mark.parametrize("line", [
    "  return <p>Open the console with the backtick (`) key.</p>;",
    "  return <kbd>Key: ` opens it</kbd>;",
    "  return <p className=\"hint\">Press ` + Enter</p>;",
])
def test_jsx_text_a_line_runs_back_to_a_tag_through(tmp_path, line):
    _write(tmp_path, "Help.jsx", "export function Help() {\n" + line + "\n}\n"
                                 "export async function load(u) {\n  const r = await fetch(u);\n  return r.json();\n}\n"
                                 "const greeting = `hi`;\n")
    assert ("Help.jsx", 5, "network-call") in _found(tmp_path), line


def test_a_template_after_a_comparison_is_still_a_template(tmp_path):
    _write(tmp_path, "a.jsx", "const A = () => <div/>;\nif (a<b && c > 1) s = `x ${fetch(u)}`;\nconst t = `y`;\n")
    assert ("a.jsx", 2, "network-call") in _found(tmp_path)


def test_comments_after_a_jsx_text_backquote_stay_comments(tmp_path):
    _write(tmp_path, "Help.jsx", "export const Help = () => <p>Press ` to open the console</p>;\n"
                                 "// import axios from 'axios';\n"
                                 "// const s = new WebSocket('wss://old.example.com/socket');\n"
                                 "/* see https://internal.example.com/wiki */\nexport const t = `x`;\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- PowerShell
def test_start_process_with_an_argument_list(tmp_path):
    _write(tmp_path, "update.ps1", "Start-Process git -ArgumentList 'pull' -Wait -NoNewWindow\n"
                                   "Start-Process -FilePath npm -ArgumentList 'install' -Wait\n"
                                   "Start-Process -Wait -FilePath \"git\" -ArgumentList \"clone\",$u\n"
                                   "Start-Process notepad.exe -ArgumentList 'a.txt'\n"
                                   "Start-Process git -ArgumentList '--version'\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2, 3]


def test_invoke_expression_runs_its_string(tmp_path):
    _write(tmp_path, "a.ps1", "Invoke-Expression \"git pull\"\niex 'npm install'\nWrite-Host \"git pull is next\"\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2]


# ---------------------------------------------------------------- the SAX parser
def test_sax_by_keyword_through_an_attribute_and_not_pulldom(tmp_path):
    _write(tmp_path, "a.py", "import xml.sax\nfrom xml.dom import pulldom\nclass F:\n    def __init__(self):\n"
                             "        self.p = xml.sax.make_parser()\n    def go(self, u):\n        self.p.parse(u)\n"
                             "    def here(self):\n        self.p.parse('feed.xml')\n"
                             "xml.sax.parse(source='https://feeds.example.com/n.xml', handler=None)\n"
                             "pulldom.parse(u)\npulldom.parse('https://feeds.example.com/n.xml')\n")
    found = _found(tmp_path)
    assert ("a.py", 7, "unresolved-call") in found and ("a.py", 10, "network-call") in found
    assert not any(ln in (9, 11, 12) and k != "external-url" for _, ln, k in found)


# ---------------------------------------------------------------- markup
def test_a_quoted_attribute_holding_a_greater_than_sign(tmp_path):
    _write(tmp_path, "Logo.vue", '<template>\n  <img v-if="items.length > 0" src="https://cdn.example.com/logo.png">\n'
                                 '  <a v-if="n > 1" href="https://docs.example.com">docs</a>\n</template>\n')
    found = _found(tmp_path)
    assert ("Logo.vue", 2, "html-external") in found and ("Logo.vue", 3, "external-link") in found


@pytest.mark.parametrize("text, kinds", [
    ('<iframe src="data:text/xml,<x/>"></iframe>\n', {"dynamic-exec"}),
    ("<p>data:text/xml</p>\n", set()),
])
def test_xml_opened_in_a_frame(tmp_path, text, kinds):
    _write(tmp_path, "i.html", text)
    assert _kinds(tmp_path) == kinds


# ---------------------------------------------------------------- key armour
_RNG = random.Random(11)
_BODY = base64.b64encode(bytes(_RNG.randrange(256) for _ in range(600))).decode()
_PEM = "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(textwrap.wrap(_BODY, 64)) + "\n-----END RSA PRIVATE KEY-----\n"
_B = base64.b64encode(_PEM.encode()).decode()


def _wrap(s: str, w: int, indent: str = "") -> str:
    return "\n".join(indent + s[i:i + w] for i in range(0, len(s), w)) + "\n"


@pytest.mark.parametrize("rel, text", [
    ("x.sh", "#!/bin/sh\ncat <<EOF | base64 -d > k.pem\n" + _wrap(_B, 76) + "EOF\n"),
    ("k.yaml", "data:\n  tls.key: " + _B[:76] + "\n" + _wrap(_B[76:], 76, "    ")),
    ("conf.py", "KEY = (\n" + "".join(f'    "{_B[i:i + 60]}"\n' for i in range(0, len(_B), 60)) + ")\n"),
    ("k.json", '{"key": [\n' + ",\n".join(f'  "{_B[i:i + 60]}"' for i in range(0, len(_B), 60)) + "\n]}\n"),
    ("secret.txt", _wrap(_B, 12)),
])
def test_base64_armour_however_its_lines_are_joined(tmp_path, rel, text):
    _write(tmp_path, rel, text)
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings


@pytest.mark.parametrize("rel, text", [
    ("values.yaml", "tls:\n  key: |\n    -----BEGIN PRIVATE KEY-----\n    <paste your key here>\n    -----END PRIVATE KEY-----\n"),
    ("schema.json", '{"example": "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----"}\n'),
    ("notes.txt", "-----BEGIN PRIVATE KEY-----\nCHANGE_ME\n-----END PRIVATE KEY-----\n"),
    (".env.example", 'PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nCHANGE_ME\n-----END PRIVATE KEY-----"\n'),
])
def test_an_armour_header_with_no_key_is_a_placeholder(tmp_path, rel, text):
    _write(tmp_path, rel, text)
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings == []


def test_a_real_key_in_those_files_is_still_found(tmp_path):
    _write(tmp_path, "values.yaml", "tls:\n  key: |\n" + textwrap.indent(_PEM, "    "))
    _write(tmp_path, ".env", 'PRIVATE_KEY="' + _PEM.strip() + '"\n')
    found = key_provenance.scan_key_provenance(tmp_path, label="t").findings
    files = {f["file"] if isinstance(f, dict) else f.file for f in found}
    assert files == {"values.yaml", ".env"}


# ---------------------------------------------------------------- requirements added to as setup.py runs
def _sbom(root: Path):
    return asdict(sbom.build_sbom(root, label="t"))


@pytest.mark.parametrize("body, names", [
    ('install_requires = ["requests==2.31.0"]\nif sys.platform == "win32":\n    install_requires.append("pywin32==306")\n'
     'install_requires += ["urllib3==2.2.1"]\nsetup(name="x", install_requires=install_requires)\n',
     ["pywin32", "requests", "urllib3"]),
    ('reqs = ["flask"]\nreqs.extend(["requests"])\nsetup(name="x", install_requires=reqs)\n', ["flask", "requests"]),
    ('kw = dict(name="x", install_requires=["requests"])\nsetup(**kw)\n', ["requests"]),
    ('BASE = ["requests"]\nsetup(name="x", install_requires=BASE + ["flask"])\n', ["flask", "requests"]),
    ('extras = {}\nextras["s3"] = ["boto3"]\nsetup(name="x", extras_require=extras)\n', ["boto3"]),
    ('def reqs():\n    return None\nsetup(name="x", install_requires=reqs())\n', []),
    # an item built only from the dict itself adds nothing the other items do not hold
    ("extras = {'s3': ['boto3']}\nextras['all'] = sum(extras.values(), [])\nsetup(name='x', extras_require=extras)\n",
     ["boto3"]),
    # assigned in each branch, or chosen by a condition
    ('if sys.platform == "win32":\n    reqs = ["pywin32"]\nelse:\n    reqs = ["uvloop"]\nsetup(name="x", install_requires=reqs)\n',
     ["pywin32", "uvloop"]),
    ('kw = {} if sys.platform == "win32" else {"install_requires": ["uvloop"]}\nsetup(name="x", **kw)\n', ["uvloop"]),
    ('kw = {"name": "x"}\nreqs = ["requests"]\nkw["install_requires"] = reqs\nsetup(**kw)\n', ["requests"]),
    # a dict unpacked into another, then more items
    ('extras = {"s3": ["boto3"]}\nsetup(name="x", extras_require={**extras, "web": ["selenium"]})\n',
     ["boto3", "selenium"]),
    # `*` unpacking inside a list, and strings added together
    ('base = ["requests"]\nm = "; python_version < \'3.12\'"\nsetup(name="x", install_requires=[*base, "tomli" + m])\n',
     ["requests", "tomli"]),
])
def test_requirements_added_to_as_setup_py_runs(tmp_path, body, names):
    _write(tmp_path, "setup.py", "import sys\nfrom setuptools import setup\n" + body)
    rep = _sbom(tmp_path)
    assert sorted(c["name"] for c in rep["components"]) == names
    assert not any("NOT" in u for u in rep["unknown_fields"])


@pytest.mark.parametrize("body", [
    'reqs = ["flask"]\nreqs.append(os.environ["EXTRA"])\nsetup(name="x", install_requires=reqs)\n',
    'setup(**load_config())\n',
    "extras = {'s3': ['boto3']}\nextras['all'] = make_all()\nsetup(name='x', extras_require=extras)\n",
])
def test_an_addition_that_is_not_a_literal_is_recorded_as_not_read(tmp_path, body):
    _write(tmp_path, "setup.py", "import os\nfrom setuptools import setup\n" + body)
    rep = _sbom(tmp_path)
    assert rep["verdict"] == "INCOMPLETE" and any("NOT" in u for u in rep["unknown_fields"])


# ---------------------------------------------------------------- shell
def test_a_default_given_as_a_path(tmp_path):
    _write(tmp_path, "a.sh", '${CURL:-/usr/bin/curl} -fsSL "$U"\n"${GIT:-/usr/bin/git}" pull\n${X:-./tools/run} build\n')
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2]


def test_an_offline_flag_outside_a_quoted_command_is_the_outer_programs(tmp_path):
    _write(tmp_path, "a.sh", "bash -c 'yarn install' --offline\nnpm exec -c 'yarn install' --offline\n"
                             "yarn install --offline\nnpm config set x \"y z\" --offline\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2]


def test_pull_never_pulls_nothing(tmp_path):
    _write(tmp_path, "a.sh", "docker run --pull never img\ndocker run --pull=never img\ndocker compose up --pull never\n"
                             "docker-compose up --pull never\ndocker run --pull always img\ndocker run img\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [5, 6]


def test_more_programs_that_reach_the_network(tmp_path):
    _write(tmp_path, "a.sh", "pnpx create-vite app\nssh-keyscan github.com >> ~/.ssh/known_hosts\nntpdate pool.ntp.org\n"
                             "sendmail -t < msg.txt\necho \"run pnpx later\"\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [1, 2, 3, 4]


def test_jenkins_checkouts(tmp_path):
    _write(tmp_path, "Jenkinsfile", "pipeline {\n  stages { stage('a') { steps {\n    checkout scm\n"
                                    "    git url: 'https://github.com/o/r.git', branch: 'main'\n"
                                    "    git 'https://github.com/o/r.git'\n    echo \"checkout scm later\"\n  } } }\n}\n")
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == [3, 4, 5]


# ---------------------------------------------------------------- executables under source names
def test_an_executable_under_a_source_files_name(tmp_path):
    for name in ("a.js", "b.html", "c.css", "d.ts"):
        _write(tmp_path, name, b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
    _write(tmp_path, "ok.js", "const x = 1;\n")
    _write(tmp_path, "mz.html", "MZ is a prefix\n")
    assert sorted(f for f, _, k in _found(tmp_path) if k == "unanalysed-artifact") == ["a.js", "b.html", "c.css", "d.ts"]


# ---------------------------------------------------------------- cbom
def test_cbom_hash_calls(tmp_path):
    _write(tmp_path, "a.py", "import hashlib, secrets\nALG = 'sha1'\na = hashlib.new('sha1', usedforsecurity=False)\n"
                             "b = hashlib.md5(b'x', usedforsecurity=False)\nok = secrets.compare_digest(x, y)\n"
                             "d = hashlib.file_digest(f, 'md5')\ne = hashlib.new(ALG)\nt = secrets.token_hex(8)\n")
    comps = [(c["line"], c["primitive"], c["quantum"]) for c in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]]
    assert (3, "SHA-1", "REVIEW") in comps and (4, "MD5", "REVIEW") in comps
    assert (6, "MD5", "BROKEN") in comps and (7, "SHA-1", "BROKEN") in comps
    assert not any(ln == 5 for ln, _, _ in comps) and (8, "secrets-CSPRNG", "SAFE") in comps


# ---------------------------------------------------------------- reports
def test_an_adapter_aimed_at_its_own_input_writes_nothing(tmp_path, capsys):
    _write(tmp_path / "tree", "a.py", "import requests\n")
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(asdict(audit(tmp_path / "tree", label="t"))), encoding="utf-8")
    before = rep.read_bytes()
    assert sarif.main([str(rep), "--out", str(rep)]) == 2
    assert rep.read_bytes() == before and "reads" in capsys.readouterr().err
    assert sarif.main([str(rep), "--out", str(tmp_path / "r.sarif")]) == 0


def test_a_report_with_a_byte_order_mark_is_refused_with_the_reason(tmp_path, capsys):
    _write(tmp_path / "tree", "a.py", "import requests\n")
    rep = tmp_path / "r.json"
    rep.write_bytes(b"\xef\xbb\xbf" + json.dumps(asdict(audit(tmp_path / "tree", label="t"))).encode())
    assert verify.main([str(rep)]) == 2
    assert "byte-order mark" in capsys.readouterr().err

"""One tree, one answer: wherever the tree sits, whatever the operating system sorted first, whatever
the checkout did to line endings. And the plain forms of a spawn, an import, a manifest line, a web
reference, a key and a signature that a reader would expect a tool like this to read."""
import io
import json
import subprocess
import sys
import tokenize
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, manifests, sbom
from entrovouch.manifests import collect_manifests, tree_files
from entrovouch.no_egress_auditor import (
    _strip_js_comments, audit, report_is_intact, verify_report,
)
from entrovouch.signer import MerkleSigner

REPO = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, text: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        p.write_bytes(text)
    else:
        p.write_bytes(text.encode("utf-8"))
    return p


def _kinds(root: Path) -> set:
    return {f["kind"] for f in audit(root, label="t").findings}


# ---------------------------------------------------------------------------
# The same tree gives the same answer wherever it sits
# ---------------------------------------------------------------------------
TREE = {
    "requirements.txt": "requests==2.31\nstripe\n",
    "pyproject.toml": '[project]\nname="x"\nversion="1"\ndependencies=["boto3"]\n',
    "app.py": 'import hashlib, rsa\nSECRET_KEY = "0123456789abcdef0123456789abcdef"\nhashlib.md5(b"x")\n',
}


@pytest.mark.parametrize("parent", ["plain", "build", "dist", "venv", ".venv", "node_modules", ".tox"])
def test_a_folder_above_the_tree_named_like_a_skipped_directory_changes_nothing(tmp_path, parent):
    here = tmp_path / "plain" / "proj"
    there = tmp_path / "moved" / parent / "proj"
    for root in (here, there):
        for rel, text in TREE.items():
            _write(root, rel, text)
    a, b = audit(here, label="t"), audit(there, label="t")
    assert a.verdict == b.verdict == "FINDINGS"
    assert a.findings_digest == b.findings_digest
    assert cbom.build_cbom(here, label="t").findings_digest == cbom.build_cbom(there, label="t").findings_digest
    assert cbom.build_cbom(there).verdict == "BROKEN-CRYPTO"
    assert key_provenance.scan_key_provenance(there).verdict == "REVIEW"
    assert [c["name"] for c in sbom.build_sbom(there).components] == ["boto3", "requests", "stripe"]


def test_skipping_is_decided_by_the_path_inside_the_tree(tmp_path):
    _write(tmp_path, "src/build/hidden.py", "import requests\n")
    _write(tmp_path, "src/app.py", "x = 1\n")
    rep = audit(tmp_path, label="t")
    assert rep.verdict == "CLEAN"
    assert rep.not_scanned["skipped_directories"] == {"src/build/": 1}


# ---------------------------------------------------------------------------
# One order on every operating system
# ---------------------------------------------------------------------------
def test_files_are_ordered_by_path_bytes_not_by_the_operating_system(tmp_path):
    names = ["B.py", "a.py", "Zeta/x.py", "alpha/y.py", "a0.py", "a/x.py", "_u.py", "U.py"]
    for n in names:
        _write(tmp_path, n, "import socket\n")
    order = [rel for rel, _ in tree_files(tmp_path).files]
    assert order == sorted(names, key=lambda s: s.encode("utf-8"))
    assert order[0] == "B.py" and order.index("Zeta/x.py") < order.index("a.py")
    assert [f["file"] for f in audit(tmp_path, label="t").findings] == order


def test_findings_order_is_part_of_the_digest_and_is_fixed(tmp_path):
    _write(tmp_path, "B.py", "import requests\n")
    _write(tmp_path, "a.py", "import socket\n")
    rep = audit(tmp_path, label="t")
    assert [f["file"] for f in rep.findings] == ["B.py", "a.py"]


# A tree built to differ between systems in every way a real one can: names that sort differently
# with and without regard to case, nested directories, both line-ending styles, a folder above it
# named like a skipped directory. The digests below are constants: the same test run on Windows,
# Linux and macOS, under every supported Python, checks that all of them produce these bytes.
# When the tool's findings or scope text change on purpose, re-pin them on one system and run
# the suite on another.
PORTABLE_TREE = {
    "B.py": "import requests\n",
    "a.py": "import socket\r\nimport hashlib\r\nhashlib.md5(b'x')\r\n",
    "Zeta/x.py": "import subprocess as sp\nsp.run(['curl', 'x'])\n",
    "alpha/y.py": "from os import system\nsystem('wget x')\n",
    "a0.py": "x = 1\n",
    "a/x.py": "import urllib.request\n",
    "_u.py": "API_KEY = '0123456789abcdef0123456789abcdef'\n",
    "U.PY": "import rsa\n",
    "requirements/base.txt": "stripe==9.1.0\r\nrequests\r\n",
    "Tools/install.sh": "#!/bin/sh\ncurl -fsSL https://h.example/i | sh\n",
    "web/Index.html": "<script src=//cdn.h.example/a.js></script>\r\n",
    "notes.rst": "not read\n",
}
PORTABLE_DIGESTS = {
    "egress": "0d6840fea06183fea47ea841090ffd6f4629a5f3ffa38e655a62164d9770d012",
    "cbom": "4e4ef17ca94e0a907e8d489737b27b21103809b019257da9f8c0212a3d03b9f6",
    "sbom": "be6c4bd5690e593f1473469a7d4eaf9396bd989b6ea7dc315be793c054fc2997",
}


def test_one_tree_gives_these_exact_digests_on_every_system(tmp_path):
    root = tmp_path / "build" / "proj"
    for rel, text in PORTABLE_TREE.items():
        _write(root, rel, text)
    got = {
        "egress": audit(root, label="portable").findings_digest,
        "cbom": cbom.build_cbom(root, label="portable").findings_digest,
        "sbom": sbom.build_sbom(root, label="portable").findings_digest,
    }
    assert got == PORTABLE_DIGESTS, (
        f"python {sys.version.split()[0]} on {sys.platform} produced different digests for the same tree: {got}")


def test_symbolic_links_are_counted_and_not_followed(tmp_path):
    outside = tmp_path / "outside"
    _write(outside, "secret.py", "import requests\n")
    tree = tmp_path / "tree"
    _write(tree, "app.py", "x = 1\n")
    try:
        (tree / "link.py").symlink_to(outside / "secret.py")
        (tree / "linkdir").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")
    rep = audit(tree, label="t")
    assert rep.verdict == "CLEAN"
    assert rep.not_scanned["symbolic_links"] == 2


def test_a_link_is_never_read_on_systems_that_cannot_make_one_here(tmp_path, monkeypatch):
    """The same rule, checked without creating a link: a path the operating system reports
    as a symbolic link is counted and left unread."""
    _write(tmp_path, "app.py", "x = 1\n")
    linked = _write(tmp_path, "link.py", "import requests\n")
    real = manifests.os.path.islink
    monkeypatch.setattr(manifests.os.path, "islink", lambda p: str(p) == str(linked) or real(p))
    rep = audit(tmp_path, label="t")
    assert rep.verdict == "CLEAN"
    assert rep.not_scanned["symbolic_links"] == 1
    assert rep.files_scanned == 1


# ---------------------------------------------------------------------------
# Line endings
# ---------------------------------------------------------------------------
def test_crlf_and_lf_checkouts_of_one_source_give_one_digest(tmp_path):
    files = {"a.py": "import requests\nx = 1\n", "requirements.txt": "stripe\n", "s.sh": "curl x\n",
             "page.html": '<img src="http://h.example/p.gif">\n'}
    for rel, text in files.items():
        _write(tmp_path / "lf", rel, text)
        _write(tmp_path / "crlf", rel, text.replace("\n", "\r\n"))
    a, b = audit(tmp_path / "lf", label="t"), audit(tmp_path / "crlf", label="t")
    assert a.subject_digest == b.subject_digest
    assert a.findings_digest == b.findings_digest
    assert cbom.build_cbom(tmp_path / "lf", label="t").findings_digest == \
        cbom.build_cbom(tmp_path / "crlf", label="t").findings_digest
    assert sbom.build_sbom(tmp_path / "lf", label="t").findings_digest == \
        sbom.build_sbom(tmp_path / "crlf", label="t").findings_digest


def test_a_changed_character_still_changes_the_digest(tmp_path):
    _write(tmp_path / "a", "a.py", "x = 1\n")
    _write(tmp_path / "b", "a.py", "x = 2\n")
    assert audit(tmp_path / "a", label="t").subject_digest != audit(tmp_path / "b", label="t").subject_digest


def test_artifacts_are_hashed_byte_for_byte(tmp_path):
    _write(tmp_path / "a", "m.pkl", b"\x80\x04a\r\nb")
    _write(tmp_path / "b", "m.pkl", b"\x80\x04a\nb")
    assert audit(tmp_path / "a", label="t").subject_digest != audit(tmp_path / "b", label="t").subject_digest


# ---------------------------------------------------------------------------
# The supported Python versions can read every file in this repository
# ---------------------------------------------------------------------------
def test_no_tracked_python_file_uses_fstring_syntax_newer_than_3_11():
    """Python 3.12 allowed the enclosing quote and backslashes inside an f-string expression.
    3.11 is supported, so neither may appear. Checked from the token stream, which only
    marks f-string parts on 3.12 and later."""
    if sys.version_info < (3, 12):
        pytest.skip("f-string parts are separate tokens from 3.12")
    offenders = []
    files = [p for d in ("entrovouch", "tests", "examples") for p in sorted((REPO / d).rglob("*.py"))]
    for f in files:
        stack = []
        for tok in tokenize.generate_tokens(io.StringIO(f.read_text(encoding="utf-8")).readline):
            kind = tokenize.tok_name[tok.type]
            if kind == "FSTRING_START":
                quote = tok.string.lstrip("rRbBfFuU")
                if stack and len(stack[-1]) == 1 and quote[0] == stack[-1]:
                    offenders.append((f.name, tok.start[0]))
                stack.append(quote)
            elif kind == "FSTRING_END":
                stack.pop()
            elif stack and kind == "STRING":
                inner = tok.string.lstrip("rRbBuU")
                if (len(stack[-1]) == 1 and inner[0] == stack[-1]) or "\\" in tok.string:
                    offenders.append((f.name, tok.start[0]))
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# Plain spawn and import forms
# ---------------------------------------------------------------------------
SPAWN_FORMS = {
    "module alias": ('import subprocess as sp\nsp.run(["curl", "-O", t])\n', "subprocess-net-binary"),
    "from-import alias": ('from subprocess import run as r\nr(["wget", t])\n', "subprocess-net-binary"),
    "args keyword": ('import subprocess\nsubprocess.run(args=["curl", t])\n', "subprocess-net-binary"),
    "shell=1": ('import subprocess\nsubprocess.run("curl " + t, shell=1)\n', "subprocess-shell"),
    "os alias": ('import os as o\no.system("curl -s " + t)\n', "subprocess-shell"),
    "from os import system": ('from os import system\nsystem("curl -s " + t)\n', "subprocess-shell"),
    "from os import popen": ('from os import popen\npopen("wget " + t)\n', "subprocess-shell"),
    "env wrapper": ('import subprocess\nsubprocess.run(["env", "A=1", "curl", t])\n', "subprocess-net-binary"),
    "sudo wrapper": ('import subprocess\nsubprocess.run(["sudo", "wget", t])\n', "subprocess-net-binary"),
    "timeout wrapper": ('import subprocess\nsubprocess.run(["timeout", "5", "curl", t])\n', "subprocess-net-binary"),
    "literal split": ('import subprocess\nsubprocess.run("curl -s -O f".split())\n', "subprocess-net-binary"),
    "shlex.split literal": ('import subprocess, shlex\nsubprocess.run(shlex.split("curl -s x"))\n',
                            "subprocess-net-binary"),
    "argv bound once": ('import subprocess\ncmd = ["curl", t]\nsubprocess.run(cmd)\n', "subprocess-net-binary"),
    "ipython shell": ('get_ipython().system("curl " + t)\n', "subprocess-shell"),
    "importlib.__import__": ('import importlib\nimportlib.__import__("socket")\n', "dynamic-exec"),
    "bare asyncio call": ('from asyncio import open_connection\nasync def f():\n'
                          '    await open_connection("h.example", 80)\n', "network-call"),
    "datagram endpoint": ('import asyncio\nasync def f(loop):\n'
                          '    await loop.create_datagram_endpoint(P, remote_addr=("h", 53))\n', "network-call"),
    "ssl certificate fetch": ('import ssl\nssl.get_server_certificate(("h.example", 443))\n', "network-call"),
    "logging.config.listen": ('import logging.config\nlogging.config.listen(9999).start()\n', "inbound-listener"),
    "multiprocessing.managers": ('from multiprocessing.managers import BaseManager\n', "network-import"),
    "nntplib": ("import nntplib\n", "network-import"),
    "smtpd": ("import smtpd\n", "inbound-listener"),
}


@pytest.mark.parametrize("name", sorted(SPAWN_FORMS))
def test_plain_spawn_and_import_forms_are_read(tmp_path, name):
    src, kind = SPAWN_FORMS[name]
    _write(tmp_path, "a.py", src)
    assert kind in _kinds(tmp_path), name


@pytest.mark.parametrize("src", [
    'import ssl\nctx = ssl.create_default_context()\n',
    'from mylib import run\nrun(["report", "--fast"])\n',
    'import subprocess as sp\nsp.run(["ls", "-l"])\n',
    'cmd = ["echo", "hi"]\nimport subprocess\nsubprocess.run(cmd)\n',
    'import subprocess\nsubprocess.run(["env", "python3", "-V"])\n',
    'x = a / b  # http://not-a-url-in-python-comment.example\n',
])
def test_ordinary_code_stays_clean(tmp_path, src):
    _write(tmp_path, "a.py", src)
    assert audit(tmp_path, label="t").verdict == "CLEAN"


# ---------------------------------------------------------------------------
# What the list does not know is named, not passed over
# ---------------------------------------------------------------------------
def test_third_party_imports_on_no_list_are_named_in_the_report(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/util.py", "x = 1\n")
    _write(tmp_path, "pkg/core.py", "import os, json\nimport numpy as np\nfrom acmehttp import Client\n"
                                     "from pkg import util\nfrom . import util as u\nimport orbital.sdk\n")
    rep = audit(tmp_path, label="t")
    assert rep.verdict == "CLEAN"                       # nothing on the list: no finding is claimed
    assert rep.unlisted_imports == ["acmehttp", "numpy", "orbital"]
    from entrovouch.no_egress_auditor import render_markdown
    assert "not known to this tool (3)" in render_markdown(rep)


def test_listed_standard_library_and_own_modules_are_not_called_unlisted(tmp_path):
    _write(tmp_path, "src/mypkg/__init__.py", "")
    _write(tmp_path, "src/mypkg/a.py", "import requests\nimport tomllib, asyncio, sqlite3\nimport mypkg.b\nfrom mypkg import b\n")
    _write(tmp_path, "src/mypkg/b.py", "import flask\nfrom requests.adapters import HTTPAdapter\n")
    assert audit(tmp_path, label="t").unlisted_imports == []


def test_the_unlisted_list_is_inside_the_findings_digest(tmp_path):
    _write(tmp_path / "a", "m.py", "import acmehttp\n")
    _write(tmp_path / "b", "m.py", "import zetarpc\n")
    a, b = audit(tmp_path / "a", label="t"), audit(tmp_path / "b", label="t")
    assert a.verdict == b.verdict == "CLEAN" and a.findings_digest != b.findings_digest


def test_the_parsing_python_is_recorded_outside_the_findings_digest(tmp_path):
    from entrovouch.no_egress_auditor import reproducible_body
    _write(tmp_path, "m.py", "x = 1\n")
    rep = audit(tmp_path, label="t")
    assert rep.parser_python == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert b"parser_python" not in reproducible_body(asdict(rep))
    assert cbom.build_cbom(tmp_path, label="t").parser_python == rep.parser_python


def test_the_standard_library_names_are_data_not_the_running_python():
    from entrovouch._stdlib_names import STDLIB_MODULE_NAMES
    public = {n for n in sys.stdlib_module_names if not n.startswith("_") or n in ("__future__", "_thread")}
    assert public <= STDLIB_MODULE_NAMES
    assert {"asyncore", "telnetlib", "tomllib"} <= STDLIB_MODULE_NAMES     # removed in some versions, added in others


def test_a_project_is_not_a_dependency_on_itself(tmp_path):
    """A repository whose own package shares a name with a listed module imports ITSELF, in the
    `src/` layout, directly under the root, or when the package directory is the audited target."""
    body = "from celery import app\nimport celery.utils\n"
    for layout in ("src/celery", "celery"):
        root = tmp_path / layout.replace("/", "_")
        _write(root, f"{layout}/__init__.py", "")
        _write(root, f"{layout}/utils.py", "x = 1\n")
        _write(root, f"{layout}/worker.py", body)
        rep = audit(root, label="t")
        assert rep.verdict == "CLEAN" and rep.shadowed_imports == ["celery"], layout
    pkg = tmp_path / "direct" / "celery"
    _write(pkg, "__init__.py", "")
    _write(pkg, "worker.py", body)
    assert audit(pkg, label="t").shadowed_imports == ["celery"]


def test_a_package_vendored_inside_another_package_does_not_hide_a_top_level_import(tmp_path):
    _write(tmp_path, "app/__init__.py", "")
    _write(tmp_path, "app/_vendor/__init__.py", "")
    _write(tmp_path, "app/_vendor/requests/__init__.py", "")
    _write(tmp_path, "app/main.py", "import requests\n")
    assert "network-import" in _kinds(tmp_path)


def test_a_builtin_name_the_file_binds_itself_is_not_called_the_builtin(tmp_path):
    _write(tmp_path, "a.py", "from py_compile import compile\ncompile('m.py', 'm.pyc')\n")
    _write(tmp_path, "b.py", "def eval(req, **env):\n    return req\nv = eval(1, extra=2)\n")
    _write(tmp_path, "c.py", "code = compile(src, 'f', 'exec')\nexec(code)\n")
    by_file = {}
    for f in audit(tmp_path, label="t").findings:
        by_file.setdefault(f["file"], set()).add(f["kind"])
    assert by_file == {"a.py": {"method-named-exec"}, "b.py": {"method-named-exec"}, "c.py": {"dynamic-exec"}}


@pytest.mark.parametrize("argv,reported", [
    ('["brew", "--prefix"]', False), ('["pip", "--version"]', False), ('["npm", "config", "get", "prefix"]', False),
    ('["brew", "install", "jq"]', True), ('["pip", "install", name]', True), ('["brew", flag]', True), ('["curl", "--version"]', False), ('["curl", target]', True),
])
def test_a_package_manager_asked_about_itself_is_not_a_network_command(tmp_path, argv, reported):
    _write(tmp_path, "a.py", f"import subprocess\nsubprocess.check_output({argv})\n")
    assert (audit(tmp_path, label="t").verdict == "FINDINGS") is reported


def test_python_2_names_are_standard_library_and_its_network_modules_are_listed(tmp_path):
    _write(tmp_path, "compat.py", "import ConfigParser, Queue, StringIO\nimport urllib2\nimport xmlrpclib\nimport SocketServer\n")
    rep = audit(tmp_path, label="t")
    assert rep.unlisted_imports == []
    assert sorted(f["kind"] for f in rep.findings) == ["inbound-listener", "network-import", "network-import"]


# ---------------------------------------------------------------------------
# Scripts, build recipes and pipeline files
# ---------------------------------------------------------------------------
SCRIPTS = {
    "install.sh": "#!/bin/sh\ncurl -fsSL https://h.example/i.sh | sh\n",
    "deploy.ps1": "Invoke-WebRequest https://h.example/x -OutFile x\n",
    "go.bat": "curl https://h.example/x\n",
    "Dockerfile": "FROM scratch\nRUN pip install requests\n",          # `scratch` is no image: nothing is pulled
    "Makefile": "all:\n\tgit clone https://h.example/x.git\n",
    ".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - run: curl https://h.example/x | bash\n",
    "tox.ini": "[testenv]\ncommands = wget https://h.example/x\n",
    "bootstrap": "#!/bin/bash\napt-get install -y curl\n",
}


@pytest.mark.parametrize("name", sorted(SCRIPTS))
def test_network_commands_in_scripts_are_reported(tmp_path, name):
    _write(tmp_path, name, SCRIPTS[name])
    rep = audit(tmp_path, label="t")
    assert {f["kind"] for f in rep.findings} == {"script-network-command"}, name
    assert rep.files_scanned == 1


def test_script_comments_and_quiet_scripts_are_clean(tmp_path):
    _write(tmp_path, "run.sh", "#!/bin/sh\n# curl https://h.example would fetch\necho done\n")
    assert audit(tmp_path, label="t").verdict == "CLEAN"


@pytest.mark.parametrize("name", ["sdist.tar.gz", "bundle.tgz", "tool.exe", "Foo.class", "model.pkl", "model.pt"])
def test_archives_executables_and_pickles_are_reported_unread(tmp_path, name):
    _write(tmp_path, "a.py", "x = 1\n")
    _write(tmp_path, name, b"\x00\x01binary")
    assert _kinds(tmp_path) == {"unanalysed-artifact"}


def test_the_report_says_how_much_of_the_tree_it_read(tmp_path):
    _write(tmp_path, "setup.cfg", "[metadata]\nname = x\n")
    for i in range(5):
        _write(tmp_path, f"src/m{i}.rs", "fn main() {}\n")
    for i in range(3):
        _write(tmp_path, f"node_modules/p/m{i}.js", "x = 1\n")
    rep = audit(tmp_path, label="t")
    # five of a type with no reader, three under a skipped directory: eight not read beside one read
    assert (rep.verdict, rep.files_scanned, rep.files_not_read) == ("CLEAN", 1, 8)
    from entrovouch.no_egress_auditor import render_markdown
    assert "8 more were not read" in render_markdown(rep)


# ---------------------------------------------------------------------------
# Web: minified output and schemes other than http
# ---------------------------------------------------------------------------
def test_a_regex_literal_does_not_end_the_line_for_the_checker(tmp_path):
    line = 'var r=/^https?:\\/\\//;function s(d){fetch("https://c.example/v1",{body:d})}\n'
    assert "fetch(" in _strip_js_comments(line)
    _write(tmp_path, "app.min.js", line)
    assert {"network-call", "external-url"} <= _kinds(tmp_path)


def test_division_and_real_comments_are_still_told_apart():
    assert _strip_js_comments("a = b / c; // https://x.example").rstrip() == "a = b / c;"
    assert "https" not in _strip_js_comments("x = 1 /* https://x.example */")


WEB = {
    "a.js": ["var x=new XMLHttpRequest;x.open('GET',u);x.send();\n",
             "const b = navigator.sendBeacon.bind(navigator); b(u, d);\n",
             "globalThis['fetch'](u);\n",
             'const endpoint = "wss://collector.h.example/v1";\n',
             'const u = "ftp://h.example/f";\n',
             "const m = await import(u);\n"],
    "a.html": ["<script src=//cdn.h.example/a.js></script>\n",
               "<form action=//h.example/collect method=post></form>\n",
               "<link rel=dns-prefetch href=//h.example>\n",
               '<meta http-equiv="refresh" content="0;url=//h.example/">\n',
               '<div data-endpoint="ws://h.example/s"></div>\n',
               '<script>var a="<!--"; new Image().src="http://h.example/p"; var b="-->";</script>\n',
               '<a href="docs/*">d</a>\n<img src="http://h.example/t.gif">\n<p>*/</p>\n'],
}


@pytest.mark.parametrize("name,line", [(n, l) for n, lines in WEB.items() for l in lines])
def test_web_forms_minifiers_and_other_schemes(tmp_path, name, line):
    _write(tmp_path, name, line)
    assert audit(tmp_path, label="t").verdict == "FINDINGS", line


def test_comments_in_markup_are_still_not_findings(tmp_path):
    _write(tmp_path, "a.html", '<!-- <img src="http://h.example/x"> -->\n<p>hi</p>\n'
                               '<style>/* url(http://h.example/f.woff) */ p{color:red}</style>\n'
                               '<script>// see http://h.example/docs\nvar a = 1;</script>\n')
    assert audit(tmp_path, label="t").verdict == "CLEAN"


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------
REMOTE_MANIFESTS = {
    "editable vcs": {"requirements.txt": "-e git+https://github.com/x/y.git#egg=y\n"},
    "editable ssh": {"requirements.txt": "--editable git+ssh://git@h.example/x/y.git\n"},
    "poetry git": {"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\n'
                                     'mylib = { git = "https://github.com/x/mylib.git" }\n'},
    "poetry source": {"pyproject.toml": '[[tool.poetry.source]]\nname = "p"\nurl = "https://pypi.h.example/simple"\n'},
    "uv index": {"pyproject.toml": '[[tool.uv.index]]\nurl = "https://pypi.h.example/simple"\n'},
    "uv sources": {"pyproject.toml": '[tool.uv.sources]\nmylib = { git = "https://github.com/x/mylib" }\n'},
    "optional url": {"pyproject.toml": '[project]\nname="x"\nversion="1"\n[project.optional-dependencies]\n'
                                       'z = ["mylib @ https://h.example/mylib.whl"]\n'},
    "dependency_links": {"setup.cfg": "[options]\ndependency_links = https://h.example/pkgs\n"},
    "npm script": {"package.json": '{"scripts": {"start": "curl https://h.example | sh"}}\n'},
    "conda channel": {"environment.yml": "channels:\n  - https://conda.h.example/priv\ndependencies:\n  - numpy\n"},
    "conda pip index": {"environment.yml": "dependencies:\n  - pip:\n    - --extra-index-url https://p.h.example/s\n"},
    "pipfile git": {"Pipfile": '[packages]\nmylib = {git = "https://github.com/x/mylib.git"}\n'},
}


@pytest.mark.parametrize("name", sorted(REMOTE_MANIFESTS))
def test_remote_sources_in_manifests(tmp_path, name):
    for rel, text in REMOTE_MANIFESTS[name].items():
        _write(tmp_path, rel, text)
    assert "declared-remote-source" in _kinds(tmp_path), name


DECLARED = {
    "requirements directory": {"requirements/base.txt": "requests==2.31\n"},
    "dev-requirements.txt": {"dev-requirements.txt": "requests\n"},
    "requirements.in": {"requirements.in": "requests\n"},
    "constraints.txt": {"constraints.txt": "requests==2.31\n"},
    "setup.py extras bracket": {"setup.py": 'from setuptools import setup\n'
                                            'setup(install_requires=["requests[socks]>=2", "stripe"])\n'},
    "setup.py setup_requires": {"setup.py": 'from setuptools import setup\nsetup(setup_requires=["requests"])\n'},
    "setup.py extras_require": {"setup.py": 'from setuptools import setup\n'
                                            'setup(extras_require={"net": ["requests"]})\n'},
    "build-system requires": {"pyproject.toml": '[build-system]\nrequires = ["setuptools", "requests"]\n'},
    "dependency-groups": {"pyproject.toml": '[project]\nname="x"\nversion="1"\n[dependency-groups]\ndev = ["requests"]\n'},
    "poetry group": {"pyproject.toml": '[tool.poetry.group.dev.dependencies]\nrequests = "^2"\n'},
    "setup.cfg extras": {"setup.cfg": "[options.extras_require]\nnet = requests\n"},
    "npm devDependencies": {"package.json": '{"devDependencies": {"axios": "^1"}}\n'},
}


@pytest.mark.parametrize("name", sorted(DECLARED))
def test_declared_network_dependencies_in_every_layout(tmp_path, name):
    for rel, text in DECLARED[name].items():
        _write(tmp_path, rel, text)
    assert "declared-network-dependency" in _kinds(tmp_path), name


def test_setup_py_with_an_extras_bracket_keeps_every_dependency(tmp_path):
    _write(tmp_path, "setup.py", 'from setuptools import setup\n'
                                 'setup(install_requires=["requests[socks]>=2", "stripe"])\n')
    assert [d.name for d in collect_manifests(tmp_path).deps] == ["requests", "stripe"]
    assert [c["name"] for c in sbom.build_sbom(tmp_path).components] == ["requests", "stripe"]


def test_the_sbom_reads_requirement_directories_and_leaves_out_dev_and_build(tmp_path):
    _write(tmp_path, "requirements/base.txt", "requests==2.31.0\n")
    _write(tmp_path, "pyproject.toml", '[build-system]\nrequires = ["setuptools"]\n'
                                       '[dependency-groups]\ndev = ["pytest"]\n')
    assert [c["name"] for c in sbom.build_sbom(tmp_path).components] == ["requests"]
    scopes = {d.name: d.scope for d in collect_manifests(tmp_path).deps}
    assert scopes == {"requests": "required", "setuptools": "build", "pytest": "dev"}


def test_an_editable_requirement_keeps_its_name(tmp_path):
    assert manifests.requirement_name("-e git+https://github.com/x/y.git#egg=y") == "y"
    assert manifests.requirement_name("--editable git+ssh://git@h.example/x/proj.git") == "proj"
    _write(tmp_path, "requirements.txt", "-e git+https://github.com/x/requests.git#egg=requests\n")
    assert {"declared-remote-source", "declared-network-dependency"} <= _kinds(tmp_path)


def test_a_local_editable_install_is_not_a_dependency_or_a_remote(tmp_path):
    _write(tmp_path, "requirements.txt", "-e .\n-e ./libs/mine\n")
    scan = collect_manifests(tmp_path)
    assert scan.deps == [] and scan.remotes == []


@pytest.mark.parametrize("include", ["oth\x00er.txt", "x" * 5000 + ".txt", "..\\..\\outside.txt", "missing.txt"])
def test_an_include_that_cannot_be_read_is_reported_and_never_raises(tmp_path, include):
    """A requirements file is data from the audited tree. Whatever its include line holds, the
    result is the same finding on every Python version."""
    _write(tmp_path, "requirements.txt", f"requests\n-r {include}\n")
    rep = audit(tmp_path, label="t")
    kinds = [f["kind"] for f in rep.findings]
    assert kinds.count("unparseable-source") == 1 and "declared-network-dependency" in kinds
    # what the include declares is not in the inventory, and the inventory says so
    assert sbom.build_sbom(tmp_path).verdict == "INCOMPLETE"


def test_requirement_file_names():
    yes = ["requirements.txt", "requirements-dev.txt", "dev-requirements.txt", "requirements.in", "constraints.txt"]
    no = ["notes.txt", "README.txt", "requirements.md", "data.in"]
    assert all(manifests.is_requirements_filename(n) for n in yes)
    assert not any(manifests.is_requirements_filename(n) for n in no)
    assert manifests.is_requirements_path("requirements/base.txt")
    assert not manifests.is_requirements_path("docs/base.txt")


# ---------------------------------------------------------------------------
# Key provenance
# ---------------------------------------------------------------------------
def _aws() -> str:
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"      # the documentation example, assembled so this file holds no match


KEY_FORMS = {
    "keyword literal": {"a.py": 'c = Client(api_key="sk-0123456789abcdef01234567")\n'},
    "dictionary value": {"a.py": 'cfg = {"api_key": "0123456789abcdef01234567"}\n'},
    "environ default": {"a.py": 'import os\nSECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-0123456789")\n'},
    "getenv default": {"a.py": 'import os\nsigning_key = os.getenv("K", "0123456789abcdef0123456789abcdef")\n'},
    "json config": {"settings.json": '{"db": {"password": "correct-horse-battery-1"}}\n', "a.py": "x = 1\n"},
    "own key file": {"k.json": '{"seed": "' + "ab" * 32 + '", "height": 10, "next_index": 3}\n', "a.py": "x = 1\n"},
}


@pytest.mark.parametrize("name", sorted(KEY_FORMS))
def test_key_material_in_plain_forms(tmp_path, name):
    for rel, text in KEY_FORMS[name].items():
        _write(tmp_path, rel, text)
    rep = key_provenance.scan_key_provenance(tmp_path)
    assert rep.verdict == "REVIEW" and len(rep.findings) == 1, (name, rep.findings)


def test_provider_credential_shapes(tmp_path):
    _write(tmp_path, "a.py", f'ident = "{_aws()}"\nt = "gh' + 'p_' + "a1B2" * 9 + '"\n'
                             'h = {"Authorization": "Bea' + 'rer ' + "abcdEFGH1234" * 3 + '"}\n')
    rep = key_provenance.scan_key_provenance(tmp_path)
    assert [f["line"] for f in rep.findings] == [1, 2, 3]


@pytest.mark.parametrize("src", [
    'key = "name"\nsort_key = "date"\n',
    'import os\nSECRET_KEY = os.environ["SECRET_KEY"]\n',
    'import os\nSECRET_KEY = os.environ.get("SECRET_KEY", "")\n',
    'c = Client(api_key="<your-key-here>")\n',
    'd = {"password": "changeme"}\n',
    'rows.sort(key="created_at_field")\n',
])
def test_key_shaped_names_that_are_not_secrets_stay_quiet(tmp_path, src):
    _write(tmp_path, "a.py", src)
    assert key_provenance.scan_key_provenance(tmp_path).verdict == "NOTHING-FOUND"


# ---------------------------------------------------------------------------
# Cryptographic inventory
# ---------------------------------------------------------------------------
VULNERABLE = {
    "pyca dh": 'from cryptography.hazmat.primitives.asymmetric import dh\ndh.generate_parameters(2, 2048)\n',
    "paramiko RSAKey": 'import paramiko\nparamiko.RSAKey.generate(2048)\n',
    "pyOpenSSL TYPE_RSA": 'from OpenSSL import crypto\nk = crypto.PKey()\nk.generate_key(crypto.TYPE_RSA, 2048)\n',
}


@pytest.mark.parametrize("name", sorted(VULNERABLE))
def test_quantum_vulnerable_key_generation_is_classified(tmp_path, name):
    _write(tmp_path, "a.py", VULNERABLE[name])
    assert cbom.build_cbom(tmp_path).verdict == "MIGRATION-NEEDED"


@pytest.mark.parametrize("src", [
    'import hashlib\nhashlib.new(name="sha1")\n',
    'import ssl\nctx = ssl.create_default_context()\nctx.minimum_version = ssl.TLSVersion.TLSv1\n',
])
def test_broken_primitives_named_by_keyword_or_enum(tmp_path, src):
    _write(tmp_path, "a.py", src)
    assert cbom.build_cbom(tmp_path).verdict == "BROKEN-CRYPTO"


@pytest.mark.parametrize("src", [
    'from Crypto.Cipher import AES\nc = AES.new(k, AES.MODE_ECB)\n',
    'import requests\nrequests.get(u, verify=False)\n',
    'import tink\n',
])
def test_a_component_that_needs_a_person_is_not_reported_as_nothing_found(tmp_path, src):
    _write(tmp_path, "a.py", src)
    rep = cbom.build_cbom(tmp_path)
    assert rep.verdict == "REVIEW-NEEDED"
    assert cbom.main([str(tmp_path)]) == 1


# ---------------------------------------------------------------------------
# A report changed after issue is not converted; a signature has one encoding
# ---------------------------------------------------------------------------
def test_adapters_refuse_a_report_whose_body_was_edited(tmp_path):
    _write(tmp_path / "p", "a.py", "import requests\n")
    rep = asdict(audit(tmp_path / "p", label="t"))
    assert report_is_intact(rep) is True
    rep["findings"], rep["verdict"] = [], "CLEAN"
    assert report_is_intact(rep) is False
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(rep), encoding="utf-8")
    for module, extra in (("sarif", []), ("attestation", []), ("timestamp", ["request"])):
        out = tmp_path / f"out_{module}"
        r = subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *extra, str(edited),
                            "--out", str(out)], cwd=REPO, capture_output=True, text=True)
        assert r.returncode == 2 and "changed after it was issued" in r.stderr, module
        assert not out.exists()


def test_a_document_with_no_content_hash_has_nothing_to_check():
    assert report_is_intact({"findings": []}) is None


def test_signing_waits_out_another_process_holding_the_key_file(tmp_path):
    """A reader with the state file open (a second signer, a backup tool, a scanner) blocks its
    replacement on Windows for as long as the handle is held. Signing waits and then succeeds;
    the leaf is spent exactly once."""
    import threading
    import time
    path = tmp_path / "k.json"
    signer = MerkleSigner.create(path, height=2)
    holding, release = threading.Event(), threading.Event()

    def hold():
        with open(path, "rb"):
            holding.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    assert holding.wait(5)
    threading.Timer(0.4, release.set).start()
    started = time.monotonic()
    sig = signer.sign(b"m")
    t.join()
    assert sig["leaf_index"] == 0 and MerkleSigner.load(path).next_index == 1
    assert time.monotonic() - started < 9


def test_a_signature_has_exactly_one_accepted_encoding(tmp_path):
    signer = MerkleSigner.create(tmp_path / "k.json", height=2)
    _write(tmp_path / "p", "a.py", "x = 1\n")
    rep = asdict(audit(tmp_path / "p", label="t", signer=signer))
    root = signer.public_root
    assert verify_report(rep, expected_root=root) == (True, "ATTESTED")

    def variant(change):
        r = json.loads(json.dumps(rep))
        change(r["signature"])
        return verify_report(r, expected_root=root)

    e = rep["signature"]["ots"][0]
    assert variant(lambda s: s.update(leaf_index=str(s["leaf_index"]))) == (False, "TAMPERED")
    assert variant(lambda s: s.update(leaf_index=s["leaf_index"] + 0.9)) == (False, "TAMPERED")
    assert variant(lambda s: s.update(leaf_index=float(s["leaf_index"]))) == (False, "TAMPERED")
    assert variant(lambda s: s.update(leaf_index=bool(s["leaf_index"]))) == (False, "TAMPERED")
    assert variant(lambda s: s.update(height=float(s["height"]))) == (False, "TAMPERED")
    assert variant(lambda s: s["ots"].__setitem__(0, e.upper())) == (False, "TAMPERED")
    assert variant(lambda s: s["ots"].__setitem__(0, " ".join(e[i:i + 2] for i in range(0, 64, 2)))) == (False, "TAMPERED")
    assert variant(lambda s: s.update(extra="anything")) == (False, "TAMPERED")
    assert variant(lambda s: s.update(public_root=s["public_root"].upper())) == (False, "TAMPERED")

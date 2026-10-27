"""Child interpreters, wrappers and the container rule, read as the programs and the language read them.

A program named by `executable=` that the line does not spell out is still reported when the argv's own first word
reaches the network; `sys.executable` is Python however it is reached; a child's code is read for the file it is in;
the interpreter's options, the wrappers' options and `env -S` strings are read as CPython and GNU env 8.32 read them
(measured on those programs); and a file that can change a container's methods by reflection gets no container
exemption. Each case asserts what must be reported, and its neighbour that must not be.
"""
import time
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit

URL = "https://e.example/x"
NETC = "import socket; socket.create_connection((chr(104), 80))"


def _audit(tmp_path: Path, src: str, name: str = "a.py"):
    (tmp_path / name).write_text(src, encoding="utf-8")
    return audit(tmp_path, label="t")


def _kinds(tmp_path: Path, src: str, name: str = "a.py") -> list:
    return sorted({f["kind"] for f in _audit(tmp_path, src, name).findings})


def _run(argv: str, pre: str = "") -> str:
    return f'import subprocess, sys, os, shutil\nNETC = "{NETC}"\nx = input()\n{pre}subprocess.run({argv})\n'


# ---------------------------------------------------------------- executable= not spelled out
@pytest.mark.parametrize("argv,kinds", [
    ('["python3", "-c", NETC], executable=os.environ["PY"]', ["unresolved-call"]),
    ('["curl", "https://pypi.org/simple/"], executable=x', ["unresolved-call"]),
    ('["git", "fetch", "origin"], executable=x', ["unresolved-call"]),
    ('["sh", "-c", "curl https://pypi.org/"], executable=x', ["unresolved-call"]),
    ('["tool", "https://e.example/a"], executable=x', ["external-url"]),
    ('["tool", "--local"], executable=x', []),
    ('["python3", "-c", "print(1)"], executable=x', []),
])
def test_an_executable_the_line_does_not_spell_out_is_read_through_the_argv(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


@pytest.mark.parametrize("argv,pre", [
    ('["x", "-c", NETC], executable=shutil.which("python3")', ""),
    ('["x", "-c", NETC], executable=PY', 'PY = shutil.which("python3")\n'),
    ('["x", "-c", NETC], executable=executable', "from sys import executable\n"),
    ('["x", "-c", NETC], executable=s.executable', "import sys as s\n"),
    ('["x", "-c", NETC], executable=PY', "PY = sys.executable\n"),
    ('["x", "-c", NETC], executable=os.sys.executable', ""),
    ('["x", "-c", NETC], executable=sys._base_executable', ""),
    ('["x", "-c", NETC], executable=str(sys.executable)', ""),
    ('["x", "-c", NETC], executable=b"/usr/bin/python3"', ""),
    ('[PY, "-c", NETC]', "PY = sys.executable\n"),
    ('[executable, "-c", NETC]', "from sys import executable\n"),
    ('[sys.executable, b"-c", b"import socket"]', ""),
])
def test_sys_executable_however_it_is_reached_runs_python(tmp_path, argv, pre):
    assert "network-import" in _kinds(tmp_path, _run(argv, pre)), argv


def test_a_name_that_only_looks_like_sys_executable_is_not_python(tmp_path):
    src = _run('[self_python, "-c", NETC]', "self_python = os.environ['P']\n")
    assert "network-import" not in _kinds(tmp_path, src)


# ---------------------------------------------------------------- a child's code is read for the file it is in
def _files(tmp_path, files):
    for name, src in files.items():
        (tmp_path / name).write_text(src, encoding="utf-8")
    rep = audit(tmp_path, label="t")
    return {name: sorted(f["kind"] for f in rep.findings if f["file"] == name) for name in files}


PSQL = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', \"import subprocess; subprocess.run(['psql', '-c', 'select 1'])\"])\n"
PGHOST = "import os\nos.environ['PGHOST'] = 'db.corp.example.org'\n" + PSQL.split("\n", 1)[1]


@pytest.mark.parametrize("files,target", [
    ({"a.py": PSQL, "b.py": "import subprocess, sys\n" + PGHOST}, "b.py"),
    ({"a.py": PSQL, "b.py": "import subprocess, sys\n" + PGHOST}, "a.py"),
    ({"a.py": "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'import requests'])\n",
      "requests.py": "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'import requests'])\n"},
     "requests.py"),
])
def test_what_a_childs_code_yields_does_not_depend_on_another_file(tmp_path, files, target):
    together = _files(tmp_path / "both", files) if (tmp_path / "both").mkdir() is None else None
    (tmp_path / "alone").mkdir()
    alone = _files(tmp_path / "alone", {target: files[target]})
    assert together[target] == alone[target]


# ---------------------------------------------------------------- the interpreter's own options, as CPython reads them
@pytest.mark.parametrize("argv,network", [
    ('["python3", "-W", "-c", NETC]', False),             # `-c` is -W's value; NETC is then a script name
    ('["python3", "-X", "-c", NETC]', False),
    ('["python3", "--check-hash-based-pycs", "-c", NETC]', False),
    ('["python3", "-W", "ignore", "-c", NETC]', True),
    ('["python3", "-W", x, "-c", NETC]', True),
    ('["python3", "-tc", NETC]', True),                   # -t is accepted (and ignored) by CPython 3.14
    ('["python3", "-Btc", NETC]', True),
    ('["python3", "--", "-c", NETC]', False),             # after `--` the next word is a script
    ('["python3", "-V", "-c", NETC]', False),             # prints its version and exits
    ('["python3", "-hc", NETC]', False),                  # prints help and exits
    ('["python3", "--help-env", "-c", NETC]', False),
    ('["python3", "--check-hash-based-pycs=always", "-c", NETC]', False),   # refused
    ('["python3", "-Xdev", "-c", NETC]', True),
    ('["python3", "-Xshowrefcount", "-c", NETC]', True),  # an attached -X value holding an h is still -X's value
])
def test_the_interpreter_reads_its_options_as_cpython_does(tmp_path, argv, network):
    assert ("network-import" in _kinds(tmp_path, _run(argv))) is network, argv


@pytest.mark.parametrize("exe", ["python3.14t", "pypy3.10", "python3-dbg", "graalpy", "pythonw3.14",
                                 "C:\\\\Python314\\\\python3.14t.exe", "python3.12d"])
def test_interpreter_names_real_installs_use(tmp_path, exe):
    assert "network-import" in _kinds(tmp_path, _run(f'["{exe}", "-c", NETC]')), exe


def test_a_program_that_only_starts_with_python_is_not_one(tmp_path):
    assert "network-import" not in _kinds(tmp_path, _run('["pythonista", "-c", NETC]'))


def test_code_written_with_an_fstring_is_read_by_its_written_parts(tmp_path):
    src = _run('[sys.executable, "-c", f"import socket; socket.create_connection(({x}, 80))"]')
    assert "network-import" in _kinds(tmp_path, src)
    assert _kinds(tmp_path, _run('[sys.executable, "-c", f"print({x})"]')) == []


@pytest.mark.parametrize("argv,kinds", [
    ('["python", x, "-m", "pip", "install", "list"]', ["subprocess-net-binary"]),
    ('[sys.executable, x, "-m", "pip", "install", "-v"]', ["subprocess-net-binary"]),
    ('["sudo", "python3", x, "-m", "pip", "install", "list"]', ["subprocess-net-binary"]),
    ('[sys.executable, x, "-m", "pip", "freeze"]', []),
    ('[sys.executable, x, "-m", "pip", "show", "requests"]', []),
    ('["python", x, "-m", "pip", "--version"]', []),
])
def test_m_after_a_word_the_line_does_not_spell_out(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


def test_placing_a_reading_in_a_long_argv_takes_linear_time(tmp_path):
    words = ", ".join(['x', '"python3"'] * 2000)
    start = time.perf_counter()
    _audit(tmp_path, _run(f'["sudo", {words}]'))
    assert time.perf_counter() - start < 10


# ---------------------------------------------------------------- wrappers' options, as their manuals and getopt read them
@pytest.mark.parametrize("argv,kinds", [
    ('["sudo", "-lu", "root", "git", "fetch"]', []),       # -l: lists whether it is allowed; nothing runs
    ('["sudo", "-nl", "git", "fetch"]', []),
    ('["sudo", "--li", "git", "fetch"]', []),              # an abbreviation of --list
    ('["doas", "-nC", "conf", "git", "fetch"]', []),
    ('["command", "-pv", "git", "fetch"]', []),
    ('["time", "--vers", "git", "fetch"]', []),
    ('["env", "--help", "git", "fetch"]', []),
    ('["env", "-0", "git", "fetch"]', []),                 # env refuses a command after -0
    ('["sudo", "-u", "root", "git", "fetch"]', ["git-remote"]),
    ('["sudo", "-n", "git", "fetch"]', ["git-remote"]),
    ('["env", "-i", "git", "fetch"]', ["git-remote"]),
])
def test_an_option_after_which_nothing_runs_is_seen_in_clusters_and_abbreviations(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


@pytest.mark.parametrize("argv,kinds", [
    ('["sudo", "--", "-u", "root", "git", "fetch"]', []),   # after `--`, `-u` is the command
    ('["env", "--", "-u", "X", "git", "fetch"]', []),
    ('["env", "-u", "X", "--", "-u", "Y", "git", "fetch"]', []),
    ('["chroot", "/", "--", "git", "fetch"]', []),          # after NEWROOT, `--` is the command
    ('["timeout", "5", "--", "git", "fetch"]', []),         # after DURATION too: "failed to run command '--'"
    ('["ionice", "-n", "nice", "--", "8", x, "curl"]', []),   # options are not read again after `--`
    ('["sudo", "--", "git", "fetch"]', ["git-remote"]),
    ('["timeout", "--", "5", "git", "fetch"]', ["git-remote"]),
    ('["timeout", "--", "-s", "bash", "-c", "ls"]', []),      # `-s` is the duration after `--`: refused
])
def test_double_dash_is_read_as_getopt_reads_it(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


@pytest.mark.parametrize("argv,kinds", [
    ('["timeout", "--kill", "1", "5", "git", "fetch"]', ["git-remote"]),   # --kill-after, abbreviated
    ('["sudo", "--us", "root", "git", "fetch"]', ["git-remote"]),          # --user
    ('["env", "--uns", "X", "git", "fetch"]', ["git-remote"]),             # --unset
    ('["timeout", "1.5m", "git", "fetch"]', ["git-remote"]),
    ('["timeout", "git", "fetch"]', []),                    # not a duration: refused, nothing runs
])
def test_long_options_are_read_by_their_unambiguous_abbreviations(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


def test_a_duration_that_is_not_one_names_no_program(tmp_path):
    rep = _audit(tmp_path, _run('["timeout", "git", "pandoc"]'))
    assert rep.unlisted_programs == []


# ---------------------------------------------------------------- env -S as GNU env 8.32 splits it (measured)
@pytest.mark.parametrize("argv,kinds", [
    ('["env", "-S", "A=1\\n#x curl https://e.example/a"]', ["subprocess-net-binary"]),   # a newline is not a space
    ('["env", "-S", "git\\nfetch"]', []),                   # one word, `git<newline>fetch`: no such program
    ('["env", "-S", "git\\vfetch origin"]', []),
    ('["env", "-S", "git\\tfetch"]', ["git-remote"]),       # a tab is
    ('["env", "-S", "curl \'a\\\\qb\' https://e.example/a"]', []),             # refused: invalid sequence
    ('["env", "-S", "curl \'a\\\\nb\' https://e.example/a"]', ["subprocess-net-binary"]),   # kept as written
])
def test_env_split_strings_split_on_spaces_and_tabs_only(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


def test_a_split_string_the_line_does_not_spell_out_leaves_the_program_unknown(tmp_path):
    rep = _audit(tmp_path, _run('["env", "-S", x, "pandoc"]'))
    assert rep.unlisted_programs == []
    assert "git-remote" not in _kinds(tmp_path, _run('["env", "-S", x, "git", "fetch"]'))


# ---------------------------------------------------------------- the container rule and reflection
CONTAINER_CALL = 'q.get("' + URL + '")\n'


@pytest.mark.parametrize("patch", [
    "q.get = urllib.request.urlopen\n",
    "setattr(q, 'get', print)\n",
    "vars(q)['get'] = print\n",
    "type(q).get = print\n",
    "T = type(q)\nT.get = print\n",
    "queue.LifoQueue.__mro__[1].get = print\n",
    "Q = vars(queue)['Queue']\nQ.get = print\n",
    "Q = queue.Queue\nQ1 = Q\nQ2 = Q1\nQ3 = Q2\nQ4 = Q3\nQ4.get = print\n",
    "def patch_class(cls):\n    cls.get = print\npatch_class(queue.Queue)\n",
    "import functools\nfunctools.partial(setattr, queue.Queue)('get', print)\n",
    "from unittest import mock\nmock.patch(target='queue.Queue.get', new=print).start()\n",
    "import sys\nfrom unittest import mock\nmock.patch.dict(sys.modules, {'queue': urllib}).start()\n",
    "import builtins\nbuiltins.__dict__.update(__import__=print)\n",
    "import sys\ngetattr(sys, 'mod' + 'ules')['queue'] = urllib\n",
    "exec('queue.Queue.get = print', {'queue': queue})\n",
    "import inspect\ninspect.currentframe().f_globals['queue'] = urllib\n",
    "q.get.__func__.__code__ = print.__code__\n",
    "import importlib\nimportlib.__import__('queue').Queue = list\n",
])
def test_a_file_that_can_change_a_containers_methods_gets_no_exemption(tmp_path, patch):
    src = "import queue, urllib.request\nq = queue.Queue()\n" + patch + CONTAINER_CALL
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), patch


def test_a_container_the_file_builds_and_leaves_alone_keeps_its_exemption(tmp_path):
    src = "import queue\nq = queue.Queue()\nq.put(1)\n" + CONTAINER_CALL
    last = src.count("\n")
    assert not any(f["line"] == last for f in _audit(tmp_path, src).findings)


@pytest.mark.parametrize("deep", [
    "x" + ".a" * 600 + ".b = 1\n",
    "setattr(x" + ".a" * 600 + ", 'k', 1)\n",
    "y = x" + ".a" * 600 + ".sys\n",
    "L = [L[0]]\nM = L[0]\n",
    "A = [B[0]]\nB = [A[0]]\nM = A[0]\n",
    "import sys\nL0 = [sys]\n" + "".join(f"L{i} = [L{i - 1}[0]]\n" for i in range(1, 1200)) + "M = L1199[0]\n",
])
def test_a_deeply_nested_file_never_stops_the_audit(tmp_path, deep):
    (tmp_path / "deep.py").write_text("x = object()\n" + deep, encoding="utf-8")
    (tmp_path / "net.py").write_text("import socket\nsocket.create_connection(('e.example', 80))\n",
                                     encoding="utf-8")
    rep = audit(tmp_path, label="t")
    assert any(f["file"] == "net.py" and f["kind"] == "network-call" for f in rep.findings)


@pytest.mark.parametrize("head,link", [
    ("import builtins\nb0 = builtins\n", "b"),
    ("import sys\nb0 = sys.meta_path\n", "b"),
    ("import sys\nb0 = sys\n", "b"),
    ("import sys\nb0 = sys.modules\n", "b"),
])
def test_alias_chains_take_linear_time(tmp_path, head, link):
    src = head + "".join(f"{link}{i} = {link}{i - 1}\n" for i in range(1, 6000)) + "import queue\nq = queue.Queue()\n"
    start = time.perf_counter()
    _audit(tmp_path, src + CONTAINER_CALL)
    assert time.perf_counter() - start < 15


def test_a_python_file_is_walked_a_few_times_not_once_per_rule(tmp_path, monkeypatch):
    """The rules read every node of a file many times; the tree is walked once and the list reused. Before, a
    200,000-element literal was walked 57 times (49 of 50 seconds); this counts walks of a whole module."""
    import ast
    import entrovouch.no_egress_auditor as A
    real, walks = A.ast.walk, []

    def counting(node):
        if isinstance(node, ast.Module):
            walks.append(node)
        return real(node)
    monkeypatch.setattr(A.ast, "walk", counting)
    _audit(tmp_path, "import queue, subprocess\nq = queue.Queue()\nq.put(1)\nsubprocess.run(['ls'])\n")
    assert len(walks) <= 5, len(walks)

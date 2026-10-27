"""Durations as GNU timeout reads them, the Windows launcher's version selector, `--` as an option's value, names that
reach sys through a list, a tree's own `queue` module, and `executable=` in its other forms.

Each case was settled on the real program (GNU coreutils 8.32, CPython 3.14, the Windows `py` launcher) or by running
the code; each asserts what must be reported and its neighbour that must not be.
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
    return (f'import subprocess, sys, os, shutil, pathlib\nNETC = "{NETC}"\nURL = "{URL}"\nx = sys.argv[1]\n{pre}'
            f"subprocess.run({argv})\n")


# ---------------------------------------------------------------- DURATION as cl_strtod reads it (measured)
@pytest.mark.parametrize("duration", ["5", "+5", "0x5", " 5", "\\t1", "0x1p3", "+inf", "0X1", "1.5m", ".5s", "-0"])
def test_a_duration_timeout_accepts_runs_the_program(tmp_path, duration):
    assert _kinds(tmp_path, _run(f'["timeout", "--", "{duration}", "git", "fetch"]')) == ["git-remote"], duration


@pytest.mark.parametrize("duration", ["5 ", "git", "-1", "nan", "5x"])
def test_a_duration_timeout_refuses_runs_nothing(tmp_path, duration):
    assert _kinds(tmp_path, _run(f'["timeout", "--", "{duration}", "git", "fetch"]')) == [], duration


def test_a_negative_zero_after_dashes_is_a_duration(tmp_path):
    assert _kinds(tmp_path, _run('["timeout", "--", "-0", "curl", URL]')) == ["subprocess-net-binary"]


# ---------------------------------------------------------------- the `py` launcher's version selector
@pytest.mark.parametrize("argv,network", [
    ('["py", "-V:3.14", "-c", NETC]', True),
    ('["py", "-V:PythonCore/3.14", "-c", NETC]', True),
    ('["py", "-3.14", "-c", NETC]', True),
    ('["py", "-V", "-c", NETC]', False),               # plain -V prints the version and exits
])
def test_the_launchers_version_selector_is_not_the_version_flag(tmp_path, argv, network):
    assert ("network-import" in _kinds(tmp_path, _run(argv))) is network, argv


def test_py_launcher_selector_before_m_pip(tmp_path):
    assert _kinds(tmp_path, _run('["py", "-V:3.14", "-m", "pip", "download", "requests"]')) == \
        ["subprocess-net-binary"]


# ---------------------------------------------------------------- `--` as the value of an option of unknown arity
@pytest.mark.parametrize("argv,kinds", [
    ('["env", x, "--", "-v", "git", "push"]', ["unresolved-call"]),    # x may be -u, which takes `--`
    ('["xargs", x, "--", "-0", "scp", "a", "h:/b"]', ["unresolved-call"]),
    ('["env", "--", "-v", "git", "push"]', []),                         # no word before it to take it
])
def test_dashes_may_be_the_value_of_an_option_before_them(tmp_path, argv, kinds):
    assert _kinds(tmp_path, _run(argv)) == kinds, argv


def test_dashes_as_a_value_then_a_child_interpreter(tmp_path):
    assert "network-import" in str(_audit(tmp_path, _run('["env", x, "--", "-v", "python3", "-c", NETC]')).findings)


# ---------------------------------------------------------------- env -S with ${NAME} before -c
def test_a_value_env_may_drop_does_not_hide_the_code(tmp_path):
    # unset W drops the word, so -W takes -c; a set W keeps it, so the code runs (measured on env 8.32)
    src = _run('["env", "-S", "python3 -W ${W} -c \'import socket\'"]')
    assert "network-import" in _kinds(tmp_path, src)
    # spelled out, -W takes -c and the code is a script's name
    assert _kinds(tmp_path, _run('["env", "-S", "python3 -W -c \'import socket\'"]')) == []


# ---------------------------------------------------------------- sys through a list element
@pytest.mark.parametrize("chain", ["S = sys\nL = [S]\nT = L[0]\n", "S = sys\nL = [S]\nT = L[0] if c else None\n"])
def test_sys_reached_through_a_list_element_swaps_the_module(tmp_path, chain):
    src = ("import sys, queue\nc = True\n" + chain + "T.modules['queue'] = object\nq = queue.Queue()\n"
           f'q.get("{URL}")\n')
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings)


@pytest.mark.parametrize("chain", [
    "import builtins\nB = builtins\nL = [B]\nT = L[0]\nT.__import__ = print\n",
    "import builtins\nL = [builtins]\nT = L[0] if c else None\nT.__import__ = print\n",
    "import sys\nL = [sys.meta_path]\nT = L[0]\nT.insert(0, object())\n",
])
def test_builtins_or_a_hook_list_reached_through_a_list_element(tmp_path, chain):
    src = "import queue\nc = True\n" + chain + f'q = queue.Queue()\nq.get("{URL}")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings)


def test_a_list_holding_something_else_swaps_nothing(tmp_path):
    src = f'import queue\nS = 1\nL = [S]\nT = L[0]\nq = queue.Queue()\nq.get("{URL}")\n'
    last = src.count("\n")
    assert not any(f["line"] == last for f in _audit(tmp_path, src).findings)


# ---------------------------------------------------------------- a tree's own queue module
def test_a_trees_own_queue_module_is_not_the_standard_one(tmp_path):
    (tmp_path / "queue.py").write_text("from fetchlib import Queue\n", encoding="utf-8")
    src = f'import queue\nq = queue.Queue()\nq.get("{URL}")\n'
    assert any(f["line"] == 3 for f in _audit(tmp_path, src).findings)


# ---------------------------------------------------------------- executable= in its other forms
@pytest.mark.parametrize("argv", [
    '["x", "-c", NETC], executable=pathlib.Path(sys.executable)',
    '["x", "-c", NETC], executable=os.fsencode(sys.executable)',
    '["x", "-c", NETC], executable=getattr(sys, "executable")',
])
def test_these_name_the_running_interpreter(tmp_path, argv):
    assert "network-import" in _kinds(tmp_path, _run(argv)), argv


def test_a_from_imported_executable_bound_again_is_not_python(tmp_path):
    src = _run('[executable, "-c", NETC]', "from sys import executable\nexecutable = shutil.which('curl')\n")
    assert "network-import" not in _kinds(tmp_path, src)


def test_the_third_positional_argument_of_popen_is_the_executable(tmp_path):
    src = _run('["x", URL], -1, "/usr/bin/curl"').replace("subprocess.run(", "subprocess.Popen(")
    assert _kinds(tmp_path, src) == ["subprocess-net-binary"]


def test_which_that_finds_nothing_leaves_the_argvs_own_program(tmp_path):
    # shutil.which returns None when the program is absent, and then the argv's first word runs
    assert "subprocess-net-binary" in _kinds(tmp_path, _run('["curl", URL], executable=shutil.which("x")'))


@pytest.mark.parametrize("exe", ["python_d", "python3.14t_d"])
def test_windows_debug_interpreter_names(tmp_path, exe):
    assert "network-import" in _kinds(tmp_path, _run(f'["{exe}", "-c", NETC]')), exe


# ---------------------------------------------------------------- a long env -S string in linear time
@pytest.mark.parametrize("words", ["A=1 " * 100000, "-u A " * 30000], ids=["settings", "options"])
def test_a_long_split_string_is_read_in_linear_time(tmp_path, words):
    start = time.perf_counter()
    kinds = _kinds(tmp_path, _run(f'["env", "-S", "{words}curl {URL}"]'))
    assert time.perf_counter() - start < 15
    assert kinds == ["subprocess-net-binary"]

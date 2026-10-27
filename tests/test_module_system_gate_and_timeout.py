"""The container exemption only in a file that does not reach the module system, a tree's own `queue` anywhere, and
timeout's DURATION and `--` as GNU timeout 8.32 reads them.

Each case was settled on the real program or by running the code (a recorder in place of `urlopen`); each asserts
what must be reported and its neighbour that must not be.
"""
import time
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit

URL = "https://e.example/x"


def _audit(tmp_path: Path, src: str, name: str = "a.py"):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return audit(tmp_path, label="t")


def _kinds(tmp_path: Path, src: str) -> list:
    return sorted({f["kind"] for f in _audit(tmp_path, src).findings})


def _run(argv: str, pre: str = "") -> str:
    return f'import subprocess, os, shutil\nx = input()\nURL = "{URL}"\n{pre}subprocess.run({argv})\n'


# ---------------------------------------------------------------- the module system, reached any way
@pytest.mark.parametrize("swap", [
    "import sys\nT = [sys][0]\nT.modules['queue'] = object\n",
    "import sys\nT = (sys,)[0]\nT.modules['queue'] = object\n",
    "import sys\nL = [[sys]]\nL[0][0].modules['queue'] = object\n",
    "import sys\nD = {'s': sys}\nD['s'].modules['queue'] = object\n",
    "import sys\nnext(iter([sys])).modules['queue'] = object\n",
    "import sys, types\ntypes.SimpleNamespace(s=sys).s.modules['queue'] = object\n",
    "import sys\nfor s in [sys]:\n    s.modules['queue'] = object\n",
    "import sys\nclass K:\n    s = sys\nK.s.modules['queue'] = object\n",
    "import sys\n(None or sys).modules['queue'] = object\n",
    "import sys\nsys.path.insert(0, 'build')\n",
])
def test_a_file_that_reaches_the_module_system_keeps_no_container_exemption(tmp_path, swap):
    src = "import queue\n" + swap + f'q = queue.Queue()\nq.get("{URL}")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), swap


def test_a_file_that_does_not_keeps_it(tmp_path):
    src = f'import queue, json\nq = queue.Queue()\nq.put(json.dumps({{}}))\nq.get("{URL}")\n'
    assert not any(f["line"] == 4 for f in _audit(tmp_path, src).findings)


@pytest.mark.parametrize("shadow", ["build/queue.py", "tools/queue.py", "pkg/collections/__init__.py"])
def test_a_trees_own_queue_anywhere_keeps_no_container_exemption(tmp_path, shadow):
    (tmp_path / shadow).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / shadow).write_text("from fetchlib import Queue\n", encoding="utf-8")
    src = f'import queue\nq = queue.Queue()\nq.get("{URL}")\n'
    assert any(f["line"] == 3 for f in _audit(tmp_path, src, "tools/main.py").findings), shadow


@pytest.mark.parametrize("depth", [24])
def test_nested_lists_are_read_in_linear_time(tmp_path, depth):
    lines = "".join(f"A{i} = [A{i + 1}[0], A{i + 1}[0]]\n" for i in range(depth)) + f"A{depth} = [1]\n"
    start = time.perf_counter()
    _audit(tmp_path, "import queue\n" + lines + f"A0[0].append(1)\nq = queue.Queue()\nq.get('{URL}')\n")
    assert time.perf_counter() - start < 10


def test_many_reads_of_one_table_are_read_in_linear_time(tmp_path):
    table = "CONF = {" + ", ".join(f"'k{i}': {i}" for i in range(4000)) + "}\n"
    reads = "".join(f"x{i} = CONF['k{i}']\n" for i in range(4000))
    start = time.perf_counter()
    _audit(tmp_path, table + reads)
    assert time.perf_counter() - start < 15


# ---------------------------------------------------------------- timeout's DURATION and `--`
@pytest.mark.parametrize("duration", ["0x1p99999", "0x1P99999s", "0x" + "f" * 300])
def test_a_duration_too_large_for_a_float_is_infinity_and_never_stops_the_audit(tmp_path, duration):
    (tmp_path / "net.py").write_text("import socket\nsocket.create_connection(('h', 1))\n", encoding="utf-8")
    rep = _audit(tmp_path, _run(f'["timeout", "{duration}", "curl", URL]'))
    kinds = {(f["file"], f["kind"]) for f in rep.findings}
    assert ("a.py", "subprocess-net-binary") in kinds and ("net.py", "network-call") in kinds


def test_a_negative_duration_too_large_is_refused(tmp_path):
    assert _kinds(tmp_path, _run('["timeout", "--", "-0x1p99999", "curl", URL]')) == []


@pytest.mark.parametrize("duration,runs", [("5S", False), ("infS", False), ("5s", True), ("INF", True)])
def test_the_duration_unit_is_lower_case(tmp_path, duration, runs):
    kinds = _kinds(tmp_path, _run(f'["timeout", "{duration}", "curl", URL]'))
    assert (kinds == ["subprocess-net-binary"]) is runs, duration


@pytest.mark.parametrize("argv,kind", [
    ('["timeout", x, "--", "5", "curl", URL]', "subprocess-net-binary"),   # x may be --foreground
    ('["timeout", x, "--", "5", "git", "push"]', "git-remote"),
    ('["sudo", "timeout", x, "--", "5", "curl", URL]', "subprocess-net-binary"),
    ('["chroot", x, "--", "/", "curl", URL]', "subprocess-net-binary"),
])
def test_a_word_not_spelled_out_then_dashes_may_be_an_option(tmp_path, argv, kind):
    assert kind in _kinds(tmp_path, _run(argv)), argv


def test_a_duration_then_dashes_still_runs_nothing(tmp_path):
    assert _kinds(tmp_path, _run('["timeout", "5", "--", "curl", URL]')) == []


@pytest.mark.parametrize("duration", ["+5", "0x5"])
def test_a_word_before_a_duration_is_read_as_an_option(tmp_path, duration):
    assert "subprocess-net-binary" in _kinds(tmp_path, _run(f'["timeout", x, "{duration}", "curl", URL]'))


# ---------------------------------------------------------------- -W before a value env may drop, and the py launcher
@pytest.mark.parametrize("string", [
    "python3 -W ${W} -c -c 'import socket'",            # W set: -W takes it, `-c -c` gives code `-c`... or W unset
    "python3 -W -c -c 'import socket' ${HOME}",          # nothing dropped before -c: -W takes -c, then -c CODE
])
def test_both_readings_of_a_value_env_may_drop(tmp_path, string):
    assert "network-import" in _kinds(tmp_path, _run(f'["env", "-S", "{string}"]')), string


def test_only_the_launcher_reads_a_version_selector(tmp_path):
    assert "network-import" in _kinds(tmp_path, _run('["py", "-V:3.14", "-c", "import socket"]'))
    assert "network-import" not in _kinds(tmp_path, _run('["python", "-V:3.14", "-c", "import socket"]'))


# ---------------------------------------------------------------- executable= forms
def test_a_local_of_the_same_name_does_not_unbind_executable(tmp_path):
    pre = "from sys import executable\ndef f():\n    executable = 1\n    return executable\n"
    assert "network-import" in _kinds(tmp_path, _run('[executable, "-c", "import socket"]', pre))


def test_a_module_level_assignment_does(tmp_path):
    pre = "from sys import executable\nexecutable = shutil.which('curl')\n"
    assert "network-import" not in _kinds(tmp_path, _run('[executable, "-c", "import socket"]', pre))


def test_an_executable_bound_to_none_runs_the_argvs_own_program(tmp_path):
    src = _run('["curl", URL], -1, E', "E = None\n")
    assert _kinds(tmp_path, src) == ["subprocess-net-binary"]


def test_getattr_of_os_sys_executable_is_python(tmp_path):
    assert "network-import" in _kinds(tmp_path, _run('["x", "-c", "import socket"], executable=getattr(os.sys, '
                                                     '"executable")'))


def test_a_single_file_is_judged_by_its_own_folder_only(tmp_path):
    """For one file, only that file's folder is looked at for a `queue.py` (a script's folder leads its import path),
    never the folder's whole subtree, which for a file in the system temp folder would be everything in it."""
    import entrovouch.no_egress_auditor as A
    (tmp_path / "deep" / "x").mkdir(parents=True)
    (tmp_path / "deep" / "x" / "queue.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "a.py").write_text("import queue", encoding="utf-8")
    assert not A._tree_shadows_containers(tmp_path / "a.py")
    assert A._tree_shadows_containers(tmp_path)                 # a folder: its whole tree
    (tmp_path / "queue.py").write_text("x = 1", encoding="utf-8")
    assert A._tree_shadows_containers(tmp_path / "a.py")

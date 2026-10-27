"""Argv words read as written, wrappers' tables as their manuals give them, and the module table by every route.

A literal string is read as written even when it holds a character the argv readings use internally; an `env -S`
string is split as env splits it; a wrapper whose options take no separate value never has one take the next word;
the search over wrapper readings that cannot finish still reads the line, and does so in time; and a store into the
interpreter's module table is recognised however `sys` is reached. Each case asserts what must be reported, and its
neighbour that must not be.
"""
import time
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit

URL = "https://e.example/x"
NET = "import urllib.request; urllib.request.urlopen('https://e.example/x')"


def _audit(tmp_path: Path, src: str, name: str = "a.py"):
    (tmp_path / name).write_text(src, encoding="utf-8")
    return audit(tmp_path, label="t")


def _kinds(tmp_path: Path, src: str, name: str = "a.py") -> list:
    return [f["kind"] for f in _audit(tmp_path, src, name).findings]


# ---------------------------------------------------------------- a literal holding \x00 or \x01 is read as written
@pytest.mark.parametrize("call,kinds", [
    (f'subprocess.run(["python", "-c", "{NET} #\\x01"])', ["network-import", "network-call"]),
    (f'os.startfile("{URL}\\x01")', ["network-call"]),
    (f'subprocess.run(["xdg-open", "{URL}\\x01"])', ["subprocess-net-binary"]),
    ('subprocess.run(["git", "-c", "a=b\\x01", "push"])', ["git-remote"]),
    (f'subprocess.run(["foo", "{URL}\\x01"])', ["external-url"]),
    (f'subprocess.run(["curl", "{URL}\\x00"])', ["subprocess-net-binary"]),
])
def test_a_literal_holding_a_control_character_is_read_as_written(tmp_path, call, kinds):
    assert _kinds(tmp_path, f"import subprocess, os\n{call}\n") == kinds


def test_such_a_literal_is_named_with_the_character_escaped(tmp_path):
    rep = _audit(tmp_path, 'import subprocess\nsubprocess.run(["sudo", "tool\\x01", "a"])\n')
    assert rep.unlisted_programs == ["tool\u2401"]


def test_an_invoke_command_holding_one_is_read(tmp_path):
    src = 'from invoke import task\n@task\ndef t(c):\n    c.run("curl https://e.example/a #\\x01")\n'
    assert _kinds(tmp_path, src, "tasks.py") == ["script-network-command"]


# ---------------------------------------------------------------- env -S strings
@pytest.mark.parametrize("argv,kinds", [
    ('["env", "-S", f"curl {x}"]', ["subprocess-net-binary"]),
    ('["env", "-S", f"A=1 {x} curl https://e.example/a"]', ["unresolved-call"]),     # x's words may be the command
    ('["env", "-S", f"-u {x} curl https://e.example/a"]', ["subprocess-net-binary"]),
    ('["env", f"-S{x} https://e.example/a"]', ["external-url"]),
    ('["env", "-iScurl https://e.example/a"]', ["subprocess-net-binary"]),
    ('["env", "-iSssh host"]', ["subprocess-net-binary"]),
    ('["env", f"-iScurl {x}"]', ["subprocess-net-binary"]),
    ('["env", "-S", f"ls {x}"]', []),
])
def test_an_env_split_string_is_split_as_env_splits_it(tmp_path, argv, kinds):
    assert _kinds(tmp_path, f"import subprocess\nx = input()\nsubprocess.run({argv})\n") == kinds


def test_a_value_inside_a_split_string_may_be_the_command(tmp_path):
    """An -S string's value is split into words too, so unlike `env x foo` it may be the command itself: `foo` is not
    named, and the words after the string are its operands."""
    for argv in ('["env", f"-S{x}", "foo"]', '["env", "-S", f"{x}pandoc a"]', '["env", "-S", f"A=1 {x}", "foo"]'):
        rep = _audit(tmp_path, f"import subprocess\nx = input()\nsubprocess.run({argv})\n")
        assert rep.unlisted_programs == [] and rep.findings == [], argv


# ---------------------------------------------------------------- wrappers as their manuals give them
@pytest.mark.parametrize("argv", [
    '["setsid", f"-n{x}", "foo", "curl", URL]',
    '["nohup", f"-k{x}", "foo", "curl", URL]',
    '["command", f"-S{x}", "foo", "curl", URL]',
    '["xargs", f"-i{x}", "foo", "curl", URL]',
    '["xargs", f"-l{x}", "foo", "curl", URL]',
    '["watch", f"-d{x}", "foo", "curl", URL]',
])
def test_an_option_start_that_cannot_take_the_next_word_leaves_the_program_where_it_is(tmp_path, argv):
    """None of these options takes a separate value (`xargs -i[replace-str]`, `watch -d[=permanent]` take theirs
    attached only), so `foo` is the program and the address is handed to it."""
    rep = _audit(tmp_path, f'import subprocess\nURL = "{URL}"\nx = input()\nsubprocess.run({argv})\n')
    assert [f["kind"] for f in rep.findings] == ["external-url"]
    assert rep.unlisted_programs == ["foo"]


@pytest.mark.parametrize("argv", [
    ["nice", "-5", "foo", "a"],
    ["timeout", "-f", "5", "foo", "a"],
    ["timeout", "-p", "5", "foo", "a"],
    ["env", "--block-signal", "foo", "a"],
    ["env", "-iSfoo a"],
])
def test_documented_forms_name_their_program(tmp_path, argv):
    assert _audit(tmp_path, f"import subprocess\nsubprocess.run({argv!r})\n").unlisted_programs == ["foo"]


def test_an_exec_with_a_path_first_reads_its_wrappers_like_the_other_calls(tmp_path):
    for call in ("os.execv('/usr/bin/' + 'x', ARGV)", "os.execvp('sudo', ARGV)"):
        src = f'import os\nx = input()\nARGV = ["sudo", f"--{{x}}", "foo", "curl", "{URL}"]\n{call}\n'
        assert _kinds(tmp_path, src) == ["unresolved-call"], call


# ---------------------------------------------------------------- a search that cannot finish
def _words(*parts) -> str:
    """An argv written out in the source word by word (the tool does not expand `list * n`)."""
    return "[" + ", ".join(parts) + "]"


@pytest.mark.parametrize("argv", [
    _words(*['"chroot", x'] * 200, '"ssh", y'),
    _words(*['"chroot", x'] * 200, '"curl", URL'),
    _words(*['"timeout", x'] * 200, '"ssh", y'),
])
def test_a_search_stopped_by_its_parse_cap_still_reads_the_line(tmp_path, argv):
    src = f'import subprocess\nURL = "{URL}"\nx = y = input()\nsubprocess.run({argv})\n'
    assert _kinds(tmp_path, src) == ["unresolved-call"]


@pytest.mark.parametrize("words", [15, 16, 40])
def test_a_word_after_the_program_has_started_is_never_read_as_the_program(tmp_path, words):
    """After `x`, the plain words `w` are not options, so the program has started by the second of them under every
    reading; `ssh` is an argument, whatever the search's limits."""
    argv = _words('"sudo"', *['"-x", "sudo"'] * 12, "x", *['"w"'] * words, '"ssh", y')
    src = f'import subprocess\nx = y = input()\nsubprocess.run({argv})\n'
    assert _kinds(tmp_path, src) == []


@pytest.mark.parametrize("pairs", [15, 70, 200])
def test_past_the_fallback_limit_a_named_network_program_still_flags(tmp_path, pairs):
    """Here every `w` may be the value of the `-x` before it, so `ssh` may be the program however many there are."""
    argv = _words('"sudo"', *['"-x", "sudo"'] * 12, "x", *['"-x", "w"'] * pairs, '"ssh", y')
    src = f'import subprocess\nx = y = input()\nsubprocess.run({argv})\n'
    assert _kinds(tmp_path, src) == ["unresolved-call"]


@pytest.mark.parametrize("tail,flagged", [('"mytool", "-r", "ssh"', False), ('"mytool", "-s", "ssh"', True),
                                          ('"mytool", "-s", "ls"', False)])
def test_the_fallback_skips_the_value_of_the_wrappers_own_option(tmp_path, tail, flagged):
    """After `sudo`, `-r ssh` is a role (sudo's `-r` takes a value) and `-s ssh` is sudo's shell flag before ssh."""
    argv = _words('"sudo"', *['"-x", "sudo"'] * 12, "x", tail, "y")
    src = f'import subprocess\nx = y = input()\nsubprocess.run({argv})\n'
    assert bool(_kinds(tmp_path, src)) is flagged


def test_nested_child_code_behind_long_wrapper_chains_is_read_in_time(tmp_path):
    """Each level hands the next one to a child interpreter after a hundred wrapper words; the code is read once per
    level, not once per candidate word, so four levels take well under the time of one exponential pass."""
    code = "print(1)"
    for _ in range(4):
        argv = _words(*['"chroot", x'] * 100, *['"python", "-c", C'] * 16)
        code = f"import subprocess\nx = input()\nC = {code!r}\nsubprocess.run({argv})\n"
    start = time.perf_counter()
    _audit(tmp_path, code)
    assert time.perf_counter() - start < 20


# ---------------------------------------------------------------- the module table by every route
@pytest.mark.parametrize("swap", [
    "import os\nos.sys.modules['queue'] = requests\n",
    "import subprocess\nsubprocess.sys.modules['queue'] = requests\n",
    "import sys\nS = sys\nS.modules['queue'] = requests\n",
    "import sys\n(m := sys.modules)['queue'] = requests\n",
    "import importlib as il\nil.import_module('sys').modules['queue'] = requests\n",
    "from importlib import import_module\nimport_module('sys').modules['queue'] = requests\n",
    "import sys\na = sys.modules\nb = a\nc = b\nd = c\ne = d\ne['queue'] = requests\n",
    "import sys\ndict.__setitem__(sys.modules, 'queue', requests)\n",
    "import sys\ndict.update(sys.modules, queue=requests)\n",
    "import sys, operator\noperator.setitem(sys.modules, 'queue', requests)\n",
    "import sys\nvars(sys).get('modules')['queue'] = requests\n",
    "import sys\nglobals()['sys'].modules['queue'] = requests\n",
    "vars(queue)['Queue'] = requests.Session\n",
    "queue.__dict__['Queue'] = requests.Session\n",
])
def test_the_module_table_or_the_module_reached_any_way_is_a_swap(tmp_path, swap):
    src = "import queue, requests\n" + swap + 'q = queue.Queue()\nq.get("' + URL + '")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


def test_a_dict_that_is_not_the_module_table_swaps_nothing(tmp_path):
    src = ('import queue, operator\nreg = {}\noperator.setitem(reg, "queue", 1)\ndict.update(reg, a=1)\n'
           'q = queue.Queue()\nq.put("' + URL + '")\n')
    last = src.count("\n")
    assert not any(f["line"] == last for f in _audit(tmp_path, src).findings)


# ---------------------------------------------------------------- env -S as GNU env reads it
@pytest.mark.parametrize("argv,kinds", [
    ('["env", "-S", "#", "git", "fetch"]', ["git-remote"]),           # a comment ends the string; the argv runs
    ('["env", "-S", "A=1 #x", "git", "fetch"]', ["git-remote"]),
    ('["env", "-S", "#c", "curl", URL]', ["subprocess-net-binary"]),
    ('["env", "-S", "\\"git\\" fetch"]', ["git-remote"]),           # quotes are removed
    ('["env", "-S", "\'curl\' https://e.example/a"]', ["subprocess-net-binary"]),
    ('["env", "-S", "git\\\\_fetch"]', ["git-remote"]),             # \_ separates words
    ('["env", "--split", "git fetch"]', ["git-remote"]),              # abbreviations of --split-string
    ('["env", "--split-str=git fetch"]', ["git-remote"]),
    ('["env", "-S", "-S \'git fetch\'"]', ["git-remote"]),           # a -S inside the string is read
    ('["env", "-S", "A=1", "-S", "curl https://e.example/a"]', ["external-url"]),  # after it, -S is the program
])
def test_env_split_strings_follow_gnu_env(tmp_path, argv, kinds):
    rep = _audit(tmp_path, f'import subprocess\nURL = "{URL}"\nsubprocess.run({argv})\n')
    assert [f["kind"] for f in rep.findings] == kinds
    assert not any(p.startswith(("#", "'", '"')) for p in rep.unlisted_programs)


def test_a_variable_in_a_split_string_is_not_named(tmp_path):
    rep = _audit(tmp_path, 'import subprocess\nsubprocess.run(["env", "-S", "${GIT} fetch"])\n')
    assert rep.unlisted_programs == []


@pytest.mark.parametrize("argv", [
    '["sudo", "-S", f"{p} x=1", "pandoc", "a.md"]',
    '["sudo", "-S", f"{p}=1", "pandoc", "a.md"]',
    '["timeout", "-s", "KILL", "-S", f"{p}=1", "5", "pandoc"]',
])
def test_another_wrappers_dash_s_takes_no_split_string(tmp_path, argv):
    """`sudo -S` is `--stdin`: the f-string after it is a word the line does not spell out, possibly the program."""
    rep = _audit(tmp_path, f"import subprocess\np = input()\nsubprocess.run({argv})\n")
    assert rep.unlisted_programs == []


# ---------------------------------------------------------------- each child interpreter's code is read
def test_the_code_of_a_second_child_interpreter_is_read(tmp_path):
    net = "import socket\\nsocket.create_connection(('e.example', 80))"
    for head in (_words(*['"sudo", "-x"'] * 20, '"true"', '"-x"'), '["sudo", "-x", "pandoc", "-x"'):
        argv = head.rstrip("]") + f', "python", "-c", "pass", "-x", "python", "-c", "{net}"]'
        src = f"import subprocess\nsubprocess.run({argv})\n"
        assert _kinds(tmp_path, src), argv


# ---------------------------------------------------------------- the fallback reads words where they stand
def test_the_fallback_does_not_take_a_variable_for_the_next_word(tmp_path):
    pairs = ", ".join(f'"-x", "a{i}"' for i in range(64))
    src = f'import subprocess\nu = input()\nsubprocess.run(["sudo", {pairs}, "-u", u, "git", "fetch"])\n'
    assert _kinds(tmp_path, src) == ["unresolved-call"]


@pytest.mark.parametrize("tail", ['"sh", "-c", "git fetch"', '"bash", "-c", "x"', '"xdg-open", URL'])
def test_past_the_fallback_limit_any_program_with_a_rule_flags_the_line(tmp_path, tail):
    pairs = ", ".join(f'"-x", "a{i}"' for i in range(100))
    src = (f'import subprocess\nURL = "{URL}"\nu = input()\n'
           f'subprocess.run(["sudo", {pairs}, "-u", u, {tail}])\n')
    assert _kinds(tmp_path, src) == ["unresolved-call"]


# ---------------------------------------------------------------- literals, named programs, clusters
@pytest.mark.parametrize("call", ['subprocess.run(["x", URL], executable="cu\\x01rl")',
                                  'subprocess.run([shutil.which("cu\\x01rl"), URL])',
                                  'subprocess.run(["x", URL], executable="cu\\x00rl")'])
def test_executable_and_which_are_read_as_written(tmp_path, call):
    rep = _audit(tmp_path, f'import subprocess, shutil\nURL = "{URL}"\n{call}\n')
    assert [f["kind"] for f in rep.findings] == ["external-url"]
    assert len(rep.unlisted_programs) == 1 and "\x00" not in rep.unlisted_programs[0]
    assert "\x01" not in rep.unlisted_programs[0]


@pytest.mark.parametrize("argv", [["xargs", "-ia", "git", "fetch"], ["xargs", "-en", "git", "fetch"],
                                  ["xargs", "-la", "git", "fetch"], ["watch", "-dn", "git", "fetch"]])
def test_a_cluster_reaching_an_attached_only_value_takes_no_next_word(tmp_path, argv):
    assert _kinds(tmp_path, f"import subprocess\nsubprocess.run({argv!r})\n") == ["git-remote"]


# ---------------------------------------------------------------- a program read from inside an -S string never crashes
@pytest.mark.parametrize("argv", ["['env', '-S', '${P} host example.com']", "['env', '-S', 'host example.com']",
                                  "['env', '-S', f'{x} pip install a']", "['sudo', 'env', '-S', '${P} npm install']",
                                  "['env', '-S', '-u ${P} dig example.com']"])
def test_a_script_judged_program_inside_a_split_string_is_read(tmp_path, argv):
    rep = _audit(tmp_path, f"import subprocess\nx = input()\nsubprocess.run({argv})\n")
    assert rep is not None


# ---------------------------------------------------------------- after -S, env reads options again until its first operand
@pytest.mark.parametrize("argv,kinds", [
    ("['env', '-S', '-u', 'X', 'curl', URL]", ["subprocess-net-binary"]),
    ("['env', '-S', '-i', '-u', 'X', 'curl', URL]", ["subprocess-net-binary"]),
    ("['env', '-S-i', '-u', 'X', 'curl', URL]", ["subprocess-net-binary"]),
    ("['env', '-S', '-C', '/tmp', 'curl', URL]", ["subprocess-net-binary"]),
    ("['env', '-S', '-u', 'X', 'git', 'fetch']", ["git-remote"]),
    ("['env', '-S', '-i', '--', 'curl', URL]", ["subprocess-net-binary"]),
    ("['env', '-S', '-i -u', 'X', 'curl', URL]", ["subprocess-net-binary"]),
    ("['sudo', 'env', '-S', '-u', 'A', 'curl', URL]", ["subprocess-net-binary"]),
    ("['env', '-S', 'A=1', '-u', 'X', 'curl', URL]", ["external-url"]),     # A=1 ends env's options: `-u` runs
    ("['env', 'A=1', '-S', 'curl https://e.example/a']", ["external-url"]),
    ('["env", "-S", f"A={x}", "-S", f"B={x}", "curl"]', []),             # a setting, spelled out or not, ends them
])
def test_env_reads_options_after_a_split_string_until_its_first_operand(tmp_path, argv, kinds):
    rep = _audit(tmp_path, f'import subprocess\nURL = "{URL}"\nx = input()\nsubprocess.run({argv})\n')
    assert [f["kind"] for f in rep.findings] == kinds, argv


@pytest.mark.parametrize("argv", ["['env', '-S', 'cu\\\\rl ' 'https://e.example/a']",   # `cu<CR>l`, not curl
                                  "['env', '-S', 'a\\\\qb curl https://e.example/a']",   # an escape env refuses
                                  "['env', '-S', '\"curl https://e.example/a']",          # an unterminated quote
                                  "['env', '-S', '${X curl https://e.example/a']",
                                  "['env', '-S', '$CMD https://e.example/a']"])
def test_strings_env_misreads_or_refuses_run_no_listed_program(tmp_path, argv):
    rep = _audit(tmp_path, f"import subprocess\nsubprocess.run({argv})\n")
    assert not any(f["kind"] == "subprocess-net-binary" for f in rep.findings), argv
    assert not any("$" in p or "curl" == p for p in rep.unlisted_programs)


@pytest.mark.parametrize("argv", ['["env", "-S", f"A={x} curl https://e.example/a"]',
                                  '["env", "-S", f"-u{x} curl https://e.example/a"]'])
def test_a_settled_start_inside_a_split_string_settles_its_word(tmp_path, argv):
    assert _kinds(tmp_path, f"import subprocess\nx = input()\nsubprocess.run({argv})\n") == ["subprocess-net-binary"]


@pytest.mark.parametrize("argv,kinds", [
    ('["sudo", "-S", f"-u{u}", "curl", URL]', ["subprocess-net-binary"]),
    ('["sudo", "-S", f"--user={u}", "curl", URL]', ["subprocess-net-binary"]),
    ('["sudo", "-S", f"HOME={u}", "git", "fetch"]', ["git-remote"]),
])
def test_after_another_wrappers_dash_s_an_option_start_is_still_that_option(tmp_path, argv, kinds):
    src = f'import subprocess\nURL = "{URL}"\nu = input()\nsubprocess.run({argv})\n'
    assert _kinds(tmp_path, src) == kinds


# ---------------------------------------------------------------- the module table and module patches, both directions
@pytest.mark.parametrize("swap", [
    "import os\no = os\no.sys.modules['queue'] = requests\n",
    "import importlib\nimportlib.import_module('os').sys.modules['queue'] = requests\n",
    "__import__('os').sys.modules['queue'] = requests\n",
    "import sys\nclass A: pass\na = A()\na.sys = sys\na.sys.modules['queue'] = requests\n",
    "from os import sys as S2\nS2.modules['queue'] = requests\n",
    "import sys\nsys.meta_path = []\n",
    "import sys\nsys.meta_path += [object()]\n",
    "import sys\nmp = sys.meta_path\nmp.insert(0, object())\n",
    "import builtins\nsetattr(builtins, '__import__', print)\n",
    "import builtins\nbuiltins.__dict__['__import__'] = print\n",
    "import builtins\nsa = builtins.setattr\nsa(queue, 'Queue', requests.Session)\n",
    "from builtins import setattr as sa\nsa(queue, 'Queue', requests.Session)\n",
    "import builtins\ngetattr(builtins, 'setattr')(queue, 'Queue', requests.Session)\n",
    "Q = queue.Queue\nQ.get = requests.get\n",
    "getattr(queue, 'Queue').get = requests.get\n",
    "import sys\nm = sys.modules['queue']\nm.Queue = requests.Session\n",
    "import importlib\nimportlib.import_module('queue').Queue = requests.Session\n",
])
def test_these_routes_swap_or_patch_the_module(tmp_path, swap):
    src = "import queue, requests\n" + swap + 'q = queue.Queue()\nq.get("' + URL + '")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


@pytest.mark.parametrize("other", [
    "def worker(queue):\n    queue.put(1)\n",
    "import json\nn = json.dumps({})\n",
])
def test_these_change_nothing_about_the_module(tmp_path, other):
    src = "import queue as qmod\n" + other + 'q = qmod.Queue()\nq.put("' + URL + '")\n'
    last = src.count("\n")
    assert not any(f["line"] == last for f in _audit(tmp_path, src).findings), src


@pytest.mark.parametrize("other", [
    "import sys\nfor f in sys.meta_path.copy():\n    pass\nsys.meta_path.index(sys.meta_path[0])\n",
    "class A: pass\na = A()\na.__import__ = 1\n",
    "class A: pass\na = A()\na.sys = 1\na.sys.modules = {}\n",
])
def test_a_file_that_reaches_the_module_system_gets_no_container_exemption(tmp_path, other):
    """These change nothing about `queue` at run time, but a reading cannot tell them from the forms that do (four
    rounds of blind readers each found routes to `sys` a precise rule missed). So a file that reaches the module system
    at all gets no exemption, as the published 1.1.3 gave none; measured on the 81 real roots, no file both builds a
    container and hands one of its methods an address, so this costs no real-code precision (2026-10-26)."""
    src = "import queue as qmod\n" + other + 'q = qmod.Queue()\nq.put("' + URL + '")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


# ---------------------------------------------------------------- the fallback, the interpreter's own options
def test_the_fallback_names_no_program_from_an_address_or_a_late_word(tmp_path):
    argv = _words('"sudo"', *['"-Q", "sudo"'] * 14, *['"f"'] * 70, '"https://e.example/open"')
    rep = _audit(tmp_path, f"import subprocess\nsubprocess.run({argv})\n")
    assert not any(f["kind"] == "unresolved-call" for f in rep.findings)


@pytest.mark.parametrize("argv,kinds", [
    ('["python", "-m", "mod", "-c", "import socket"]', []),
    ('["python", "tool.py", "bash", "-c", "x y"]', []),
    ('["python", "-u", "-c", "import socket"]', ["network-import"]),
    ('["python", "-Bc", "import socket"]', ["network-import"]),
])
def test_only_the_interpreters_own_dash_c_is_read_as_code(tmp_path, argv, kinds):
    assert _kinds(tmp_path, f"import subprocess\nsubprocess.run({argv})\n") == kinds


def test_code_reused_on_many_nested_lines_is_read_once(tmp_path):
    code = "import socket\nsocket.create_connection(('e.example', 80))"
    for _ in range(6):
        lines = "".join(f"subprocess.run(['python', '-c', C])\n" for _ in range(4))
        code = f"import subprocess\nC = {code!r}\n{lines}"
    start = time.perf_counter()
    rep = _audit(tmp_path, code)
    assert time.perf_counter() - start < 10 and rep.findings


# ---------------------------------------------------------------- the interpreter's options, as CPython reads them
NETC = "import socket; socket.create_connection(('e.example', 80))"


@pytest.mark.parametrize("argv,kinds", [
    ('[sys.executable, "-W", w, "-c", NETC]', ["network-import", "network-call"]),      # a value not spelled out
    ('[sys.executable, "-X", w, "-c", NETC]', ["network-import", "network-call"]),
    ('(sys.executable, "-W", w, "-c", NETC)', ["network-import", "network-call"]),
    ('[sys.executable, "-X", w] + ["-c", NETC]', ["network-import", "network-call"]),
    ('[sys.executable, "-W", w, "-m", "pip", "install", "x"]', ["subprocess-net-binary"]),
    ('["sudo", "python3", "-W", w, "-c", NETC]', ["network-import", "network-call"]),
    ('[sys.executable, "-BW", "ignore", "-c", NETC]', ["network-import", "network-call"]),   # clusters
    ('[sys.executable, "-bX", "dev", "-c", NETC]', ["network-import", "network-call"]),
    ('[sys.executable, "-BW", "ignore", "-m", "pip", "install", "x"]', ["subprocess-net-binary"]),
    ('["ipython", "--profile", "x", "-c", NETC]', ["network-import", "network-call"]),   # a long option's value
    ('["pypy3", "--jit", "off", "-c", NETC]', ["network-import", "network-call"]),
    ('[sys.executable, "-mpip", "install", "x"]', ["subprocess-net-binary"]),
    ('[sys.executable, w, "-c", NETC]', ["network-import", "network-call"]),          # `w` may be a flag
])
def test_the_interpreter_reads_its_options_as_cpython_does(tmp_path, argv, kinds):
    src = f'import subprocess, sys\nNETC = "{NETC}"\nw = input()\nsubprocess.run({argv})\n'
    assert sorted(_kinds(tmp_path, src)) == sorted(kinds), argv


def test_the_interpreter_reads_attached_code_written_out(tmp_path):
    src = 'import subprocess, sys\nsubprocess.run([sys.executable, "-cimport socket", "x"])\n'
    assert _kinds(tmp_path, src) == ["network-import"]


@pytest.mark.parametrize("call,kinds,unlisted", [
    ('subprocess.run(["x", "-c", "import socket"], executable=sys.executable)', ["network-import"], []),
    # the program is not spelled out: an address on another machine handed to it is an address, as for any unknown
    # program
    ('subprocess.run(["mytool", "https://e.example/a"], executable=e)', ["external-url"], []),
    ('subprocess.run(["mytool", "--local"], executable=e)', [], []),
])
def test_executable_that_is_not_a_literal(tmp_path, call, kinds, unlisted):
    rep = _audit(tmp_path, f"import subprocess, sys\ne = input()\n{call}\n")
    assert [f["kind"] for f in rep.findings] == kinds and rep.unlisted_programs == unlisted


# ---------------------------------------------------------------- -S strings with a value next to an escape or quote
@pytest.mark.parametrize("argv,kinds", [
    ('["env", "-S", f"curl https://e.example/\\\\{p}"]', ["subprocess-net-binary"]),
    ('["env", "-S", f"curl ${p} https://e.example/"]', ["subprocess-net-binary"]),
    ('["env", "-S", f"curl \'{p} https://e.example/"]', ["subprocess-net-binary"]),
    ('["env", "-S", "curl ${1} https://e.example/"]', []),                     # env expands only ${NAME}
    ('["env", "-u", "nice", "-S", f"curl {p}"]', ["subprocess-net-binary"]),   # `nice` is -u's value, not a wrapper
])
def test_a_value_beside_an_escape_or_quote_does_not_make_env_refuse(tmp_path, argv, kinds):
    rep = _audit(tmp_path, f"import subprocess\np = input()\nsubprocess.run({argv})\n")
    assert [f["kind"] for f in rep.findings] == kinds, argv


# ---------------------------------------------------------------- import hooks and patches by every route
@pytest.mark.parametrize("swap", [
    "import builtins\nb = builtins\nb.__import__ = print\n",
    "import sys\nsys.modules['builtins'].__import__ = print\n",
    "import importlib\nimportlib.import_module('builtins').__import__ = print\n",
    "__builtins__['__import__'] = print\n",
    "import builtins\nb = builtins\nsetattr(b, '__import__', print)\n",
    "import builtins\nvars(builtins)['__import__'] = print\n",
    "import builtins\ngetattr(builtins, '__dict__')['__import__'] = print\n",
    "import sys\nsys.meta_path.reverse()\n",
    "import sys\nsys.meta_path.sort(key=id)\n",
    "import sys\ndel sys.meta_path[0]\n",
    "import sys\nsetattr(sys, 'meta_path', [])\n",
    "import sys\ngetattr(sys, 'meta_path').append(object())\n",
    "import sys\nmp = sys.meta_path\nmp += [object()]\n",
    "import sys, operator\noperator.setitem(sys.meta_path, 0, object())\n",
    "from sys import meta_path\nmeta_path.append(object())\n",
    "from queue import Queue\nQueue.get = requests.get\n",
    "def test(monkeypatch):\n    monkeypatch.setattr('queue.Queue.get', requests.get)\n",
    "from unittest import mock\nmock.patch('queue.Queue.get', requests.get).start()\n",
    "from unittest import mock\nmock.patch.object(queue.Queue, 'get', requests.get).start()\n",
    "class T:\n    def setup(self):\n        self.Q = queue.Queue\n        self.Q.get = requests.get\n",
    "import os\no = os\np = o\nr = p\ns = r\nu = s\nu.sys.modules['queue'] = requests\n",
])
def test_these_routes_hook_imports_or_patch_the_module(tmp_path, swap):
    src = "import queue, requests\n" + swap + 'q = queue.Queue()\nq.get("' + URL + '")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


def test_the_code_cache_reads_shared_code_once_per_file(tmp_path):
    """The same code on many lines of a file is read once; in each other file it is read again, because what it
    yields depends on the file (a module of the tree's own name, a database host the file names)."""
    import entrovouch.no_egress_auditor as A
    calls = []
    real = A._check_python

    def spy(*a, **k):
        if k.get("source"):
            calls.append(k["source"])
        return real(*a, **k)
    A._check_python = spy
    try:
        line = 'subprocess.run(["python", "-c", "import socket"])\n'
        (tmp_path / "a.py").write_text("import subprocess\n" + line * 5, encoding="utf-8")
        for name in ("b.py", "c.py"):
            (tmp_path / name).write_text("import subprocess\n" + line, encoding="utf-8")
        audit(tmp_path, label="t")
    finally:
        A._check_python = real
    assert calls.count("import socket") == 3


def test_names_bound_to_one_another_are_resolved_in_linear_time(tmp_path):
    """Names bound several times to one another: following every binding of every name recursively is exponential;
    the module rule computes its sets once, to a fixed point."""
    chain = "".join(f"a{i} = a{i + 1}\na{i} = b{i}\nb{i} = a{i + 1}\n" for i in range(60))
    src = "import queue, sys\n" + chain + "mp = a0\nmp.append(1)\nq = queue.Queue()\nq.get('https://e.example/x')\n"
    start = time.perf_counter()
    _audit(tmp_path, src)
    assert time.perf_counter() - start < 10

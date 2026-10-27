"""How a started program is named, and what a call on the file's own container is.

A program is resolved the same way whichever call starts it: written in place, or a name bound once to a literal,
for `subprocess`, `os.exec*` / `os.spawn*`, `pty.spawn` and `asyncio.create_subprocess_exec`, and for the program
given as `executable=`. A program the tool has no rule for is named in `unlisted_programs`, as an import it has no
rule for is named in `unlisted_imports`, and an address handed to it is reported. A call on a container the file
builds itself (`{}`, `queue.Queue()`) is that container's method. Each case asserts both halves: what must be
reported is, and the neighbour that must not be, is not.
"""
import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import attestation
from entrovouch.no_egress_auditor import audit, report_dict
from entrovouch.signer import MerkleSigner, verify_signature

URL = "https://e.example/x"


def _audit(tmp_path: Path, src: str, name: str = "a.py"):
    (tmp_path / name).write_text(src, encoding="utf-8")
    return audit(tmp_path, label="t")


def _kinds(tmp_path: Path, src: str, name: str = "a.py") -> list:
    return [f["kind"] for f in _audit(tmp_path, src, name).findings]


# ---------------------------------------------------------------- a program bound once to a literal
@pytest.mark.parametrize("src", [
    f'import os\nPROG = "curl"\nos.execlp(PROG, PROG, "{URL}")\n',
    f'import os\nPROG = "curl"\nos.spawnlp(os.P_WAIT, PROG, PROG, "{URL}")\n',
    f'import os\nP = "/usr/bin/curl"\nos.execv(P, ["x", "{URL}"])\n',
    f'import pty\nPROG = "curl"\npty.spawn([PROG, "{URL}"])\n',
    f'import asyncio\nPROG = "curl"\nasync def f():\n    await asyncio.create_subprocess_exec(PROG, "{URL}")\n',
    f'import asyncio\nasync def f():\n    prog = "curl"\n    await asyncio.create_subprocess_exec(prog, "{URL}")\n',
    f'import asyncio\nARGS = ["curl", "{URL}"]\nasync def f():\n    await asyncio.create_subprocess_exec(*ARGS)\n',
    f'import os\nos.execlp("curl", "curl", "{URL}")\n',                       # written in place, as before
])
def test_a_program_bound_once_is_resolved_for_every_spawn_call(tmp_path, src):
    assert "subprocess-net-binary" in _kinds(tmp_path, src), src


@pytest.mark.parametrize("src", [
    'import os\nPROG = "ls"\nos.execlp(PROG, PROG, "-l")\n',
    'import asyncio\nPROG = "ls"\nasync def f():\n    await asyncio.create_subprocess_exec(PROG, "-l")\n',
])
def test_a_local_program_bound_once_is_not_a_network_program(tmp_path, src):
    rep = _audit(tmp_path, src)
    assert "subprocess-net-binary" not in [f["kind"] for f in rep.findings]
    assert rep.unlisted_programs == ["ls"]


# ---------------------------------------------------------------- executable=
def test_the_executable_keyword_names_the_program_that_runs(tmp_path):
    assert "subprocess-net-binary" in _kinds(
        tmp_path, f'import subprocess\nsubprocess.Popen(["upload", "{URL}"], executable="curl")\n')


def test_the_executable_keyword_bound_once_is_resolved(tmp_path):
    assert "subprocess-net-binary" in _kinds(
        tmp_path, f'import subprocess\nEXE = "curl"\nsubprocess.run(["x", "{URL}"], executable=EXE)\n')


def test_a_local_executable_is_not_a_network_program(tmp_path):
    assert "subprocess-net-binary" not in _kinds(
        tmp_path, 'import subprocess\nsubprocess.run(["listing", "-l"], executable="ls")\n')


def test_with_shell_true_the_executable_is_the_shell(tmp_path):
    kinds = _kinds(tmp_path, 'import subprocess\nsubprocess.run("echo hi", shell=True, executable="/bin/bash")\n')
    assert kinds == ["subprocess-shell"]


# ---------------------------------------------------------------- programs the tool has no rule for
def test_a_program_on_no_list_is_named_and_the_verdict_says_only_what_is_known(tmp_path):
    rep = _audit(tmp_path, 'import subprocess\nsubprocess.run(["twine", "upload", "dist/*"])\n')
    assert rep.verdict == "CLEAN" and rep.findings == []
    assert rep.unlisted_programs == ["twine"]


def test_an_address_handed_to_a_program_on_no_list_is_reported(tmp_path):
    kinds = _kinds(tmp_path, f'import subprocess\nsubprocess.run(["xh", "GET", "{URL}"])\n')
    assert kinds == ["external-url"]


def test_an_address_on_this_machine_handed_to_a_program_is_not(tmp_path):
    assert _kinds(tmp_path, 'import subprocess\nsubprocess.run(["xh", "http://localhost:8000/"])\n') == []


def test_a_known_network_program_is_reported_once_not_twice(tmp_path):
    assert _kinds(tmp_path, f'import subprocess\nsubprocess.run(["curl", "{URL}"])\n') == ["subprocess-net-binary"]


def test_unlisted_programs_are_in_the_findings_digest(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "m.py").write_text('import subprocess\nsubprocess.run(["twine", "check"])\n', encoding="utf-8")
    (b / "m.py").write_text('import subprocess\nsubprocess.run(["flit", "check"])\n', encoding="utf-8")
    ra, rb = audit(a, label="t"), audit(b, label="t")
    assert ra.verdict == rb.verdict == "CLEAN" and ra.findings == rb.findings == []
    assert ra.findings_digest != rb.findings_digest


def test_a_tree_that_starts_no_unlisted_program_carries_no_field(tmp_path):
    # the field appears only when there is something in it, so a report on such a tree is the report the
    # previous release wrote
    rep = _audit(tmp_path, f'import subprocess\nsubprocess.run(["curl", "{URL}"])\n')
    assert rep.unlisted_programs == []
    assert "unlisted_programs" not in report_dict(rep)
    assert "unlisted_programs" in report_dict(_audit(tmp_path, 'import subprocess\nsubprocess.run(["twine"])\n'))


def test_the_written_json_matches_the_digest(tmp_path):
    from entrovouch.no_egress_auditor import findings_digest_matches
    for src in ('import subprocess\nsubprocess.run(["twine", "check"])\n', 'import json\n'):
        assert findings_digest_matches(report_dict(_audit(tmp_path, src)))


# ---------------------------------------------------------------- a process function under another name
@pytest.mark.parametrize("src,kind", [
    (f'import subprocess\nrunner = subprocess.run\nrunner(["curl", "{URL}"])\n', "subprocess-net-binary"),
    (f'import subprocess\nstart = subprocess.Popen\nstart(["curl", "{URL}"])\n', "subprocess-net-binary"),
    (f'import os\nsh = os.system\nsh("curl {URL}")\n', "subprocess-shell"),
    (f'import os\nrun = os.popen\nrun("curl {URL}")\n', "subprocess-shell"),
    (f'import os\nex = os.execlp\nex("curl", "curl", "{URL}")\n', "subprocess-net-binary"),
])
def test_a_process_function_bound_to_another_name_is_that_function(tmp_path, src, kind):
    rep = _audit(tmp_path, src)
    assert kind in [f["kind"] for f in rep.findings], src


def test_the_finding_names_the_function_the_alias_reaches(tmp_path):
    rep = _audit(tmp_path, f'import os\nrun = os.popen\nrun("curl {URL}")\n')
    assert any("os.popen" in f["detail"] for f in rep.findings), rep.findings


def test_the_files_own_function_under_that_name_is_not_a_process(tmp_path):
    assert _kinds(tmp_path, f'def runner(x):\n    return x\nrunner(["curl", "{URL}"])\n') == []


# ---------------------------------------------------------------- the file's own containers
@pytest.mark.parametrize("src", [
    f'seen = {{}}\nseen.get("{URL}")\n',
    f'LINKS = {{"a": "{URL}"}}\ndef f(url):\n    return LINKS.get(url)\n',
    f'seen = {{k: 1 for k in "ab"}}\nseen.get("{URL}")\n',
    f'urls = []\nurls.append("{URL}")\nurls.pop()\n',
    f'import queue\nq = queue.Queue()\nq.put("{URL}")\n',
    f'from collections import Counter\nc = Counter()\nc.get("{URL}")\n',
    f'import collections\nd = collections.OrderedDict()\nd.get("{URL}")\n',
])
def test_a_call_on_a_container_the_file_builds_is_not_an_unresolved_call(tmp_path, src):
    assert "unresolved-call" not in _kinds(tmp_path, src), src


@pytest.mark.parametrize("src,kind", [
    (f'c = make_store()\nc.get("{URL}")\n', "unresolved-call"),
    (f'import requests\ns = requests.Session()\ns.get("{URL}")\n', "network-call"),
    (f'seen = {{}}\nseen = make_store()\nseen.get("{URL}")\n', "unresolved-call"),   # bound twice: not resolved
    # the namespace is rebound, so the name may hold anything by the call
    (f'import requests\nsess = {{}}\nglobals()["sess"] = requests.Session()\nsess.get("{URL}")\n', "unresolved-call"),
    (f'import requests, sys\nsess = {{}}\nsetattr(sys.modules[__name__], "sess", requests.Session())\n'
     f'sess.get("{URL}")\n', "unresolved-call"),
    (f'from settings import *\nsess = {{}}\nsess.get("{URL}")\n', "unresolved-call"),
    # a name that is not the imported module: `collections` here is requests
    (f'import requests\ncollections = requests\nsess = collections.Session()\nsess.get("{URL}")\n', "unresolved-call"),
])
def test_a_store_of_unknown_kind_is_still_reported(tmp_path, src, kind):
    assert kind in _kinds(tmp_path, src), src


@pytest.mark.parametrize("src,expected", [
    ('import subprocess, sys\ntool = sys.argv[1]\nsubprocess.run(["sudo", tool, "data.tar"])\n', []),
    ('import subprocess, sys\nsubprocess.run(["env", sys.argv[1], "--input", "report.pdf"])\n', []),
    ('import subprocess\nsubprocess.run(["", "x"])\nsubprocess.run([" ", "x"])\n', []),
    ('import subprocess\nsubprocess.run(["sudo", "mytool", "x"])\n', ["mytool"]),
    ('import subprocess\nsubprocess.run("pandoc")\n', ["pandoc"]),
    ('import subprocess\nsubprocess.run("pandoc in.md")\n', ["pandoc"]),
])
def test_only_a_program_the_line_names_is_recorded(tmp_path, src, expected):
    """After a wrapper, a word that is not a literal is the program: nothing after it is recorded as one, and an
    empty name never is. A program run with no arguments is still a program the file starts."""
    rep = _audit(tmp_path, src)
    assert rep.unlisted_programs == expected
    assert rep.findings == []


# ---------------------------------------------------------------- a Statement whose signature is removed
@pytest.fixture(scope="module")
def signed_statement(tmp_path_factory):
    d = tmp_path_factory.mktemp("st")
    (d / "t").mkdir()
    (d / "t" / "app.py").write_text("import requests\n", encoding="utf-8")
    signer = MerkleSigner.create(d / "key.json", height=3)
    return signer.public_root, attestation.to_statement(asdict(audit(d / "t", label="x", signer=signer)))


def test_a_signed_statement_with_its_signature_removed_is_tampered(signed_statement):
    root, st = signed_statement
    assert attestation.verify_statement(st, root) == (True, "ATTESTED")
    stripped = copy.deepcopy(st)
    stripped["signature"] = None
    assert attestation.verify_statement(stripped, root) == (False, "TAMPERED")
    gone = copy.deepcopy(st)
    del gone["signature"]
    assert attestation.verify_statement(gone, root) == (False, "TAMPERED")


def test_a_statement_naming_another_signer_than_its_signature_is_tampered(signed_statement):
    root, st = signed_statement
    other = copy.deepcopy(st)
    other["predicate"]["public_root"] = "0" * 64
    assert attestation.verify_statement(other, root) == (False, "TAMPERED")


@pytest.mark.parametrize("bad", ["", "z" * 64, "ab" * 31])
def test_a_malformed_root_is_refused_by_both_verifiers(signed_statement, bad, tmp_path_factory):
    """A root that is not 64 hex digits is the caller's mistake: both verifiers say so, neither answers TAMPERED."""
    from entrovouch.no_egress_auditor import verify_report
    _, st = signed_statement
    with pytest.raises(ValueError, match="64 hex digits"):
        attestation.verify_statement(st, bad)
    d = tmp_path_factory.mktemp("rep")
    (d / "t").mkdir()
    (d / "t" / "app.py").write_text("import json\n", encoding="utf-8")
    signer = MerkleSigner.create(d / "key.json", height=2)
    report = report_dict(audit(d / "t", label="x", signer=signer))
    assert verify_report(report, signer.public_root) == (True, "ATTESTED")
    with pytest.raises(ValueError, match="64 hex digits"):
        verify_report(report, bad)


def test_an_unsigned_statement_is_still_unsigned(tmp_path):
    (tmp_path / "app.py").write_text("import json\n", encoding="utf-8")
    st = attestation.to_statement(asdict(audit(tmp_path, label="x")))
    assert attestation.verify_statement(st) == (False, "UNSIGNED")


def test_a_statement_written_before_the_predicate_named_its_signer_still_verifies(signed_statement):
    root, st = signed_statement
    old = copy.deepcopy(st)
    for k in ("signature_algorithm", "public_root"):
        old["predicate"].pop(k, None)
    assert attestation.verify_statement(old, root) == (True, "ATTESTED")


# ---------------------------------------------------------------- a root written in capitals
def test_verify_signature_reads_a_root_in_capitals_as_the_same_root(tmp_path):
    signer = MerkleSigner.create(tmp_path / "k.json", height=2)
    sig = signer.sign(b"message")
    assert verify_signature(b"message", sig, expected_root=signer.public_root)
    assert verify_signature(b"message", sig, expected_root=signer.public_root.upper())
    assert verify_signature(b"message", sig, expected_root=f"  {signer.public_root}\n")
    assert not verify_signature(b"message", sig, expected_root="0" * 64)


@pytest.mark.parametrize("src", [
    # a setting the line does not spell out sits between the wrapper and the program: the address is still reported
    'import subprocess, os\nt = os.environ["T"]\nsubprocess.run(["env", f"TOKEN={t}", "uploader", "' + URL + '"])\n',
    'import subprocess, sys\nsubprocess.run(["env", sys.argv[1], "mytool", "' + URL + '"])\n',
])
def test_an_address_after_a_wrapper_and_an_unspelled_word_is_still_reported(tmp_path, src):
    """Under `env`, a word the line does not spell out before a program name is a setting, so the program after it
    is the one that runs: it is named, and the address handed to it is reported."""
    rep = _audit(tmp_path, src)
    assert [f["kind"] for f in rep.findings] == ["external-url"]
    assert len(rep.unlisted_programs) == 1


@pytest.mark.parametrize("src,expected", [
    ('import subprocess\nsubprocess.run(["sudo", "-u", "root", "mytool", "x"])\n', ["mytool"]),
    ('import subprocess\nsubprocess.run(["timeout", "-s", "KILL", "5", "mytool"])\n', ["mytool"]),
    ('import subprocess\nsubprocess.run(["env", "-u", "HOME", "mytool"])\n', ["mytool"]),
])
def test_a_wrapper_option_value_is_not_the_program(tmp_path, src, expected):
    assert _audit(tmp_path, src).unlisted_programs == expected


@pytest.mark.parametrize("src", [
    'import collections, niquests\nfor collections in [niquests]: pass\nsess = collections.Session()\nsess.get("' + URL + '")\n',
    'import collections\nwith connect() as collections:\n    pass\nsess = collections.OrderedDict()\nsess.get("' + URL + '")\n',
    'import collections\ndef go(collections):\n    sess = collections.Session()\n    sess.get("' + URL + '")\n',
])
def test_a_module_name_rebound_by_for_with_or_a_parameter_is_not_that_module(tmp_path, src):
    assert "unresolved-call" in _kinds(tmp_path, src), src


# ---------------------------------------------------------------- a wrapper option whose value is not a literal
@pytest.mark.parametrize("argv,kind", [
    ('["sudo", "-u", user, "curl", URL]', "subprocess-net-binary"),
    ('["sudo", "-u", user, "wget", URL]', "subprocess-net-binary"),
    ('["sudo", "-u", user, "git", "push"]', "git-remote"),
    ('["sudo", "-u", user, "bash", "-c", "curl " + URL]', "subprocess-shell"),
    ('["sudo", "-u", f"{user}", "curl", URL]', "subprocess-net-binary"),
    ('["nice", "-n", user, "curl", URL]', "subprocess-net-binary"),
    ('["env", "-u", user, "curl", URL]', "subprocess-net-binary"),
    ('["strace", "-o", user, "curl", URL]', "subprocess-net-binary"),
    ('["xargs", "-I", user, "curl", URL]', "subprocess-net-binary"),
    ('["timeout", "-s", user, "5", "curl", URL]', "subprocess-net-binary"),
    ('["watch", "-d", "curl", URL]', "subprocess-net-binary"),
    ('["watch", "-d", "git", "fetch"]', "git-remote"),
    ('["sudo", "-h", "curl", URL]', "unresolved-call"),   # -h: a host before a command, or help
    ('["chroot", "/srv", "curl", URL]', "subprocess-net-binary"),
])
def test_the_program_after_a_wrapper_option_with_an_unspelled_value_is_read(tmp_path, argv, kind):
    """The value of a wrapper's option is skipped whether or not it is a literal, and the program after it is the one
    that runs. `watch -d` and `sudo -h` take no separate word; `chroot` takes its new root before the program."""
    for src in (f'import subprocess, sys\nuser = sys.argv[1]\nURL = "{URL}"\nsubprocess.run({argv})\n',
                f'import subprocess, sys\nuser = sys.argv[1]\nURL = "{URL}"\ncmd = {argv}\nsubprocess.run(cmd)\n'):
        rep = _audit(tmp_path, src)
        assert kind in [f["kind"] for f in rep.findings], src
        assert not set(rep.unlisted_programs or []) & {"x", "push", "fetch", "srv", "e.example"}, src


def test_os_exec_after_a_wrapper_with_an_unspelled_value_is_read(tmp_path):
    src = f'import os, sys\nuser = sys.argv[1]\nos.execvp("sudo", ["sudo", "-u", user, "curl", "{URL}"])\n'
    assert "subprocess-net-binary" in _kinds(tmp_path, src)


@pytest.mark.parametrize("src,expected", [
    ('import subprocess, sys\nu = sys.argv[1]\nsubprocess.run(["sudo", "-u", u, "mytool", "x"])\n', ["mytool"]),
    ('import subprocess\nsubprocess.run(["chroot", "/srv", "mytool"])\n', ["mytool"]),
    ('import subprocess\nsubprocess.run(["chroot", "/srv"])\n', []),
])
def test_a_wrapper_value_or_argument_is_never_recorded_as_the_program(tmp_path, src, expected):
    assert _audit(tmp_path, src).unlisted_programs == expected


@pytest.mark.parametrize("src", [
    'import collections, requests\nmatch requests:\n    case collections:\n        pass\n'
    'd = collections.Session()\nd.get("' + URL + '")\n',
    'import collections, requests\nclass collections:\n    deque = requests.Session\n'
    'd = collections.deque()\nd.get("' + URL + '")\n',
    'import collections, requests\ndef collections():\n    return requests\n'
    'd = collections.deque()\nd.get("' + URL + '")\n',
    'import collections, requests\nmatch {}:\n    case {**collections}:\n        pass\n'
    'd = collections.deque()\nd.get("' + URL + '")\n',
])
def test_a_module_name_rebound_by_def_class_or_match_is_not_that_module(tmp_path, src):
    rep = _audit(tmp_path, src)
    last = src.count("\n")
    assert any(f["kind"] == "unresolved-call" and f["line"] == last for f in rep.findings), src


def test_the_real_container_neighbour_is_still_not_reported(tmp_path):
    src = 'import collections\nd = collections.deque()\nd.append("' + URL + '")\nd.pop()\n'
    assert "unresolved-call" not in _kinds(tmp_path, src)



# ---------------------------------------------------------------- every reading of a wrapper line
@pytest.mark.parametrize("argv,kind", [
    ('["env", x, "A=1", "git", "push"]', "git-remote"),
    ('["env", x, "A=1", "bash", "-c", "ls"]', "subprocess-shell"),
    ('["env", x, "A=1", "npm", "install"]', "subprocess-net-binary"),
    ('["timeout", x, "5", "ssh", "host"]', "subprocess-net-binary"),
    # (`timeout x -- ssh h`: x is DURATION, so `--` is the command; or x is an option, so `ssh` is DURATION. GNU
    # timeout 8.32 runs nothing either way: "failed to run command '--'", measured 2026-10-25)
    ('["timeout", x, "ssh", "h"]', "subprocess-net-binary"),
    ('["env", x, "-i", "curl", x]', "subprocess-net-binary"),
    ('["xargs", x, "-0", "curl"]', "subprocess-net-binary"),
    ('["nice", x, "-n", "5", "curl", x]', "subprocess-net-binary"),
    ('["sudo", x, "--", "curl", x]', "subprocess-net-binary"),
    ('["sudo", x, "-u", "root", "curl", "-T", "f", x]', "subprocess-net-binary"),
    ('["sudo", x, "-u", "root", "git", "push"]', "git-remote"),
    ('["env", x, "A=1", "curl", URL]', "subprocess-net-binary"),
    ('["sudo", "-h", "myhost", "curl", URL]', "subprocess-net-binary"),   # -h takes the host before a command
    ('["sudo", "-iu", "root", "curl", URL]', "subprocess-net-binary"),
    ('["sudo", "-uroot", "curl", URL]', "subprocess-net-binary"),
    ('["sudo", "env", "nice", "timeout", "5", "nohup", "curl", URL]', "subprocess-net-binary"),
    ('["time", "-o", "out", "curl", URL]', "subprocess-net-binary"),
    ('["chroot", "--userspec", "a:b", "/srv", "curl", URL]', "subprocess-net-binary"),
])
def test_a_wrapper_line_is_reported_when_any_reading_reaches_the_network(tmp_path, argv, kind):
    """A word the line does not spell out after a wrapper, followed by one of that wrapper's documented options, a
    setting, a number or `--`, is read as an option too, so the program after it is found; documented option values
    are skipped. An address finding does not stand in for a stronger one."""
    for src in (f'import subprocess\nx = input()\nURL = "{URL}"\nsubprocess.run({argv})\n',
                f'import subprocess\nx = input()\nURL = "{URL}"\ncmd = {argv}\nsubprocess.check_call(cmd)\n'):
        kinds = [f["kind"] for f in _audit(tmp_path, src).findings]
        assert kind in kinds, src
        assert "external-url" not in kinds, src


def test_an_address_after_an_unspelled_program_is_still_reported(tmp_path):
    src = f'import subprocess\nx = input()\nsubprocess.run(["chroot", "/srv", x, "{URL}"])\n'
    assert _kinds(tmp_path, src) == ["external-url"]


@pytest.mark.parametrize("argv,expected", [
    ('["sudo", "-iu", "root", "mytool"]', ["mytool"]),
    ('["sudo", "-uroot", "mytool"]', ["mytool"]),
    ('["stdbuf", "--output", "L", "mytool"]', ["mytool"]),
    ('["strace", "-P", "/tmp", "mytool"]', ["mytool"]),
    ('["time", "-o", "out", "mytool"]', ["mytool"]),
    ('["chroot", "--userspec", "a:b", "/srv", "mytool"]', ["mytool"]),
    ('["sudo", "env", "nice", "timeout", "5", "nohup", "mytool"]', ["mytool"]),
    ('["chroot", "/srv", "--", "mytool"]', []),
    ('["env", x, "A=1", "mytool"]', ["mytool"]),           # `A=1` shows the unknown word is a setting too
    ('["nice", "--frob", "KILL", "wget"]', []),              # the program depends on the reading: nothing named
    ('["env", "--", "A=1", "mytool"]', ["mytool"]),
])
def test_the_program_recorded_is_the_one_the_wrappers_run(tmp_path, argv, expected):
    src = f'import subprocess\nx = input()\nsubprocess.run({argv})\n'
    assert _audit(tmp_path, src).unlisted_programs == expected


@pytest.mark.parametrize("src", [
    'import queue\nfrom requests import sessions as queue\nq = queue.Session()\nq.get("' + URL + '")\n',
    'import sys, requests\nsys.modules["queue"] = requests\nimport queue\nq = queue.Session()\nq.get("' + URL + '")\n',
    'import sys, queue, requests\nsys.modules[__name__].queue = requests\nq = queue.Session()\nq.get("' + URL + '")\n',
    'import queue, requests\nqueue.Queue = requests.Session\nq = queue.Queue()\nq.get("' + URL + '")\n',
    'import queue, requests\nsetattr(queue, "Queue", requests.Session)\nq = queue.Queue()\nq.get("' + URL + '")\n',
    'import queue\ndel queue\nq = queue.Queue()\nq.get("' + URL + '")\n',
])
def test_a_module_swapped_patched_or_imported_twice_is_not_a_container(tmp_path, src):
    rep = _audit(tmp_path, src)
    last = src.count("\n")
    assert any(f["line"] == last for f in rep.findings), src


@pytest.mark.parametrize("src", [
    'import queue\nclass W:\n    def run(self, queue_): pass\nq = queue.Queue()\nq.get("' + URL + '")\n',
    'import collections\nq = collections.deque()\nq.append("' + URL + '")\n',
])
def test_a_real_container_is_still_its_own_method(tmp_path, src):
    assert "unresolved-call" not in _kinds(tmp_path, src)



# ---------------------------------------------------------------- every parse, whatever an option's arity
@pytest.mark.parametrize("argv,kinds", [
    ('["nice", "--frob", "KILL", "wget"]', {"unresolved-call"}),     # an option no manual lists
    ('["nice", "--frob", "out", "git", "push"]', {"unresolved-call"}),
    ('["nice", x, "--frob", "root", "python", "-m", "pip", "install", "x"]', {"unresolved-call"}),
    # (`ionice -n nice -- 8 x curl` moved to test_interpreters_wrappers_and_reflection.py: after `--`, `8` is the
    # command and nothing is flagged)
    ('["sudo", "-u", x, "root", "curl", URL]', {"external-url"}),       # -u takes x; `root` runs, handed an address
    ('["env", "-i", "nice", "--frob", "KILL", "wget", x, "file.txt"]', {"unresolved-call"}),
    ('["timeout", "30", x, "-d", URL]', {"external-url"}),             # x is the program; -d is its option
])
def test_a_line_whose_program_depends_on_an_options_arity_is_reported(tmp_path, argv, kinds):
    """Where an option's arity is not documented (`nice --frob`), the documented reading decides, and a
    parse that reads the option the other way and reaches the network adds one `unresolved-call`. Found by the
    2026-10-25 random-input Monte Carlo, then corrected for the documented arities."""
    src = f'import subprocess\nx = input()\nURL = "{URL}"\nsubprocess.run({argv})\n'
    rep = _audit(tmp_path, src)
    assert {f["kind"] for f in rep.findings} == kinds, src
    assert len(rep.findings) == 1, src


@pytest.mark.parametrize("argv", [
    '["nice", "-n", "root", "time", "-o", "curl"]',          # GNU time -o FILE: `curl` is the output file
    '["sudo", "-g", "docker", "make", "build"]',            # -g GROUP
    '["sudo", "-u", "wget", "make", "all"]',
    '["timeout", "-s", "curl", "5", "ls"]',
    '["env", "-C", "ssh", "make"]',
    '["chroot", "/srv/curl", "make"]',
    '["chroot", "--userspec", "curl", "/srv", "ls"]',
    '["watch", "-d", "out", "git", "push"]',                 # watch -d takes its value only attached: `out` runs
    '["watch", "-d", "KILL", "wget"]',
])
def test_a_documented_option_value_is_never_the_program(tmp_path, argv):
    """A value an option is documented to take is skipped and never read as the program, even when it is spelled
    like one (the false class a reading-every-way union brought back)."""
    assert _audit(tmp_path, f'import subprocess\nsubprocess.run({argv})\n').findings == []


@pytest.mark.parametrize("argv", [
    '["sudo", "-u", u, "python", "-m", "pip", "install", "x"]',
    '["sudo", "-g", g, "ssh", "host"]',
    '["sudo", "-u", "mysql", "mysqldump", "db"]',
    '["env", "-u", "mysql", "rclone", "copy", ".", URL]',
])
def test_one_wrapper_line_gives_one_finding(tmp_path, argv):
    src = f'import subprocess\nu = g = input()\nURL = "{URL}"\nsubprocess.run({argv})\n'
    assert len(_audit(tmp_path, src).findings) <= 1, src


def test_an_address_is_not_dropped_for_a_listener_another_reading_finds(tmp_path):
    src = f'import subprocess\nsubprocess.run(["env", "-u", "git", "daemon", "{URL}"])\n'
    assert [f["kind"] for f in _audit(tmp_path, src).findings] == ["external-url"]


def test_nested_python_c_through_wrappers_stays_fast(tmp_path):
    import time
    code = "import subprocess; subprocess.run(['curl', 'https://e.example/x'])"
    for _ in range(9):
        code = ('import subprocess; subprocess.run(["chroot", "--userspec", "python", "python", "python", "-c", '
                + repr(code) + "])")
    (tmp_path / "a.py").write_text(code + "\n", encoding="utf-8")
    t0 = time.perf_counter()
    audit(tmp_path, label="t")
    assert time.perf_counter() - t0 < 3


@pytest.mark.parametrize("argv", [
    '["sudo", "-u", "deploy", "systemctl", "restart", "app"]',
    '["timeout", "-s", "KILL", "5", "pytest", "-q"]',
    '["nice", "-n", "10", "make", "all"]',
    '["chroot", "/srv", "ls", "-l"]',
])
def test_a_local_program_after_wrappers_is_still_clean(tmp_path, argv):
    assert _audit(tmp_path, f'import subprocess\nsubprocess.run({argv})\n').findings == []


def test_a_long_wrapper_line_stays_fast(tmp_path):
    import time
    words = ", ".join(['"sudo", "-u", "a", "-g", "b", "env", "-u", "c", "nice", "-n", "d"'] * 6)
    src = f'import subprocess\nsubprocess.run([{words}, "curl", "{URL}"])\n'
    t0 = time.perf_counter()
    _audit(tmp_path, src)
    assert time.perf_counter() - t0 < 5



# ---------------------------------------------------------------- round 8: options with a spelled-out start, no-run
SOCK = "import socket; socket.create_connection(('evil.example', 80))"


@pytest.mark.parametrize("argv", [
    '["nice", f"-n{lvl}", sys.executable, "-c", SOCK]',
    '["sudo", f"--user={u}", sys.executable, "-c", SOCK]',
    '["sudo", f"PATH={u}", sys.executable, "-c", SOCK]',
    '["stdbuf", f"-o{u}", sys.executable, "-c", SOCK]',
    '["nice", adj, "python", "-c", SOCK]',
    '["sudo", adj, "python3", "-c", SOCK]',
])
def test_code_handed_to_python_after_wrappers_is_always_read(tmp_path, argv):
    """An f-string whose literal start is an option or a setting (`f"-n{lvl}"`) is that option, and code handed to a
    child interpreter is read even when the program after the wrappers is not settled. Every build up to 1.1.3
    reported these; an earlier 1.1.4 candidate did not."""
    src = f'import subprocess, sys\nadj = lvl = u = input()\nSOCK = {SOCK!r}\nsubprocess.run({argv})\n'
    assert "network-call" in _kinds(tmp_path, src), src


@pytest.mark.parametrize("argv,kind", [
    ('["nice", f"-n{lvl}", "curl", URL]', "subprocess-net-binary"),
    ('["sudo", f"HTTPS_PROXY={u}", "curl", URL]', "subprocess-net-binary"),
    ('["ionice", f"-c{lvl}", "git", "fetch"]', "git-remote"),
    ('["env", "-Scurl https://e.example/x"]', "subprocess-net-binary"),
    ('["env", "-iS", "curl https://e.example/x"]', "subprocess-net-binary"),
    ('["env", "-S", "-i curl https://e.example/x"]', "subprocess-net-binary"),
    ('["env", "-S", "A=1 curl https://e.example/x"]', "subprocess-net-binary"),
    ('["doas", "-a", "bsdauth", "curl", URL]', "subprocess-net-binary"),
    ('["sudo", "-c", "daemon", "curl", URL]', "subprocess-net-binary"),
    ('["xargs", "--arg-file", "urls.txt", "curl", "-O"]', "subprocess-net-binary"),
    ('["strace", "--output", "trace.log", "curl", URL]', "subprocess-net-binary"),
    ('["strace", "-U", "name,calls", "curl", URL]', "subprocess-net-binary"),
    ('["env", "-a", "name", "curl", URL]', "subprocess-net-binary"),
    ('["timeout", "--", "5", "curl", URL]', "subprocess-net-binary"),   # (`timeout 5 -- curl` runs `--`)
    ('["timeout", "5", adj, "-v", URL]', "external-url"),            # after DURATION the program: adj runs
    ('["env", adj, URL]', "external-url"),
    (repr(["nohup"] * 40 + ["curl", "https://e.example/x"]), "external-url"),   # past the depth followed
])
def test_the_documented_reading_names_the_kind(tmp_path, argv, kind):
    src = f'import subprocess, sys\nadj = lvl = u = input()\nURL = "{URL}"\nsubprocess.run({argv})\n'
    rep = _audit(tmp_path, src)
    assert [f["kind"] for f in rep.findings] == [kind], src


@pytest.mark.parametrize("argv", [
    '["sudo", "-l", "curl", URL]',            # lists whether curl is allowed
    '["sudo", "-e", "curl"]',                 # edits a file named curl
    '["command", "-v", "curl"]',              # describes curl
    '["ionice", "-P", "123", "curl", URL]',   # sets the class of process group 123; the rest are IDs
])
def test_a_wrapper_option_that_runs_nothing_runs_nothing(tmp_path, argv):
    src = f'import subprocess\nURL = "{URL}"\nsubprocess.run({argv})\n'
    assert _audit(tmp_path, src).findings == []


@pytest.mark.parametrize("src", [
    'try:\n    from queue import Queue\nexcept ImportError:\n    from .queue import Queue\nq = Queue()\nq.put("' + URL + '")\n',
    'import sys, queue, requests\nsys.modules["_queue"] = requests\nq = queue.SimpleQueue()\nq.put("' + URL + '")\n',
    'import sys, queue, requests\nsys.modules["threading"] = requests\nq = queue.Queue()\nq.put("' + URL + '")\n',
])
def test_a_relative_import_or_a_swapped_dependency_is_not_the_container(tmp_path, src):
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


@pytest.mark.parametrize("argv", [repr(["sudo"] + ["-x", "sudo"] * 24 + ["-x"]),
                                  "[" + ", ".join(['"sudo"', "h"] * 24) + "]"])
def test_alternating_unknown_options_and_wrappers_stay_fast(tmp_path, argv):
    import time
    src = f'import subprocess\nh = input()\nsubprocess.run({argv})\n'
    t0 = time.perf_counter()
    _audit(tmp_path, src)
    assert time.perf_counter() - t0 < 3



# ---------------------------------------------------------------- round 9: a spelled-out start helps only the wrappers
@pytest.mark.parametrize("argv,kind", [
    ('["git", "-c", f"a={b}", "-C", repo, "push"]', "git-remote"),
    ('["kubectl", "version", f"--client={c}"]', "subprocess-net-binary"),
    ('["dotnet", "restore", f"--source={src}"]', "subprocess-net-binary"),
    ('["helm", "template", "rel", "chart", f"--repo={r}"]', "subprocess-net-binary"),
    ('["psql", f"--dbname={d}", "-c", "select 1"]', "subprocess-net-binary"),
    ('[f"--{x}", "curl", URL]', "subprocess-net-binary"),
])
def test_an_fstring_start_changes_nothing_outside_the_wrapper_readings(tmp_path, argv, kind):
    """Every rule but the wrapper readings sees an f-string as a word the line does not spell out, as before: the
    literal start (`--client=`, `--source=`) must not be read as a value."""
    src = f'import subprocess\nb = c = src = r = d = x = repo = input()\nURL = "{URL}"\nsubprocess.run({argv})\n'
    rep = _audit(tmp_path, src)
    assert kind in [f["kind"] for f in rep.findings], src


def test_no_report_text_carries_the_internal_marker(tmp_path):
    src = ('import subprocess, sys\ncmd = s = x = input()\nURL = "' + URL + '"\n'
           'subprocess.run(["env", f"-S{cmd}"])\nsubprocess.run(["env", "-S", f"A=1 tool{s}", URL])\n'
           'subprocess.run([f"--{x}", "curl", URL])\nsubprocess.run([sys.executable, "-c", f"x={x}; print(x)"])\n')
    rep = _audit(tmp_path, src)
    text = json.dumps(report_dict(rep))
    assert "\\u0001" not in text and "\x01" not in text
    assert "unparseable-source" not in [f["kind"] for f in rep.findings]   # (the scope text names the kind)


@pytest.mark.parametrize("argv,kinds,named", [
    ('["nice", "-n5", "mytool", "curl", URL]', ["external-url"], ["mytool"]),   # -n5: the value is attached
    ('["sudo", f"-u", "root", "curl", URL]', ["subprocess-net-binary"], []),     # no placeholder: a literal -u
    ('["sudo", opt, "-l", "curl", URL]', ["subprocess-net-binary"], []),         # opt may be -u, making -l a user
    ('["sudo", "--frob", "-l", "curl", URL]', ["subprocess-net-binary"], []),
    ('["sudo", "-u", "root", "-l", "curl", URL]', [], []),                       # -l lists: nothing runs
    ('["nice", "--frob", "x", "python", "-c", NET]', ["unresolved-call"], []),   # x is the program as documented
])
def test_the_principal_reading_keeps_its_place(tmp_path, argv, kinds, named):
    net = "import urllib.request; urllib.request.urlopen('https://e.example/x')"
    src = f'import subprocess\nopt = input()\nURL = "{URL}"\nNET = {net!r}\nsubprocess.run({argv})\n'
    rep = _audit(tmp_path, src)
    assert [f["kind"] for f in rep.findings] == kinds, src
    assert rep.unlisted_programs == named, src


@pytest.mark.parametrize("argv", [
    '["doas", "-C", "doas.conf", "curl", URL]',     # checks the configuration
    '["doas", "-L"]',
    '["sudo", "-v", "curl", URL]',                  # validates credentials
    '["time", "-V", "curl", URL]',
])
def test_more_options_that_run_nothing(tmp_path, argv):
    assert _audit(tmp_path, f'import subprocess\nURL = "{URL}"\nsubprocess.run({argv})\n').findings == []


def test_a_thousand_word_argv_neither_crashes_nor_goes_silent(tmp_path):
    src = f'import subprocess\nsubprocess.run({["nice"] + ["--frob"] * 1000 + ["mytool", URL]!r})\n'
    assert [f["kind"] for f in _audit(tmp_path, src).findings] == ["external-url"]


@pytest.mark.parametrize("swap", [
    'import sys as s\ns.modules["queue"] = requests\n',
    'from sys import modules\nmodules["queue"] = requests\n',
    'import sys\nsys.modules.update(queue=requests)\n',
])
def test_sys_modules_under_another_name_is_a_swap(tmp_path, swap):
    src = "import queue, requests\n" + swap + 'q = queue.Queue()\nq.get("' + URL + '")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


NETC = "import urllib.request as q; q.urlopen(h)"


@pytest.mark.parametrize("argv", [
    '["sudo", f"--{o}", "root", "curl", URL]',
    '["sudo", f"-i{o}", "root", "git", "push"]',
    '["sudo", f"--us{o}", "root", "git", "push"]',
    '["doas", f"-n{o}", "root", "git", "push"]',
    '["env", f"--{o}", "NAME", "curl", URL]',
    '["nice", f"--{o}", "x", "git", "pull"]',
    '["stdbuf", f"--{o}", "L", "git", "pull"]',
    '["timeout", f"--{o}", "KILL", "5", "git", "pull"]',
    '["sudo", f"--{o}", "root", "python3", "-c", NETC]',
])
def test_an_option_start_that_does_not_settle_its_arity_leaves_the_program_open(tmp_path, argv):
    """`f"--{o}"`, `f"-i{o}"`: an option, never the program, which may take the next word. The line is flagged as
    depending on that reading, and no program name is claimed for it."""
    src = f'import subprocess\nURL = "{URL}"\nNETC = "{NETC}"\no = h = input()\nsubprocess.run({argv})\n'
    rep = _audit(tmp_path, src)
    assert [f["kind"] for f in rep.findings] == ["unresolved-call"], rep.findings
    assert rep.unlisted_programs == []
    assert "\x01" not in json.dumps(report_dict(rep))


@pytest.mark.parametrize("argv,kind", [
    ('["sudo", f"-u{user}", "git", "push"]', "git-remote"),         # -u takes a value: it is attached
    ('["sudo", f"--user={user}", "git", "push"]', "git-remote"),
    ('["nice", f"-n{user}", "git", "push"]', "git-remote"),
    ('["sudo", f"HOME={user}", "git", "push"]', "git-remote"),
    ('["sudo", f"--{user}", "-l", "git", "push"]', "git-remote"),   # `-l` may be the unsettled option's value
    ('["sudo", f"--{user}", "git", "push"]', "git-remote"),           # the reading the wrapper's syntax gives
    ('["env", f"-Scurl {user}", URL]', "subprocess-net-binary"),
    ('["env", "-S", f"A=1 curl {user}", URL]', "subprocess-net-binary"),
    ('["env", f"--split-string=curl -fsSL {user}"]', "subprocess-net-binary"),
    ('["env", "-S", f"GIT_DIR=x git fetch {user}"]', "git-remote"),
])
def test_a_settled_option_start_and_an_env_split_string_are_read(tmp_path, argv, kind):
    src = f'import subprocess\nURL = "{URL}"\nuser = input()\nsubprocess.run({argv})\n'
    assert [f["kind"] for f in _audit(tmp_path, src).findings] == [kind]


@pytest.mark.parametrize("src", [
    'import os\nx = input()\nos.startfile(f"x=https://e.example/{x}")\n',
    'import os\nx = input()\nos.startfile(f"-https://e.example/{x}")\n',
])
def test_an_option_start_is_not_an_address_outside_the_wrapper_readings(tmp_path, src):
    assert _audit(tmp_path, src).findings == []


def test_code_after_more_words_than_the_search_follows_is_still_read(tmp_path):
    words = ", ".join(["x"] * 400)
    src = (f'import subprocess\nh = x = input()\n'
           f'subprocess.run(["nice", {words}, "python3", "-c", "{NETC}"])\n')
    assert [f["kind"] for f in _audit(tmp_path, src).findings] == ["unresolved-call"]


@pytest.mark.parametrize("tail,flagged", [
    (["mytool", "git", "status"], False),
    (["-u", "curl", "ls"], False),
    (["mytool", "git", "push"], True),
])
def test_a_search_that_runs_out_reads_the_tail_without_inventing_a_call(tmp_path, tail, flagged):
    argv = ["sudo"] + ["-x", "sudo"] * 12 + tail
    rep = _audit(tmp_path, f'import subprocess\nsubprocess.run({argv!r})\n')
    assert bool(rep.findings) is flagged, rep.findings


def test_twenty_thousand_unspelled_words_are_read_quickly(tmp_path):
    import time
    words = ", ".join(["x"] * 20000)
    src = f'import subprocess\nx = input()\nsubprocess.run(["timeout", {words}, "curl", "{URL}"])\n'
    start = time.perf_counter()
    rep = _audit(tmp_path, src)
    assert time.perf_counter() - start < 20
    assert [f["kind"] for f in rep.findings] == ["unresolved-call"]


@pytest.mark.parametrize("swap", [
    'import sys\nm = sys.modules\nm["queue"] = requests\n',
    'import sys\nm = sys.modules\nm |= {"queue": requests}\n',
    'import sys\ngetattr(sys, "modules")["queue"] = requests\n',
    'import sys\nvars(sys)["modules"]["queue"] = requests\n',
    'import sys\nsys.__dict__["modules"]["queue"] = requests\n',
    'import sys\nsys.modules |= {"queue": requests}\n',
    'import sys\nsetattr(sys, "modules", {"queue": requests})\n',
])
def test_the_module_table_reached_another_way_is_a_swap(tmp_path, swap):
    src = "import queue, requests\n" + swap + 'q = queue.Queue()\nq.get("' + URL + '")\n'
    last = src.count("\n")
    assert any(f["line"] == last for f in _audit(tmp_path, src).findings), src


@pytest.mark.parametrize("other", [
    'class Registry:\n    def add(self, k, v):\n        self.modules[k] = v\n',
    'class Registry:\n    modules = {}\nRegistry.modules.update(a=1)\n',
    'import plugins\nplugins.modules[name] = 1\n',
])
def test_a_table_that_is_not_the_interpreters_swaps_nothing(tmp_path, other):
    src = 'import queue\nname = "a"\n' + other + 'q = queue.Queue()\nq.put("' + URL + '")\n'
    last = src.count("\n")
    assert not any(f["line"] == last for f in _audit(tmp_path, src).findings), src


@pytest.mark.parametrize("argv", [
    '["chroot", x, "--userspec", "out", x, "timeout", "-s", "root", "curl", "file.txt"]',
    '["nice", "-n", "KILL", "--", "chroot", x, "6", "/srv", "wget", x]',
    '["chroot", "--userspec", x, x, x, "time", "-o", "root", "-p", "env", "-i", "out", "--", "--", "wget"]',
    '["timeout", "--frob", "KILL", "5", "git", "pull"]',
])
def test_an_option_of_unknown_arity_may_take_a_wrappers_own_argument_and_options_end_at_dashes(tmp_path, argv):
    """An option no manual lists may take the word in a wrapper's own-argument place (`--frob KILL`, then
    `timeout 5`); after `--` every word is an operand (`chroot -- -- wget`: the root is `--`)."""
    src = f'import subprocess\nx = input()\nsubprocess.run({argv})\n'
    assert [f["kind"] for f in _audit(tmp_path, src).findings] == ["unresolved-call"]

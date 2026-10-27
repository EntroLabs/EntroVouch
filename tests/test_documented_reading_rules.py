"""What README.md, CHANGELOG.md and docs/WHAT_IS_READ.md say about started programs, containers and mapping names.

Each test pins one sentence of those files, so the documentation and the behaviour cannot drift apart without a
test failing: the programs `unlisted_programs` names, the process-start forms 1.1.4 reads that 1.1.3 did not, the
folders the container rule looks in for a tree's own `queue`, and `get` on a receiver named like a mapping.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit

URL = "https://e.example/x"


def _audit(tmp_path: Path, src: str, name: str = "a.py"):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return audit(tmp_path, label="t")


def _kinds(rep) -> list:
    return sorted({f["kind"] for f in rep.findings})


# ---------------------------------------------------------------- unlisted_programs (README, CHANGELOG)
@pytest.mark.parametrize("argv, program", [
    (["cargo", "build"], "cargo"),
    (["mvn", "package"], "mvn"),
    (["poetry", "install"], "poetry"),
    (["s3cmd", "ls", "s3://b"], "s3cmd"),
])
def test_a_program_the_command_rules_judge_is_named_beside_its_finding(tmp_path, argv, program):
    rep = _audit(tmp_path, f"import subprocess\nsubprocess.run({argv!r})\n")
    assert "subprocess-net-binary" in _kinds(rep)
    assert rep.unlisted_programs == [program]


@pytest.mark.parametrize("argv", [["curl", URL], ["git", "fetch"], ["pip", "install", "x"], ["npm", "ci"],
                                  ["ssh", "h.example.com"], ["docker", "pull", "x"]])
def test_a_program_on_the_started_program_lists_is_not_named(tmp_path, argv):
    rep = _audit(tmp_path, f"import subprocess\nsubprocess.run({argv!r})\n")
    assert rep.findings
    assert rep.unlisted_programs == []


def test_an_address_handed_to_a_program_no_rule_covers_is_external_url(tmp_path):
    rep = _audit(tmp_path, f"import subprocess\nsubprocess.run(['mytool', '{URL}'])\n")
    assert _kinds(rep) == ["external-url"] and rep.unlisted_programs == ["mytool"]


# ---------------------------------------------------------------- bound program names (CHANGELOG 1.1.4)
@pytest.mark.parametrize("src", [
    f'import os\nPROG = "curl"\nos.execv(PROG, [PROG, "{URL}"])\n',
    f'import os\nPROG = "curl"\nos.execlp(PROG, PROG, "{URL}")\n',
    f'import os\nPROG = "curl"\nos.spawnlp(os.P_WAIT, PROG, PROG, "{URL}")\n',
    f'import os\nPROG = "curl"\nos.spawnv(os.P_WAIT, PROG, [PROG, "{URL}"])\n',
    f'import asyncio\nPROG = "curl"\nasync def m():\n    await asyncio.create_subprocess_exec(PROG, "{URL}")\n',
    f'import asyncio\nARGS = ["curl", "{URL}"]\nasync def m():\n    await asyncio.create_subprocess_exec(*ARGS)\n',
])
def test_a_bound_program_name_no_literal_argv_spells_out_is_read(tmp_path, src):
    assert "subprocess-net-binary" in _kinds(_audit(tmp_path, src))


@pytest.mark.parametrize("src", [
    f'import pty\nARGS = ["ssh", "h.example.com"]\npty.spawn(ARGS)\n',
    f'import os\nARGS = ["curl", "{URL}"]\nos.execvp(ARGS[0], ARGS)\n',
    f'import os\nARGS = ["curl", "{URL}"]\nos.spawnv(os.P_WAIT, "/usr/bin/curl", ARGS)\n',
])
def test_a_literal_argv_bound_to_a_name_is_read_as_before(tmp_path, src):
    assert "subprocess-net-binary" in _kinds(_audit(tmp_path, src))


# ---------------------------------------------------------------- a tree's own queue (CHANGELOG, WHAT_IS_READ)
_CONTAINER = f'import queue\nq = queue.Queue()\nv = q.get("{URL}")\n'


@pytest.mark.parametrize("where", ["pkg/queue.py", "_queue.py", ".venv/queue.py", "build/queue.py",
                                   "collections/__init__.py"])
def test_a_tree_queue_in_a_read_or_name_skipped_folder_ends_the_exemption(tmp_path, where):
    (tmp_path / where).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / where).write_text("x = 1\n", encoding="utf-8")
    assert "unresolved-call" in _kinds(_audit(tmp_path, _CONTAINER))


@pytest.mark.parametrize("where", [".git/queue.py", "node_modules/queue.py"])
def test_a_tree_queue_under_git_or_node_modules_is_not_looked_for(tmp_path, where):
    (tmp_path / where).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / where).write_text("x = 1\n", encoding="utf-8")
    assert _kinds(_audit(tmp_path, _CONTAINER)) == []


def test_the_container_exemption_holds_with_no_queue_in_the_tree(tmp_path):
    assert _kinds(_audit(tmp_path, _CONTAINER)) == []


@pytest.mark.parametrize("pre", ["import sys\n", "q2 = None\nimport queue as qq\nqq.Queue.get = print\n",
                                 "vars(queue)\n", "from unittest import mock\nmock.patch('queue.Queue')\n"])
def test_the_conditions_what_is_read_lists_end_the_exemption(tmp_path, pre):
    assert "unresolved-call" in _kinds(_audit(tmp_path, "import queue\n" + pre + _CONTAINER))


# ---------------------------------------------------------------- get on a mapping-named receiver (WHAT_IS_READ)
@pytest.mark.parametrize("name", ["cache", "config", "data", "headers", "settings"])
def test_get_on_a_mapping_named_receiver_gives_no_finding(tmp_path, name):
    assert _kinds(_audit(tmp_path, f'def f({name}):\n    return {name}.get("{URL}")\n')) == []


def test_get_on_another_receiver_name_is_unresolved(tmp_path):
    assert _kinds(_audit(tmp_path, f'def f(s):\n    return s.get("{URL}")\n')) == ["unresolved-call"]


def test_a_client_named_like_a_mapping_keeps_its_import_finding_only(tmp_path):
    rep = _audit(tmp_path, f'import requests\ncache = requests.Session()\ncache.get("{URL}")\n')
    assert [(f["line"], f["kind"]) for f in rep.findings] == [(1, "network-import")]

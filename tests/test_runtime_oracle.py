"""A second opinion from the running program.

The auditor reads source. Python can also report what a program does while it runs: an audit hook
(`sys.addaudithook`, PEP 578) is told when a socket connects, a name is looked up or a process is
started. The two share nothing, so one can check the other.

Each small program in `oracle_programs/` is run in a child process with a hook installed, and read
by the auditor.

- `plain/`: whatever the hook saw, the auditor must also have reported. That is a check on recall
  made by something other than the auditor's own lists.
- `quiet/`: the hook must see nothing and the auditor must report nothing.
- `built_at_run_time/`: the program connects, with names put together while it runs. The hook sees
  the connection; the auditor reports only that a module is loaded by a computed name.
- `process_not_resolved/`: a process is started with a command that is harmless or decided while
  running. The hook sees the process; the auditor reports nothing.

The last two are the limits the README states, shown here from both sides.

Nothing leaves the machine: every connection is to a loopback port that was closed a moment
before, so it is refused. The programs are ordinary files, so an audit of this repository reports
them, under `tests/oracle_programs/`. What this does not show: recall on code nobody here wrote.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit

PROGRAMS = Path(__file__).parent / "oracle_programs"
HARNESS = PROGRAMS / "_harness.py"

# What the hook must see for each plain program.
PLAIN = {
    "socket_connect": {"socket.connect"},
    "create_connection": {"socket.connect"},
    "getaddrinfo": {"socket.getaddrinfo"},
    "urlopen": {"urllib.Request"},
    "from_import_urlopen": {"urllib.Request"},
    "http_client": {"http.client.connect"},
    "smtplib": {"socket.connect"},
    "ftplib": {"socket.connect"},
    "asyncio": {"socket.connect"},
    "alias": {"socket.connect"},
    "inside_function": {"socket.connect"},
    "child_given_code": {"subprocess.Popen"},
    "os_system": {"os.system"},
    "server_bind": {"socket.bind"},
}


def _names(group: str) -> list:
    return sorted(p.stem for p in (PROGRAMS / group).glob("*.py"))


def _observe(tmp_path: Path, group: str, name: str) -> tuple:
    """Run the program under a hook, and read a copy of it with the auditor."""
    program = PROGRAMS / group / (name + ".py")
    done = subprocess.run([sys.executable, str(HARNESS), str(program)], capture_output=True, text=True, timeout=60)
    line = [ln for ln in done.stdout.splitlines() if ln.startswith("EVENTS ")]
    assert line, done.stdout + done.stderr
    tree = tmp_path / "tree"
    tree.mkdir()
    shutil.copyfile(program, tree / "program.py")
    return set(json.loads(line[-1][len("EVENTS "):])), audit(tree, label="t")


def test_every_plain_program_has_an_expectation():
    assert _names("plain") == sorted(PLAIN)
    assert len(_names("quiet")) >= 5 and len(_names("built_at_run_time")) >= 2 and len(_names("process_not_resolved")) >= 2


@pytest.mark.parametrize("name", sorted(PLAIN))
def test_what_the_running_program_did_the_reader_reported(tmp_path, name):
    events, report = _observe(tmp_path, "plain", name)
    assert PLAIN[name] <= events, f"the hook did not see the program act: {sorted(events)}"
    assert report.verdict != "CLEAN" and report.findings, f"{name}: the program did {sorted(events)} and the report is clean"


@pytest.mark.parametrize("name", _names("quiet"))
def test_a_program_that_does_nothing_is_quiet_to_both(tmp_path, name):
    events, report = _observe(tmp_path, "quiet", name)
    assert events == set(), sorted(events)
    assert report.verdict == "CLEAN", report.findings


@pytest.mark.parametrize("name", _names("built_at_run_time"))
def test_a_name_built_while_running_is_seen_by_the_hook_and_not_named_by_the_reader(tmp_path, name):
    events, report = _observe(tmp_path, "built_at_run_time", name)
    assert "socket.connect" in events
    assert {f["kind"] for f in report.findings} == {"dynamic-exec"}


@pytest.mark.parametrize("name", _names("process_not_resolved"))
def test_a_process_whose_command_says_nothing_is_seen_by_the_hook_only(tmp_path, name):
    events, report = _observe(tmp_path, "process_not_resolved", name)
    assert "subprocess.Popen" in events
    assert report.verdict == "CLEAN", report.findings

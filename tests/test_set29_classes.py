"""Forms read in set 29, each with its true neighbour still reported.

Two programs named certutil; a syslog handler judged by its address; Cython source named as source; a shell
variable that holds a command.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _findings(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [f for f in audit(tmp_path).findings if not f["kind"].startswith(("network-import", "network-dependency"))]


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    return [(f["kind"], f["line"]) for f in _findings(tmp_path, name, text)]


def test_nss_certutil_on_a_local_database_reaches_nothing(tmp_path):
    src = "#!/bin/sh\ncertutil -d $NSSDB -N --empty-password\ncertutil -d $NSSDB -A -n ca -t CT,, -a -i ca.pem\n"
    assert not _kinds(tmp_path, "gen.sh", src)
    py = "import subprocess\nsubprocess.run(['certutil', '-d', 'db', '-L'])\n"
    assert not [k for k in _kinds(tmp_path, "gen.py", py) if k[0] == "subprocess-net-binary"]


def test_windows_certutil_that_downloads_is_still_a_command(tmp_path):
    src = "certutil -urlcache -split -f https://h.example/x.exe x.exe\n"
    assert ("script-network-command", 1) in _kinds(tmp_path, "fetch.cmd", src)
    py = "import subprocess\nsubprocess.run(['certutil', '-urlcache', '-f', url, 'x.exe'])\n"
    assert ("subprocess-net-binary", 2) in _kinds(tmp_path, "fetch.py", py)


@pytest.mark.parametrize("call", ["SysLogHandler(address='/dev/log')", "SysLogHandler()",
                                  "SysLogHandler(('localhost', 514))"])
def test_a_syslog_handler_to_this_machine_is_a_loopback_call(tmp_path, call):
    src = f"import logging.handlers\nfrom logging.handlers import SysLogHandler\nh = {call}\n"
    assert ("loopback-call", 3) in _kinds(tmp_path, "log.py", src), call


@pytest.mark.parametrize("call", ["SysLogHandler(address=('logs.example', 514))",
                                  "SysLogHandler(address=url.netloc.split(':'))",
                                  "HTTPHandler('logs.example', '/log')"])
def test_a_handler_to_another_host_is_still_a_network_call(tmp_path, call):
    src = f"import logging.handlers\nfrom logging.handlers import SysLogHandler, HTTPHandler\nh = {call}\n"
    assert ("network-call", 3) in _kinds(tmp_path, "log.py", src), call


def test_cython_source_is_named_as_source(tmp_path):
    found = _findings(tmp_path, "fast.pyx", "def f():\n    return 1\n")
    assert [f["kind"] for f in found] == ["unanalysed-artifact"]
    assert "Cython source" in found[0]["detail"] and "compiled" not in found[0]["detail"]


def test_a_compiled_module_is_still_called_compiled(tmp_path):
    (tmp_path / "x.so").write_bytes(b"\x7fELF\x02\x01\x01\x00" + bytes(64))
    found = [f for f in audit(tmp_path).findings]
    assert found and "compiled" in found[0]["detail"]


@pytest.mark.parametrize("line", ['CMD="curl -v -x $PROXY_URL https://h.example/robots.txt"',
                                  'CURL="curl -v --connect-timeout 20"',
                                  "export FETCH='wget -q https://h.example/x'"])
def test_a_variable_that_holds_a_command_is_a_word(tmp_path, line):
    kinds = [k for k, _ in _kinds(tmp_path, "t.sh", f"#!/bin/sh\n{line}\n")]
    assert "script-network-word" in kinds and "script-network-command" not in kinds, line


@pytest.mark.parametrize("line", ['RESPONSE=$(curl -s https://h.example/x)',
                                  'V="$(curl -s https://h.example/v)"',
                                  'HTTPS_PROXY=x curl -s https://h.example/x'])
def test_a_substitution_or_a_command_after_the_assignment_still_runs(tmp_path, line):
    assert "script-network-command" in [k for k, _ in _kinds(tmp_path, "t.sh", f"#!/bin/sh\n{line}\n")], line

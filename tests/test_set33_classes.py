"""Forms read in sets 28 and 33, each with its true neighbour still reported.

A requirement installed from a `file:///` address is a path on this machine; one from another host is still a remote
source. A connection opened by the name of a plugin the same file defines and registers is that plugin's code; the
same call with no such plugin keeps its claim.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if not f["kind"].startswith("network-import")]


@pytest.mark.parametrize("dep", ['"neo4j @ file:///${PROJECT_ROOT}/.."', '"mylib @ file://localhost/srv/mylib"'])
def test_a_requirement_from_a_local_file_url_is_not_a_remote_source(tmp_path, dep):
    toml = f'[project]\nname = "bench"\nversion = "0"\ndependencies = [\n  {dep},\n]\n'
    assert not [k for k in _kinds(tmp_path, "pyproject.toml", toml) if k[0] == "declared-remote-source"], dep


@pytest.mark.parametrize("dep", ['"mylib @ https://h.example/mylib-1.0.tar.gz"', '"mylib @ file://fileserver/share/mylib"'])
def test_a_requirement_from_another_host_is_still_a_remote_source(tmp_path, dep):
    toml = f'[project]\nname = "bench"\nversion = "0"\ndependencies = [\n  {dep},\n]\n'
    assert [k for k in _kinds(tmp_path, "pyproject.toml", toml) if k[0] == "declared-remote-source"], dep


PLUGIN_TEST = """from nornir.core.plugins.connections import ConnectionPluginRegister

class DummyConnectionPlugin:
    name = "dummy-plugin"
    def open(self, hostname, username, password, port, platform, extras=None, configuration=None):
        self.connection = True

def open_and_close(task, config):
    task.host.open_connection("dummy", config)

def open_by_attribute(task, config):
    task.host.open_connection(DummyConnectionPlugin.name, config)

def open_real(task, config):
    task.host.open_connection("netmiko", config)

class Test:
    @classmethod
    def setup_class(cls):
        ConnectionPluginRegister.register("dummy", DummyConnectionPlugin)
        ConnectionPluginRegister.register(DummyConnectionPlugin.name, DummyConnectionPlugin)
"""


def test_a_connection_to_a_plugin_this_file_registers_is_not_resolved(tmp_path):
    kinds = _kinds(tmp_path, "tests/test_connections.py", PLUGIN_TEST)
    assert ("unresolved-call", 9) in kinds and ("unresolved-call", 12) in kinds


def test_a_connection_to_a_plugin_registered_elsewhere_keeps_its_claim(tmp_path):
    assert ("network-call", 15) in _kinds(tmp_path, "tests/test_connections.py", PLUGIN_TEST)

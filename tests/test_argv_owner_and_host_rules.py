"""Forms read in earlier sets, each with its true neighbour still reported.

Where a program's argument sits, what a method belongs to, and what host a line names: an argv element that is not a
literal still holds its place; a method called on another call's result is that object's; a server-named method of an
SSH connection is not asyncio's; a client with no host talks to this machine; a URL whose host is a bare name or a
variable does not show where it points.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if not f["kind"].startswith("network-import")]


def test_a_variable_argument_keeps_its_place(tmp_path):
    src = ("import subprocess\n"
           "subprocess.run(['docker', 'compose', '-f', compose_file, 'down', '-t', '0'])\n"
           "subprocess.run(['docker', 'compose', '-f', compose_file, 'pull'])\n")
    kinds = _kinds(tmp_path, "a.py", src)
    assert not [k for k in kinds if k[1] == 2]
    assert ("subprocess-net-binary", 3) in kinds


def test_a_script_runner_with_nothing_after_it_lists_scripts(tmp_path):
    src = ("from subprocess import Popen\n"
           "Popen(['npm', 'run-script'])\n"
           "Popen(['npm', 'run-script', name])\n"
           "Popen(['npm', 'install'])\n")
    kinds = _kinds(tmp_path, "a.py", src)
    # running a package script is judged as `npm run-script x` is on a script line: the script's own commands are
    # judged where package.json writes them
    assert not [k for k in kinds if k[1] in (2, 3)]
    assert ("subprocess-net-binary", 4) in kinds


def test_a_copy_tool_reaches_the_network_only_when_a_host_is_named(tmp_path):
    src = ("import subprocess\n"
           "subprocess.Popen('/bin/rsync *')\n"
           "subprocess.run(['rsync', '-a', 'src/', 'host:dst/'])\n"
           "subprocess.run(['scp', 'a', dst])\n")
    kinds = _kinds(tmp_path, "a.py", src)
    assert not [k for k in kinds if k[1] == 2]
    assert ("subprocess-net-binary", 3) in kinds and ("subprocess-net-binary", 4) in kinds


def test_a_client_with_no_host_talks_to_this_machine(tmp_path):
    src = ("import subprocess\n"
           "subprocess.run(['redis-cli', '-p', '6360', 'ping'])\n"
           "subprocess.run(['redis-cli', '-h', 'cache.example.com', 'ping'])\n"
           "subprocess.run(['redis-cli', '-p', port, 'ping'])\n"
           "subprocess.run(['psql', '-h', 'db.example.com', '-c', 'select 1'])\n"
           "subprocess.run(['pip', '-h'])\n")
    kinds = _kinds(tmp_path, "a.py", src)
    assert ("loopback-call", 2) in kinds
    # line 4: the variable is the port (`-p`); no host is given, so it is this machine as well
    assert ("subprocess-net-binary", 3) in kinds and ("loopback-call", 4) in kinds
    assert ("subprocess-net-binary", 5) in kinds
    assert not [k for k in kinds if k[1] == 6]


def test_certutil_with_an_argument_not_shown_keeps_its_claim(tmp_path):
    src = ("import subprocess, os\n"
           "subprocess.run(['certutil.exe', '-q', target])\n"
           "os.execvp('/usr/bin/certutil', ['/usr/bin/certutil', target])\n"
           "subprocess.run(['certutil', '-d', 'sql:db', '-A'])\n"
           "subprocess.run(['certutil', '-urlcache', '-f', 'https://h.example/x', 'x'])\n")
    kinds = _kinds(tmp_path, "a.py", src)
    assert ("subprocess-net-binary", 2) in kinds and ("subprocess-net-binary", 3) in kinds
    assert not [k for k in kinds if k[1] == 4]
    assert ("subprocess-net-binary", 5) in kinds


def test_a_method_on_another_calls_result_is_not_subprocess(tmp_path):
    src = ("import subprocess\n"
           "promise = _runner().run(_, pty=True, shell='sea')\n"
           "subprocess.run('curl x', shell=True)\n")
    kinds = _kinds(tmp_path, "a.py", src)
    assert not [k for k in kinds if k[1] == 2]
    assert ("subprocess-shell", 3) in kinds


SSH = """import asyncio
import asyncssh
async def f(conn, loop):
    await conn.start_server(handler, '', 8888)
    await loop.create_server(factory, '0.0.0.0', 80)
    await asyncio.start_server(cb, '0.0.0.0', 80)
    await asyncssh.create_server(Server, '', 8022)
"""


def test_an_ssh_connections_server_method_is_not_asyncios(tmp_path):
    kinds = _kinds(tmp_path, "a.py", SSH)
    assert ("unresolved-call", 4) in kinds
    assert ("inbound-listener", 5) in kinds and ("inbound-listener", 6) in kinds and ("inbound-listener", 7) in kinds


def test_without_asyncssh_an_untraced_server_method_stays_asyncios(tmp_path):
    src = "import asyncio\nasync def f(conn):\n    await conn.start_server(handler, '', 8888)\n"
    assert ("inbound-listener", 3) in _kinds(tmp_path, "a.py", src)


CONN = ("import asyncio\n"
        "class Conn:\n"
        "    async def create_unix_server(self, factory, path):\n"
        "        return await self._loop.create_unix_server(factory, path)\n"
        "    async def forward(self, path):\n"
        "        return await self.create_unix_server(factory, path)\n")


def test_in_asyncssh_source_a_connections_own_server_method_is_asyncsshs(tmp_path):
    kinds = _kinds(tmp_path, "asyncssh/connection.py", CONN)
    assert ("inbound-listener", 4) in kinds and ("unresolved-call", 6) in kinds


def test_elsewhere_a_classs_own_server_method_keeps_its_claim(tmp_path):
    kinds = _kinds(tmp_path, "mylib/conn.py", CONN)
    assert ("inbound-listener", 4) in kinds and ("inbound-listener", 6) in kinds


def test_a_tests_own_server_harness_keeps_its_claim_beside_asyncssh(tmp_path):
    src = ("import asyncio\n"
           "import asyncssh\n"
           "class T:\n"
           "    async def test_x(self):\n"
           "        await self.create_server(upstream)\n")
    assert ("inbound-listener", 5) in _kinds(tmp_path, "tests/test_forward.py", src)


def test_a_call_on_an_object_the_test_patches_claims_less(tmp_path):
    src = ("from unittest import mock\n"
           "def test_x():\n"
           "    policy = HTTPPolicy()\n"
           "    with mock.patch.object(policy, 'resolve', return_value=[]):\n"
           "        policy.create_connection('example.com', 443)\n"
           "    other = HTTPPolicy()\n"
           "    other.create_connection('example.com', 443)\n")
    kinds = _kinds(tmp_path, "tests/test_http.py", src)
    assert ("unresolved-call", 5) in kinds and ("network-call", 7) in kinds


def _details(tmp_path: Path, name: str, text: str) -> dict:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return {(f["kind"], f["line"]): f["detail"] for f in audit(tmp_path).findings}


def test_a_declared_protocol_library_is_named_as_one(tmp_path):
    toml = '[project]\nname = "x"\nversion = "0"\ndependencies = [\n  "h2>=4",\n  "requests",\n]\n'
    d = _details(tmp_path, "pyproject.toml", toml)
    assert "protocol library" in d[("declared-network-dependency", 5)]
    assert "known network package" in d[("declared-network-dependency", 6)]


def test_an_interface_packages_api_is_named_as_sending_nothing(tmp_path):
    src = ("from opentelemetry.trace import get_tracer\n"
           "from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter\n"
           "from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter\n"
           "from requests.structures import CaseInsensitiveDict\n")
    d = _details(tmp_path, "a.py", src)
    assert "sends nothing itself" in d[("network-dependency", 1)]
    assert "sends nothing itself" in d[("network-dependency", 2)]
    assert ("network-import", 3) in d
    assert "network-capable package" in d[("network-dependency", 4)]


UNIX = """import asyncio, socket
async def unix_client(loop, path):
    sock = socket.socket(socket.AF_UNIX)
    await loop.sock_connect(sock, path)
    await loop.sock_sendall(sock, b'x')
async def tcp_client(loop, addr):
    sock = socket.socket()
    await loop.sock_connect(sock, addr)
async def with_client(loop, addr):
    with socket.socket(socket.AF_INET) as s:
        await loop.sock_connect(s, addr)
async def either(loop, addr, family):
    s = socket.socket(family)
    await loop.sock_connect(s, addr)
async def accepted(loop):
    srv = socket.socket(socket.AF_INET)
    conn, _ = await loop.sock_accept(srv)
    await loop.sock_sendall(conn, b'x')
"""


def test_a_unix_socket_stays_on_this_machine_and_an_internet_one_keeps_its_claim(tmp_path):
    kinds = _kinds(tmp_path, "a.py", UNIX)
    assert ("loopback-call", 4) in kinds and ("loopback-call", 5) in kinds
    assert ("network-call", 8) in kinds and ("network-call", 11) in kinds and ("network-call", 18) in kinds
    assert ("unresolved-call", 14) in kinds


def test_without_a_unix_socket_in_the_file_an_untraced_socket_keeps_its_claim(tmp_path):
    src = ("import asyncio, socket\n"
           "async def f(loop, s, addr):\n"
           "    assert 'AF_UNIX' not in repr(s)\n"
           "    await loop.sock_connect(s, addr)\n")
    assert ("network-call", 4) in _kinds(tmp_path, "a.py", src)


def test_python2_urllib_string_helpers_are_not_a_network_import(tmp_path):
    src = ("from urllib import unquote, splitquery\n"
           "from urllib import parse\n"
           "from urllib import urlopen, quote\n"
           "from urllib import request\n"
           "from urllib import thing\n")
    kinds = _kinds_all(tmp_path, "a.py", src)
    assert not [k for k in kinds if k[1] in (1, 2)]
    assert ("network-import", 3) in kinds and ("network-import", 4) in kinds
    assert ("network-import", 5) in kinds          # a name not known to be pure keeps the claim


def test_this_machines_own_name_is_not_an_external_address(tmp_path):
    src = ("#!/bin/bash\n"
           "export A=http://$(hostname):8081\n"
           "export B=https://$(hostname -f):8082\n"
           "export C=http://$HOSTNAME:80/\n"
           "export D=http://$hostname:80/\n"
           "export E=https://example.com/\n")
    kinds = _kinds(tmp_path, "s.sh", src)
    assert not [k for k in kinds if k[1] in (2, 3, 4)]
    assert ("unresolved-call", 5) in kinds and ("external-url", 6) in kinds


STUB = """import requests, urllib3
from unittest import mock
class HttpStub:
    def urlopen(self, method, url, **kw):
        return None
def test_stub():
    http = HttpStub()
    authed = urllib3.PoolManager(http=http)
    authed.urlopen("GET", "http://example.com")
def test_real():
    pool = urllib3.PoolManager()
    pool.urlopen("GET", "http://example.com")
@mock.patch("requests.adapters.HTTPAdapter.send")
def test_patched(send):
    session = requests.Session()
    session.get("https://example.com")
def test_unpatched():
    session = requests.Session()
    session.get("https://example.com")
"""


def test_a_client_over_a_stand_in_or_a_patched_transport_reaches_nothing(tmp_path):
    kinds = _kinds(tmp_path, "tests/test_http.py", STUB)
    assert ("network-target", 9) in kinds and ("network-target", 16) in kinds
    assert ("network-call", 12) in kinds and ("network-call", 19) in kinds


SCOPE = """from unittest import mock
import httpx, requests, urllib3
@mock.patch("requests.adapters.HTTPAdapter.send")
def test_other_library(send):
    httpx.get("https://collector.example.com/v1")
    requests.get("https://api.example.com/x")
def test_wraps():
    real = requests.Session.request
    with mock.patch("requests.Session.request", wraps=real, autospec=True):
        requests.Session().get("https://api.example.com/y")
@mock.patch("urllib3.connectionpool.HTTPConnectionPool.urlopen")
def test_lower_layer(urlopen):
    requests.get("https://api.example.com/z")
"""

PROD = """import urllib3
import google.auth.transport.urllib3 as gat
class RetryingPool(urllib3.PoolManager):
    def __init__(self):
        super().__init__(retries=3)
class Plain:
    pass
def fetch(creds):
    authed = gat.AuthorizedHttp(creds, http=RetryingPool())
    return authed.urlopen("GET", "https://storage.example.com/bucket")
def fetch_plain(creds):
    authed = gat.AuthorizedHttp(creds, http=Plain())
    return authed.urlopen("GET", "https://storage.example.com/bucket")
"""


def test_a_transport_patch_covers_only_the_library_it_replaces(tmp_path):
    kinds = _kinds(tmp_path, "tests/test_scope.py", SCOPE)
    assert ("network-call", 5) in kinds            # httpx is not touched by a requests patch
    assert ("network-target", 6) in kinds          # requests is
    assert ("network-call", 10) in kinds           # wraps= passes the call on to the real method
    assert ("network-target", 13) in kinds         # requests sends through urllib3's pool


def test_a_class_outside_tests_or_built_on_a_real_transport_is_not_a_stand_in(tmp_path):
    kinds = _kinds(tmp_path, "pkg/storage.py", PROD)
    assert ("network-call", 10) in kinds and ("network-call", 13) in kinds
    assert not [k for k in kinds if k[0] == "network-target"]
    kinds = _kinds(tmp_path / "t", "tests/test_storage.py", PROD)
    assert ("network-call", 10) in kinds           # subclasses urllib3.PoolManager: a real transport
    assert ("network-target", 13) in kinds         # a plain class in a test file is a stand-in


def test_a_module_importing_its_own_name_gets_the_installed_package(tmp_path):
    src = ("import socks\n"
           "def connect(host, port):\n"
           "    return socks.create_connection((host, port), proxy_type=2)\n")
    kinds = _kinds_all(tmp_path, "pkg/contrib/socks.py", src)
    assert ("network-import", 1) in kinds and ("network-call", 3) in kinds


def _kinds_all(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings]


@pytest.mark.parametrize("name, text, line", [
    ("docker-compose.yml", "services:\n  app:\n    environment:\n      URL: http://elasticsearch:9200\n", 4),
    ("s.sh", "#!/bin/bash\nexport url=http://${es_node_name}:9200\n", 2),
])
def test_a_url_whose_host_names_no_place_claims_less(tmp_path, name, text, line):
    assert ("unresolved-call", line) in _kinds(tmp_path, name, text)


@pytest.mark.parametrize("name, text, line", [
    ("docker-compose.yml", "services:\n  app:\n    environment:\n      URL: https://example.com/x\n", 4),
    ("s.sh", "#!/bin/bash\nexport url=https://${es_node_name}.example.com/\n", 2),
])
def test_a_url_with_a_domain_is_still_external(tmp_path, name, text, line):
    assert ("external-url", line) in _kinds(tmp_path, name, text)

"""Forms read in set 27, each with its true neighbour still reported.

A connection-named method of the project's own package reached by its absolute name; a URL whose host is a glob;
text held in a YAML value that is not a script.
"""
from pathlib import Path

from entrovouch.no_egress_auditor import audit


def _write(root: Path, files: dict) -> None:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _kinds_at(tmp_path: Path, files: dict, rel: str) -> list:
    _write(tmp_path, files)
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if f["file"] == rel]


PKG = {"shop/__init__.py": "", "shop/dsl/__init__.py": "",
       "shop/dsl/connections.py": "class Connections:\n    def create_connection(self, alias='default', **kw):\n"
                                  "        return object()\n"}


def test_the_projects_own_method_reached_by_its_absolute_name_is_not_resolved(tmp_path):
    files = dict(PKG)
    files["examples/a.py"] = ("from shop.dsl import connections\n"
                              "connections.create_connection(hosts=['https://es.example:9200'])\n")
    files["examples/b.py"] = ("import asyncio\nfrom shop.dsl import async_connections\n"
                              "async def main():\n    async_connections.create_connection(hosts=['x'])\n")
    files["tests/test_c.py"] = ("from shop.dsl import connections\n"
                                "c = connections.Connections[object](elasticsearch_class=object)\n"
                                "c.create_connection('testing', hosts=['https://es.example:9200'])\n")
    assert ("unresolved-call", 2) in _kinds_at(tmp_path, files, "examples/a.py")
    assert ("unresolved-call", 4) in _kinds_at(tmp_path, files, "examples/b.py")
    assert ("unresolved-call", 3) in _kinds_at(tmp_path, files, "tests/test_c.py")


def test_a_network_librarys_own_call_keeps_its_loopback_and_patched_claims(tmp_path):
    """In websocket-client's own tree `websocket.create_connection` is the project's method, and the line still
    says when it is given this machine or runs under a patched socket."""
    files = {"websocket/__init__.py": "def create_connection(url, **kw):\n    return url\n",
             "tests/test_ws.py": ("import websocket\nfrom unittest import mock\n"
                                  "ws = websocket.create_connection('ws://127.0.0.1:8080')\n"
                                  "with mock.patch('socket.socket'):\n"
                                  "    websocket.create_connection('ws://h.example/x')\n"
                                  "websocket.create_connection('ws://h.example/y')\n")}
    kinds = _kinds_at(tmp_path, files, "tests/test_ws.py")
    assert ("loopback-call", 3) in kinds and ("network-target", 5) in kinds and ("unresolved-call", 6) in kinds


def test_an_event_loops_connection_beside_the_projects_package_is_still_a_network_call(tmp_path):
    files = dict(PKG)
    files["shop/net.py"] = ("import asyncio\nfrom shop.dsl import connections\n"
                            "async def go(loop):\n    await loop.create_connection(lambda: P(), 'h.example', 443)\n")
    assert ("network-call", 4) in _kinds_at(tmp_path, files, "shop/net.py")


def test_a_third_party_package_named_like_asyncio_stays_a_network_call(tmp_path):
    files = dict(PKG)
    files["shop/ws.py"] = "import websocket\nws = websocket.create_connection('wss://h.example/socket')\n"
    assert ("network-call", 2) in _kinds_at(tmp_path, files, "shop/ws.py")


def test_a_url_with_a_glob_host_is_a_pattern(tmp_path):
    files = {"check.sh": '#!/bin/sh\ncase "$BASE_URL" in\n  https://*) ;;\n  *) exit 1 ;;\nesac\n',
             "run.sh": "#!/bin/sh\ndocker run --env repositories.url.allowed_urls=http://snapshot.test* es\n"}
    assert not [k for k in _kinds_at(tmp_path, files, "check.sh") if k[0] == "external-url"]
    assert not [k for k in _kinds_at(tmp_path, files, "run.sh") if k[0] == "external-url"]


def test_a_url_with_a_real_host_beside_a_glob_is_still_reported(tmp_path):
    files = {"a.sh": '#!/bin/sh\nBASE_URL="${BASE:-https://api.example.com/v1}"\ncase "$BASE_URL" in https://*) ;; esac\n'}
    assert ("external-url", 2) in _kinds_at(tmp_path, files, "a.sh")


PIPELINE = """jobs:
  review:
    steps:
      - name: review
        env:
          SYSTEM_PROMPT: |-
            Known false positive: a plain
            curl call without -L leaks credentials via a redirect.
            Check a value before using it in a `gh api search` query.
        run: |
          curl -fsS https://h.example/x -o x
          gh api repos/o/r/issues
"""


def test_text_in_a_yaml_value_is_not_run(tmp_path):
    kinds = _kinds_at(tmp_path, {".github/workflows/r.yml": PIPELINE}, ".github/workflows/r.yml")
    assert ("script-network-word", 8) in kinds and ("script-network-word", 9) in kinds
    assert ("script-network-command", 8) not in kinds and ("script-network-command", 9) not in kinds


def test_the_run_script_beside_it_still_runs(tmp_path):
    kinds = _kinds_at(tmp_path, {".github/workflows/r.yml": PIPELINE}, ".github/workflows/r.yml")
    assert ("script-network-command", 11) in kinds and ("script-network-command", 12) in kinds


def test_a_script_held_under_an_actions_own_key_still_runs(tmp_path):
    """run-on-arch-action's `install: |` and cibuildwheel's `CIBW_BEFORE_ALL_LINUX: |` hold scripts."""
    wf = ("jobs:\n  a:\n    steps:\n      - uses: uraimo/run-on-arch-action@v2\n        with:\n          install: |\n"
          "            apt-get update\n        env:\n          CIBW_BEFORE_ALL_LINUX: |\n            yum install -y git\n")
    kinds = _kinds_at(tmp_path, {".github/workflows/w.yml": wf}, ".github/workflows/w.yml")
    assert ("script-network-command", 7) in kinds and ("script-network-command", 10) in kinds


def test_a_script_under_a_key_that_names_neither_still_runs(tmp_path):
    """freebsd-vm's `prepare: |`: the key says nothing either way, so the block keeps the command claim."""
    wf = ("jobs:\n  a:\n    steps:\n      - uses: vmactions/freebsd-vm@v1\n        with:\n          prepare: |\n"
          "            pkg install -y python3\n")
    assert ("script-network-command", 7) in _kinds_at(tmp_path, {".github/workflows/w.yml": wf}, ".github/workflows/w.yml")


def test_a_compose_command_block_still_runs(tmp_path):
    compose = "services:\n  a:\n    command: >\n      sh -c 'curl -fsS https://h.example/x'\n"
    assert ("script-network-command", 4) in _kinds_at(tmp_path, {"docker-compose.yml": compose}, "docker-compose.yml")

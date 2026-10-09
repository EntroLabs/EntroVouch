"""Forms read in set 30, each with its true neighbour still reported.

Shell commands written as text inside an `actions/github-script` step's JavaScript; a string appended to a shell
array; a connection to a socket the same file bound to this machine.
"""
from pathlib import Path

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings if not f["kind"].startswith("network-import")]


GITHUB_SCRIPT = """jobs:
  a:
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const body = [
              `git fetch upstream`,
              `git clone https://h.example/r.git`,
            ].join("\\n");
      - name: Fetch
        run: |
          git fetch origin
"""


def test_commands_written_inside_github_script_are_text(tmp_path):
    kinds = _kinds(tmp_path, ".github/workflows/w.yml", GITHUB_SCRIPT)
    assert ("script-network-command", 8) not in kinds and ("script-network-command", 9) not in kinds
    assert ("script-network-word", 8) in kinds and ("script-network-word", 9) in kinds


def test_a_run_step_after_it_still_runs(tmp_path):
    assert ("script-network-command", 13) in _kinds(tmp_path, ".github/workflows/w.yml", GITHUB_SCRIPT)


def test_a_gitlab_script_block_still_runs(tmp_path):
    ci = "build:\n  script: |\n    curl -fsS https://h.example/x -o x\n"
    assert ("script-network-command", 3) in _kinds(tmp_path, ".gitlab-ci.yml", ci)


def test_a_string_appended_to_a_shell_array_is_a_word(tmp_path):
    for line in ('missing_deps+=("wget or curl")', "deps=(curl jq git)"):
        kinds = [k for k, _ in _kinds(tmp_path, "s.sh", f"#!/bin/sh\n{line}\n")]
        assert "script-network-word" in kinds and "script-network-command" not in kinds, line


def test_an_array_filled_by_a_substitution_still_runs(tmp_path):
    kinds = [k for k, _ in _kinds(tmp_path, "s.sh", "#!/bin/sh\nfiles=($(curl -s https://h.example/list))\n")]
    assert "script-network-command" in kinds


def test_a_connection_to_a_socket_bound_to_this_machine_is_a_loopback_call(tmp_path):
    src = ("import asyncio, socket\n"
           "async def pair():\n"
           "    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
           "    listener.bind(('127.0.0.1', 0))\n"
           "    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
           "    loop = asyncio.get_running_loop()\n"
           "    await loop.sock_connect(client, listener.getsockname())\n")
    assert ("loopback-call", 7) in _kinds(tmp_path, "t.py", src)


def test_a_connection_to_a_socket_bound_elsewhere_is_still_a_network_call(tmp_path):
    src = ("import asyncio, socket\n"
           "async def pair(host):\n"
           "    listener = socket.socket()\n"
           "    listener.bind((host, 0))\n"
           "    client = socket.socket()\n"
           "    loop = asyncio.get_running_loop()\n"
           "    await loop.sock_connect(client, listener.getsockname())\n")
    assert ("network-call", 7) in _kinds(tmp_path, "t.py", src)

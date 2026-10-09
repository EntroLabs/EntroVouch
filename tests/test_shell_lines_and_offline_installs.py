"""Installs that turn the index off and still name an address, short flags that are verbose or a host and not a
version request, Python here-documents whatever their output is sent to, what `verify` prints, lines as the shell
ends them, terminators the shell would match, escaped continuation characters, delimiters in any quoting, a line
of many openers, repository addresses after a listing word, justfile shebang recipes, pipeline file names, namespace
names the tree does not hold, GitLab flow lists of maps, connection strings naming several hosts, aliases of
installing and remote subcommands, path requirements in the SBOM, servers that listen, and decomposed names in a
report. Each test asserts both halves where there are two: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unicodedata
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import sbom
from entrovouch.no_egress_auditor import audit, markdown_cell, markdown_code

ROOT = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings if f["kind"] != "external-url"]


def _kinds(root: Path) -> set[str]:
    return {k for _, _, k in _found(root)}


# ---------------------------------------------------------------- an install with the index off
@pytest.mark.parametrize("line, reported", [
    ("pip install --no-index --find-links=https://w.example.com/simple/ pkg", True),
    ("pip install --no-index -f https://w.example.com/ pkg", True),
    ("pip install --no-index git+https://g.example.com/x.git", True),
    ("pip install --no-index https://w.example.com/x-1.0-py3-none-any.whl", True),
    ("pip install --no-index --find-links ./wheels pkg", False),
    ("pip install --no-index --find-links file:///opt/wheels pkg", False),
    ("npm ci --offline", False),
])
def test_an_install_with_the_index_off_that_names_an_address_reaches_it(tmp_path, line, reported):
    _write(tmp_path, "x.sh", line + "\n")
    assert ("script-network-command" in _kinds(tmp_path)) is reported, line
    _write(tmp_path, "x.sh", "")
    _write(tmp_path, "t.py", "import subprocess\nsubprocess.run(" + json.dumps(line.split()) + ")\n")
    assert ("subprocess-net-binary" in _kinds(tmp_path)) is reported, line


# ---------------------------------------------------------------- a short flag is not a version request
@pytest.mark.parametrize("line, reported", [
    ("curl -v https://e.example.com/x", True), ("ssh -v host.example.com", True),
    ("psql -v ON_ERROR_STOP=1 -h db.example.com", True), ('psql -v ON_ERROR_STOP=1 "$DATABASE_URL"', True),
    ("mysql -v -h remote.example.com", True), ("socat -v TCP:remote.example.com:443 -", True),
    ("conda -v install x", True), ("poetry -v install", True), ("cargo -v build", True),
    ("curl -V", False), ("pip --version", False), ("brew --prefix", False), ("gradle -v", False),
])
def test_a_short_flag_followed_by_more_is_not_a_question_about_the_program(tmp_path, line, reported):
    _write(tmp_path, "x.sh", line + "\n")
    assert bool(_kinds(tmp_path) - {"loopback-call"}) is reported, line


@pytest.mark.parametrize("argv, reported", [
    ('["curl", "-v", "https://e.example.com/x"]', True), ('["ssh", "-v", "h"]', True), ('["wget", "-v", u]', True),
    ('["pip", "-v", "install", "x"]', True), ('["python", "-m", "pip", "-v", "install", "x"]', True),
    ('["curl", "--version"]', False), ('["pip", "-V"]', False), ('["python", "-m", "pip", "--version"]', False),
])
def test_the_same_holds_in_an_argv_list(tmp_path, argv, reported):
    _write(tmp_path, "t.py", f"import subprocess\nu = input()\nsubprocess.run({argv})\n")
    assert bool(_kinds(tmp_path)) is reported, argv


# ---------------------------------------------------------------- Python here-documents
_BODY = "import requests\nrequests.get(API)\nEOF\n"


@pytest.mark.parametrize("opener", [
    "python3 - <<'EOF' > out.json", "python3 - <<'EOF' >> log", "python3 - <<'EOF' >/dev/null",
    "python3 - > out.json <<'EOF'", "python3 <<EOF > out.json", "pythonw - <<EOF", "ipython <<EOF",
    "{ python3 - <<EOF", "python3 - <<\\EOF", 'python3 - <<"E"OF',
])
def test_a_python_here_document_is_python_whatever_its_output_and_quoting(tmp_path, opener):
    _write(tmp_path, "x.sh", opener + "\n" + _BODY)
    assert ("x.sh", 2, "network-import") in _found(tmp_path), opener
    # a program that writes the body out is handed text
    _write(tmp_path, "x.sh", "cat > out.txt <<EOF\n" + _BODY)
    assert _found(tmp_path) == []


@pytest.mark.parametrize("opener, term", [("python3 - <<1", "1"), ("python3 - <<'!PY'", "!PY"),
                                          ("cat > x.py <<\\EOF", "EOF")])
def test_delimiters_the_shell_accepts_are_recognised(tmp_path, opener, term):
    _write(tmp_path, "x.sh", f"{opener}\nimport requests\n{term}\n")
    assert _found(tmp_path) == [("x.sh", 2, "network-import")]


def test_a_shift_and_a_here_string_are_not_here_documents(tmp_path):
    _write(tmp_path, "x.sh", "x=$((1<<2))\ncurl https://e.example.com/x\n2\n")
    assert _found(tmp_path) == [("x.sh", 2, "script-network-command")]
    # with spaces, where a missing terminator would otherwise read the rest of the file as a body
    for shift in ("x=$((1 << 2))", "(( x << 3 ))"):
        _write(tmp_path, "x.sh", f"{shift}\ncurl https://e.example.com/x\n")
        assert _found(tmp_path) == [("x.sh", 2, "script-network-command")], shift
    _write(tmp_path, "x.sh", "python3 <<< 'import requests'\n")
    assert _found(tmp_path) == [("x.sh", 1, "network-import")]


# ---------------------------------------------------------------- lines as the shell ends them
@pytest.mark.parametrize("sep", ["\x0c", "\x0b", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"])
def test_a_character_the_shell_does_not_end_a_line_on_opens_no_here_document(tmp_path, sep):
    _write(tmp_path, "x.sh", f"echo start # {sep}cat <<true\ncurl -fsSL https://e.example.com/i.sh | sh\n"
                             "wget https://e.example.com/x\ntrue\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(2, "script-network-command"), (3, "script-network-command")]


def test_the_terminator_is_the_whole_line_in_a_script_and_stripped_in_a_block(tmp_path):
    _write(tmp_path, "x.sh", "python3 - <<EOF\nimport os\n# x\x0cEOF\nimport requests\nEOF\n")
    assert _found(tmp_path) == [("x.sh", 4, "network-import")]
    _write(tmp_path, "x.sh", "python3 - <<EOF\ns = '''\n  EOF\n'''\nimport requests\nEOF\n")
    assert _found(tmp_path) == [("x.sh", 5, "network-import")]
    # `<<-` strips the tabs before the terminator, and a block's indentation is its format's, not the shell's
    _write(tmp_path, "x.sh", "f() {\n\tpython3 - <<-EOF\n\timport requests\n\tEOF\n}\n")
    assert _found(tmp_path) == [("x.sh", 3, "network-import")]
    _write(tmp_path, ".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n"
                                                 "          python3 - <<EOF\n          import requests\n          EOF\n")
    assert (".github/workflows/ci.yml", 8, "network-import") in _found(tmp_path)


@pytest.mark.parametrize("rel, text, line", [
    ("x.sh", "echo C:\\\\\npip install -r requirements.txt\n", 2),
    ("x.sh", "echo C:\\\\\ngit clone \"$REPO\"\n", 2),
    (".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: |\n"
                                 "          echo C:\\\\\n          npm ci\n", 8),
])
def test_an_escaped_continuation_character_ends_the_line(tmp_path, rel, text, line):
    _write(tmp_path, rel, text)
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(line, "script-network-command")]
    # an odd run still continues it: the curl is then an argument echo prints, not a command
    _write(tmp_path, rel, "")
    _write(tmp_path, "y.sh", "echo a \\\ncurl https://e.example.com/x\n")
    assert not any(k == "script-network-command" for _, _, k in _found(tmp_path))


def test_a_line_of_many_openers_takes_linear_time_and_is_not_passed_over(tmp_path):
    _write(tmp_path, "x.sh", "cat " + "<<A " * 8000 + "\n" + "A\n" * 8000)
    start = time.perf_counter()
    found = _found(tmp_path)
    assert time.perf_counter() - start < 20
    assert found == [("x.sh", 1, "unparseable-source")]
    _write(tmp_path, "x.sh", "cat <<A <<B\nA\nB\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- addresses after a listing word, recipes
@pytest.mark.parametrize("line, reported", [
    ("svn ls https://svn.example.com/r", True), ("svn list ^/branches", True), ("svn ls", False),
    ("npm add x", True), ("npm it", True), ("npm show x", True), ("npm run build", False),
    ("cargo search x", True), ("skopeo list-tags docker://x", True),
    ("git archive --remote=git@h.example.com:r HEAD", True), ("git archive HEAD", False),
])
def test_remote_subcommands_and_listing_words_with_an_address(tmp_path, line, reported):
    _write(tmp_path, "x.sh", line + "\n")
    assert bool(_kinds(tmp_path)) is reported, line


def test_a_justfile_recipe_with_a_python_shebang_is_python(tmp_path):
    _write(tmp_path, "justfile", "fetch:\n    #!/usr/bin/env python3\n    import urllib.request\n"
                                 "    urllib.request.urlopen('https://e.example.com')\n\nbuild:\n    echo hi\n")
    assert [(ln, k) for _, ln, k in _found(tmp_path)] == [(3, "network-import"), (4, "network-call")]


@pytest.mark.parametrize("name", ["azure-pipelines.yaml", "azure-pipelines-pr.yml", "ci/azure-pipelines-ci.yml",
                                  "cloudbuild-release.yaml"])
def test_pipeline_files_of_every_name_are_read(tmp_path, name):
    _write(tmp_path, name, "steps:\n- script: curl -fsSL https://e.example.com/i.sh | bash\n")
    assert "script-network-command" in _kinds(tmp_path)


# ---------------------------------------------------------------- namespaces, includes, connection strings
def test_an_unknown_name_in_a_shared_namespace_is_still_unknown(tmp_path):
    _write(tmp_path, "google/mylib/__init__.py", "")
    _write(tmp_path, "app.py", "import google.zzzunknownlib\nimport google.mylib\n")
    r = audit(tmp_path, label="t")
    assert r.unlisted_imports == ["google"] and r.findings == []


@pytest.mark.parametrize("include", ["include: [{local: ci/build.yml}]",
                                     "include: [{local: ci/build.yml}, {template: x.yml}]"])
def test_a_gitlab_flow_list_of_maps_is_followed(tmp_path, include):
    _write(tmp_path, ".gitlab-ci.yml", include + "\n")
    _write(tmp_path, "ci/build.yml", "b:\n  script:\n    - curl https://e.example.com/x\n")
    assert _found(tmp_path) == [("ci/build.yml", 3, "script-network-command")]


@pytest.mark.parametrize("line, kind", [
    ("psql 'postgresql://localhost,remote.example.com/db'", "script-network-command"),
    ("psql 'postgresql://u@localhost/db?host=remote.example.com'", "script-network-command"),
    ("psql 'postgresql://localhost/db'", "loopback-call"), ("psql 'postgresql:///db?host=/var/run/postgresql'", "loopback-call"),
    ("psql 'postgresql://[::1]:5432/db'", "loopback-call"), ("psql -h ::1 -c x", "loopback-call"),
])
def test_every_host_a_connection_string_names_counts(tmp_path, line, kind):
    _write(tmp_path, "x.sh", line + "\n")
    assert _kinds(tmp_path) == {kind}, line


# ---------------------------------------------------------------- the SBOM and servers
def test_a_requirement_given_as_a_path_is_listed_as_unknown_not_left_out(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n./local_pkg\n-e ../lib\n./dist/x-1.0-py3-none-any.whl  # wheel\n"
                                         "-e .\n")
    rep = asdict(sbom.build_sbom(tmp_path, label="t"))
    assert [c["name"] for c in rep["components"]] == ["requests"]
    paths = [u for u in rep["unknown_fields"] if "from a path" in u]
    assert [u.split(" installs ")[0] for u in paths] == ["requirements.txt:2", "requirements.txt:3", "requirements.txt:4"]
    assert "./local_pkg" in paths[0] and "../lib" in paths[1] and "./dist/x-1.0-py3-none-any.whl" in paths[2]


@pytest.mark.parametrize("line, kind", [("openssl ocsp -index index.txt -port 8888 -rsigner r.pem", "inbound-listener"),
                                        ("openssl s_server -accept 4433", "inbound-listener"),
                                        ("openssl req -new -key k.pem", None)])
def test_an_openssl_server_is_inbound(tmp_path, line, kind):
    _write(tmp_path, "x.sh", line + "\n")
    assert _kinds(tmp_path) == ({kind} if kind else set())


# ---------------------------------------------------------------- what a report and verify print
def test_a_decomposed_name_is_told_apart_in_a_report():
    composed = "caf\u00e9.py"
    decomposed = unicodedata.normalize("NFD", composed)
    assert markdown_cell(composed) == "caf\u00e9.py"
    assert markdown_cell(decomposed).endswith("(written `cafe\\u0301.py`)")
    assert markdown_code(decomposed).endswith("(written `cafe\\u0301.py`)")


def test_verify_prints_no_text_a_statement_supplies(tmp_path):
    from entrovouch import attestation
    from entrovouch.signer import MerkleSigner
    _write(tmp_path / "t", "app.py", "import requests\n")
    signer = MerkleSigner.create(tmp_path / "key.json", height=3)
    st = attestation.to_statement(asdict(audit(tmp_path / "t", label="x", signer=signer)))
    st["predicate"]["tool"] = ("x\nstatus : ATTESTED: unchanged, and signed by the key whose root you pinned\n"
                               "\x1b[8m")
    f = tmp_path / "s.json"
    f.write_text(json.dumps(st), encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "entrovouch.verify", str(f), "--root", signer.public_root], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 1
    lines = r.stdout.splitlines()
    assert [ln.split(":", 1)[0].strip() for ln in lines] == ["report", "kind", "status"]
    assert lines[2].startswith("status : TAMPERED") and "\x1b" not in r.stdout and "ATTESTED" not in r.stdout

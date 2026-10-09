"""Where a dependency comes from, which module a name finds, and every way Python binds a value. Each test asserts both
halves: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, manifests, sbom
from entrovouch.no_egress_auditor import _subject_name, audit

REPO = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _cli(module: str, *args):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=REPO, capture_output=True, text=True, encoding="utf-8")


def _components(root: Path) -> dict[str, dict]:
    return {c["name"]: c for c in asdict(sbom.build_sbom(root, label="t"))["components"]}


def _kp(root: Path) -> list[tuple[int, str]]:
    return sorted((f["line"], f["detail"]) for f in key_provenance.scan_key_provenance(root, label="t").findings)


# ---------------------------------------------------------------- a package not from the registry gets no registry URL
def test_poetry_git_path_and_url_dependencies_get_no_registry_package_url(tmp_path):
    _write(tmp_path, "pyproject.toml", (
        '[tool.poetry]\nname = "x"\nversion = "1"\n\n'
        '[tool.poetry.dependencies]\n'
        'python = "^3.10"\n'
        'requests = "2.31.0"\n'
        'mylib = { git = "https://example.org/mylib.git", tag = "v1" }\n'
        'local = { path = "../local" }\n'
        'wheel = { url = "https://example.org/w-1.0-py3-none-any.whl" }\n'))
    c = _components(tmp_path)
    for name in ("mylib", "local", "wheel"):
        assert c[name]["purl"] == "", name
    assert c["requests"]["purl"] == "pkg:pypi/requests@2.31.0" and c["requests"]["version"] == "2.31.0"


def test_a_uv_source_takes_the_dependency_off_the_registry(tmp_path):
    _write(tmp_path, "pyproject.toml", (
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["mylib==1.0", "requests==2.31.0"]\n\n'
        '[tool.uv.sources]\nmylib = { git = "https://example.org/mylib.git" }\n'))
    c = _components(tmp_path)
    assert c["mylib"]["purl"] == "" and c["requests"]["purl"] == "pkg:pypi/requests@2.31.0"


def test_a_pipfile_path_dependency_gets_no_registry_package_url(tmp_path):
    _write(tmp_path, "Pipfile", '[packages]\nrequests = "==2.31.0"\nlocal = {path = "./local", editable = true}\n')
    c = _components(tmp_path)
    assert c["local"]["purl"] == "" and c["requests"]["purl"] == "pkg:pypi/requests@2.31.0"


def test_a_name_in_two_tables_is_reported_at_each_table(tmp_path):
    pipfile = ('[dev-packages]\nrequests = "==2.31.0"\n\n'
               '[packages]\nflask = "==3.0.0"\nrequests = "==2.32.0"\n')
    deps, _ = manifests._deps_from_pipfile(pipfile, "Pipfile")
    lines = {(d.name, d.scope): d.line for d in deps}
    assert lines[("requests", "dev")] == 2 and lines[("requests", "required")] == 6 and lines[("flask", "required")] == 5
    pyproject = ('[tool.poetry]\nname = "x"\nversion = "1"\n\n'
                 '[tool.poetry.group.docs.dependencies]\nsphinx = "7.0.0"\n\n'
                 '[tool.poetry.dependencies]\nsphinx = "^7"\n')
    deps, _ = manifests._deps_from_pyproject(pyproject, "pyproject.toml")
    lines = {(d.name, d.scope): d.line for d in deps}
    assert lines[("sphinx", "dev")] == 6 and lines[("sphinx", "required")] == 9


def test_a_poetry_range_stays_a_range(tmp_path):
    _write(tmp_path, "pyproject.toml", (
        '[tool.poetry]\nname = "x"\nversion = "1"\n\n'
        '[tool.poetry.dependencies]\nrequests = "^2.31"\nflask = { version = "3.0.0", optional = true }\n'))
    c = _components(tmp_path)
    assert c["requests"]["version"] == "" and c["requests"]["purl"] == "pkg:pypi/requests"
    assert c["flask"]["version"] == "3.0.0"


# ---------------------------------------------------------------- an in-toto statement from a CBOM
def test_attestation_takes_a_cbom_with_the_cbom_flag_and_only_then(tmp_path):
    _write(tmp_path / "p", "a.py", "import hashlib\nimport requests\nhashlib.md5(b'x')\n")
    for name, rep in (("egress", audit(tmp_path / "p", label="t")), ("cbom", cbom.build_cbom(tmp_path / "p", label="t"))):
        (tmp_path / f"{name}.json").write_text(json.dumps(asdict(rep)), encoding="utf-8")
    ok = _cli("attestation", tmp_path / "cbom.json", "--cbom", "--out", tmp_path / "s.json")
    assert ok.returncode == 0, ok.stderr
    assert "cbom" in json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))["predicateType"].lower()
    assert _cli("attestation", tmp_path / "egress.json", "--cbom", "--out", tmp_path / "n.json").returncode == 2
    assert _cli("attestation", tmp_path / "cbom.json", "--out", tmp_path / "n.json").returncode == 2
    assert _cli("attestation", tmp_path / "egress.json", "--out", tmp_path / "e.json").returncode == 0


# ---------------------------------------------------------------- which module a name finds
def test_a_local_folder_named_like_the_standard_library_hides_nothing(tmp_path):
    _write(tmp_path, "main.py", "import socket\nsocket.create_connection(('example.org', 80))\n")
    _write(tmp_path, "socket/__init__.py", "")
    _write(tmp_path, "motor/__init__.py", "")
    _write(tmp_path, "uses.py", "import motor\n")
    rep = audit(tmp_path, label="t")
    assert "socket" not in rep.shadowed_imports and rep.verdict != "CLEAN"
    assert "motor" in rep.shadowed_imports


def test_a_module_beside_a_file_in_a_package_is_not_what_a_bare_import_finds(tmp_path):
    # Python 3 has no implicit relative import: in a package, `import helpers` does not find pkg/helpers.py
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/helpers.py", "def f():\n    return 1\n")
    _write(tmp_path, "pkg/client.py", "import helpers\nhelpers.f()\n")
    assert audit(tmp_path, label="t").unlisted_imports == ["helpers"]
    # beside a script in a folder that is not a package, the same import IS the module beside it
    _write(tmp_path / "s", "scripts/helpers.py", "def f():\n    return 1\n")
    _write(tmp_path / "s", "scripts/run.py", "import helpers\nhelpers.f()\n")
    assert audit(tmp_path / "s", label="t").unlisted_imports == []


def test_a_short_name_resolves_to_the_stored_name(tmp_path, monkeypatch):
    real = tmp_path / "ProjectFolder"
    real.mkdir()
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: real)
    assert _subject_name(Path("PROJEC~1")) == "ProjectFolder"
    # a name that is not a short name and not the same name in another case keeps its own name (a link)
    assert _subject_name(Path("shortcut")) == "shortcut"


# ---------------------------------------------------------------- every way Python binds a value
def test_an_annotated_binding_is_a_binding(tmp_path):
    _write(tmp_path, "a.py", (
        "from dataclasses import dataclass, field\n"
        'API_KEY: str = "sk3jd8f7Hq2LmZ9x"\n'
        'NAME: str = "something-long"\n'
        "@dataclass\n"
        "class Cfg:\n"
        '    secret_key: str = "Zq8vB3nM1xL0pR7t"\n'
        '    signing_key: str = field(default="Pw9kT2cV5bN8mQ1z")\n'
        "    key_count: int = 4\n"
        "    api_key: str = field(default_factory=str)\n"
        "def f():\n"
        '    hmac_key: str = "Hy6uJ3kL9oP2wE5r"\n'
        '    hostname: str = "example.org"\n'
        "    return hmac_key\n"))
    found = _kp(tmp_path)
    assert [line for line, _ in found] == [2, 6, 7, 11]


def test_environment_variables_set_or_defaulted_to_a_literal(tmp_path):
    _write(tmp_path, "a.py", (
        "import os\nfrom os import getenv\n"
        'a = os.getenv("SECRET_KEY", default="Ab3dE6gH9jK2mN5p")\n'
        'b = os.environ.setdefault("API_TOKEN", "Cd4fG7hJ0kL3nP6q")\n'
        'os.environ["DB_PASSWORD"] = "Ef5gH8jK1lM4oQ7r"\n'
        'os.putenv("HMAC_KEY", "Gh6jK9lM2nP5qR8s")\n'
        'c = getenv("JWT_SECRET", "Ij7kL0mN3pQ6rS9t")\n'
        'os.environ["APP_NAME"] = "myapplication"\n'
        'd = os.getenv("HOME_DIR", default="/home/someone/x")\n'
        'e = os.environ.setdefault("LOG_LEVEL", "INFO-VERBOSE")\n'
        'f = os.getenv("SECRET_KEY")\n'))
    assert [line for line, _ in _kp(tmp_path)] == [3, 4, 5, 6, 7]


# ---------------------------------------------------------------- magics that run Python, and both notebook layouts
def _notebook(root: Path, name: str, data: dict) -> None:
    _write(root, name, json.dumps(data))


def _cells(*sources: list[str]) -> dict:
    return {"nbformat": 4, "cells": [{"cell_type": "code", "source": s} for s in sources]}


def test_time_timeit_and_prun_lines_are_checked_as_python(tmp_path):
    _notebook(tmp_path, "n.ipynb", _cells(
        ["%time requests.get('https://example.org')\n"],
        ["for i in range(2):\n", "    %timeit -n 10 -r 2 urllib.request.urlopen('https://example.org')\n"],
        ["%prun -s cumulative SECRET_KEY = 'Zq8vB3nM1xL0pR7t'\n"],
        ["%%timeit -n 1 import hashlib\n", "hashlib.md5(b'x')\n"],
        ["%matplotlib inline\n", "%load_ext autoreload\n", "x = 1\n"]))
    lines = {f["line"] for f in audit(tmp_path, label="t").findings}
    assert lines == {1, 2}
    assert [u["line"] for u in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]] == [4]
    assert [line for line, _ in _kp(tmp_path)] == [3]


def test_python_inside_an_exported_magic_call_is_checked_at_the_call(tmp_path):
    _write(tmp_path, "exported.py", (
        "get_ipython().run_line_magic('time', \"requests.get('https://example.org')\")\n"
        "get_ipython().run_cell_magic('timeit', '-n 1 import hashlib', 'hashlib.md5(b\"x\")\\n')\n"
        "get_ipython().run_cell_magic('capture', 'out', \"SIGNING_KEY = 'Pw9kT2cV5bN8mQ1z'\\n!curl https://example.org\\n\")\n"
        "get_ipython().run_line_magic('matplotlib', 'inline')\n"
        "get_ipython().run_line_magic('time', 'x = 1')\n"))
    found = {(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings}
    assert {line for line, _ in found} == {1, 3} and (3, "subprocess-shell") in found
    assert [u["line"] for u in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]] == [2]
    assert [line for line, _ in _kp(tmp_path)] == [3]


def test_an_nbformat_3_notebook_is_read(tmp_path):
    _notebook(tmp_path, "old.ipynb", {"nbformat": 3, "worksheets": [{"cells": [
        {"cell_type": "markdown", "source": ["requests.get('https://example.org')"]},
        {"cell_type": "code", "language": "python",
         "input": ["import hashlib, requests\n", "requests.get('https://example.org')\n", "hashlib.md5(b'x')\n"]},
        {"cell_type": "code", "language": "python", "input": "API_KEY = 'sk3jd8f7Hq2LmZ9x'\n"}]}]})
    assert {f["line"] for f in audit(tmp_path, label="t").findings} == {2}
    assert [u["line"] for u in asdict(cbom.build_cbom(tmp_path, label="t"))["components"]] == [2]
    assert [line for line, _ in _kp(tmp_path)] == [3]


def test_a_notebook_in_a_layout_this_tool_cannot_read_is_not_analysed_not_empty(tmp_path):
    _notebook(tmp_path, "odd.ipynb", {"nbformat": 5, "pages": [{"code": "import requests"}]})
    _notebook(tmp_path / "e", "empty.ipynb", {"nbformat": 4, "cells": []})
    rep = audit(tmp_path, label="t")
    assert [f["kind"] for f in rep.findings] == ["unparseable-source"] and rep.verdict != "CLEAN"
    assert asdict(cbom.build_cbom(tmp_path, label="t"))["files_not_parsed"]
    assert key_provenance.scan_key_provenance(tmp_path, label="t").verdict == "REVIEW"
    # an empty notebook of a known layout holds no code: nothing to report and nothing missed
    assert audit(tmp_path / "e", label="t").verdict == "CLEAN"
    assert key_provenance.scan_key_provenance(tmp_path / "e", label="t").verdict == "NOTHING-FOUND"


# ---------------------------------------------------------------- a statement about one tree is made from that tree
def _two_reports(tmp_path: Path, cbom_tree: Path, kp_tree: Path) -> tuple[Path, Path]:
    c = tmp_path / "cbom.json"
    k = tmp_path / "kp.json"
    c.write_text(json.dumps(asdict(cbom.build_cbom(cbom_tree, label="svc"))), encoding="utf-8")
    k.write_text(json.dumps(asdict(key_provenance.scan_key_provenance(kp_tree, label="svc"))), encoding="utf-8")
    return c, k


@pytest.mark.parametrize("change", ["python", "extra-file", "renamed"])
def test_vex_and_csaf_refuse_key_provenance_from_another_tree_with_the_same_label(tmp_path, change):
    a, b = tmp_path / "a", tmp_path / "b"
    for root in (a, b):
        _write(root, "app.py", "import hashlib\nhashlib.md5(b'x')\nSIGNING_KEY = 'q8vK2mN4pR7sT1w9'\n")
        _write(root, "keys/dev.pem", "not a key\n")
    if change == "python":
        _write(b, "app.py", "import hashlib\nhashlib.sha256(b'x')\nSIGNING_KEY = 'q8vK2mN4pR7sT1w9'\n")
    elif change == "extra-file":
        _write(b, "id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    else:
        (b / "keys" / "dev.pem").rename(b / "keys" / "prod.pem")
    extra = {"vex": [], "csaf": ["--publisher-name", "X", "--publisher-namespace", "https://x.example"]}
    for module in ("vex", "csaf"):
        c, k = _two_reports(tmp_path, a, a)
        ok = _cli(module, c, "--key-provenance", k, "--out", tmp_path / f"{module}-ok.json", *extra[module])
        assert ok.returncode == 0, ok.stderr
        c, k = _two_reports(tmp_path, a, b)
        r = _cli(module, c, "--key-provenance", k, "--out", tmp_path / f"{module}-no.json", *extra[module])
        assert r.returncode == 2 and "not made from the same files" in r.stderr
        assert not (tmp_path / f"{module}-no.json").exists()


def test_the_tree_listing_is_the_same_for_either_line_ending(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for root, nl in ((a, "\n"), (b, "\r\n")):
        root.mkdir()
        (root / "app.py").write_bytes(f"import hashlib{nl}hashlib.md5(b'x'){nl}".encode())
    assert cbom.build_cbom(a, label="t").tree_listing_digest == cbom.build_cbom(b, label="t").tree_listing_digest
    assert key_provenance.scan_key_provenance(a, label="t").tree_listing_digest \
        == cbom.build_cbom(b, label="t").tree_listing_digest


# ---------------------------------------------------------------- an output that cannot be written stops the run first
@pytest.mark.parametrize("module", ["no_egress_auditor", "cbom", "sbom"])
@pytest.mark.parametrize("where", ["key", "lock", "folder", "twice"])
def test_an_output_on_the_key_a_folder_or_another_output_is_refused_before_signing(tmp_path, module, where):
    _write(tmp_path / "t", "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    key = tmp_path / "k.json"
    assert _cli("no_egress_auditor", tmp_path / "t", "--init-key", key).returncode == 0
    before = key.read_bytes()
    (tmp_path / "out").mkdir()
    target = {"key": key, "lock": Path(str(key) + ".lock"), "folder": tmp_path / "out",
              "twice": tmp_path / "r.json"}[where]
    md = tmp_path / "r.json" if where == "twice" else tmp_path / "r.md"
    r = _cli(module, tmp_path / "t", "--key", key, "--json", target, "--md", md)
    assert r.returncode == 2 and r.stderr.startswith("error:"), r.stderr
    assert key.read_bytes() == before                 # no one-time key was spent
    ok = _cli(module, tmp_path / "t", "--key", key, "--json", tmp_path / "ok.json", "--md", tmp_path / "ok.md")
    assert ok.returncode in (0, 1) and key.read_bytes() != before


@pytest.mark.parametrize("serial,code", [
    ("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", 0), ("3e671687-395b-41f5-a30f-a58921a69b79", 2),
    ("urn:uuid:not-a-uuid", 2), ("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79\n", 2)])
def test_a_serial_number_is_a_uuid_urn(tmp_path, serial, code):
    _write(tmp_path / "t", "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    _write(tmp_path / "t", "requirements.txt", "requests==2.31.0\n")
    assert _cli("cbom", tmp_path / "t", "--json", tmp_path / "c.json").returncode in (0, 1)
    r = _cli("cyclonedx", tmp_path / "c.json", "--serial", serial, "--out", tmp_path / "c.cdx.json")
    assert r.returncode == code, r.stderr
    r = _cli("sbom", tmp_path / "t", "--serial", serial, "--json", tmp_path / "s.json", "--cdx", tmp_path / "s.cdx")
    assert r.returncode == (code or r.returncode) and (r.returncode != 2 or "--serial" in r.stderr)
    if code == 0:
        assert json.loads((tmp_path / "c.cdx.json").read_text(encoding="utf-8"))["serialNumber"] == serial


# ---------------------------------------------------------------- SARIF: one alert per finding, at a place that exists
def test_identical_findings_on_two_lines_are_two_alerts_and_the_first_keeps_its_fingerprint(tmp_path):
    from entrovouch.sarif import _fingerprint, to_sarif
    _write(tmp_path, "a.py", "import requests\nrequests.get('https://example.org')\nx = 1\nrequests.get('https://example.org')\n")
    rep = asdict(audit(tmp_path, label="t"))
    results = to_sarif(rep)["runs"][0]["results"]
    calls = [r for r in results if r["ruleId"] == "network-call"]
    prints = {r["partialFingerprints"]["entrovouchFindingV1"] for r in calls}
    assert len(calls) == 2 and len(prints) == 2
    first = min(calls, key=lambda r: r["locations"][0]["physicalLocation"]["region"]["startLine"])
    assert first["partialFingerprints"]["entrovouchFindingV1"] == _fingerprint("network-call", "a.py",
                                                                               first["message"]["text"])
    # a line inserted above both moves neither fingerprint
    _write(tmp_path, "a.py", "# a comment\nimport requests\nrequests.get('https://example.org')\nx = 1\n"
                             "requests.get('https://example.org')\n")
    moved = to_sarif(asdict(audit(tmp_path, label="t")))["runs"][0]["results"]
    assert {r["partialFingerprints"]["entrovouchFindingV1"] for r in moved if r["ruleId"] == "network-call"} == prints


def test_a_notebook_result_names_its_cell_and_a_whole_file_result_has_no_line(tmp_path):
    from entrovouch.sarif import to_sarif
    _write(tmp_path, "n.ipynb", json.dumps(_cells(["x = 1\n"], ["import requests\n", "requests.get('https://example.org')\n"])))
    _write(tmp_path, "bad.py", "def (:\n")
    results = to_sarif(asdict(audit(tmp_path, label="t")))["runs"][0]["results"]
    nb = [r for r in results if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "n.ipynb"]
    assert nb and all("region" not in r["locations"][0]["physicalLocation"] for r in nb)
    assert {r["properties"]["notebookCell"] for r in nb} == {2}
    bad = [r for r in results if r["ruleId"] == "unparseable-source"]
    assert bad and bad[0]["locations"][0]["physicalLocation"].get("region", {}).get("startLine") in (None, 1)
    py = [r for r in results if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bad.py"]
    assert py


# ---------------------------------------------------------------- a name that is not UTF-8 is printed, not a crash
def test_a_file_name_that_is_not_utf8_is_written_and_printed_escaped(tmp_path):
    from entrovouch._cli import write_text
    name = "caf\udce9.py"                      # how Python holds the Latin-1 name `café.py` read on Linux
    write_text(tmp_path / "r.md", f"| {name} |\n")
    assert (tmp_path / "r.md").read_text(encoding="utf-8") == "| caf\\udce9.py |\n"
    r = subprocess.run([sys.executable, "-c", "import sys\nfrom entrovouch._cli import run\n"
                        "sys.exit(run(lambda: print('caf\\udce9.py') or 0))"],
                       cwd=REPO, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 and "caf\\udce9.py" in r.stdout and not r.stderr


# ---------------------------------------------------------------- where a command starts, and what runs Python
def _script_kinds(root: Path) -> dict[int, str]:
    return {f["line"]: f["kind"] for f in audit(root, label="t").findings if f["file"] == "a.sh"}


def test_commands_behind_wrappers_with_values_busybox_and_a_single_ampersand_run(tmp_path):
    _write(tmp_path, "a.sh", (
        "sudo -u deploy curl -O https://example.org/a\n"
        "busybox wget https://example.org/b\n"
        "make build & wget https://example.org/c\n"
        "git lfs pull\n"
        "doas -u www wget https://example.org/d\n"
        "git lfs install\n"
        "ls 2>&1 | grep curl\n"
        "echo done &> log.txt\n"
        "grep -e curl -e wget notes.txt\n"))
    assert _script_kinds(tmp_path) == {1: "script-network-command", 2: "script-network-command",
                                       3: "script-network-command", 4: "script-network-command",
                                       5: "script-network-command", 9: "script-network-word"}


def test_a_windows_start_with_a_slash_option_runs_its_program(tmp_path):
    _write(tmp_path, "b.cmd", "start /b curl https://example.org/e\nstart /b notepad readme.txt\n")
    found = [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings]
    assert found == [(1, "script-network-command")]


@pytest.mark.parametrize("bang", ["#!/usr/bin/env pypy3", "#!/usr/bin/env -S uv run --script", "#!/usr/bin/python3"])
def test_a_pypy_or_uv_run_script_is_python(tmp_path, bang):
    _write(tmp_path, "tool", f"{bang}\nimport requests\nrequests.get('https://example.org')\n")
    _write(tmp_path / "s", "tool", "#!/bin/sh\nimport requests\n")       # a shell script with that text is not
    assert {f["kind"] for f in audit(tmp_path, label="t").findings} >= {"network-import", "network-call"}
    assert "network-import" not in {f["kind"] for f in audit(tmp_path / "s", label="t").findings}


@pytest.mark.parametrize("name", [".travis.yml", ".drone.yml", "appveyor.yml", "cloudbuild.yaml", "action.yml",
                                  ".buildkite/pipeline.yml", "buildspec.yml"])
def test_more_pipeline_files_are_read_as_pipelines(tmp_path, name):
    _write(tmp_path, name, "steps:\n  - name: fetch with curl\n    run: curl -sSf https://example.org/i.sh\n")
    _write(tmp_path / "plain", name.replace("/", "_").lstrip(".") + ".txt", "run: curl -sSf https://example.org\n")
    found = [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings if f["file"] == name]
    assert found == [(3, "script-network-command")]
    assert not audit(tmp_path / "plain", label="t").findings


def test_travis_retry_and_wait_are_wrappers(tmp_path):
    _write(tmp_path, ".travis.yml", "install: travis_retry pip install tox\nscript:\n  - travis_wait 30 pip install big\n"
                                    "  - echo travis_retry curl\n")
    assert [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings] == [
        (1, "script-network-command"), (3, "script-network-command")]


# ---------------------------------------------------------------- armour in any text file; a namespace that is a URI
_ARMOUR = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
           + "-----END RSA PRIVATE KEY-----\n")


@pytest.mark.parametrize("name", ["server_test.go", "src/tls.rs", "docs/setup.md", "Fixtures.java", "key.xml"])
def test_private_key_armour_with_a_body_is_found_in_any_text_file(tmp_path, name):
    _write(tmp_path, name, "// a test fixture\nconst k = `\n" + _ARMOUR + "`\n")
    _write(tmp_path / "doc", name, "The file starts with -----BEGIN RSA PRIVATE KEY----- and ends with the END line.\n")
    found = key_provenance.scan_key_provenance(tmp_path, label="t").findings
    assert [(f["file"], f["line"], f["kind"]) for f in found] == [(name, 3, "key-file-in-tree")]
    # armour named in prose, with no key body, is not a key
    assert key_provenance.scan_key_provenance(tmp_path / "doc", label="t").findings == []


def test_armour_inside_a_file_with_nul_bytes_is_still_found(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\n" + _ARMOUR.encode())
    (tmp_path / "plain.bin").write_bytes(b"\x00\x01\x02 no key here")
    rep = key_provenance.scan_key_provenance(tmp_path, label="t")
    assert [(f["file"], f["kind"]) for f in rep.findings] == [("blob.bin", "key-file-in-tree")]
    assert rep.files_scanned == 2


@pytest.mark.parametrize("namespace,ok", [
    ("https://example.com", True), ("https://xn--exmple-cua.com/p", True), ("https://a.example:8080/x?y#z", True),
    ("https://exämple.com", False), ("https://example.com/ü", False), ("https://user@host.example", False),
    ("https://-bad-.example", False), ("https://example.com/a b", False)])
def test_the_csaf_namespace_is_an_ascii_uri(tmp_path, namespace, ok):
    from entrovouch.csaf import to_csaf
    _write(tmp_path / "t", "a.py", "import hashlib\nhashlib.md5(b'x')\n")
    c = asdict(cbom.build_cbom(tmp_path / "t", label="t"))
    if ok:
        assert to_csaf(c, publisher_name="X", publisher_namespace=namespace)["document"]["publisher"]["namespace"] \
            == namespace
    else:
        with pytest.raises(ValueError):
            to_csaf(c, publisher_name="X", publisher_namespace=namespace)


# ---------------------------------------------------------------- Python handed to an interpreter from a script
def test_python_passed_with_dash_c_is_checked_as_python_where_a_command_starts(tmp_path):
    _write(tmp_path, "a.sh", "\n".join([
        """python3 -c "import urllib.request; urllib.request.urlopen('https://example.org/x')\"""",
        """python -W ignore -c 'import socket; socket.create_connection(("example.org", 80))'""",
        """python -c "import sys; print(sys.version)\"""",
        """echo python -c "import requests\"""",
        """sudo -u app python3 -c "import ftplib\"""",
        """python -m pip install -c constraints.txt requests""",
        """python -c "print('$HOME')\"""",
    ]) + "\n")
    found = [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings]
    assert found == [(1, "network-import"), (1, "network-call"), (2, "network-import"), (2, "network-call"),
                     (5, "network-import"), (6, "script-network-command")]


def test_a_python_here_document_is_checked_as_python_at_its_own_lines(tmp_path):
    _write(tmp_path, "a.sh", "python - <<'PY'\nimport requests\nrequests.get('https://example.org/y')\nPY\n"
                             "python3 <<-EOF\n\timport smtplib\nEOF\n"
                             "cat <<EOF\nimport requests is only text here\nEOF\n")
    found = [(f["line"], f["kind"], f["detail"].split(":")[0]) for f in audit(tmp_path, label="t").findings]
    assert found == [(2, "network-import", "Python read from a here-document"),
                     (3, "network-call", "Python read from a here-document"),
                     (6, "network-import", "Python read from a here-document")]


def test_inline_python_in_a_pipeline_step_is_checked(tmp_path):
    _write(tmp_path, ".github/workflows/ci.yml",
           "jobs:\n  t:\n    steps:\n      - run: python -c \"import requests; requests.get('https://example.org/z')\"\n"
           "      - name: python -c \"import requests\"\n")
    assert [(f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings] == [
        (4, "network-import"), (4, "network-call")]

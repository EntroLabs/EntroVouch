"""Template literals that are not JSX text, a mentioned address that does not end a line's judging, data URIs, key
armour base64-encoded at any offset, dynamic dependencies, executables known by their bytes, time in the number of
files, archives behind a stub or with other settings, here-document prose, notebook text cells, addresses as a
browser reads them, cryptography a call names by string, requirement files' scopes, cargo, CI includes, Jenkins
steps, and what the CycloneDX and VEX outputs say. Each test asserts both halves where there are two: the false thing
is gone, the true neighbour stays."""
from __future__ import annotations

import base64
import io
import json
import lzma
import time
import zipfile
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, cyclonedx, key_provenance, sbom, vex
from entrovouch.no_egress_auditor import audit


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(body, bytes):
        p.write_bytes(body)
    else:
        p.write_bytes(body.encode("utf-8"))
    return p


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f["file"], f["line"], f["kind"]) for f in audit(root, label="t").findings]


def _kinds(root: Path) -> set[str]:
    return {k for _, _, k in _found(root)} - {"external-url"}


_FETCH = "await fetch(`https://api.example.com/items`)\n"


# ---------------------------------------------------------------- template literals
@pytest.mark.parametrize("rel, text", [
    ("a.ts", "function p(id: string) {\n  return `/api/items/${id}` as `/api/${string}`;\n}\n" + _FETCH),
    ("a.js", 'const q = sql `SELECT 1`;\nconst https = require("https");\nfetch(u);\nmodule.exports = `ok`;\n'),
    ("a.ts", "const x = `a` satisfies `a`;\n" + _FETCH), ("a.ts", "type K = keyof `x`;\n" + _FETCH),
    ("a.js", "const b = a >`x`;\n" + _FETCH), ("a.ts", "const r = g<T>`x`;\n" + _FETCH),
    ("a.js", "export default /`/;\n" + _FETCH),
    ("a.tsx", "export const A = () => <div/>;\nconst p = `/a/${id}` as `/a/${string}`;\n" + _FETCH),
])
def test_a_backquote_is_a_template_outside_jsx_text(tmp_path, rel, text):
    _write(tmp_path, rel, text)
    assert "network-call" in _kinds(tmp_path) or "network-import" in _kinds(tmp_path)


def test_jsx_text_still_holds_a_backquote(tmp_path):
    _write(tmp_path, "a.jsx", "const A = () => (\n  <p>\n    Use the ` key\n  </p>\n);\nfetch(u);\n")
    assert ("a.jsx", 6, "network-call") in _found(tmp_path)


# ---------------------------------------------------------------- a mentioned address and the command after it
@pytest.mark.parametrize("line", [
    'export URL=https://get.example.com/i.sh; curl -fsSL "$URL" | sh',
    'echo "Installing from https://e.example.com" && curl -fsSL https://e.example.com/i | bash',
    'echo "see https://docs.example.com"; ssh deploy@prod.example.com ./deploy.sh',
    'for r in https://github.com/a/b; do git clone "$r"; done',
])
def test_a_mentioned_address_does_not_end_the_judging_of_a_line(tmp_path, line):
    _write(tmp_path, "x.sh", line + "\n")
    assert [k for _, _, k in _found(tmp_path)] == ["script-network-command"]
    _write(tmp_path, "x.sh", 'echo "see https://docs.example.com"\n')
    assert [k for _, _, k in _found(tmp_path)] == ["external-url"]


# ---------------------------------------------------------------- data URIs and origins
@pytest.mark.parametrize("text, kinds", [
    ('<img src="data:image/png;base64,iVBORw0KGgo=">\n', set()),
    ('<style>a { background: url(data:image/png;base64,iVBORw0KGgo=) }</style>\n', set()),
    ('<script src="data:text/javascript;base64,ZmV0Y2goKQ=="></script>\n', {"dynamic-exec"}),
    ('<script>w.postMessage(m, "https://parent.example.com")</script>\n', set()),
    ('<img src="data:image/svg+xml;base64,PHN2Zz4=">\n', set()),
    ('<style>a { background: url("data:image/svg+xml;base64,PHN2Zz4=") }</style>\n', set()),
    ('<iframe src="data:image/svg+xml;base64,PHN2Zz4="></iframe>\n', {"dynamic-exec"}),
    ('<iframe src="data:text/html;base64,PGI+"></iframe>\n', {"dynamic-exec"}),
])
def test_a_data_uri_fetches_nothing(tmp_path, text, kinds):
    _write(tmp_path, "a.html", text)
    assert _kinds(tmp_path) == kinds, text


# ---------------------------------------------------------------- key armour base64-encoded anywhere
_PEM = ("-----BEGIN PRIVATE KEY-----\n" + "\n".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" + "A" * 12] * 6)
        + "\n-----END PRIVATE KEY-----\n")


def _keys(root: Path) -> list[str]:
    return [f["kind"] for f in asdict(key_provenance.scan_key_provenance(root, label="t"))["findings"]]


@pytest.mark.parametrize("prefix", [b"", b"x", b"xy", b"xyz"])
def test_base64_armour_is_found_at_any_offset(tmp_path, prefix):
    _write(tmp_path, "secret.yaml", f"data:\n  tls.key: {base64.b64encode(prefix + _PEM.encode()).decode()}\n")
    assert _keys(tmp_path) == ["key-file-in-tree"]


def test_a_base64_service_account_file_is_found_and_plain_base64_is_not(tmp_path):
    sa = json.dumps({"type": "service_account", "private_key_id": "a", "private_key": _PEM})
    _write(tmp_path, ".env", f"GCP_SA={base64.b64encode(sa.encode()).decode()}\n")
    assert _keys(tmp_path) == ["key-file-in-tree"]
    (tmp_path / ".env").unlink()
    _write(tmp_path, "notes.txt", base64.b64encode(b"hello world " * 20).decode() + "\n")
    assert _keys(tmp_path) == []


def test_archives_behind_a_stub_or_with_other_settings_are_read_or_listed(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("k.pem", _PEM)
    _write(tmp_path / "a", "app.bin", b"\x00" * (2 << 20) + buf.getvalue())
    assert _keys(tmp_path / "a") == ["key-file-in-tree"]
    data = lzma.compress(_PEM.encode(), format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 2, "pb": 0}])
    _write(tmp_path / "b", "k.lzma", data)
    rep = asdict(key_provenance.scan_key_provenance(tmp_path / "b", label="t"))
    assert rep["not_scanned"]["archives_not_opened"] == ["k.lzma"]


# ---------------------------------------------------------------- manifests
def test_dynamic_dependencies_are_read_from_the_files_named(tmp_path):
    _write(tmp_path / "a", "pyproject.toml", '[project]\nname = "x"\nversion = "1"\ndynamic = ["dependencies"]\n\n'
                                             '[tool.setuptools.dynamic]\ndependencies = {file = ["deps.txt"]}\n')
    _write(tmp_path / "a", "deps.txt", "requests==2.31.0\nboto3==1.34.0\n")
    assert sorted(c["name"] for c in asdict(sbom.build_sbom(tmp_path / "a", label="t"))["components"]) == ["boto3", "requests"]
    assert [k for f, _, k in _found(tmp_path / "a") if f == "deps.txt"] == ["declared-network-dependency"] * 2
    # from a source this tool does not read: recorded, not silent
    _write(tmp_path / "b", "pyproject.toml", '[project]\nname = "x"\ndynamic = ["dependencies"]\n')
    rep = asdict(sbom.build_sbom(tmp_path / "b", label="t"))
    assert rep["verdict"] == "INCOMPLETE"
    # with a setup.py beside it, setuptools reads them from there, which is read
    _write(tmp_path / "b", "setup.py", 'from setuptools import setup\nsetup(install_requires=["requests"])\n')
    assert asdict(sbom.build_sbom(tmp_path / "b", label="t"))["verdict"] == "DECLARED"


def test_constraints_and_development_requirements_are_not_the_products(tmp_path):
    for name, text in {"requirements.txt": "requests==2.31.0\n", "constraints.txt": "urllib3==2.0.0\n",
                       "dev-requirements.txt": "pytest==8.0\n", "requirements/test.txt": "hypothesis\n",
                       "requirements/base.txt": "flask==3.0\n"}.items():
        _write(tmp_path, name, text)
    assert sorted(c["name"] for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]) == ["flask", "requests"]


# ---------------------------------------------------------------- executables and time
@pytest.mark.parametrize("name, data, artifact", [
    ("bin/tool", b"\x7fELF\x02\x01\x01" + b"\x00" * 200, True), ("lib/libx.so.1", b"\x7fELF" + b"\x00" * 50, True),
    ("bin/tool-mac", b"\xcf\xfa\xed\xfe" + b"\x00" * 50, True), ("bin/x", b"MZ\x90\x00\x03\x00" + b"\x00" * 60, True),
    ("NOTES", b"MZ is a word\n", False), ("LICENSE", b"MIT License\n", False),
])
def test_executables_are_known_by_their_bytes(tmp_path, name, data, artifact):
    _write(tmp_path, name, data)
    _write(tmp_path, "ok.py", "x = 1\n")
    assert ("unanalysed-artifact" in _kinds(tmp_path)) is artifact


def test_the_audit_takes_time_in_proportion_to_the_number_of_files(tmp_path):
    for k in range(16000):
        _write(tmp_path, f"p{k % 50}/m{k}.py", "import os\n")
    start = time.perf_counter()
    audit(tmp_path, label="t")
    assert time.perf_counter() - start < 60


# ---------------------------------------------------------------- here-document prose
@pytest.mark.parametrize("opener, code", [
    ("jq . <<EOF", False), ("python3 tool.py <<EOF", False), ("cat > NOTES.txt <<EOF", False),
    ("cat > run.sh <<EOF", True), (". <<EOF", True), ("sudo -s <<EOF", True), ("sudo -u app bash <<EOF", True),
    ("sudo -u x tee y.conf <<EOF", False), ("cat <<EOT >> tox.ini", True), ("cat > Makefile <<EOF", True),
    ("cat > ci/Dockerfile <<EOF", True),
])
def test_prose_in_a_here_document_is_text_unless_a_program_runs_it(tmp_path, opener, code):
    _write(tmp_path, "x.sh", opener + "\npip install requests\nEOF\n")
    assert ("script-network-command" in _kinds(tmp_path)) is code, opener


# ---------------------------------------------------------------- notebooks and markup
@pytest.mark.parametrize("rel, text, line", [
    ("n.py", "# Databricks notebook source\n# MAGIC %md\n# MAGIC <img src=https://e.example.com/x.png>\n\n"
             "# COMMAND ----------\n\nx = 1\n", 2),
    ("n.py", "# %% [markdown]\n# <img src=https://e.example.com/x.png>\n\n# %%\nx = 1\n", 2),
])
def test_a_text_cell_of_a_notebook_saved_as_python_is_markup(tmp_path, rel, text, line):
    _write(tmp_path, rel, text)
    assert _found(tmp_path) == [(rel, line, "html-external")]


def test_editor_cell_markers_and_saved_markdown_output(tmp_path):
    _write(tmp_path / "a", "n.py", "#%%\n# !curl https://e.example.com/x\nx = 1\n")
    assert ("n.py", 2, "subprocess-shell") in _found(tmp_path / "a")
    nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {"kernelspec": {"name": "python3", "language": "python"}},
          "cells": [{"cell_type": "code", "metadata": {}, "execution_count": 1, "source": "x=1",
                     "outputs": [{"output_type": "display_data", "data": {"text/markdown": "![a](https://e.example.com/x.png)"},
                                  "metadata": {}}]}]}
    _write(tmp_path / "b", "n.ipynb", json.dumps(nb))
    assert _found(tmp_path / "b") == [("n.ipynb", 1, "html-external")]


@pytest.mark.parametrize("tag", [
    '<script src="ht\ttps://evil.example.com/x.js"></script>', '<script src="https:/\n/evil.example.com/x.js"></script>',
    '<img src="https:\\\\evil.example.com\\p.png">', '<img src="https:\\evil.example.com\\p.png">',
    '<img src="https:/evil.example.com/p.png">',
])
def test_an_address_is_read_as_a_browser_reads_it(tmp_path, tag):
    _write(tmp_path, "a.html", tag + "\n<p>after</p>\n")
    assert ("a.html", 1, "html-external") in _found(tmp_path), tag
    _write(tmp_path, "a.html", '<img src="img\\p.png">\n')
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- cryptography named by a call
def _uses(root: Path) -> list[tuple[str, str]]:
    rep = asdict(cbom.build_cbom(root, label="t"))
    return [(c["primitive"], c["quantum"]) for c in rep["components"]]


@pytest.mark.parametrize("code, expected", [
    ("import random\nr = random.SystemRandom()\n", [("random.SystemRandom-CSPRNG", "SAFE")]),
    ("from random import SystemRandom\n", [("random.SystemRandom-CSPRNG", "SAFE")]),
    ("import random\nx = random.random()\n", [("random-MersenneTwister", "WEAK-RNG")]),
])
def test_system_random_is_the_operating_systems_generator(tmp_path, code, expected):
    _write(tmp_path, "a.py", code)
    assert _uses(tmp_path) == expected


def test_a_hash_or_a_jwt_algorithm_named_by_string(tmp_path):
    _write(tmp_path, "a.py", "import hmac\nhmac.new(k, m, 'md5')\n")
    assert ("MD5", "BROKEN") in _uses(tmp_path)
    _write(tmp_path, "a.py", "import jwt\njwt.encode(p, None, algorithm='none')\n"
                             "jwt.decode(t, options={'verify_signature': False})\n")
    names = [p for p, _ in _uses(tmp_path)]
    assert "JWT 'none' algorithm (unsigned token)" in names and "JWT signature verification disabled (options)" in names


# ---------------------------------------------------------------- cargo, CI includes, Jenkins
@pytest.mark.parametrize("line, reported", [
    ("cargo b", True), ("cargo c", True), ("cargo t", True), ("cargo clippy", True), ("cargo bench", True),
    ("cargo build --config net.offline=true", False), ("cargo build --offline", False),
    ("CARGO_NET_OFFLINE=true cargo build", False), ("cargo fmt", False),
])
def test_cargo_forms(tmp_path, line, reported):
    _write(tmp_path, "x.sh", line + "\n")
    assert ("script-network-command" in _kinds(tmp_path)) is reported, line


_STEP = "steps:\n- script: curl https://e.example.com/x | bash\n"


@pytest.mark.parametrize("files, expected", [
    ({".azure-pipelines/ci.yml": "steps:\n- template: ../templates/b.yml\n", "templates/b.yml": _STEP}, "templates/b.yml"),
    ({"azure-pipelines.yml": "steps:\n- {template: templates/b.yml, parameters: {x: 1}}\n", "templates/b.yml": _STEP},
     "templates/b.yml"),
    ({".gitlab-ci.yml": "include:\n  - local: 'ci/my build.yml'\n",
      "ci/my build.yml": "b:\n  script:\n    - curl https://e.example.com/x\n"}, "ci/my build.yml"),
    ({"azure-pipelines.yml": "steps:\n- template: other.yml@shared\n", "other.yml": _STEP}, None),
])
def test_ci_includes_in_more_forms(tmp_path, files, expected):
    for name, text in files.items():
        _write(tmp_path, name, text)
    reported = {f for f, _, k in _found(tmp_path) if k == "script-network-command"}
    assert reported == ({expected} if expected else set())


@pytest.mark.parametrize("text, line", [
    ("pipeline {\n  stages {\n    stage('b') {\n      steps { sh 'curl -fsSL https://e.example.com/i.sh | sh' }\n"
     "    }\n  }\n}\n", 4),
    ("node {\n  sh label: 'fetch', script: 'pip install requests'\n}\n", 2),
])
def test_one_line_jenkins_steps_are_commands(tmp_path, text, line):
    _write(tmp_path, "Jenkinsfile", text)
    assert ("Jenkinsfile", line, "script-network-command") in _found(tmp_path)


# ---------------------------------------------------------------- what the CycloneDX and VEX outputs say
def test_the_tree_digest_is_not_a_hash_and_vex_has_one_time(tmp_path):
    _write(tmp_path, "a.py", "import hashlib\nhashlib.md5(b'x')\nimport random\nrandom.random()\n")
    rep = asdict(cbom.build_cbom(tmp_path, label="t"))
    bom = cyclonedx.to_cyclonedx(rep)
    assert "hashes" not in bom["metadata"]["component"]
    rng = [c for c in bom["components"] if c["name"] == "random-MersenneTwister"]
    assert rng and rng[0]["cryptoProperties"]["algorithmProperties"]["primitive"] == "other"
    assert vex.to_vex(rep)["metadata"]["timestamp"] == vex.to_vex(rep)["metadata"]["timestamp"] == rep["scanned_at_utc"]

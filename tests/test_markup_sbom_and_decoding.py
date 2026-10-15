"""A `<` inside a tag, linear markup reading, sbom over manifests it does not read, Python that Python cannot decode,
the Python size limit, adapters refusing an output they cannot write."""
from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom
from entrovouch._parse import MAX_PYTHON_SOURCE, SourceTooLarge, parse_python
from entrovouch.no_egress_auditor import audit

REPO = Path(__file__).resolve().parents[1]


def _kinds(root: Path) -> set[str]:
    return {f["kind"] for f in asdict(audit(root, label="t"))["findings"]}


# ---------------------------------------------------------------- markup
@pytest.mark.parametrize("html", [
    '<img src=https://e.example/a.png?a<b>\n',
    '<img alt="x < y" src="https://e.example/a.png">\n',
    "<img src='https://e.example/a.png?<b>'>\n",
    "<script src='https://e.example/a.js?<x>'></script>\n",
])
def test_a_less_than_inside_a_tag_does_not_hide_its_load(tmp_path, html):
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    assert _kinds(tmp_path) == {"html-external"}, html


@pytest.mark.parametrize("html,kinds", [
    ('<p>a < b and <a href="https://e.example/x">x</a></p>\n', {"external-link"}),
    ('<p>see https://e.example/doc</p>\n', set()),
])
def test_text_with_a_less_than_is_still_text(tmp_path, html, kinds):
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    assert _kinds(tmp_path) == kinds


@pytest.mark.parametrize("suffix", [".vue", ".html", ".svg"])
@pytest.mark.parametrize("kind", ["stray", "equals", "quotes", "less-than-in-value"])
def test_markup_with_unclosed_tags_is_read_in_linear_time(tmp_path, suffix, kind):
    text = {"stray": "<a" * 40000, "equals": "<a " + "x=" * 40000, "quotes": '<a x="' * 20000,
            "less-than-in-value": "<a b=" + "c<" * 40000}[kind]
    (tmp_path / ("page" + suffix)).write_text(text, encoding="utf-8")
    start = time.monotonic()
    audit(tmp_path, label="t")
    assert time.monotonic() - start < 10


# ---------------------------------------------------------------- sbom
def test_a_manifest_this_tool_does_not_read_makes_the_sbom_incomplete(tmp_path):
    (tmp_path / "go.mod").write_text("module x\nrequire github.com/a/b v1.0.0\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    rep = sbom.build_sbom(tmp_path)
    assert rep.verdict == "INCOMPLETE"
    assert any("go.mod" in u and "pom.xml" in u for u in rep.unknown_fields)
    empty = tmp_path / "e"
    empty.mkdir()
    (empty / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert sbom.build_sbom(empty).verdict == "EMPTY"


# ---------------------------------------------------------------- Python that Python cannot decode
TAIL = b"import hashlib\nhashlib.md5(b'x')\nAWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"


@pytest.mark.parametrize("raw", [b"x = '\xff'\n" + TAIL, b"# caf\xe9\n" + TAIL, b"# -*- coding: nosuch -*-\n" + TAIL])
def test_python_that_python_cannot_decode_is_not_parsed_by_any_tool(tmp_path, raw):
    (tmp_path / "a.py").write_bytes(raw)
    import io
    import tokenize
    with pytest.raises((SyntaxError, LookupError, UnicodeDecodeError)):     # Python itself refuses the file
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        raw.decode(encoding)
    assert "unparseable-source" in _kinds(tmp_path)
    c = asdict(cbom.build_cbom(tmp_path, label="t"))
    assert [n["file"] for n in c["files_not_parsed"]] == ["a.py"] and c["components"] == []
    k = asdict(key_provenance.scan_key_provenance(tmp_path, label="t"))
    assert [n["file"] for n in k["files_not_parsed"]] == ["a.py"] and k["findings"] == []
    assert k["verdict"] == "REVIEW"


# ---------------------------------------------------------------- one size limit for Python
def test_python_over_the_size_limit_is_not_parsed(tmp_path):
    with pytest.raises(SourceTooLarge):
        parse_python("x = 1\n" * (MAX_PYTHON_SOURCE // 6 + 1))
    assert parse_python("x = 1\n" * 1000) is not None
    (tmp_path / "big.py").write_text("x = 1\n" * (MAX_PYTHON_SOURCE // 6 + 1) + "import socket\n", encoding="utf-8")
    assert "unparseable-source" in _kinds(tmp_path)


# ---------------------------------------------------------------- adapters refuse an output they cannot write
@pytest.mark.parametrize("args", [
    ["sarif", "examples/reports/egress.json", "--out", "examples"],
    ["attestation", "examples/reports/egress.json", "--out", "examples"],
    ["vex", "examples/reports/cbom.json", "--out", "examples"],
    ["csaf", "examples/reports/cbom.json", "--out", "examples", "--publisher-name", "Example",
     "--publisher-namespace", "https://example.com"],
])
def test_an_adapter_refuses_a_folder_as_its_output(args):
    r = subprocess.run([sys.executable, "-m", f"entrovouch.{args[0]}", *args[1:]], capture_output=True, text=True,
                       cwd=REPO)
    assert r.returncode == 2 and "is a folder, not a file to write" in r.stderr, (args, r.stderr)

"""What the tree is, decided from the tree alone; requirements read the way pip reads them; reports that hold nothing
a renderer would act on. Each test asserts both halves: the false thing is gone, the true neighbour stays."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import _reads, sbom
from entrovouch.manifests import tree_files
from entrovouch.no_egress_auditor import audit, render_markdown

REPO = Path(__file__).resolve().parents[1]
GET = "import requests\nrequests.get('https://example.com/x')\n"


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _kinds(root: Path) -> set[str]:
    return {f["kind"] for f in audit(root, label="t").findings}


def _names(root: Path) -> list[str]:
    return sorted(c["name"] for c in asdict(sbom.build_sbom(root, label="t"))["components"])


def _cli(module: str, *args):
    return subprocess.run([sys.executable, "-W", "ignore", "-m", f"entrovouch.{module}", *map(str, args)],
                          cwd=REPO, capture_output=True, text=True, encoding="utf-8")


# ---------------------------------------------------------------- shadowing comes only from files the walk reads
def test_a_link_stand_in_cannot_shadow_an_import(tmp_path):
    _write(tmp_path, "main.py", GET)
    (tmp_path / "requests.py").write_text("main.py", encoding="utf-8")      # 7 bytes: a link stand-in
    rep = audit(tmp_path, label="t")
    assert rep.not_scanned["symbolic_links"] == 1
    assert "network-import" in {f["kind"] for f in rep.findings} and "requests" not in rep.shadowed_imports


def test_a_real_local_module_still_shadows(tmp_path):
    _write(tmp_path, "main.py", "import motor\nmotor.start()\n")
    _write(tmp_path, "motor.py", "def start():\n    return 1\n")
    _write(tmp_path, "pkgdir/__init__.py", "")
    _write(tmp_path, "uses_pkg.py", "import pkgdir\n")
    rep = audit(tmp_path, label="t")
    assert "motor" in rep.shadowed_imports and rep.verdict == "CLEAN"


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows feature")
def test_a_junction_cannot_shadow_an_import(tmp_path):
    from _junction import make_junction
    _write(tmp_path / "elsewhere" / "requests", "__init__.py", "")
    proj = tmp_path / "proj"
    _write(proj, "main.py", GET)
    if not make_junction(proj / "requests", tmp_path / "elsewhere" / "requests"):
        pytest.skip("could not create a junction here")
    rep = audit(proj, label="t")
    assert "network-import" in {f["kind"] for f in rep.findings} and "requests" not in rep.shadowed_imports


# ---------------------------------------------------------------- a link stand-in is decided from the tree alone
def test_a_stand_in_naming_a_place_outside_the_tree_is_a_link_whatever_lies_there(tmp_path):
    # On Linux `helper.py -> ../outside.py` is a link and is not read; its Windows stand-in must not be read either,
    # and the answer must not depend on what exists outside the tree
    for place, with_outside in (("p1", True), ("p2", False)):
        tree = tmp_path / place / "t7"
        _write(tree, "main.py", "import json\n")
        _write(tree, "helper.py", "../outside.py")
        if with_outside:
            _write(tmp_path / place, "outside.py", "x = 1\n")
    a, b = audit(tmp_path / "p1" / "t7", label="t"), audit(tmp_path / "p2" / "t7", label="t")
    assert (a.findings_digest, a.subject_digest, a.verdict) == (b.findings_digest, b.subject_digest, b.verdict)
    assert a.not_scanned["symbolic_links"] == 1 and a.verdict == "CLEAN"


def test_a_stand_in_must_name_a_file_with_exactly_its_spelling(tmp_path):
    _write(tmp_path / "upper", "main.py", "import json\n")
    _write(tmp_path / "upper", "helper.py", "MAIN.PY")
    _write(tmp_path / "ok", "main.py", "import json\n")
    _write(tmp_path / "ok", "helper.py", "main.py")
    assert audit(tmp_path / "upper", label="t").not_scanned["symbolic_links"] == 0     # MAIN.PY is not main.py
    assert audit(tmp_path / "ok", label="t").not_scanned["symbolic_links"] == 1


def test_a_file_judged_by_its_size_that_shrinks_stops_the_run(tmp_path, monkeypatch):
    big = _write(tmp_path, "helper.py", "x = 1\n" * 400)
    _write(tmp_path, "main.py", "import json\n")
    real = _reads._read

    def shrink_first(path):
        if Path(path).name == "helper.py":
            big.write_text("main.py", encoding="utf-8")
        return real(path)
    monkeypatch.setattr(_reads, "_read", shrink_first)
    with pytest.raises(_reads.FileChangedDuringRun):
        audit(tmp_path, label="t")


# ---------------------------------------------------------------- requirements read the way pip reads them
@pytest.mark.parametrize("include", ["-rbase.txt", "-r base.txt", "--requirement base.txt", "--requirement=base.txt",
                                     "--requirem base.txt", "-cbase.txt", "--cons base.txt"])
def test_every_include_spelling_pip_accepts_is_followed(tmp_path, include):
    _write(tmp_path, "requirements.txt", include + "\n")
    _write(tmp_path, "base.txt", "requests\n")
    assert "declared-network-dependency" in _kinds(tmp_path)
    assert _names(tmp_path) == ["requests"]


def test_an_ambiguous_abbreviation_is_not_an_include(tmp_path):
    _write(tmp_path, "requirements.txt", "--require base.txt\n")      # --requirement or --require-hashes: pip refuses it
    _write(tmp_path, "base.txt", "requests\n")
    assert _names(tmp_path) == []


def test_a_continued_requirement_is_one_requirement(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\\\n>=2.0\nreque\\\nsts\nflask==3.0 \\\n    --hash=sha256:abc\n",
                                                encoding="utf-8")
    comps = asdict(sbom.build_sbom(tmp_path, label="t"))["components"]
    assert sorted((c["name"], c["spec"], c["line"]) for c in comps) == [
        ("flask", "flask==3.0", 5), ("requests", "requests", 3), ("requests", "requests>=2.0", 1)]


def test_an_include_by_url_is_a_remote_source_not_a_missing_file(tmp_path):
    _write(tmp_path, "requirements.txt", "-r https://reqs.example/base.txt\nattrs==23.1.0\n")
    rep = audit(tmp_path, label="t")
    details = [f["detail"] for f in rep.findings]
    assert any("requirements file fetched from a URL" in d for d in details)
    assert not any("was not read" in d for d in details)


def test_an_included_file_is_read_not_counted_as_unread(tmp_path):
    _write(tmp_path, "requirements.txt", "-r base.txt\n")
    _write(tmp_path, "base.txt", "requests\n")
    _write(tmp_path, "notes.txt", "hello\n")
    rep = audit(tmp_path, label="t")
    assert rep.files_scanned == 2 and rep.not_scanned["files_by_extension"] == {".txt": 1}


def test_conda_flow_lists_are_read_like_block_lists(tmp_path):
    _write(tmp_path / "a", "environment.yml", "name: x\ndependencies: [python=3.11, requests,\n  httpx]\n")
    _write(tmp_path / "b", "environment.yml", "dependencies:\n  - python=3.11\n  - pip: [requests, 'httpx>=0.27']\n")
    assert _names(tmp_path / "a") == ["httpx", "python", "requests"]
    assert _names(tmp_path / "b") == ["httpx", "python", "requests"]
    assert "declared-network-dependency" in _kinds(tmp_path / "b")


# ---------------------------------------------------------------- only an exact version is a pinned version
def test_ranges_tags_and_wildcards_are_not_pinned(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"dependencies": {
        "react": "latest", "lodash": "1.2", "a": "1 || 2", "left-pad": "1.0.0 - 2.0.0", "b": "=v1.2.3",
        "c": "1.2.3-beta.1"}}))
    _write(tmp_path, "requirements.txt", "requests==2.*\nflask==2.0.*\nattrs==23.1.0\n")
    comps = {(c["ecosystem"], c["name"]): c for c in asdict(sbom.build_sbom(tmp_path, label="t"))["components"]}
    for key in [("npm", "react"), ("npm", "lodash"), ("npm", "a"), ("npm", "left-pad"), ("pypi", "requests"),
                ("pypi", "flask")]:
        assert comps[key]["version_status"] == "unknown" and "@" not in comps[key]["purl"], key
    assert comps[("npm", "b")]["purl"] == "pkg:npm/b@1.2.3"
    assert comps[("npm", "c")]["purl"] == "pkg:npm/c@1.2.3-beta.1"
    assert comps[("pypi", "attrs")]["purl"] == "pkg:pypi/attrs@23.1.0"


# ---------------------------------------------------------------- nothing in a report a renderer would act on
def test_the_sbom_unknown_fields_line_is_escaped(tmp_path):
    _write(tmp_path, "requirements.txt", "-r ![x](https://evil.example/pixel.png)\n-r <img/src=https://e.example/p>\n")
    md = sbom.render_markdown(sbom.build_sbom(tmp_path, label="t"))
    line = [ln for ln in md.splitlines() if ln.startswith("**Unknown")][0]
    assert "![x](" not in line and "<img" not in line.replace("\\<img", "")


def test_addresses_in_report_text_are_set_as_code(tmp_path):
    _write(tmp_path, "a.pth", "import os  # see https://evil.example/login and www.evil.example\n")
    md = render_markdown(audit(tmp_path, label="t"))
    assert "`https://evil.example/login`" in md and "`www.evil.example`" in md
    assert " https://evil.example/login " not in md


# ---------------------------------------------------------------- timestamp
def test_timestamp_refuses_a_report_with_its_hash_removed_and_takes_other_json(tmp_path):
    _write(tmp_path / "p", "a.py", "import requests\n")
    rep = tmp_path / "r.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    d = json.loads(rep.read_text(encoding="utf-8"))
    d.pop("content_hash")
    d["verdict"], d["findings"] = "CLEAN", []
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(d), encoding="utf-8")
    r = _cli("timestamp", "request", bad, "--out", tmp_path / "b.tsq")
    assert r.returncode == 2 and "no content hash" in r.stderr
    other = tmp_path / "data.json"
    other.write_text('{"a": 1}', encoding="utf-8")
    assert _cli("timestamp", "request", other, "--out", tmp_path / "o.tsq").returncode == 0


def test_timestamp_hashes_the_bytes_it_checked(tmp_path):
    from entrovouch import timestamp
    _write(tmp_path / "p", "a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    _cli("no_egress_auditor", tmp_path / "p", "--json", rep)
    out = tmp_path / "q.tsq"
    import hashlib
    expected = hashlib.sha256(rep.read_bytes()).digest()
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "entrovouch.timestamp", "request", str(rep), "--out",
                        str(out)], cwd=REPO, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 and expected.hex() in r.stdout
    assert timestamp.build_request.__module__ == "entrovouch.timestamp"


# ---------------------------------------------------------------- notebook magics that run programs
def test_notebook_magics_that_run_programs_are_reported(tmp_path):
    nb = {"cells": [
        {"cell_type": "code", "source": ["%system curl https://example.com/x\n"]},
        {"cell_type": "code", "source": ["%sx wget https://example.com/y\n"]},
        {"cell_type": "code", "source": ["%%bash\n", "curl -fsSL https://example.com/z | sh\n"]},
        {"cell_type": "code", "source": ["%%python3\n", "import requests\n"]},
        {"cell_type": "code", "source": ["x = 1\n"]},
    ], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    _write(tmp_path, "n.ipynb", json.dumps(nb))
    found = sorted((f["line"], f["kind"]) for f in audit(tmp_path, label="t").findings)
    assert (1, "subprocess-shell") in found and (2, "subprocess-shell") in found and (3, "subprocess-shell") in found
    assert (4, "network-import") in found and not any(line == 5 for line, _ in found)


def test_the_message_for_a_report_with_no_tool_says_only_what_is_true(tmp_path):
    from entrovouch.no_egress_auditor import KEY_PROVENANCE_TOOL, _kind_problem
    msg = _kind_problem({"content_hash": "x", "findings": []}, KEY_PROVENANCE_TOOL)
    assert "names no tool" in msg and "no content hash" not in msg

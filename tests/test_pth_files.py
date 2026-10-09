"""`.pth` files: the lines Python's `site` module executes are audited as Python.

The first test pins the behaviour of `site` itself, so the rest of the file rests on
what the interpreter does and not on a description of it.
"""
import site
import sys
from dataclasses import asdict

from entrovouch.no_egress_auditor import audit
from entrovouch.sarif import to_sarif


def _kinds(report, name):
    return [(f["line"], f["kind"]) for f in report.findings if f["file"] == name]


def test_site_executes_only_lines_that_start_with_import(tmp_path):
    (tmp_path / "probe.pth").write_text(
        "import sys; sys._entrovouch_pth_probe = 'ran'\n"
        "  import sys; sys._entrovouch_pth_indented = 'ran'\n"
        "# import sys; sys._entrovouch_pth_comment = 'ran'\n",
        encoding="utf-8",
    )
    try:
        site.addpackage(str(tmp_path), "probe.pth", set())
        assert getattr(sys, "_entrovouch_pth_probe", None) == "ran"
        assert not hasattr(sys, "_entrovouch_pth_indented")
        assert not hasattr(sys, "_entrovouch_pth_comment")
    finally:
        for name in ("_entrovouch_pth_probe", "_entrovouch_pth_indented", "_entrovouch_pth_comment"):
            if hasattr(sys, name):
                delattr(sys, name)
        sys.path[:] = [p for p in sys.path if "import sys" not in p]


def test_path_only_pth_is_scanned_and_clean(tmp_path):
    (tmp_path / "paths.pth").write_text("# extra source directory\n./src\n../shared\n", encoding="utf-8")
    report = audit(tmp_path)
    assert report.verdict == "CLEAN"
    assert report.files_scanned == 1


def test_executed_line_is_reported_and_analysed(tmp_path):
    (tmp_path / "boot.pth").write_text(
        "./src\n"
        "# comment\n"
        "import base64; exec(base64.b64decode('cHJpbnQoMSk=').decode())\n",
        encoding="utf-8",
    )
    report = audit(tmp_path)
    assert report.verdict == "FINDINGS"
    assert _kinds(report, "boot.pth") == [(3, "startup-exec"), (3, "dynamic-exec")]


def test_network_import_on_an_executed_line(tmp_path):
    (tmp_path / "boot.pth").write_text(
        "import urllib.request; urllib.request.urlopen('https://example.invalid/')\n", encoding="utf-8"
    )
    kinds = [kind for _line, kind in _kinds(audit(tmp_path), "boot.pth")]
    assert kinds[0] == "startup-exec"
    assert "network-import" in kinds


def test_plain_import_line_is_startup_exec_only(tmp_path):
    (tmp_path / "hook.pth").write_text("import some_local_hook\n", encoding="utf-8")
    assert _kinds(audit(tmp_path), "hook.pth") == [(1, "startup-exec")]


def test_lines_site_does_not_execute_are_not_reported(tmp_path):
    (tmp_path / "quiet.pth").write_text(
        "  import urllib.request\n# import urllib.request\nimportlib_dir\n", encoding="utf-8"
    )
    report = audit(tmp_path)
    assert report.verdict == "CLEAN"


def test_tab_after_import_is_executed_too(tmp_path):
    (tmp_path / "tab.pth").write_text("import\tsocket\n", encoding="utf-8")
    kinds = [kind for _line, kind in _kinds(audit(tmp_path), "tab.pth")]
    assert kinds[0] == "startup-exec"


def test_binary_file_with_the_same_extension_is_reported_unread(tmp_path):
    """Model checkpoints are commonly saved as `.pth`. `site` never reads them and neither does the
    auditor: they are serialised objects, reported as content that was not analysed."""
    (tmp_path / "model.pth").write_bytes(b"PK\x03\x04" + bytes(range(256)) * 8 + b"import os\n")
    (tmp_path / "weights.pth").write_bytes(b"import os\x00" + b"\x00" * 64)   # valid text apart from the nulls
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    report = audit(tmp_path)
    assert report.files_scanned == 1
    assert [(f["file"], f["kind"]) for f in report.findings] == [
        ("model.pth", "unanalysed-artifact"), ("weights.pth", "unanalysed-artifact")]
    assert report.not_scanned["files_by_extension"] == {}


def test_a_tree_with_nothing_readable_is_not_called_clean(tmp_path):
    (tmp_path / "main.go").write_text('package main\nimport "net/http"\n', encoding="utf-8")
    report = audit(tmp_path)
    assert report.verdict == "NOT-ANALYSED"
    assert report.files_scanned == 0
    assert report.not_scanned["files_by_extension"] == {".go": 1}


def test_pth_content_is_bound_into_the_subject_digest(tmp_path):
    target = tmp_path / "boot.pth"
    target.write_text("import a_hook\n", encoding="utf-8")
    first = audit(tmp_path, label="t").subject_digest
    target.write_text("import b_hook\n", encoding="utf-8")
    assert audit(tmp_path, label="t").subject_digest != first


def test_startup_exec_has_a_sarif_rule(tmp_path):
    (tmp_path / "boot.pth").write_text("import a_hook\n", encoding="utf-8")
    sarif = to_sarif(asdict(audit(tmp_path, label="t")))
    rules = {rule["id"] for run in sarif["runs"] for rule in run["tool"]["driver"]["rules"]}
    assert "startup-exec" in rules

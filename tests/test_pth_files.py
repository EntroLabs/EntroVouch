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
    # Up to 3.14 the line must begin with `import` as written; 3.15 (PEP 829) strips it first, so an
    # indented import line runs too. The auditor reports every line any of these versions runs.
    (tmp_path / "probe.pth").write_text(
        "import sys; sys._entrovouch_pth_probe = 'ran'\n"
        "  import sys; sys._entrovouch_pth_indented = 'ran'\n"
        "# import sys; sys._entrovouch_pth_comment = 'ran'\n",
        encoding="utf-8",
    )
    try:
        site.addpackage(str(tmp_path), "probe.pth", set())
        assert getattr(sys, "_entrovouch_pth_probe", None) == "ran"
        assert hasattr(sys, "_entrovouch_pth_indented") == (sys.version_info >= (3, 15))
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
        "# import urllib.request\n  # import urllib.request\nimportlib_dir\n  ./src\n", encoding="utf-8"
    )
    report = audit(tmp_path)
    assert report.verdict == "CLEAN"


def test_an_indented_import_line_is_executed_by_python_315_and_reported(tmp_path):
    # PEP 829: 3.15 strips each line before the `import` test, so these run at start-up there.
    (tmp_path / "hook.pth").write_text(
        "./src\n  import urllib.request\n\timport os; os.getcwd()\n  # import socket\n", encoding="utf-8"
    )
    report = audit(tmp_path)
    kinds = _kinds(report, "hook.pth")
    assert (2, "startup-exec") in kinds and (3, "startup-exec") in kinds
    details = [f["detail"] for f in report.findings if f["file"] == "hook.pth" and f["kind"] == "startup-exec"]
    assert details and all("from Python 3.15 on" in d for d in details), details
    assert any(line == 2 and kind == "network-import" for line, kind in kinds)
    assert not any(line in (1, 4) for line, _kind in kinds)


def test_an_unindented_import_line_is_described_as_running_on_every_version(tmp_path):
    (tmp_path / "hook.pth").write_text("import os\n", encoding="utf-8")
    [detail] = [f["detail"] for f in audit(tmp_path).findings if f["kind"] == "startup-exec"]
    assert "3.15" not in detail and "is executed by Python's site module at every interpreter start" in detail


def test_start_file_entry_points_are_reported(tmp_path):
    # PEP 829 `.start` files: 3.15's site calls each `pkg.mod:callable` line at start-up.
    (tmp_path / "boot.start").write_text(
        "# entry points\n\nmypkg.boot:main\n  other.mod:run.now  \nnot an entry point\nmypkg.boot\n",
        encoding="utf-8",
    )
    report = audit(tmp_path)
    assert _kinds(report, "boot.start") == [(3, "startup-exec"), (4, "startup-exec")]
    assert report.files_scanned == 1
    assert ".start" not in report.not_scanned.get("files_by_extension", {})


def test_start_file_with_no_entry_points_is_clean(tmp_path):
    (tmp_path / "empty.start").write_text("# nothing to call\n\nplain words here\n", encoding="utf-8")
    report = audit(tmp_path)
    assert report.verdict == "CLEAN"
    assert report.files_scanned == 1


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


def test_start_entry_points_follow_site_rules(tmp_path):
    """`site` reads `*.start` case-sensitively, as UTF-8, and resolves names as Python identifiers."""
    (tmp_path / "boot.start").write_text("été:run\n_private.mod:go\n", encoding="utf-8")
    (tmp_path / "upper.START").write_text("mypkg.boot:main\n", encoding="utf-8")
    (tmp_path / "latin1.start").write_bytes("mypkg.boot:main\n# caf\xe9\n".encode("latin-1"))
    report = audit(tmp_path)
    assert _kinds(report, "boot.start") == [(1, "startup-exec"), (2, "startup-exec")]
    assert _kinds(report, "upper.START") == []          # site never reads it, on any system
    assert _kinds(report, "latin1.start") == []         # site skips a file that is not UTF-8


def test_a_start_file_with_a_nul_byte_is_named_as_not_analysed(tmp_path):
    """The same answer a `.pth` holding a NUL byte gets: a finding that says the file was not read."""
    (tmp_path / "boot.start").write_bytes(b"mypkg.boot:main\n\x00\n")
    (tmp_path / "boot.pth").write_bytes(b"import a\n\x00\n")
    report = audit(tmp_path)
    assert _kinds(report, "boot.start") == [(0, "unanalysed-artifact")]
    assert _kinds(report, "boot.pth") == [(0, "unanalysed-artifact")]

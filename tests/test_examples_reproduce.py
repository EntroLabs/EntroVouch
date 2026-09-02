"""The committed example reports must still be what the tool produces today.

WHY THIS EXISTS
---------------
`examples/reports/` is the demo: a prospect clones this repo, runs the tools
against `examples/sample_service/`, and compares one value against the committed
report. That only means something if the committed report cannot drift from the
tool that claims to produce it.

⭐ A published artifact nobody re-derives is a claim, not evidence. Without this
test the demo would degrade silently on the first behaviour change — and it would
degrade in the worst direction, because a prospect's honest run would then
DISAGREE with our published output and they would reasonably conclude we faked it.

WHAT IT COMPARES, and what it deliberately does not
---------------------------------------------------
· `findings_digest` — bit-identical across runs, processes and machines. Covers
  the tool, its version, the subject digest, the verdict and every finding.
  **This is the comparison.**
· `subject_digest`  — binds the report to the audited tree. Also compared.
· `content_hash`    — covers the issuance timestamp and is EXPECTED to differ on
  every run. Comparing it is the mistake the README warns readers away from, so
  this test must not make it either.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
REPORTS = REPO / "examples" / "reports"
TREE = "examples/sample_service"

#: (committed report, module, extra argv) — exit 1 means "found something", not an error.
CASES = [
    ("egress.json", "entrovouch.no_egress_auditor",
     ["--label", "entrovouch/examples/sample_service"]),
    ("cbom.json", "entrovouch.cbom", []),
    ("key_provenance.json", "entrovouch.key_provenance",
     ["--label", "entrovouch/examples/sample_service"]),
    ("sbom.json", "entrovouch.sbom",
     ["--label", "entrovouch/examples/sample_service"]),
]


def _regenerate(module: str, extra: list[str], out: Path) -> dict:
    r = subprocess.run(
        [sys.executable, "-m", module, TREE, "--json", str(out), *extra],
        cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    assert r.returncode in (0, 1), (
        f"{module} exited {r.returncode} (2 means it could not run): "
        + (r.stderr or r.stdout or "")[-600:]
    )
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name,module,extra", CASES, ids=[c[0] for c in CASES])
def test_committed_example_still_reproduces(name, module, extra, tmp_path):
    committed_path = REPORTS / name
    assert committed_path.is_file(), (
        f"{name} is missing. The demo depends on it; run examples/regenerate.py."
    )
    committed = json.loads(committed_path.read_text(encoding="utf-8"))
    fresh = _regenerate(module, extra, tmp_path / name)

    for field in ("findings_digest", "subject_digest"):
        if field not in committed and field not in fresh:
            # ⚠️ Pinned rather than skipped. `key_provenance` emits NO digest at
            # all, so the README's "re-run and compare one value" instruction does
            # not apply to it — a real asymmetry between the three tools, named in
            # examples/README.md. A silent `continue` here would have let this test
            # report success while verifying nothing for that report.
            assert name == "key_provenance.json", (
                f"{name} lost its {field}. Only key_provenance is expected to lack "
                "one; if another report drops it, the reproduce instruction stops "
                "working for that report and the docs must say so."
            )
            continue
        assert committed.get(field) == fresh.get(field), (
            f"{name}: {field} no longer reproduces.\n"
            f"  committed: {committed.get(field)}\n"
            f"  today    : {fresh.get(field)}\n"
            "The tool's behaviour changed. Re-run examples/regenerate.py and commit "
            "the result — but read the diff first: a prospect comparing against the "
            "old artifact would have concluded the report was fabricated."
        )


def test_content_hash_is_expected_to_differ():
    """The negative half, and it is the half a reader gets wrong.

    `content_hash` covers the issuance timestamp. Two honest runs produce
    different ones. The README tells readers not to compare it; this asserts the
    property that makes that advice correct, so the advice cannot quietly become
    false.
    """
    committed = json.loads((REPORTS / "egress.json").read_text(encoding="utf-8"))
    assert "content_hash" in committed, "the report no longer carries a content_hash"
    assert "findings_digest" in committed, "the report no longer carries a findings_digest"
    assert committed["content_hash"] != committed["findings_digest"], (
        "content_hash and findings_digest are equal — if they ever converge, the "
        "README's central instruction ('compare the findings digest, not the "
        "content hash') stops distinguishing anything."
    )


def test_the_fixture_actually_produces_findings():
    """A demo where every scanner comes back clean demonstrates nothing.

    The fixture carries a deliberate network import, deliberate weak primitives
    and a deliberate in-source signing key. If any of those stop being found, the
    example still 'passes' while showing a reader nothing — the failure mode this
    whole directory exists to avoid.
    """
    # The CBOM inventories `components`, not `findings` — the field differs by
    # report type, and assuming otherwise made this test fail on a healthy report.
    expected = {"egress.json": "findings",
                "cbom.json": "components",
                "key_provenance.json": "findings",
                "sbom.json": "components"}
    for name, field in expected.items():
        rep = json.loads((REPORTS / name).read_text(encoding="utf-8"))
        items = rep.get(field) or []
        assert items, (
            f"{name} contains no {field}. The fixture is built to produce them; "
            "an empty demo report is worse than no demo."
        )


def test_the_digests_printed_in_the_examples_readme_are_the_real_ones():
    """The demo's whole instruction is "compare this value". It must be current.

    ⭐ This repository already learned this once, in `test_readme_claims.py`: a
    number written by hand in prose and maintained by memory goes stale on the
    next commit, every time. Here the stale number would be worse than a wrong
    test count — a prospect following our own instructions would compare against a
    dead digest, see a mismatch, and reasonably conclude the published report was
    fabricated. That is the exact conclusion this directory exists to prevent.
    """
    import re
    readme = (REPO / "examples" / "README.md").read_text(encoding="utf-8")
    stated = set(re.findall(r"`([0-9a-f]{64})`", readme))
    assert stated, "examples/README.md no longer prints any digest to compare"

    real = set()
    for name, fields in (("egress.json", ("findings_digest", "subject_digest")),
                         ("cbom.json", ("findings_digest",)),
                         ("sbom.json", ("findings_digest",))):
        rep = json.loads((REPORTS / name).read_text(encoding="utf-8"))
        real.update(rep[f] for f in fields if f in rep)

    stale = sorted(stated - real)
    assert not stale, (
        "examples/README.md prints digest(s) that no report carries: "
        + ", ".join(stale)
        + ". Re-run examples/regenerate.py and update the table — a reader "
        "comparing against these would conclude our published report was faked."
    )
    missing = sorted(real - stated)
    assert not missing, (
        "these digests exist in the committed reports and are NOT offered to the "
        "reader: " + ", ".join(missing) + ". Add them to the table, or the demo "
        "silently covers less than it appears to."
    )


def test_the_readme_try_it_command_reproduces_the_published_digest(tmp_path):
    """🔴 THE GAP THAT MADE EVERY OTHER TEST IN THIS FILE GREEN OVER A BROKEN DEMO.

    Found 2026-09-02, in a clean anonymous clone of the published repo.

    The root README's `## Try it` block — the page calls it *"the whole pitch"* —
    told a reader to run::

        python -m entrovouch.no_egress_auditor examples/sample_service

    and compare `findings_digest` against the table in `examples/README.md`. It
    did **not** match. `--label` is inside the digested body, `examples/regenerate.py`
    passes one and that command did not, so the published table and the documented
    command could not agree by construction.

    ⭐ **Every guard in this file was green throughout**, because they all reproduce
    via `regenerate.py`'s argv. They verified *the committed report against the tool*
    and never *the documented command against the published table*. A test that
    builds its own arguments cannot detect that the arguments in the docs are wrong —
    it is a second implementation of the happy path, not a check on the first.

    ⭐ **THE ARGV MUST COME OUT OF THE README.** That is the whole point: if someone
    edits the command on the page, this fails. If this test hardcoded the command,
    it would pass over exactly the defect it was written for.

    Only `--json <path>` is appended, so the report can be read as data instead of
    scraped from truncated markdown. That flag chooses an output destination and is
    not part of the report body — asserted below rather than assumed.
    """
    import re
    import shlex

    readme = (REPO / "README.md").read_text(encoding="utf-8")

    section = re.search(r"^## Try it\s*$(.*?)^## ", readme, re.S | re.M)
    assert section, "README no longer has a '## Try it' section — did the demo move?"
    blocks = re.findall(r"```bash\n(.*?)```", section.group(1), re.S)
    assert blocks, "the '## Try it' section shows no bash block for a reader to run"

    commands = [ln.strip() for b in blocks for ln in b.splitlines()
                if ln.strip().startswith("python -m entrovouch")]
    assert len(commands) == 1, (
        "expected exactly one `python -m entrovouch...` line in '## Try it', found "
        f"{len(commands)}: {commands}. If the demo now shows several, this guard must "
        "check each of them rather than silently pick one."
    )

    argv = shlex.split(commands[0])
    assert argv[:2] == ["python", "-m"], f"unexpected command shape: {argv}"
    out = tmp_path / "readme_try_it.json"
    r = subprocess.run(
        [sys.executable, *argv[1:], "--json", str(out)],
        cwd=REPO, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    assert r.returncode in (0, 1), (
        "the command the README tells a reader to run did not complete "
        f"(exit {r.returncode}):\n" + (r.stderr or r.stdout or "")[-800:]
    )
    produced = json.loads(out.read_text(encoding="utf-8"))["findings_digest"]

    examples_readme = (REPO / "examples" / "README.md").read_text(encoding="utf-8")
    row = re.search(
        r"`reports/egress\.json`\s*\|\s*`findings_digest`\s*\|\s*`([0-9a-f]{64})`",
        examples_readme)
    assert row, (
        "could not find the egress `findings_digest` row in examples/README.md. "
        "The README sends readers to that table; if its shape changed, update this "
        "guard in the same commit."
    )
    published = row.group(1)

    assert produced == published, (
        "THE README'S OWN COMMAND DOES NOT REPRODUCE THE PUBLISHED DIGEST.\n"
        f"  command  : {commands[0]}\n"
        f"  produced : {produced}\n"
        f"  published: {published}\n"
        "A prospect following the front page would see a mismatch and reasonably "
        "conclude the published report was fabricated. Fix the command on the page "
        "or regenerate the reports — do not adjust this test."
    )


def test_the_json_flag_does_not_change_the_report_body(tmp_path):
    """The guard above appends `--json`. This asserts that is a free action.

    If `--json` ever entered the digested body, the test above would be checking a
    report no reader ever produces, and would go green while the documented path
    broke — the same substitution it was written to catch, one level down.
    """
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    common = [sys.executable, "-m", "entrovouch.no_egress_auditor", TREE,
              "--label", "entrovouch/examples/sample_service"]
    for out in (a, b):
        r = subprocess.run(common + ["--json", str(out)], cwd=REPO,
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300)
        assert r.returncode in (0, 1), (r.stderr or r.stdout)[-400:]
    da = json.loads(a.read_text(encoding="utf-8"))["findings_digest"]
    db = json.loads(b.read_text(encoding="utf-8"))["findings_digest"]
    assert da == db, (
        f"the output path changed the findings digest ({da} vs {db}) — `--json` is "
        "not a free action and the README-command guard above is no longer valid."
    )

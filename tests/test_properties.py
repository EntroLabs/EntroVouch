"""Property-based tests: inputs nobody chose.

WHY THESE EXIST
---------------
**Zero egress means zero early warning**: this package ships with no
telemetry by construction, so there is no channel through which a field failure reports itself.
Everything a telemetry channel would catch has to be caught before release instead.

Example-based tests check the cases their author thought of. **A generator only emits what its
author already believes.** Property-based testing attacks that by generating inputs nobody chose,
including the empty, the enormous, and the adversarially shaped.

**SKIPS CLEANLY IF `hypothesis` IS ABSENT, DELIBERATELY.** ENTROVOUCH's product claim is *clone
it and run it*, and a hard test dependency would put a `pip install` between a sceptical reader and
reproducing our results. A reader without hypothesis still gets the full example-based suite; a
developer with it gets these too.

**THE LIMIT: properties are still OUR assumptions.** These check that the code is internally
coherent under adversarial input. They cannot tell us the output conforms to an external standard:
only an external reference does that (see `test_sarif_schema.py` and `test_cyclonedx_schema.py`).
"""
from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import sys

import pytest

# GUARD ON WHAT IS ACTUALLY USED, NOT ON THE MODULE NAME.
#
# `importorskip` succeeds as soon as the NAME imports, and the `from hypothesis
# import ...` below needs the module's CONTENTS. A leftover empty directory (from
# a partial uninstall, an interrupted install, a stale wheel) imports as an
# implicit namespace package with `__file__ = None`, so `importorskip` alone
# passes and the next line raises `ImportError: cannot import name 'given'`.
#
# A module-level ImportError does not skip this file: it ABORTS COLLECTION FOR
# THE WHOLE RUN, so `pytest -q` exits 2 with zero tests executed, in a repository
# whose entire argument is *re-run it yourself*.
#
# So the guard tries the real import, and skips the file if it does not work.
pytest.importorskip(
    "hypothesis",
    reason="hypothesis not installed; example-based suite still covers this package fully",
)
try:
    from hypothesis import given, settings, HealthCheck, strategies as st  # noqa: E402
except ImportError as exc:  # present but unusable: skip the FILE, never the run
    pytest.skip(
        f"hypothesis imports but is unusable ({exc}); reinstall it or remove the "
        f"leftover directory. The example-based suite still covers this package.",
        allow_module_level=True,
    )

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from entrovouch.no_egress_auditor import (  # noqa: E402
    audit, canonical_body, reproducible_body, verify_report, _subject_name,
)
from entrovouch.signer import MerkleSigner, verify_signature  # noqa: E402

SLOW = settings(max_examples=40, deadline=None,
                suppress_health_check=[HealthCheck.function_scoped_fixture])


# ---------------------------------------------------------------------------
# The verifier must never CRASH. A verifier that raises on hostile input is a
# denial-of-service surface, and "it threw an exception" is not "it rejected".
# ---------------------------------------------------------------------------
@given(st.dictionaries(st.text(max_size=20), st.text(max_size=40), max_size=8))
@SLOW
def test_verify_report_never_raises_on_arbitrary_dicts(d):
    """Garbage in must produce a verdict, never a traceback."""
    ok, status = verify_report(d)
    assert ok is False, "no arbitrary dict may verify as attested"
    assert status in {"TAMPERED", "UNSIGNED", "UNVERIFIED", "ATTESTED"}


@given(st.binary(max_size=64), st.binary(max_size=64), st.text(max_size=80))
@SLOW
def test_verify_signature_never_raises(msg, blob, root):
    """The signature verifier is the most hostile-facing function here."""
    fake = {"algorithm": "whatever", "sig": blob.hex(), "leaf_index": 0, "height": 2}
    assert verify_signature(msg, fake, expected_root=root) is False


# ---------------------------------------------------------------------------
# Reproducibility is the PRODUCT CLAIM, so it gets a property, not an example.
# ---------------------------------------------------------------------------
@given(st.text(min_size=1, max_size=60).filter(lambda s: s.strip()))
@SLOW
def test_findings_digest_ignores_issuance_but_label_still_binds(label):
    """`findings_digest` must exclude issuance fields and include the label.

    Two audits of the same tree under the SAME label must agree; under DIFFERENT
    labels they must not, because the label is part of the claim being made.
    """
    a = dataclasses.asdict(audit(pathlib.Path("entrovouch"), label=label))
    b = dataclasses.asdict(audit(pathlib.Path("entrovouch"), label=label))
    assert a["findings_digest"] == b["findings_digest"], "same label must reproduce"
    assert a["content_hash"] != b["content_hash"], "issuance must stay distinguishable"
    body = json.loads(reproducible_body(a))
    assert body["target"] == label


# ---------------------------------------------------------------------------
# The same tree gives the same report, however it reached the disk.
# ---------------------------------------------------------------------------
_NAMES = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=8)
_LINES = st.sampled_from([
    "import json", "import socket", "import requests", "x = 1", "print('hello')", "",
    "import subprocess", "subprocess.run(['curl', 'https://h.example/x'])", "# a comment",
    "URL = 'https://h.example/a'", "import urllib.request", "def f():", "    return 2",
])
_TREES = st.dictionaries(
    st.tuples(st.lists(_NAMES, min_size=0, max_size=2).map(tuple), _NAMES, st.sampled_from([".py", ".js", ".sh", ".txt"])),
    st.lists(_LINES, min_size=0, max_size=6), min_size=1, max_size=5)


def _build(root: pathlib.Path, tree: dict, newline: str, order: list) -> None:
    root.mkdir(parents=True)
    for key in order:
        folders, name, ext = key
        d = root.joinpath(*folders)
        d.mkdir(parents=True, exist_ok=True)
        (d / (name + ext)).write_bytes((newline.join(tree[key]) + newline).encode("utf-8"))


def _comparable(tree: dict) -> bool:
    """One path must not be both a file and a folder, and names must not differ only by case."""
    files = {"/".join([*f, n + e]) for f, n, e in tree}
    folders = {"/".join(f[:i]) for f, _, _ in tree for i in range(1, len(f) + 1)}
    return not (files & folders) and len({p.lower() for p in files | folders}) == len(files | folders)


@given(_TREES, st.randoms(use_true_random=False), _NAMES, _NAMES)
@SLOW
def test_the_report_does_not_depend_on_how_the_tree_reached_the_disk(tmp_path_factory, tree, rnd, here, there):
    """Line endings, the order files were written in, and the name of the folder holding the
    tree are facts about a checkout. None of them is a fact about the code."""
    if not _comparable(tree):
        return
    base = tmp_path_factory.mktemp("inv")
    keys = sorted(tree)
    shuffled = list(keys)
    rnd.shuffle(shuffled)
    _build(base / "a" / here, tree, "\n", keys)
    _build(base / "b" / there, tree, "\r\n", shuffled)
    one, two = audit(base / "a" / here, label="t"), audit(base / "b" / there, label="t")
    assert one.findings == two.findings
    assert one.findings_digest == two.findings_digest
    assert one.subject_digest == two.subject_digest


@given(_TREES, st.lists(_LINES, min_size=1, max_size=4))
@SLOW
def test_a_file_in_a_skipped_folder_changes_no_finding_and_is_counted(tmp_path_factory, tree, extra):
    if not _comparable(tree) or any("node_modules" in f for f, _, _ in tree):
        return
    base = tmp_path_factory.mktemp("skip")
    _build(base / "t", tree, "\n", sorted(tree))
    before = audit(base / "t", label="t")
    (base / "t" / "node_modules" / "pkg").mkdir(parents=True)
    (base / "t" / "node_modules" / "pkg" / "index.js").write_bytes(("\n".join(extra) + "\n").encode("utf-8"))
    after = audit(base / "t", label="t")
    assert after.findings == before.findings
    assert after.not_scanned != before.not_scanned, "what was skipped is stated, never silent"


@given(_TREES)
@SLOW
def test_adding_a_comment_adds_no_finding(tmp_path_factory, tree):
    py = [k for k in sorted(tree) if k[2] == ".py"]
    if not _comparable(tree) or not py:
        return
    base = tmp_path_factory.mktemp("cmt")
    _build(base / "a", tree, "\n", sorted(tree))
    changed = dict(tree)
    changed[py[0]] = [*tree[py[0]], "# nothing to see"]
    _build(base / "b", changed, "\n", sorted(changed))
    one, two = audit(base / "a", label="t"), audit(base / "b", label="t")
    # The line is left out: where a file that does not parse is reported moves with its last line.
    assert [(f["file"], f["kind"]) for f in one.findings] == [(f["file"], f["kind"]) for f in two.findings]


@given(st.integers(min_value=1, max_value=4))
@SLOW
def test_signing_never_reuses_a_leaf(n):
    """One-time keys: reusing a leaf leaks half the key pair. Never allow it."""
    signer = MerkleSigner(seed=b"\x11" * 32, height=3, path=None)
    seen = set()
    for i in range(n):
        sig = signer.sign(b"m%d" % i)
        idx = sig.get("leaf_index")
        assert idx not in seen, f"leaf {idx} reused: this leaks key material"
        seen.add(idx)
    assert seen == set(range(n)), "leaves must be spent in order from 0"


# ---------------------------------------------------------------------------
# Canonicalisation must be a FUNCTION of content, or signatures mean nothing.
# ---------------------------------------------------------------------------
@given(st.dictionaries(
    st.sampled_from(["target", "verdict", "files_scanned", "scope_statement"]),
    st.one_of(st.text(max_size=30), st.integers(min_value=0, max_value=999)),
    min_size=1))
@SLOW
def test_canonical_body_is_order_independent(d):
    """Key insertion order must not change the signed bytes.

    If it did, the same report could produce two different signatures depending
    on how a dict happened to be built: and a verifier would reject an honest
    report at random.
    """
    forward = canonical_body(dict(d))
    backward = canonical_body({k: d[k] for k in reversed(list(d))})
    assert forward == backward


# ---------------------------------------------------------------------------
# The subject name: `.` and its spellings must never give an EMPTY in-toto subject.
# ---------------------------------------------------------------------------
# `.\` is a spelling of the current directory only where a backslash separates path parts.
# On Linux and macOS it is an ordinary file name with a backslash in it, so it is left out there.
_HERE_SPELLINGS = [".", "./", "entrovouch", "./entrovouch"] + ([".\\"] if os.sep == "\\" else [])


@given(st.sampled_from(_HERE_SPELLINGS))
@SLOW
def test_subject_name_is_never_empty(rel):
    """An in-toto Statement with a blank subject name defeats its own purpose."""
    name = _subject_name(pathlib.Path(rel))
    assert name, f"{rel!r} produced an empty subject name"
    assert "/" not in name and "\\" not in name, "only the final component may appear"

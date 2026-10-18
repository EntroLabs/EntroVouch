"""A report or key file that arrives malformed gets an answer, never a traceback.

Exit code 1 means "the scan ran and found something". A crash used to exit 1 too, so a pipeline keying on the
code would read a broken run as findings. Every command now ends a failure at 2, and the verification functions
return a status for any input. Each test also checks the neighbour that must keep working.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import attestation, csaf, cyclonedx, sarif, vex
from entrovouch._cli import run
from entrovouch.cbom import build_cbom
from entrovouch.no_egress_auditor import audit, canonical_body, verify_any, verify_report
from entrovouch.signer import MerkleSigner, SignerError, verify_signature

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "examples" / "sample_service"
SIGNER = MerkleSigner(seed=b"\x05" * 32, height=2, path=None)
_SIGNED: list = []


def _signed_report() -> dict:
    """The sample report, signed once per process.

    pytest rebuilds a module-scoped fixture each time a run re-enters the module, so under a shuffled order a fixture
    that signed on every setup would sign again on every re-entry, and the fifth would exhaust SIGNER's four one-time
    keys. Signing a fresh body
    with a rebuilt signer would reuse a one-time key on a different message (`scanned_at_utc` differs per scan), so the
    report is signed once and every setup gets its own copy."""
    if not _SIGNED:
        _SIGNED.append(asdict(audit(SAMPLE, label="entrovouch/examples/sample_service", signer=SIGNER)))
    return copy.deepcopy(_SIGNED[0])


@pytest.fixture(scope="module")
def report():
    return _signed_report()


def test_report_fixture_survives_reentry():
    # Five setups, as a shuffled run produces: each copy verifies, and only one one-time key is spent.
    copies = [_signed_report() for _ in range(5)]
    for c in copies:
        assert verify_report(c, expected_root=SIGNER.public_root) == (True, "ATTESTED")
    assert SIGNER.next_index == 1
    copies[0]["verdict"] = "tampered"
    assert _signed_report()["verdict"] != "tampered", "each setup must get its own copy"


_ORDER_PLUGIN = """
import os
import random


def pytest_collection_modifyitems(session, config, items):
    # Leave out the re-entry tests by test name (`-k` would also match the temporary folder's name).
    items[:] = [i for i in items if "reentr" not in i.name]
    mode = os.environ["ENTROVOUCH_TEST_ORDER"]
    mine = [i for i in items if "test_malformed_input" in i.nodeid]
    other = [i for i in items if "test_malformed_input" not in i.nodeid]
    if mode == "interleave":
        out = []
        while mine or other:
            if mine:
                out.append(mine.pop(0))
            if other:
                out.append(other.pop(0))
    elif mode == "reverse":
        out = mine[::-1] + other
    else:
        out = mine + other
        random.Random(int(mode.split(":")[1])).shuffle(out)
    items[:] = out
"""


def _run_this_file(tmp_path, order: str):
    (tmp_path / "order_plugin.py").write_text(_ORDER_PLUGIN, encoding="utf-8")
    other = tmp_path / "test_other_module.py"
    other.write_text("".join(f"def test_other_{i}():\n    pass\n\n\n" for i in range(20)), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(tmp_path) + os.pathsep + os.environ.get("PYTHONPATH", ""),
               PYTHONDONTWRITEBYTECODE="1", ENTROVOUCH_TEST_ORDER=order)
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "order_plugin", "-p", "no:cacheprovider",
                        "--setup-show", str(Path(__file__).resolve()), str(other)],
                       cwd=REPO, env=env, capture_output=True, text=True, timeout=900)
    return r, r.stdout + r.stderr


def test_report_fixture_reentry_through_pytest(tmp_path):
    # The test above calls the helper; this one makes pytest itself set the module fixture up again and again, as a
    # shuffled run does: this file's tests alternate with another module's, so every test re-enters the module.
    r, out = _run_this_file(tmp_path, "interleave")
    setups = len(re.findall(r"SETUP\s+M report\b", out))  # pytest's own setup report, not a counter of ours
    assert "KeyExhausted" not in out, "a fixture setup signed again and ran out of one-time keys:\n" + out[-3000:]
    assert r.returncode == 0, out[-3000:]
    assert setups >= 5, f"the fixture was set up {setups} times, not five, so this run proves nothing"


def test_this_file_passes_reversed_and_shuffled_not_only_on_reentry(tmp_path):
    # Order independence within this file: reversed, and shuffled with this file's tests mixed into another module's.
    # The shuffle seed is drawn fresh on every run and printed on failure, so a failure can be replayed. This covers
    # this file only, not the whole suite.
    import secrets
    seed = secrets.randbits(32)
    for order in ("reverse", f"shuffle:{seed}"):
        r, out = _run_this_file(tmp_path, order)
        assert r.returncode == 0, f"order {order}:\n" + out[-3000:]


@pytest.fixture(scope="module")
def cbom_doc():
    return asdict(build_cbom(REPO / "entrovouch"))


def _rehash(d):
    d["content_hash"] = hashlib.sha3_256(canonical_body(d)).hexdigest()
    return d


def _malformed(report):
    cases = {}
    for name, value in (("non-ascii", "é" * 64), ("integer", 5), ("none", None), ("list", ["a"])):
        d = copy.deepcopy(report)
        d["content_hash"] = value
        cases[f"content_hash {name}"] = d
    for name, value in (("list", ["x"]), ("string", "abc"), ("integer", 7)):
        d = copy.deepcopy(report)
        d["signature"] = value
        cases[f"signature {name}"] = d
    cases["top level list"] = [report]
    cases["top level none"] = None
    return cases


def test_verify_report_answers_every_malformed_report(report):
    root = SIGNER.public_root
    assert verify_report(report, expected_root=root) == (True, "ATTESTED")
    for name, doc in _malformed(report).items():
        assert verify_report(doc, expected_root=root) == (False, "TAMPERED"), name


def test_nothing_unsigned_travels_inside_an_attested_report(report):
    """`integrity_tag` is outside the signed body. Issued empty; any other value is not part of what was signed,
    so the report is not ATTESTED with it."""
    root = SIGNER.public_root
    assert report["integrity_tag"] == ""
    for value in ("forged-0123", 5, {"claim": "CLEAN"}, None):
        d = copy.deepcopy(report)
        d["integrity_tag"] = value
        assert verify_report(d, expected_root=root) == (False, "TAMPERED"), value
    d = copy.deepcopy(report)
    d.pop("integrity_tag")
    assert verify_report(d, expected_root=root) == (True, "ATTESTED")       # absent is fine


def test_verify_signature_and_verify_any_return_false_for_a_signature_that_is_not_an_object(report):
    body = canonical_body(report)
    assert verify_signature(body, report["signature"], expected_root=SIGNER.public_root)
    for sig in (["x"], "abc", 7, None):
        assert verify_signature(body, sig) is False
        assert verify_any(body, sig) is False
    assert verify_signature("text, not bytes", report["signature"]) is False


def _write(tmp_path, name, content):
    p = tmp_path / name
    if isinstance(content, bytes):
        p.write_bytes(content)
    elif isinstance(content, str):
        p.write_text(content, encoding="utf-8")
    else:
        p.write_text(json.dumps(content), encoding="utf-8")
    return p


def _adapters(path, out):
    yield "sarif", lambda: sarif.main([str(path), "--out", str(out)])
    yield "attestation", lambda: attestation.main([str(path), "--out", str(out)])
    yield "cyclonedx", lambda: cyclonedx.main([str(path), "--out", str(out)])
    yield "vex", lambda: vex.main([str(path), "--out", str(out)])
    yield "csaf", lambda: csaf.main([str(path), "--out", str(out), "--publisher-name", "Example Ltd",
                                     "--publisher-namespace", "https://example.com"])


def test_every_adapter_refuses_malformed_input_with_exit_2(tmp_path, report, cbom_doc, capsys):
    bad_hash = copy.deepcopy(report)
    bad_hash["content_hash"] = "é" * 64
    inputs = {
        "non-ascii content hash": bad_hash,
        "top level list": [1, 2],
        "not json": "{not json",
        "not utf-8": b"\xff\xfe\x00garbage",
        "missing file": None,
    }
    for label, content in inputs.items():
        path = tmp_path / "missing.json" if content is None else _write(tmp_path, "in.json", content)
        for name, call in _adapters(path, tmp_path / "out.json"):
            assert call() == 2, f"{name}: {label}"
            assert "Traceback" not in capsys.readouterr().err


def test_an_intact_report_still_converts(tmp_path, report, cbom_doc):
    rep = _write(tmp_path, "rep.json", report)
    cb = _write(tmp_path, "cbom.json", cbom_doc)
    assert sarif.main([str(rep), "--out", str(tmp_path / "a")]) == 0
    assert attestation.main([str(rep), "--out", str(tmp_path / "b")]) == 0
    assert cyclonedx.main([str(cb), "--out", str(tmp_path / "c")]) == 0
    assert vex.main([str(cb), "--out", str(tmp_path / "d")]) == 0


def test_a_crash_inside_any_command_exits_2_not_1(capsys):
    def boom():
        raise RuntimeError("something nobody handled")
    assert run(boom) == 2
    assert "did not complete" in capsys.readouterr().err
    assert run(lambda: 1) == 1 and run(lambda: 0) == 0


@pytest.mark.parametrize("state, why", [
    ('{"seed": "' + "ab" * 32 + '", "height": "10", "next_index": 0}', "height is not an integer"),
    ('{"seed": "' + "ab" * 32 + '", "height": 10.0, "next_index": 0}', "height is not an integer"),
    ('{"seed": "zz", "height": 10, "next_index": 0}', "seed is not 64"),
    ('{"seed": "' + "AB" * 32 + '", "height": 10, "next_index": 0}', "seed is not 64"),
    ('{"seed": "' + "ab" * 32 + '", "height": 10, "next_index": 0, "extra": 1}', "expected exactly"),
    ("not json at all", "not JSON"),
    ("[1, 2]", "expected exactly"),
])
def test_a_malformed_signing_state_is_refused_by_name(tmp_path, state, why):
    p = tmp_path / "k.json"
    p.write_text(state, encoding="utf-8")
    with pytest.raises(SignerError, match=why):
        MerkleSigner.load(p)


def test_a_signing_state_this_package_wrote_still_loads(tmp_path):
    made = MerkleSigner.create(tmp_path / "k.json", height=2)
    loaded = MerkleSigner.load(tmp_path / "k.json")
    assert loaded.seed == made.seed and loaded.height == 2 and loaded.next_index == 0

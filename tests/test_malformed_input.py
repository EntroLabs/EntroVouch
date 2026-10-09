"""A report or key file that arrives malformed gets an answer, never a traceback.

Exit code 1 means "the scan ran and found something". A crash used to exit 1 too, so a pipeline keying on the
code would read a broken run as findings. Every command now ends a failure at 2, and the verification functions
return a status for any input. Each test also checks the neighbour that must keep working.
"""
from __future__ import annotations

import copy
import hashlib
import json
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


@pytest.fixture(scope="module")
def report():
    return asdict(audit(SAMPLE, label="entrovouch/examples/sample_service", signer=SIGNER))


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

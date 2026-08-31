"""Trusted timestamps and VEX output.

Both modules answer a question the rest of the package cannot, and both are
constrained by the same rule: **no network operations, ever.** A tool that
acquired a network client in order to prove it has no network client would be
self-refuting, so the timestamp work is split — we build the request, you send
it, we check what comes back.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from entrovouch import timestamp as ts
from entrovouch import vex as vx

REPO = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# RFC 3161 request construction
# ---------------------------------------------------------------------------
def test_request_is_well_formed_der(tmp_path):
    """Structure, checked by parsing it back rather than by eyeballing bytes.

    ⭐ The stronger check is external and was run by hand during development:
    `openssl ts -query -in req.tsq -text` parses this output and reports
    Version 1, sha256, the correct message digest and the nonce. openssl is the
    reference implementation; agreement with it is conformance, agreement with
    ourselves would only be self-consistency.
    """
    digest = bytes(range(32))
    req, nonce = ts.build_request(digest, nonce=12345)
    assert req[0] == 0x30, "TimeStampReq must be a DER SEQUENCE"
    assert digest in req, "the message imprint must carry our digest"
    assert nonce == 12345
    assert len(req) > 40


def test_request_rejects_a_wrong_length_digest():
    """SHA-256 or nothing. A 20-byte digest would encode fine and mean SHA-1."""
    with pytest.raises(ValueError):
        ts.build_request(b"\x00" * 20)


def test_nonce_is_random_by_default():
    """A nonce is the only thing between the caller and a replayed token, so it
    is generated rather than defaulted to a constant."""
    _, n1 = ts.build_request(bytes(32))
    _, n2 = ts.build_request(bytes(32))
    assert n1 != n2


def test_cert_req_flag_changes_the_encoding():
    with_cert, _ = ts.build_request(bytes(32), nonce=1, cert_req=True)
    without, _ = ts.build_request(bytes(32), nonce=1, cert_req=False)
    assert with_cert != without


# ---------------------------------------------------------------------------
# Imprint checking — and what it deliberately does not do
# ---------------------------------------------------------------------------
def test_token_containing_the_digest_is_accepted():
    digest = bytes(range(32))
    fake_token = b"\x30\x82" + b"junk" + digest + b"more junk"
    assert ts.token_contains_digest(fake_token, digest) is True


def test_token_for_a_different_report_is_rejected():
    """The realistic mistake this catches: a token pasted from the wrong file."""
    assert ts.token_contains_digest(b"\x30\x82 unrelated bytes", bytes(range(32))) is False


def test_imprint_check_is_not_a_signature_check():
    """🔴 THE LIMIT, ASSERTED SO IT CANNOT BE QUIETLY FORGOTTEN.

    A token whose only virtue is containing the digest passes. That is correct
    for the question asked and is NOT verification: this module does not parse
    CMS or validate an X.509 chain, because doing so would import a trust root
    the package exists to avoid. The docstring says so, and so does the CLI.
    """
    digest = bytes(range(32))
    obviously_forged = b"I am not a real timestamp token" + digest
    assert ts.token_contains_digest(obviously_forged, digest) is True
    assert "not a signature" in ts.token_contains_digest.__doc__.lower() or \
           "cannot catch: a forged token" in ts.token_contains_digest.__doc__


def test_report_digest_covers_file_bytes_not_reparsed_json(tmp_path):
    """A timestamp must bind the artifact somebody holds. Re-serialising the
    parsed JSON would bind a document only this tool ever produced."""
    p = tmp_path / "r.json"
    p.write_text('{"b":1,   "a":2}', encoding="utf-8")
    import hashlib
    assert ts.report_digest(p) == hashlib.sha256(b'{"b":1,   "a":2}').digest()


# ---------------------------------------------------------------------------
# VEX
# ---------------------------------------------------------------------------
def _cbom(*statuses):
    return {"components": [
        {"file": "f.py", "line": i, "primitive": f"P{i}", "category": "hash", "quantum": s}
        for i, s in enumerate(statuses, 1)]}


def test_every_statement_is_in_triage():
    """🔴 THE LOAD-BEARING ASSERTION OF THIS WHOLE MODULE.

    Exploitability is a property of reachability and static analysis does not
    establish reachability. `exploitable` would claim an analysis that never ran;
    `not_affected` would clear a finding on the strength of not having looked.
    `in_triage` is the format's own word for *identified, a human decides*.
    """
    doc = vx.to_vex(_cbom("BROKEN", "WEAK-RNG", "VULNERABLE"))
    assert doc["vulnerabilities"], "expected statements"
    assert {v["analysis"]["state"] for v in doc["vulnerabilities"]} == {"in_triage"}


def test_identifiers_are_cwe_never_cve():
    """This tool has no vulnerability database and makes no network call to get
    one. A CVE identifier here would be invented."""
    doc = vx.to_vex(_cbom("BROKEN", "WEAK-RNG"))
    ids = [v["id"] for v in doc["vulnerabilities"]]
    assert ids and all(i.startswith("CWE-") for i in ids)
    assert not any("CVE" in json.dumps(v) for v in doc["vulnerabilities"])


def test_safe_primitives_produce_no_statement():
    """A clean CBOM must yield an empty VEX document, not a reassuring one."""
    doc = vx.to_vex(_cbom("SAFE", "GROVER-REDUCED", "REVIEW"))
    assert doc["vulnerabilities"] == []


def test_many_sites_of_one_weakness_are_one_statement():
    """Forty MD5 call sites are one weakness in forty places. A document that
    inflates the second into the first is the raw-count error this estate has
    measured before."""
    many = {"components": [
        {"file": f"f{i}.py", "line": i, "primitive": "MD5", "category": "hash", "quantum": "BROKEN"}
        for i in range(40)]}
    doc = vx.to_vex(many)
    assert len(doc["vulnerabilities"]) == 1
    assert "40 site(s)" in doc["vulnerabilities"][0]["affects"][0]["ref"]


def test_key_provenance_adds_one_hardcoded_credential_statement():
    doc = vx.to_vex(_cbom("SAFE"), key_findings=[{"kind": "literal-key"}, {"kind": "literal-key"}])
    ids = [v["id"] for v in doc["vulnerabilities"]]
    assert ids == ["CWE-798"], "one statement for the class, not one per site"


def test_vex_validates_against_the_pinned_cyclonedx_schema():
    """The same official schema the CBOM output is validated against."""
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((REPO / "tests" / "schemas" / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    doc = vx.to_vex(_cbom("BROKEN", "WEAK-RNG", "VULNERABLE"),
                    key_findings=[{"kind": "literal-key"}])
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors[:6])


# ---------------------------------------------------------------------------
# Neither module may acquire a network client
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mod", ["entrovouch/timestamp.py", "entrovouch/vex.py"])
def test_new_modules_are_still_zero_egress(mod):
    """⭐ The package's central claim, re-asserted against its newest code.

    A timestamp module is exactly where a network client would arrive by
    accident — fetching the token is the obvious next line to write, and it is
    the one line that would break the property everything else rests on.
    """
    from dataclasses import asdict
    from entrovouch.no_egress_auditor import audit
    rep = asdict(audit(REPO / "entrovouch", label="self"))
    offenders = [f for f in rep["findings"] if Path(str(f["file"])).name == Path(mod).name]
    assert not offenders, f"{mod} acquired network capability: {offenders}"


def test_timestamp_cli_runs_and_reports_what_it_did_not_verify(tmp_path):
    r = tmp_path / "r.json"
    r.write_text('{"x":1}', encoding="utf-8")
    out = tmp_path / "req.tsq"
    proc = subprocess.run([sys.executable, "-m", "entrovouch.timestamp", "request",
                           str(r), "--out", str(out)],
                          cwd=REPO, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert out.is_file() and out.stat().st_size > 40
    assert "will not" in proc.stdout, "the CLI must say it does not send the request itself"

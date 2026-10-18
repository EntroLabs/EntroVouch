"""`entrovouch.lms` against RFC 9858's own published test vectors.

`tests/vectors/rfc9858_test_cases.json` holds Appendix A of RFC 9858 (Test Cases, A.1 to A.4), transcribed from the
RFC text: for each case the HSS public key, the message and the HSS signature, concatenated as the appendix says to
read them, and the seed and identifier of its private key figure. The four cases cover the three hash choices RFC 9858
adds: SHA-256/192 (A.1, with W8 and height 5; A.4, with W4 and height 20), SHAKE256/192 (A.2, W8, height 5) and
SHAKE256/256 (A.3, W8, height 5).

What this backs: all four published signatures verify, and flipping the low bit of any one byte of a public key or a
message, or of a sampled byte of a signature (each of the first 16 and the last 16, and every 11th), makes
verification fail. The seeds are not used: this module does not sign with the RFC 9858 sets, so the
published signatures are verified and not reproduced. It does not back CAVP or NIST SP 800-208 validation, and it says
nothing about the signer that signs reports.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from entrovouch import lms

VECTORS = json.loads((Path(__file__).parent / "vectors" / "rfc9858_test_cases.json").read_text(encoding="utf-8"))
CASES = ("A.1", "A.2", "A.3", "A.4")

# Appendix A: case -> (LMS type name, LM-OTS type name) the type codes in its figures name.
PUBLISHED_SETS = {
    "A.1": ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W8"),
    "A.2": ("LMS_SHAKE_M24_H5", "LMOTS_SHAKE_N24_W8"),
    "A.3": ("LMS_SHAKE_M32_H5", "LMOTS_SHAKE_N32_W8"),
    "A.4": ("LMS_SHA256_M24_H20", "LMOTS_SHA256_N24_W4"),
}


def _case(name):
    v = VECTORS["cases"][name]
    return bytes.fromhex(v["public_key"]), bytes.fromhex(v["message"]), bytes.fromhex(v["signature"])


def test_the_vector_file_names_its_source_and_holds_four_cases():
    assert VECTORS["source"].startswith("RFC 9858, Appendix A")
    assert "rfc-editor.org/rfc/rfc9858" in VECTORS["source"]
    assert "Transcribed from the RFC text" in VECTORS["note"]
    assert tuple(VECTORS["cases"]) == CASES and len(CASES) == 4


@pytest.mark.parametrize("name", CASES)
def test_each_case_has_the_published_shape(name):
    v = VECTORS["cases"][name]
    pub, msg, sig = _case(name)
    lms_type, ots_type = int(v["lms_type"], 16), int(v["lmots_type"], 16)
    assert (lms.LMS_VERIFY_TYPES[lms_type][0], lms.LMOTS_VERIFY_TYPES[ots_type][0]) == PUBLISHED_SETS[name]
    # HSS public key: L = 1, then the LMS public key (type, LM-OTS type, I, K)
    assert pub[:4] == b"\x00\x00\x00\x01" and len(pub) == 4 + lms.lms_public_key_length(lms_type)
    assert pub[4:8] == lms_type.to_bytes(4, "big") and pub[8:12] == ots_type.to_bytes(4, "big")
    assert pub[12:28].hex() == v["I"]
    # HSS signature: Nspk = 0, then one LMS signature (q, LM-OTS signature, LMS type, path)
    assert sig[:4] == b"\x00\x00\x00\x00" and len(sig) == 4 + lms.lms_signature_length(lms_type, ots_type)
    assert int.from_bytes(sig[4:8], "big") == v["q"]
    assert msg.decode("ascii") == v["message_ascii"]


def test_the_cases_cover_the_three_rfc_9858_hashes():
    families = {(lms.LMS_VERIFY_TYPES[int(v["lms_type"], 16)][1], lms.LMS_VERIFY_TYPES[int(v["lms_type"], 16)][2])
                for v in VECTORS["cases"].values()}
    assert families == {("sha256", 24), ("shake256", 24), ("shake256", 32)}


@pytest.mark.parametrize("name", CASES)
def test_the_published_signature_verifies(name):
    pub, msg, sig = _case(name)
    assert lms.hss_verify(pub, msg, sig) is True
    # With one level the HSS signature is Nspk then a single LMS signature: the LMS layer accepts it alone.
    assert lms.lms_verify(pub[4:], msg, sig[4:]) is True


def _positions(n: int) -> list[int]:
    """Every byte of the first 16 and the last 16, and one in every 11 between: each 24- or 32-byte value of a
    signature gets at least two."""
    return sorted(set(range(min(16, n))) | set(range(max(0, n - 16), n)) | set(range(0, n, 11)))


@pytest.mark.parametrize("name", CASES)
@pytest.mark.parametrize("part", ("public_key", "message", "signature"))
def test_one_changed_byte_of_a_vector_fails(name, part):
    pub, msg, sig = _case(name)
    values = {"public_key": pub, "message": msg, "signature": sig}
    original = values[part]
    positions = range(len(original)) if part != "signature" else _positions(len(original))
    for i in positions:
        changed = bytearray(original)
        changed[i] ^= 0x01
        values[part] = bytes(changed)
        assert lms.hss_verify(values["public_key"], values["message"], values["signature"]) is False, (part, i)
    values[part] = original
    assert lms.hss_verify(pub, msg, sig) is True


@pytest.mark.parametrize("name", CASES)
def test_a_signature_is_refused_under_another_cases_key(name):
    pub, msg, sig = _case(name)
    for other in CASES:
        if other != name:
            assert lms.hss_verify(_case(other)[0], msg, sig) is False, other


@pytest.mark.parametrize("name", CASES)
def test_a_truncated_or_extended_signature_fails(name):
    pub, msg, sig = _case(name)
    assert not lms.hss_verify(pub, msg, sig[:-1])
    assert not lms.hss_verify(pub, msg, sig + b"\x00")
    assert not lms.hss_verify(pub, msg, b"\x00\x00\x00\x01" + sig[4:])     # Nspk 1 against L = 1
    assert not lms.hss_verify(pub, msg, b"")

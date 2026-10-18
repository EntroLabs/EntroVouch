"""`entrovouch.lms` against RFC 8554's own published test vectors.

`tests/vectors/rfc8554_appendix_f.json` holds Appendix F of RFC 8554 (Test Cases, pages 49 to 58): for each of the
two test cases the HSS public key, the message and the HSS signature, concatenated as the appendix says to read
them, and for test case 2 the two seeds and identifiers the appendix gives under "Test Case 2 Private Key"
(derived with the procedure of Appendix A).

What this backs: both signatures verify, test case 2 is reproduced byte for byte from its private keys, and flipping
the low bit of any one byte of a public key or a message, or of a sampled byte of a signature (each of the first 16
and the last 16, and every 13th), makes verification fail. It does not back NIST SP 800-208
validation, which this module does not have, and it says nothing about the signer that signs reports.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from entrovouch import lms
from entrovouch.signer import IndexReuse, KeyExhausted, SignerError

REPO = Path(__file__).resolve().parents[1]
VECTORS = json.loads((Path(__file__).parent / "vectors" / "rfc8554_appendix_f.json").read_text(encoding="utf-8"))
CASES = ("test_case_1", "test_case_2")


def _case(name):
    v = VECTORS[name]
    return bytes.fromhex(v["public_key"]), bytes.fromhex(v["message"]), bytes.fromhex(v["signature"])


def test_the_vector_file_names_its_source_and_has_the_published_shape():
    assert VECTORS["source"].startswith("RFC 8554, Appendix F")
    # The messages are the ASCII the RFC prints beside the hex (the right-hand column of each listing).
    assert _case("test_case_1")[1] == (b"The powers not delegated to the United States by the Constitution, nor "
                                       b"prohibited by it to the States, are reserved to the States respectively, or "
                                       b"to the people.\n")
    assert _case("test_case_2")[1] == (b"The enumeration in the Constitution, of certain rights, shall not be "
                                       b"construed to deny or disparage others retained by the people.\n")
    # HSS public key: L = 2, then an LMS public key (type, LM-OTS type, I, K)
    pub1, _, sig1 = _case("test_case_1")
    pub2, _, sig2 = _case("test_case_2")
    assert pub1[:12] == bytes.fromhex("00000002" "00000005" "00000004") and len(pub1) == 60
    assert pub2[:12] == bytes.fromhex("00000002" "00000006" "00000003") and len(pub2) == 60
    # Nspk = 1; two LMS signatures and one signed LMS public key
    assert len(sig1) == 4 + 1292 + 56 + 1292 and len(sig2) == 4 + 2508 + 56 + 1292
    assert pub2[12:28].hex() == VECTORS["test_case_2"]["top_I"]


@pytest.mark.parametrize("name", CASES)
def test_the_published_signature_verifies(name):
    pub, msg, sig = _case(name)
    assert lms.hss_verify(pub, msg, sig) is True


def test_test_case_2_is_reproduced_from_its_private_keys():
    """Key generation (Appendix A), the tree, and signing, against the published values: with the published
    randomizers C, both LMS signatures in the HSS signature come out byte for byte."""
    v = VECTORS["test_case_2"]
    pub, msg, sig = _case("test_case_2")
    top = lms.LmsKey(lms.LMS_SHA256_M32_H10, lms.LMOTS_SHA256_N32_W4, bytes.fromhex(v["top_I"]),
                     bytes.fromhex(v["top_seed"]))
    second = lms.LmsKey(lms.LMS_SHA256_M32_H5, lms.LMOTS_SHA256_N32_W8, bytes.fromhex(v["second_I"]),
                        bytes.fromhex(v["second_seed"]))
    assert b"\x00\x00\x00\x02" + top.public_key == pub
    top_sig, at = lms._split_lms_signature(sig, 4)
    child, at = lms._split_lms_public_key(sig, at)
    final, at = lms._split_lms_signature(sig, at)
    assert at == len(sig) and child == second.public_key
    q_top, q_final = int.from_bytes(top_sig[:4], "big"), int.from_bytes(final[:4], "big")
    assert (q_top, q_final) == (3, 4)
    made = (b"\x00\x00\x00\x01"
            + top.sign(second.public_key, q=q_top, randomizer=top_sig[8:40])
            + second.public_key
            + second.sign(msg, q=q_final, randomizer=final[8:40]))
    assert made == sig


def _positions(n: int) -> list[int]:
    """Every byte of the first 16 and the last 16, and one in every 13 between: each 32-byte value of a signature
    gets at least two."""
    return sorted(set(range(min(16, n))) | set(range(max(0, n - 16), n)) | set(range(0, n, 13)))


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
def test_a_signature_of_the_wrong_length_or_level_count_fails(name):
    pub, msg, sig = _case(name)
    assert not lms.hss_verify(pub, msg, sig[:-1])
    assert not lms.hss_verify(pub, msg, sig + b"\x00")
    assert not lms.hss_verify(pub, msg, b"\x00\x00\x00\x00" + sig[4:])       # Nspk 0 against L = 2
    assert not lms.hss_verify(b"\x00\x00\x00\x01" + pub[4:], msg, sig)      # L = 1 against Nspk 1
    assert not lms.hss_verify(b"\x00\x00\x00\x09" + pub[4:], msg, sig)      # L above 8
    assert not lms.hss_verify(pub, msg, b"")


@pytest.mark.parametrize("ots_type", sorted(lms.LMOTS_TYPES))
def test_every_lmots_parameter_set_signs_and_verifies(ots_type):
    key = lms.LmsKey(lms.LMS_SHA256_M32_H5, ots_type, bytes(range(16)), bytes(range(32)))
    sig = key.sign(b"entrovouch lms")
    assert len(sig) == lms.lms_signature_length(lms.LMS_SHA256_M32_H5, ots_type)
    assert lms.lms_verify(key.public_key, b"entrovouch lms", sig)
    assert not lms.lms_verify(key.public_key, b"entrovouch lmz", sig)


def test_a_key_taller_than_the_signing_limit_is_refused():
    with pytest.raises(SignerError):
        lms.LmsKey(7, lms.LMOTS_SHA256_N32_W8, bytes(16), bytes(32))


# ----------------------------------------------------------------------------------------- one-time keys
def test_a_used_leaf_is_refused_and_the_state_is_written_first(tmp_path):
    path = tmp_path / "lms.json"
    key = lms.LmsKey.create(path)
    first = key.sign(b"one")
    assert int.from_bytes(first[:4], "big") == 0
    assert json.loads(path.read_text(encoding="utf-8"))["next_q"] == 1
    second = key.sign(b"two")
    assert int.from_bytes(second[:4], "big") == 1
    with pytest.raises(IndexReuse):
        key.sign(b"three", q=0)
    with pytest.raises(IndexReuse):
        key.sign(b"three", q=1)
    # a second handle loaded from the file continues after the last used leaf
    again = lms.LmsKey.load(path)
    assert again.next_q == 2 and int.from_bytes(again.sign(b"four")[:4], "big") == 2
    assert lms.lms_verify(key.public_key, b"two", second)


def test_a_state_file_moved_backwards_is_refused(tmp_path):
    path = tmp_path / "lms.json"
    key = lms.LmsKey.create(path)
    before = path.read_bytes()
    key.sign(b"one")
    path.write_bytes(before)                           # a restore from a copy taken before the signature
    with pytest.raises(IndexReuse):
        key.sign(b"two")


def test_a_key_is_never_overwritten_and_is_exhausted_at_the_last_leaf(tmp_path):
    path = tmp_path / "lms.json"
    key = lms.LmsKey.create(path)
    with pytest.raises(SignerError):
        lms.LmsKey.create(path)
    assert key.advance(31) == 31
    key.sign(b"last")
    with pytest.raises(KeyExhausted):
        key.sign(b"past the end")


def test_reports_are_not_signed_with_lms():
    """The report signer and the report format are unchanged: nothing outside this module and its tests uses it."""
    from entrovouch import signer
    assert signer.ALGORITHM == "Lamport-Merkle-SHA3-256 (hash-based, post-quantum)"
    import re
    for p in (REPO / "entrovouch").glob("*.py"):
        if p.name != "lms.py":
            assert not re.search(r"\blms\b", p.read_text(encoding="utf-8")), p.name


def test_conformance_states_the_scope_of_the_claim():
    doc = (REPO / "CONFORMANCE.md").read_text(encoding="utf-8")
    start = doc.index("### RFC 8554")
    section = doc[start:doc.index("\n### ", start + 1)]
    assert "test_lms_rfc8554.py" in section and "Appendix F" in section
    assert "SP 800-208" in section and "NOT" in section
    assert "does not sign reports" in section.lower()

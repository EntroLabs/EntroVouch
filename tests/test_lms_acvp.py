"""The LMS verifier against the LMS sigVer vectors NIST publishes in its ACVP-Server repository.

The file is `gen-val/json-files/LMS-sigVer-1.0/internalProjection.json` from usnistgov/ACVP-Server at commit
2972def23bf9f3680c2c531561ed9bdd0f1086ad, copied unchanged and pinned below by its SHA-256. It holds 2 groups of 4
cases, both SHA-256/192 (RFC 9858) parameter sets, and only 2 of the 8 cases are valid signatures. A verifier that
refused everything would agree with 6 of 8, so the test also asserts that both valid signatures verify.

Running NIST's published vectors is not CAVP validation. No CAVP validation has been run.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from entrovouch import lms

VECTORS = Path(__file__).resolve().parent / "vectors" / "acvp_lms_sigver_1_0_internalProjection.json"
VECTORS_SHA256 = "298bf08f3dab576483b731dc58a4feab18b93e1e741bc6192133285962cf77dd"


def _load() -> dict:
    data = VECTORS.read_bytes()
    assert hashlib.sha256(data).hexdigest() == VECTORS_SHA256, "the vendored ACVP file changed"
    return json.loads(data.decode("utf-8"))


def _cases():
    doc = _load()
    assert (doc["algorithm"], doc["mode"], doc["revision"]) == ("LMS", "sigVer", "1.0")
    for group in doc["testGroups"]:
        pub = bytes.fromhex(group["publicKey"])
        for case in group["tests"]:
            yield group, pub, case


def test_the_vendored_file_is_the_pinned_one_and_holds_eight_cases():
    doc = _load()
    groups = doc["testGroups"]
    assert [(g["lmsMode"], g["lmOtsMode"]) for g in groups] == [
        ("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"), ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2")]
    assert sum(len(g["tests"]) for g in groups) == 8


def test_every_acvp_case_gets_the_published_answer():
    ran, verified = 0, []
    for group, pub, case in _cases():
        # the group's mode names agree with the typecodes inside its public key
        assert lms.LMS_VERIFY_TYPES[int.from_bytes(pub[:4], "big")][0] == group["lmsMode"]
        assert lms.LMOTS_VERIFY_TYPES[int.from_bytes(pub[4:8], "big")][0] == group["lmOtsMode"]
        got = lms.lms_verify(pub, bytes.fromhex(case["message"]), bytes.fromhex(case["signature"]))
        assert got is case["testPassed"], (case["tcId"], case["reason"])
        ran += 1
        if got:
            verified.append(case["tcId"])
    assert ran == 8
    assert verified == [3, 5], "both published valid signatures must verify; a verifier refusing all scores 6 of 8"


def test_a_valid_vector_fails_when_one_byte_of_it_changes():
    for _, pub, case in _cases():
        if not case["testPassed"]:
            continue
        msg, sig = bytes.fromhex(case["message"]), bytearray.fromhex(case["signature"])
        assert lms.lms_verify(pub, msg, bytes(sig))
        sig[-1] ^= 1
        assert not lms.lms_verify(pub, msg, bytes(sig))
        assert not lms.lms_verify(pub, msg + b"\x00", bytes.fromhex(case["signature"]))


def test_a_tree_and_one_time_keys_of_different_hashes_are_refused():
    """The SHA-256/192 tree of the first group over a SHAKE256/192 or a SHA-256 n = 32 one-time-key type."""
    _, pub, case = next(c for c in _cases() if c[2]["testPassed"])
    for other_ots in (13, 1):            # LMOTS_SHAKE_N24_W1, LMOTS_SHA256_N32_W1
        swapped = pub[:4] + other_ots.to_bytes(4, "big") + pub[8:]
        assert not lms.lms_verify(swapped, bytes.fromhex(case["message"]), bytes.fromhex(case["signature"]))
    assert not lms._same_hash(0x0A, 13) and not lms._same_hash(0x0A, 1) and lms._same_hash(0x0A, 5)
    assert lms._same_hash(0x0F, 9) and lms._same_hash(0x14, 13) and not lms._same_hash(0x0F, 13)


def test_the_rfc9858_tables_match_the_rfc():
    """Typecodes and parameters as RFC 9858 Tables 1 and 2 give them."""
    ots = {code: v[1:] for code, v in lms.LMOTS_VERIFY_TYPES.items()}
    assert ots[5] == ("sha256", 24, 1, 200, 8) and ots[8] == ("sha256", 24, 8, 26, 0)
    assert ots[9] == ("shake256", 32, 1, 265, 7) and ots[12] == ("shake256", 32, 8, 34, 0)
    assert ots[13] == ("shake256", 24, 1, 200, 8) and ots[16] == ("shake256", 24, 8, 26, 0)
    assert sorted(ots) == list(range(1, 17))
    trees = {code: v[1:] for code, v in lms.LMS_VERIFY_TYPES.items()}
    assert sorted(trees) == list(range(5, 0x19))
    assert trees[0x0A] == ("sha256", 24, 5) and trees[0x0E] == ("sha256", 24, 25)
    assert trees[0x0F] == ("shake256", 32, 5) and trees[0x13] == ("shake256", 32, 25)
    assert trees[0x14] == ("shake256", 24, 5) and trees[0x18] == ("shake256", 24, 25)
    assert lms.lms_public_key_length(0x0A) == 48


@pytest.mark.parametrize("lms_type, ots_type", [(0x0A, 5), (0x0F, 9), (0x14, 13)])
def test_rfc9858_sets_are_verified_and_never_signed(lms_type, ots_type):
    with pytest.raises(lms.SignerError):
        lms.LmsKey(lms_type, ots_type, bytes(16), bytes(32))


def test_shake_and_truncated_hashes_are_what_the_rfc_names():
    assert lms._hash("sha256", 24)(b"a", b"b") == hashlib.sha256(b"ab").digest()[:24]
    assert lms._hash("shake256", 32)(b"ab") == hashlib.shake_256(b"ab").digest(32)
    assert lms._hash("shake256", 24)(b"ab") == hashlib.shake_256(b"ab").digest(24)

"""Known answers for the signer.

A signature made from a fixed seed is a fixed value. The values in `vectors/signer_known_answers.json`
were written once; this file checks that the signer still produces them, on whichever Python and
operating system the suite is run.

The second half checks the signer against a verifier written here from the construction in the
module's own docstring, using `hashlib` and nothing from the package. The two share no code, so a
mistake has to be made twice, the same way, to pass.

What this does not show: that the construction is a good one. The vectors were produced by this
package, so they show the output has not changed and that two readings of the description agree.
"""
import hashlib
import json
from pathlib import Path

import pytest

from entrovouch.signer import ALGORITHM, MerkleSigner, verify_signature

VECTORS = json.loads((Path(__file__).parent / "vectors" / "signer_known_answers.json").read_text(encoding="utf-8"))


def _sha3(*parts: bytes) -> bytes:
    d = hashlib.sha3_256()
    for p in parts:
        d.update(p)
    return d.digest()


def _sign(vector: dict) -> tuple[MerkleSigner, dict]:
    signer = MerkleSigner(seed=bytes.fromhex(vector["seed"]), height=vector["height"])
    return signer, signer.sign(bytes.fromhex(vector["message"]), index=vector["leaf_index"])


def _independent_root(message: bytes, sig: dict) -> str:
    """The root a signature leads to, computed from the written construction alone."""
    digest = hashlib.sha3_256(message).digest()
    bits = [(byte >> (7 - k)) & 1 for byte in digest for k in range(8)]
    pairs = []
    for i, bit in enumerate(bits):
        shown, other = bytes.fromhex(sig["ots"][2 * i]), bytes.fromhex(sig["ots"][2 * i + 1])
        pair = (_sha3(shown), other) if bit == 0 else (other, _sha3(shown))
        pairs.extend(pair)
    node, index = _sha3(b"\x00", *pairs), sig["leaf_index"]
    for sibling in sig["auth_path"]:
        s = bytes.fromhex(sibling)
        node = _sha3(b"\x01", node, s) if index % 2 == 0 else _sha3(b"\x01", s, node)
        index //= 2
    return node.hex()


def _independent_public_root(seed: bytes, height: int) -> str:
    """The public root, from the seed, computed from the written construction alone."""
    level = []
    for leaf in range(1 << height):
        parts = [b"\x00"]
        for i in range(256):
            for b in (0, 1):
                secret = _sha3(seed, leaf.to_bytes(4, "big"), i.to_bytes(2, "big"), bytes([b]))
                parts.append(_sha3(secret))
        level.append(_sha3(*parts))
    while len(level) > 1:
        level = [_sha3(b"\x01", level[j], level[j + 1]) for j in range(0, len(level), 2)]
    return level[0].hex()


def test_the_vector_file_is_for_this_algorithm():
    assert VECTORS["algorithm"] == ALGORITHM
    assert len(VECTORS["vectors"]) >= 4


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_a_fixed_seed_gives_the_recorded_signature(vector):
    signer, sig = _sign(vector)
    assert signer.public_root == vector["public_root"]
    assert sig["public_root"] == vector["public_root"]
    assert sig["auth_path"] == vector["auth_path"]
    assert hashlib.sha3_256("".join(sig["ots"]).encode("ascii")).hexdigest() == vector["ots_sha3_256"]
    if "signature" in vector:
        assert sig == vector["signature"]
    assert verify_signature(bytes.fromhex(vector["message"]), sig, expected_root=vector["public_root"])


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_a_verifier_written_from_the_description_agrees(vector):
    _, sig = _sign(vector)
    message = bytes.fromhex(vector["message"])
    assert _independent_root(message, sig) == vector["public_root"]
    assert _independent_public_root(bytes.fromhex(vector["seed"]), vector["height"]) == vector["public_root"]
    # and it tells a different message apart
    assert _independent_root(message + b"x", sig) != vector["public_root"]


def test_the_recorded_signature_verifies_without_the_signer():
    """The stored signature is checked as a reader would check it: public values only."""
    vector = next(v for v in VECTORS["vectors"] if "signature" in v)
    message = bytes.fromhex(vector["message"])
    assert verify_signature(message, vector["signature"], expected_root=vector["public_root"])
    assert _independent_root(message, vector["signature"]) == vector["public_root"]
    assert not verify_signature(message + b"x", vector["signature"], expected_root=vector["public_root"])

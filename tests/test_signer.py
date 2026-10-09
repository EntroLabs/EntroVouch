"""Tests for the hash-based post-quantum signer.

The load-bearing test is `test_public_material_cannot_forge`: nothing an
outsider can legitimately hold (the public root, earlier signatures) is enough
to sign a new message. An HMAC keyed from published material does not have that
property, which is why the signer is hash-based.
"""
import json
import hashlib
import hmac

import pytest

from entrovouch.signer import (
    ALGORITHM, UNSIGNED, MerkleSigner, verify_signature,
    IndexReuse, KeyExhausted, SignerError,
)


@pytest.fixture
def signer(tmp_path):
    # height=3 -> 8 leaves: fast, and small enough to exhaust in a test.
    return MerkleSigner.create(tmp_path / "id.json", height=3)


# ---------------------------------------------------------------- roundtrip
def test_sign_and_verify_roundtrip(signer):
    msg = b"ENTROVOUCH audit report body"
    sig = signer.sign(msg)
    assert sig["algorithm"] == ALGORITHM
    assert verify_signature(msg, sig, expected_root=signer.public_root)


def test_tampered_message_fails(signer):
    sig = signer.sign(b"verdict: CLEAN")
    assert not verify_signature(b"verdict: DIRTY", sig, expected_root=signer.public_root)


def test_tampered_signature_fails(signer):
    msg = b"body"
    sig = signer.sign(msg)
    sig["ots"][0] = "00" * 32
    assert not verify_signature(msg, sig, expected_root=signer.public_root)


def test_wrong_root_rejected(signer, tmp_path):
    other = MerkleSigner.create(tmp_path / "other.json", height=3)
    msg = b"body"
    sig = signer.sign(msg)
    assert not verify_signature(msg, sig, expected_root=other.public_root)


# ------------------------------------------------------- the core property
def test_public_material_cannot_forge(signer):
    """An attacker holding the public root and an earlier signature cannot
    sign a NEW message."""
    real_msg = b"audit of repo A"
    real_sig = signer.sign(real_msg)
    root = signer.public_root

    # Everything an outsider could legitimately have.
    public_only = json.loads(json.dumps(real_sig))
    forged_msg = b"audit of repo B - CLEAN, definitely"

    # Reusing the captured signature verbatim on a new message must fail.
    assert not verify_signature(forged_msg, public_only, expected_root=root)

    # Replaying it under a different leaf index must also fail.
    replay = json.loads(json.dumps(real_sig))
    replay["leaf_index"] = 1
    assert not verify_signature(forged_msg, replay, expected_root=root)
    assert not verify_signature(real_msg, replay, expected_root=root)


def test_a_mac_keyed_by_public_text_is_not_accepted(signer):
    """A forgery from public material: derive an HMAC key from the published
    Covenant string and mint a 'signature'. The verifier must not accept it in
    any form."""
    covenant = "Optimize systems for people, not margin extraction. One Covenant. Always."
    body = b'{"verdict":"CLEAN"}'
    legacy_key = hashlib.sha3_256(covenant.encode()).digest()
    legacy_sig = hmac.new(legacy_key, body, hashlib.sha3_256).hexdigest()

    assert not verify_signature(body, {"algorithm": ALGORITHM, "ots": legacy_sig})
    assert not verify_signature(
        body,
        {"algorithm": "HMAC-SHA3-256", "signature": legacy_sig},
        expected_root=signer.public_root,
    )


# ------------------------------------------------- one-time key discipline
def test_index_reuse_refused(signer):
    signer.sign(b"first")
    with pytest.raises(IndexReuse):
        signer.sign(b"second", index=0)


def test_key_exhaustion_is_an_error_not_a_wrap(signer):
    for i in range(8):            # height=3 -> exactly 8 leaves
        signer.sign(f"report {i}".encode())
    with pytest.raises(KeyExhausted):
        signer.sign(b"one too many")


def test_every_leaf_verifies_under_one_root(tmp_path):
    s = MerkleSigner.create(tmp_path / "k.json", height=3)
    root = s.public_root
    for i in range(8):
        msg = f"report {i}".encode()
        assert verify_signature(msg, s.sign(msg), expected_root=root)


# ----------------------------------------------------------- key lifecycle
def test_create_refuses_to_clobber(tmp_path):
    p = tmp_path / "k.json"
    MerkleSigner.create(p, height=3)
    with pytest.raises(SignerError):
        MerkleSigner.create(p, height=3)


def test_index_persists_across_reload(tmp_path):
    p = tmp_path / "k.json"
    s = MerkleSigner.create(p, height=3)
    s.sign(b"a")
    s.sign(b"b")
    reloaded = MerkleSigner.load(p)
    assert reloaded.next_index == 2
    assert reloaded.public_root == s.public_root
    # A fresh process must not be able to re-use a spent index.
    with pytest.raises(IndexReuse):
        reloaded.sign(b"replay", index=1)


def test_signing_is_deterministic_for_a_given_leaf(tmp_path):
    """Same seed, same leaf -> byte-identical signature.

    The clone is IN-MEMORY (path=None) and that is the point, not a
    convenience. Determinism is a property of the key derivation, not of the
    state file.

    A persisted signer must reserve its leaf on disk before returning a
    signature. An in-memory signer reserves nothing and is the right object
    for asking what the crypto does.
    """
    a = MerkleSigner.create(tmp_path / "a.json", height=3)
    clone = MerkleSigner(seed=a.seed, height=a.height, next_index=0, path=None)
    assert a.sign(b"x", index=0) == clone.sign(b"x", index=0)


def test_persisted_signer_without_state_refuses_clearly(tmp_path):
    """A missing state file is a SignerError naming the remedy, never an OSError.

    `sign()` reloads the state file to reserve a leaf before returning. A
    handle whose file does not exist must say so and name both remedies: a raw
    FileNotFoundError from inside the reload is a crash a reader cannot act on.
    """
    ghost = MerkleSigner(seed=b"\x07" * 32, height=3, next_index=0,
                         path=tmp_path / "never-written.json")
    with pytest.raises(SignerError) as e:
        ghost.sign(b"x")
    msg = str(e.value)
    assert "does not exist" in msg
    assert "create(" in msg and "path=None" in msg, "the error must name both remedies"


# --------------------------------------------------------- malformed input
@pytest.mark.parametrize("mutate", [
    lambda s: s.pop("ots"),
    lambda s: s.update(ots=s["ots"][:10]),
    lambda s: s.update(auth_path=[]),
    lambda s: s.update(leaf_index=999),
    lambda s: s.update(algorithm="HMAC-SHA3-256"),
])
def test_malformed_signature_returns_false_not_exception(signer, mutate):
    msg = b"body"
    sig = signer.sign(msg)
    mutate(sig)
    assert verify_signature(msg, sig, expected_root=signer.public_root) is False


def test_unsigned_constant_is_explicit():
    assert "NOT attested" in UNSIGNED

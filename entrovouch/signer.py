#!/usr/bin/env python3
"""
ENTROVOUCH — hash-based post-quantum signer (Lamport-Merkle over SHA3-256).

WHY THIS EXISTS
---------------
Until 2026-08-14 this package "signed" its audit reports with
`HMAC-SHA3-256(sha3_256(covenant_text), body)` where `covenant_text` defaulted
to a **string literal published in this repository**. That is not a signature.
Anyone who read the source could derive the key and mint a report that passed
`verify_report()` — demonstrated by execution before this module was written:
a fabricated CLEAN verdict for a codebase nobody ever audited verified True.

The distinction the old code lost is one this estate already states correctly
elsewhere (`ENTROAUDIT/claim_manifest.py`): a locally-keyed MAC proves *this
workspace wrote it*; it can never prove *this is genuine* to a third party.
ENTROVOUCH's whole product claim is third-party verifiability, so it needs the
asymmetric property: a verifier holding only public material must be unable to
produce a signature.

WHY HASH-BASED AND NOT ML-DSA
-----------------------------
- Post-quantum by construction. Security rests only on the preimage and
  collision resistance of SHA3-256 — no lattice assumption, no number theory.
  This package's own CBOM classifier already scores "Lamport OTS (hash-based)"
  and "Merkle/XMSS" as SAFE, so the tool is consistent with its own policy.
- Pure stdlib. This repo is the ONE public artifact in the estate and it has
  zero dependencies on purpose; the no-egress claim is auditable partly
  *because* there is nothing vendored to hide in. Importing a lattice library
  (or vendoring ENTROAUTH's ML-DSA) would trade the strongest property this
  package has for a shorter signature.
- The cost is honest and stated: signatures are ~16 KB, and each leaf key is
  ONE-TIME. Both are enforced below rather than left to the caller's care.

CONSTRUCTION
------------
Lamport one-time signatures over the 256-bit SHA3-256 digest, with the
per-report public keys committed into a Merkle tree whose root is the signer's
long-lived public identity.

  sk[i][b]  = SHA3-256(master_seed || leaf_index || i || b)      (never stored)
  pk[i][b]  = SHA3-256(sk[i][b])
  leaf      = SHA3-256(pk[0][0] || pk[0][1] || ... || pk[255][1])
  root      = Merkle root over 2**height leaves

  signature = for each bit i of the message digest:
                  sk[i][bit_i]        (the revealed preimage)
                  pk[i][1 - bit_i]    (the unrevealed side's hash)
              + the Merkle authentication path + leaf index

A verifier holding only `root` recomputes each pk pair, rebuilds the leaf,
walks the auth path, and checks it lands on `root`. Producing that without the
master seed requires inverting SHA3-256.

ONE-TIME DISCIPLINE
-------------------
Signing twice under one leaf index leaks, on average, half of each Lamport key
pair and makes existential forgery practical. `MerkleSigner` therefore persists
its used-index high-water mark alongside the seed and REFUSES to reuse an
index (`KeyExhausted` / `IndexReuse`). This is a hard error, never a warning.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "SignerError", "IndexReuse", "KeyExhausted", "BadSignature",
    "MerkleSigner", "verify_signature", "ALGORITHM", "UNSIGNED",
]

ALGORITHM = "Lamport-Merkle-SHA3-256 (hash-based, post-quantum)"
UNSIGNED = "UNSIGNED - content hash only, origin NOT attested"

_DIGEST_BITS = 256
_HASH_LEN = 32

# Domain separation (RFC 6962 / RFC 8391 practice). Without distinct tags for
# leaves and internal nodes, an internal node can be presented as a leaf: the
# classic Merkle second-preimage confusion. Here the leaf preimage is 512
# hashes wide and an internal preimage is two, so the confusion was not
# practically exploitable -- but "not exploitable in this shape" is an argument
# that has to be re-made every time the shape changes, and a one-byte tag
# retires it permanently.
#
# NOTE: these tags change `public_root` for a given seed. That is a BREAKING
# change to signing identity, and it is free exactly once -- before any root is
# published and pinned by a reader. It was taken at that moment, deliberately.
_LEAF_TAG = bytes([0])   # 0x00 - leaf domain
_NODE_TAG = bytes([1])   # 0x01 - internal-node domain

# A hostile or corrupt keyfile must not be able to hang the process: building a
# tree is O(2**height * 512) hashes, so height is bounded on load, not trusted.
_MAX_HEIGHT = 20


class SignerError(Exception):
    """Base class for signer failures."""


class IndexReuse(SignerError):
    """Refused to sign twice under one one-time key index."""


class KeyExhausted(SignerError):
    """Every leaf of this Merkle tree has been used."""


class BadSignature(SignerError):
    """Signature is malformed (structurally invalid, not merely wrong)."""


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha3_256()
    for p in parts:
        d.update(p)
    return d.digest()


def _bits(digest: bytes) -> list[int]:
    """Message digest -> 256 bits, most-significant-first within each byte."""
    return [(byte >> (7 - k)) & 1 for byte in digest for k in range(8)]


def _sk_element(seed: bytes, leaf: int, i: int, b: int) -> bytes:
    """Derive one Lamport secret element. The full secret key is never stored."""
    return _h(seed, leaf.to_bytes(4, "big"), i.to_bytes(2, "big"), bytes([b]))


def _leaf_commitment(seed: bytes, leaf: int) -> bytes:
    parts = [_LEAF_TAG]
    for i in range(_DIGEST_BITS):
        parts.append(_h(_sk_element(seed, leaf, i, 0)))
        parts.append(_h(_sk_element(seed, leaf, i, 1)))
    return _h(*parts)


def _merkle_root(leaves: list[bytes]) -> bytes:
    level = leaves
    while len(level) > 1:
        level = [_h(_NODE_TAG, level[j], level[j + 1])
                 for j in range(0, len(level), 2)]
    return level[0]


def _auth_path(leaves: list[bytes], index: int) -> list[str]:
    """Sibling hashes from the leaf up to (not including) the root."""
    path: list[str] = []
    level, idx = leaves, index
    while len(level) > 1:
        sibling = idx ^ 1
        path.append(level[sibling].hex())
        level = [_h(_NODE_TAG, level[j], level[j + 1])
                 for j in range(0, len(level), 2)]
        idx //= 2
    return path


@dataclass
class MerkleSigner:
    """A long-lived signing identity backed by 2**height one-time leaves.

    The keyfile holds the master seed, the tree height, and the next unused
    index. It is secret material: callers must keep it out of version control.
    `public_root` is the only value a verifier needs.
    """

    seed: bytes
    height: int = 10
    next_index: int = 0
    path: Path | None = None
    # Building the tree costs ~2**height * 1024 SHA3 ops, so it is computed once
    # per process and reused. Excluded from repr/compare: it is derived state.
    _leaf_cache: list[bytes] | None = None

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, path: Path, height: int = 10) -> "MerkleSigner":
        """Generate a NEW identity. Refuses to clobber an existing keyfile."""
        if path.exists():
            raise SignerError(
                f"{path} already exists - refusing to overwrite a signing key. "
                "Delete it deliberately if the identity is genuinely being retired."
            )
        signer = cls(seed=os.urandom(32), height=height, next_index=0, path=path)
        signer._save()
        return signer

    @classmethod
    def load(cls, path: Path) -> "MerkleSigner":
        raw = json.loads(path.read_text(encoding="utf-8"))
        h = int(raw["height"])
        if not (1 <= h <= _MAX_HEIGHT):
            raise SignerError(
                f"keyfile height {h} outside 1..{_MAX_HEIGHT}; refusing to build "
                "a tree of that size (a corrupt or hostile keyfile must fail, "
                "not hang)"
            )
        return cls(
            seed=bytes.fromhex(raw["seed"]),
            height=h,
            next_index=int(raw["next_index"]),
            path=path,
        )

    def _save(self) -> None:
        if self.path is None:
            return
        # Write-then-replace: a truncating in-place write that fails mid-encode
        # would destroy the identity outright.
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(
                {"seed": self.seed.hex(), "height": self.height,
                 "next_index": self.next_index},
                indent=2,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    # -- keys --------------------------------------------------------------
    @property
    def leaf_count(self) -> int:
        return 1 << self.height

    def _leaves(self) -> list[bytes]:
        if self._leaf_cache is None:
            self._leaf_cache = [
                _leaf_commitment(self.seed, i) for i in range(self.leaf_count)
            ]
        return self._leaf_cache

    @property
    def public_root(self) -> str:
        """The signer's public identity. Safe to publish; safe to pin."""
        return _merkle_root(self._leaves()).hex()

    @property
    def algorithm(self) -> str:
        """The scheme this signer uses, readable BEFORE anything is signed.

        Exposed 2026-08-21 so `audit()` can write the algorithm name into the
        body it then signs. Previously the name was read back off the produced
        signature and attached afterwards, which put it OUTSIDE the signed
        bytes -- and a field a reader relies on to check a post-quantum claim
        cannot be one anybody can edit without detection.
        """
        return ALGORITHM

    # -- signing -----------------------------------------------------------
    def sign(self, message: bytes, index: int | None = None) -> dict:
        """Sign `message` under the next unused one-time leaf.

        Passing `index` explicitly is allowed only for a leaf not yet used;
        reuse raises rather than silently degrading the key to forgeable.
        """
        idx = self.next_index if index is None else index
        if idx >= self.leaf_count:
            raise KeyExhausted(
                f"all {self.leaf_count} one-time keys used; create a new identity"
            )
        if idx < self.next_index:
            raise IndexReuse(
                f"leaf {idx} already used (next unused is {self.next_index}); "
                "signing twice under one Lamport key enables forgery"
            )

        # RESERVE THE INDEX ON DISK BEFORE REVEALING ANY SECRET MATERIAL.
        # The previous order was: sign, then persist. A crash, a full disk, or a
        # kill between those two steps left the used index unrecorded, so the
        # next process reused it -- and reuse of a Lamport leaf leaks half of
        # each key pair and makes forgery practical. NIST SP 800-208 treats this
        # crash-consistency requirement as the defining hazard of stateful
        # hash-based signatures, not an implementation detail.
        #
        # Failing forward (burning an index on an error) costs one signature out
        # of 2**height. Failing backward costs the identity.
        _previous = self.next_index
        self.next_index = idx + 1
        try:
            self._save()
        except Exception:
            self.next_index = _previous
            raise

        bits = _bits(hashlib.sha3_256(message).digest())
        reveal: list[str] = []
        for i, b in enumerate(bits):
            reveal.append(_sk_element(self.seed, idx, i, b).hex())
            reveal.append(_h(_sk_element(self.seed, idx, i, 1 - b)).hex())

        sig = {
            "algorithm": ALGORITHM,
            "public_root": self.public_root,
            "leaf_index": idx,
            "height": self.height,
            "ots": reveal,
            "auth_path": _auth_path(self._leaves(), idx),
        }
        return sig


def verify_signature(message: bytes, sig: dict, expected_root: str | None = None) -> bool:
    """Verify a signature using ONLY public material.

    `expected_root` is the caller's pinned identity. Omitting it checks that the
    signature is internally consistent but NOT who produced it - which is the
    exact confusion this module exists to remove, so callers verifying a report
    from a third party must always pass it.
    """
    try:
        if sig.get("algorithm") != ALGORITHM:
            return False
        ots = sig["ots"]
        if not isinstance(ots, list) or len(ots) != _DIGEST_BITS * 2:
            raise BadSignature(f"expected {_DIGEST_BITS * 2} OTS elements, got {len(ots)}")
        idx = int(sig["leaf_index"])
        height = int(sig["height"])
        auth = sig["auth_path"]
        if len(auth) != height:
            raise BadSignature(f"auth path length {len(auth)} != height {height}")
        if not (1 <= height <= _MAX_HEIGHT):
            raise BadSignature(f"height {height} outside 1..{_MAX_HEIGHT}")
        if not (0 <= idx < (1 << height)):
            raise BadSignature("leaf index outside tree")

        root = sig["public_root"]
        if expected_root is not None and root != expected_root:
            return False

        bits = _bits(hashlib.sha3_256(message).digest())

        # Rebuild the leaf commitment from revealed preimages + supplied hashes.
        parts: list[bytes] = []
        for i, b in enumerate(bits):
            revealed = bytes.fromhex(ots[2 * i])
            other = bytes.fromhex(ots[2 * i + 1])
            if len(revealed) != _HASH_LEN or len(other) != _HASH_LEN:
                raise BadSignature("OTS element is not a 32-byte value")
            hashed = _h(revealed)
            parts.append(hashed if b == 0 else other)
            parts.append(other if b == 0 else hashed)
        node = _h(_LEAF_TAG, *parts)

        # Walk the authentication path to the root.
        for sibling_hex in auth:
            sibling = bytes.fromhex(sibling_hex)
            node = (_h(_NODE_TAG, node, sibling) if idx % 2 == 0
                    else _h(_NODE_TAG, sibling, node))
            idx //= 2

        return node.hex() == root
    except BadSignature:
        return False
    except (KeyError, ValueError, TypeError):
        return False

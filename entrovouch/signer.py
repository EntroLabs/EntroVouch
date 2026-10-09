#!/usr/bin/env python3
"""
ENTROVOUCH hash-based signer (Lamport-Merkle over SHA3-256).

WHY A SIGNATURE AND NOT A MAC
-----------------------------
A MAC keyed by anything the verifier can also hold proves only that someone with
that key wrote the message. It can never prove to a third party who that was. This
package's product claim is third-party verifiability, so it needs the asymmetric
property: a verifier holding only public material must be unable to produce a
signature.

WHY HASH-BASED
--------------
- Post-quantum by construction. Security rests only on the preimage and
  collision resistance of SHA3-256: no lattice assumption, no number theory.
  This package's own CBOM classifier scores hash-based signatures as SAFE, so
  the tool is consistent with its own policy.
- Pure standard library. This package has zero dependencies on purpose; the
  no-egress claim is auditable partly because there is nothing vendored to hide
  in. A lattice library would trade that property for a shorter signature.
- The cost is stated: signatures are about 16 KB, and each leaf key is ONE-TIME.
  Both are enforced below rather than left to the caller's care.

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
import re
from dataclasses import dataclass, field
from contextlib import nullcontext
import threading
from ._state_io import state_lock, atomic_write, read_state_text, remove_stale_temps
from pathlib import Path

__all__ = [
    "SignerError", "IndexReuse", "KeyExhausted", "BadSignature",
    "MerkleSigner", "verify_signature", "ALGORITHM", "UNSIGNED",
]

ALGORITHM = "Lamport-Merkle-SHA3-256 (hash-based, post-quantum)"
UNSIGNED = "UNSIGNED - content hash only, origin NOT attested"

_DIGEST_BITS = 256
_HASH_LEN = 32
# A signature has exactly these fields, integers that are integers, and 32-byte values
# written as 64 lower-case hex digits. One signature has one encoding.
_SIG_FIELDS = frozenset({"algorithm", "public_root", "leaf_index", "height", "ots", "auth_path"})
_HEX32 = re.compile(r"[0-9a-f]{64}")


def _is_hex32(value) -> bool:
    return isinstance(value, str) and _HEX32.fullmatch(value) is not None

# Domain separation (RFC 6962 / RFC 8391 practice). Without distinct tags for leaves
# and internal nodes, an internal node can be presented as a leaf: the classic Merkle
# second-preimage confusion. A one-byte tag rules it out whatever shape the leaf and
# node preimages have.
#
# These tags are part of what `public_root` commits to: changing one changes every
# root, which breaks every identity a reader has pinned.
_LEAF_TAG = bytes([0])   # 0x00 - leaf domain
_NODE_TAG = bytes([1])   # 0x01 - internal-node domain

# A hostile or corrupt keyfile must not be able to hang the process: building a
# tree is O(2**height * 512) hashes, so height is bounded on load, not trusted.
_MAX_HEIGHT = 20
# the tallest tree a key may be made or loaded with: signing builds every leaf once per process, and a height-16
# tree (65,536 one-time keys) takes about a minute; a verifier still accepts signatures up to _MAX_HEIGHT
_MAX_KEY_HEIGHT = 16


class SignerError(Exception):
    """Base class for signer failures."""


class IndexReuse(SignerError):
    """Refused to sign twice under one one-time key index."""


class KeyExhausted(SignerError):
    """Every leaf of this Merkle tree has been used."""


class BadSignature(SignerError):
    """Signature is malformed (structurally invalid, not merely wrong)."""


def _refuse_second_name(path: Path) -> None:
    """A hard link gives one state file two names. The lock follows the name and a write replaces the file under
    one name only, so two names can hand out the same leaf. Refused."""
    try:
        if os.stat(path).st_nlink > 1:
            raise SignerError(f"signing state {path} has more than one name (a hard link); a one-time key must have "
                              "exactly one, or two signers can use the same leaf. Keep one name and remove the others.")
    except FileNotFoundError:
        return


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
    _thread_lock: object = field(default_factory=threading.RLock, repr=False, compare=False)

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, path: Path, height: int = 10) -> "MerkleSigner":
        """Generate a NEW identity. Refuses to clobber an existing keyfile."""
        path = Path(path).resolve()
        if type(height) is not int or not 1 <= height <= _MAX_KEY_HEIGHT:
            raise SignerError(f'invalid tree height (1..{_MAX_KEY_HEIGHT})')
        with state_lock(path):
            if path.exists():
                raise SignerError(f'{path} already exists; refusing to overwrite a signing key')
            signer = cls(seed=os.urandom(32), height=height, next_index=0, path=path)
            signer._save()
        return signer

    @classmethod
    def load(cls, path: Path) -> "MerkleSigner":
        try:
            raw = json.loads(read_state_text(path))
        except ValueError:
            raise SignerError('malformed signing state: not JSON') from None
        if not isinstance(raw, dict) or set(raw) != {"seed", "height", "next_index"}:
            raise SignerError('malformed signing state: expected exactly seed, height and next_index')
        h = raw["height"]
        if type(h) is not int:
            raise SignerError('malformed signing state: height is not an integer')
        if not (1 <= h <= _MAX_KEY_HEIGHT):
            raise SignerError(
                f"keyfile height {h} outside 1..{_MAX_KEY_HEIGHT}; refusing to build "
                "a tree of that size (a corrupt or hostile keyfile must fail, "
                "not hang)"
            )
        if not _is_hex32(raw['seed']):
            raise SignerError('malformed signing state: the seed is not 64 lower-case hex digits')
        seed = bytes.fromhex(raw['seed'])
        next_index = raw['next_index']
        if len(seed) != 32 or type(next_index) is not int or not 0 <= next_index <= (1 << h):
            raise SignerError('malformed signing state')
        return cls(
            seed=seed,
            height=h,
            next_index=next_index,
            path=Path(path).resolve(),
        )

    def _save(self) -> None:
        if self.path is None:
            return
        # Write-then-replace: a truncating in-place write that fails mid-encode
        # would destroy the identity outright.
        remove_stale_temps(self.path)
        atomic_write(self.path,
            json.dumps(
                {"seed": self.seed.hex(), "height": self.height,
                 "next_index": self.next_index},
                indent=2,
            ).encode('utf-8'),
        )

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

        `audit()` writes the algorithm name into the body it then signs, so the
        name a reader relies on is inside the signed bytes rather than attached
        afterwards where anybody could edit it without detection.
        """
        return ALGORITHM

    # -- signing -----------------------------------------------------------
    def sign(self, message: bytes, index: int | None = None) -> dict:
        """Sign `message` under the next unused one-time leaf.

        Passing `index` explicitly is allowed only for a leaf not yet used;
        reuse raises rather than silently degrading the key to forgeable.
        """
        with self._thread_lock:
            with state_lock(self.path) if self.path is not None else nullcontext():
                if self.path is not None:
                    # A missing state file is reported with its remedies, never as a
                    # raw FileNotFoundError from inside json. It is NOT created here:
                    # `create()` refuses to overwrite a signing key, and provisioning
                    # one on an arbitrary path would defeat that. A signer with no
                    # persisted state is legitimate (path=None) but is a different
                    # object, and the caller has to say which one they meant.
                    if not self.path.exists():
                        raise SignerError(
                            f"signing state {self.path} does not exist. One-time "
                            "signatures reserve their leaf on disk before the "
                            "signature is returned, so a persisted signer needs "
                            "its state file. Use MerkleSigner.create(path) to "
                            "provision one, or MerkleSigner(..., path=None) for "
                            "an in-memory signer that reserves nothing."
                        )
                    _refuse_second_name(self.path)
                    latest = type(self).load(self.path)
                    if latest.seed != self.seed or latest.height != self.height:
                        raise SignerError('signing identity changed on disk')
                    if latest.next_index < self.next_index:
                        raise IndexReuse('signing state rolled back since this handle loaded')
                    self.next_index = latest.next_index
                return self._sign_reserved(message, index)

    def advance(self, count: int) -> int:
        """Mark the next `count` leaves as spent without signing, and persist that.

        Use it after restoring the key file from a backup, or before a second copy
        of the key signs anywhere: every leaf a lost or copied state file may have
        used must never be used again, and nothing in a signature can tell a
        verifier that a leaf was reused. Advance by at least the number of
        signatures that could have been made since the copy was taken. Returns the
        new next unused index.
        """
        if type(count) is not int or count < 1:
            raise SignerError("count must be a positive integer")
        with self._thread_lock:
            with state_lock(self.path) if self.path is not None else nullcontext():
                if self.path is not None:
                    _refuse_second_name(self.path)
                    latest = type(self).load(self.path)
                    if latest.seed != self.seed or latest.height != self.height:
                        raise SignerError('signing identity changed on disk')
                    self.next_index = max(self.next_index, latest.next_index)
                new = self.next_index + count
                if new > self.leaf_count:
                    raise KeyExhausted(f"advancing by {count} passes the last of {self.leaf_count} leaves")
                _previous = self.next_index
                self.next_index = new
                if self.path is not None:
                    try:
                        self._save()
                    except Exception:
                        self.next_index = _previous
                        raise
        return self.next_index

    def _sign_reserved(self, message: bytes, index: int | None) -> dict:
        if not isinstance(message, bytes):
            raise TypeError('message must be bytes')
        idx = self.next_index if index is None else index
        if type(idx) is not int or idx < 0:
            raise SignerError('leaf index must be a nonnegative integer')
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
        # If the signature were returned first, a crash, a full disk or a kill before the
        # index was recorded would let the next process reuse the leaf, and reuse of a
        # Lamport leaf leaks half of each key pair and makes forgery practical. NIST
        # SP 800-208 treats this crash-consistency requirement as the defining hazard of
        # stateful hash-based signatures, not an implementation detail. This scheme
        # claims no conformance to SP 800-208: the key is a file, and exportable.
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
    if not isinstance(sig, dict) or not isinstance(message, (bytes, bytearray, memoryview)):
        return False
    try:
        if sig.get("algorithm") != ALGORITHM:
            return False
        if set(sig) != _SIG_FIELDS:
            raise BadSignature("a signature has exactly the six documented fields")
        ots = sig["ots"]
        if not isinstance(ots, list) or len(ots) != _DIGEST_BITS * 2:
            raise BadSignature(f"expected {_DIGEST_BITS * 2} OTS elements")
        idx = sig["leaf_index"]
        height = sig["height"]
        if type(idx) is not int or type(height) is not int:
            raise BadSignature("leaf index and height are integers")
        auth = sig["auth_path"]
        if not isinstance(auth, list) or not all(_is_hex32(x) for x in auth) or not all(_is_hex32(x) for x in ots):
            raise BadSignature("every value is 64 lower-case hex digits")
        if not _is_hex32(sig["public_root"]):
            raise BadSignature("the public root is 64 lower-case hex digits")
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

"""
ENTROVOUCH: Leighton-Micali signatures (LMS) and the Hierarchical Signature System (HSS), RFC 8554.

Pure standard library (`hashlib.sha256`). It verifies LMS and HSS signatures for the parameter sets RFC 8554
defines (SHA-256, n = m = 32: LMOTS W1, W2, W4, W8 and LMS heights 5, 10, 15, 20 and 25), and signs with an LMS key whose
one-time keys are derived from a seed as RFC 8554 Appendix A describes.

WHAT IT CLAIMS, AND WHAT IT DOES NOT
------------------------------------
- It reproduces the published test vectors of RFC 8554 Appendix F: both HSS signatures verify, and the second test
  case, whose private keys the RFC gives, is reproduced byte for byte from those keys
  (`tests/test_lms_rfc8554.py`). That is the whole of its conformance claim.
- It is NOT validated under NIST SP 800-208. SP 800-208 permits LMS signing only inside a hardware cryptographic
  module that holds the state; this module keeps its state in a file on disk, where a copy or a restore from backup
  can bring a used one-time key back.
- It does not replace the signer that signs reports. Reports are signed by `entrovouch.signer` (Lamport-Merkle over
  SHA3-256), which claims conformance to no standard. Nothing in the report format uses this module.

ONE-TIME KEYS
-------------
Each leaf q of an LMS tree is a one-time key: two signatures under one q reveal enough of that key to forge. A key
with a state file records the next unused q on disk BEFORE a signature is computed, refuses an explicit q below it
(`IndexReuse`), refuses a q past the last leaf (`KeyExhausted`), and refuses a state file that moved backwards while
this handle has it loaded. Restoring a state file from a copy defeats this, as it does for every file-held stateful key: after a
restore, call `advance` past every q the copy may have missed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path

from ._state_io import atomic_write, read_state_text, remove_stale_temps, state_lock
from .signer import IndexReuse, KeyExhausted, SignerError, _refuse_second_name

__all__ = [
    "LMOTS_TYPES", "LMS_TYPES", "LmsKey", "lms_verify", "hss_verify", "lms_public_key_length",
    "lms_signature_length", "LMS_SHA256_M32_H5", "LMS_SHA256_M32_H10", "LMOTS_SHA256_N32_W4",
    "LMOTS_SHA256_N32_W8",
]

# RFC 8554 Section 4.1, Table 1: typecode -> (name, n, w, p, ls)
LMOTS_TYPES = {
    1: ("LMOTS_SHA256_N32_W1", 32, 1, 265, 7),
    2: ("LMOTS_SHA256_N32_W2", 32, 2, 133, 6),
    3: ("LMOTS_SHA256_N32_W4", 32, 4, 67, 4),
    4: ("LMOTS_SHA256_N32_W8", 32, 8, 34, 0),
}
# RFC 8554 Section 5.1, Table 2: typecode -> (name, m, h)
LMS_TYPES = {
    5: ("LMS_SHA256_M32_H5", 32, 5),
    6: ("LMS_SHA256_M32_H10", 32, 10),
    7: ("LMS_SHA256_M32_H15", 32, 15),
    8: ("LMS_SHA256_M32_H20", 32, 20),
    9: ("LMS_SHA256_M32_H25", 32, 25),
}
LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8 = 3, 4
LMS_SHA256_M32_H5, LMS_SHA256_M32_H10 = 5, 6

D_PBLC, D_MESG, D_LEAF, D_INTR = b"\x80\x80", b"\x81\x81", b"\x82\x82", b"\x83\x83"
_HSS_MAX_LEVELS = 8          # RFC 8554 Section 6: L is at most 8
# Signing builds the whole tree once per process: 2**h leaves, each p * (2**w - 1) hashes. A height-10 tree with W8
# is about nine million SHA-256 calls (well under a minute); taller trees are verified here, not made.
_MAX_SIGNING_HEIGHT = 10


def _u32(x: int) -> bytes:
    return x.to_bytes(4, "big")


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


def _coef(s: bytes, i: int, w: int) -> int:
    """RFC 8554 Section 3.1.3."""
    return ((1 << w) - 1) & (s[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w)))


def _cksm(s: bytes, n: int, w: int, ls: int) -> bytes:
    """RFC 8554 Section 4.4: the checksum of a hash value, shifted left by ls and written as two bytes."""
    total = sum(((1 << w) - 1) - _coef(s, i, w) for i in range(n * 8 // w))
    return ((total << ls) & 0xFFFF).to_bytes(2, "big")


def _chain(I: bytes, q: bytes, i: int, start: int, stop: int, tmp: bytes) -> bytes:
    """Iterate the LM-OTS chain for digit i from step `start` up to (not including) `stop`."""
    i_bytes = i.to_bytes(2, "big")
    for j in range(start, stop):
        tmp = _h(I, q, i_bytes, bytes([j]), tmp)
    return tmp


def lms_public_key_length(lms_type: int) -> int:
    return 4 + 4 + 16 + LMS_TYPES[lms_type][1]


def _ots_signature_length(ots_type: int) -> int:
    _, n, _, p, _ = LMOTS_TYPES[ots_type]
    return 4 + n * (p + 1)


def lms_signature_length(lms_type: int, ots_type: int) -> int:
    _, m, h = LMS_TYPES[lms_type]
    return 4 + _ots_signature_length(ots_type) + 4 + m * h


def _ots_candidate(I: bytes, q: int, sig: bytes, message: bytes, pub_ots_type: int) -> bytes | None:
    """RFC 8554 Algorithm 4b: the public key a valid LM-OTS signature implies, or None if it is malformed."""
    if len(sig) < 4:
        return None
    ots_type = int.from_bytes(sig[:4], "big")
    if ots_type != pub_ots_type or ots_type not in LMOTS_TYPES:
        return None
    _, n, w, p, ls = LMOTS_TYPES[ots_type]
    if len(sig) != 4 + n * (p + 1):
        return None
    c = sig[4:4 + n]
    qb = _u32(q)
    digest = _h(I, qb, D_MESG, c, message)
    digits = digest + _cksm(digest, n, w, ls)
    z = []
    for i in range(p):
        a = _coef(digits, i, w)
        y = sig[4 + n + i * n:4 + n + (i + 1) * n]
        z.append(_chain(I, qb, i, a, (1 << w) - 1, y))
    return _h(I, qb, D_PBLC, *z)


def _parse_lms_public_key(pub: bytes):
    if len(pub) < 8:
        return None
    lms_type = int.from_bytes(pub[:4], "big")
    ots_type = int.from_bytes(pub[4:8], "big")
    if lms_type not in LMS_TYPES or ots_type not in LMOTS_TYPES or len(pub) != lms_public_key_length(lms_type):
        return None
    return lms_type, ots_type, pub[8:24], pub[24:]


def lms_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8554 Algorithm 6a. True only for a valid signature of `message` under `public_key`."""
    parsed = _parse_lms_public_key(bytes(public_key))
    if parsed is None or not isinstance(message, (bytes, bytearray)):
        return False
    lms_type, ots_type, I, T1 = parsed
    sig = bytes(signature)
    _, m, h = LMS_TYPES[lms_type]
    if len(sig) < 8:
        return False
    q = int.from_bytes(sig[:4], "big")
    if int.from_bytes(sig[4:8], "big") != ots_type:
        return False
    ots_len = _ots_signature_length(ots_type)
    if len(sig) < 4 + ots_len + 4:
        return False
    if int.from_bytes(sig[4 + ots_len:8 + ots_len], "big") != lms_type:
        return False
    if q >= (1 << h) or len(sig) != lms_signature_length(lms_type, ots_type):
        return False
    kc = _ots_candidate(I, q, sig[4:4 + ots_len], bytes(message), ots_type)
    if kc is None:
        return False
    path = sig[8 + ots_len:]
    node = (1 << h) + q
    tmp = _h(I, _u32(node), D_LEAF, kc)
    i = 0
    while node > 1:
        sibling = path[i * m:(i + 1) * m]
        if node & 1:
            tmp = _h(I, _u32(node // 2), D_INTR, sibling, tmp)
        else:
            tmp = _h(I, _u32(node // 2), D_INTR, tmp, sibling)
        node //= 2
        i += 1
    return hmac.compare_digest(tmp, T1)


def hss_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8554 Section 6.3: verify an HSS signature against an HSS public key (u32 L || LMS public key)."""
    pub, sig = bytes(public_key), bytes(signature)
    if len(pub) < 4 or len(sig) < 4 or not isinstance(message, (bytes, bytearray)):
        return False
    levels = int.from_bytes(pub[:4], "big")
    nspk = int.from_bytes(sig[:4], "big")
    if not 1 <= levels <= _HSS_MAX_LEVELS or nspk + 1 != levels:
        return False
    key, at = pub[4:], 4
    for _ in range(nspk):
        part = _split_lms_signature(sig, at)
        if part is None:
            return False
        lms_sig, at = part
        child = _split_lms_public_key(sig, at)
        if child is None:
            return False
        child_pub, at = child
        if not lms_verify(key, child_pub, lms_sig):
            return False
        key = child_pub
    part = _split_lms_signature(sig, at)
    if part is None:
        return False
    lms_sig, at = part
    return at == len(sig) and lms_verify(key, bytes(message), lms_sig)


def _split_lms_signature(buf: bytes, at: int):
    """The LMS signature that starts at `at`, read by its own type fields, and where the next value starts."""
    if len(buf) < at + 8:
        return None
    ots_type = int.from_bytes(buf[at + 4:at + 8], "big")
    if ots_type not in LMOTS_TYPES:
        return None
    type_at = at + 4 + _ots_signature_length(ots_type)
    if len(buf) < type_at + 4:
        return None
    lms_type = int.from_bytes(buf[type_at:type_at + 4], "big")
    if lms_type not in LMS_TYPES:
        return None
    end = at + lms_signature_length(lms_type, ots_type)
    if len(buf) < end:
        return None
    return buf[at:end], end


def _split_lms_public_key(buf: bytes, at: int):
    if len(buf) < at + 4:
        return None
    lms_type = int.from_bytes(buf[at:at + 4], "big")
    if lms_type not in LMS_TYPES:
        return None
    end = at + lms_public_key_length(lms_type)
    if len(buf) < end:
        return None
    return buf[at:end], end


@dataclass
class LmsKey:
    """An LMS private key whose one-time keys are derived from `seed` and `I` (RFC 8554 Appendix A).

    With `path`, the key and the next unused leaf are kept in that file, and every signature reserves its leaf there
    before it is computed. Without it the key lives in memory and reserves nothing beyond this object.
    """

    lms_type: int
    ots_type: int
    I: bytes
    seed: bytes
    next_q: int = 0
    path: Path | None = None
    _tree: dict | None = field(default=None, repr=False, compare=False)
    _thread_lock: object = field(default_factory=threading.RLock, repr=False, compare=False)

    def __post_init__(self):
        if self.lms_type not in LMS_TYPES or self.ots_type not in LMOTS_TYPES:
            raise SignerError("unknown LMS or LM-OTS typecode")
        if LMS_TYPES[self.lms_type][2] > _MAX_SIGNING_HEIGHT:
            raise SignerError(f"signing keys are limited to height {_MAX_SIGNING_HEIGHT}; taller trees are verified only")
        if not isinstance(self.I, bytes) or len(self.I) != 16:
            raise SignerError("I is 16 bytes")
        if not isinstance(self.seed, bytes) or len(self.seed) != 32:
            raise SignerError("the seed is 32 bytes")
        if type(self.next_q) is not int or not 0 <= self.next_q <= self.leaf_count:
            raise SignerError("next_q outside the tree")

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, path: Path, lms_type: int = LMS_SHA256_M32_H5,
               ots_type: int = LMOTS_SHA256_N32_W8) -> "LmsKey":
        """A new key with a fresh seed and I, kept in `path`. Refuses to overwrite an existing file."""
        path = Path(path).resolve()
        with state_lock(path):
            if path.exists():
                raise SignerError(f"{path} already exists; refusing to overwrite a signing key")
            key = cls(lms_type, ots_type, os.urandom(16), os.urandom(32), 0, path)
            key._save()
        return key

    @classmethod
    def load(cls, path: Path) -> "LmsKey":
        try:
            raw = json.loads(read_state_text(path))
        except ValueError:
            raise SignerError("malformed LMS state: not JSON") from None
        if not isinstance(raw, dict) or set(raw) != {"lms_type", "ots_type", "I", "seed", "next_q"}:
            raise SignerError("malformed LMS state: expected exactly lms_type, ots_type, I, seed and next_q")
        try:
            return cls(raw["lms_type"], raw["ots_type"], bytes.fromhex(raw["I"]), bytes.fromhex(raw["seed"]),
                       raw["next_q"], Path(path).resolve())
        except (TypeError, ValueError):
            raise SignerError("malformed LMS state") from None

    def _save(self) -> None:
        if self.path is None:
            return
        remove_stale_temps(self.path)
        atomic_write(self.path, json.dumps({"lms_type": self.lms_type, "ots_type": self.ots_type,
                                            "I": self.I.hex(), "seed": self.seed.hex(),
                                            "next_q": self.next_q}, indent=2).encode("utf-8"))

    # -- keys --------------------------------------------------------------
    @property
    def height(self) -> int:
        return LMS_TYPES[self.lms_type][2]

    @property
    def leaf_count(self) -> int:
        return 1 << self.height

    def _x(self, q: int, i: int) -> bytes:
        """RFC 8554 Appendix A: x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)."""
        return _h(self.I, _u32(q), i.to_bytes(2, "big"), b"\xff", self.seed)

    def _ots_public(self, q: int) -> bytes:
        _, _, w, p, _ = LMOTS_TYPES[self.ots_type]
        qb = _u32(q)
        return _h(self.I, qb, D_PBLC, *(_chain(self.I, qb, i, 0, (1 << w) - 1, self._x(q, i)) for i in range(p)))

    def _nodes(self) -> dict:
        """Every node of the tree, numbered as RFC 8554 Section 5.3 numbers them (root is 1)."""
        if self._tree is None:
            leaves = self.leaf_count
            t = {}
            for q in range(leaves):
                r = leaves + q
                t[r] = _h(self.I, _u32(r), D_LEAF, self._ots_public(q))
            for r in range(leaves - 1, 0, -1):
                t[r] = _h(self.I, _u32(r), D_INTR, t[2 * r], t[2 * r + 1])
            self._tree = t
        return self._tree

    @property
    def public_key(self) -> bytes:
        """u32str(lms_type) || u32str(ots_type) || I || T[1]."""
        return _u32(self.lms_type) + _u32(self.ots_type) + self.I + self._nodes()[1]

    # -- signing -----------------------------------------------------------
    def sign(self, message: bytes, q: int | None = None, randomizer: bytes | None = None) -> bytes:
        """Sign under the next unused leaf, or under an explicit `q` not yet used.

        `randomizer` is the value C, normally fresh random bytes; it is a parameter only so a known-answer test can
        reproduce a published signature. A q is refused once used whatever C is.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        with self._thread_lock:
            with state_lock(self.path) if self.path is not None else nullcontext():
                if self.path is not None:
                    if not self.path.exists():
                        raise SignerError(f"LMS state {self.path} does not exist; use LmsKey.create(path)")
                    _refuse_second_name(self.path)
                    latest = type(self).load(self.path)
                    if (latest.seed, latest.I, latest.lms_type, latest.ots_type) != (
                            self.seed, self.I, self.lms_type, self.ots_type):
                        raise SignerError("signing identity changed on disk")
                    if latest.next_q < self.next_q:
                        raise IndexReuse("LMS state rolled back since this handle loaded")
                    self.next_q = latest.next_q
                use = self.next_q if q is None else q
                if type(use) is not int or use < 0:
                    raise SignerError("q must be a nonnegative integer")
                if use >= self.leaf_count:
                    raise KeyExhausted(f"all {self.leaf_count} one-time keys of this LMS tree are used")
                if use < self.next_q:
                    raise IndexReuse(f"leaf {use} already used (next unused is {self.next_q}); "
                                     "two signatures under one LM-OTS key enable forgery")
                # reserve the leaf on disk before any secret-derived value is computed or returned
                previous = self.next_q
                self.next_q = use + 1
                try:
                    self._save()
                except Exception:
                    self.next_q = previous
                    raise
        return self._sign_at(bytes(message), use, randomizer)

    def advance(self, count: int) -> int:
        """Mark the next `count` leaves spent without signing (after restoring a state file from a copy)."""
        if type(count) is not int or count < 1:
            raise SignerError("count must be a positive integer")
        with self._thread_lock:
            with state_lock(self.path) if self.path is not None else nullcontext():
                if self.path is not None:
                    _refuse_second_name(self.path)
                    self.next_q = max(self.next_q, type(self).load(self.path).next_q)
                if self.next_q + count > self.leaf_count:
                    raise KeyExhausted(f"advancing by {count} passes the last of {self.leaf_count} leaves")
                previous = self.next_q
                self.next_q += count
                try:
                    self._save()
                except Exception:
                    self.next_q = previous
                    raise
        return self.next_q

    def _sign_at(self, message: bytes, q: int, randomizer: bytes | None) -> bytes:
        _, n, w, p, ls = LMOTS_TYPES[self.ots_type]
        c = os.urandom(n) if randomizer is None else bytes(randomizer)
        if len(c) != n:
            raise SignerError(f"the randomizer C is {n} bytes")
        qb = _u32(q)
        digest = _h(self.I, qb, D_MESG, c, message)
        digits = digest + _cksm(digest, n, w, ls)
        ys = [_chain(self.I, qb, i, 0, _coef(digits, i, w), self._x(q, i)) for i in range(p)]
        nodes = self._nodes()
        node, path = self.leaf_count + q, []
        while node > 1:
            path.append(nodes[node ^ 1])
            node //= 2
        return qb + _u32(self.ots_type) + c + b"".join(ys) + _u32(self.lms_type) + b"".join(path)

"""
ENTROVOUCH issuance log: an append-only record of the reports an issuer enters, kept as a tiled transparency log.
A report signed and never entered leaves no trace in it.

Each entry is one line naming a report, `entrovouch/issuance/v1 <findings_digest> <content_hash>` and a newline,
both values 64 lower-case hex digits. The log is laid out as C2SP tlog-tiles describes it (c2sp.org/tlog-tiles):
a signed checkpoint (c2sp.org/tlog-checkpoint, a signed note per c2sp.org/signed-note) at `checkpoint`, hash tiles
of height 8 at `tile/<L>/<N>`, partial tiles at `tile/<L>/<N>.p/<W>`, and entry bundles at `tile/entries/<N>`.
Hashing is the Merkle tree of RFC 9162 Section 2.1.1 over SHA-256; inclusion proofs are generated and verified as
RFC 9162 Section 2.1.3 describes, and consistency proofs as Section 2.1.4 describes for 0 < old size < new size.
At the boundaries (equal sizes, an old size of 0) the rules are the ones `verify_consistency` states.

A buyer holding a report, a proof bundle for it and the issuer's verifier key (vkey) checks the report with
`python -m entrovouch.verify` or `verify_report` (intact, and signed under the report root they pin) and the bundle
with `verify_bundle` (a checkpoint the log key signed includes an entry whose findings digest and content hash are
the report's). Pin the log's origin and vkey through a channel you trust, as you pin the report root: `verify_bundle`
and `verify_log_dir` return the origin and do not compare it with one you expect. Two checkpoints of the same size signed by one key with different
roots are a fork: the key signed two trees that cannot both be true, which happens when the issuer keeps two logs,
when the log key leaked or was copied, and when the log directory was restored from a copy older than a checkpoint
already handed out and then appended to (`detect_fork`). The log has no witnesses: an issuer can show different
buyers different histories, and only buyers who compare checkpoints, or ask for consistency proofs between them, can
detect it.

WHAT IT CLAIMS, AND WHAT IT DOES NOT
------------------------------------
- The checkpoint is signed with this package's signer (Lamport-Merkle over SHA3-256), which claims conformance to no
  standard. signed-note reserves the type byte 0xff for signature types it assigns no identifier, and recommends
  following it with a longer identifier unlikely to collide; the key is 0xff, then a 32-byte algorithm identifier.
  signed-note defines key encodings only for its own types, tells verifiers to ignore signatures from unknown keys,
  and tells clients to reject a note on which no signature from a known key verifies. So a signed-note client that
  does not implement this signature type cannot be given this key, ignores the signature, and rejects the
  checkpoint. This follows from the signed-note rules; no such client was run. Checking these checkpoints needs this
  tool (`verify_bundle`, `verify_log_dir`, `detect_fork`).
- The log key is a separate key from the key that signs reports, and `append` refuses a report signed by the log key.
  Each checkpoint uses one one-time leaf of the log key, so a key of height h signs at most 2**h checkpoints.
  `IssuanceLog.create` makes a key of height 10 unless given `key_height` (at most 16) and signs the empty checkpoint
  with the first leaf, so a new key leaves 2**h - 1 appends. When no leaf is left, `append` raises TlogError and the
  checkpoint is not changed. A log keeps its key: a new key has a new vkey and starts a new log, which nothing signed
  links to the old one, and buyers pin the new vkey.
- The log key is a file and stateful like the report key: a copied or restored copy reuses leaves. A second signature
  under one leaf reveals about half of that leaf's secret values not yet revealed and weakens it toward forgery; each
  further signature under it reveals more, and a few make forging a checkpoint under it practical. Keep one copy;
  advance a restored copy past every leaf the other copy may have used
  (`python -m entrovouch.no_egress_auditor --key PATH --advance-key N`). Do not roll the log directory back either:
  a restored copy older than a checkpoint already handed out, appended to, signs trees that do not extend that
  checkpoint, which is a fork. One key file used for two logs makes them a fork when they share an origin, so
  `IssuanceLog.create` refuses a key file that already exists unless given `reuse_key=True`.
- The tree hashes are checked against the published RFC 6962 test roots for trees of 1 to 8 entries, from
  transparency-dev/merkle `testonly/constants.go` as of commit 77f1b57d7aa25fcd2e51273166b6b2b0e74923b1, and the
  empty tree against SHA-256 of the empty string, as RFC 9162 Section 2.1.1 defines it (`tests/test_tlog.py`). No
  published inclusion or consistency proof vectors have been run: proofs are compared with a reference written in
  the test. No conformance suite for C2SP tlog-tiles or signed-note has been run.
- The log is files in one directory. It is append-only in the sense that this module never rewrites or removes a
  file a checkpoint covers, and never signs a checkpoint smaller than, or inconsistent with, the one it replaces.
  Before it signs, it reads the new tree back from the directory and refuses to sign unless every file it wrote
  holds exactly the bytes written, the stored entries past the last checkpoint are the ones being appended, the
  entries carried from below it hash to the last checkpoint's tile, and the root computed from the stored tiles
  equals the root computed from the last checkpoint's tree and the hashes of those entries. Nothing stops someone with write access
  to the directory from replacing it: that is what the signed checkpoints and `detect_fork` are for.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from pathlib import Path

from ._state_io import atomic_write, state_lock
from .signer import ALGORITHM, MerkleSigner, SignerError, verify_signature

__all__ = [
    "TlogError", "IssuanceLog", "ENTRY_PREFIX", "ALG_ID", "KEY_TYPE", "TILE_HEIGHT",
    "entry_line", "leaf_hash", "node_hash", "merkle_root", "inclusion_path", "consistency_path",
    "verify_inclusion", "verify_consistency", "encode_vkey", "parse_vkey", "verify_checkpoint",
    "verify_bundle", "verify_log_dir", "detect_fork",
]

ENTRY_PREFIX = "entrovouch/issuance/v1"
TILE_HEIGHT = 8
_TILE_WIDTH = 1 << TILE_HEIGHT
KEY_TYPE = 0xFF
ALG_ID = hashlib.sha256(b"entrovouch/lamport-merkle-sha3-256/v1").digest()
BUNDLE_FORMAT = "entrovouch/issuance-proof/v1"
_EMPTY_ROOT = hashlib.sha256(b"").digest()

_HEX64 = re.compile(r"[0-9a-f]{64}")
_ENTRY = re.compile(r"entrovouch/issuance/v1 ([0-9a-f]{64}) ([0-9a-f]{64})\n")
_SIG_PREFIX = "— "                         # the signed-note separator: an em dash and a space
_MAX_SIGNATURES = 64                            # signed-note: verifiers accept at least 16
_OTS_COUNT = 512
_REPORT_TOOLS = ("ENTROVOUCH no-egress auditor", "ENTROVOUCH CBOM generator", "ENTROVOUCH SBOM")


class TlogError(Exception):
    """A log, checkpoint, proof or bundle that does not verify, or an operation the log refuses."""


# ------------------------------------------------------------------------------------------------ hashing
def leaf_hash(entry: bytes) -> bytes:
    """RFC 9162 Section 2.1.1: MTH({d}) = SHA-256(0x00 || d)."""
    return hashlib.sha256(b"\x00" + bytes(entry)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 9162 Section 2.1.1: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


def _mth(leaves, start: int, n: int) -> bytes:
    """MTH of n leaf hashes from `start`, where `leaves(i)` is the hash of leaf i."""
    if n == 0:
        return _EMPTY_ROOT
    if n == 1:
        return leaves(start)
    k = _split(n)
    return node_hash(_mth(leaves, start, k), _mth(leaves, start + k, n - k))


def _memo_mth(hashes: list):
    """MTH over ranges of a list of leaf hashes, each range computed once."""
    memo = {}

    def mth(start: int, n: int) -> bytes:
        if (start, n) not in memo:
            if n <= 1:
                memo[start, n] = _EMPTY_ROOT if n == 0 else hashes[start]
            else:
                k = _split(n)
                memo[start, n] = node_hash(mth(start, k), mth(start + k, n - k))
        return memo[start, n]
    return mth


def merkle_root(hashes: list) -> bytes:
    """MTH over a list of leaf hashes; MTH({}) = SHA-256 of the empty string."""
    return _mth(hashes.__getitem__, 0, len(hashes))


def _path(mth, m: int, start: int, n: int) -> list:
    """RFC 9162 Section 2.1.3.1, PATH(m, D[start:start+n])."""
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return _path(mth, m, start, k) + [mth(start + k, n - k)]
    return _path(mth, m - k, start + k, n - k) + [mth(start, k)]


def _subproof(mth, m: int, start: int, n: int, whole: bool) -> list:
    """RFC 9162 Section 2.1.4.1, SUBPROOF(m, D[start:start+n], b)."""
    if m == n:
        return [] if whole else [mth(start, n)]
    k = _split(n)
    if m <= k:
        return _subproof(mth, m, start, k, whole) + [mth(start + k, n - k)]
    return _subproof(mth, m - k, start + k, n - k, False) + [mth(start, k)]


def inclusion_path(hashes: list, index: int, size: int | None = None) -> list:
    """The inclusion proof for leaf `index` in the tree of the first `size` leaf hashes."""
    size = len(hashes) if size is None else size
    if not 0 <= index < size <= len(hashes):
        raise TlogError("leaf index outside the tree")
    return _path(_memo_mth(hashes), index, 0, size)


def consistency_path(hashes: list, old_size: int, new_size: int | None = None) -> list:
    """The consistency proof from the tree of `old_size` leaves to the tree of `new_size` (empty when old_size is 0
    or equals new_size: there is then nothing to prove)."""
    new_size = len(hashes) if new_size is None else new_size
    if not 0 <= old_size <= new_size <= len(hashes):
        raise TlogError("tree sizes out of order")
    if old_size == 0 or old_size == new_size:
        return []
    return _subproof(_memo_mth(hashes), old_size, 0, new_size, True)


def _is_hash(value) -> bool:
    return isinstance(value, (bytes, bytearray)) and len(value) == 32


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list, root: bytes) -> bool:
    """RFC 9162 Section 2.1.3.2, step by step. `leaf` is the leaf hash."""
    if type(index) is not int or type(size) is not int or index < 0 or not _is_hash(leaf) or not _is_hash(root):
        return False
    if not isinstance(proof, (list, tuple)) or not all(_is_hash(p) for p in proof):
        return False
    if index >= size:                                    # 1
        return False
    fn, sn, r = index, size - 1, bytes(leaf)             # 2
    for p in proof:                                      # 3
        if sn == 0:                                      # 3a
            return False
        if fn & 1 or fn == sn:                           # 3b
            r = node_hash(bytes(p), r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, bytes(p))
        fn >>= 1                                         # 3c
        sn >>= 1
    return sn == 0 and hmac.compare_digest(r, bytes(root))   # 4


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list) -> bool:
    """RFC 9162 Section 2.1.4.2, step by step, for 0 < old_size < new_size. At the boundaries, where Section 2.1.4
    defines no proof: equal sizes are consistent only with equal roots and an empty proof; an old size of 0 is
    consistent with any new tree when the proof is empty, whatever `old_root` is, and never with a non-empty proof.
    The empty tree's root is checked where checkpoints are read, in `verify_checkpoint`. Sizes out of order, a
    malformed hash or a malformed proof give False."""
    if type(old_size) is not int or type(new_size) is not int or not 0 <= old_size <= new_size:
        return False
    if not _is_hash(old_root) or not _is_hash(new_root):
        return False
    if not isinstance(proof, (list, tuple)) or not all(_is_hash(p) for p in proof):
        return False
    if old_size == new_size:
        return len(proof) == 0 and hmac.compare_digest(bytes(old_root), bytes(new_root))
    if old_size == 0:
        return len(proof) == 0
    path = [bytes(p) for p in proof]
    if not path:                                         # 1
        return False
    if old_size & (old_size - 1) == 0:                   # 2: an exact power of two
        path = [bytes(old_root)] + path
    fn, sn = old_size - 1, new_size - 1                  # 3
    while fn & 1:                                        # 4
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]                                    # 5
    for c in path[1:]:                                   # 6
        if sn == 0:                                      # 6a
            return False
        if fn & 1 or fn == sn:                           # 6b
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1                                         # 6c
        sn >>= 1
    return hmac.compare_digest(fr, bytes(old_root)) and hmac.compare_digest(sr, bytes(new_root)) and sn == 0   # 7


# ------------------------------------------------------------------------------------------------ entries
def entry_line(findings_digest: str, content_hash: str) -> bytes:
    """The log entry for one report."""
    if not (isinstance(findings_digest, str) and _HEX64.fullmatch(findings_digest)
            and isinstance(content_hash, str) and _HEX64.fullmatch(content_hash)):
        raise TlogError("findings_digest and content_hash are each 64 lower-case hex digits")
    return f"{ENTRY_PREFIX} {findings_digest} {content_hash}\n".encode("ascii")


def _parse_entry(entry: bytes):
    try:
        m = _ENTRY.fullmatch(entry.decode("ascii"))
    except UnicodeDecodeError:
        m = None
    if m is None:
        raise TlogError("an entry is not an issuance line")
    return m.group(1), m.group(2)


# ------------------------------------------------------------------------------------------------ paths
def _tile_path(n: int) -> str:
    """C2SP tlog-tiles: the index in 3-digit groups, every group but the last prefixed with x."""
    if type(n) is not int or n < 0:
        raise TlogError("tile index is a nonnegative integer")
    digits = str(n)
    digits = "0" * (-len(digits) % 3) + digits
    groups = [digits[i:i + 3] for i in range(0, len(digits), 3)]
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


def _tile_name(level: int, n: int, width: int) -> str:
    base = f"tile/{level}/{_tile_path(n)}"
    return base if width == _TILE_WIDTH else f"{base}.p/{width}"


def _bundle_name(n: int, width: int) -> str:
    base = f"tile/entries/{_tile_path(n)}"
    return base if width == _TILE_WIDTH else f"{base}.p/{width}"


def _level_count(size: int, level: int) -> int:
    """Hashes stored at tile level `level` for a tree of `size` leaves (complete subtrees of 256**level leaves)."""
    return size >> (TILE_HEIGHT * level)


def _tile_width(size: int, level: int, n: int) -> int:
    return min(_TILE_WIDTH, _level_count(size, level) - n * _TILE_WIDTH)


# ------------------------------------------------------------------------------------------------ base64, keys, notes
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    """Standard base64 with padding, canonical only: a value any other encoding of which decodes the same is refused."""
    if not isinstance(text, str) or not text.isascii():
        raise TlogError("not base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise TlogError("not base64") from None
    if _b64(raw) != text:
        raise TlogError("non-canonical base64")
    return raw


def _check_name(name, what: str) -> None:
    """signed-note key names and tlog origins: non-empty, at most 255 bytes, no spaces, plus signs or controls."""
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 255:
        raise TlogError(f"{what} is a non-empty string of at most 255 bytes")
    if any(c.isspace() or c == "+" or ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise TlogError(f"{what} may not contain spaces, plus signs or control characters")


def _encoded_key(root: bytes) -> bytes:
    return bytes([KEY_TYPE]) + ALG_ID + root


def _key_id(keyname: str, encoded_key: bytes) -> bytes:
    return hashlib.sha256(keyname.encode("utf-8") + b"\n" + encoded_key).digest()[:4]


def encode_vkey(keyname: str, public_root: str) -> str:
    """The verifier key `<keyname>+<8 hex key ID>+<base64(0xff || ALG_ID || root)>`."""
    _check_name(keyname, "the key name")
    if not isinstance(public_root, str) or not _HEX64.fullmatch(public_root):
        raise TlogError("the public root is 64 lower-case hex digits")
    enc = _encoded_key(bytes.fromhex(public_root))
    return f"{keyname}+{_key_id(keyname, enc).hex()}+{_b64(enc)}"


def parse_vkey(vkey: str):
    """(keyname, key ID, public root hex) of a verifier key of this package's type. Any other key is refused."""
    if not isinstance(vkey, str):
        raise TlogError("a vkey is a string")
    parts = vkey.split("+", 2)       # the name and the key ID hold no plus sign; base64 may
    if len(parts) != 3:
        raise TlogError("a vkey is <name>+<key ID>+<key>")
    name, kid, key64 = parts
    _check_name(name, "the key name")
    if not re.fullmatch(r"[0-9a-f]{8}", kid):
        raise TlogError("the key ID is 8 lower-case hex digits")
    enc = _unb64(key64)
    if len(enc) != 65 or enc[0] != KEY_TYPE or enc[1:33] != ALG_ID:
        raise TlogError("unknown key type: not this package's signer")
    if _key_id(name, enc).hex() != kid:
        raise TlogError("the key ID does not match the key")
    return name, bytes.fromhex(kid), enc[33:].hex()


def _sig_bytes(sig: dict) -> bytes:
    """A signer signature as bytes: height (1), leaf index (4, big-endian), the OTS values, the authentication path."""
    height = sig["height"]
    out = bytes([height]) + sig["leaf_index"].to_bytes(4, "big")
    out += b"".join(bytes.fromhex(x) for x in sig["ots"])
    return out + b"".join(bytes.fromhex(x) for x in sig["auth_path"])


def _sig_dict(raw: bytes, root_hex: str):
    if len(raw) < 5:
        return None
    height = raw[0]
    if len(raw) != 5 + 32 * (_OTS_COUNT + height):
        return None
    body = raw[5:]
    return {
        "algorithm": ALGORITHM, "public_root": root_hex, "leaf_index": int.from_bytes(raw[1:5], "big"),
        "height": height,
        "ots": [body[32 * i:32 * (i + 1)].hex() for i in range(_OTS_COUNT)],
        "auth_path": [body[32 * (_OTS_COUNT + i):32 * (_OTS_COUNT + i + 1)].hex() for i in range(height)],
    }


def _split_note(note: str):
    """(text, [(name, raw signature)]) of a signed note, or TlogError."""
    if not isinstance(note, str) or not note.endswith("\n"):
        raise TlogError("a signed note is text ending in a newline")
    if any(ord(c) < 0x20 and c != "\n" for c in note) or "\x7f" in note:
        raise TlogError("a signed note may not contain control characters")
    at = note.rfind("\n\n")
    if at == -1:
        raise TlogError("a signed note has a blank line before its signatures")
    text, sigs = note[:at + 1], note[at + 2:]
    lines = sigs.split("\n")[:-1]
    if not lines or len(lines) > _MAX_SIGNATURES:
        raise TlogError("a signed note carries between 1 and 64 signatures")
    parsed = []
    for line in lines:
        if not line.startswith(_SIG_PREFIX):
            raise TlogError("a signature line starts with an em dash and a space")
        fields = line[len(_SIG_PREFIX):].split(" ")
        if len(fields) != 2:
            raise TlogError("a signature line is <dash> <name> <base64>")
        _check_name(fields[0], "the key name")
        parsed.append((fields[0], _unb64(fields[1])))
    return text, parsed


def _verify_note(note: str, vkey: str) -> str:
    """The note's text if a signature by `vkey` verifies. Signatures by other keys are ignored, as signed-note
    requires; one by this key that fails rejects the note."""
    name, kid, root = parse_vkey(vkey)
    text, sigs = _split_note(note)
    verified = False
    for sig_name, raw in sigs:
        if sig_name != name or raw[:4] != kid:
            continue
        sig = _sig_dict(raw[4:], root)
        if sig is None or not verify_signature(text.encode("utf-8"), sig, expected_root=root):
            raise TlogError("a signature by the trusted key does not verify")
        verified = True
    if not verified:
        raise TlogError("no signature by the trusted key")
    return text


def _parse_checkpoint_text(text: str):
    """(origin, size, root) of checkpoint text. Extension lines are refused: this log writes none."""
    lines = text.split("\n")
    if len(lines) != 4 or lines[3] != "":
        raise TlogError("a checkpoint is three lines: origin, size, root")
    origin, size_s, root_s = lines[:3]
    _check_name(origin, "the origin")
    if not re.fullmatch(r"0|[1-9][0-9]*", size_s):
        raise TlogError("the tree size is a decimal with no leading zeros")
    root = _unb64(root_s)
    if len(root) != 32:
        raise TlogError("the root hash is 32 bytes")
    return origin, int(size_s), root


def _checkpoint_text(origin: str, size: int, root: bytes) -> str:
    return f"{origin}\n{size}\n{_b64(root)}\n"


def verify_checkpoint(note: str, vkey: str):
    """(origin, size, root) of a checkpoint signed by `vkey`, or TlogError."""
    origin, size, root = _parse_checkpoint_text(_verify_note(note, vkey))
    if size == 0 and root != _EMPTY_ROOT:
        raise TlogError("an empty tree has the root SHA-256 of the empty string")
    return origin, size, root


# ------------------------------------------------------------------------------------------------ the log
def _read_bundle(data: bytes) -> list:
    entries, at = [], 0
    while at < len(data):
        if at + 2 > len(data):
            raise TlogError("an entry bundle ends inside a length prefix")
        length = int.from_bytes(data[at:at + 2], "big")
        if at + 2 + length > len(data):
            raise TlogError("an entry bundle ends inside an entry")
        entries.append(data[at + 2:at + 2 + length])
        at += 2 + length
    return entries


def _bundle_bytes(entries: list) -> bytes:
    return b"".join(len(e).to_bytes(2, "big") + e for e in entries)


class _Tiles:
    """Read access to a log directory's tiles and bundles as of tree size `size`."""

    def __init__(self, root: Path, size: int):
        self.root, self.size, self._cache, self._memo = Path(root), size, {}, {}

    def _file(self, name: str):
        if name not in self._cache:
            p = self.root / name
            self._cache[name] = p.read_bytes() if p.is_file() else None
        return self._cache[name]

    def _read(self, name, n: int, width: int):
        """(data, width it holds) of the file named for this size's width, else of the full file. A full file next
        to a partial one for a smaller size can be left by an append that stopped before signing, so the file for the
        size being read comes first."""
        data = self._file(name(n, width))
        if data is not None or width == _TILE_WIDTH:
            return data, width
        return self._file(name(n, _TILE_WIDTH)), _TILE_WIDTH

    def tile(self, level: int, n: int) -> list:
        """The hashes of tile `n` at `level`: the tile of this size's width (the full tile when that is 256), else
        the full tile."""
        width = _tile_width(self.size, level, n)
        if width <= 0:
            raise TlogError("tile outside the tree")
        data, held = self._read(lambda i, w: _tile_name(level, i, w), n, width)
        if data is None or len(data) != 32 * held:
            raise TlogError(f"tile {level}/{n} is missing or is not the size its name gives")
        return [data[32 * i:32 * (i + 1)] for i in range(width)]

    def stored(self, level: int, index: int) -> bytes:
        return self.tile(level, index // _TILE_WIDTH)[index % _TILE_WIDTH]

    def node(self, height: int, index: int) -> bytes:
        """The hash of the complete subtree of 2**height leaves at position `index`."""
        level, rest = divmod(height, TILE_HEIGHT)
        if rest == 0:
            return self.stored(level, index)
        return node_hash(self.node(height - 1, 2 * index), self.node(height - 1, 2 * index + 1))

    def mth(self, start: int, n: int) -> bytes:
        """MTH of the n leaves from `start`. A hash of a range inside the tree does not depend on the tree's size,
        so it is computed once per view."""
        key = (start, n)
        if key not in self._memo:
            if n == 0:
                value = _EMPTY_ROOT
            elif n & (n - 1) == 0 and start % n == 0:
                value = self.node(n.bit_length() - 1, start // n)
            else:
                k = _split(n)
                value = node_hash(self.mth(start, k), self.mth(start + k, n - k))
            self._memo[key] = value
        return self._memo[key]

    def entries(self, n: int) -> list:
        """The entries of bundle `n`, read the way `tile` reads a tile."""
        width = _tile_width(self.size, 0, n)
        if width <= 0:
            raise TlogError("entry bundle outside the tree")
        data, held = self._read(_bundle_name, n, width)
        if data is None:
            raise TlogError(f"entry bundle {n} is missing")
        found = _read_bundle(data)
        if len(found) != held:
            raise TlogError(f"entry bundle {n} does not hold the number of entries its name gives")
        return found[:width]


class IssuanceLog:
    """An issuance log in a directory, signed by a Lamport-Merkle key kept in `key_path`."""

    def __init__(self, directory: Path, origin: str, keyname: str, signer: MerkleSigner):
        self.directory, self.origin, self.keyname, self.signer = Path(directory), origin, keyname, signer
        self._seen = None            # (checkpoint text, view) of the last checkpoint read and verified

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, directory, origin: str, keyname: str, key_path, key_height: int = 10, *,
               reuse_key: bool = False) -> "IssuanceLog":
        """A new, empty log with a signed checkpoint of size 0. `origin` names the log and is required. A new log key
        of height `key_height` is made at `key_path`; a file already there is refused, because it may be another
        log's key or the key that signs reports. With `reuse_key=True` an existing key file is loaded instead and
        `key_height` is ignored: one key file used for two logs makes them a fork when they share an origin, and the
        log key must not be the key that signs reports."""
        _check_name(origin, "the origin")
        _check_name(keyname, "the key name")
        directory = Path(directory)
        key_path = Path(key_path)
        if key_path.exists() and not reuse_key:
            raise TlogError(f"{key_path} already exists; a new log makes a new key (pass reuse_key=True to load it)")
        directory.mkdir(parents=True, exist_ok=True)
        if (directory / "checkpoint").exists() or (directory / "tile").exists():
            raise TlogError(f"{directory} already holds a log")
        if directory.resolve() in key_path.resolve().parents:
            raise TlogError("the log key may not be kept inside the log directory, which is published")
        signer = MerkleSigner.load(key_path) if key_path.exists() else MerkleSigner.create(key_path, key_height)
        log = cls(directory, origin, keyname, signer)
        with state_lock(directory / "checkpoint"):
            log._sign_checkpoint(0, hashlib.sha256(b"").digest())
        return log

    @classmethod
    def open(cls, directory, keyname: str, key_path) -> "IssuanceLog":
        """An existing log, whose checkpoint must verify under the key in `key_path`."""
        signer = MerkleSigner.load(Path(key_path))
        directory = Path(directory)
        note = (directory / "checkpoint").read_text(encoding="utf-8")
        origin, _, _ = verify_checkpoint(note, encode_vkey(keyname, signer.public_root))
        return cls(directory, origin, keyname, signer)

    @property
    def vkey(self) -> str:
        """The verifier key a buyer pins: obtained from the issuer through a channel the buyer trusts."""
        return encode_vkey(self.keyname, self.signer.public_root)

    def checkpoint(self) -> str:
        return (self.directory / "checkpoint").read_text(encoding="utf-8")

    def state(self):
        """(size, root) of the current signed checkpoint."""
        _, size, root = verify_checkpoint(self.checkpoint(), self.vkey)
        return size, root

    def _view(self) -> _Tiles:
        """The tiles as of the current checkpoint, re-read whenever the checkpoint changes."""
        note = self.checkpoint()
        if self._seen is None or self._seen[0] != note:
            _, size, _ = verify_checkpoint(note, self.vkey)
            self._seen = (note, _Tiles(self.directory, size))
        return self._seen[1]

    @property
    def size(self) -> int:
        return self.state()[0]

    # -- appending ---------------------------------------------------------
    def _entry_for(self, report: dict, report_root: str) -> bytes:
        from .no_egress_auditor import verify_report     # imported here: the auditor module is large
        if not isinstance(report, dict) or report.get("tool") not in _REPORT_TOOLS:
            raise TlogError("not a report this package signs")
        if not isinstance(report_root, str) or not _HEX64.fullmatch(report_root.strip().lower()):
            raise TlogError("the report root is 64 hex digits")
        root = report_root.strip().lower()
        if root == self.signer.public_root:
            raise TlogError("the report is signed by the log key; the log key and the report key must differ")
        ok, status = verify_report(report, expected_root=root, expected_tool=report.get("tool"))
        if not ok:
            raise TlogError(f"the report does not verify ATTESTED under the pinned root (status {status})")
        return entry_line(report.get("findings_digest"), report.get("content_hash"))

    def append(self, report: dict, report_root: str) -> int:
        """Enter one report and sign the new checkpoint. Returns the report's index. The report must verify ATTESTED
        under `report_root`, the root of the key that signs reports."""
        return self.append_all([report], report_root)[0]

    def append_all(self, reports: list, report_root: str) -> list:
        """Enter several reports under one new checkpoint. Every report is checked before anything is written.

        If this raises, read `state()` before retrying: on a platform that can report an error after the new
        checkpoint has been renamed into place (a failed directory sync on POSIX), the append may have happened."""
        entries = [self._entry_for(r, report_root) for r in reports]
        if not entries:
            raise TlogError("nothing to append")
        with state_lock(self.directory / "checkpoint"):
            old_size, old_root = self.state()
            self._written = []
            new_size = old_size + len(entries)
            view = _Tiles(self.directory, old_size)
            self._write_bundles(view, old_size, entries)
            self._write_tiles(view, old_size, [leaf_hash(e) for e in entries])
            new_view = _Tiles(self.directory, new_size)
            new_root = new_view.mth(0, new_size)
            self._check_written(old_size, old_root, new_view, entries)
            proof = _subproof(new_view.mth, old_size, 0, new_size, True) if 0 < old_size else []
            if not verify_consistency(old_size, new_size, old_root, new_root, proof):
                raise TlogError("the new tree is not consistent with the last checkpoint; refusing to sign it")
            self._sign_checkpoint(new_size, new_root)
        return list(range(old_size, new_size))

    def _check_written(self, old_size: int, old_root: bytes, new_view: _Tiles, entries: list) -> None:
        """Read the new tree back before it is signed. Every file this append wrote must hold exactly the bytes
        written; the stored entries for [old_size, new_size) must be `entries`, and the entries carried from below
        old_size must hash to the last checkpoint's level-0 tile; the last checkpoint's tiles must still hash to its
        root; and the root of the stored tiles must equal the root computed from that tree and the hashes of
        `entries`. Raises TlogError, and nothing is signed, otherwise."""
        for name, data in getattr(self, "_written", []):
            path = self.directory / name
            if not path.is_file() or path.read_bytes() != data:
                raise TlogError(f"{name} does not hold what this append wrote; refusing to sign")
        new_size = old_size + len(entries)
        stored = []
        for n in range(old_size // _TILE_WIDTH, (new_size + _TILE_WIDTH - 1) // _TILE_WIDTH):
            stored.extend(new_view.entries(n))
        skip = old_size - (old_size // _TILE_WIDTH) * _TILE_WIDTH
        if stored[skip:skip + len(entries)] != list(entries):
            raise TlogError("the stored entries are not the ones being appended; refusing to sign")
        old_view = _Tiles(self.directory, old_size)
        if old_view.mth(0, old_size) != old_root:
            raise TlogError("the stored tiles do not hash to the last checkpoint's root; refusing to sign")
        if skip and [leaf_hash(e) for e in stored[:skip]] != old_view.tile(0, old_size // _TILE_WIDTH):
            raise TlogError("the carried entries do not hash to the last checkpoint's tile; refusing to sign")
        appended = _memo_mth([leaf_hash(e) for e in entries])

        def expected(start: int, n: int) -> bytes:
            if start + n <= old_size:
                return old_view.mth(start, n)
            if start >= old_size:
                return appended(start - old_size, n)
            k = _split(n)
            return node_hash(expected(start, k), expected(start + k, n - k))

        if new_view.mth(0, new_size) != expected(0, new_size):
            raise TlogError("the stored tiles do not hash to the root of the entries being appended; refusing to sign")

    def _write_new(self, name: str, data: bytes) -> None:
        """Write a tile or bundle. Every name written here covers at least one position past the last checkpoint,
        so no checkpoint covers it. A file already under that name was left by an append that stopped before
        signing: it is replaced when its bytes differ from `data` and kept when they are the same. A leftover under
        a name this append does not write stays where it is; readers take the file named for the size they read
        before a full one, so a leftover full tile or bundle is not read for a smaller size while the partial for
        that size is present, and it is replaced when an append fills that tile. Older partial tiles stay where they
        are. Every (name, bytes) is recorded so `_check_written` can read it back."""
        path = self.directory / name
        self._written = getattr(self, "_written", [])
        self._written.append((name, data))
        if path.is_file() and path.read_bytes() == data:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, data)

    def _write_bundles(self, view: _Tiles, old_size: int, entries: list) -> None:
        first = old_size // _TILE_WIDTH
        carried = view.entries(first) if old_size % _TILE_WIDTH else []
        pending = carried + entries
        n = first
        while pending:
            chunk, pending = pending[:_TILE_WIDTH], pending[_TILE_WIDTH:]
            self._write_new(_bundle_name(n, len(chunk)), _bundle_bytes(chunk))
            n += 1

    def _write_tiles(self, view: _Tiles, old_size: int, new_hashes: list) -> None:
        level, old_count = 0, old_size
        while new_hashes:
            first = old_count // _TILE_WIDTH
            carried = view.tile(level, first) if old_count % _TILE_WIDTH else []
            pending = carried + new_hashes
            completed, n = [], first
            while pending:
                chunk, pending = pending[:_TILE_WIDTH], pending[_TILE_WIDTH:]
                self._write_new(_tile_name(level, n, len(chunk)), b"".join(chunk))
                if len(chunk) == _TILE_WIDTH:
                    completed.append(merkle_root(chunk))     # only a full tile is hashed into the level above
                n += 1
            level, old_count, new_hashes = level + 1, old_count // _TILE_WIDTH, completed

    def _sign_checkpoint(self, size: int, root: bytes) -> None:
        path = self.directory / "checkpoint"
        if path.exists():
            _, last_size, last_root = verify_checkpoint(path.read_text(encoding="utf-8"), self.vkey)
            if size < last_size:
                raise TlogError(f"refusing to sign size {size}, smaller than the last checkpoint ({last_size})")
            if size == last_size and root != last_root:
                raise TlogError("refusing to sign a second root for the same size")
        text = _checkpoint_text(self.origin, size, root)
        enc = _encoded_key(bytes.fromhex(self.signer.public_root))
        try:
            sig = self.signer.sign(text.encode("utf-8"))
        except SignerError as exc:
            raise TlogError(f"the log key cannot sign: {exc}") from exc
        line = _SIG_PREFIX + self.keyname + " " + _b64(_key_id(self.keyname, enc) + _sig_bytes(sig)) + "\n"
        atomic_write(path, (text + "\n" + line).encode("utf-8"))

    # -- proofs ------------------------------------------------------------
    def entry(self, index: int) -> bytes:
        view = self._view()
        if not 0 <= index < view.size:
            raise TlogError("index outside the log")
        return view.entries(index // _TILE_WIDTH)[index % _TILE_WIDTH]

    def inclusion_proof(self, index: int, size: int | None = None) -> list:
        view = self._view()
        size = view.size if size is None else size
        if type(index) is not int or not 0 <= index < size <= view.size:
            raise TlogError("index outside the tree")
        return _path(view.mth, index, 0, size)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list:
        view = self._view()
        new_size = view.size if new_size is None else new_size
        if not 0 <= old_size <= new_size <= view.size:
            raise TlogError("tree sizes out of order")
        if old_size == 0 or old_size == new_size:
            return []
        return _subproof(view.mth, old_size, 0, new_size, True)

    def root_at(self, size: int) -> bytes:
        view = self._view()
        if not 0 <= size <= view.size:
            raise TlogError("size outside the log")
        return view.mth(0, size)

    def proof_bundle(self, index: int) -> dict:
        """Everything a buyer needs offline to check that entry `index` is in the signed log."""
        with state_lock(self.directory / "checkpoint"):
            note = self.checkpoint()
            entry = self.entry(index)
            proof = self.inclusion_proof(index)
        return {"format": BUNDLE_FORMAT, "checkpoint": note, "index": index, "entry": entry.decode("ascii"),
                "inclusion": [p.hex() for p in proof]}


# ------------------------------------------------------------------------------------------------ offline checks
def verify_bundle(bundle: dict, vkey: str, report: dict | None = None) -> dict:
    """Check a proof bundle against the issuer's vkey, with no network and no access to the log. With `report`, also
    check that the entry's findings digest and content hash are the report's; the report's own signature is checked
    by `verify_report`, not here; a `report` that is not a dict raises TlogError. Without `report`, nothing ties the
    entry to the report you hold. The origin is returned, not compared with an expected one. Returns what was proven;
    raises TlogError otherwise."""
    if not isinstance(bundle, dict) or set(bundle) != {"format", "checkpoint", "index", "entry", "inclusion"}:
        raise TlogError("a proof bundle has exactly format, checkpoint, index, entry and inclusion")
    if bundle["format"] != BUNDLE_FORMAT:
        raise TlogError("not an issuance proof bundle")
    if report is not None and not isinstance(report, dict):
        raise TlogError("the report is a dict, as the tools write it")
    origin, size, root = verify_checkpoint(bundle["checkpoint"], vkey)
    index, proof = bundle["index"], bundle["inclusion"]
    if type(index) is not int or not isinstance(proof, list) or not isinstance(bundle["entry"], str):
        raise TlogError("malformed proof bundle")
    if not all(isinstance(p, str) and _HEX64.fullmatch(p) for p in proof):
        raise TlogError("an inclusion hash is 64 lower-case hex digits")
    entry = bundle["entry"].encode("utf-8")
    findings_digest, content_hash = _parse_entry(entry)
    if not verify_inclusion(leaf_hash(entry), index, size, [bytes.fromhex(p) for p in proof], root):
        raise TlogError("the inclusion proof does not verify against the signed checkpoint")
    if report is not None and (report.get("findings_digest"), report.get("content_hash")) != (
            findings_digest, content_hash):
        raise TlogError("the entry names a different report")
    return {"origin": origin, "size": size, "index": index, "findings_digest": findings_digest,
            "content_hash": content_hash}


def verify_log_dir(directory, vkey: str) -> dict:
    """Check a whole log directory offline: the signed checkpoint, every entry, and every tile the checkpoint's tree
    uses, recomputed from the entries. Returns origin, size and root (the origin is not compared with an expected
    one); raises TlogError on any difference."""
    directory = Path(directory)
    try:
        note = (directory / "checkpoint").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise TlogError("no readable checkpoint") from None
    origin, size, root = verify_checkpoint(note, vkey)
    view = _Tiles(directory, size)
    hashes = []
    for n in range((size + _TILE_WIDTH - 1) // _TILE_WIDTH):
        for entry in view.entries(n):
            _parse_entry(entry)
            hashes.append(leaf_hash(entry))
    level = 0
    while hashes:
        for n in range((len(hashes) + _TILE_WIDTH - 1) // _TILE_WIDTH):
            if view.tile(level, n) != hashes[n * _TILE_WIDTH:(n + 1) * _TILE_WIDTH]:
                raise TlogError(f"tile {level}/{n} does not match the entries")
        hashes = [merkle_root(hashes[i:i + _TILE_WIDTH])
                  for i in range(0, len(hashes) - _TILE_WIDTH + 1, _TILE_WIDTH)]
        level += 1
    if view.mth(0, size) != root:
        raise TlogError("the entries do not hash to the signed root")
    return {"origin": origin, "size": size, "root": root.hex()}


def _proof_hashes(proof):
    """A consistency proof given as 64-hex-digit strings or 32-byte values, as bytes; None if it is neither."""
    if not isinstance(proof, (list, tuple)):
        return None
    out = []
    for p in proof:
        if isinstance(p, str) and _HEX64.fullmatch(p):
            out.append(bytes.fromhex(p))
        elif _is_hash(p):
            out.append(bytes(p))
        else:
            return None
    return out


def detect_fork(cp_a: str, cp_b: str, vkey: str, proof: list | None = None):
    """Compare two checkpoints of one log, both signed by `vkey`.

    True: they have the same size and different roots, so the key signed two trees that cannot both be true. That
    happens when the issuer keeps two logs, when the log key leaked or was copied, and when the log directory was
    restored from a copy older than a checkpoint already handed out and then appended to.
    False: they are consistent. They have the same size and the same root, or different sizes and `proof` (hashes as
    64 lower-case hex digits or 32 bytes, from the smaller tree to the larger) verifies as a consistency proof between them. A
    checkpoint of size 0 is consistent with every checkpoint, so it gives False with or without a proof.
    None: they have different sizes and no proof is given, or the proof given does not verify. A proof that fails
    does not show that no proof exists, so it is not evidence of a fork.
    A checkpoint that does not verify under `vkey` raises TlogError: it is not evidence. Two checkpoints naming
    different origins raise TlogError: this compares checkpoints of one log only."""
    origin_a, size_a, root_a = verify_checkpoint(cp_a, vkey)
    origin_b, size_b, root_b = verify_checkpoint(cp_b, vkey)
    if origin_a != origin_b:
        raise TlogError("the checkpoints name different logs")
    if size_a > size_b:
        size_a, size_b, root_a, root_b = size_b, size_a, root_b, root_a
    if size_a == size_b:
        return not hmac.compare_digest(root_a, root_b)
    if size_a == 0:
        return False                 # verify_checkpoint refuses an empty tree with any root but the empty one
    if proof is None:
        return None
    hashes = _proof_hashes(proof)
    if hashes is None or not verify_consistency(size_a, size_b, root_a, root_b, hashes):
        return None
    return False

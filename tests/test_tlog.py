"""The issuance log: RFC 9162 hashing and proofs, the C2SP tlog-tiles layout, signed checkpoints, and the offline checks
a buyer runs.

The tree hashes are checked against the RFC 6962 test roots for trees of 1 to 8 entries that the transparency-dev
Merkle library publishes in `testonly/constants.go` (as of commit 77f1b57d7aa25fcd2e51273166b6b2b0e74923b1, the file's
last change, 2022-04-25; read 2026-10-17), and the empty tree against SHA-256 of the empty string, as RFC 9162
Section 2.1.1 defines it. No published proof vectors are run: every proof the log produces is compared with a
reference written here from the RFC 9162 Section 2.1 definitions, sharing no code with `entrovouch.tlog`.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import shutil
import subprocess
import sys
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

import pytest

from entrovouch import tlog
from entrovouch.no_egress_auditor import audit
from entrovouch.signer import _MAX_KEY_HEIGHT, MerkleSigner, SignerError
from entrovouch.tlog import IssuanceLog, TlogError

REPO = Path(__file__).resolve().parents[1]

# transparency-dev/merkle testonly/constants.go, as of commit 77f1b57d7aa25fcd2e51273166b6b2b0e74923b1 (2022-04-25,
# the file's last change; read 2026-10-17): LeafInputs and RootHashes for tree sizes 1 to 8. ROOT_HASHES[0], the empty
# tree, is SHA-256 of the empty string (RFC 9162 Section 2.1.1), not from that file.
LEAF_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
ROOT_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
ORIGIN = "example.com/issuance-test"
LOG_SIZE = 300


# ------------------------------------------------------------------------- a reference from RFC 9162 Section 2.1
def _ref_leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _k(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


class _Ref:
    def __init__(self, leaves: list):
        self.leaves = leaves

        @lru_cache(maxsize=None)
        def mth(start, n):
            if n == 0:
                return hashlib.sha256(b"").digest()
            if n == 1:
                return self.leaves[start]
            k = _k(n)
            return hashlib.sha256(b"\x01" + mth(start, k) + mth(start + k, n - k)).digest()
        self.mth = mth

    def path(self, m, start, n):
        if n == 1:
            return []
        k = _k(n)
        if m < k:
            return self.path(m, start, k) + [self.mth(start + k, n - k)]
        return self.path(m - k, start + k, n - k) + [self.mth(start, k)]

    def subproof(self, m, start, n, b):
        if m == n:
            return [] if b else [self.mth(start, n)]
        k = _k(n)
        if m <= k:
            return self.subproof(m, start, k, b) + [self.mth(start + k, n - k)]
        return self.subproof(m - k, start + k, n - k, False) + [self.mth(start, k)]


# ------------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def world(tmp_path_factory):
    base = tmp_path_factory.mktemp("tlog")
    tree = base / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("x = 1\n", encoding="utf-8")
    report_signer = MerkleSigner.create(base / "report.key.json", height=9)
    reports = [asdict(audit(tree, label=f"subject-{i}", signer=report_signer)) for i in range(LOG_SIZE)]
    log = IssuanceLog.create(base / "log", ORIGIN, ORIGIN, base / "log.key.json", key_height=5)
    checkpoints = {0: log.checkpoint()}
    for stop in (1, 2, 7, 40, 255, 256, 257, LOG_SIZE):
        log.append_all(reports[log.size:stop], report_signer.public_root)
        checkpoints[stop] = log.checkpoint()
    entries = [tlog.entry_line(r["findings_digest"], r["content_hash"]) for r in reports]
    return {"base": base, "tree": tree, "report_signer": report_signer, "reports": reports, "log": log,
            "checkpoints": checkpoints, "entries": entries, "ref": _Ref([_ref_leaf(e) for e in entries])}


# ------------------------------------------------------------------------- hashing and paths
def test_tree_hashes_match_the_published_roots_for_sizes_0_to_8():
    hashes = [tlog.leaf_hash(bytes.fromhex(x)) for x in LEAF_INPUTS]
    for n, expected in enumerate(ROOT_HASHES):
        assert tlog.merkle_root(hashes[:n]).hex() == expected, n


def test_published_roots_through_inclusion_and_consistency():
    hashes = [tlog.leaf_hash(bytes.fromhex(x)) for x in LEAF_INPUTS]
    roots = [bytes.fromhex(r) for r in ROOT_HASHES]
    for n in range(1, 9):
        for i in range(n):
            assert tlog.verify_inclusion(hashes[i], i, n, tlog.inclusion_path(hashes, i, n), roots[n])
        for m in range(1, n):
            assert tlog.verify_consistency(m, n, roots[m], roots[n], tlog.consistency_path(hashes, m, n))


@pytest.mark.parametrize("n, path", [(1234067, "x001/x234/067"), (5, "005"), (0, "000"), (999, "999"),
                                     (1000, "x001/000"), (256, "256"), (1000000, "x001/x000/000")])
def test_tile_path(n, path):
    assert tlog._tile_path(n) == path


def test_tile_and_bundle_names():
    assert tlog._tile_name(0, 1234067, 256) == "tile/0/x001/x234/067"
    assert tlog._tile_name(1, 0, 17) == "tile/1/000.p/17"
    assert tlog._bundle_name(5, 256) == "tile/entries/005"
    assert tlog._bundle_name(5, 3) == "tile/entries/005.p/3"


# ------------------------------------------------------------------------- the log on disk
def test_the_layout_is_tlog_tiles(world):
    d, ref, entries = world["log"].directory, world["ref"], world["entries"]
    assert (d / "tile" / "0" / "000").read_bytes() == b"".join(ref.leaves[:256])
    assert (d / "tile" / "0" / "001.p" / "44").read_bytes() == b"".join(ref.leaves[256:300])
    assert (d / "tile" / "1" / "000.p" / "1").read_bytes() == ref.mth(0, 256)
    bundle = (d / "tile" / "entries" / "000").read_bytes()
    assert bundle == b"".join(len(e).to_bytes(2, "big") + e for e in entries[:256])
    assert (d / "tile" / "entries" / "001.p" / "44").is_file()
    # older partial tiles and bundles are left where they are
    for w in (1, 2, 7, 40, 255):
        assert (d / "tile" / "0" / "000.p" / str(w)).read_bytes() == b"".join(ref.leaves[:w])
        assert (d / "tile" / "entries" / "000.p" / str(w)).is_file()
    assert (d / "tile" / "0" / "001.p" / "1").is_file()
    assert not (d / "tile" / "1" / "000").exists()           # a partial tile is never hashed upward
    assert not (d / "tile" / "2").exists()


def test_the_checkpoint_is_a_signed_note(world):
    log = world["log"]
    note = log.checkpoint()
    text, sig = note.split("\n\n")
    assert text == f"{ORIGIN}\n{LOG_SIZE}\n{base64.b64encode(world['ref'].mth(0, LOG_SIZE)).decode()}"
    assert sig.startswith("— " + ORIGIN + " ") and sig.endswith("\n") and sig.count("\n") == 1
    name, kid_hex, key64 = log.vkey.split("+", 2)
    key = base64.b64decode(key64)
    assert key[0] == 0xFF and key[1:33] == hashlib.sha256(b"entrovouch/lamport-merkle-sha3-256/v1").digest()
    assert key[33:].hex() == log.signer.public_root
    assert kid_hex == hashlib.sha256(name.encode() + b"\n" + key).digest()[:4].hex()
    assert base64.b64decode(sig.split(" ")[2])[:4].hex() == kid_hex
    assert tlog.verify_checkpoint(note, log.vkey) == (ORIGIN, LOG_SIZE, world["ref"].mth(0, LOG_SIZE))


def test_inclusion_for_every_index_at_every_size_from_1_to_300(world):
    log, ref = world["log"], world["ref"]
    for size in range(1, LOG_SIZE + 1):
        root = ref.mth(0, size)
        assert log.root_at(size) == root
        for i in range(size):
            proof = log.inclusion_proof(i, size)
            assert proof == ref.path(i, 0, size), (i, size)
            assert tlog.verify_inclusion(ref.leaves[i], i, size, proof, root), (i, size)
            if size > 1:
                assert not tlog.verify_inclusion(ref.leaves[i], (i + 1) % size, size, proof, root), (i, size)


def test_consistency_for_every_pair_up_to_40(world):
    log, ref = world["log"], world["ref"]
    for n in range(2, 41):
        for m in range(1, n):
            proof = log.consistency_proof(m, n)
            assert proof == ref.subproof(m, 0, n, True), (m, n)
            assert proof == tlog.consistency_path(ref.leaves, m, n)
            assert tlog.verify_consistency(m, n, ref.mth(0, m), ref.mth(0, n), proof), (m, n)
            assert not tlog.verify_consistency(m, n, ref.mth(0, n), ref.mth(0, m), proof), (m, n)
            if proof:
                assert not tlog.verify_consistency(m, n, ref.mth(0, m), ref.mth(0, n), proof[:-1]), (m, n)
    assert tlog.verify_consistency(0, 5, ref.mth(0, 0), ref.mth(0, 5), [])
    assert tlog.verify_consistency(5, 5, ref.mth(0, 5), ref.mth(0, 5), [])
    assert not tlog.verify_consistency(5, 5, ref.mth(0, 5), ref.mth(0, 4), [])
    assert not tlog.verify_consistency(3, 5, ref.mth(0, 3), ref.mth(0, 5), [])


def test_consistency_across_the_tile_boundary(world):
    log, ref = world["log"], world["ref"]
    for m, n in ((1, 300), (255, 256), (256, 257), (40, 300), (257, 300), (128, 300)):
        assert tlog.verify_consistency(m, n, ref.mth(0, m), ref.mth(0, n), log.consistency_proof(m, n))


def test_the_whole_directory_verifies_offline(world):
    log = world["log"]
    assert tlog.verify_log_dir(log.directory, log.vkey) == {
        "origin": ORIGIN, "size": LOG_SIZE, "root": world["ref"].mth(0, LOG_SIZE).hex()}


def test_a_proof_bundle_verifies_offline_and_names_its_report(world):
    log, reports = world["log"], world["reports"]
    for i in (0, 1, 255, 256, 299):
        bundle = json.loads(json.dumps(log.proof_bundle(i)))
        got = tlog.verify_bundle(bundle, log.vkey, report=reports[i])
        assert got == {"origin": ORIGIN, "size": LOG_SIZE, "index": i,
                       "findings_digest": reports[i]["findings_digest"], "content_hash": reports[i]["content_hash"]}
        with pytest.raises(TlogError):
            tlog.verify_bundle(bundle, log.vkey, report=reports[(i + 1) % LOG_SIZE])


def test_a_reopened_log_keeps_its_state(world):
    log = world["log"]
    again = IssuanceLog.open(log.directory, ORIGIN, world["base"] / "log.key.json")
    assert again.origin == ORIGIN and again.size == LOG_SIZE and again.vkey == log.vkey


def test_bundles_tiles_then_checkpoint_are_written_in_that_order(tmp_path, monkeypatch):
    signer = MerkleSigner.create(tmp_path / "r.key.json", height=2)
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "a.py").write_text("x = 1\n", encoding="utf-8")
    report = asdict(audit(tmp_path / "t", label="one", signer=signer))
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "l.key.json", key_height=2)
    written = []
    real = tlog.atomic_write
    monkeypatch.setattr(tlog, "atomic_write", lambda path, data: (
        written.append(path.relative_to(log.directory).as_posix()), real(path, data)))
    log.append(report, signer.public_root)
    assert written == ["tile/entries/000.p/1", "tile/0/000.p/1", "checkpoint"]


def test_a_log_key_of_height_h_signs_2_to_the_h_checkpoints(world, tmp_path):
    """`create` signs the empty checkpoint with the first leaf, so a key of height 1 leaves one append. When no leaf
    is left, `append` raises and the signed checkpoint is not changed."""
    signer = world["report_signer"]
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=1)
    assert log.signer.leaf_count == 2 and log.signer.next_index == 1
    log.append(world["reports"][0], signer.public_root)
    before = log.checkpoint()
    with pytest.raises(TlogError):
        log.append(world["reports"][1], signer.public_root)
    assert log.checkpoint() == before and log.size == 1
    assert tlog.verify_log_dir(log.directory, log.vkey)["size"] == 1
    assert inspect.signature(IssuanceLog.create).parameters["key_height"].default == 10
    assert _MAX_KEY_HEIGHT == 16
    with pytest.raises(SignerError):
        IssuanceLog.create(tmp_path / "too-tall", ORIGIN, ORIGIN, tmp_path / "tall.key.json", key_height=17)


def _checkpoint_leaf(note: str) -> int:
    """The one-time leaf a checkpoint's signature used: after the 4-byte key ID come the height and the leaf index."""
    raw = base64.b64decode(note.split("\n\n")[1].rstrip("\n").split(" ")[2])
    return int.from_bytes(raw[5:9], "big")


def test_a_restored_log_key_is_advanced_with_the_report_key_command(world, tmp_path):
    """The log key is a signer key file like the report key, so `--advance-key` moves a restored copy past leaves the
    other copy may have used."""
    signer = world["report_signer"]
    key = tmp_path / "log.key.json"
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, key, key_height=4)
    assert _checkpoint_leaf(log.checkpoint()) == 0
    r = subprocess.run([sys.executable, "-m", "entrovouch.no_egress_auditor", "--key", str(key), "--advance-key", "5"],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, r.stderr
    log = IssuanceLog.open(tmp_path / "log", ORIGIN, key)
    log.append(world["reports"][0], signer.public_root)
    assert _checkpoint_leaf(log.checkpoint()) == 6


# ------------------------------------------------------------------------- refusals and tampering
def _copy(world, tmp_path):
    dst = tmp_path / "copy"
    shutil.copytree(world["log"].directory, dst)
    return dst


def test_a_tampered_entry_bundle_fails(world, tmp_path):
    d = _copy(world, tmp_path)
    path = d / "tile" / "entries" / "000"
    data = bytearray(path.read_bytes())
    data[40] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(TlogError):
        tlog.verify_log_dir(d, world["log"].vkey)


@pytest.mark.parametrize("index", [0, 1, 127, 254, 255, 256, 257, LOG_SIZE - 2, LOG_SIZE - 1])
def test_a_well_formed_tampered_entry_fails_on_the_tile_hash(world, tmp_path, index):
    # The test above breaks the line's syntax, so the parser catches it before any hash is compared. This tamper keeps
    # the line a valid issuance line (one hex digit of the findings digest changed), so only the comparison of the
    # entries' hashes with the signed tiles can catch it. The indices cover the first, middle and last entry of the
    # full tile and of the partial one, so a comparison that skips any position within a tile is caught; every bundle
    # holding the entry is rewritten, so whichever one the verifier reads carries the tamper.
    line = world["entries"][index]
    bad = bytearray(line)
    pos = len(tlog.ENTRY_PREFIX) + 1
    bad[pos] = ord("1") if bad[pos] == ord("0") else ord("0")
    bad = bytes(bad)
    tlog._parse_entry(bad)  # still well formed, so the parser cannot be what rejects it
    d = _copy(world, tmp_path)
    hits = 0
    for f in sorted((d / "tile" / "entries").rglob("*")):
        if f.is_file() and line in (data := f.read_bytes()):
            f.write_bytes(data.replace(line, bad))
            hits += 1
    assert hits, f"entry {index} is in no bundle"
    with pytest.raises(TlogError, match="does not match the entries"):
        tlog.verify_log_dir(d, world["log"].vkey)


def test_a_tampered_tile_or_partial_bundle_fails(world, tmp_path):
    d = _copy(world, tmp_path)
    tile = d / "tile" / "0" / "001.p" / "44"
    data = bytearray(tile.read_bytes())
    data[0] ^= 1
    tile.write_bytes(bytes(data))
    with pytest.raises(TlogError):
        tlog.verify_log_dir(d, world["log"].vkey)
    d2 = tmp_path / "copy2"
    shutil.copytree(world["log"].directory, d2)
    bundle = d2 / "tile" / "entries" / "001.p" / "44"
    bundle.write_bytes(bundle.read_bytes()[:-1])
    with pytest.raises(TlogError):
        tlog.verify_log_dir(d2, world["log"].vkey)


def test_a_wrong_index_or_a_truncated_proof_fails(world):
    log = world["log"]
    bundle = log.proof_bundle(10)
    for edit in ({"index": 11}, {"index": LOG_SIZE}, {"inclusion": bundle["inclusion"][:-1]},
                 {"inclusion": bundle["inclusion"] + [bundle["inclusion"][0]]},
                 {"entry": bundle["entry"].replace("v1 ", "v1  ", 1)}, {"checkpoint": world["checkpoints"][257]}):
        with pytest.raises(TlogError):
            tlog.verify_bundle(dict(bundle, **edit), log.vkey)
    proof = log.inclusion_proof(10)
    root = world["ref"].mth(0, LOG_SIZE)
    assert not tlog.verify_inclusion(world["ref"].leaves[10], 10, LOG_SIZE, proof[:-1], root)
    assert not tlog.verify_inclusion(world["ref"].leaves[10], 10, LOG_SIZE, proof[1:], root)


def test_a_fork_is_detected(tmp_path, world):
    signer = world["report_signer"]
    key = tmp_path / "shared.key.json"
    a = IssuanceLog.create(tmp_path / "a", ORIGIN, ORIGIN, key, key_height=3)
    b = IssuanceLog.create(tmp_path / "b", ORIGIN, ORIGIN, key, reuse_key=True)    # one key file, two logs
    assert a.vkey == b.vkey
    a.append(world["reports"][0], signer.public_root)
    b.append(world["reports"][1], signer.public_root)
    assert a.size == b.size == 1
    # one key signed two trees of size 1 with different roots: they cannot both be true
    assert tlog.detect_fork(a.checkpoint(), b.checkpoint(), a.vkey) is True
    assert tlog.detect_fork(b.checkpoint(), a.checkpoint(), a.vkey, []) is True
    assert tlog.detect_fork(a.checkpoint(), a.checkpoint(), a.vkey) is False
    # the same two histories at different sizes: no consistency proof verifies, and a failing proof is not a finding
    first_a = a.checkpoint()
    b.append(world["reports"][2], signer.public_root)
    proof_b = [p.hex() for p in b.consistency_proof(1, 2)]
    assert tlog.detect_fork(first_a, b.checkpoint(), a.vkey, proof_b) is None
    assert tlog.detect_fork(first_a, b.checkpoint(), a.vkey) is None


def test_two_origins_are_not_compared(tmp_path, world):
    key = tmp_path / "shared.key.json"
    a = IssuanceLog.create(tmp_path / "a", ORIGIN, ORIGIN, key, key_height=2)
    b = IssuanceLog.create(tmp_path / "b", "example.com/another-log", ORIGIN, key, reuse_key=True)
    with pytest.raises(TlogError):
        tlog.detect_fork(a.checkpoint(), b.checkpoint(), a.vkey)


def test_consistent_checkpoints_are_not_a_fork(world):
    log, cps = world["log"], world["checkpoints"]
    proof = [p.hex() for p in log.consistency_proof(40, 257)]
    assert tlog.detect_fork(cps[40], cps[257], log.vkey, proof) is False
    assert tlog.detect_fork(cps[257], cps[40], log.vkey, proof) is False
    assert tlog.detect_fork(cps[40], cps[257], log.vkey, [bytes.fromhex(p) for p in proof]) is False
    assert tlog.detect_fork(cps[40], cps[40], log.vkey) is False
    assert tlog.detect_fork(cps[0], cps[300], log.vkey) is False                      # an empty tree needs no proof
    assert tlog.detect_fork(cps[0], cps[300], log.vkey, proof) is False


def test_a_missing_or_failing_proof_says_nothing(world):
    """Different sizes with no proof, or with a proof that does not verify, give None: a proof that fails does not
    show that no proof exists, so an honest log with a corrupted proof is not reported as forked."""
    log, cps = world["log"], world["checkpoints"]
    proof = [p.hex() for p in log.consistency_proof(40, 257)]
    corrupted = list(proof)
    corrupted[0] = ("0" if corrupted[0][0] != "0" else "1") + corrupted[0][1:]
    other_pair = [p.hex() for p in log.consistency_proof(40, 256)]
    for bad in (None, [], proof[:-1], proof[1:], proof + [proof[0]], corrupted, other_pair,
                [p.upper() for p in proof], ["not hex"] + proof[1:], [None] + proof[1:], "".join(proof), 7):
        assert tlog.detect_fork(cps[40], cps[257], log.vkey, bad) is None, bad


def test_an_unknown_key_is_rejected(world, tmp_path):
    log = world["log"]
    other = MerkleSigner.create(tmp_path / "other.key.json", height=1)
    stranger = tlog.encode_vkey(ORIGIN, other.public_root)
    with pytest.raises(TlogError):
        tlog.verify_checkpoint(log.checkpoint(), stranger)
    with pytest.raises(TlogError):
        tlog.verify_log_dir(log.directory, stranger)
    with pytest.raises(TlogError):
        tlog.verify_bundle(log.proof_bundle(3), stranger)
    with pytest.raises(TlogError):
        tlog.detect_fork(log.checkpoint(), log.checkpoint(), stranger)
    # the same key under another name is another key: its key ID differs and the signature is ignored
    with pytest.raises(TlogError):
        tlog.verify_checkpoint(log.checkpoint(), tlog.encode_vkey("example.com/other", log.signer.public_root))
    # an Ed25519 vkey (type 0x01) is not this package's key type
    ed = bytes([1]) + bytes(32)
    kid = hashlib.sha256(ORIGIN.encode() + b"\n" + ed).digest()[:4].hex()
    with pytest.raises(TlogError):
        tlog.parse_vkey(f"{ORIGIN}+{kid}+{base64.b64encode(ed).decode()}")
    name, kid, key64 = log.vkey.split("+", 2)
    with pytest.raises(TlogError):
        tlog.parse_vkey(f"{name}+{'0' * 8}+{key64}")


def test_a_signature_by_the_trusted_key_that_fails_rejects_the_note(world):
    log = world["log"]
    text, sig = log.checkpoint().split("\n\n")
    forged_text = text.replace(f"\n{LOG_SIZE}\n", f"\n{LOG_SIZE + 1}\n")
    with pytest.raises(TlogError):
        tlog.verify_checkpoint(forged_text + "\n\n" + sig, log.vkey)
    # a second, unknown signature line beside a valid one is ignored
    stranger = "— example.com/other " + base64.b64encode(b"\x00" * 8).decode() + "\n"
    assert tlog.verify_checkpoint(log.checkpoint() + stranger, log.vkey)[1] == LOG_SIZE


def _non_canonical(b64: str) -> str:
    """The same bytes under different base64 text: set a padding bit the decoder discards."""
    assert b64.endswith("=")
    stem = b64.rstrip("=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet[alphabet.index(stem[-1]) | 1]
    out = stem[:-1] + last + b64[len(stem):]
    assert out != b64 and base64.b64decode(out) == base64.b64decode(b64)
    return out


def test_non_canonical_base64_is_rejected(world):
    log = world["log"]
    text, sig = log.checkpoint().split("\n\n")
    dash, name, value = sig.rstrip("\n").split(" ")
    with pytest.raises(TlogError):
        tlog.verify_checkpoint(text + "\n\n" + " ".join((dash, name, _non_canonical(value))) + "\n", log.vkey)
    vname, kid, key64 = log.vkey.split("+", 2)
    with pytest.raises(TlogError):
        tlog.parse_vkey("+".join((vname, kid, _non_canonical(key64))))
    with pytest.raises(TlogError):
        tlog._unb64(_non_canonical(base64.b64encode(b"\x01\x02").decode()))
    with pytest.raises(TlogError):
        tlog._unb64("AQI")                                                   # no padding


def test_a_checkpoint_with_a_leading_zero_or_extension_lines_is_refused():
    root = base64.b64encode(bytes(32)).decode()
    for text in (f"{ORIGIN}\n07\n{root}\n", f"{ORIGIN}\n7\n{root}\nextra\n", f"{ORIGIN}\n\n{root}\n",
                 f"origin with space\n7\n{root}\n", f"a+b\n7\n{root}\n"):
        with pytest.raises(TlogError):
            tlog._parse_checkpoint_text(text)
    assert tlog._parse_checkpoint_text(f"{ORIGIN}\n7\n{root}\n") == (ORIGIN, 7, bytes(32))


def test_append_refuses_an_unsigned_tampered_or_unpinned_report(world, tmp_path):
    signer = world["report_signer"]
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=3)
    unsigned = asdict(audit(world["tree"], label="unsigned"))
    with pytest.raises(TlogError):
        log.append(unsigned, signer.public_root)
    tampered = json.loads(json.dumps(world["reports"][5]))
    tampered["target"] = "somewhere-else"
    with pytest.raises(TlogError):
        log.append(tampered, signer.public_root)
    edited_digest = json.loads(json.dumps(world["reports"][5]))
    edited_digest["findings_digest"] = "0" * 64
    with pytest.raises(TlogError):
        log.append(edited_digest, signer.public_root)
    with pytest.raises(TlogError):
        log.append(world["reports"][5], "0" * 64)                          # signed, but not by the pinned root
    with pytest.raises(TlogError):
        log.append({"tool": "something else"}, signer.public_root)
    with pytest.raises(TlogError):
        log.append_all([world["reports"][6], tampered], signer.public_root)
    assert log.size == 0 and not (log.directory / "tile").exists()        # nothing written for a refused batch
    log.append(world["reports"][5], signer.public_root)
    assert log.size == 1


def test_a_report_signed_by_the_log_key_is_refused(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "a.py").write_text("x = 1\n", encoding="utf-8")
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=3)
    report = asdict(audit(tmp_path / "t", label="self", signer=log.signer))
    with pytest.raises(TlogError):
        log.append(report, log.signer.public_root)


def test_the_log_refuses_to_sign_a_smaller_or_a_second_tree(world, tmp_path):
    signer = world["report_signer"]
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=3)
    log.append_all(world["reports"][:3], signer.public_root)
    with pytest.raises(TlogError):
        log._sign_checkpoint(2, world["ref"].mth(0, 2))
    with pytest.raises(TlogError):
        log._sign_checkpoint(3, world["ref"].mth(0, 2))
    assert tlog.verify_checkpoint(log.checkpoint(), log.vkey)[1] == 3


def test_create_refuses_an_existing_log_bad_names_and_a_key_inside_the_log(world, tmp_path):
    with pytest.raises(TlogError):
        IssuanceLog.create(world["log"].directory, ORIGIN, ORIGIN, tmp_path / "k.key.json")
    for origin, keyname in (("", ORIGIN), ("has space", ORIGIN), ("a+b", ORIGIN), (ORIGIN, "x+y"), (ORIGIN, "")):
        with pytest.raises(TlogError):
            IssuanceLog.create(tmp_path / "new", origin, keyname, tmp_path / "k.key.json")
    with pytest.raises(TlogError):
        IssuanceLog.create(tmp_path / "inside", ORIGIN, ORIGIN, tmp_path / "inside" / "k.key.json")


def test_create_refuses_an_existing_key_file_unless_told_to_reuse_it(world, tmp_path):
    """A key file already at `key_path` may be another log's key or the report key: `create` refuses it, spends no
    leaf on it and writes no log, unless given `reuse_key=True`."""
    key = tmp_path / "log.key.json"
    first = IssuanceLog.create(tmp_path / "a", ORIGIN, ORIGIN, key, key_height=2)
    state = key.read_bytes()
    with pytest.raises(TlogError):
        IssuanceLog.create(tmp_path / "b", ORIGIN, ORIGIN, key, key_height=2)
    assert key.read_bytes() == state and not (tmp_path / "b" / "checkpoint").exists()
    report_key = world["base"] / "report.key.json"
    before = report_key.read_bytes()
    with pytest.raises(TlogError):
        IssuanceLog.create(tmp_path / "c", ORIGIN, ORIGIN, report_key)
    assert report_key.read_bytes() == before and not (tmp_path / "c" / "checkpoint").exists()
    again = IssuanceLog.create(tmp_path / "b", ORIGIN, ORIGIN, key, reuse_key=True)
    assert again.vkey == first.vkey
    param = inspect.signature(IssuanceLog.create).parameters["reuse_key"]
    assert param.default is False and param.kind is inspect.Parameter.KEYWORD_ONLY


def test_verify_bundle_refuses_a_report_that_is_not_a_dict(world):
    log = world["log"]
    bundle = log.proof_bundle(3)
    for bad in ([1], "a report", 7, ()):
        with pytest.raises(TlogError):
            tlog.verify_bundle(bundle, log.vkey, report=bad)


# ------------------------------------------------------------------------- an append that stops before signing
def _fail(exc):
    def fail(*args, **kwargs):
        raise exc
    return fail


def test_a_failed_append_that_filled_a_tile_does_not_decide_the_next_entry(world, tmp_path, monkeypatch):
    """A batch of 256 writes the full tile and bundle 000 before it signs. When signing fails they stay on disk and
    no checkpoint covers them. The next append, of one other report, must enter that report: the reader takes the
    partial file named for the size it reads, not the leftover full one."""
    signer, reports, entries = world["report_signer"], world["reports"], world["entries"]
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=3)
    monkeypatch.setattr(IssuanceLog, "_sign_checkpoint", _fail(TlogError("the log key cannot sign")))
    with pytest.raises(TlogError):
        log.append_all(reports[:256], signer.public_root)
    monkeypatch.undo()
    assert log.size == 0 and (log.directory / "tile" / "0" / "000").is_file()
    assert (log.directory / "tile" / "entries" / "000").is_file()
    assert log.append(reports[299], signer.public_root) == 0 and log.size == 1
    assert log.entry(0) == entries[299]
    assert tlog.verify_log_dir(log.directory, log.vkey)["size"] == 1
    bundle = log.proof_bundle(0)
    assert tlog.verify_bundle(bundle, log.vkey, report=reports[299])["index"] == 0
    with pytest.raises(TlogError):
        tlog.verify_bundle(bundle, log.vkey, report=reports[0])
    # filling the tile replaces the leftover full files with the ones the log signs
    log.append_all(reports[1:256], signer.public_root)
    assert log.size == 256 and tlog.verify_log_dir(log.directory, log.vkey)["size"] == 256
    signed = [entries[299]] + entries[1:256]
    assert (log.directory / "tile" / "0" / "000").read_bytes() == b"".join(_ref_leaf(e) for e in signed)
    assert tlog.verify_bundle(log.proof_bundle(255), log.vkey, report=reports[255])["index"] == 255


def test_a_failed_append_between_bundles_and_tiles_does_not_corrupt_the_next(world, tmp_path, monkeypatch):
    """At size 10, a batch of 250 writes bundle 000 in full and then stops before any tile is written. The next
    append must sign a log `verify_log_dir` accepts, with its own report at index 10."""
    signer, reports, entries = world["report_signer"], world["reports"], world["entries"]
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=3)
    log.append_all(reports[:10], signer.public_root)
    monkeypatch.setattr(IssuanceLog, "_write_tiles", _fail(OSError("no space left on the device")))
    with pytest.raises(OSError):
        log.append_all(reports[10:260], signer.public_root)
    monkeypatch.undo()
    assert log.size == 10 and (log.directory / "tile" / "entries" / "000").is_file()
    assert log.append(reports[299], signer.public_root) == 10 and log.size == 11
    assert tlog.verify_log_dir(log.directory, log.vkey)["size"] == 11
    assert [log.entry(i) for i in range(11)] == entries[:10] + [entries[299]]
    assert tlog.verify_bundle(log.proof_bundle(10), log.vkey, report=reports[299])["index"] == 10
    assert tlog.verify_bundle(log.proof_bundle(9), log.vkey, report=reports[9])["index"] == 9


def test_an_append_reads_the_new_tree_back_before_it_signs(world, tmp_path, monkeypatch):
    """A tile or bundle that does not land as written is found before the checkpoint is signed: the append raises
    and the checkpoint does not change. The consistency check alone does not catch a wrong tile past the last
    checkpoint, since the proof is built from the same tiles."""
    signer, reports, entries = world["report_signer"], world["reports"], world["entries"]
    real = tlog.atomic_write

    def wrong_tile(path, data):
        if path.name != "checkpoint" and "entries" not in path.parts:
            data = data[:-1] + bytes([data[-1] ^ 1])
        real(path, data)

    def wrong_bundle(path, data):
        if "entries" in path.parts:
            data = data.replace(entries[3], entries[200])
        real(path, data)

    for writer in (wrong_tile, wrong_bundle):          # a log each: a file already right is not written again
        d = tmp_path / writer.__name__
        log = IssuanceLog.create(d / "log", ORIGIN, ORIGIN, d / "log.key.json", key_height=3)
        log.append_all(reports[:3], signer.public_root)
        before = log.checkpoint()
        monkeypatch.setattr(tlog, "atomic_write", writer)
        with pytest.raises(TlogError):
            log.append(reports[3], signer.public_root)
        monkeypatch.undo()
        assert log.checkpoint() == before and log.size == 3
        assert log.append(reports[3], signer.public_root) == 3          # the leftover is replaced
        assert tlog.verify_log_dir(log.directory, log.vkey)["size"] == 4
        assert log.entry(3) == entries[3]


def _flip(path, offset=0):
    data = bytearray(path.read_bytes())
    data[offset] ^= 1
    path.write_bytes(bytes(data))


def test_a_file_changed_between_writing_and_signing_is_found(world, tmp_path, monkeypatch):
    """Something outside the module (a disk fault, another writer) changes a file after the append wrote it and
    before it signs: a full level-0 tile under a level-1 hash, or a carried entry in the first rewritten bundle.
    Every file the append wrote is read back byte for byte, so the append raises and signs nothing."""
    signer, reports = world["report_signer"], world["reports"]
    cases = [(0, 300, ("tile", "0", "000")), (5, 3, ("tile", "entries", "000.p", "8"))]
    for start, count, parts in cases:
        d = tmp_path / f"c{start}"
        log = IssuanceLog.create(d / "log", ORIGIN, ORIGIN, d / "log.key.json", key_height=3)
        if start:
            log.append_all(reports[:start], signer.public_root)
        before = log.checkpoint()
        real = IssuanceLog._write_tiles

        def write_then_corrupt(self, *a, **k):
            real(self, *a, **k)
            target = self.directory.joinpath(*parts)
            _flip(target, 30 if "entries" in parts else 0)

        monkeypatch.setattr(IssuanceLog, "_write_tiles", write_then_corrupt)
        with pytest.raises(TlogError, match="does not hold what this append wrote"):
            log.append_all(reports[start:start + count], signer.public_root)
        monkeypatch.undo()
        assert log.checkpoint() == before


def test_a_carried_entry_corrupted_before_the_append_is_found(world, tmp_path):
    """An entry below the last checkpoint that no longer hashes to its tile is carried into the next bundle; the
    append refuses rather than signing it."""
    signer, reports = world["report_signer"], world["reports"]
    log = IssuanceLog.create(tmp_path / "log", ORIGIN, ORIGIN, tmp_path / "log.key.json", key_height=3)
    log.append_all(reports[:5], signer.public_root)
    before = log.checkpoint()
    _flip(log.directory / "tile" / "entries" / "000.p" / "5", 30)
    with pytest.raises(TlogError, match="carried entries"):
        log.append_all(reports[5:8], signer.public_root)
    assert log.checkpoint() == before


def test_entry_lines_are_exact():
    line = tlog.entry_line("a" * 64, "b" * 64)
    assert line == ("entrovouch/issuance/v1 " + "a" * 64 + " " + "b" * 64 + "\n").encode()
    for bad in (("A" * 64, "b" * 64), ("a" * 63, "b" * 64), ("a" * 64, None)):
        with pytest.raises(TlogError):
            tlog.entry_line(*bad)

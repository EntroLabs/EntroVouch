"""Tests for the ENTROVOUCH CBOM (Cryptographic Bill of Materials) generator."""
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from entrovouch.cbom import build_cbom, verify_cbom, render_markdown  # noqa: E402


def _write(d: Path, name: str, content: str) -> None:
    (d / name).write_text(content, encoding="utf-8")


def _prims(rep):
    return {c["primitive"] for c in rep.components}


def _statuses(rep):
    return {c["quantum"] for c in rep.components}


# --- PQ-safe stdlib crypto (the EntroVerse baseline) ------------------------------------------------
def test_pq_safe_stdlib_baseline(tmp_path):
    _write(tmp_path, "auth.py",
           "import hashlib, hmac, secrets\n"
           "def sign(m, k):\n"
           "    return hmac.new(k, m, hashlib.sha3_256).hexdigest()\n"
           "n = secrets.token_bytes(32)\n")
    rep = build_cbom(tmp_path)
    assert rep.verdict == "QUANTUM-SAFE"
    assert "HMAC" in _prims(rep)
    assert "SHA3-256" in _prims(rep)
    assert "secrets-CSPRNG" in _prims(rep)
    assert "VULNERABLE" not in _statuses(rep) and "BROKEN" not in _statuses(rep)


def test_pq_signature_tokens_detected(tmp_path):
    # how ENTROVERSE names its PQ schemes in code (scheme strings + class names)
    _write(tmp_path, "pq.py",
           'SCHEME = "lamport-merkle-sha3"\n'
           'class MerkleConsentAuthority: pass\n'
           'ALG = "ML-DSA-65"\n')
    rep = build_cbom(tmp_path)
    assert rep.verdict == "QUANTUM-SAFE"
    prims = _prims(rep)
    assert any("Lamport" in p for p in prims)
    assert any("Merkle" in p or "XMSS" in p for p in prims)
    assert any("ML-DSA" in p for p in prims)


# --- quantum-vulnerable public-key crypto = MIGRATION-NEEDED ----------------------------------------
def test_vulnerable_rsa_flags_migration(tmp_path):
    _write(tmp_path, "legacy.py", "import rsa\nk = rsa.newkeys(2048)\n")
    rep = build_cbom(tmp_path)
    assert rep.verdict == "MIGRATION-NEEDED"
    assert "VULNERABLE" in _statuses(rep)
    assert any("RSA" in p for p in _prims(rep))


def test_vulnerable_ecdsa_token(tmp_path):
    _write(tmp_path, "e.py", 'CURVE = "secp256r1"\nkind = "ecdsa"\n')
    rep = build_cbom(tmp_path)
    assert rep.verdict == "MIGRATION-NEEDED"
    assert any(c["quantum"] == "VULNERABLE" for c in rep.components)


def test_ed25519_and_x25519_vulnerable(tmp_path):
    _write(tmp_path, "c.py", 'a = "ed25519"\nb = "x25519"\n')
    rep = build_cbom(tmp_path)
    assert rep.verdict == "MIGRATION-NEEDED"


# --- classically broken primitives = BROKEN-CRYPTO (worst) ------------------------------------------
def test_broken_md5_worst_verdict(tmp_path):
    _write(tmp_path, "b.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    rep = build_cbom(tmp_path)
    assert rep.verdict == "BROKEN-CRYPTO"
    assert any(c["primitive"] == "MD5" and c["quantum"] == "BROKEN" for c in rep.components)


def test_broken_dominates_vulnerable(tmp_path):
    # both present -> BROKEN wins the verdict
    _write(tmp_path, "b.py", "import hashlib, rsa\nhashlib.sha1(b'x')\n")
    rep = build_cbom(tmp_path)
    assert rep.verdict == "BROKEN-CRYPTO"


def test_hashlib_new_string_algo(tmp_path):
    _write(tmp_path, "n.py", "import hashlib\nh = hashlib.new('sha256')\n")
    rep = build_cbom(tmp_path)
    assert "SHA-256" in _prims(rep)
    assert rep.verdict == "QUANTUM-SAFE"   # sha256 is GROVER-REDUCED, not vulnerable


# --- the discipline: prose that NAMES an algorithm must not fire ------------------------------------
def test_docstring_prose_not_flagged(tmp_path):
    _write(tmp_path, "doc.py",
           '"""This module deliberately avoids RSA and ECDSA and uses only post-quantum schemes."""\n'
           "import hashlib\n"
           "hashlib.sha3_512(b'x')\n")
    rep = build_cbom(tmp_path)
    # the long docstring sentence mentioning RSA/ECDSA is skipped; only the real SHA3-512 use fires
    assert rep.verdict == "QUANTUM-SAFE"
    assert "SHA3-512" in _prims(rep)
    assert not any("RSA" in p for p in _prims(rep))


def test_weak_rng_flagged_informational(tmp_path):
    _write(tmp_path, "r.py", "import random\nrandom.random()\n")
    rep = build_cbom(tmp_path)
    assert any(c["quantum"] == "WEAK-RNG" for c in rep.components)
    # weak RNG alone doesn't downgrade the verdict below QUANTUM-SAFE (it's informational)
    assert rep.verdict == "QUANTUM-SAFE"


def test_library_import_review(tmp_path):
    _write(tmp_path, "l.py", "from cryptography.hazmat.primitives import hashes\n")
    rep = build_cbom(tmp_path)
    assert any(c["quantum"] == "REVIEW" for c in rep.components)


# --- signing / integrity ----------------------------------------------------------------------------
def test_signature_verifies(tmp_path):
    _write(tmp_path, "a.py", "import hashlib\nhashlib.sha3_256(b'x')\n")
    rep = build_cbom(tmp_path)
    assert verify_cbom(asdict(rep)) == (False, "UNSIGNED")  # fail-closed: unsigned is not evidence


def test_signature_breaks_on_tamper(tmp_path):
    _write(tmp_path, "a.py", "import hashlib\nhashlib.sha3_256(b'x')\n")
    rep = build_cbom(tmp_path)
    d = asdict(rep)
    d["verdict"] = "QUANTUM-SAFE-TAMPERED"
    assert verify_cbom(d) == (False, "TAMPERED")


def test_components_ordered_most_severe_first(tmp_path):
    _write(tmp_path, "m.py", "import hashlib, rsa\nhashlib.md5(b'x')\nhashlib.sha3_512(b'y')\n")
    rep = build_cbom(tmp_path)
    order = [c["quantum"] for c in rep.components]
    # BROKEN appears before VULNERABLE before SAFE
    assert order.index("BROKEN") < order.index("VULNERABLE") < order.index("SAFE")


def test_markdown_renders_with_badge(tmp_path):
    _write(tmp_path, "a.py", "import rsa\n")
    rep = build_cbom(tmp_path)
    md = render_markdown(rep)
    assert "MIGRATION-NEEDED" in md and "RSA" in md and "Cryptographic Bill of Materials" in md


def test_skip_dirs_ignored(tmp_path):
    (tmp_path / "__pycache__").mkdir()
    _write(tmp_path / "__pycache__", "junk.py", "import rsa\n")
    _write(tmp_path, "ok.py", "import hashlib\nhashlib.sha3_256(b'x')\n")
    rep = build_cbom(tmp_path)
    assert rep.verdict == "QUANTUM-SAFE"


def test_empty_dir_no_components(tmp_path):
    rep = build_cbom(tmp_path)
    assert rep.components == [] and rep.verdict == "QUANTUM-SAFE"

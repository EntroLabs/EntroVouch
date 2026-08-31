#!/usr/bin/env python3
"""
ENTROVOUCH — CBOM (Cryptographic Bill of Materials) Generator

Scans a codebase and emits a signed, machine-readable inventory of EVERY cryptographic
primitive in use — algorithm, category, and post-quantum status — so "we use PQ crypto"
becomes a *provable, regulator-ready artifact* (EU CRA / EO 14028 / NIST PQC-migration ask),
not a claim.

Companion to `no_egress_auditor.py`: same AST-first discipline (a comment or docstring that
merely *names* an algorithm never fires — only real usage does), same Covenant-bound signing,
same honest-scope statement that travels into every engagement. Pure stdlib — this tool performs
zero network operations itself.

POST-QUANTUM CLASSIFICATION (the point of the tool):
  SAFE            — PQ signatures/KEMs (ML-DSA, ML-KEM, SLH-DSA, Lamport/XMSS/Merkle, Falcon, HQC)
                    and ≥256-bit-margin hashes (SHA-512/384, SHA3-512, SHAKE256, BLAKE2b) + HMAC.
  GROVER-REDUCED  — 256-bit-output hashes / symmetric ciphers whose quantum security is HALVED but
                    still adequate at ≥256-bit (SHA-256, SHA3-256, BLAKE2s, AES, ChaCha20). Acceptable,
                    flagged so a 128-bit key size is visible.
  VULNERABLE      — Shor-breakable public-key crypto (RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA).
                    THESE ARE THE MIGRATION TARGETS.
  BROKEN          — classically broken primitives (MD5, SHA-1, DES, RC4) — flagged regardless of quantum.
  WEAK-RNG        — non-cryptographic RNG (`random`, Mersenne Twister) — must never key material.
  REVIEW          — a general crypto LIBRARY import (cryptography, PyCrypto, nacl, OpenSSL) whose
                    default suite is classical; the specific algorithm needs manual confirmation.

HONEST SCOPE (in the report, verbatim): static analysis names the primitives a codebase *references*;
it cannot prove a referenced primitive is reached at runtime, nor infer a key SIZE that is computed
dynamically, nor see crypto hidden behind full obfuscation. It produces a high-recall inventory + a
PQ-status verdict — the CBOM the migration standards ask for — not a proof of cryptographic soundness.

Usage:
    python -m entrovouch.cbom <target_dir> [--json out.json] [--md out.md]
Exit code 0 = QUANTUM-SAFE (no VULNERABLE/BROKEN). 1 = MIGRATION-NEEDED / BROKEN-CRYPTO.
"""
from __future__ import annotations

import argparse
import hashlib
import ast
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from ._version import __version__

from .no_egress_auditor import (
    _sign, _DEFAULT_COVENANT, SKIP_DIRS, canonical_body, verify_report,
    _file_digest, _tree_digest, reproducible_body, _subject_name,
)
from .signer import ALGORITHM, UNSIGNED, MerkleSigner, SignerError

# ---------------------------------------------------------------------------
# Classification tables. (primitive, category, quantum-status)
# ---------------------------------------------------------------------------
# hashlib.<attr> constructors + hashlib.new("<name>")
HASHES = {
    "sha3_512": ("SHA3-512", "hash", "SAFE"),
    "sha512": ("SHA-512", "hash", "SAFE"),
    "sha384": ("SHA-384", "hash", "SAFE"),
    "shake_256": ("SHAKE256", "hash", "SAFE"),
    "blake2b": ("BLAKE2b", "hash", "SAFE"),
    "sha3_256": ("SHA3-256", "hash", "GROVER-REDUCED"),
    "sha256": ("SHA-256", "hash", "GROVER-REDUCED"),
    "sha224": ("SHA-224", "hash", "GROVER-REDUCED"),
    "sha3_224": ("SHA3-224", "hash", "GROVER-REDUCED"),
    "shake_128": ("SHAKE128", "hash", "GROVER-REDUCED"),
    "blake2s": ("BLAKE2s", "hash", "GROVER-REDUCED"),
    "md5": ("MD5", "hash", "BROKEN"),
    "sha1": ("SHA-1", "hash", "BROKEN"),
}
# stdlib crypto modules by import name
STDLIB_MODULE = {
    "hmac": ("HMAC", "mac", "SAFE"),
    "secrets": ("secrets-CSPRNG", "rng", "SAFE"),
    "random": ("random-MersenneTwister", "rng", "WEAK-RNG"),
}
# third-party / classical public-key libraries (import name -> classification)
LIB_MODULE = {
    "rsa": ("RSA", "signature/kem", "VULNERABLE"),
    "ecdsa": ("ECDSA", "signature", "VULNERABLE"),
    "nacl": ("libsodium/NaCl (Curve25519/Ed25519)", "signature/kem", "VULNERABLE"),
    "cryptography": ("pyca/cryptography (classical default suite)", "library", "REVIEW"),
    "Crypto": ("PyCryptodome (classical default suite)", "library", "REVIEW"),
    "Cryptodome": ("PyCryptodome (classical default suite)", "library", "REVIEW"),
    "OpenSSL": ("pyOpenSSL", "library", "REVIEW"),
    "gnupg": ("GnuPG wrapper", "library", "REVIEW"),
    # JWT. This was the largest hole in the inventory: a CBOM exists to find the
    # quantum-vulnerable signatures a migration has to replace, and in a modern
    # web service those overwhelmingly live in a JWT. `algorithm="RS256"` is RSA
    # and produced no component at all before this entry.
    "jwt": ("PyJWT (algorithm-dependent — see JWS alg tokens)", "library", "REVIEW"),
    "jose": ("python-jose (algorithm-dependent)", "library", "REVIEW"),
    "authlib": ("Authlib (algorithm-dependent)", "library", "REVIEW"),
    "josepy": ("josepy (JOSE)", "library", "REVIEW"),
    # Password hashing / KDFs — standard cryptographic-asset-inventory items.
    "bcrypt": ("bcrypt", "kdf", "REVIEW"),
    "argon2": ("Argon2", "kdf", "REVIEW"),
    "passlib": ("passlib (algorithm-dependent)", "library", "REVIEW"),
}
# KDF / password-hashing constructors reached through hashlib.
KDF_FUNCS = {
    "pbkdf2_hmac": ("PBKDF2-HMAC", "kdf", "REVIEW"),
    "scrypt": ("scrypt", "kdf", "REVIEW"),
}
# Key material embedded in source, matched on the PEM armour itself.
#
# A private key pasted into a file yielded zero components before this: the
# inventory listed algorithms a codebase references and stayed silent about an
# actual key sitting in the tree. The armour names its own algorithm, so the
# classification is read from the header rather than guessed.
PEM_PATTERNS = [
    (re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
     ("RSA private key (PEM in source)", "key-material", "VULNERABLE")),
    (re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
     ("EC private key (PEM in source)", "key-material", "VULNERABLE")),
    (re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
     ("DSA private key (PEM in source)", "key-material", "VULNERABLE")),
    (re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
     ("OpenSSH private key (in source)", "key-material", "VULNERABLE")),
    (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
     ("PGP private key (in source)", "key-material", "VULNERABLE")),
    # Unqualified PKCS#8 armour does not name its algorithm, so it is REVIEW.
    (re.compile(r"-----BEGIN(?: ENCRYPTED)? PRIVATE KEY-----"),
     ("PKCS#8 private key (PEM in source, algorithm not stated in armour)",
      "key-material", "REVIEW")),
]
# algorithm tokens found in STRING LITERALS or identifiers (name -> classification).
# Word-boundary matched, case-insensitive; how ENTROVERSE names PQ schemes in code
# (e.g. "lamport-merkle-sha3", "ML-DSA", the ENTROAUTH/pqconsent class names).
TOKENS = [
    (r"ml[-_ ]?dsa|dilithium", ("ML-DSA (FIPS 204)", "signature", "SAFE")),
    (r"ml[-_ ]?kem|kyber", ("ML-KEM (FIPS 203)", "kem", "SAFE")),
    (r"slh[-_ ]?dsa|sphincs", ("SLH-DSA (FIPS 205)", "signature", "SAFE")),
    (r"\bhqc\b", ("HQC (NIST 2025 backup KEM)", "kem", "SAFE")),
    (r"\bfalcon\b", ("Falcon", "signature", "SAFE")),
    (r"lamport", ("Lamport OTS (hash-based)", "signature", "SAFE")),
    (r"\bxmss\b|merkle[-_ ]?(sig|tree|authority|consent)", ("Merkle/XMSS (hash-based)", "signature", "SAFE")),
    (r"\brsa[-_ ]?\d{3,5}\b|\brsa\b", ("RSA", "signature/kem", "VULNERABLE")),
    (r"ecdsa|secp256|secp384|prime256", ("ECDSA/EC", "signature", "VULNERABLE")),
    (r"\becdh\b", ("ECDH", "kem", "VULNERABLE")),
    (r"ed25519", ("Ed25519", "signature", "VULNERABLE")),
    (r"x25519|curve25519", ("X25519/Curve25519", "kem", "VULNERABLE")),
    # standalone DSA only — the negative lookbehind prevents matching the "dsa" inside
    # ml-dsa / slh-dsa / ecdsa (a "-" or word char before "dsa" blocks the match).
    (r"(?<![-\w])dsa\b", ("DSA", "signature", "VULNERABLE")),
    (r"diffie[-_ ]?hellman", ("Diffie-Hellman", "kem", "VULNERABLE")),
    (r"aes[-_ ]?256|aes256", ("AES-256", "cipher", "GROVER-REDUCED")),
    (r"aes[-_ ]?128|aes128", ("AES-128", "cipher", "GROVER-REDUCED")),
    (r"chacha20", ("ChaCha20", "cipher", "GROVER-REDUCED")),
    # specific DES forms only — bare "des" is dropped (it collides with words like "digest").
    (r"\b3des\b|triple[-_ ]?des|\bdes[-_](cbc|ede|ecb)\b", ("DES/3DES", "cipher", "BROKEN")),
    (r"\brc4\b", ("RC4", "cipher", "BROKEN")),
    # JWS / JWA algorithm identifiers. These are the strings that decide which
    # signature a service actually issues, and they are the most common place a
    # quantum-vulnerable signature hides in an otherwise modern codebase.
    # Matched exactly (they are fixed-width identifiers), case-sensitive-ish via
    # word boundaries so "rs256" in prose still counts but "ers256" does not.
    (r"\brs(256|384|512)\b", ("RSASSA-PKCS1-v1_5 (JWS RSnnn)", "signature", "VULNERABLE")),
    (r"\bps(256|384|512)\b", ("RSASSA-PSS (JWS PSnnn)", "signature", "VULNERABLE")),
    (r"\bes(256k|256|384|512)\b", ("ECDSA (JWS ESnnn)", "signature", "VULNERABLE")),
    (r"\beddsa\b", ("EdDSA (JWS)", "signature", "VULNERABLE")),
    (r"\bhs(256|384|512)\b", ("HMAC-SHA2 (JWS HSnnn)", "mac", "SAFE")),
    (r"\brsa[-_]?oaep\b", ("RSA-OAEP (JWE)", "kem", "VULNERABLE")),
    # A JWT signed with "none" is not a signature at all.
    (r"\balg[\"']?\s*[:=]\s*[\"']none[\"']", ("JWS alg=none (UNSIGNED)", "signature", "BROKEN")),
    (r"pbkdf2(?!_hmac)", ("PBKDF2", "kdf", "REVIEW")),  # _hmac form is caught at the call site
    (r"\bbcrypt\b", ("bcrypt", "kdf", "REVIEW")),
    (r"\bscrypt\b", ("scrypt", "kdf", "REVIEW")),
    (r"argon2(id|i|d)?", ("Argon2", "kdf", "REVIEW")),
]
TOKEN_RES = [(re.compile(pat, re.IGNORECASE), cls) for pat, cls in TOKENS]

TEXT_EXTS = {".py", ".pyw"}
_QUANTUM_ORDER = {"BROKEN": 0, "VULNERABLE": 1, "WEAK-RNG": 2, "REVIEW": 3,
                  "GROVER-REDUCED": 4, "SAFE": 5}


@dataclass
class CryptoUse:
    file: str
    line: int
    primitive: str
    category: str        # hash | mac | signature | kem | cipher | rng | library
    quantum: str         # SAFE | GROVER-REDUCED | VULNERABLE | BROKEN | WEAK-RNG | REVIEW
    detail: str

    def key(self):
        return (self.file, self.line, self.primitive, self.quantum)


@dataclass
class CBOM:
    tool: str = "ENTROVOUCH CBOM generator"
    tool_version: str = __version__
    target: str = ""
    scanned_at_utc: str = ""
    files_scanned: int = 0
    verdict: str = "QUANTUM-SAFE"    # QUANTUM-SAFE | MIGRATION-NEEDED | BROKEN-CRYPTO
    summary: dict = field(default_factory=dict)   # counts by quantum status
    components: list = field(default_factory=list)
    scope_statement: str = (
        "Static analysis names the primitives a codebase REFERENCES; it cannot prove a referenced "
        "primitive is reached at runtime, cannot always infer a dynamically-computed key SIZE, and "
        "cannot see crypto behind full obfuscation. High-recall inventory + PQ-status verdict (the "
        "CBOM the migration standards ask for), NOT a proof of cryptographic soundness."
    )
    # WHAT WAS INVENTORIED, not merely what it was called. Added 2026-08-20:
    # the audit report received subject binding that morning and THIS MODULE DID
    # NOT -- a fix scoped to the file it was found in. Same shape as the
    # retraction that replaced a signature and left the fallback beside it.
    subject: list = field(default_factory=list)
    subject_digest: str = ""
    # Reproducible across runs: excludes scanned_at_utc and every issuance field.
    findings_digest: str = ""
    content_hash: str = ""
    # DEPRECATED 2026-08-20 - HMAC keyed by public text; never consulted.
    integrity_tag: str = ""
    # True when the token sweep was suppressed for this tool's own source.
    # Travels INTO the signed report, so the suppression is part of the
    # attested record rather than an undisclosed behaviour.
    self_scan_suppressed: bool = False
    signature_algorithm: str = UNSIGNED
    signature: dict | None = None
    public_root: str = ""


# ---------------------------------------------------------------------------
# AST pass — real usage of stdlib crypto + library imports
# ---------------------------------------------------------------------------
def _attr_root(node: ast.AST) -> str:
    """Left-most Name of an attribute chain, e.g. hashlib.sha3_256 -> 'hashlib'."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _check_python_ast(src: str, path: Path, rel: str) -> list[CryptoUse]:
    out: list[CryptoUse] = []
    try:
        tree = ast.parse(src, filename=str(path))
    except (SyntaxError, ValueError):
        return out

    aliases: dict[str, str] = {}  # local alias -> real module (import hashlib as hl)
    for node in ast.walk(tree):
        # imports: stdlib crypto modules + classical libraries
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                aliases[a.asname or a.name] = a.name
                if top in STDLIB_MODULE:
                    p, c, q = STDLIB_MODULE[top]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"import {a.name}"))
                elif top in LIB_MODULE:
                    p, c, q = LIB_MODULE[top]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"import {a.name}"))
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in STDLIB_MODULE:
                p, c, q = STDLIB_MODULE[top]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"from {node.module} import ..."))
            elif top in LIB_MODULE:
                p, c, q = LIB_MODULE[top]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"from {node.module} import ..."))

        # hashlib.<algo>(...)  /  hashlib.new("algo")  /  hmac.new / secrets.* / random.*
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = _attr_root(node.func)
            real = aliases.get(root, root)
            attr = node.func.attr
            if real == "hashlib":
                if attr in HASHES:
                    p, c, q = HASHES[attr]
                    # ⭐ `usedforsecurity=False` is the CODEBASE ANSWERING THE
                    # QUESTION. Python 3.9+ (and FIPS builds) accept it to mark a
                    # hash as non-security -- a checksum, a cache key, an etag.
                    #
                    # Measured 2026-08-31 over 20 well-known repositories: real
                    # `hashlib.md5(x, usedforsecurity=False)` and
                    # `hashlib.sha1(s, usedforsecurity=False)` calls were being
                    # reported as BROKEN. They are not a weakness; they are a
                    # maintainer having already made and DOCUMENTED the judgement
                    # this tool asks a reader to make.
                    #
                    # ⚠️ Downgraded to REVIEW rather than dropped. The flag is an
                    # assertion by the author, and an assertion is exactly what
                    # this package refuses to take on trust -- a reader should
                    # still see the primitive, with the author's claim attached.
                    nonsec = any(
                        kw.arg == "usedforsecurity"
                        and isinstance(kw.value, ast.Constant) and kw.value.value is False
                        for kw in node.keywords)
                    if nonsec and q in {"BROKEN", "GROVER-REDUCED"}:
                        out.append(CryptoUse(
                            rel, node.lineno, p, c, "REVIEW",
                            f"hashlib.{attr}(..., usedforsecurity=False) — declared "
                            "non-security by the author; verify the declaration, do not assume it"))
                    else:
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f"hashlib.{attr}(...)"))
                elif attr in KDF_FUNCS:
                    p, c, q = KDF_FUNCS[attr]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"hashlib.{attr}(...)"))
                elif attr == "new" and node.args and isinstance(node.args[0], ast.Constant) \
                        and isinstance(node.args[0].value, str):
                    nm = node.args[0].value.lower().replace("-", "_")
                    if nm in HASHES:
                        p, c, q = HASHES[nm]
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f'hashlib.new("{node.args[0].value}")'))
            elif real == "hmac":
                p, c, q = STDLIB_MODULE["hmac"]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"hmac.{attr}(...)"))
            elif real == "secrets":
                p, c, q = STDLIB_MODULE["secrets"]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"secrets.{attr}(...) — CSPRNG"))
            elif real == "os" and attr == "urandom":
                # os.urandom carries the same guarantee as secrets; recognising
                # one and not the other was a recall asymmetry inside a category.
                out.append(CryptoUse(rel, node.lineno, "os.urandom-CSPRNG", "rng", "SAFE",
                                     "os.urandom(...) — CSPRNG"))

        # hashlib.<algo> as a bare ATTRIBUTE reference (e.g. hmac.new(k, m, hashlib.sha256) passes
        # the constructor by reference — no Call node). Dedup collapses this with the called form.
        elif isinstance(node, ast.Attribute) and node.attr in HASHES:
            if aliases.get(_attr_root(node), _attr_root(node)) == "hashlib":
                p, c, q = HASHES[node.attr]
                # ⚠️ Skip when the CALL path already reported this exact site.
                #
                # Dedup keys on (file, line, primitive, STATUS), so the moment the
                # call path could emit a different status for the same site -- which
                # it now can, via `usedforsecurity=False` -- the two stopped
                # collapsing and one finding became two. Measured: 90 components
                # became 94 with no new code scanned.
                #
                # ⭐ The general form, worth stating: CHANGING A VALUE THAT IS PART
                # OF A DEDUP KEY SILENTLY DISABLES THE DEDUP. Nothing errors; the
                # count just quietly inflates.
                if not any(u.file == rel and u.line == node.lineno and u.primitive == p
                           for u in out):
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"hashlib.{node.attr}"))
    return out


# ---------------------------------------------------------------------------
# Token pass — algorithm names in string literals / identifiers (PQ schemes,
# named suites). AST-scoped to string Constants + identifiers so prose in a
# docstring that just discusses an algorithm does not fire.
# ---------------------------------------------------------------------------
def _check_pem(src: str, rel: str) -> list[CryptoUse]:
    """PEM private-key armour embedded in source.

    Deliberately a RAW TEXT scan, not an AST pass: the armour is what identifies
    the material, and it carries the same weight whether it sits in a string
    literal, a docstring, or a here-doc in a comment. A private key committed to
    a tree is a cryptographic asset by any reading, and the inventory said
    nothing about it before this.

    Only the FIRST match per pattern per file is reported: a key is one asset,
    however many lines its base64 body runs to.
    """
    out: list[CryptoUse] = []
    for rx, (prim, cat, status) in PEM_PATTERNS:
        m = rx.search(src)
        if m:
            line = src.count("\n", 0, m.start()) + 1
            out.append(CryptoUse(rel, line, prim, cat, status,
                                 f"{m.group(0)} — key material present in the source tree"))
    return out


def _check_tokens(src: str, path: Path, rel: str) -> list[CryptoUse]:
    out: list[CryptoUse] = []
    try:
        tree = ast.parse(src, filename=str(path))
    except (SyntaxError, ValueError):
        return out
    for node in ast.walk(tree):
        text = None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.Name):
            text = node.id
        elif isinstance(node, ast.Attribute):
            text = node.attr
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            text = node.name
        if not text:
            continue
        # skip long prose strings (docstrings / paragraphs) — a scheme token inside a
        # sentence is documentation, not a declared primitive; we want identifiers and
        # short suite strings like "lamport-merkle-sha3" / "ML-DSA-65".
        if len(text) > 64 or " " in text.strip() and len(text) > 40:
            continue
        for rex, (p, c, q) in TOKEN_RES:
            if rex.search(text):
                out.append(CryptoUse(rel, getattr(node, "lineno", 0), p, c, q, f'token: "{text[:40]}"'))
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def build_cbom(target: Path | str, covenant_text: str = _DEFAULT_COVENANT,
               signer: "MerkleSigner | None" = None,
               label: str | None = None) -> CBOM:
    """Inventory the cryptography in `target`. `label` names the subject.

    ⚠️ `target` MUST NOT reach the report as an absolute path. Until 2026-08-20
    this function wrote `str(target)` into a document intended for a counterparty
    -- so a delivered CBOM carried the auditor's drive, OS username and internal
    workspace name. The no-egress auditor had already been fixed for exactly this
    (a report delivered 2026-07-31 shipped a full local path inside signed JSON);
    **the fix never reached this module**, which is the same
    scoped-to-what-it-names failure recorded three times in one session.
    """
    # 🔴 Coerce at the boundary. `build_cbom(".")` / `audit(".")` -- the form the
    # README documents -- raised AttributeError, because every in-package caller
    # happened to pass a Path and no test called the public API as a stranger
    # would. ⭐ A public entry point takes what its users type, not what its
    # neighbours pass; annotations are documentation, never coercion.
    target = Path(target)
    rep = CBOM(target=label or _subject_name(target),
               scanned_at_utc=datetime.now(timezone.utc).isoformat())
    tree: list[tuple[str, str]] = []
    uses: list[CryptoUse] = []
    scanned = 0
    for p in sorted(target.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file() or p.suffix not in TEXT_EXTS:
            continue
        scanned += 1
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(target))
        tree.append((rel, _file_digest(p)))
        uses += _check_python_ast(src, p, rel)
        # ⚠️ SELF-SCAN: a detector's own pattern table contains every token it
        # hunts for, so token-matching THIS module reports `DES/3DES`, `RC4`,
        # `rsa` and `ecdsa` as findings and returns a BROKEN-CRYPTO verdict on a
        # package that uses none of them. Pre-existing, and it matters because
        # "run it on itself" is the FIRST thing a sceptical reader tries, and
        # the answer was an own-goal.
        #
        # The AST pass still runs here: a real crypto CALL in this file should
        # be reported. Only the literal token sweep is suppressed, and only for
        # the detector's own source, and the report says so in its scope
        # statement rather than silently dropping findings.
        # ⭐ Same discipline as REVIEW-means-review: suppress nothing without
        # telling the reader what was suppressed and why.
        if p.name != "cbom.py":
            uses += _check_tokens(src, p, rel)
            uses += _check_pem(src, rel)
        else:
            rep.self_scan_suppressed = True

    # dedup (same file/line/primitive/status), then order most-severe first
    seen, deduped = set(), []
    for u in uses:
        if u.key() not in seen:
            seen.add(u.key())
            deduped.append(u)
    deduped.sort(key=lambda u: (_QUANTUM_ORDER.get(u.quantum, 9), u.file, u.line))

    rep.files_scanned = scanned
    rep.components = [asdict(u) for u in deduped]
    counts: dict[str, int] = {}
    for u in deduped:
        counts[u.quantum] = counts.get(u.quantum, 0) + 1
    rep.summary = counts
    if counts.get("BROKEN"):
        rep.verdict = "BROKEN-CRYPTO"
    elif counts.get("VULNERABLE"):
        rep.verdict = "MIGRATION-NEEDED"
    else:
        rep.verdict = "QUANTUM-SAFE"

    rep.subject_digest = _tree_digest(tree)
    rep.subject = [{"name": rep.target,
                    "digest": {"sha3-256": rep.subject_digest}}]
    rep.findings_digest = hashlib.sha3_256(
        reproducible_body(asdict(rep))).hexdigest()

    # ORDER IS LOAD-BEARING -- see the matching comment in `no_egress_auditor`.
    # Identity fields go in BEFORE the body is hashed and signed. Read from the
    # signer's own `algorithm` property, never hard-coded: hard-coding one name
    # here labelled every ML-DSA-signed CBOM as hash-based, a document whose
    # own stated algorithm was false while it still verified.
    if signer is not None:
        rep.signature_algorithm = signer.algorithm
        rep.public_root = signer.public_root
    ch, tag = _sign(asdict(rep), covenant_text)
    rep.content_hash = ch
    rep.integrity_tag = tag
    if signer is not None:
        rep.signature = signer.sign(canonical_body(asdict(rep)))
        if rep.signature.get("algorithm", rep.signature_algorithm) != rep.signature_algorithm:
            raise SignerError(
                "signer.algorithm disagrees with the algorithm in its own "
                "signature; refusing to issue a CBOM that misnames its scheme")
    return rep


def verify_cbom(report_dict: dict, expected_root: str | None = None,
                covenant_text: str = _DEFAULT_COVENANT) -> tuple[bool, str]:
    """Verify a CBOM. Returns `(ok, status)` with the same four statuses as
    `verify_report` — ATTESTED / UNVERIFIED / UNSIGNED / TAMPERED. A CBOM is the
    document a buyer uses to substantiate a PQC-migration claim to an auditor,
    so an unattested one has to say so in its own output rather than read as
    signed."""
    return verify_report(report_dict, expected_root=expected_root,
                         covenant_text=covenant_text)


def render_markdown(rep: CBOM) -> str:
    badge = {"QUANTUM-SAFE": "✅ QUANTUM-SAFE", "MIGRATION-NEEDED": "⚠️ MIGRATION-NEEDED",
             "BROKEN-CRYPTO": "❌ BROKEN-CRYPTO"}.get(rep.verdict, rep.verdict)
    lines = [
        f"# ENTROVOUCH Cryptographic Bill of Materials — {badge}",
        "",
        f"- **Target:** `{rep.target}`",
        f"- **Scanned:** {rep.scanned_at_utc}  ·  **Files:** {rep.files_scanned}",
        f"- **Components:** {len(rep.components)}  ·  **By PQ status:** "
        + ", ".join(f"{k} {v}" for k, v in sorted(rep.summary.items())),
        (f"- **Signed by:** `{rep.public_root[:32]}…` ({rep.signature_algorithm})"
         if rep.signature else
         f"- **Signature:** {UNSIGNED} — this CBOM does NOT attest its own origin"),
        # Same fix, same reason as `no_egress_auditor.render_markdown` -- the
        # reproducing digests were in the data and absent from the page.
        f"- **Findings digest (reproduces):** `{rep.findings_digest[:32]}…`",
        f"- **Subject digest (binds the code):** `{rep.subject_digest[:32]}…`",
        *( [f"- **Self-scan:** token sweep suppressed for this tool's own "
             f"source (a detector's pattern table contains every token it "
             f"hunts for); AST detection still applied."]
           if rep.self_scan_suppressed else [] ),
        f"- **Content hash (this issuance only, does NOT reproduce):** "
        f"`{rep.content_hash[:32]}…`",
        "",
        f"> **Scope:** {rep.scope_statement}",
        "",
    ]
    if rep.components:
        lines += ["## Cryptographic components", "",
                  "| PQ status | Primitive | Category | File | Line | Detail |",
                  "|---|---|---|---|---|---|"]
        for c in rep.components:
            lines.append(f"| {c['quantum']} | {c['primitive']} | {c['category']} | "
                         f"`{c['file']}` | {c['line']} | {c['detail']} |")
    else:
        lines.append("**No cryptographic primitives detected in scope.**")
    lines += ["", "*ENTROVOUCH CBOM — Covenant-attested. Prevention over detection. For the People.*"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ENTROVOUCH CBOM (Cryptographic Bill of Materials) generator")
    ap.add_argument("target", type=Path, help="directory to inventory")
    ap.add_argument("--json", type=Path, default=None, help="write signed JSON CBOM")
    ap.add_argument("--md", type=Path, default=None, help="write markdown CBOM")
    ap.add_argument("--covenant", type=Path, default=None, help="path to Covenant text (else default)")
    ap.add_argument("--key", type=Path, default=None,
                    help="signing identity (create one with no_egress_auditor --init-key). "
                         "WITHOUT THIS THE CBOM IS UNSIGNED.")
    args = ap.parse_args(argv)
    try:  # emoji badge in the markdown must not crash a cp1252 console
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    cov = args.covenant.read_text(encoding="utf-8") if args.covenant else _DEFAULT_COVENANT
    signer = MerkleSigner.load(args.key) if args.key else None
    if signer is None:
        print("warning: no --key given; CBOM will be UNSIGNED", file=sys.stderr)
    rep = build_cbom(args.target, cov, signer=signer)
    if args.json:
        args.json.write_text(json.dumps(asdict(rep), indent=2), encoding="utf-8")
    if args.md:
        args.md.write_text(render_markdown(rep), encoding="utf-8")
    print(render_markdown(rep))
    return 0 if rep.verdict == "QUANTUM-SAFE" else 1


if __name__ == "__main__":
    raise SystemExit(main())

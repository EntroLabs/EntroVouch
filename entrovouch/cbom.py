#!/usr/bin/env python3
"""
ENTROVOUCH: CBOM (Cryptographic Bill of Materials) Generator

Scans Python source and emits a signed, machine-readable inventory of the cryptographic
primitives it recognises: algorithm, category and post-quantum status. It is the inventory
the migration guidance asks for (EU CRA, EO 14028, NIST PQC migration), built from what the
source references.

Companion to `no_egress_auditor.py`: same AST-first discipline (a comment or docstring that
merely *names* an algorithm never fires: only real usage does), the same signer,
same honest-scope statement that travels into every engagement. Pure stdlib: this tool performs
zero network operations itself.

POST-QUANTUM CLASSIFICATION (the point of the tool):
  SAFE           : PQ signatures/KEMs (ML-DSA, ML-KEM, SLH-DSA, Lamport/XMSS/Merkle, Falcon, HQC)
                    and ≥256-bit-margin hashes (SHA-512/384, SHA3-512, SHAKE256, BLAKE2b) + HMAC.
  GROVER-REDUCED : 256-bit-output hashes / symmetric ciphers whose quantum security is HALVED but
                    still adequate at ≥256-bit (SHA-256, SHA3-256, BLAKE2s, AES, ChaCha20). Acceptable,
                    flagged so a 128-bit key size is visible.
  VULNERABLE     : Shor-breakable public-key crypto (RSA, ECDSA, ECDH, Ed25519, X25519, DH, DSA).
                    THESE ARE THE MIGRATION TARGETS.
  BROKEN         : classically broken primitives (MD5, SHA-1, DES, RC4): flagged regardless of quantum.
  WEAK-RNG       : non-cryptographic RNG (`random`, Mersenne Twister): must never key material.
  REVIEW         : a general crypto LIBRARY import (cryptography, PyCrypto, nacl, OpenSSL) whose
                    default suite is classical; the specific algorithm needs manual confirmation.

SCOPE (in the report, verbatim): static analysis names the primitives a codebase references;
it cannot prove a referenced primitive is reached at runtime, nor infer a key size that is
computed dynamically, nor see crypto behind obfuscation, and it reads Python only. It produces
an inventory of the primitives it knows plus a post-quantum status, not a proof of
cryptographic soundness, and NOTHING-VULNERABLE-FOUND means exactly that.

Usage:
    python -m entrovouch.cbom <target_dir> [--json out.json] [--md out.md]
Exit code 0 = NOTHING-VULNERABLE-FOUND. 1 = MIGRATION-NEEDED / BROKEN-CRYPTO. 2 = nothing was scanned.
"""
from __future__ import annotations

import argparse
import hashlib
import ast
import warnings
import json
import re
import sys
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from pathlib import Path

from ._cli import missing_folder, run, write_text
from ._version import __version__

from .no_egress_auditor import (
    _sign, SKIP_DIRS, canonical_body, verify_report,
    _file_digest, _tree_digest, tree_listing_digest, reproducible_body, _subject_name, _rel, _read_python_source,
    markdown_cell, markdown_code, python_units, NotPythonNotebook,
)
from .manifests import tree_files
from .signer import ALGORITHM, UNSIGNED, MerkleSigner, SignerError
from ._pem import armour_with_key
from . import _reads

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
# PyNaCl holds public-key, secret-key, hashing and password-hashing modules; what a line imports decides which.
NACL_PUBLIC = ("libsodium/NaCl (Curve25519/Ed25519)", "signature/kem", "VULNERABLE")
NACL_PARTS = {
    **{k: NACL_PUBLIC for k in ("public", "signing", "crypto_box", "crypto_sign", "crypto_kx", "crypto_scalarmult",
                                "crypto_core")},
    **{k: ("libsodium/NaCl secret-key (XSalsa20/ChaCha20-Poly1305, AES-GCM)", "cipher", "GROVER-REDUCED")
       for k in ("secret", "crypto_aead", "crypto_secretbox", "crypto_secretstream")},
    **{k: ("libsodium/NaCl hashing (BLAKE2b, SipHash, SHA-2)", "hash", "GROVER-REDUCED")
       for k in ("hash", "hashlib", "crypto_generichash", "crypto_shorthash", "crypto_hash")},
    **{k: ("libsodium/NaCl password hashing (Argon2, scrypt)", "kdf", "REVIEW") for k in ("pwhash", "crypto_pwhash")},
    "randombytes": ("libsodium randombytes (CSPRNG)", "rng", "SAFE"),
    # helpers with no primitive in them
    **{k: None for k in ("exceptions", "encoding", "utils", "sodium_core")},
}
NACL_WHOLE = ("libsodium/NaCl (algorithm chosen at the call)", "library", "REVIEW")


# the modules whose `encode` and `decode` make and read JWTs (PyJWT, python-jose)
_JWT_MODULES = {"jwt", "jose", "jose.jwt"}


def _jwt_operation(call: ast.Call, aliases: dict, from_jwt: dict) -> str | None:
    """`encode` or `decode` when the call reaches a JWT library's: `jwt.decode`, `j.decode` after `import jwt as j`,
    `jose.jwt.decode`, `jwt.decode` after `from jose import jwt`, `decode` after `from jwt import decode`."""
    f = call.func
    if isinstance(f, ast.Name):
        op = from_jwt.get(f.id)
        return op if op in ("encode", "decode") else None
    if not (isinstance(f, ast.Attribute) and f.attr in ("encode", "decode")):
        return None
    owner = f.value
    if isinstance(owner, ast.Name):
        if owner.id in ("jwt", "jose_jwt", "pyjwt") or from_jwt.get(owner.id) == "module" \
                or aliases.get(owner.id) in _JWT_MODULES - {"jose"}:
            return f.attr
        return None
    if isinstance(owner, ast.Attribute) and owner.attr == "jwt" and isinstance(owner.value, ast.Name) \
            and aliases.get(owner.value.id, owner.value.id) == "jose":
        return f.attr
    return None


def _only_compare_digest(tree: ast.AST, name: str) -> bool:
    """Is every use of the module bound to `name` (`hmac`, `secrets`) its `compare_digest`?"""
    attrs = {n.attr for n in ast.walk(tree)
             if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == name}
    return attrs == {"compare_digest"}


def _only_system_random(tree: ast.AST, name: str) -> bool:
    """Is every use of the module bound to `name` (`random`) its `SystemRandom` class?"""
    attrs = {n.attr for n in ast.walk(tree)
             if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == name}
    # `random = random.SystemRandom()`: the name is the generator from then on, and its methods are the generator's
    rebound = [n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    if rebound and all(isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "SystemRandom"
                       and isinstance(v.func.value, ast.Name) and v.func.value.id == name for v in rebound):
        return True
    return bool(attrs) and attrs <= {"SystemRandom"}


def nacl_classes(module: str, names: list[str]) -> list[tuple[str, str, str]]:
    """`import nacl.encoding` is a helper, `from nacl.secret import SecretBox` a symmetric cipher, `from nacl import
    signing` Ed25519; `import nacl` or `nacl.bindings` as a whole names no algorithm."""
    parts = module.split(".")
    if len(parts) > 1 and parts[-1] in NACL_PARTS:
        hit = NACL_PARTS[parts[-1]]
        return [hit] if hit else []
    if len(parts) > 2 and parts[1] == "bindings" and parts[-1] == "utils":
        return []
    if module == "nacl" and names:
        found = [NACL_PARTS.get(n, NACL_WHOLE) for n in names]
        return list(dict.fromkeys(h for h in found if h))
    return [NACL_WHOLE]


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
    # JWT. A CBOM exists to find the quantum-vulnerable signatures a migration has to
    # replace, and in a web service those mostly live in a JWT: `algorithm="RS256"` is RSA.
    "jwt": ("PyJWT (algorithm-dependent: see JWS alg tokens)", "library", "REVIEW"),
    "jose": ("python-jose (algorithm-dependent)", "library", "REVIEW"),
    "authlib": ("Authlib (algorithm-dependent)", "library", "REVIEW"),
    "josepy": ("josepy (JOSE)", "library", "REVIEW"),
    # Password hashing / KDFs: standard cryptographic-asset-inventory items.
    "bcrypt": ("bcrypt", "kdf", "REVIEW"),
    "argon2": ("Argon2", "kdf", "REVIEW"),
    "passlib": ("passlib (algorithm-dependent)", "library", "REVIEW"),
    "paramiko": ("paramiko (SSH; key classes name the algorithm)", "library", "REVIEW"),
    "M2Crypto": ("M2Crypto (OpenSSL binding, classical default suite)", "library", "REVIEW"),
    "tink": ("Tink (key templates name the algorithm)", "library", "REVIEW"),
    "pqcrypto": ("pqcrypto (PQC bindings)", "library", "REVIEW"),
    "oqs": ("liboqs wrapper (PQC; algorithm named at the call)", "library", "REVIEW"),
    "kyber_py": ("kyber-py (ML-KEM)", "kem", "SAFE"),
    "dilithium_py": ("dilithium-py (ML-DSA)", "signature", "SAFE"),
}
# paramiko key classes: the class names the algorithm.
PARAMIKO_KEYS = {
    "RSAKey": ("RSA", "signature/kem", "VULNERABLE"), "DSSKey": ("DSA", "signature", "VULNERABLE"),
    "ECDSAKey": ("ECDSA/EC", "signature", "VULNERABLE"), "Ed25519Key": ("Ed25519", "signature", "VULNERABLE"),
}
# pyca/cryptography asymmetric modules: the module names the algorithm family.
PYCA_ASYMMETRIC = {
    "rsa": ("RSA", "signature/kem", "VULNERABLE"), "dsa": ("DSA", "signature", "VULNERABLE"),
    "ec": ("ECDSA/EC", "signature", "VULNERABLE"), "dh": ("Diffie-Hellman (finite field)", "kem", "VULNERABLE"),
    "ed25519": ("Ed25519", "signature", "VULNERABLE"), "ed448": ("Ed448", "signature", "VULNERABLE"),
    "x25519": ("X25519/Curve25519", "kem", "VULNERABLE"), "x448": ("X448", "kem", "VULNERABLE"),
}
# pyOpenSSL key-type constants: `crypto.TYPE_RSA`.
PYOPENSSL_TYPES = {
    "TYPE_RSA": ("RSA", "signature/kem", "VULNERABLE"), "TYPE_DSA": ("DSA", "signature", "VULNERABLE"),
    "TYPE_EC": ("ECDSA/EC", "signature", "VULNERABLE"), "TYPE_DH": ("Diffie-Hellman (finite field)", "kem", "VULNERABLE"),
}
# `ssl.TLSVersion.<member>` values below TLS 1.2.
TLS_VERSION_MEMBERS = {
    "SSLv3": ("SSL 3.0 (TLSVersion)", "protocol", "BROKEN"), "TLSv1": ("TLS 1.0 (TLSVersion)", "protocol", "BROKEN"),
    "TLSv1_1": ("TLS 1.1 (TLSVersion)", "protocol", "BROKEN"),
}
# Block-cipher modes that need a person to look: ECB encrypts equal blocks to equal blocks.
CIPHER_MODES = {"MODE_ECB": ("ECB mode", "cipher-mode", "REVIEW"), "ECB": ("ECB mode", "cipher-mode", "REVIEW")}
# TLS protocol constants and verification switches in the standard library's ssl module.
SSL_ATTRS = {
    "PROTOCOL_SSLv2": ("SSL 2.0 protocol constant", "protocol", "BROKEN"),
    "PROTOCOL_SSLv3": ("SSL 3.0 protocol constant", "protocol", "BROKEN"),
    "PROTOCOL_TLSv1": ("TLS 1.0 protocol constant", "protocol", "BROKEN"),
    "PROTOCOL_TLSv1_1": ("TLS 1.1 protocol constant", "protocol", "BROKEN"),
    "_create_unverified_context": ("TLS certificate verification disabled", "protocol", "REVIEW"),
    "CERT_NONE": ("TLS certificate verification disabled (CERT_NONE)", "protocol", "REVIEW"),
}
# The openssl and ssh-keygen command lines that generate or handle keys.
OPENSSL_SUBCOMMANDS = {
    "genrsa": ("RSA", "signature/kem", "VULNERABLE"), "rsa": ("RSA", "signature/kem", "VULNERABLE"),
    "rsautl": ("RSA", "signature/kem", "VULNERABLE"), "ecparam": ("ECDSA/EC", "signature", "VULNERABLE"),
    "ec": ("ECDSA/EC", "signature", "VULNERABLE"), "dsaparam": ("DSA", "signature", "VULNERABLE"),
    "gendsa": ("DSA", "signature", "VULNERABLE"), "dsa": ("DSA", "signature", "VULNERABLE"),
}
SSH_KEYGEN_TYPES = {
    "rsa": ("RSA", "signature/kem", "VULNERABLE"), "dsa": ("DSA", "signature", "VULNERABLE"),
    "ecdsa": ("ECDSA/EC", "signature", "VULNERABLE"), "ed25519": ("Ed25519", "signature", "VULNERABLE"),
    "ecdsa-sk": ("ECDSA/EC", "signature", "VULNERABLE"), "ed25519-sk": ("Ed25519", "signature", "VULNERABLE"),
}
# pyca/cryptography CLASS constructors: `hashes.MD5()`, `algorithms.AES(key)`. The
# hash table above is keyed on `hashlib.<attr>`; these are the same primitives
# reached through the other library everybody uses.
PYCA_HASHES = {
    "MD5": ("MD5", "hash", "BROKEN"), "SHA1": ("SHA-1", "hash", "BROKEN"),
    "SHA224": ("SHA-224", "hash", "GROVER-REDUCED"), "SHA256": ("SHA-256", "hash", "GROVER-REDUCED"),
    "SHA384": ("SHA-384", "hash", "SAFE"), "SHA512": ("SHA-512", "hash", "SAFE"),
    "SHA3_256": ("SHA3-256", "hash", "GROVER-REDUCED"), "SHA3_512": ("SHA3-512", "hash", "SAFE"),
    "BLAKE2b": ("BLAKE2b", "hash", "SAFE"), "BLAKE2s": ("BLAKE2s", "hash", "GROVER-REDUCED"),
    "SM3": ("SM3", "hash", "REVIEW"),
}
# PyCryptodome, resolved to the actual primitive. A CBOM exists to say WHICH
# primitives; "classical default suite" is the question restated. In PyCryptodome the
# primitive is the module (`from Crypto.Cipher import AES`), so this resolves at the
# import. The library-level entry remains as a fallback for submodules not named here.
PYCRYPTODOME_PRIMITIVES = {
    # Crypto.Cipher
    "AES": ("AES", "cipher", "GROVER-REDUCED"),
    "ChaCha20": ("ChaCha20", "cipher", "GROVER-REDUCED"),
    "ChaCha20_Poly1305": ("ChaCha20-Poly1305", "cipher", "GROVER-REDUCED"),
    "Salsa20": ("Salsa20", "cipher", "GROVER-REDUCED"),
    "DES": ("DES", "cipher", "BROKEN"),
    "DES3": ("DES/3DES", "cipher", "BROKEN"),
    "ARC4": ("RC4", "cipher", "BROKEN"),
    "ARC2": ("RC2", "cipher", "BROKEN"),
    "Blowfish": ("Blowfish", "cipher", "BROKEN"),
    "CAST": ("CAST5", "cipher", "REVIEW"),
    "PKCS1_v1_5": ("RSA PKCS#1 v1.5", "cipher", "VULNERABLE"),
    "PKCS1_OAEP": ("RSA-OAEP", "cipher", "VULNERABLE"),
    # Crypto.Hash
    "MD5": ("MD5", "hash", "BROKEN"),
    "MD4": ("MD4", "hash", "BROKEN"),
    "MD2": ("MD2", "hash", "BROKEN"),
    "SHA1": ("SHA-1", "hash", "BROKEN"),
    "RIPEMD160": ("RIPEMD-160", "hash", "BROKEN"),
    "SHA224": ("SHA-224", "hash", "GROVER-REDUCED"),
    "SHA256": ("SHA-256", "hash", "GROVER-REDUCED"),
    "SHA384": ("SHA-384", "hash", "SAFE"),
    "SHA512": ("SHA-512", "hash", "SAFE"),
    "SHA3_256": ("SHA3-256", "hash", "GROVER-REDUCED"),
    "SHA3_512": ("SHA3-512", "hash", "SAFE"),
    "BLAKE2b": ("BLAKE2b", "hash", "SAFE"),
    "BLAKE2s": ("BLAKE2s", "hash", "GROVER-REDUCED"),
    "HMAC": ("HMAC", "mac", "SAFE"),
    "CMAC": ("CMAC", "mac", "SAFE"),
    "Poly1305": ("Poly1305", "mac", "SAFE"),
    # Crypto.PublicKey / Signature
    "RSA": ("RSA", "signature/kem", "VULNERABLE"),
    "DSA": ("DSA", "signature", "VULNERABLE"),
    "ECC": ("ECDSA/EC", "signature", "VULNERABLE"),
    "ElGamal": ("ElGamal", "signature/kem", "VULNERABLE"),
    "pkcs1_15": ("RSASSA-PKCS1-v1_5", "signature", "VULNERABLE"),
    "pss": ("RSASSA-PSS", "signature", "VULNERABLE"),
    "DSS": ("DSA/ECDSA signature", "signature", "VULNERABLE"),
    # Crypto.Protocol / Random
    "KDF": ("PyCryptodome KDF (see call site)", "kdf", "REVIEW"),
    "scrypt": ("scrypt", "kdf", "SAFE"),
    "PBKDF2": ("PBKDF2", "kdf", "SAFE"),
    "HKDF": ("HKDF", "kdf", "SAFE"),
}

PYCA_CIPHERS = {
    "AES": ("AES", "cipher", "GROVER-REDUCED"), "AES128": ("AES-128", "cipher", "GROVER-REDUCED"),
    "AES256": ("AES-256", "cipher", "GROVER-REDUCED"), "Camellia": ("Camellia", "cipher", "GROVER-REDUCED"),
    "ChaCha20": ("ChaCha20", "cipher", "GROVER-REDUCED"),
    "TripleDES": ("DES/3DES", "cipher", "BROKEN"), "ARC4": ("RC4", "cipher", "BROKEN"),
    "Blowfish": ("Blowfish", "cipher", "BROKEN"), "CAST5": ("CAST5", "cipher", "REVIEW"),
    "IDEA": ("IDEA", "cipher", "REVIEW"), "SEED": ("SEED", "cipher", "REVIEW"),
}

# KDF / password-hashing constructors reached through hashlib.
KDF_FUNCS = {
    "pbkdf2_hmac": ("PBKDF2-HMAC", "kdf", "REVIEW"),
    "scrypt": ("scrypt", "kdf", "REVIEW"),
}
# Key material embedded in source, matched on the PEM armour itself.
#
# A private key committed to the tree is a cryptographic asset, whatever the code around
# it references. The armour names its own algorithm, so the classification is read from
# the header rather than guessed.
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
def _hash_key(name: str) -> str:
    """A hash named by string, in every spelling hashlib and hmac accept (`'SHA-1'`, `'sha-256'`, `'sha3-256'`,
    OpenSSL's `'md5-sha1'`), as its `HASHES` key."""
    key = name.strip().lower().replace("-", "_")
    key = re.sub(r"^sha_(?=\d)", "sha", key)
    return "md5" if key == "md5_sha1" else key


# algorithm tokens found in string literals, identifiers and import names (name -> classification).
# Word-boundary matched, case-insensitive: "lamport-merkle-sha3", "ML-DSA", "ML_KEM_768".
TOKENS = [
    (r"ml[-_ ]?dsa|dilithium", ("ML-DSA (FIPS 204)", "signature", "SAFE")),
    (r"ml[-_ ]?kem|kyber", ("ML-KEM (FIPS 203)", "kem", "SAFE")),
    (r"slh[-_ ]?dsa|sphincs", ("SLH-DSA (FIPS 205)", "signature", "SAFE")),
    (r"\bhqc\b", ("HQC (NIST 2025 backup KEM)", "kem", "SAFE")),
    # the signature with its parameter set, or its FIPS 206 name: a bare `falcon` is the web framework
    (r"\bfalcon[-_ ]?(?:512|1024|padded)|\bfn[-_]?dsa\b", ("Falcon", "signature", "SAFE")),
    (r"lamport", ("Lamport OTS (hash-based)", "signature", "SAFE")),
    (r"\bxmss\b|merkle[-_ ]?(sig|tree|authority|consent)", ("Merkle/XMSS (hash-based)", "signature", "SAFE")),
    (r"\brsa[-_ ]?\d{3,5}\b|\brsa\b", ("RSA", "signature/kem", "VULNERABLE")),
    (r"ecdsa|secp256|secp384|prime256", ("ECDSA/EC", "signature", "VULNERABLE")),
    (r"\becdh\b", ("ECDH", "kem", "VULNERABLE")),
    (r"ed25519", ("Ed25519", "signature", "VULNERABLE")),
    (r"x25519|curve25519", ("X25519/Curve25519", "kem", "VULNERABLE")),
    # standalone DSA only: the negative lookbehind prevents matching the "dsa" inside
    # ml-dsa / slh-dsa / ecdsa (a "-" or word char before "dsa" blocks the match).
    (r"(?<![-\w])dsa\b", ("DSA", "signature", "VULNERABLE")),
    (r"diffie[-_ ]?hellman", ("Diffie-Hellman", "kem", "VULNERABLE")),
    (r"aes[-_ ]?256|aes256", ("AES-256", "cipher", "GROVER-REDUCED")),
    (r"aes[-_ ]?128|aes128", ("AES-128", "cipher", "GROVER-REDUCED")),
    (r"chacha20", ("ChaCha20", "cipher", "GROVER-REDUCED")),
    # specific DES forms only: bare "des" is dropped (it collides with words like "digest").
    (r"\b3des\b|triple[-_ ]?des|\bdes[-_](cbc|ede|ecb)(?:3|\b)", ("DES/3DES", "cipher", "BROKEN")),
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


def _parse_quietly(src: str, filename: str = "<unknown>") -> ast.AST:
    """`ast.parse` with the audited file's own compile-time warnings set aside. An invalid escape in
    someone else's string (`"\\d"`) is their warning, not this tool's output; and under `-W error` it
    would turn a file that parses into one reported as unparseable."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(src, filename=filename)



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
    # NOTHING-VULNERABLE-FOUND | REVIEW-NEEDED | MIGRATION-NEEDED | BROKEN-CRYPTO | NOT-ANALYSED
    verdict: str = "NOTHING-VULNERABLE-FOUND"
    summary: dict = field(default_factory=dict)   # counts by quantum status
    components: list = field(default_factory=list)
    # Python files that would not parse: their cryptography was NOT inventoried. Never rounds to a clean verdict.
    files_not_parsed: list = field(default_factory=list)
    # directories skipped by name (with their file counts; left out of findings_digest) and links not followed
    not_scanned: dict = field(default_factory=dict)
    scope_statement: str = (
        "Static analysis of Python source names the cryptographic primitives a codebase REFERENCES; "
        "it cannot prove a referenced primitive is reached at runtime, cannot always infer a "
        "dynamically-computed key SIZE, cannot see crypto behind obfuscation, and reads no language "
        "but Python. It is an inventory of the primitives this tool knows plus a post-quantum status, "
        "NOT a proof of cryptographic soundness. NOTHING-VULNERABLE-FOUND means nothing vulnerable came "
        "to this tool's attention in the files it read; REVIEW-NEEDED means nothing was classified "
        "vulnerable or broken and at least one component (a library whose algorithm is chosen at the "
        "call, a mode, a switch) needs a person to classify it, or a Python file would not parse and is listed in "
        "files_not_parsed; NOT-ANALYSED means no file was read."
    )
    # What was inventoried, not merely what it was called: the in-toto subject binding.
    subject: list = field(default_factory=list)
    subject_digest: str = ""
    # every file in the tree, by name and content: matched by VEX and CSAF against a key-provenance report
    tree_listing_digest: str = ""
    # Reproducible across runs: excludes scanned_at_utc and every issuance field.
    findings_digest: str = ""
    content_hash: str = ""
    # Deprecated: an HMAC keyed by public text, emitted for old readers and never consulted.
    integrity_tag: str = ""
    # True when the token sweep was suppressed for this tool's own source.
    # Travels INTO the signed report, so the suppression is part of the
    # attested record rather than an undisclosed behaviour.
    self_scan_suppressed: bool = False
    # The Python that parsed the tree, as major.minor (issuance metadata, outside the findings digest).
    parser_python: str = ""
    signature_algorithm: str = UNSIGNED
    signature: dict | None = None
    public_root: str = ""


# ---------------------------------------------------------------------------
# AST pass: real usage of stdlib crypto + library imports
# ---------------------------------------------------------------------------
def _attr_root(node: ast.AST) -> str:
    """Left-most Name of an attribute chain, e.g. hashlib.sha3_256 -> 'hashlib'."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


_PARSE_FAILURES = (SyntaxError, ValueError, RecursionError, MemoryError)


def _check_python_ast(src: str, path: Path, rel: str, tree: ast.AST | None = None) -> list[CryptoUse]:
    out: list[CryptoUse] = []
    if tree is None:
        try:
            tree = _parse_quietly(src, str(path))
        except _PARSE_FAILURES:
            return out

    # Does this FILE use pyca/cryptography at all? The class-constructor detection
    # below is gated on it, so `hashes.MD5()` in an unrelated module is not claimed.
    # Plain substring tests, deliberately: a guard that is always false disables what
    # it guards and raises nothing, and a substring test has no escape to get wrong.
    _pyca = ("from cryptography" in src) or ("import cryptography" in src)
    _pyopenssl = ("from OpenSSL" in src) or ("import OpenSSL" in src)
    _cipher_lib = _pyca or any(t in src for t in ("from Crypto", "import Crypto", "from Cryptodome", "import Cryptodome"))

    aliases: dict[str, str] = {}  # local alias -> real module (import hashlib as hl)
    from_hashlib: dict[str, str] = {}  # `from hashlib import md5 as m` -> {"m": "md5"}
    # callables that take a hash by name: `from hashlib import new`, `from hmac import HMAC as H` -> {"H": ("hmac", ...)}
    from_named_hash: dict[str, tuple[str, str]] = {}
    # `from jwt import decode as d`, `from jose import jwt`: names that reach a JWT library's encode or decode
    from_jwt: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "") == "hashlib":
            for a in node.names:
                if a.name in HASHES or a.name in KDF_FUNCS:
                    from_hashlib[a.asname or a.name] = a.name
                elif a.name == "new":
                    from_named_hash[a.asname or a.name] = ("hashlib", "new")
        elif isinstance(node, ast.ImportFrom) and (node.module or "") == "hmac":
            for a in node.names:
                if a.name in ("HMAC", "new", "digest"):
                    from_named_hash[a.asname or a.name] = ("hmac", a.name)
        elif isinstance(node, ast.ImportFrom) and (node.module or "") in _JWT_MODULES:
            for a in node.names:
                if a.name in ("encode", "decode"):
                    from_jwt[a.asname or a.name] = a.name
                elif a.name == "jwt":
                    from_jwt[a.asname or a.name] = "module"
    # every value each plain name is bound to in the file (`opts = {"verify_signature": False}`)
    dict_bound: dict[str, list] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    dict_bound.setdefault(t.id, []).append(node.value)
    for node in ast.walk(tree):
        # imports: stdlib crypto modules + classical libraries
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                aliases[a.asname or a.name] = a.name
                # `import Crypto.Cipher.AES`: the primitive is the tail, same
                # as the `from` forms below.
                tail = a.name.split(".")[-1]
                if top in ("Crypto", "Cryptodome") and tail in PYCRYPTODOME_PRIMITIVES:
                    p_, c_, q_ = PYCRYPTODOME_PRIMITIVES[tail]
                    out.append(CryptoUse(rel, node.lineno, p_, c_, q_,
                                         f"import {a.name}  [PyCryptodome]"))
                elif a.name == "random" and _only_system_random(tree, a.asname or "random"):
                    # every use is `random.SystemRandom`: the operating system's CSPRNG, not the Mersenne Twister
                    out.append(CryptoUse(rel, node.lineno, "random.SystemRandom-CSPRNG", "rng", "SAFE",
                                         "random.SystemRandom: the operating system's CSPRNG"))
                elif top in ("hmac", "secrets") and _only_compare_digest(tree, a.asname or a.name):
                    pass        # used only for `compare_digest`: a comparison, no MAC and no random number
                elif top in STDLIB_MODULE:
                    p, c, q = STDLIB_MODULE[top]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"import {a.name}"))
                elif top == "nacl":
                    for p, c, q in nacl_classes(a.name, []):
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f"import {a.name}"))
                elif top in LIB_MODULE:
                    p, c, q = LIB_MODULE[top]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"import {a.name}"))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            top = mod.split(".")[0]
            # PyCryptodome names the primitive in the module path, so resolve it
            # here rather than emitting the library placeholder. Two forms:
            #   from Crypto.Cipher import AES      -> the NAME is the primitive
            #   from Crypto.Cipher.AES import new  -> the TAIL is the primitive
            if top in ("Crypto", "Cryptodome"):
                parts = mod.split(".")
                named = [a.name for a in node.names]
                hits = [n for n in named if n in PYCRYPTODOME_PRIMITIVES]
                tail = parts[-1] if len(parts) >= 3 else None
                if hits:
                    for n in hits:
                        p_, c_, q_ = PYCRYPTODOME_PRIMITIVES[n]
                        out.append(CryptoUse(rel, node.lineno, p_, c_, q_,
                                             f"from {mod} import {n}  [PyCryptodome]"))
                elif tail in PYCRYPTODOME_PRIMITIVES:
                    p_, c_, q_ = PYCRYPTODOME_PRIMITIVES[tail]
                    out.append(CryptoUse(rel, node.lineno, p_, c_, q_,
                                         f"from {mod} import ...  [PyCryptodome]"))
                else:
                    # A submodule this table does not name: the library entry is reported,
                    # so an unlisted name is never silent.
                    p, c, q = LIB_MODULE[top]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"from {mod} import ..."))
            elif mod == "random" and node.names and all(a.name == "SystemRandom" for a in node.names):
                out.append(CryptoUse(rel, node.lineno, "random.SystemRandom-CSPRNG", "rng", "SAFE",
                                     "from random import SystemRandom: the operating system's CSPRNG"))
            elif top in ("hmac", "secrets") and all(a.name == "compare_digest" for a in node.names):
                pass            # `from secrets import compare_digest`: a comparison, no MAC and no random number
            elif top in STDLIB_MODULE:
                p, c, q = STDLIB_MODULE[top]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"from {mod} import ..."))
            elif top == "nacl" and not node.level:
                for p, c, q in nacl_classes(mod, [a.name for a in node.names]):
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"from {mod} import ..."))
            elif top in LIB_MODULE:
                p, c, q = LIB_MODULE[top]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"from {mod} import ..."))
                # the module or class imported names the algorithm family
                if top == "cryptography" and ".asymmetric" in mod:
                    named = [a.name for a in node.names] + [mod.rsplit(".", 1)[-1]]
                    for n in named:
                        if n in PYCA_ASYMMETRIC:
                            p_, c_, q_ = PYCA_ASYMMETRIC[n]
                            out.append(CryptoUse(rel, node.lineno, p_, c_, q_,
                                                 f"from {mod} import ...  [pyca/cryptography {n}]"))
                elif top == "paramiko":
                    for a in node.names:
                        if a.name in PARAMIKO_KEYS:
                            p_, c_, q_ = PARAMIKO_KEYS[a.name]
                            out.append(CryptoUse(rel, node.lineno, p_, c_, q_, f"from paramiko import {a.name}"))

        # `from hashlib import md5` then `md5(...)`: the primitive called by its bare name
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in from_hashlib:
            algo = from_hashlib[node.func.id]
            p, c, q = HASHES.get(algo) or KDF_FUNCS[algo]
            out.append(CryptoUse(rel, node.lineno, p, c, q, f"{node.func.id}(...) [from hashlib import {algo}]"))
        # `from hashlib import new` then `new('sha-1')`, `from hmac import HMAC` then `HMAC(k, m, 'md5')`: the hash
        # named by string, as for the same calls on the module
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in from_named_hash:
            module, real_name = from_named_hash[node.func.id]
            if module == "hmac":
                p, c, q = STDLIB_MODULE["hmac"]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"{node.func.id}(...) [from hmac import {real_name}]"))
                named = node.args[2] if len(node.args) > 2 else next(
                    (kw.value for kw in node.keywords if kw.arg in ("digestmod", "digest")), None)
            else:
                named = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg == "name"), None)
            if isinstance(named, ast.Constant) and isinstance(named.value, str) and _hash_key(named.value) in HASHES:
                hp, hc, hq = HASHES[_hash_key(named.value)]
                out.append(CryptoUse(rel, node.lineno, hp, hc, hq,
                                     f'{node.func.id}(..., "{named.value}") [from {module} import {real_name}]'))
        # openssl / ssh-keygen command lines that generate or handle keys
        if isinstance(node, ast.Call):
            for arg in node.args:
                if isinstance(arg, (ast.List, ast.Tuple)):
                    elts = [e.value for e in arg.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                    if len(elts) >= 2 and elts[0].replace("\\", "/").rsplit("/", 1)[-1].lower() in ("openssl", "openssl.exe"):
                        p, c, q = OPENSSL_SUBCOMMANDS.get(elts[1], ("openssl CLI (subcommand not classified)", "library", "REVIEW"))
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f"openssl {elts[1]} via subprocess"))
                    elif elts and elts[0].replace("\\", "/").rsplit("/", 1)[-1].lower() in ("ssh-keygen", "ssh-keygen.exe"):
                        kind = elts[elts.index("-t") + 1] if "-t" in elts and elts.index("-t") + 1 < len(elts) else "rsa"
                        p, c, q = SSH_KEYGEN_TYPES.get(kind.lower(), ("ssh-keygen (type not classified)", "library", "REVIEW"))
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f"ssh-keygen -t {kind} via subprocess"))
        # paramiko key classes anywhere in an attribute chain: `paramiko.RSAKey.generate(...)`
        if isinstance(node, ast.Attribute) and node.attr in PARAMIKO_KEYS \
                and aliases.get(_attr_root(node), _attr_root(node)) == "paramiko":
            p, c, q = PARAMIKO_KEYS[node.attr]
            out.append(CryptoUse(rel, node.lineno, p, c, q, f"paramiko.{node.attr}"))
        # pyOpenSSL key types
        if _pyopenssl and isinstance(node, ast.Attribute) and node.attr in PYOPENSSL_TYPES:
            p, c, q = PYOPENSSL_TYPES[node.attr]
            out.append(CryptoUse(rel, node.lineno, p, c, q, f"OpenSSL.crypto.{node.attr}"))
        # ssl.TLSVersion members below TLS 1.2
        if isinstance(node, ast.Attribute) and node.attr in TLS_VERSION_MEMBERS \
                and isinstance(node.value, ast.Attribute) and node.value.attr == "TLSVersion":
            p, c, q = TLS_VERSION_MEMBERS[node.attr]
            out.append(CryptoUse(rel, node.lineno, p, c, q, f"ssl.TLSVersion.{node.attr}"))
        # ECB mode, in files that use a cipher library
        if _cipher_lib and isinstance(node, ast.Attribute) and node.attr in CIPHER_MODES:
            p, c, q = CIPHER_MODES[node.attr]
            out.append(CryptoUse(rel, node.lineno, p, c, q, f"{node.attr}: equal plaintext blocks encrypt to "
                                 "equal ciphertext blocks"))
        # a JWT signed with `none`, or decoded with its signature check switched off through options
        jwt_op = _jwt_operation(node, aliases, from_jwt) if isinstance(node, ast.Call) else None
        if jwt_op:
            for kw in node.keywords:
                values = kw.value.elts if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)) else [kw.value]
                if kw.arg in ("algorithm", "algorithms") and any(
                        isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value.lower() == "none"
                        for v in values):
                    out.append(CryptoUse(rel, node.lineno, "JWT 'none' algorithm (unsigned token)", "signature",
                                         "REVIEW", f"jwt.{jwt_op}(..., {kw.arg}=... 'none'): a token with no "
                                         "signature"))
                options = kw.value
                if isinstance(options, ast.Name) and len(dict_bound.get(options.id, ())) == 1:
                    options = dict_bound[options.id][0]       # `options=opts`, with `opts = {...}` bound once
                if kw.arg == "options" and isinstance(options, ast.Dict) and any(
                        isinstance(k, ast.Constant) and k.value == "verify_signature"
                        and isinstance(v, ast.Constant) and v.value is False
                        for k, v in zip(options.keys, options.values)):
                    out.append(CryptoUse(rel, node.lineno, "JWT signature verification disabled (options)",
                                         "signature", "REVIEW", "jwt.decode(..., options={'verify_signature': False}): "
                                         "the signature is not checked"))
        # certificate verification switched off at a call: `verify=False`
        if isinstance(node, ast.Call) and any(
                kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                for kw in node.keywords):
            fn_name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            owner = node.func.value if isinstance(node.func, ast.Attribute) else None
            if jwt_op == "decode":
                # `jwt.decode(token, verify=False)`: the token's signature is not checked
                out.append(CryptoUse(rel, node.lineno, "JWT signature verification disabled (verify=False)",
                                     "signature", "REVIEW", "jwt.decode(..., verify=False): the signature is not "
                                     "checked"))
            elif _tls_call(node):
                out.append(CryptoUse(rel, node.lineno, "TLS certificate verification disabled (verify=False)",
                                     "protocol", "REVIEW", "a call passes verify=False"))
            else:
                # `get_encoding_from_response(r, verify=False)`: a parameter of the same name on a call this line
                # does not tie to TLS. Reported, and the sentence stops at what the line shows.
                out.append(CryptoUse(rel, node.lineno, "verify=False on a call not shown to be TLS", "protocol",
                                     "REVIEW", "a call passes verify=False; whether it switches off certificate "
                                     "checks is NOT shown by this line"))
        # ssl protocol constants and verification switches
        if isinstance(node, ast.Attribute) and node.attr in SSL_ATTRS and aliases.get(_attr_root(node), _attr_root(node)) == "ssl":
            p, c, q = SSL_ATTRS[node.attr]
            out.append(CryptoUse(rel, node.lineno, p, c, q, f"ssl.{node.attr}"))
        # hashlib.<algo>(...)  /  hashlib.new("algo")  /  hmac.new / secrets.* / random.*
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            root = _attr_root(node.func)
            real = aliases.get(root, root)
            attr = node.func.attr
            if real == "hashlib":
                if attr in HASHES:
                    p, c, q = HASHES[attr]
                    # `usedforsecurity=False` is the codebase answering the question:
                    # Python 3.9+ accepts it to mark a hash as non-security (a checksum,
                    # a cache key, an etag). Downgraded to REVIEW rather than dropped:
                    # the flag is an assertion by the author, and the reader should
                    # still see the primitive with that assertion attached.
                    nonsec = any(
                        kw.arg == "usedforsecurity"
                        and isinstance(kw.value, ast.Constant) and kw.value.value is False
                        for kw in node.keywords)
                    if nonsec and q in {"BROKEN", "GROVER-REDUCED"}:
                        out.append(CryptoUse(
                            rel, node.lineno, p, c, "REVIEW",
                            f"hashlib.{attr}(..., usedforsecurity=False): declared "
                            "non-security by the author; verify the declaration, do not assume it"))
                    else:
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f"hashlib.{attr}(...)"))
                elif attr in KDF_FUNCS:
                    p, c, q = KDF_FUNCS[attr]
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"hashlib.{attr}(...)"))
                    # the hash it is built on, named first (`pbkdf2_hmac("sha1", ...)`), is used too
                    named = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg == "hash_name"), None)
                    if isinstance(named, ast.Constant) and isinstance(named.value, str) \
                            and _hash_key(named.value) in HASHES:
                        hp, hc, hq = HASHES[_hash_key(named.value)]
                        out.append(CryptoUse(rel, node.lineno, hp, hc, hq, f'hashlib.{attr}("{named.value}", ...)'))
                elif attr in ("new", "file_digest"):
                    # the algorithm: `new`'s first argument (or `name=`), `file_digest`'s second (or `digest=`); a
                    # name the file binds once to a string is that string
                    if attr == "new":
                        first = node.args[0] if node.args else next(
                            (kw.value for kw in node.keywords if kw.arg == "name"), None)
                    else:
                        first = node.args[1] if len(node.args) > 1 else next(
                            (kw.value for kw in node.keywords if kw.arg == "digest"), None)
                    if isinstance(first, ast.Name) and len(dict_bound.get(first.id, ())) == 1:
                        first = dict_bound[first.id][0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        nm = _hash_key(first.value)
                        if nm in HASHES:
                            p, c, q = HASHES[nm]
                            nonsec = any(kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant)
                                         and kw.value.value is False for kw in node.keywords)
                            if nonsec and q in {"BROKEN", "GROVER-REDUCED"}:
                                out.append(CryptoUse(rel, node.lineno, p, c, "REVIEW",
                                                     f'hashlib.{attr}("{first.value}", usedforsecurity=False): declared '
                                                     "non-security by the author; verify the declaration, do not "
                                                     "assume it"))
                            else:
                                out.append(CryptoUse(rel, node.lineno, p, c, q, f'hashlib.{attr}("{first.value}")'))
            elif real == "hmac" and attr != "compare_digest":
                # (`hmac.compare_digest` compares two values in constant time: no MAC is computed)
                p, c, q = STDLIB_MODULE["hmac"]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"hmac.{attr}(...)"))
                # the hash named by string (`hmac.new(k, m, 'md5')`, `digestmod="sha1"`) is used too
                named = node.args[2] if len(node.args) > 2 else next(
                    (kw.value for kw in node.keywords if kw.arg in ("digestmod", "digest")), None)
                if isinstance(named, ast.Constant) and isinstance(named.value, str):
                    nm = _hash_key(named.value)
                    if nm in HASHES:
                        hp, hc, hq = HASHES[nm]
                        out.append(CryptoUse(rel, node.lineno, hp, hc, hq, f'hmac.{attr}(..., "{named.value}")'))
            elif real == "secrets" and attr != "compare_digest":
                # (`secrets.compare_digest` is `hmac.compare_digest`: a comparison, no random number)
                p, c, q = STDLIB_MODULE["secrets"]
                out.append(CryptoUse(rel, node.lineno, p, c, q, f"secrets.{attr}(...): CSPRNG"))
            # pyca class constructors. Gated on the FILE importing `cryptography`,
            # because `hashes`, `algorithms`, `AES` and `MD5` are ordinary names and
            # firing on them everywhere would be the false-positive trade this
            # package keeps refusing.
            elif _pyca and attr in PYCA_HASHES and _attr_root(node.func) in ("hashes", "_hashes"):
                p_, c_, q_ = PYCA_HASHES[attr]
                out.append(CryptoUse(rel, node.lineno, p_, c_, q_, f"hashes.{attr}()  [pyca/cryptography]"))
            elif _pyca and attr in PYCA_CIPHERS and _attr_root(node.func) in ("algorithms", "_algorithms"):
                p_, c_, q_ = PYCA_CIPHERS[attr]
                out.append(CryptoUse(rel, node.lineno, p_, c_, q_, f"algorithms.{attr}()  [pyca/cryptography]"))
            elif real == "paramiko" and attr in PARAMIKO_KEYS:
                p_, c_, q_ = PARAMIKO_KEYS[attr]
                out.append(CryptoUse(rel, node.lineno, p_, c_, q_, f"paramiko.{attr}(...)"))
            elif real == "os" and attr == "urandom":
                # os.urandom carries the same guarantee as secrets; recognising
                # one and not the other was a recall asymmetry inside a category.
                out.append(CryptoUse(rel, node.lineno, "os.urandom-CSPRNG", "rng", "SAFE",
                                     "os.urandom(...): CSPRNG"))

        # hashlib.<algo> as a bare ATTRIBUTE reference (e.g. hmac.new(k, m, hashlib.sha256) passes
        # the constructor by reference: no Call node). Dedup collapses this with the called form.
        elif isinstance(node, ast.Attribute) and node.attr in HASHES:
            if aliases.get(_attr_root(node), _attr_root(node)) == "hashlib":
                p, c, q = HASHES[node.attr]
                # Skip when the CALL path already reported this exact site. Dedup keys on
                # (file, line, primitive, status) and the call path can report a different
                # status for the same site (`usedforsecurity=False`), so the two would not
                # collapse: a value that is part of a dedup key must not differ between the
                # two paths that report one site.
                if not any(u.file == rel and u.line == node.lineno and u.primitive == p
                           for u in out):
                    out.append(CryptoUse(rel, node.lineno, p, c, q, f"hashlib.{node.attr}"))
    return out


# ---------------------------------------------------------------------------
# Token pass: algorithm names in string literals / identifiers (PQ schemes,
# named suites). AST-scoped to string Constants + identifiers so prose in a
# docstring that just discusses an algorithm does not fire.
# ---------------------------------------------------------------------------
def _check_pem(src: str, rel: str) -> list[CryptoUse]:
    """PEM private-key armour embedded in source.

    Deliberately a RAW TEXT scan, not an AST pass: the armour is what identifies
    the material, and it carries the same weight whether it sits in a string
    literal, a docstring, or a here-doc in a comment. A private key committed to
    a tree is a cryptographic asset by any reading.

    Only the FIRST match per pattern per file is reported: a key is one asset,
    however many lines its base64 body runs to.
    """
    out: list[CryptoUse] = []
    for rx, (prim, cat, status) in PEM_PATTERNS:
        # the armour followed by a key body: a search string, an assertion or a docstring naming it holds no key
        m = armour_with_key(src, rx)
        if m:
            line = src.count("\n", 0, m.start()) + 1
            out.append(CryptoUse(rel, line, prim, cat, status,
                                 f"{m.group(0)}: key material present in the source tree"))
    return out


# The call names that take `verify=` for TLS: an HTTP verb, a client or session, a connection or pool.
_TLS_CALL_NAME = re.compile(r"^(?:get|post|put|patch|delete|head|options|request|send|urlopen|stream|connect)$"
                            r"|client|session|connection|pool|adapter|transport|resource|api$|ssl|tls|https?|url"
                            r"|opener|socket", re.IGNORECASE)
_TLS_HINT_KWARGS = {"secure", "ssl", "ssl_context", "cert", "cert_reqs", "ca_certs", "cafile", "capath", "tls",
                    "client_cert", "verify_ssl", "https", "insecure"}


def _tls_call(call: ast.Call) -> bool:
    """`verify=False` on this call is a certificate check switched off: the call is a request or a client, carries
    another TLS argument, or is given an https address."""
    fn = call.func
    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
    if _TLS_CALL_NAME.search(name or ""):
        return True
    if any(kw.arg in _TLS_HINT_KWARGS for kw in call.keywords):
        return True
    return any(isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.lower().startswith("https://")
               for a in list(call.args) + [kw.value for kw in call.keywords])


# English function words: a string that holds one is a phrase about an algorithm (`"Use Argon2 or Bcrypt"`,
# `"not-a-scrypt-hash"`), not the name of one.
_PROSE_WORDS = {"a", "an", "the", "not", "no", "is", "are", "use", "for", "or", "and", "with", "of", "to", "be",
                "new", "please", "must", "should", "only"}


def _is_phrase(text: str) -> bool:
    # Words are what whitespace separates: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and
    # `audience=https://a,signing_algorithm=HS256` are one word each, and both name a real algorithm.
    words = [w.strip(".,:;!?()'\"").lower() for w in text.split()]
    if len(words) >= 2 and any(w in _PROSE_WORDS for w in words):
        return True
    # `"Load RSA private key."`, `"Unrecognized RSA PKCS1 signature alg"`: a sentence or a message, by its words
    plain = [w for w in text.split() if re.fullmatch(r"[a-z]{3,}[.,:;]?", w)]
    if len(words) >= 3 and (len(plain) >= 2 or text.strip().endswith(".")):
        return True
    # `not-a-scrypt-hash`: a negated name, written as one hyphenated word
    return re.match(r"(?:not|no)[-_]", text.strip().lower()) is not None


# The words of a name that says its collection holds what is refused (`WEAK_CIPHERS`, `isInsecure`, `deny_list`); a
# word inside another (`BLOCKCHAIN`, `BLOCK_CIPHERS`) or one that names what is still supported (`LEGACY`) does not
_REFUSAL_WORDS = {"weak", "insecure", "banned", "blocked", "blocklist", "blacklist", "denied", "deny", "denylist",
                  "disallowed", "disallow", "forbidden", "forbid", "rejected", "reject", "unsafe", "deprecated",
                  "excluded", "exclude", "broken", "refused", "refuse", "unsupported", "prohibited"}


def _refusal_name(name: str) -> bool:
    """A name that says its collection holds what is refused, and not that it is allowed (`ALLOW_WEAK_HASHES`,
    `INSECURE_ALGORITHMS_ENABLED` list what is used)."""
    words = {w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", name)}
    return bool(words & _REFUSAL_WORDS) and not words & _ALLOW_WORDS


_ALLOW_WORDS = {"allow", "allowed", "allows", "enable", "enabled", "permit", "permitted", "accept", "accepted",
                "supported", "support", "use", "used", "uses", "default", "defaults"}
_ENUM_BASES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}
# An item of an OpenSSL cipher list that excludes (`:!MD5`, `:-RC4`, `!aNULL` first)
_CIPHER_EXCLUSION = re.compile(r"(?:^|[:,])[!-][A-Za-z0-9]")


def _check_tokens(src: str, path: Path, rel: str, tree: ast.AST | None = None) -> list[CryptoUse]:
    out: list[CryptoUse] = []
    if tree is None:
        try:
            tree = _parse_quietly(src, str(path))
        except _PARSE_FAILURES:
            return out
    # Names that exclude: the items of a literal collection bound to a name that says it holds what is refused
    # (`WEAK_CIPHERS = [...]`) or checked with `in` inside a function so named (`def is_weak(alg): return alg in
    # (...)`), and an Enum member whose value is a phrase that names no algorithm (`RC4 = "release candidate 4"`).
    # Naming an algorithm to refuse it is not using it. (A collection a library dispatches on, or an Enum of the
    # algorithms it supports, names what it uses.)
    refused = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("add_argument", "add_option", "option", "argument"):
            # a command-line option's own name (`parser.add_argument('--rsa-key')`) names an input, not an algorithm
            refused |= {id(a) for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
                        and a.value.startswith("-")}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _refusal_name(node.name):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in inner.ops):
                    for comp in inner.comparators:
                        if isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                            refused |= {id(e) for e in comp.elts}
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(getattr(node, "value", None),
                                                                        (ast.Tuple, ast.List, ast.Set)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and _refusal_name(t.id) for t in targets):
                refused |= {id(e) for e in node.value.elts}
        elif isinstance(node, ast.ClassDef) and any(
                (b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", "")) in _ENUM_BASES for b in node.bases):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) \
                        and isinstance(stmt.value.value, str) and " " in stmt.value.value.strip() \
                        and not any(rex.search(stmt.value.value) for rex, _ in TOKEN_RES):
                    refused |= {id(t) for t in stmt.targets if isinstance(t, ast.Name)}
    for node in ast.walk(tree):
        text = None
        if id(node) in refused:
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            # module and imported names carry algorithm names too (`from kyber_py.ml_kem import ML_KEM_768`)
            names = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
            for nm in names:
                for rex, (p, c, q) in TOKEN_RES:
                    if rex.search(nm):
                        out.append(CryptoUse(rel, node.lineno, p, c, q, f'token: "{nm[:40]}"'))
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
        elif isinstance(node, ast.Name):
            text = node.id
        elif isinstance(node, ast.Attribute):
            text = node.attr
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            # a test named after an algorithm (`test_pbkdf2_verify_rejects_...`) is a test, not a use of it
            if node.name.lower().startswith("test"):
                continue
            text = node.name
        if not text:
            continue
        if isinstance(node, ast.Constant) and _is_phrase(text):
            continue
        shown = text
        if isinstance(node, ast.Constant) and ":" in text and _CIPHER_EXCLUSION.search(text):
            # an OpenSSL cipher list (`HIGH:!aNULL:!MD5:!RC4`): an item after `!` or `-` is excluded, not used
            text = ":".join(t for t in re.split(r"[:,\s]+", text) if t and t[0] not in "!-")
            if not text:
                continue
        # skip long prose strings (docstrings / paragraphs): a scheme token inside a
        # sentence is documentation, not a declared primitive; we want identifiers and
        # short suite strings like "lamport-merkle-sha3" / "ML-DSA-65".
        if len(text) > 64 or " " in text.strip() and len(text) > 40:
            continue
        for rex, (p, c, q) in TOKEN_RES:
            if rex.search(text):
                out.append(CryptoUse(rel, getattr(node, "lineno", 0), p, c, q, f'token: "{shown[:40]}"'))
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def build_cbom(target: Path | str,
               signer: "MerkleSigner | None" = None,
               label: str | None = None) -> CBOM:
    """Inventory the cryptography in `target`; see `_build_cbom`. Each file is read as one version for the whole run,
    so the components and the subject digest describe the same bytes."""
    with _reads.one_read_per_file():
        return _build_cbom(target, signer, label)


_OWN_SOURCE = Path(__file__).read_bytes().replace(b"\r\n", b"\n")


def _is_own_source(path: Path) -> bool:
    """The file's bytes are this module's own source (line endings aside)."""
    try:
        return _reads.read_bytes(path).replace(b"\r\n", b"\n") == _OWN_SOURCE
    except OSError:
        return False


def _build_cbom(target: Path | str,
                signer: "MerkleSigner | None" = None,
                label: str | None = None) -> CBOM:
    """Inventory the cryptography in `target`. `label` names the subject.

    `target` never reaches the report as an absolute path: a report is handed to a
    counterparty, and the auditor's drive, user name and directory layout are not
    theirs to receive. Only the final path component, or the label, is recorded.
    """
    target = Path(target)   # a public entry point takes what its users type
    rep = CBOM(target=label or _subject_name(target),
               scanned_at_utc=datetime.now(timezone.utc).isoformat())
    tree: list[tuple[str, str]] = []
    uses: list[CryptoUse] = []
    not_parsed: list[dict] = []
    scanned = 0
    unreadable = 0
    walk = tree_files(target)
    for rel, p in walk.files:
        try:
            units = python_units(p)
        except ValueError as exc:
            # a notebook that is not JSON, or one for another language's kernel: its cryptography was not inventoried
            scanned += 1
            tree.append((rel, _file_digest(p)))
            why = exc.args[0] if isinstance(exc, NotPythonNotebook) else \
                "not JSON, or not a notebook layout this tool reads"
            not_parsed.append({"file": rel, "line": 0,
                               "detail": f"could not read this notebook ({why}), so its cryptography was NOT inventoried"})
            continue
        except OSError as exc:
            # a file the run could not open (permissions, a lock held by another program): listed, never clean
            unreadable += 1
            not_parsed.append({"file": rel, "line": 0,
                               "detail": f"could not be opened ({type(exc).__name__}), so its cryptography was NOT "
                                         "inventoried"})
            continue
        if units is None:
            continue
        scanned += 1
        tree.append((rel, _file_digest(p)))
        # SELF-SCAN: a detector's own pattern table contains every token it hunts for, so
        # token-matching THIS module would report `DES/3DES`, `RC4`, `rsa` and `ecdsa` on a
        # package that uses none of them. The AST pass still runs here: a real crypto CALL
        # in this file is reported. Only the literal token sweep is suppressed, only for a
        # file whose bytes ARE this detector's source (never for another file of the same
        # name), and the report carries `self_scan_suppressed` so the reader is told.
        own = _is_own_source(p)
        for src, cell in units:
            try:
                parsed = _parse_quietly(src, str(p))
            except _PARSE_FAILURES as exc:
                # A file that will not parse is a file whose cryptography was not inventoried, not a file with none.
                where = (f"cell {cell} of this notebook" if _reads.suffix_of(p).lower() == ".ipynb"
                         else f"the magic text at line {cell} of this file") if cell else "this file"
                not_parsed.append({"file": rel, "line": cell or getattr(exc, "lineno", None) or 0,
                                   "detail": f"could not parse {where} as Python "
                                             f"({type(exc).__name__}), so its cryptography was NOT inventoried"})
                if not own:
                    found = _check_pem(src, rel)     # armour is found in the text, parsed or not
                    uses += [replace(u, line=cell) for u in found] if cell else found
                continue
            found = _check_python_ast(src, p, rel, parsed)
            if own:
                rep.self_scan_suppressed = True
            else:
                found += _check_tokens(src, p, rel, parsed)
                found += _check_pem(src, rel)
            uses += [replace(u, line=cell) for u in found] if cell else found

    # dedup (same file/line/primitive/status), then order most-severe first
    seen, deduped = set(), []
    for u in uses:
        if u.key() not in seen:
            seen.add(u.key())
            deduped.append(u)
    # most severe first; then by path bytes, so the order is the same on every operating system
    deduped.sort(key=lambda u: (_QUANTUM_ORDER.get(u.quantum, 9), u.file.encode("utf-8", "backslashreplace"),
                                u.line, u.primitive, u.detail))

    rep.files_scanned = scanned
    rep.parser_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    rep.components = [asdict(u) for u in deduped]
    rep.files_not_parsed = sorted(not_parsed, key=lambda d: (d["file"].encode("utf-8", "backslashreplace"), d["line"]))
    counts: dict[str, int] = {}
    for u in deduped:
        counts[u.quantum] = counts.get(u.quantum, 0) + 1
    rep.summary = counts
    if counts.get("BROKEN"):
        rep.verdict = "BROKEN-CRYPTO"
    elif counts.get("VULNERABLE"):
        rep.verdict = "MIGRATION-NEEDED"
    elif scanned == 0:
        rep.verdict = "NOT-ANALYSED"      # no Python file was read, so nothing can be said
    elif counts.get("REVIEW") or rep.files_not_parsed:
        rep.verdict = "REVIEW-NEEDED"     # nothing classified vulnerable; something a person must classify or read
    else:
        rep.verdict = "NOTHING-VULNERABLE-FOUND"

    rep.subject_digest = _tree_digest(tree)
    rep.tree_listing_digest = tree_listing_digest(walk.files)
    rep.not_scanned = {"skipped_directories": dict(sorted(walk.skipped.items())), "symbolic_links": walk.symlinks,
                       # every other file: this inventory reads Python only (JavaScript, Go, C are not read)
                       "files_not_python": len(walk.files) - scanned - unreadable}
    rep.subject = [{"name": rep.target,
                    "digest": {"sha3-256": rep.subject_digest}}]
    rep.findings_digest = hashlib.sha3_256(
        reproducible_body(asdict(rep))).hexdigest()

    # ORDER IS LOAD-BEARING: identity fields go in BEFORE the body is hashed and signed, and
    # the algorithm name is read from the signer, never hard-coded, so a report cannot
    # name a scheme other than the one that signed it.
    if signer is not None:
        rep.signature_algorithm = signer.algorithm
        rep.public_root = signer.public_root
    ch, tag = _sign(asdict(rep))
    rep.content_hash = ch
    rep.integrity_tag = tag
    if signer is not None:
        rep.signature = signer.sign(canonical_body(asdict(rep)))
        if rep.signature.get("algorithm", rep.signature_algorithm) != rep.signature_algorithm:
            raise SignerError(
                "signer.algorithm disagrees with the algorithm in its own "
                "signature; refusing to issue a CBOM that misnames its scheme")
    return rep


def verify_cbom(report_dict: dict, expected_root: str | None = None) -> tuple[bool, str]:
    """Verify a CBOM. Returns `(ok, status)` with the same four statuses as
    `verify_report`: ATTESTED / UNVERIFIED / UNSIGNED / TAMPERED. A CBOM is the
    document a buyer uses to substantiate a PQC-migration claim to an auditor,
    so an unattested one has to say so in its own output rather than read as
    signed."""
    return verify_report(report_dict, expected_root=expected_root, expected_tool="ENTROVOUCH CBOM generator")


_cell = markdown_cell


def render_markdown(rep: CBOM) -> str:
    badge = {"NOTHING-VULNERABLE-FOUND": "NOTHING-VULNERABLE-FOUND", "NOT-ANALYSED": "NOT-ANALYSED (no Python file read)",
             "MIGRATION-NEEDED": "⚠️ MIGRATION-NEEDED",
             "BROKEN-CRYPTO": "❌ BROKEN-CRYPTO"}.get(rep.verdict, rep.verdict)
    lines = [
        f"# ENTROVOUCH Cryptographic Bill of Materials: {badge}",
        "",
        f"- **Target:** {markdown_code(rep.target, in_table=False)}",
        f"- **Scanned:** {rep.scanned_at_utc}  ·  **Files:** {rep.files_scanned}",
        f"- **Components:** {len(rep.components)}  ·  **By PQ status:** "
        + ", ".join(f"{k} {v}" for k, v in sorted(rep.summary.items())),
        (f"- **Signed by:** `{rep.public_root}` ({rep.signature_algorithm})"
         if rep.signature else
         f"- **Signature:** {UNSIGNED}: this CBOM does NOT attest its own origin"),
        # The reproducing digests are printed on the page, each labelled, as in
        # `no_egress_auditor.render_markdown`.
        f"- **Findings digest (reproduces):** `{rep.findings_digest}`",
        f"- **Subject digest (binds the files this inventory read):** `{rep.subject_digest}`",
        *([f"- **Not Python, not read:** {rep.not_scanned['files_not_python']} file(s)"]
          if rep.not_scanned.get("files_not_python") else []),
        *([f"- **Not read:** {len(rep.not_scanned.get('skipped_directories') or {})} skipped director"
           f"{'y' if len(rep.not_scanned.get('skipped_directories') or {}) == 1 else 'ies'} "
           f"({', '.join(markdown_code(k, in_table=False) for k in list(rep.not_scanned.get('skipped_directories') or {})[:8])}), "
           f"{rep.not_scanned.get('symbolic_links', 0)} link(s) not followed"]
          if (rep.not_scanned.get("skipped_directories") or rep.not_scanned.get("symbolic_links")) else []),
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
            lines.append(f"| {c['quantum']} | {_cell(c['primitive'])} | {c['category']} | "
                         f"{markdown_code(c['file'])} | {c['line']} | {_cell(c['detail'])} |")
    else:
        lines.append("**No cryptographic primitives detected in scope.**")
    if rep.files_not_parsed:
        lines += ["", "## Files not parsed (their cryptography was NOT inventoried)", "",
                  "| File | Line | Why |", "|---|---|---|"]
        for d in rep.files_not_parsed:
            lines.append(f"| {markdown_code(d['file'])} | {d['line']} | {_cell(d['detail'])} |")
    lines += ["", "*ENTROVOUCH CBOM. Prevention over detection. For the People.*"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ENTROVOUCH CBOM (Cryptographic Bill of Materials) generator")
    ap.add_argument("target", type=Path, help="directory to inventory")
    ap.add_argument("--json", type=Path, default=None, help="write signed JSON CBOM")
    ap.add_argument("--md", type=Path, default=None, help="write markdown CBOM")
    ap.add_argument("--label", default=None,
                    help="name of the subject inside the signed body (org/repo@commit); default: the folder's name")
    ap.add_argument("--key", type=Path, default=None,
                    help="signing identity (create one with no_egress_auditor --init-key). "
                         "WITHOUT THIS THE CBOM IS UNSIGNED.")
    args = ap.parse_args(argv)
    try:  # emoji badge in the markdown must not crash a cp1252 console
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    if args.key and not args.key.is_file():
        what = "is a folder, not a key file" if args.key.is_dir() else "does not exist"
        print(f"error: signing key {args.key} {what}", file=sys.stderr)
        return 2
    problem = missing_folder(args.json, args.md, key=args.key, tree=args.target)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    try:
        signer = MerkleSigner.load(args.key) if args.key else None
        if signer is None:
            print("warning: no --key given; CBOM will be UNSIGNED", file=sys.stderr)
        rep = build_cbom(args.target, signer=signer, label=args.label)
    except (SignerError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        write_text(args.json, json.dumps(asdict(rep), indent=2))
    if args.md:
        write_text(args.md, render_markdown(rep))
    print(render_markdown(rep))
    if rep.verdict == "NOT-ANALYSED":
        return 2
    return 0 if rep.verdict == "NOTHING-VULNERABLE-FOUND" else 1


if __name__ == "__main__":
    raise SystemExit(run(main))

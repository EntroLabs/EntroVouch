"""Fixture module: uses cryptography, so the CBOM has something to inventory.

⚠️ The weak primitives below are PRESENT ON PURPOSE. They are what a real legacy
codebase looks like, and a demo where everything is already correct demonstrates
nothing.
"""
import hashlib
import hmac
import random
import secrets


def legacy_fingerprint(blob: bytes) -> str:
    # Deliberately weak: this is the kind of finding the CBOM exists to surface.
    return hashlib.md5(blob).hexdigest()


def session_id() -> str:
    # Deliberately wrong RNG for a security context; flagged as WEAK-RNG.
    return "%016x" % random.getrandbits(64)


def strong_session_id() -> str:
    return secrets.token_hex(16)


def sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


# ⚠️ FIXTURE: a signing key living in the source tree. Present on purpose — this
# is the exact shape of defect `key_provenance` exists to surface, and it is the
# shape that was live in this package's own predecessor.
WEBHOOK_SIGNING_KEY = b"s3cret-webhook-key-do-not-ship"


def sign_webhook(message: bytes) -> str:
    return hmac.new(WEBHOOK_SIGNING_KEY, message, hashlib.sha256).hexdigest()


# JWS algorithm identifier. `algorithm="RS256"` is RSA and is what a CBOM
# exists to find in a modern web service. The import is not executed in the
# demo; the auditor reads the source.
def encode_token(payload: dict, key) -> str:
    import jwt
    return jwt.encode(payload, key, algorithm="RS256")


def pyca_legacy_digest(data: bytes) -> bytes:
    """pyca constructor, not hashlib.md5 — the hole S13 closed."""
    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.MD5())
    digest.update(data)
    return digest.finalize()


# Truncated armour. The detector matches the header, not the body. Not a real key.
_DEV_RSA_PEM = """-----BEGIN RSA PRIVATE KEY-----
FIXTURE-NOT-A-KEY
-----END RSA PRIVATE KEY-----
"""

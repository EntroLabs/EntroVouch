# ENTROVOUCH Cryptographic Bill of Materials — ❌ BROKEN-CRYPTO

- **Target:** `sample_service`
- **Scanned:** 2026-09-01T22:33:54.943636+00:00  ·  **Files:** 6
- **Components:** 14  ·  **By PQ status:** BROKEN 2, GROVER-REDUCED 2, REVIEW 2, SAFE 5, VULNERABLE 2, WEAK-RNG 1
- **Signature:** UNSIGNED - content hash only, origin NOT attested — this CBOM does NOT attest its own origin
- **Findings digest (reproduces):** `c945e12617f146e65ff2ebb9bbfe96dd…`
- **Subject digest (binds the code):** `b707f8f2ed031bd9358248241bb083fb…`
- **Content hash (this issuance only, does NOT reproduce):** `c3d3316df7d12e969ca89f7fcd9dfe79…`

> **Scope:** Static analysis names the primitives a codebase REFERENCES; it cannot prove a referenced primitive is reached at runtime, cannot always infer a dynamically-computed key SIZE, and cannot see crypto behind full obfuscation. High-recall inventory + PQ-status verdict (the CBOM the migration standards ask for), NOT a proof of cryptographic soundness.

## Cryptographic components

| PQ status | Primitive | Category | File | Line | Detail |
|---|---|---|---|---|---|
| BROKEN | MD5 | hash | `tokens.py` | 15 | hashlib.md5(...) |
| BROKEN | MD5 | hash | `tokens.py` | 52 | hashes.MD5()  [pyca/cryptography] |
| VULNERABLE | RSASSA-PKCS1-v1_5 (JWS RSnnn) | signature | `tokens.py` | 46 | token: "RS256" |
| VULNERABLE | RSA private key (PEM in source) | key-material | `tokens.py` | 58 | -----BEGIN RSA PRIVATE KEY----- — key material present in the source tree |
| WEAK-RNG | random-MersenneTwister | rng | `tokens.py` | 9 | import random |
| REVIEW | PyJWT (algorithm-dependent — see JWS alg tokens) | library | `tokens.py` | 45 | import jwt |
| REVIEW | pyca/cryptography (classical default suite) | library | `tokens.py` | 51 | from cryptography.hazmat.primitives import ... |
| GROVER-REDUCED | SHA-256 | hash | `tokens.py` | 28 | hashlib.sha256 |
| GROVER-REDUCED | SHA-256 | hash | `tokens.py` | 38 | hashlib.sha256 |
| SAFE | HMAC | mac | `tokens.py` | 8 | import hmac |
| SAFE | secrets-CSPRNG | rng | `tokens.py` | 10 | import secrets |
| SAFE | secrets-CSPRNG | rng | `tokens.py` | 24 | secrets.token_hex(...) — CSPRNG |
| SAFE | HMAC | mac | `tokens.py` | 28 | hmac.new(...) |
| SAFE | HMAC | mac | `tokens.py` | 38 | hmac.new(...) |

*ENTROVOUCH CBOM — Covenant-attested. Prevention over detection. For the People.*
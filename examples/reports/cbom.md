# ENTROVOUCH Cryptographic Bill of Materials: ❌ BROKEN-CRYPTO

- **Target:** `entrovouch/examples/sample_service`
- **Scanned:** 2026-10-25T04:57:29.930192+00:00  ·  **Files:** 6
- **Components:** 13  ·  **By PQ status:** BROKEN 2, GROVER-REDUCED 2, REVIEW 2, SAFE 5, VULNERABLE 1, WEAK-RNG 1
- **Signature:** UNSIGNED - content hash only, origin NOT attested: this CBOM does NOT attest its own origin
- **Findings digest (reproduces):** `4ffa7155986baf4120d342151712eef7e96f19f748f57c8ef71757ecbd7a2511`
- **Subject digest (binds the files this inventory read):** `0855e8da6d88266811290678063bc7e21d53a1460c74a3b451a7c029a78313df`
- **Not Python, not read:** 2 file(s)
- **Content hash (this issuance only, does NOT reproduce):** `e1173a2972848603ab22b380c295d2c3…`

> **Scope:** Static analysis of Python source names the cryptographic primitives a codebase REFERENCES; it cannot prove a referenced primitive is reached at runtime, cannot always infer a dynamically-computed key SIZE, cannot see crypto behind obfuscation, and reads no language but Python. It is an inventory of the primitives this tool knows plus a post-quantum status, NOT a proof of cryptographic soundness. NOTHING-VULNERABLE-FOUND means nothing vulnerable came to this tool's attention in the files it read; REVIEW-NEEDED means nothing was classified vulnerable or broken and at least one component (a library whose algorithm is chosen at the call, a mode, a switch) needs a person to classify it, or a Python file would not parse and is listed in files_not_parsed; NOT-ANALYSED means no file was read.

## Cryptographic components

| PQ status | Primitive | Category | File | Line | Detail |
|---|---|---|---|---|---|
| BROKEN | MD5 | hash | `tokens.py` | 15 | hashlib.md5\(...\) |
| BROKEN | MD5 | hash | `tokens.py` | 52 | hashes.MD5\(\)  \[pyca/cryptography\] |
| VULNERABLE | RSASSA-PKCS1-v1\_5 \(JWS RSnnn\) | signature | `tokens.py` | 46 | token: "RS256" |
| WEAK-RNG | random-MersenneTwister | rng | `tokens.py` | 9 | import random |
| REVIEW | PyJWT \(algorithm-dependent: see JWS alg tokens\) | library | `tokens.py` | 45 | import jwt |
| REVIEW | pyca/cryptography \(classical default suite\) | library | `tokens.py` | 51 | from cryptography.hazmat.primitives import ... |
| GROVER-REDUCED | SHA-256 | hash | `tokens.py` | 28 | hashlib.sha256 |
| GROVER-REDUCED | SHA-256 | hash | `tokens.py` | 38 | hashlib.sha256 |
| SAFE | HMAC | mac | `tokens.py` | 8 | import hmac |
| SAFE | secrets-CSPRNG | rng | `tokens.py` | 10 | import secrets |
| SAFE | secrets-CSPRNG | rng | `tokens.py` | 24 | secrets.token\_hex\(...\): CSPRNG |
| SAFE | HMAC | mac | `tokens.py` | 28 | hmac.new\(...\) |
| SAFE | HMAC | mac | `tokens.py` | 38 | hmac.new\(...\) |

*ENTROVOUCH CBOM. Prevention over detection. For the People.*
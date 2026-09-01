# ENTROVOUCH Cryptographic Bill of Materials — ❌ BROKEN-CRYPTO

- **Target:** `sample_service`
- **Scanned:** 2026-09-01T02:04:38.604067+00:00  ·  **Files:** 3
- **Components:** 9  ·  **By PQ status:** BROKEN 1, GROVER-REDUCED 2, SAFE 5, WEAK-RNG 1
- **Signature:** UNSIGNED - content hash only, origin NOT attested — this CBOM does NOT attest its own origin
- **Findings digest (reproduces):** `742552a9cbdf95f238cf7018371323b9…`
- **Subject digest (binds the code):** `3855a3f2fd37a4eff5b724a72acd0f54…`
- **Content hash (this issuance only, does NOT reproduce):** `d5a68368aba5ab036ef0639908f7a695…`

> **Scope:** Static analysis names the primitives a codebase REFERENCES; it cannot prove a referenced primitive is reached at runtime, cannot always infer a dynamically-computed key SIZE, and cannot see crypto behind full obfuscation. High-recall inventory + PQ-status verdict (the CBOM the migration standards ask for), NOT a proof of cryptographic soundness.

## Cryptographic components

| PQ status | Primitive | Category | File | Line | Detail |
|---|---|---|---|---|---|
| BROKEN | MD5 | hash | `tokens.py` | 15 | hashlib.md5(...) |
| WEAK-RNG | random-MersenneTwister | rng | `tokens.py` | 9 | import random |
| GROVER-REDUCED | SHA-256 | hash | `tokens.py` | 28 | hashlib.sha256 |
| GROVER-REDUCED | SHA-256 | hash | `tokens.py` | 38 | hashlib.sha256 |
| SAFE | HMAC | mac | `tokens.py` | 8 | import hmac |
| SAFE | secrets-CSPRNG | rng | `tokens.py` | 10 | import secrets |
| SAFE | secrets-CSPRNG | rng | `tokens.py` | 24 | secrets.token_hex(...) — CSPRNG |
| SAFE | HMAC | mac | `tokens.py` | 28 | hmac.new(...) |
| SAFE | HMAC | mac | `tokens.py` | 38 | hmac.new(...) |

*ENTROVOUCH CBOM — Covenant-attested. Prevention over detection. For the People.*
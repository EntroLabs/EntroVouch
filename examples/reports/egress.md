# ENTROVOUCH No-Egress Audit — FINDINGS

- **Target:** `entrovouch/examples/sample_service`
- **Scanned:** 2026-08-30T22:17:46.107841+00:00
- **Files scanned:** 3
- **Findings:** 1
- **Findings digest (reproduces):** `ab550ec3a55c490ba2c95e129bb64fe1…`
- **Subject digest (binds the code):** `3855a3f2fd37a4eff5b724a72acd0f54…`
- **Content hash (this issuance only, does NOT reproduce):** `770a2ab75e3b2c18f026ad563f367567…`
- **Signature:** UNSIGNED - content hash only, origin NOT attested

> ⚠️ **This report is NOT attested.** The content hash proves the body matches its own digest; it proves nothing about who produced it, because anyone can recompute it. Do not rely on this document as evidence of source.

> **How to reproduce this report:** re-run the same tool version against the same tree and compare **`findings digest`** — it is bit-identical across runs, processes and machines. Do NOT compare the content hash: it covers the issuance timestamp and is *expected* to differ on every run. A different content hash with an identical findings digest is the same result, issued twice.

> **Scope:** Static analysis of Python, TypeScript and HTML/JS. Catches the realistic/accidental egress class plus common deliberate patterns (network-capable imports, git remote subcommands, shell=True and os.system/popen, child_process, dynamic import/exec/eval, external references, network binaries spawned via argv list, telemetry/APM and cloud SDK imports). Does NOT mathematically prove zero egress in a Turing-complete language. Known blind spots, stated rather than implied: detection is BLOCKLIST-BASED, so it is complete only against names it knows -- a renamed, vendored or dynamically-constructed module or argv entry is invisible, and a blocklist can never be complete by construction. Non-literal arguments (variables, f-strings, lists built at runtime) are not resolved. This report is therefore DETECTION-grade evidence and does not support an unqualified claim of absence.

## Findings

| File | Line | Kind | Detail |
|---|---|---|---|
| `collector.py` | 2 | network-import | import urllib.request |

*ENTROVOUCH — Covenant-attested. For the People.*
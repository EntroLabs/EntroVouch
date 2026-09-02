# ENTROVOUCH No-Egress Audit — FINDINGS

- **Target:** `entrovouch/examples/sample_service`
- **Scanned:** 2026-09-01T22:33:54.676452+00:00
- **Files scanned:** 7
- **Resolved locally, NOT counted as network imports:** `motor` — this tree supplies a top-level module of each name, which shadows any installed package. Check these if the tree vendors dependencies.
- **Findings:** 2
- **Findings digest (reproduces):** `505e9bdfecedb54a38919dc6f710a126…`
- **Subject digest (binds the code):** `9919e0bddd5cd02013d90fbb4ad235be…`
- **Content hash (this issuance only, does NOT reproduce):** `29cf2449f3d78fbdfaf263e3a86935dc…`
- **Signature:** UNSIGNED - content hash only, origin NOT attested

> ⚠️ **This report is NOT attested.** The content hash proves the body matches its own digest; it proves nothing about who produced it, because anyone can recompute it. Do not rely on this document as evidence of source.

> **How to reproduce this report:** re-run the same tool version against the same tree and compare **`findings digest`** — it is bit-identical across runs, processes and machines. Do NOT compare the content hash: it covers the issuance timestamp and is *expected* to differ on every run. A different content hash with an identical findings digest is the same result, issued twice.

> **Scope:** Static analysis of Python, TypeScript and HTML/JS. Catches the realistic/accidental egress class plus common deliberate patterns (network-capable imports, git remote subcommands, shell=True and os.system/popen, child_process, dynamic import/exec/eval, external references, network binaries spawned via argv list, telemetry/APM and cloud SDK imports). Does NOT mathematically prove zero egress in a Turing-complete language. Known blind spots, stated rather than implied: detection is BLOCKLIST-BASED, so it is complete only against names it knows -- a renamed, vendored or dynamically-constructed module or argv entry is invisible, and a blocklist can never be complete by construction. MEASURED 2026-08-31: against 59 network libraries chosen WITHOUT reference to the blocklist, recall is 0%, and it stayed 0% after the list was extended by 46 names -- so a PLAIN, unobfuscated `import X` of a library this tool does not name is invisible, exactly like an obfuscated one. Check FORBIDDEN_IMPORT_MODULES against your own dependencies before reading anything into a CLEAN verdict. Files that fail to parse are reported as `unparseable-source` findings and were NOT analysed. An import is NOT counted as a network import when the tree itself supplies a top-level module of that name, because that module shadows any installed package; every such name is listed in `shadowed_imports`, so a network client VENDORED into the tree root appears there rather than disappearing. Declared dependencies in pyproject.toml, requirements*.txt, setup.cfg and package.json that name a known network package are reported as `declared-network-dependency`: evidence the tree depends on that package, not a claim that a call site reaches the network. Non-literal arguments (variables, f-strings, lists built at runtime) are not resolved. This report is therefore DETECTION-grade evidence and does not support an unqualified claim of absence.

## Findings

| File | Line | Kind | Detail |
|---|---|---|---|
| `collector.py` | 2 | network-import | import urllib.request |
| `pyproject.toml` | 10 | declared-network-dependency | declared dependency 'stripe' names a known network package — not a call site; the tree depends on it |

*ENTROVOUCH — Covenant-attested. For the People.*
# ENTROVOUCH No-Egress Audit: FINDINGS

- **Target:** `entrovouch/examples/sample_service`
- **Scanned:** 2026-10-09T21:24:50.685280+00:00
- **Files scanned:** 7 (1 more were not read: skipped directories, types this tool has no reader for, and links, listed below)
- **Resolved locally, NOT counted as network imports:** `motor`: this tree supplies a top-level module of each name, which shadows any installed package. Check these if the tree vendors dependencies.
- **Imported, and not known to this tool (2):** `cryptography`, `jwt`. These third-party modules are on none of this tool's lists, so it says nothing about what they do. Check them against what you know they are.
- **Files of types this tool does not read:** 1 (`.md` (1))
- **Parsed with:** Python 3.14
- **Findings:** 3
- **Findings digest (reproduces):** `57a8ec283551cc9d45d8281cc738ca65d0558625f0a9d87c119145337dc3cd62`
- **Subject digest (binds the files this audit read):** `a19a74eacd9be59d4545aec928772b5e6a745c65f029969df244700c84fdc269`
- **Content hash (this issuance only, does NOT reproduce):** `5a80e417e0930a42cc4049909053369a…`
- **Signature:** UNSIGNED - content hash only, origin NOT attested

> ⚠️ **This report is NOT attested.** The content hash proves the body matches its own digest; it proves nothing about who produced it, because anyone can recompute it. Do not rely on this document as evidence of source.

> **How to reproduce this report:** re-run the same tool version against the same tree with the same label and compare **`findings digest`**: it is bit-identical across runs, processes and machines. Do NOT compare the content hash: it covers the issuance timestamp and is *expected* to differ on every run. A different content hash with an identical findings digest is the same result, issued twice.

> **Scope:** Static analysis of Python (including notebooks, .pth files and shebang scripts), JavaScript, TypeScript, markup, stylesheets, shell, PowerShell and batch scripts, Dockerfiles, Makefiles, pipeline definitions and dependency manifests. It reports network-capable imports, calls that connect or listen, process spawns that reach a network binary, shell strings, dynamic code loading, native calls, external references, network commands in scripts, and declared network dependencies and remote sources. It does NOT prove zero egress: this is a Turing-complete language and the analysis underapproximates. Detection is BLOCKLIST-BASED, so it is complete only against names it knows: a renamed, vendored or dynamically-constructed module or argv entry is invisible. Measured against network libraries chosen without reference to the list, recall is 0%, so a PLAIN, unobfuscated `import X` of a library this tool does not name produces no finding, exactly like an obfuscated one. Check FORBIDDEN_IMPORT_MODULES against your own dependencies before reading anything into a CLEAN verdict. Every third-party module the Python in the tree imports that is on none of this tool's lists is named in `unlisted_imports` (for JavaScript and TypeScript packages, `unlisted_js_imports`): the verdict covers the names the tool knows, and that field lists the ones it does not. Files that fail to parse are reported as `unparseable-source` and were NOT analysed. Directories skipped by name, files of types this tool has no reader for (configuration data, other languages, lockfiles) and symbolic links are listed under `not_scanned` and counted in `files_not_read`; a tree in which nothing was read is NOT-ANALYSED rather than CLEAN. An import is NOT counted as a network import when the tree itself supplies a top-level module of that name, because that module shadows any installed package; every such name is listed in `shadowed_imports`, so a network client VENDORED into the tree root appears there rather than disappearing. Declared dependencies (pyproject.toml, requirement files, setup.cfg, setup.py, Pipfile, conda environment files, package.json) that name a known network package are reported as `declared-network-dependency`: evidence the tree depends on that package, not a claim that a call site reaches the network. An argument is resolved when the source spells it out or binds it once to a literal; anything built at run time (f-strings, concatenation, lists assembled in code) is not, except a file path whose UNC root is written in the file. The subject digest folds CRLF line endings to LF in text files, and file order is by path bytes, so the same tree gives the same report on every operating system and wherever it sits on disk. This report is DETECTION-grade evidence and does not support an unqualified claim of absence.

## Findings

| File | Line | Kind | Detail |
|---|---|---|---|
| `collector.py` | 2 | network-import | import urllib.request |
| `collector.py` | 10 | network-target | Request\(...\) builds a request for a URL literal; nothing is sent at this line |
| `pyproject.toml` | 10 | declared-network-dependency | declared dependency 'stripe' names a known network package - not a call site; the tree depends on it |

*ENTROVOUCH. For the People.*
# ENTROVOUCH

Audit a codebase's network access, cryptography, keys and dependencies, and sign the result.

Four tools in pure Python, with no dependencies. None of them opens a network connection.

| Tool | Question it answers |
|---|---|
| `no_egress_auditor` | Does this code talk to the outside world, and where? |
| `cbom` | What cryptography does its Python use, and is any of it quantum-vulnerable? |
| `key_provenance` | Does a key or credential come from secret storage, or is it written into the tree? |
| `sbom` | What dependencies does the tree declare? |

Anyone can check a report without trusting us: run the same tool on the same tree and compare one value, the
findings digest. With the publisher's public root pinned, you can also confirm who issued a signed report.

A `CLEAN` result means nothing came to our attention in the files the tool read. It does not mean nothing is there;
[What a result means](#what-a-result-means) explains why.

[Verify our output yourself](examples/README.md): a fixture tree, the reports generated from it, and the command
that regenerates them. No account, no upload, no network call.

## Try it

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python -m entrovouch.no_egress_auditor examples/sample_service --label entrovouch/examples/sample_service
```

Compare the `findings_digest` it prints with the table in [examples/README.md](examples/README.md).

The label names what was audited and is covered by the digest: pass ours to reproduce our value, and your own
(`org/repo@commit`) for your own code.

The tools need Python 3.11 or later and nothing else. The test suite needs `pytest`:

```bash
python -m pytest -q      # 3203 tests, pytest only, exit 0
```

Some tests skip where the machine lacks something (`jsonschema`, or the right to create symbolic links on Windows).
27 more need the optional extras: run `pip install -e .[test]`, then re-run for 3230. A test asserts both counts.

The shipped package, `entrovouch/`, audits `CLEAN`. The demo tree, the test programs and the test workflow produce
findings on purpose, and `cbom` and `key_provenance` report the package's own search strings. The auditor has no
rule that skips this repository's folders.

## Use

```bash
python -m entrovouch.no_egress_auditor /path/to/project
python -m entrovouch.cbom /path/to/project
python -m entrovouch.key_provenance /path/to/project
python -m entrovouch.sbom /path/to/project --cdx bom.cdx.json
python -m entrovouch.verify report.json --root <the issuer's public root>
```

Each scanner takes a directory, prints a markdown report, writes JSON with `--json` and markdown with `--md`, and
takes `--label`.

- `no_egress_auditor` reports imports, calls, commands and declared dependencies that can reach the network, in
  Python, JavaScript, scripts, Dockerfiles, Makefiles, CI pipelines, web pages and package manifests.
- `cbom` lists the cryptography the Python code uses, by library, call and algorithm name, and marks what a quantum
  computer would break. `REVIEW-NEEDED` means something it found needs a person to classify it.
- `key_provenance` looks for key material and credentials written into the tree, in code, key files, `.env` and
  configuration files, notebooks and archives. Its verdict is always `REVIEW`: whether a key in the tree is a defect
  depends on who receives the artifact.
- `sbom` writes a CycloneDX 1.6 inventory of the dependencies the tree declares, top level only and before any build.
  The EU Cyber Resilience Act
  ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj), Annex I Part II(1)) asks for at least
  the top-level dependencies from 11 December 2027.

What each tool reads and reports: [docs/TOOLS.md](docs/TOOLS.md). How `no_egress_auditor` reads each kind of file,
and what it lists as not read: [docs/WHAT_IS_READ.md](docs/WHAT_IS_READ.md).

### Adapters

The same findings in other formats. What each format name claims: [CONFORMANCE.md](CONFORMANCE.md); what each
adapter refuses: [docs/ADAPTERS.md](docs/ADAPTERS.md).

```bash
python -m entrovouch.sarif report.json --out results.sarif          # SARIF 2.1.0
python -m entrovouch.attestation report.json --out statement.json   # in-toto Statement, not DSSE
python -m entrovouch.cyclonedx cbom.json --out bom.cdx.json         # CycloneDX 1.6 CBOM
python -m entrovouch.vex cbom.json --out vex.cdx.json               # in_triage, CWE-, never CVE-
python -m entrovouch.csaf cbom.json --publisher-name "Example Ltd" \
    --publisher-namespace https://example.com --out vex.csaf.json   # CSAF 2.0 VEX, under_investigation
python -m entrovouch.timestamp request report.json --out req.tsq    # RFC 3161; you send this, we never open a socket
python -m entrovouch.timestamp check report.json --token resp.tsr --nonce N   # imprint and nonce, not TSA-chain verify
```

### Reproducing a report

```python
from pathlib import Path
from entrovouch.no_egress_auditor import audit
audit(Path("/path/to/project"), label="org/repo@commit").findings_digest
```

| Field | Reproduces? | What it answers |
|---|---|---|
| `findings_digest` | yes, across runs, processes and machines | *Does this tool, on this tree, still say this?* |
| `subject_digest` | yes, per tree | *Which tree was audited?* |
| `content_hash` | no, by design | *Is this the exact artifact I was handed?* |

Compare `findings_digest`; `content_hash` covers the time of issue and differs on every run. `key_provenance` has no
findings digest: re-run it and read the findings. Details: [docs/REPRODUCING.md](docs/REPRODUCING.md).

### Exit codes

```
0  clean          no findings   (SBOM: the run succeeded; empty vs declared is a field)
1  findings       the scan ran and found something, or a file it could not parse
                  (verify: any status but ATTESTED)
2  could not run  bad arguments, unreadable target, missing key, an internal error,
                  or NOTHING WAS SCANNED (`NOT-ANALYSED`): never a clean result
```

Treat 1 and 2 differently in a pipeline: 2 means the scan did not run, or read nothing.

## What a result means

`no_egress_auditor` underapproximates. A sound analyser overapproximates: it may report egress that cannot happen,
but it never misses egress that can. This one reports the network surface it knows and is silent about the rest, so
a `CLEAN` result is evidence of absence, not proof.

Detection is list-based. An ordinary import of a network library that is not on the list produces no finding. The
list is `FORBIDDEN_IMPORT_MODULES` in [`entrovouch/no_egress_auditor.py`](entrovouch/no_egress_auditor.py); check it
against your own dependencies. Every report carries `unlisted_imports` and `unlisted_js_imports`: the third-party
Python modules and JavaScript packages the tree imports that are on none of the tool's lists. The tool says nothing
about what they do. Both lists are covered by the findings digest.

Every report also lists what the tool did not read: skipped directories, file types it has no reader for, and
links. A file that will not parse is a finding, and so is a compiled module, executable or archive in the tree. A
tree in which nothing was read is `NOT-ANALYSED`, exit 2.

- The analysis is static. It does not watch the code run, and it does not see egress from a dependency you did not
  point it at, from dynamic loading or from a compiled extension.
- A declared dependency is not a call site: `stripe` in `pyproject.toml` is reported as
  `declared-network-dependency`.
- A server is `inbound-listener`, never egress.
- A report describes the tree at one commit.
- `REVIEW` means review: a person reads the finding before anything passes.

### What kind of assurance this is

Under ISAE 3000 and SSAE 18, reasonable assurance is a positive opinion (*in our opinion, X is the case*) and
limited assurance is a negative one (*nothing came to our attention to suggest otherwise*). Everything these tools
produce is limited assurance: `CLEAN`, `NOTHING-VULNERABLE-FOUND` and `NOTHING-FOUND` mean nothing came to our
attention in the files the tool read. Because the analyser underapproximates, no amount of effort lets it give a
positive opinion. EntroVerse is not a licensed audit firm, and running these tools is not an engagement under either
standard.

### How often is it wrong?

Each tool was run on public Python repositories drawn at random with a fixed seed and pinned to a commit. Every
finding was read at its source line against one question: is what it says about that line true? A finding defensible
either way is counted both ways. The figures are for this release, on sets no change was made from; every set is in
[PRECISION_CORPUS.md](PRECISION_CORPUS.md).

| Tool | Sets | Findings | False | Either way | Precision |
|---|---|---|---|---|---|
| `no_egress_auditor` | 42, 43, 45 | 885 | 0 | 3 | 100% (99.66%) |
| `cbom` | 41 to 46 | 249 | 0 | 7 | 100% (97.19%) |
| `key_provenance` | 50 | 21 | 3 | 16 | 85.7% (9.5%) |

The first figure counts either-way findings as right; the figure in brackets counts them as wrong. `sbom` reads
declared dependencies and has no precision figure.

`key_provenance` is the weakest of the three measured. Its figure rests on 21 findings, so the 95% interval (Wilson)
runs from 65.4% to 95.0%; 16 of the 21 were placeholder values in tests. Its precision varies a lot between trees and
is lowest on repositories heavy with configuration. Read every finding.

Known false findings in this release: `key_provenance` reports a constant whose value names the setting it stands
for (`CONF_CLIENT_SECRET = "client_secret"`) or a dictionary key (`NESTED_DOC_KEY = "_childDocuments_"`). The
either-way findings of the other tools are listed per set in the corpus.

Expect new false findings on code these tools have not seen, more of them from `key_provenance`. One or two
repositories make most of the findings in most sets. The findings were read by AI models under the maintainers'
direction, the `key_provenance` set twice and independently; no person has re-read a set. Of the 885
`no_egress_auditor` findings, 188 are in folders named `test`, `tests`, `example`, `examples`, `doc` or `docs`. They
are accurate and often not what a buyer is asking about.

### How often does it miss?

| Tier | What it represents | Recall |
|---|---|---|
| **A: plain, module on the list** | `import requests`, a lazy import in a function, `from http import client`, `import subprocess as sp` then `sp.run(["curl", ...])` | **4/4** import fixtures; the spawn forms are pinned by tests |
| **A′: plain, module not on the list** | the same developer using a library the list does not name | **0/59** as findings; each is named in `unlisted_imports` |
| **B: light obfuscation** | aliases, `try/except` imports, `importlib`, split strings, `curl` via `subprocess` | **6/6**, pinned by the suite |
| **C: deliberate evasion** | ten programs written by someone who read this source: assembled names, a module written to disk and imported, the interpreter started through `Popen` | **7/10** trees not `CLEAN` |

Recall on libraries the list does not name is 0% by construction; `unlisted_imports` names them in every report
instead. The tier C programs are in `tests/test_detection_scope.py`, which fails if the three misses change, and
`tests/test_runtime_oracle.py` compares the auditor with a Python audit hook (PEP 578) on 23 programs. We wrote
both sets of programs, so an adversary who has not seen them may do better than tier C suggests.

## Signing

One signer ships: Lamport-Merkle over SHA3-256, resting on SHA3-256 preimage resistance alone. It claims conformance
to no published standard and does not meet NIST SP 800-208, which requires stateful keys to live in a hardware
module; this key is a file. Each leaf signs once, so keep one copy of the key that signs, and run
`python -m entrovouch.no_egress_auditor --key PATH --advance-key N` before a restored copy signs again. With the root
pinned, a signature shows who issued a report and that it is unchanged. It says nothing about whether the verdict is
correct. The full rules are in [docs/SIGNING.md](docs/SIGNING.md).

### The publisher's public root

```
eb309717634b3a9bd952aac903538bd9b3350d1b006f5176d1c87763ba87a96b
```

A customer's engagement letter carries the root to pin. This copy is a convenience, and anyone who can alter the
repository can alter it. The example reports are unsigned on purpose.

```python
from entrovouch.no_egress_auditor import verify_report    # cbom.verify_cbom, sbom.verify_sbom for those
ok, status = verify_report(report, expected_root="eb309717…")
# ok is True only for ATTESTED
```

`verify` prints `ATTESTED`, `UNVERIFIED`, `UNSIGNED` or `TAMPERED`. A report you did not pin a root for is not
evidence of origin.

## Independently issued audits

The tools, the module lists and the signing capability on this page are free, complete and identical for everyone.
Independence cannot be self-served: nobody else can rely on an audit you ran on your own code. Third-party
issuance, classification of findings and scheduled re-issuance: [entroverse.com](https://entroverse.com).

## License

See `LICENSE`.

---

*Prevention over detection. For the People.*

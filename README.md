# ENTROVOUCH

**Audit what a codebase actually does, and sign the result.**

Four tools. Pure Python standard library, no dependencies, no network access of their own.

| Tool | Answers |
|---|---|
| **`no_egress_auditor`** | *Does this code talk to the outside world, and where?* |
| **`cbom`** | *What cryptography does it use, and is any of it quantum-vulnerable?* |
| **`key_provenance`** | *Where does a signing key come from: secret storage, or this source tree?* |
| **`sbom`** | *What dependencies does this tree declare?* |

Point this at a tree. It tells you whether the *capability* to talk to the network is in
the source, and it signs that answer. **`CLEAN` means nothing came to our attention, not
that nothing is there.** You do not have to trust the issuer: re-run the tool and compare
one value. With the publisher's root pinned, you can also confirm *who* issued it.

**→ [Verify our output yourself](examples/README.md)** — a fixture tree, the reports we
generated from it, and the command that regenerates them. No account, no upload, no
network call.

A vendor questionnaire asks what your system does. *"We have a policy"* is a weaker
answer than *"here is a signed audit; regenerate it yourself."*

---

## Try it

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python -m entrovouch.no_egress_auditor examples/sample_service
```

Then compare **`findings_digest`** to the table in [examples/README.md](examples/README.md).
That is the whole pitch.

Python 3.10+. No runtime dependencies. If you want to check our work:

```bash
python -m pytest -q      # 384 tests, no installs, exit 0
```

A clean clone runs **384** tests with nothing installed and exits 0. **24** more need
optional extras (`hypothesis`, `jsonschema`) and *skip* without them rather than failing.
Run `pip install -e .[test]`, then re-run for **408**. Both counts are asserted by a
test, not maintained by hand. A `pip install` between a sceptical reader and reproducing
our results would undercut the only claim this package makes.

Scanning *this* repository: the shipped package (`entrovouch/`) audits CLEAN;
`examples/` is a deliberate hit so the demo is not empty; `cbom` self-hits on its own
search strings (`DES` in the file that searches for DES). The auditor is not taught to
skip `examples/`. Scope the claim, never blind the instrument.

## Use

```bash
python -m entrovouch.no_egress_auditor /path/to/project
python -m entrovouch.cbom /path/to/project
python -m entrovouch.key_provenance /path/to/project
python -m entrovouch.sbom /path/to/project --cdx bom.cdx.json
```

Each scanner prints a markdown report. `key_provenance` reports `REVIEW` rather than a
verdict: whether publicly-derivable key material is a defect depends on who receives the
artifact, which source cannot tell you.

`sbom` is the inventory [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
(the Cyber Resilience Act) Annex I Part II(1) asks for: a software bill of materials in a
commonly used machine-readable format covering at least the top-level dependencies. It
emits CycloneDX 1.6 from what the tree *declares*. Pre-build, top-level only. It does not
hash a built artifact, does not walk transitives, and does not claim CISA 2026
minimum-element conformance — those gaps are labelled `unknown` in the document. The
SBOM obligation itself applies **11 December 2027**. This command is the inventory, not
incident reporting.

### Adapters

Same findings, in formats other tools already ingest. What each name actually claims is
in [CONFORMANCE.md](CONFORMANCE.md).

```bash
python -m entrovouch.sarif report.json --out results.sarif          # SARIF 2.1.0
python -m entrovouch.attestation report.json --out statement.json   # in-toto Statement, not DSSE
python -m entrovouch.cyclonedx cbom.json --out bom.cdx.json         # CycloneDX 1.6 CBOM
python -m entrovouch.vex cbom.json --out vex.cdx.json               # in_triage, CWE-, never CVE-
python -m entrovouch.timestamp request report.json --out req.tsq    # you send this; we never open a socket
python -m entrovouch.timestamp check report.json --token resp.tsr   # imprint match, not TSA-chain verify
```

SARIF, CycloneDX and the SBOM validate against their official schemas (test-only
`jsonschema`; runtime stays stdlib). Schema validation is not a blank cheque: see
CONFORMANCE.md.

### Reproducing a report

```python
from entrovouch.no_egress_auditor import audit
audit(Path("/path/to/project"), label="org/repo@commit").findings_digest
```

| Field | Reproduces? | What it answers |
|---|---|---|
| `findings_digest` | **yes**, across runs, processes and machines | *Does this tool, on this tree, still say this?* |
| `subject_digest` | yes, per tree | *Which tree was audited?* |
| `content_hash` | **no**, by design | *Is this the exact artifact I was handed?* |

All three are printed on the report, each labelled. **Comparing `content_hash` is the
obvious instinct and the wrong move:** it covers the issuance timestamp and is *expected*
to differ. A different content hash with an identical findings digest is the same result,
issued twice. `key_provenance` has no digest; re-run it and read the findings.

`subject_digest` is an order-independent SHA3-256 over every file the audit read, also
carried as in-toto `subject`. A signature over a free-text label attests the sentence,
not the tree.

## What it will not do

**The three scanners are AST-first, not grep.** A docstring that *mentions* `requests`
does not fire; an import or call does. The SBOM reads declared dependencies, not a
syntax tree.

**This analyser underapproximates, and that word is the most important one on this page.**
A *sound* analyser overapproximates: it may report egress that cannot happen, but never
misses egress that can. This one does the opposite. It names the network surface it knows
and stays silent about the rest, so **a CLEAN result is evidence of absence, not proof of
it.**

The blind spots are not only the clever ones. Obfuscation is undecidable in a
Turing-complete language, but **an ordinary, unobfuscated import of a network module that
is not on the list is equally invisible.** Detection is list-based and a list is never
complete. The list is
[`FORBIDDEN_IMPORT_MODULES`](entrovouch/no_egress_auditor.py), deliberately plain:
check it against your own dependencies rather than taking a claim about coverage on trust.

- **Static analysis only.** No runtime observation. No egress from a dependency you did
  not point at, from dynamic loading, or from a compiled extension.
- **A file that will not parse is reported, not skipped** (`unparseable-source`). An
  unanalysed region is not "nothing found."
- **A local module of the same name is not a network import.** `motor.py` in the tree
  shadows the package; the name is listed in `shadowed_imports` rather than vanished.
- **A declared dependency is not a call site.** `stripe` in `pyproject.toml` is
  `declared-network-dependency`. Names the import list does not know stay invisible
  here too — declared-intent uses the same list; it does not secretly complete it.
- **Outbound and inbound are different findings.** A listening socket is
  `inbound-listener`, never egress.
- **A clean audit describes a tree at a commit, not a running system.**
- **`REVIEW` means review.** It is not a pass.

### How often is it wrong?

Measured, not asserted. The three scanners (not `sbom`) were run on 2026-08-30 over
**20 well-known, permissively-licensed Python repositories** (requests, flask, pytest,
pydantic, httpx, black, typer, attrs, click, tox, isort, structlog, loguru, tenacity,
faker, jsonschema, anyio, more-itertools, python-dotenv, records). Every finding was
classified against one question: **can the flagged construct actually reach the network?**

| Tool | Findings | False positives, first run | After the fix |
|---|---|---|---|
| `no_egress_auditor` | 430 | **32 of 257 judged, 12.5%** | **0**, finding count unchanged |
| `key_provenance` | 23 | **16 of 23, 70%** | **1 arguable of 8**, all 7 true positives kept |
| `cbom` | 90 | 0 against its stated scope | 4 downgraded where the author declared non-security |

Each false-positive class was one structural defect (pure submodules reported as
sockets; mapping keys named `*_KEY`; `usedforsecurity=False` ignored), not a longer
exception list. **41 of the 90 CBOM components are `random`:** accurate, and in a test
suite rarely actionable. Accuracy and actionability are different properties.

### And how often does it MISS?

| Tier | What it represents | Recall |
|---|---|---|
| **A — plain, module on the list** | not hiding: `import requests`, a lazy import in a function | **3/3, 100%** |
| **A′ — plain, module NOT on the list** | the same developer using a library we never named: `import stripe`, `import minio` | **0/59, 0%** |
| **B — light obfuscation** | avoiding a linter: aliases, `try/except` imports, `importlib`, split strings, `curl` via `subprocess` | **6/6, 100%** |
| **C — deliberate evasion** | someone who read this source: `getattr` chains, `ctypes`, char-code module names, vendored copies | **2/10, 20%** |

**Tier A′ is the row that matters.** Tiers A and B originally used modules already on
the list, so those rows could not fail. A fixture set drawn independently scored 0 of 46.
The list was extended by 46 names and A′ re-measured against 59 libraries deliberately
not added: **still 0%.**

> **Extending the list moves the boundary. It does not remove it.** Recall against
> libraries the list does not name is 0% by construction, not by oversight, and not
> fixable by a longer list.

**20% against a deliberate adversary is why this page says `underapproximates` rather
than `proves`.** Most of tier C is undecidable. One miss
(`subprocess.run([sys.executable, "-c", ...])`) was measured and declined: treating
the interpreter as a network binary would trade that miss for a flood of false
positives on test runners.

Precision is measured on mature libraries; recall against fixtures we wrote. An
adversary who has not seen them may do better than tier C suggests. Published work
puts static-analysis abandonment at false-positive rates above 20–30%. The corpus,
date and method are stated so you can redo both.

### What kind of assurance this is

Under ISAE 3000 and SSAE 18, **reasonable assurance** is a positive opinion (*in our
opinion, X is the case*) and **limited assurance** is a negative one (*nothing came to
our attention to suggest otherwise*). They are different statements, not a strong and
weak version of the same one.

**Everything this tool produces is limited assurance.** `CLEAN` means *nothing came to
our attention*, not *there is nothing there*. Because the analyser underapproximates, a
positive opinion is not available to it at any level of effort.

**This is a translation, not a credential.** EntroVerse is not a licensed audit firm,
this is not an engagement under any standard, and nothing here is performed by a party
independent of the tool's author unless you separately engage one.

### Exit codes

```
0  clean          no findings   (SBOM: the run succeeded; empty vs declared is a field)
1  findings       the scan ran and found something
2  could not run  bad arguments, unreadable target — NOT a clean result
```

**1 and 2 are different answers.** A pipeline that treats them alike will eventually
report a broken scan as a passing one. `sbom` exits 0 if it ran; whether the BOM lists
components is in the document, not the exit code.

## Signing

**One signer ships: Lamport-Merkle SHA3-256.** Hardness is SHA3-256 preimage resistance
alone. Keys are one-time; the leaf index is persisted before any secret is revealed.
Signatures are ~16 KB. **It claims conformance to no published standard.** That is a
position, not a gap: a signature you can check against a pinned root is worth more than
a standards name this repository cannot support.

With the root pinned, a signature proves the report came from the holder of that key
and that its bytes are unaltered. It says nothing about whether the verdict is
*correct*. The algorithm name and the public root are inside the signed bytes: editing
either yields `TAMPERED`.

### The publisher's public root

```
eb309717634b3a9bd952aac903538bd9b3350d1b006f5176d1c87763ba87a96b
```

**Paying customers pin the copy on [entroverse.com](https://entroverse.com) and in the
engagement letter.** The value above is a convenience copy. Anyone who can alter this
repository can alter this line. The `findings_digest` check does not depend on it.

```python
from entrovouch.no_egress_auditor import verify_report
ok, status = verify_report(report, expected_root="eb309717…")
# ok is True only for ATTESTED
```

**`ok` is `True` for `ATTESTED` and nothing else.** `UNSIGNED` and `UNVERIFIED` are
false. A report you did not pin a root for is not evidence of origin.

Unsigned reports, and reports from before the current signer, are not evidence of
origin. Re-run.

## Independently issued audits

The tools, the module lists and the signing capability on this page are free, complete
and identical for everyone. What cannot be self-served is independence: an audit you
run on your own code is not an audit anyone else can rely on, and no amount of software
fixes that. **Independent third-party issuance, classification of findings, and
scheduled re-issuance: [entroverse.com](https://entroverse.com).**

## License

See `LICENSE`.

---

*Prevention over detection. For the People.*

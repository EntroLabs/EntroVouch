# ENTROVOUCH

**Audit what a codebase actually does, and sign the result.**

Three auditors. Pure Python standard library, no dependencies, no network access of their own.

| Tool | Answers |
|---|---|
| **`no_egress_auditor`** | *Does this code talk to the outside world, and where?* |
| **`cbom`** | *What cryptography does it use, and is any of it quantum-vulnerable?* |
| **`key_provenance`** | *Where does a signing key come from: secret storage, or this source tree?* |

Each emits an independently verifiable report, optionally signed. You do not have to trust the
issuer: re-run the tool and compare one value. With the publisher's root pinned, you can also
confirm *who* issued it.

**→ [Verify our output yourself](examples/README.md)** — a fixture tree, the reports we generated
from it, and the command that regenerates them. No account, no upload, no network call.

---

## Why this exists

Most supply-chain assurance is detection: watch traffic, alert on anomalies, hope you notice. This
is prevention by structure. A static audit answers whether the egress capability is present at all,
and produces an artifact you can hand to a customer, a regulator, or a procurement team.

**Regulation (EU) 2024/2847 (the Cyber Resilience Act) obliges manufacturers placing products with
digital elements on the EU market to document their components, "including by drawing up a software
bill of materials in a commonly used and machine-readable format covering at the very least the
top-level dependencies"** (Annex I, Part II, point 1).

| CRA date | What applies |
|---|---|
| **11 June 2026** *(past)* | Chapter IV, Arts. 35–51: conformity assessment bodies |
| **11 September 2026** | **Art. 14**: reporting exploited vulnerabilities and severe incidents (24h / 72h / 14-day) |
| **11 December 2027** | The Regulation in full, **including the Annex I SBOM obligation** |

The SBOM obligation is December 2027. September 2026 is *reporting*. The link between them is an
inference rather than a clause: you cannot report on components you have not inventoried, so an
inventory has to exist first. Labelled as an argument, not dressed up as a citation.

A vendor questionnaire asks what your system does. *"We have a policy"* is a weaker answer than
*"here is a signed audit; regenerate it yourself."*

## Install

No dependencies. Python 3.10+.

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python -m pytest -q      # 359 tests, no installs, exit 0
```

A clean clone runs **359** tests with nothing installed and exits 0. **23** more need optional
extras (`hypothesis`, `jsonschema`) and *skip* without them rather than failing. Run
`pip install -e .[test]`, then re-run for **382**. Both counts are asserted by a test, not
maintained by hand.

The extras are optional on purpose: a `pip install` between a sceptical reader and reproducing our
results would undercut the only claim this package makes.

## Use

```bash
# Audit a tree for network egress
python -m entrovouch.no_egress_auditor /path/to/project

# Cryptographic Bill of Materials
python -m entrovouch.cbom /path/to/project

# Where do signing keys come from?
python -m entrovouch.key_provenance /path/to/project
```

Each produces a markdown report plus a signature line.

`key_provenance` is the detector that found the forgeable signature in this package's own
predecessor. It reports `REVIEW` rather than a verdict on purpose: whether publicly-derivable key
material is a defect depends on who receives the artifact, which source cannot tell you.

### Interoperable output

```bash
# SARIF 2.1.0 — GitHub code scanning ingests this natively
python -m entrovouch.no_egress_auditor /path/to/project --json report.json
python -m entrovouch.sarif report.json --out results.sarif

# in-toto Statement
python -m entrovouch.attestation report.json --out statement.json

# CycloneDX 1.6 CBOM — the schema regulators and PQC tooling read
python -m entrovouch.cbom /path/to/project --json cbom.json
python -m entrovouch.cyclonedx cbom.json --out bom.cdx.json

# VEX — is what is present actually exploitable?
python -m entrovouch.vex cbom.json --out vex.cdx.json
```

**Both SARIF and CycloneDX output validate against their official JSON schemas with zero errors.**
The schemas are vendored, pinned by SHA-256, and each validator was negative-tested against six
malformed documents before its zero was believed. `jsonschema` is test-only; the runtime stays pure
standard library.

Three deliberate limits in that output:

- **The CycloneDX zero does not establish the version.** That schema declares `specVersion` as a
  plain string with `"1.6"` only as an example, so `"9.9"` also validates against it. We assert 1.6
  separately. SARIF's schema *does* constrain its `version`, so passing it does establish the
  version. A per-standard fact, checked rather than assumed.
- **specVersion 1.6, not 1.7, and 1.7 is not claimed.** Nothing here has been run against that
  revision. Conformance with the CISA/NIST CBOM minimum elements is likewise not claimed: those are
  unpublished, due under EO 14412 around March 2027.
- **in-toto adopts the Statement, not the DSSE envelope.** You get payload interoperability; the
  signature stays Lamport-Merkle. A DSSE verifier can read the subject and predicate but cannot
  check the signature, and the statement says so in its own `note` field rather than letting a tool
  assume it verified something.

SARIF puts findings in a repository's security tab with no integration work and no account. Severity
is not inferred: every result is `warning`, because whether a present egress capability is a defect
depends on what you claimed about your software. Pass `--level` if you know your policy.
Fingerprints exclude the line number, so inserting a comment does not close and reopen every alert.

**VEX** is emitted as CycloneDX-native `vulnerabilities` statements against the same pinned schema.
Every statement is `in_triage` and every identifier is a `CWE-` weakness class, never a `CVE-`.
Exploitability is a property of reachability and static analysis does not establish reachability, so
`exploitable` would claim an analysis that never ran and `not_affected` would clear a finding on the
strength of not having looked. `in_triage` is the format's own word for *identified, a human
decides*. There is no CVE data here because this tool has no vulnerability database and makes no
network call to acquire one.

```bash
# RFC 3161 trusted timestamp — a signature proves who and what, never when
python -m entrovouch.timestamp request report.json --out req.tsq
curl -s -H "Content-Type: application/timestamp-query" --data-binary @req.tsq <your-tsa-url> -o resp.tsr
python -m entrovouch.timestamp check report.json --token resp.tsr
```

**The middle line is yours, and that is the design.** Fetching a timestamp means opening a socket,
and a tool that acquired a network client to prove it has no network client would refute itself. You
choose the authority; we never learn who you asked, because we never ask.

**The check is an imprint match, not a signature verification.** It confirms the token carries this
report's digest, catching a token pasted from a different document. It does not validate the TSA's
certificate chain, which would import a trust root this package exists to avoid. Use
`openssl ts -verify` for that half. The output says which half it did.

### Reproducing a report

Re-run the tool against the same tree and compare **one value**:

```python
from entrovouch.no_egress_auditor import audit
audit(Path("/path/to/project"), label="org/repo@commit").findings_digest
```

| Field | Reproduces? | What it answers |
|---|---|---|
| `findings_digest` | **yes**, across runs, processes and machines | *Does this tool, on this tree, still say this?* |
| `subject_digest` | yes, per tree | *Which tree was audited?* |
| `content_hash` | **no**, by design | *Is this the exact artifact I was handed?* |

All three are printed on the report itself, each labelled with whether it reproduces, so a reader
holding only the report knows which to compare. **Comparing `content_hash` is the obvious instinct
and the wrong move:** it covers the issuance timestamp and is *expected* to differ. A different
content hash with an identical findings digest is the same result, issued twice.

**`subject_digest` binds the report to the code.** It is an order-independent SHA3-256 over every
file the audit read. Before it existed, `target` was a free-text label, so two entirely different
trees could produce byte-identical reports under one name, and a signature over that attests the
*sentence* rather than the *subject*. The report also carries `subject` in the
[in-toto Statement](https://github.com/in-toto/attestation) shape, so the binding is the one
supply-chain tooling already verifies.

## What it will not do

**AST-first, not grep.** All three tools parse the syntax tree. A docstring that *mentions*
`requests` does not fire; an import or call does.

**This analyser underapproximates, and that word is the most important one on this page.** A *sound*
analyser overapproximates: it may report egress that cannot happen, but never misses egress that
can. This one does the opposite. It names the network surface it knows and stays silent about the
rest, so **a CLEAN result is evidence of absence, not proof of it.**

The blind spots are not only the clever ones. Obfuscation is undecidable in a Turing-complete
language, but **an ordinary, unobfuscated import of a network module that is not on the list is
equally invisible.** Detection is list-based and a list is never complete. The list is
[`FORBIDDEN_IMPORT_MODULES`](entrovouch/no_egress_auditor.py), deliberately plain and readable:
check it against your own dependencies rather than taking a claim about coverage on trust.

Other limits, worth knowing before you rely on the output:

- **Static analysis only.** It does not observe runtime behaviour, and cannot see egress introduced
  by a dependency it was not pointed at, by dynamic loading, or by a compiled extension.
- **A file that will not parse is reported, not skipped.** It appears as `unparseable-source` and
  the tree does not come back CLEAN. Reporting an unanalysed region as "nothing found" would be the
  can't-run-versus-fail conflation described under [Exit codes](#exit-codes).
- **An import is not counted when the tree supplies a module of that name.** A local `motor.py`
  shadows any installed package, so calling it a network import would be wrong. Every such name is
  listed in `shadowed_imports`, so a vendored client appears there rather than disappearing.
- **Outbound and inbound are different findings.** A listening socket is `inbound-listener`, never
  egress. It is not exfiltration, but "on-prem, no telemetry" is a claim a bound port is part of.
- **A clean audit describes a tree at a commit, not a running system.** Time T says nothing about T+1.
- **`REVIEW` means review.** It is not a pass.

### How often is it wrong?

Measured, not asserted. All three tools were run on 2026-08-30 over **20 well-known,
permissively-licensed Python repositories** (requests, flask, pytest, pydantic, httpx, black, typer,
attrs, click, tox, isort, structlog, loguru, tenacity, faker, jsonschema, anyio, more-itertools,
python-dotenv, records), and every finding was classified against one question: **can the flagged
construct actually reach the network?** The first pass measured only the egress auditor; the other
two were measured afterwards and one was far worse.

| Tool | Findings | False positives, first run | After the fix |
|---|---|---|---|
| `no_egress_auditor` | 430 | **32 of 257 judged, 12.5%** | **0**, finding count unchanged |
| `key_provenance` | 23 | **16 of 23, 70%** | **1 arguable of 8**, all 7 true positives kept |
| `cbom` | 90 | 0 against its stated scope | 4 downgraded where the author declared non-security |

In each tool the false positives were a single defect class, and in each case the fix was structural
rather than a longer exception list:

- **Egress:** a *pure submodule* of a network package. `from requests.structures import
  CaseInsensitiveDict` shows `requests` is a dependency; that module is a dict subclass with no
  network code. Now reported as `network-dependency`, so the evidence survives and the false claim
  does not.
- **Key provenance, the worst at 70%:** an uppercase `*_KEY` constant whose *value* is an
  identifier, a dunder or an env-var name (`ROOT_KEY = '__root__'`). Those are mapping keys, not key
  material. The rule judged only the name, and only its suffix, never the value.
- **CBOM:** it ignored `usedforsecurity=False`, **which is the codebase answering the question.**
  Now `REVIEW` rather than `BROKEN`: downgraded, not dropped, because the flag is the author's
  assertion and an assertion is what this package declines to take on trust.

**41 of the 90 CBOM components are `random`.** Accurate, and in a test suite or fake-data generator
rarely actionable. Accuracy and actionability are different properties.

### And how often does it MISS?

Precision is the easy half. Recall against someone hiding decides whether a clean report means
anything, so it was measured too, in four tiers.

| Tier | What it represents | Recall |
|---|---|---|
| **A — plain, module on the list** | not hiding: `import requests`, a lazy import in a function | **3/3, 100%** |
| **A′ — plain, module NOT on the list** | the same developer using a library we never named: `import stripe`, `import minio` | **0/59, 0%** |
| **B — light obfuscation** | avoiding a linter: aliases, `try/except` imports, `importlib`, split strings, `curl` via `subprocess` | **6/6, 100%** |
| **C — deliberate evasion** | someone who read this source: `getattr` chains, `ctypes`, char-code module names, vendored copies | **2/10, 20%** |

**Tier A′ is the row that matters.** It was added on 2026-08-31 after an audit found every tier-A
and tier-B fixture used a module already on the list, so those rows were the list being checked
against itself and could not fail. A fixture set drawn *independently* of the list scored 0 of 46,
including a file that POSTs a user's email to an external host. The list was then extended by 46
names and tier A′ re-measured against 59 libraries deliberately not added: **still 0%.**

> **Extending the list moves the boundary. It does not remove it.** Recall against libraries the
> list does not name is 0% by construction, not by oversight, and not fixable by a longer list.

**20% against a deliberate adversary is why this page says `underapproximates` rather than
`proves`.** Most of tier C is undecidable, and the two catches were flagged as `dynamic-exec`: the
mechanism, not the payload. One miss looked cheap to fix and was measured instead of assumed.
`subprocess.run([sys.executable, "-c", ...])` relays through the interpreter, and `sys.executable`
appears 457 times across 247 files in the corpus above, almost all test runners. That fix would have
traded one miss for hundreds of false positives, so the blind spot is named here instead.

**What these numbers are not.** Precision is measured on mature libraries; recall against fixtures
we wrote, and an adversary who has not seen them may do better than tier C suggests. Published work
puts static-analysis abandonment at false-positive rates above 20–30%, which is the bar precision is
measured against. The corpus, date and method are stated so you can redo both.

### What kind of assurance this is

A hundred-year-old profession already has words for this, and borrowing theirs saves working out
ours. Under ISAE 3000 and SSAE 18, **reasonable assurance** is a positive opinion (*in our opinion,
X is the case*) and **limited assurance** is a negative one (*nothing came to our attention to
suggest otherwise*). The second is not a weaker version of the first but a different, narrower
statement.

**Everything this tool produces is limited assurance.** `CLEAN` means *nothing came to our
attention*, not *there is nothing there*. Because the analyser underapproximates, a positive opinion
is not available to it at any level of effort.

**This is a translation, not a credential.** EntroVerse is not a licensed audit firm, this is not an
engagement under any standard, and nothing here is performed by a party independent of the tool's
author unless you separately engage one. The vocabulary is borrowed so the shape is recognisable to
whoever hands your report to their auditors.

Two self-scan caveats, since this page invites you to run the tools on their own source:

- **`cbom` on this repository reports `BROKEN-CRYPTO`,** because the file containing the string
  `DES` is the file that searches for it. Inherent to self-scanning a scanner.
- **A repo-root egress audit reports one finding, deliberately.**
  `examples/sample_service/collector.py` contains a real network import so the demo has something to
  find. The shipped package audits CLEAN, and both halves are pinned by tests. **The auditor was not
  taught to skip `examples/`:** a built-in blind spot for a directory name is the hidden exemption
  this package argues against. Scope the claim, never blind the instrument.

### Exit codes

```
0  clean          no findings
1  findings       the scan ran and found something
2  could not run  bad arguments, unreadable target — NOT a clean result
```

**1 and 2 are different answers, and a pipeline that treats them alike will eventually report a
broken scan as a passing one.** Our own regeneration script got this wrong on its first run; the
fixture caught it in a minute.

## Signing

**One signer ships: Lamport-Merkle SHA3-256.** Hardness rests on SHA3-256 preimage resistance alone,
with no lattice and no number theory. Keys are one-time and reuse is catastrophic, so the leaf index
is persisted before the secret is revealed. Signatures are ~16 KB.

**It claims conformance to no published standard**, which means no conformance test it can fail and
no standards name in this repository doing work it cannot support. That is a position, not a gap: a
signature you can check against our published root is worth more than a standards label you would
have to take on trust. It does not interoperate.

**What a signature tells you, and what it does not.** With the root pinned, it proves the report
came from the holder of that key and that its bytes are unaltered. It says nothing about whether the
verdict is *correct*. An `UNSIGNED` report proves neither origin nor authorship, only that its bytes
match its own digest.

**The algorithm name and the public root are inside the signed bytes**, so editing either yields
`TAMPERED`. That matters more than it sounds: the displayed algorithm is what a counterparty reads
to substantiate a post-quantum claim, and an unauthenticated one would let a report display a
standards claim it does not carry and still verify as genuine.

### The publisher's public root

```
eb309717634b3a9bd952aac903538bd9b3350d1b006f5176d1c87763ba87a96b
```

Pin this out of band, from a source you trust more than a file in the repository you are auditing:

```python
from entrovouch.no_egress_auditor import verify_report
ok, status = verify_report(report, expected_root="eb309717…")
# ("ATTESTED", True) only if this report came from the holder of that root
```

**`ok` is `True` for `ATTESTED` and nothing else**, not for `UNSIGNED` and not for `UNVERIFIED`. A
report you did not pin a root for is not evidence of origin, and the function says so rather than
letting a caller who checks the boolean assume otherwise.

**A root published here is a weaker pin than one you obtain independently.** Anyone who can alter
this repository can alter this line, so treat it as a convenience rather than a root of trust. The
reproduction check above does not depend on it, which is deliberate.

> **Reports issued before 2026-08-20 carry integrity evidence only and must not be relied upon as
> evidence of origin.** This includes any report delivered on 2026-07-31 or 2026-08-12. Re-run the
> audit against the current release rather than relying on an older artifact.

## Independently issued audits

The tools, the module lists and the signing capability on this page are free, complete and identical
for everyone. What cannot be self-served is independence: an audit you run on your own code is not
an audit anyone else can rely on, and no amount of software fixes that. **Independent third-party
issuance, classification of findings, and scheduled re-issuance:
[entroverse.com](https://entroverse.com).**

## License

See `LICENSE`.

---

*Prevention over detection. For the People.*

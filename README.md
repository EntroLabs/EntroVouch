# ENTROVOUCH

**Audit what a codebase actually does — and sign the result.**

Three auditors, pure Python standard library, no dependencies, no network access of their own.

| Tool | Answers |
|---|---|
| **`no_egress_auditor`** | *Does this code talk to the outside world, and where?* |
| **`cbom`** | *What cryptography does this code actually use, and is any of it quantum-vulnerable?* |
| **`key_provenance`** | *Where does a signing key come from — secret storage, or this source tree?* |

Reports export to **SARIF 2.1.0**, **CycloneDX 1.6** (ECMA-424, 1st ed.) and the **in-toto Statement** format; see [Interoperable output](#interoperable-output).

**→ [Verify our output yourself](examples/README.md)** — a fixture tree, the reports we
generated from it, and the one command that regenerates all of them. Compare a single value.
No account, no upload, no network call.

Each emits an **independently verifiable report**, optionally signed. You do not have to trust the issuer: re-run the tool yourself and compare findings. If the report is signed and you have pinned the publisher's public root, you can additionally confirm *who* issued it.

---

## Why this exists

Most supply-chain assurance is **detection**: watch traffic, alert on anomalies, hope you notice. This is **prevention by structure** — a static audit that answers whether the egress capability is present at all, and produces an artifact you can hand to a customer, a regulator, or a procurement team.

That distinction has a deadline attached to it. **Regulation (EU) 2024/2847 — the Cyber Resilience
Act — obliges manufacturers of products with digital elements placed on the EU market to identify and
document their components, "including by drawing up a software bill of materials in a commonly used
and machine-readable format covering at the very least the top-level dependencies"** (Annex I,
Part II, point 1).

| CRA date | What applies | Source |
|---|---|---|
| **11 June 2026** *(past)* | Chapter IV, Articles 35–51 — conformity assessment bodies | Art. 71(2) |
| **11 September 2026** | **Article 14** — reporting actively exploited vulnerabilities and severe incidents: 24h early warning, 72h notification, 14-day final report | Art. 71(2) |
| **11 December 2027** | The Regulation in full, **including the Annex I SBOM obligation** | Art. 71(2) |

⚠️ **Read that table carefully, because it is easy to get wrong and we did.** The SBOM obligation is
**December 2027**, not September 2026. September 2026 is *reporting*. The link between them is real
but it is an **inference, not a clause**: you cannot report on components you have not inventoried,
so an inventory has to exist before the reporting duty bites. That is an argument, and it is labelled
as one rather than dressed up as a citation.

A vendor questionnaire asks what your system does. *"We have a policy"* is a weaker answer than
*"here is a signed audit; regenerate it yourself."*

## Install

No dependencies. Python 3.10+.

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python -m pytest -q      # 322 tests, no installs, exit 0
```

**322 is what a clean clone runs with nothing installed, and it exits 0.** **23** further tests need
optional extras — `hypothesis` for the property suite, `jsonschema` for the CycloneDX and SARIF
schema-conformance suites — and **skip** without them rather than failing or aborting collection.
`pip install -e .[test]`, then re-run for **345**. Both counts are asserted by a test, not maintained
by hand.

The extras are optional on purpose: putting a `pip install` between a sceptical reader and reproducing
our results would undercut the one claim this package makes.


## Use

```bash
# Audit a tree for network egress
python -m entrovouch.no_egress_auditor /path/to/project

# Generate a Cryptographic Bill of Materials
python -m entrovouch.cbom /path/to/project

# Trace where signing keys come from — secret storage, or the source tree?
python -m entrovouch.key_provenance /path/to/project
```

Each produces a markdown report plus a signature line.

`key_provenance` is the detector that found the forgeable signature in this
package's own predecessor, and it reports `REVIEW` rather than a verdict on
purpose: whether publicly-derivable key material is a defect depends on who
receives the artifact, and source cannot tell you that.

### Interoperable output

```bash
# SARIF 2.1.0 — GitHub code scanning ingests this natively
python -m entrovouch.no_egress_auditor /path/to/project --json report.json
python -m entrovouch.sarif report.json --out results.sarif

# in-toto Statement
python -m entrovouch.attestation report.json --out statement.json
```

✅ **The output validates against the official OASIS SARIF 2.1.0 JSON schema: zero errors.** The
schema is vendored verbatim and pinned by SHA-256, and the validator was negative-tested against six
deliberately malformed documents before its zero was believed. ⭐ **Unlike CycloneDX 1.6, SARIF's own
schema DOES constrain its `version` field** — so passing it establishes the version rather than merely
being consistent with it. That difference is a per-standard fact, checked rather than assumed.

**SARIF** puts findings in the security tab of any repository that runs the tool, with no
integration work and no account. Severity is **not inferred** — every result is `warning`, because
the tool detects that an egress capability is *present* and whether that is a defect depends on what
you claimed about your own software, which source cannot show. Pass `--level` if you know your
policy. Fingerprints deliberately exclude the line number, so inserting a comment does not close
every alert and re-open an identical set.

```bash
# CycloneDX 1.6 CBOM — the schema regulators and PQC tooling read
python -m entrovouch.cbom /path/to/project --json cbom.json
python -m entrovouch.cyclonedx cbom.json --out bom.cdx.json
```

**CycloneDX** emits `cryptographic-asset` components with a NIST quantum security level per
algorithm.

✅ **The output validates against the official CycloneDX 1.6 JSON schema: zero errors.** The schema
file is pinned by hash, and the validator was negative-tested against six deliberately malformed
documents before its zero was believed. ⚠️ **The zero is the claim; the component count is not.**
It was 92 on 2026-08-30 and moves whenever a file is added to or removed from this repository, so it
is deliberately not stated as a fixed figure — a count in prose goes stale on the next commit, and
this one already did once. `jsonschema` is a **test-only**
dependency; the runtime stays pure standard library.

⚠️ **It emits specVersion 1.6, and the CycloneDX line has since moved to 1.7. Conformance to 1.7
is NOT claimed** — nothing here has been run against that revision's schema. Saying 1.7 without
running it would be the same defect this package documents elsewhere: a standards name applied
because the fields look right.

⭐ **One finding came back about the standard rather than about us.** CycloneDX 1.6 declares
`specVersion` as a plain string with `"1.6"` only as an *example* — no `enum`, no `const` — so a
document claiming `specVersion: "9.9"` validates cleanly against the 1.6 schema. **Schema
validation therefore does not establish which specification a document follows**, which is why the
1.6 claim above is asserted separately rather than resting on the validator. ⚠️ **Conformance with the CISA/NIST CBOM minimum elements is deliberately NOT claimed** —
those are due under Executive Order 14412 around March 2027 and are unpublished, so the artifact says
so in its own metadata rather than implying a compliance nobody can currently verify.

**in-toto** wraps the report as a Statement — `subject` with a digest map, plus a versioned
`predicateType`. ⚠️ **It adopts the Statement and not the DSSE envelope, deliberately.** You get
payload interoperability; the signature stays Lamport-Merkle, which is post-quantum by construction
and keeps this package at zero dependencies. **A DSSE verifier can read the subject and predicate but
cannot check the signature, and the statement says so in its own `note` field rather than letting a
tool assume it verified something.** Interoperable at the payload, sovereign at the signature — a
real trade, stated rather than finessed.

```bash
# VEX — is what is present actually exploitable?
python -m entrovouch.cbom /path/to/project --json cbom.json
python -m entrovouch.vex cbom.json --out vex.cdx.json
```

**VEX** is emitted as CycloneDX-native `vulnerabilities` statements and validates
against the same pinned 1.6 schema. ⚠️ **Every statement is `in_triage`, and every
identifier is a `CWE-` weakness class rather than a `CVE-`.** Exploitability is a
property of reachability and static analysis does not establish reachability, so
`exploitable` would claim an analysis that never ran and `not_affected` would clear
a finding on the strength of not having looked. **`in_triage` is the format's own
word for *identified, a human decides*** — `REVIEW means review`, written in a
standard your tooling already parses. There is no CVE data here because this tool
has no vulnerability database and makes no network call to acquire one.

```bash
# RFC 3161 trusted timestamp — a signature proves who and what, never WHEN
python -m entrovouch.timestamp request report.json --out req.tsq
curl -s -H "Content-Type: application/timestamp-query"      --data-binary @req.tsq <your-tsa-url> -o resp.tsr
python -m entrovouch.timestamp check report.json --token resp.tsr
```

⛔ **The middle line is yours, and that is the design.** Fetching a timestamp means
opening a socket, and a tool that acquired a network client to prove it has no
network client would refute itself. **You choose the authority; we never learn who
you asked, because we never ask.**

⚠️ **The check is an imprint match, not a signature verification.** It confirms the
token carries this report's digest — catching a token pasted from a different
document, which is the realistic mistake. It does **not** validate the TSA's
certificate chain, because that would import a trust root this package exists to
avoid. Use `openssl ts -verify` with your TSA's certificate for that half. The
output says which half it did.

### Reproducing a report

Re-run the tool against the same tree and compare **one value**:

```python
from entrovouch.no_egress_auditor import audit
audit(Path("/path/to/project"), label="org/repo@commit").findings_digest
```

**All three digests are printed on the markdown report itself**, each labelled with
whether it reproduces, so a reader holding only the report can do this without
being told which value to trust. **Comparing `content_hash` is the obvious instinct
and the wrong move**: it covers the issuance timestamp and is *expected* to differ on
every run. A different content hash with an identical findings digest is the same
result, issued twice.

`findings_digest` is **bit-identical across runs, processes and machines**. It covers the tool, its version, the subject digest, the verdict and every finding — and deliberately excludes `scanned_at_utc`, which is what lets it reproduce.

Two other values are deliberately *not* reproducible, and the distinction is the point:

| Field | Reproduces? | What it answers |
|---|---|---|
| `findings_digest` | **yes** | *Does this tool, on this tree, still say this?* |
| `subject_digest` | yes, per tree | *Which tree was audited?* |
| `content_hash` | no, by design | *Is this the exact artifact I was handed?* |

`content_hash` covers the timestamp, so a second run produces a different one. That is not a mismatch; it is a different issuance of the same finding.

**`subject_digest` binds the report to the code.** It is an order-independent SHA3-256 over every file the audit actually read. Before this existed, `target` was a free-text label and two entirely different trees could produce byte-identical reports under the same name — a signature over that attests the *sentence*, not the *subject*. The report also carries `subject` in the [in-toto Statement](https://github.com/in-toto/attestation) shape (`{name, digest}`), so the binding is the one supply-chain tooling already knows how to verify.

What the signature *is* good for is checking that a report you were handed is the report that was issued:

```python
from entrovouch.no_egress_auditor import verify_report
import json

ROOT = "…"   # the publisher's public root, obtained out of band
verify_report(json.load(open("report.json")), expected_root=ROOT)
```

The public root is the only thing you need from the publisher, and it is safe to publish and pin once. **Omitting `expected_root` returns `UNVERIFIED`, not `ATTESTED`** — the function will not let you mistake "this is a well-formed signature" for "this came from the party I think it did."

## How it works, and what it will not do

**AST-first, not grep.** All three tools parse the syntax tree. A docstring that *mentions* `requests` does not fire; an actual import or call does. This is the difference between a scanner that is useful and one that cries wolf until it is ignored.

**The CBOM classifies each primitive** as `SAFE` / `GROVER-REDUCED` / `VULNERABLE` / `BROKEN` / `WEAK-RNG` / `REVIEW`, and reports an overall verdict: `QUANTUM-SAFE`, `MIGRATION-NEEDED`, or `BROKEN-CRYPTO`.

**This analyser underapproximates, and that word is the most important one on this page.**

A *sound* analyser overapproximates: it may report egress that cannot happen, but it never misses egress that can. This one does the opposite. It names the network surface it knows and stays silent about the rest, so **a CLEAN result is evidence of absence, not proof of it.**

The blind spots are not only the clever ones. Obfuscation is genuinely undecidable in a Turing-complete language and is disclosed everywhere in this document, but **an ordinary, unobfuscated import of a network module that is not on the list is equally invisible** — no cleverness required. Detection is list-based, and a list is never complete. The list is [`FORBIDDEN_IMPORT_MODULES`](entrovouch/no_egress_auditor.py) and you can read it: judge the coverage yourself rather than taking a claim about it.

That is why the report is called detection-grade evidence and never proof, and why it says so in its own body rather than only here.

### How often is it wrong?

Measured, not asserted. All three tools were run over **20 well-known, permissively-licensed Python
repositories** (requests, flask, pytest, pydantic, httpx, black, typer, attrs, click, tox, isort,
structlog, loguru, tenacity, faker, jsonschema, anyio, more-itertools, python-dotenv, records) on
2026-08-30, and every finding was classified against one question: **can the flagged construct
actually reach the network?**

**All three tools, not one.** The first pass measured only the egress auditor; the other two were
measured afterwards and one of them was far worse.

| Tool | Findings | False positives, first run | After the fix |
|---|---|---|---|
| `no_egress_auditor` | 430 | **32 of 257 judged — 12.5%** | **0** — finding count unchanged |
| `key_provenance` | 23 | 🔴 **16 of 23 — 70%** | **1 arguable of 8** — all 7 true positives kept |
| `cbom` | 90 | 0 against its stated scope | 4 downgraded where the author declared non-security |

**In each tool the false positives were a single defect class, and in each case the fix was
structural rather than a longer exception list.**

- **Egress:** a *pure submodule* of a network-capable package. `from requests.structures import
  CaseInsensitiveDict` tells you `requests` is a dependency; that module is a dict subclass with no
  network code in it. Now reported as `network-dependency` — the evidence survives, the false claim
  does not.
- 🔴 **Key provenance, the worst of the three at 70%:** an uppercase `*_KEY` constant whose *value* is
  an identifier, a dunder or an env-var name — `CONFIGFILE_KEY = 'pydantic-mypy'`, `ROOT_KEY =
  '__root__'`, `ENV_VAR_KEY = "TOX_PARALLEL_ENV"`. **Those are mapping keys, not key material.** The
  rule that produced them judged only the *name*, and only its *suffix*. It never looked at the value.
- **CBOM:** no false positives under its stated scope — it inventories primitives a codebase
  *references* — but it ignored `usedforsecurity=False`, **which is the codebase answering the
  question.** Those are now `REVIEW` rather than `BROKEN`: downgraded, not dropped, because the flag
  is the author's assertion and an assertion is what this package declines to take on trust.

⚠️ **41 of the 90 CBOM components are `random`.** That is accurate and, in a fake-data generator or a
test suite, rarely actionable. **Accuracy and actionability are different properties and this page
will not conflate them.**

### And how often does it MISS?

Precision is the easy half. **Recall against someone actively hiding is the half that
decides whether a clean report means anything**, so it was measured too — 19 fixtures,
each a working egress path, in three tiers.

| Tier | What it represents | Recall |
|---|---|---|
| **A — plain** | a developer not hiding: `import requests`, a lazy import inside a function | **3/3 — 100%** |
| **B — light obfuscation** | avoiding a linter: aliases, `try/except` imports, `importlib` with a literal, split strings, `curl` via `subprocess` | **6/6 — 100%** |
| **C — deliberate evasion** | someone who read this source: `getattr` chains, `ctypes`, `builtins` lookups, char-code module names, spawning the interpreter, vendored copies | 🔴 **2/10 — 20%** |
| | **Overall** | **11/19 — 58%** |

🔴 **20% against a deliberate adversary. That number is the reason this page says
`underapproximates` rather than `proves`.** It is not a bug to be fixed in the next
release; most of tier C is undecidable in a Turing-complete language, and the two
that were caught were caught as `dynamic-exec` — the tool flagged the *mechanism*,
not the payload.

**One tier-C miss looked cheap to fix and was measured instead of assumed.**
`subprocess.run([sys.executable, "-c", "...urlopen..."])` relays through the
interpreter. Adding the interpreter to the network-binary list would catch it — and
`sys.executable` appears **457 times across 247 files** in the 20-repo corpus above,
almost all of them test runners and build scripts. **The fix would have traded one
miss for hundreds of false positives**, so it was not made, and the blind spot is
named here instead.

⚠️ **What these numbers are not.** Precision is measured on mature, well-maintained
libraries; recall is measured against fixtures we wrote, and **an adversary who has
not seen our fixtures may do better than our tier C suggests.** Published work puts
static-analysis tool abandonment at false-positive rates above 20–30%; that is the
bar precision is measured against. The corpus, the date and the method are stated so
you can redo both rather than take either on trust.

**Honest limits — read these before relying on the output:**

- **Static analysis only.** It audits the source you point it at. It does not observe runtime behaviour, and it cannot see egress introduced by a dependency it was not pointed at, by dynamic code loading, or by a compiled extension.
- **Outbound and inbound are different findings.** A listening socket is reported as `inbound-listener`, never as egress. It is not exfiltration, but "on-prem, no telemetry" is a claim a bound port is part of, and omitting it because this tool's name says *egress* would answer the narrow question while missing the one being asked.
- **A clean audit is a statement about a tree at a commit, not a guarantee about a running system.** Time T says nothing about T+1.
- **A signature proves origin and integrity, not correctness.** With a pinned root it proves the report came from that publisher and was not altered. It says nothing about whether the tool's verdict is *right* — and an `UNSIGNED` report proves neither origin nor authorship, only that its bytes match its own digest.
- **`REVIEW` means review.** It is not a pass.

⚠️ **A crypto detector scanning its own source flags its own pattern table.** Running `cbom` on this
repository reports `BROKEN-CRYPTO` because the file containing the string `DES` *is the file that
searches for it*. That is inherent to self-scanning a scanner, not a finding about this codebase —
and it is stated here because the README invites you to run the tools on their own source.

⚠️ **A repo-root no-egress audit reports one finding, and it is deliberate.**
`examples/sample_service/collector.py` contains a real network import so the demo in
`examples/` has something to find. **The shipped package — `entrovouch/` — audits CLEAN**,
and both halves are pinned: one test asserts the package is clean, another asserts that
*every* finding in the whole tree comes from `examples/`, so a real finding cannot hide
behind the scoped one.

⛔ **The auditor was NOT taught to skip `examples/`.** A scanner with a built-in blind spot
for one directory name is precisely the hidden exemption this package argues against, and it
would make the tool lie about anyone else's tree that happened to contain that path. **Scope
the claim, never blind the instrument.**

The tools' own findings on themselves are in the test suite, including a genuine `WEAK-RNG` flag on `random` (Mersenne Twister) that is informational rather than a defect — confirm it never keys material, which in this codebase it does not.

### Exit codes

```
0  clean          no findings
1  findings       the scan ran and found something
2  could not run  bad arguments, unreadable target — NOT a clean result
```

⚠️ **1 and 2 are different answers, and a pipeline that treats them alike will eventually
report a broken scan as a passing one.** Our own artifact-regeneration script got this wrong
on its first run; the fixture caught it in under a minute.

## Signing

**One signer ships: Lamport-Merkle SHA3-256.**

| | Lamport-Merkle SHA3-256 |
|---|---|
| Hardness | SHA3-256 preimage resistance only — no lattice, no number theory |
| Standard claimed | **none** |
| Interoperates | no; it is a construction of our own |
| State | one-time keys, and reuse is catastrophic |
| Signature size | ~16 KB |

It claims conformance to no published standard, which means there is no conformance
test it can fail and no standards name in this repository doing work it cannot
support. **That is a deliberate position rather than a limitation we are working
around:** a signature you can check against our published root is worth more than a
standards label you would have to take on trust.

⚠️ **What a signature does and does not tell you.** With the root below pinned, it
proves the report came from the holder of that key and that its bytes are unaltered.
It says nothing about whether the tool's verdict is *correct*. An `UNSIGNED` report
proves neither origin nor authorship — only that its bytes match its own digest.

⚠️ **The keys are one-time.** Each signature consumes a leaf. Reusing one destroys the
security of the scheme, so the index is persisted before the secret is revealed rather
than after.

### The publisher's public root

```
eb309717634b3a9bd952aac903538bd9b3350d1b006f5176d1c87763ba87a96b
```

Pin this value out of band — from a source you trust more than
a file in the repository you are auditing — and pass it as `expected_root`:

```python
from entrovouch.no_egress_auditor import verify_report
ok, status = verify_report(report, expected_root="eb309717…")
# ("ATTESTED", True) only if this report came from the holder of that root
```

**`ok` is `True` for `ATTESTED` and nothing else.** Not for `UNSIGNED`, not for `UNVERIFIED`.
A report you did not pin a root for is not evidence of origin, and the function says so
rather than letting a caller who checks the boolean assume otherwise.

⚠️ **A root published here is a weaker pin than one you obtain independently.** Anyone who
can alter this repository can alter this line, so treat it as a convenience, not a root of
trust — the reproduction check above does not depend on it, which is deliberate.

**The algorithm name and the public root are inside the signed bytes**, so editing
either field yields `TAMPERED`. This matters more than it sounds: the displayed
algorithm is exactly what a counterparty reads to substantiate a post-quantum
claim, and an unauthenticated one is worse than none — it would let a report
display a standards claim it does not carry and still verify as genuine.

> ⚠️ **Reports issued before 2026-08-20 carry integrity evidence only and must not be relied upon as evidence of origin.** This includes any report delivered on 2026-07-31 or 2026-08-12. Verification is fail-closed: an `UNSIGNED` report proves that its bytes match its own digest and nothing more. Re-run the audit yourself against the current release rather than relying on an older artifact.


## Independently issued audits

The tools, the module lists and the signing capability on this page are free, complete and
identical for everyone. What cannot be self-served is independence: an audit you run on your
own code is not an audit anyone else can rely on. **Independent third-party issuance,
classification of findings, and scheduled re-issuance: [entroverse.com](https://entroverse.com).**

## License

See `LICENSE`.

---

*Prevention over detection. For the People.*

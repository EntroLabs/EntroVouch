# CONFORMANCE: what this project claims about the standards it names

**Last verified 2026-10-02.** Regenerate when the answers change.

> **Naming a standard is a CHECKABLE claim.** A hostile reader can test it in an afternoon
> using free published vectors, which makes it among the first things checked and the most
> damaging to get wrong. So every standard named anywhere in this project is listed below with
> what actually backs it: a test, or an explicit statement that conformance is not claimed.
>
> **Self-consistency is not conformance.** An implementation can be internally coherent,
> pass every test its own authors thought to write, and still interoperate with nothing -
> matching parameters do not make a matching construction. Only an external reference tells
> the two apart, so every claim below names the reference that backs it.

## Standards named in this project

### CycloneDX 1.6

**VALIDATED when the suite runs with `jsonschema` installed** (`pip install -e .[test]`;
a clean clone skips the schema tests rather than failing). `entrovouch/cyclonedx.py` output
validates against the official `bom-1.6.schema.json` with **zero errors**. The schema file is pinned by hash, and the
validator was negative-tested against six deliberately malformed documents before its
zero was believed. Test: `tests/test_cyclonedx_schema.py`.

**Conformance to CycloneDX 1.7 is NOT claimed**: nothing here has been run against that
revision's schema. 1.7 is the CBOM-shaped revision (certificates, protocols, algorithm
family). This emitter still writes `assetType: algorithm` only.

**A finding about the standard rather than about us:** CycloneDX 1.6 declares `specVersion` as
a plain string with `"1.6"` only as an *example*: no `enum`, no `const`: so a document claiming
`specVersion: "9.9"` validates cleanly against the 1.6 schema. **Schema validation does not
establish which specification a document follows**, so the 1.6 claim above is asserted separately
rather than resting on the validator.

<sub>Named in: `README.md`, `docs/ADAPTERS.md`, `docs/TOOLS.md`, `entrovouch/cyclonedx.py`, `entrovouch/sbom.py`, `entrovouch/vex.py`</sub>


### SARIF 2.1.0

**VALIDATED when the suite runs with `jsonschema` installed.** Output validates against the
official OASIS `sarif-2.1.0.schema.json` (vendored, pinned by SHA-256). The validator was negative-tested against six malformed
documents, including a wrong `version` value: SARIF, unlike CycloneDX 1.6, *does* constrain
its own version field, so passing the schema establishes 2.1.0. Test:
`tests/test_sarif_schema.py`. `jsonschema` is test-only; the runtime stays standard library.

<sub>Named in: `README.md`, `docs/ADAPTERS.md`, `entrovouch/sarif.py`</sub>


### in-toto Statement

**STATEMENT SHAPE ADOPTED, DSSE ENVELOPE DECLINED: deliberately.** The payload uses the
in-toto Statement shape (`subject` + typed `predicateType`); signatures are not DSSE, so a DSSE
verifier **cannot** check them and must treat them as *unverified rather than absent*. The
statement says so in its own `note` field rather than letting a tool assume it verified
something. Interoperable at the payload, sovereign at the signature: a real trade, stated
rather than finessed.

<sub>Named in: `README.md`, `docs/ADAPTERS.md`, `entrovouch/attestation.py`, `pyproject.toml`</sub>


### RFC 3161 (trusted timestamps)

**REQUEST AND IMPRINT CHECK ONLY: TSA SIGNATURE NOT VERIFIED.**
`entrovouch/timestamp.py` builds a timestamp query and checks that a returned token carries
this report's digest. It does **not** validate the TSA's CMS/X.509 chain, because that would
import a trust root this package exists to avoid. The middle hop (sending the query) is the
operator's, because a tool that opened a socket to prove it has no socket would refute itself.
Test: `tests/test_timestamp_and_vex.py`. Use `openssl ts -verify` for the other half.

<sub>Named in: `README.md`, `docs/ADAPTERS.md`, `entrovouch/timestamp.py`</sub>


### VEX (CycloneDX-native)

**SHAPE TARGETED, STATES ONLY `in_triage`, IDENTIFIERS ONLY `CWE-`.** Output is CycloneDX
`vulnerabilities` against the same pinned 1.6 schema. Every statement is `in_triage` because
exploitability is reachability and this analyser does not establish reachability.
`exploitable` would claim an analysis that never ran; `not_affected` would clear a finding on
the strength of not having looked. Identifiers are weakness classes (`CWE-327`, `CWE-338`,
`CWE-798`), never `CVE-`: this tool has no vulnerability database. Test:
`tests/test_timestamp_and_vex.py`.

<sub>Named in: `README.md`, `docs/ADAPTERS.md`, `entrovouch/vex.py`</sub>


### CSAF 2.0 (VEX profile)

**SCHEMA VALIDATED. MANDATORY TESTS ASSERTED ONE BY ONE, NO CONFORMANCE CHECKER RUN.**
`entrovouch/csaf.py` writes a `csaf_vex` document carrying the same statements as the
CycloneDX VEX output. It is validated by a test against the CSAF 2.0 JSON schema published by
OASIS, pinned by hash in `tests/schemas/csaf-2.0.schema.json`. The standard's section 6.1
lists mandatory tests a schema cannot express; the ones this output could break are asserted
by name in `tests/test_csaf.py` (6.1.1 product ids defined, 6.1.11 CWE names, 6.1.16 and
6.1.18 version and revision history, 6.1.27 the VEX profile's status and identifier rules).
No CSAF validator service was run against it, and the CVSS and PURL tests do not apply
because neither is written. Every status is `under_investigation` and every identifier is a
`CWE-` class, for the reasons given under VEX above; no statement names a `CVE-`. The
publisher name and namespace are required arguments and are never filled in. The file name
CSAF derives from the tracking id is printed, not enforced.

<sub>Named in: `README.md`, `docs/ADAPTERS.md`, `entrovouch/csaf.py`</sub>


### Lamport-Merkle SHA3-256 (this package's signer)

**NOT A PUBLISHED STANDARD: deliberately.** The construction is hash-based one-time
signatures committed into a Merkle tree, with RFC 6962 domain tags and reserve-then-sign
state. It claims conformance to no FIPS, no RFC 8554/LMS, no RFC 8391/XMSS, and no FIPS 205
SLH-DSA. There is therefore no official vector set it can fail, and no standards name in this
repository doing work the tests cannot support.

**NIST SP 800-208 is NOT met, and cannot be by a file.** SP 800-208 requires a stateful
hash-based key to be generated and held in a hardware cryptographic module, the leaf index to
be stored before a signature leaves the module, and the private key never to be exported. This
signer does the second (the index is written and synced to disk before the signature is
returned) and not the first or third: the key is a file an operator can copy. A copied or
restored key file can reuse a one-time leaf, and nothing in a signature reveals it. The
`--advance-key` option exists for that case and does not remove it. Tests: `tests/test_signer.py`,
`tests/test_signature_fail_closed.py`, `tests/test_signed_reports.py`.

<sub>Named in: `README.md`, `docs/SIGNING.md`, `entrovouch/signer.py`</sub>


### FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA)

**DETECTOR TOKENS ONLY.** `cbom.py` recognises these names in *other people's* source so a
PQC inventory can see them. This package's own signer is not any of them, and no FIPS KAT is
run here. Naming them as *our* signature algorithm is not claimed.

<sub>Named in: `entrovouch/cbom.py`</sub>


### CISA 2026 Minimum Elements for an SBOM

**EMITTED AS A SOURCE-MANIFEST SBOM; CONFORMANCE NOT CLAIMED.**
`python -m entrovouch.sbom` writes CycloneDX 1.6 (`library` components) from declared
top-level dependencies. Generation context is `pre-build`. Tool name and version,
timestamp, data format and format version are filled. The SBOM author is not: the tool cannot
know who runs it, so naming the author is left to whoever issues the document. Component
hash of an executable artifact, licenses, producers and transitives are labelled
**unknown-to-author**, not withheld. CISA 2026 *Coverage* requires all components
including transitives with no minimum depth: a manifest parser cannot satisfy that, so
conformance is not claimed. Test: `tests/test_sbom.py`; schema:
`tests/test_cyclonedx_schema.py::test_sbom_output_validates`.

<sub>Named in: `docs/TOOLS.md`, `entrovouch/sbom.py`</sub>


### CISA / NIST CBOM minimum elements (EO 14412 §5(d))

**NOT CLAIMED.** Due under Executive Order 14412 around March 2027 and currently unpublished.
The artifact says so in its own metadata rather than implying a compliance nobody can verify.

<sub>Named in: `entrovouch/cyclonedx.py`</sub>

---

## What this file does and does not do

- It states, per standard, what backs the name where this project uses it.
- **It does not make any of them conformant.** Where it says NOT VALIDATED or NOT CLAIMED,
  that is the current state and the work is unbuilt.
- **Every path above is inside this repository.** A conformance document that cites
  measurements its reader cannot open is asking to be taken on trust, in a package whose whole
  argument is that you should not have to. Anything not reproducible from this checkout is not
  cited here.

Checked by `tests/test_conformance_claims.py`: every standard named here must carry either a
conformance test against that standard's own schema or vectors, or a stated disclaimer. There
is no third option.

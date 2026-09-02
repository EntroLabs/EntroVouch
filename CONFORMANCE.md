# CONFORMANCE — what this project claims about the standards it names

**Last verified 2026-09-01.** Regenerate when the answers change.

> ⭐ **Naming a standard is a CHECKABLE claim.** A hostile reader can test it in an afternoon
> using free published vectors, which makes it among the first things checked and the most
> damaging to get wrong. So every standard named anywhere in this project is listed below with
> what actually backs it — a test, or an explicit statement that conformance is not claimed.
>
> 🔴 **Self-consistency is not conformance.** An implementation can be internally coherent,
> pass every test its own authors thought to write, and still interoperate with nothing —
> matching parameters do not make a matching construction. Only an external reference tells
> the two apart, so every claim below names the reference that backs it.

## Standards named in this project

### CycloneDX 1.6

✅ **VALIDATED.** `entrovouch/cyclonedx.py` output validates against the official
`bom-1.6.schema.json` with **zero errors**. The schema file is pinned by hash, and the
validator was negative-tested against six deliberately malformed documents before its
zero was believed. Test: `tests/test_cyclonedx_schema.py`.

⚠️ **Conformance to CycloneDX 1.7 is NOT claimed** — nothing here has been run against that
revision's schema. 1.7 is the CBOM-shaped revision (certificates, protocols, algorithm
family). This emitter still writes `assetType: algorithm` only.

⭐ **A finding about the standard rather than about us:** CycloneDX 1.6 declares `specVersion` as
a plain string with `"1.6"` only as an *example* — no `enum`, no `const` — so a document claiming
`specVersion: "9.9"` validates cleanly against the 1.6 schema. **Schema validation does not
establish which specification a document follows**, so the 1.6 claim above is asserted separately
rather than resting on the validator.

<sub>Named in: `README.md`, `entrovouch/cyclonedx.py`, `pyproject.toml`</sub>


### SARIF 2.1.0

✅ **VALIDATED.** Output validates against the official OASIS `sarif-2.1.0.schema.json`
(vendored, pinned by SHA-256). The validator was negative-tested against six malformed
documents, including a wrong `version` value — SARIF, unlike CycloneDX 1.6, *does* constrain
its own version field, so passing the schema establishes 2.1.0. Test:
`tests/test_sarif_schema.py`. `jsonschema` is test-only; the runtime stays standard library.

<sub>Named in: `README.md`, `entrovouch/sarif.py`, `pyproject.toml`</sub>


### in-toto Statement

⚠️ **STATEMENT SHAPE ADOPTED, DSSE ENVELOPE DECLINED — deliberately.** The payload uses the
in-toto Statement shape (`subject` + typed `predicateType`); signatures are not DSSE, so a DSSE
verifier **cannot** check them and must treat them as *unverified rather than absent*. The
statement says so in its own `note` field rather than letting a tool assume it verified
something. Interoperable at the payload, sovereign at the signature — a real trade, stated
rather than finessed.

<sub>Named in: `README.md`, `entrovouch/attestation.py`, `pyproject.toml`</sub>


### RFC 3161 (trusted timestamps)

⚠️ **REQUEST AND IMPRINT CHECK ONLY — TSA SIGNATURE NOT VERIFIED.**
`entrovouch/timestamp.py` builds a timestamp query and checks that a returned token carries
this report's digest. It does **not** validate the TSA's CMS/X.509 chain, because that would
import a trust root this package exists to avoid. The middle hop (sending the query) is the
operator's, because a tool that opened a socket to prove it has no socket would refute itself.
Test: `tests/test_timestamp_and_vex.py`. Use `openssl ts -verify` for the other half.

<sub>Named in: `README.md`, `entrovouch/timestamp.py`</sub>


### VEX (CycloneDX-native)

⚠️ **SHAPE TARGETED, STATES ONLY `in_triage`, IDENTIFIERS ONLY `CWE-`.** Output is CycloneDX
`vulnerabilities` against the same pinned 1.6 schema. Every statement is `in_triage` because
exploitability is reachability and this analyser does not establish reachability.
`exploitable` would claim an analysis that never ran; `not_affected` would clear a finding on
the strength of not having looked. Identifiers are weakness classes (`CWE-327`, `CWE-338`,
`CWE-798`), never `CVE-`: this tool has no vulnerability database. Test:
`tests/test_timestamp_and_vex.py`.

<sub>Named in: `README.md`, `entrovouch/vex.py`</sub>


### Lamport-Merkle SHA3-256 (this package's signer)

⚠️ **NOT A PUBLISHED STANDARD — deliberately.** The construction is hash-based one-time
signatures committed into a Merkle tree, with RFC 6962 domain tags and reserve-then-sign
state. It claims conformance to no FIPS, no RFC 8554/LMS, no RFC 8391/XMSS, and no FIPS 205
SLH-DSA. There is therefore no official vector set it can fail, and no standards name in this
repository doing work the tests cannot support. Tests: `tests/test_signer.py`,
`tests/test_signature_fail_closed.py`, `tests/test_signed_reports.py`.

<sub>Named in: `README.md`, `entrovouch/signer.py`</sub>


### FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA)

⚠️ **DETECTOR TOKENS ONLY.** `cbom.py` recognises these names in *other people's* source so a
PQC inventory can see them. This package's own signer is not any of them, and no FIPS KAT is
run here. Naming them as *our* signature algorithm is not claimed.

<sub>Named in: `entrovouch/cbom.py`</sub>


### CISA 2026 Minimum Elements for an SBOM

⚠️ **EMITTED AS A SOURCE-MANIFEST SBOM; CONFORMANCE NOT CLAIMED.**
`python -m entrovouch.sbom` writes CycloneDX 1.6 (`library` components) from declared
top-level dependencies. Generation context is `pre-build`. Tool name and version, SBOM
author (the runner), timestamp, data format and format version are filled. Component
hash of an executable artifact, licenses, producers and transitives are labelled
**unknown-to-author**, not withheld. CISA 2026 *Coverage* requires all components
including transitives with no minimum depth — a manifest parser cannot satisfy that, so
conformance is not claimed. Test: `tests/test_sbom.py`; schema:
`tests/test_cyclonedx_schema.py::test_sbom_output_validates`.

<sub>Named in: `README.md`, `entrovouch/sbom.py`</sub>


### CISA / NIST CBOM minimum elements (EO 14412 §5(d))

⚠️ **NOT CLAIMED.** Due under Executive Order 14412 around March 2027 and currently unpublished.
The artifact says so in its own metadata rather than implying a compliance nobody can verify.

<sub>Named in: `README.md`, `entrovouch/cbom.py`, `entrovouch/cyclonedx.py`</sub>

---

## What this file does and does not do

- ✅ It states, per standard, what backs the name where this project uses it.
- ⛔ **It does not make any of them conformant.** Where it says NOT VALIDATED or NOT CLAIMED,
  that is the current state and the work is unbuilt.
- ⚠️ **Every path above is inside this repository.** An earlier revision of this file cited
  measurements in sibling projects that a reader of this repository cannot open — which is a
  conformance document asking to be taken on trust, in a package whose whole argument is that you
  should not have to. Anything not reproducible from this checkout is not cited here.

Checked by `tests/test_conformance_claims.py`: every standard named here must carry either a
conformance test against that standard's own schema or vectors, or a stated disclaimer. There
is no third option.

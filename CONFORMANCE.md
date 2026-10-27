# CONFORMANCE: what this project claims about the standards it names

**Last verified 2026-10-24.** Regenerate when the answers change.

> **Naming a standard is a CHECKABLE claim.** A hostile reader can test it in an afternoon
> using free published vectors. So every standard this project's output or signer follows is listed below
> with what actually backs it: a test, or an explicit statement that conformance is not claimed.
> Standards and regulations the documentation only cites are listed at the end, under "Cited, not
> followed".
>
> **Self-consistency is not conformance.** An implementation can be internally coherent,
> pass every test its own authors thought to write, and still interoperate with nothing:
> matching parameters do not make a matching construction. Only an external reference tells
> the two apart, so every claim below names the reference that backs it.

## Standards named in this project

### CycloneDX 1.6

**VALIDATED when the suite runs with `jsonschema` installed** (`pip install -e .[test]`;
a clean clone skips the schema tests rather than failing). `entrovouch/cyclonedx.py` output
validates against the official `bom-1.6.schema.json` with **zero errors**. The schema file is pinned by a 64-bit prefix of
its SHA-256, and the test also runs the validator against six deliberately malformed documents, which
it must reject. Test: `tests/test_cyclonedx_schema.py`.

**Conformance to CycloneDX 1.7 is NOT claimed**: nothing here has been run against that
revision's schema. 1.7 (ECMA-424, 2nd edition) adds a standard list of algorithm families and
elliptic curves for cryptographic assets. This emitter writes `assetType: algorithm` only, because the
tool finds algorithms, not certificates or protocols.

The CycloneDX 1.6 schema itself declares `specVersion` as
a plain string with `"1.6"` only as an *example* (no `enum`, no `const`), so a document claiming
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
something.

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

**SCHEMA VALIDATED WHEN `jsonschema` IS INSTALLED (A CLEAN CLONE SKIPS IT). MANDATORY TESTS ASSERTED ONE BY ONE, NO CONFORMANCE CHECKER RUN.**
`entrovouch/csaf.py` writes a `csaf_vex` document carrying the same statements as the
CycloneDX VEX output. It is validated by a test against the CSAF 2.0 JSON schema published by
OASIS, `tests/schemas/csaf-2.0.schema.json`, pinned in `tests/test_csaf.py` by a 64-bit prefix of its SHA-256. The standard's section 6.1
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


### RFC 8554 and RFC 9858 (LMS and HSS hash-based signatures)

**VERIFIED, FOR THE PARAMETER SETS THOSE VECTORS COVER, AGAINST THE PUBLISHED TEST VECTORS OF RFC 8554 AND RFC 9858
AND THE 8 LMS SIGVER VECTORS NIST PUBLISHES IN ACVP-SERVER (SHA-256/192 ONLY).**
**NOT CAVP-VALIDATED; NO CAVP OR CMVP VALIDATION AGAINST NIST SP 800-208 HAS BEEN RUN. IT DOES NOT SIGN REPORTS.**
`entrovouch/lms.py` verifies LMS and HSS signatures for the SHA-256 parameter sets RFC 8554 defines (LM-OTS W1, W2,
W4 and W8; LMS heights 5, 10, 15, 20 and 25) and for the parameter sets RFC 9858 adds (SHA-256/192, SHAKE256/256 and
SHAKE256/192, the same W values and heights), and signs with an LMS key derived from a seed as RFC 8554 Appendix A
describes (the RFC 8554 SHA-256 sets, heights 5 and 10; the RFC 9858 sets are verified only). The verifier refuses a
public key whose tree and one-time key types use different hashes. Both test cases of RFC 8554 Appendix F verify;
test case 2 is reproduced byte for byte from the private keys the appendix gives, with its published randomizers; and
a test flips the low bit of each byte of each published public key and message, one byte at a time, and of a sample
of signature bytes (each of the first 16 and the last 16, and every 13th), and asserts that every such change fails
verification. The vectors are in `tests/vectors/rfc8554_appendix_f.json`,
transcribed from Appendix F. Test: `tests/test_lms_rfc8554.py`. Appendix F covers heights 5 and 10 with W4 and W8 only:
no published vector has been run for the RFC 8554 sets at heights 15, 20 or 25, or at W1 or W2.

All 4 test cases of RFC 9858 Appendix A verify: A.1, `LMS_SHA256_M24_H5` with `LMOTS_SHA256_N24_W8`; A.2,
`LMS_SHAKE_M24_H5` with `LMOTS_SHAKE_N24_W8`; A.3, `LMS_SHAKE_M32_H5` with `LMOTS_SHAKE_N32_W8`; A.4,
`LMS_SHA256_M24_H20` with `LMOTS_SHA256_N24_W4`. That is at least one case for each hash RFC 9858 adds
(SHA-256/192, SHAKE256/192 and SHAKE256/256). A test flips the low bit of each byte of each published public key and
message, one byte at a time, and of a sample of signature bytes (each of the first 16 and the last 16, and every
11th), and asserts that every such change fails verification. The appendix gives each case's private key, but this module does not sign with the RFC 9858 sets,
so the published signatures are verified, not reproduced. The vectors are in `tests/vectors/rfc9858_test_cases.json`,
transcribed from the RFC text (https://www.rfc-editor.org/rfc/rfc9858.txt). Test: `tests/test_lms_rfc9858.py`. No
published vector has been run for an RFC 9858 parameter set other than these four and the two ACVP sets below.

It gives the published answer on all 8 LMS sigVer vectors NIST publishes in its ACVP-Server repository
(`gen-val/json-files/LMS-sigVer-1.0/internalProjection.json` at commit `2972def23bf9f3680c2c531561ed9bdd0f1086ad`,
vendored unchanged as `tests/vectors/acvp_lms_sigver_1_0_internalProjection.json` and pinned by SHA-256). They cover
two SHA-256/192 sets, `LMS_SHA256_M24_H5` with `LMOTS_SHA256_N24_W1` and `LMS_SHA256_M24_H10` with
`LMOTS_SHA256_N24_W2`, and only 2 of the 8 are valid signatures, so the test also asserts that both of those verify:
a verifier that refused everything would agree with 6 of 8. Running NIST's published vectors is not CAVP validation,
and no CAVP validation has been run. Test: `tests/test_lms_acvp.py`.

SP 800-208 permits LMS signing only inside a hardware cryptographic module that keeps the state and never exports
the key. This module keeps its state in a file: it writes the next unused leaf before a signature is computed and
refuses a used leaf, and a state file that moved backwards while the key is loaded, but a copied or restored file can
still bring a used leaf back. No CAVP or other validation has been run. Reports are signed with the Lamport-Merkle
construction above, which claims conformance to no standard, and nothing in the report format uses this module.

<sub>Named in: `README.md`, `entrovouch/lms.py`, `docs/SIGNING.md`</sub>


### C2SP tlog-tiles, tlog-checkpoint and signed-note; RFC 9162 Merkle trees

**TREE HASHES CHECKED AGAINST PUBLISHED TEST ROOTS. NO PUBLISHED PROOF VECTORS OR CONFORMANCE SUITE RUN. A
SIGNED-NOTE CLIENT THAT DOES NOT IMPLEMENT THIS SIGNATURE TYPE REJECTS THE CHECKPOINTS (FROM THE SPECIFICATION, NOT
TESTED).** `entrovouch/tlog.py` keeps the issuance log. Its tree is hashed as RFC 9162 Section 2.1.1 defines. Its
inclusion proofs are generated and verified as Section 2.1.3 describes, and its consistency proofs as Section 2.1.4
describes for 0 < old size < new size; at the boundaries (equal sizes, an old size of 0), where Section 2.1.4 defines
no proof, the rules are the ones the `verify_consistency` docstring states. The roots it computes for trees of 1 to 8
entries equal the RFC 6962 test roots the transparency-dev Merkle library publishes in `testonly/constants.go`, as of
commit `77f1b57d7aa25fcd2e51273166b6b2b0e74923b1` (2022-04-25, the file's last change; read 2026-10-17), and the empty
tree's root is SHA-256 of the empty string as Section 2.1.1 defines it. No published inclusion or consistency proof
vectors have been run: every proof for every index at every size from 1 to 300 and for every pair of sizes up to 40
is compared with a reference written in the test from the RFC's definitions, and proofs for trees of up to 8 entries
are also verified against the published roots. The directory follows C2SP tlog-tiles (tiles of height 8, the
`x`-prefixed path groups, partial tiles at `.p/<W>`, entry bundles with big-endian uint16 length prefixes) and the
checkpoint follows C2SP tlog-checkpoint and signed-note. No conformance suite for any C2SP specification has been
run. Test: `tests/test_tlog.py`.

The checkpoint is signed with this package's signer, which claims conformance to no standard. signed-note reserves the
signature type byte 0xff for types it assigns no identifier and recommends following it with a longer identifier
unlikely to collide; this key is 0xff followed by a 32-byte algorithm identifier. signed-note defines key encodings
only for its own types, requires verifiers to ignore signatures from unknown keys, and requires a client to reject a
note on which no signature from a known key verifies. So a signed-note client that does not implement this signature
type cannot be given this key, ignores the signature, and rejects the checkpoint. This follows from the signed-note
rules (c2sp.org/signed-note, read 2026-10-17); no such client was run. Checking these checkpoints needs this tool.

<sub>Named in: `README.md`, `entrovouch/tlog.py`, `docs/SIGNING.md`</sub>


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


### Package URL (purl)

**FORM TESTED; THE SPECIFICATION'S OWN TEST SUITE IS NOT RUN.** `sbom` writes each component's identifier as a
package URL (`pkg:pypi/...`, `pkg:npm/...`, `pkg:conda/...`), each name written as the purl rule for its
type says: PyPI names lowercased with `_` as `-`, npm names lowercased with a scope as `%40scope`, conda names
lowercased and otherwise as declared, with a channel written `channel::name` kept as the `channel` qualifier
(`pkg:conda/numpy@1.26.4?channel=conda-forge`). The tests check identifiers of all three types; the
purl project's published test data is not run, so conformance is not claimed.

<sub>Named in: `entrovouch/sbom.py`, `docs/WHAT_IS_READ.md`</sub>

---

## What this file does and does not do

- It states, per standard, what backs the name where this project uses it.
- **It does not make any of them conformant.** Where it says NOT CLAIMED, that is the current
  state and the work is unbuilt.
- **Every path above is inside this repository**, so every measurement cited here can be re-run
  from this checkout; nothing that cannot be is cited.

Checked by `tests/test_conformance_claims.py` for the twelve sections it names: for each, that every file its "Named
in" line points to names the standard; for eleven of them (all but in-toto Statement), that they carry their status
words (VALIDATED, NOT CLAIMED, DETECTOR TOKENS ONLY and the rest); and for CSAF and RFC 9858 that the named test file
exists. Nothing in it checks that a section's test passes, and a section added later, or a standard newly named in
the code, is not checked by it; keeping this file right is part of review. The RFC 8554 and RFC 9858 section is also
checked by `tests/test_lms_rfc8554.py`.

## Cited, not followed

These are named in the documentation or the code to explain a scope or a detection. None is a
conformance claim.

- **FIPS 206 (FN-DSA).** A detector token in `cbom`, like FIPS 203 to 205. The standard was not
  final as of 2026-10-09.
- **Regulation (EU) 2024/2847, the Cyber Resilience Act.** Cited for the scope of the SBOM it asks
  for (Annex I Part II(1)): at least the top-level dependencies, from 11 December 2027. `sbom` is built
  to that scope, for declared dependencies only, before any build. No presumption of conformity is claimed; the
  harmonised standards were still in draft as of 2026-10-09.
- **ISAE 3000 and SSAE 18.** Cited to say what kind of assurance a result is. EntroVerse is not an
  audit firm, and running these tools is not an engagement under either standard.
- **PEP 621 and PEP 440.** PEP 621 says where `pyproject.toml` declares dependencies, one of the places where
  `sbom` and the auditor read them; PEP 440 gives the normal form of a version written into a
  package URL.
- **PEP 578 (audit hooks).** Used by `tests/test_runtime_oracle.py` as an independent oracle.
- **RFC 6962 domain tags.** Borrowed by the signer's Merkle tree (see its section); RFC 6962 itself
  is not implemented.

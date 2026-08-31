# CONFORMANCE — what this project claims about the standards it names

**Last verified 2026-08-30.** Regenerate when the answers change.

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
`bom-1.6.schema.json` with **zero errors over 163 components**. The schema file is pinned by
hash, and the validator was negative-tested against six deliberately malformed documents before
its zero was believed. Test: `tests/test_cyclonedx_schema.py`.

⚠️ **Conformance to CycloneDX 1.7 is NOT claimed** — nothing here has been run against that
revision's schema.

⭐ **A finding about the standard rather than about us:** CycloneDX 1.6 declares `specVersion` as
a plain string with `"1.6"` only as an *example* — no `enum`, no `const` — so a document claiming
`specVersion: "9.9"` validates cleanly against the 1.6 schema. **Schema validation does not
establish which specification a document follows**, so the 1.6 claim above is asserted separately
rather than resting on the validator.

<sub>Named in: `README.md`, `entrovouch/cyclonedx.py`, `pyproject.toml`</sub>


### SARIF 2.1.0

⚠️ **SHAPE TARGETED, SCHEMA NOT VALIDATED.** Output is written to the SARIF 2.1.0 shape and is
ingested by GitHub code scanning in practice, but no test validates it against the published
OASIS JSON schema. Conformance is not claimed.

<sub>Named in: `README.md`, `entrovouch/sarif.py`, `pyproject.toml`</sub>

### in-toto Statement

⚠️ **STATEMENT SHAPE ADOPTED, DSSE ENVELOPE DECLINED — deliberately.** The payload uses the
in-toto Statement shape (`subject` + typed `predicateType`); signatures are not DSSE, so a DSSE
verifier **cannot** check them and must treat them as *unverified rather than absent*. The
statement says so in its own `note` field rather than letting a tool assume it verified
something. Interoperable at the payload, sovereign at the signature — a real trade, stated
rather than finessed.

<sub>Named in: `README.md`, `entrovouch/attestation.py`, `pyproject.toml`</sub>

### CISA / NIST CBOM minimum elements

⚠️ **NOT CLAIMED.** Due under Executive Order 14412 around March 2027 and currently unpublished.
The artifact says so in its own metadata rather than implying a compliance nobody can verify.

<sub>Named in: `README.md`, `entrovouch/cbom.py`</sub>

---

## What this file does and does not do

- ✅ It states, per standard, what backs the name where this project uses it.
- ⛔ **It does not make any of them conformant.** Where it says NOT VALIDATED or NOT CONFORMANT,
  that is the current state and the work is unbuilt.
- ⚠️ **Every path above is inside this repository.** An earlier revision of this file cited
  measurements in sibling projects that a reader of this repository cannot open — which is a
  conformance document asking to be taken on trust, in a package whose whole argument is that you
  should not have to. Anything not reproducible from this checkout is not cited here.

Checked by an automated standards-claim scan: every file naming a standard must carry either a
conformance test against that standard's own vectors, or a stated disclaimer. There is no third
option.

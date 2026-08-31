"""CycloneDX output validated against the OFFICIAL published schema.

Until 2026-08-22 this project emitted CycloneDX 1.6 and had never once checked
the output against the schema CycloneDX publishes. Everything that existed was
internal: our generator, our expectations, our fixtures. **Self-consistency is
not conformance** — the estate measured the cost of that assumption the day
before, when a hand-rolled ML-DSA signer with every parameter correct turned out
to accept 0 of 79 official vectors.

⭐ **RESULT: 0 schema errors, first run** (163 components on 2026-08-22; the count drifts as
files are added to this repo — the zero is the claim, not the count). The generator was
right. That is worth stating plainly — the discipline is not premised on always
finding something.

🔴 **BUT THE VALIDATOR FOUND A HOLE IN THE STANDARD'S OWN SCHEMA, AND IT MATTERS**
--------------------------------------------------------------------------------
`bom-1.6.schema.json` declares:

    "specVersion": {"type": "string", "examples": ["1.6"]}

**No `enum`. No `const`.** So a document declaring `specVersion: "9.9"` validates
cleanly against the 1.6 schema — verified here, not assumed.

⭐ **The single field that says which specification applies is the field that
specification's own schema does not constrain.** Passing `bom-1.6.schema.json`
therefore does NOT establish that a document is CycloneDX 1.6. A consumer must
check the version itself, and so must we — `test_spec_version_is_ours_to_check`
below exists precisely because the external reference cannot do it.

⚠️ **The general form, which is the reusable part: an external reference is
NECESSARY and is not automatically SUFFICIENT.** Measured twice in two days —
here, and in ENTROAUTH, where dropping the FIPS 204 context moved the official
Wycheproof corpus by only 2 cases out of 210. **Adopting an external oracle is
the beginning of the check, not the end of it.**

DEPENDENCY NOTE
---------------
`jsonschema` is **test-only**. ENTROVOUCH's runtime stays pure standard library,
which is a property a reader can verify rather than a claim they must accept.

⛔ And the validator is not hand-rolled, deliberately: a bespoke schema checker
could be wrong in the same direction as the generator it checks — the same
reasoning that made `serde_json` a test-only dependency in ENTROAUTH_RS.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

import entrovouch as ev

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
BOM_SCHEMA = SCHEMA_DIR / "bom-1.6.schema.json"

#: Pinned so a schema file cannot be swapped, corrupted or silently upgraded
#: without a test saying so. A conformance harness whose reference can change
#: underneath it is measuring something it cannot name.
SCHEMA_SHA256 = {
    "bom-1.6.schema.json": "18f57f7482593bad",
    "spdx.schema.json": "ea6e844ee6fba1e9",
    "jsf-0.82.schema.json": "8bae002c25e723db",
}

jsonschema = pytest.importorskip(
    "jsonschema",
    reason="test-only dependency; pip install jsonschema. The RUNTIME stays "
           "pure stdlib — this is not needed to use ENTROVOUCH.",
)


def _validator():
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    docs = {n: json.loads((SCHEMA_DIR / n).read_text(encoding="utf-8"))
            for n in SCHEMA_SHA256}
    registry = Registry().with_resources(
        [(d["$id"], Resource.from_contents(d, default_specification=DRAFT7))
         for d in docs.values()])
    return Draft7Validator(docs["bom-1.6.schema.json"], registry=registry)


def _bom(target: str = "."):
    return ev.to_cyclonedx(dataclasses.asdict(ev.build_cbom(target)))


def test_schema_files_are_the_ones_we_pinned():
    """⚠️ The reference must not move without a test noticing."""
    for name, prefix in SCHEMA_SHA256.items():
        p = SCHEMA_DIR / name
        assert p.is_file(), f"{name} missing — re-fetch from the CycloneDX spec repo"
        got = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
        assert got == prefix, (
            f"{name} changed: {got} != {prefix}. If this is a deliberate schema "
            "update, re-run the negative tests below before trusting the new one."
        )


def test_our_real_output_validates():
    """The claim the CBOM is sold on, checked against the published schema."""
    bom = _bom()
    errors = sorted(_validator().iter_errors(bom), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(
        f"{'/'.join(str(x) for x in e.absolute_path) or '<root>'}: {e.message[:200]}"
        for e in errors[:10])
    assert len(bom["components"]) > 0, "validated an empty BOM, which proves nothing"


def test_the_validator_actually_rejects_bad_documents():
    """🔴 A validator reporting zero errors is exactly when to distrust it.

    Six deliberate defects, each of which MUST be caught. Without this, a
    misconfigured resolver silently validating nothing would read as a clean
    pass — the "instruments fail toward false alarms and false greens" pattern
    this estate hit six times in one session.
    """
    v = _validator()
    base = _bom()
    cases = {
        "bomFormat wrong": lambda b: b.update(bomFormat="SPDX"),
        "component type invalid": lambda b: b["components"][0].update(type="not-a-type"),
        "assetType invalid": lambda b: b["components"][0]
            .get("cryptoProperties", {}).update(assetType="banana"),
        "serialNumber malformed": lambda b: b.update(serialNumber="not-a-urn"),
        "component missing name": lambda b: b["components"][0].pop("name", None),
        "unknown top-level field": lambda b: b.update(bogusField=1),
    }
    blind = []
    for label, mutate in cases.items():
        bad = copy.deepcopy(base)
        mutate(bad)
        if not list(v.iter_errors(bad)):
            blind.append(label)
    assert not blind, f"validator accepted invalid documents: {blind}"


def test_spec_version_is_ours_to_check_because_the_schema_does_not():
    """🔴 THE FINDING. The 1.6 schema does not constrain `specVersion`.

    It is declared `{"type": "string", "examples": ["1.6"]}` — no enum, no
    const — so `specVersion: "9.9"` validates against the 1.6 schema. Asserted
    directly against the schema text, not inferred, because a claim about
    someone else's document should be checkable in one line.

    ⭐ The consequence is the point: schema validation does not establish which
    specification a document follows. That check has to live here.
    """
    schema = json.loads(BOM_SCHEMA.read_text(encoding="utf-8"))
    sv = schema["properties"]["specVersion"]
    assert "enum" not in sv and "const" not in sv, (
        "CycloneDX now constrains specVersion — good news. Update this test and "
        "the module docstring; the blind spot is closed upstream.")

    v = _validator()
    forged = copy.deepcopy(_bom())
    forged["specVersion"] = "9.9"
    assert not list(v.iter_errors(forged)), (
        "the schema rejected specVersion 9.9 after all — re-read it")

    # So we check it ourselves. This is the assertion the schema cannot make.
    assert _bom()["specVersion"] == ev.cyclonedx.SPEC_VERSION == "1.6"


def test_crypto_components_carry_the_fields_a_buyer_reads():
    """A CBOM whose components validate but say nothing is not an inventory.

    ⚠️ Schema-valid is a floor, not a product: every optional field is optional.
    This asserts the fields that make the artifact useful are actually populated.
    """
    comps = [c for c in _bom()["components"] if c.get("type") == "cryptographic-asset"]
    assert comps, "no cryptographic-asset components emitted"
    for c in comps[:20]:
        cp = c.get("cryptoProperties", {})
        assert cp.get("assetType") == "algorithm", c.get("name")
        assert c.get("bom-ref"), f"{c.get('name')} has no bom-ref to reference it by"


def test_bom_refs_are_unique():
    """Duplicate refs make a BOM ambiguous while remaining schema-valid."""
    refs = [c["bom-ref"] for c in _bom()["components"] if "bom-ref" in c]
    dupes = {r for r in refs if refs.count(r) > 1}
    assert not dupes, f"duplicate bom-ref values: {sorted(dupes)[:5]}"


def test_a_str_target_works_because_that_is_what_the_readme_shows():
    """🔴 Regression guard. `build_cbom(".")` raised AttributeError until
    2026-08-22 — every in-package caller passed a Path, so no test called the
    public API the way a stranger would. ⭐ The defect was introduced by the
    previous day's fix for a different bug: a correction that narrowed the
    accepted input and was invisible from inside."""
    assert _bom(".")["components"], "str target produced no components"
    assert ev.to_cyclonedx(dataclasses.asdict(ev.build_cbom(Path("."))))["components"]

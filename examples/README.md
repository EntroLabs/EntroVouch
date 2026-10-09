# Verify our output yourself

**You do not have to trust anything in this repository.** Every report in
`reports/` was produced by the tools in this repository, from the fixture tree in
`sample_service/`, and you can regenerate all of them in one command and compare.

## The whole verification, in three lines

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python examples/regenerate.py
```

Then compare **one value** per report:

| Report | Value to compare | Expected |
|---|---|---|
| `reports/egress.json` | `findings_digest` | `57a8ec283551cc9d45d8281cc738ca65d0558625f0a9d87c119145337dc3cd62` |
| `reports/egress.json` | `subject_digest` | `a19a74eacd9be59d4545aec928772b5e6a745c65f029969df244700c84fdc269` |
| `reports/cbom.json` | `findings_digest` | `d5c39569f213db66be65ff743cfaa0bde9fa6e5258735ec1cb9ea6eb0c28d240` |
| `reports/sbom.json` | `findings_digest` | `eba24423f97e712ce825afc682a023c89308d14fbc1850120ab32cd8af307cc4` |

```bash
python -c "import json;print(json.load(open('examples/reports/egress.json'))['findings_digest'])"
```

If those match, **the tool on your machine produced exactly what we published.**
No account, no upload, no network call: the auditors have no network code in them,
which is the property they exist to demonstrate and which you can check by running
them on themselves.

## What will NOT match, and why that is correct

`content_hash` and `scanned_at_utc` **differ on every run.** `content_hash`
covers the issuance timestamp, so two honest runs produce two different values.

> **This is the mistake to avoid.** A reader who compares `content_hash`, sees a
> mismatch and concludes the report was forged has followed the most obvious instinct
> and reached the wrong answer. **All three digests are printed on the report itself,
> each labelled with whether it reproduces**, so the right comparison is the easy one.

## An asymmetry we would rather state than have you find

**`key_provenance` emits no findings digest.** Its report carries findings, a scope
statement and a content hash that shows an edit, and it is not signed, so the one-value
comparison above does not work for it: re-run it and read the findings. Egress, CBOM and SBOM
carry `findings_digest`. This is pinned in `tests/test_examples_reproduce.py` so it
cannot silently become true of another tool without someone noticing.

Exit codes for the scanners are in the [root README](../README.md#exit-codes).
`sbom` exits 0 if it ran; whether the BOM lists components is a field, not an
exit code.

## What the fixture contains, and why

`sample_service/` is **not** shipped software. It is a small tree built to
produce findings, because a demo where every scanner comes back clean demonstrates
nothing:

| File | Contains | Found by |
|---|---|---|
| `collector.py` | a network import, a request built for a URL held in a constant, and the send | no-egress auditor: `network-import` (line 2) and `network-target` (line 10, where the request is built). The send at line 12 is handed the request object, not an address, so it has no finding of its own: the import reports it |
| `pyproject.toml` | `stripe` declared, never imported | no-egress auditor (`declared-network-dependency`) |
| `urls.py` | `from urllib.parse import urlparse` | **nothing: parse is not a socket** |
| `motor.py` + `drive.py` | local module named `motor` | **not a network-import; name in `shadowed_imports`** (when `sample_service` is the audited tree; audit a folder above it and `motor.py` is no longer at the top, so `import motor` is reported) |
| `pricing.py` | pure computation, no egress | **nothing: the negative case** |
| `tokens.py` | MD5, `random`, in-source HMAC key, JWT RS256, pyca `hashes.MD5()`, and PEM armour with no key inside | CBOM, key provenance. The armour is **not** reported: armour counts only when a key body follows it |

`pricing.py`, `urls.py` and the local `motor` module matter as much as the hits.
**An auditor that flags everything is not strict, it is unusable**, and the
committed reports show it staying quiet where it should.

## Hand this to a prospect

No account. No upload. The tools need nothing installed; the test suite needs `pytest`.

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python -m pytest -q
python examples/regenerate.py
```

Then compare **one value**: `findings_digest` in `examples/reports/egress.json`
against the digest table at the top of this page. If it matches, the tool on
their machine produced exactly what we published.

What they are looking at is limited assurance: nothing came to our attention,
not a proof of absence. Independent issuance of that same report is the paid
layer: same tool, a third party on the signature.

## What a clean report does and does not mean

- **Static analysis only.** It audits the source you point it at. It does not
  observe runtime behaviour, and it cannot see egress introduced by a dependency it
  was not pointed at, by dynamic loading, or by a compiled extension.
- **Detection-grade, not proof.** Detection is blocklist-based, so it is complete
  only against names it knows. A renamed, vendored or dynamically-constructed module
  is invisible. The reports say this in their own scope statement rather than
  leaving you to discover it.
- **A signature proves origin and integrity, not correctness.** The example reports
  here are **UNSIGNED** on purpose: signing them would attest who issued them, and
  the point of this directory is the half that needs no trust at all.
- **`REVIEW` means review.** It is not a pass.

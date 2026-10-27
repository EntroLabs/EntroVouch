# Verify our output yourself

**You do not have to trust our published reports.** Every report in
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
| `reports/egress.json` | `findings_digest` | `6fa9c3709015d36df6c10e0caf272994d7cbd28c1e7ca70cece560f345272b55` |
| `reports/egress.json` | `subject_digest` | `0b1c519d12ce52b1801691b769d9eb3dbeda3f1d5c88d47da5b9174f9c113b2f` |
| `reports/cbom.json` | `findings_digest` | `4ffa7155986baf4120d342151712eef7e96f19f748f57c8ef71757ecbd7a2511` |
| `reports/sbom.json` | `findings_digest` | `72cad7cde8c755eff795a686832e3f3bffc74537803454e6944100ff380a3ec4` |

```bash
python -c "import json;print(json.load(open('examples/reports/egress.json'))['findings_digest'])"
```

If those match, **the tool on your machine produced exactly what we published.**
No account, no upload, no network call: the auditors import no network module.
Read the source, or run the auditor on `entrovouch/`; it reports `CLEAN`, which is
evidence, not proof.

## What will NOT match, and why that is correct

On the egress, CBOM and SBOM reports, `content_hash` and `scanned_at_utc` **differ between
runs issued at different times.** `content_hash` covers the issuance timestamp, so two honest
runs produce two different values, unless both fall inside one tick of the system clock (about
15.6 ms on Windows before Python 3.13). The `key_provenance` report has no timestamp, so its `content_hash` matches
when the label, the files read and the number of files in each skipped folder are the same.

> A reader who compares `content_hash`, sees a mismatch and concludes the report was
> forged has reached the wrong answer. **All three digests are printed on the egress, CBOM
> and SBOM reports, each labelled with whether it reproduces.**

## `key_provenance` has no findings digest

Its report carries findings, a scope statement and a content hash with no timestamp in
it, and it is not signed: re-run it and read the findings. Egress, CBOM and SBOM
carry `findings_digest`. `tests/test_examples_reproduce.py` fails if any other report
loses its findings digest.

## One signed report

`signed/egress.json` is the same no-egress audit of `sample_service/`, signed with the
publisher's key. Check who issued it against the root the [root README](../README.md#the-publishers-public-root)
publishes:

```bash
python -m entrovouch.verify examples/signed/egress.json --root eb309717634b3a9bd952aac903538bd9b3350d1b006f5176d1c87763ba87a96b
```

It prints `ATTESTED`. Without `--root` it prints `UNVERIFIED`, and after any change to a value in the file, `TAMPERED` (or an error, exit 2, if `tool` no longer
names a report this tool signs);
reformatting the JSON does not change what is signed. Its
`findings_digest` is the one in the table above, because it is the same audit. The key is not in this repository,
so `regenerate.py` does not re-sign it; `tests/test_signed_example.py` fails when the signed copy no longer matches
the current audit.

Exit codes for the scanners are in the [root README](../README.md#exit-codes).
`sbom` exits 0 if it ran and read every manifest, and 1 when its verdict is `INCOMPLETE`; whether the BOM lists
components is a field, not an exit code.

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

`pricing.py`, `urls.py` and the local `motor` module matter as much as the hits: an
auditor that flags everything is unusable, and the committed reports show this one
reporting no network finding for any of them.

## Short version

No account or upload is needed. The tools need nothing installed; the test suite needs `pytest`.

```bash
git clone https://github.com/EntroLabs/EntroVouch
cd EntroVouch
python -m pytest -q
python examples/regenerate.py
```

Then compare **one value**: `findings_digest` in `examples/reports/egress.json`
against the digest table at the top of this page. If it matches, the tool on
your machine produced exactly what we published.

What you are looking at is limited assurance: nothing came to our attention,
not a proof of absence. Independent issuance of that same report is the paid
layer: same tool, a third party on the signature.

## What a clean report does and does not mean

- **Static analysis only.** It audits the source you point it at. It does not
  observe runtime behaviour, and it cannot see egress introduced by a dependency it
  was not pointed at, by dynamic loading, or by a compiled extension.
- **Detection-grade, not proof.** Detection is list-based: a third-party network library
  that is not on the list produces no finding, and the report names it in `unlisted_imports`
  instead. What the auditor catches when names are disguised, and what it misses, is
  measured in the root README's recall table. The reports state their scope in their
  own body.
- **A signature, checked against a pinned root, proves origin and integrity, not correctness.** The reports in
  `reports/` are **UNSIGNED** on purpose: they are the half you can regenerate and compare yourself.
  One signed copy sits in `signed/`, described above.
- **`REVIEW` means review.** It is not a pass.

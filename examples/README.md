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
| `reports/egress.json` | `findings_digest` | `ab550ec3a55c490ba2c95e129bb64fe1b37b201e52dd85a12602af329943f513` |
| `reports/egress.json` | `subject_digest` | `3855a3f2fd37a4eff5b724a72acd0f541bfd08764a92e695077f9589c6dd520a` |
| `reports/cbom.json` | `findings_digest` | `742552a9cbdf95f238cf7018371323b9cf66baf896c26f2067324af091960299` |

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

> ⚠️ **This is the mistake to avoid.** A reader who compares `content_hash`, sees a
> mismatch and concludes the report was forged has followed the most obvious instinct
> and reached the wrong answer. **All three digests are printed on the report itself,
> each labelled with whether it reproduces**, so the right comparison is the easy one.

## An asymmetry we would rather state than have you find

**`key_provenance` emits no digest.** Its report carries findings and a scope
statement and nothing that reproduces, so the one-value comparison above does not
work for it — you can only re-run it and read the findings. The other two tools
carry `findings_digest` and `subject_digest`. This is pinned in
`tests/test_examples_reproduce.py` so it cannot silently become true of a second
tool without someone noticing.

## Exit codes, for CI

```
0  clean          no findings
1  findings       the scan ran and found something
2  could not run  bad arguments, unreadable target — NOT a clean result
```

⚠️ **1 and 2 are different answers and a pipeline that treats them alike will
eventually report a broken scan as a passing one.** Our own regeneration script got
this wrong on its first run and the fixture caught it within a minute.

## What the fixture contains, and why

`sample_service/` is **not** shipped software. It is three small modules built to
produce findings, because a demo where every scanner comes back clean demonstrates
nothing:

| File | Contains | Found by |
|---|---|---|
| `collector.py` | a real network import and an outbound POST | no-egress auditor |
| `pricing.py` | pure computation, no egress | **nothing — the negative case** |
| `tokens.py` | MD5, `random` for a session id, and a signing key written in the source | CBOM, key provenance |

`pricing.py` matters as much as the other two. **An auditor that flags everything
is not strict, it is unusable**, and the committed reports show it staying quiet
where it should.

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

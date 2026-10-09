# Adapters

The adapters write the same findings as SARIF 2.1.0, an in-toto Statement, a CycloneDX 1.6 CBOM, CycloneDX VEX,
CSAF 2.0 VEX and an RFC 3161 timestamp request. What each format name claims, and which official schema or checker
each output was run against, is in [CONFORMANCE.md](../CONFORMANCE.md).

## What every adapter refuses

An adapter exits 2 rather than convert:

- an output path that is one of its own inputs, or a hard link to one;
- a report saved with a byte-order mark it was written without (an editor adds one);
- a report whose body no longer matches its own `content_hash`, or that has no content hash;
- a report whose `findings_digest` is not the digest of the findings it shows;
- a signed report whose signature does not verify against its body, or that names a different signer than the body;
- a report that names a signer and carries no signature;
- JSON that gives one key twice in an object;
- a report of another kind, such as a CBOM handed to the SARIF converter.

The content hash has no key. It shows an edit made without recomputing it, and anyone can edit an unsigned report and
recompute both values. Only a signature binds a report to its issuer, and only a signed report that verifies against
a root you pinned is evidence of who issued it. The adapters check a signature against the report's body and have no
root to check it against, so a converted document carries the signer's root (`signedBy` in SARIF) for you to compare
with the one you pinned.

## `vex` and `csaf`

The same checks apply to the `key_provenance` report handed to `vex` or `csaf`, and one without a content hash is
refused. Naming a `key_provenance` report that does not exist, or one made from another tree, is an error: both
reports must carry the same label and the same `tree_listing_digest`. That digest covers every file the scan reads,
by name and by content, with line endings folded at any size; what sits in a skipped directory is part of neither
report and not part of the digest.

- A CBOM that read nothing is refused. One that could not parse a file carries its verdict, and the files it did not
  parse, into the document.
- One CBOM gives one CSAF tracking id, bound to what the document says and to the tree it was made from. CSAF takes
  its dates from the CBOM, so one CBOM gives one document.
- VEX names the audited tree as its subject component, and each statement affects it.
- When a CBOM holds nothing a CSAF document can state, `csaf` writes nothing and exits 0, or exits 2 when `--out`
  already holds a file, so an earlier run's document is not taken for this one's.

## `attestation`

`attestation --cbom` takes a CBOM and nothing else. A signed Statement is checked by
`python -m entrovouch.verify statement.json --root <root>`, which rebuilds the report the Statement carries and
checks it as it checks that report; a DSSE verifier cannot do this.

- A Statement holding anything `attestation` does not write (a field the signature does not cover, a predicate type
  other than its kind's, another note) is `TAMPERED`.
- Its subject names SHA3-256 as in-toto does (`sha3_256`). A Statement written with the reports' name for it
  (`sha3-256`) verifies the same.
- A Statement whose `signature` is null is `UNSIGNED`. The signer is named only in that field, so a Statement with it
  emptied cannot be told from one made unsigned, and neither verifies.

## `timestamp`

`timestamp request` takes any file, with two conditions. A file that opens as a JSON object must be strict UTF-8
without a byte-order mark and strict JSON (a JSON file in UTF-16 or UTF-32 is refused). A file that names itself a
report of this tool must be that report exactly, intact and with its content hash. The digest is taken from the bytes
that were checked.

`timestamp check` passes when the token is one DER structure holding the report's digest and, with `--nonce`, the
nonce that `request` printed, after the digest where a timestamp places it. Without `--nonce` it says the nonce was
not checked.

## SARIF

A SARIF result's fingerprint leaves out the line, so a line added above a finding moves no alert; two equal findings
in one file are told apart by their order. A notebook result names its cell (`notebookCell`) instead of a line of the
notebook's JSON, and a result about a whole file has no line. SARIF from an audit that read nothing is a run that did
not succeed.

SARIF, CycloneDX and the SBOM validate against their official schemas, using `jsonschema` in the tests only; the
tools themselves stay standard library. A schema checks a document's shape, not every claim in it; what each schema
leaves open is in [CONFORMANCE.md](../CONFORMANCE.md).

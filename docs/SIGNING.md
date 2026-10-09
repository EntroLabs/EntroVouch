# Signing

One signer ships: Lamport-Merkle over SHA3-256. Its security rests on SHA3-256 preimage resistance alone. Keys are
one-time, and the leaf index is saved before any secret is revealed. A signature is about 16.7 KB, or about 36 KB as
hex inside a JSON report.

It claims conformance to no published standard. In particular it does not meet NIST SP 800-208, which requires
stateful hash-based keys to live in a hardware module and never be exported; this key is a file.

A signature has one accepted encoding: integer index and height, 64 lower-case hex digits per value, and no extra
fields. Anything else is `TAMPERED`.

## The key is stateful

Each leaf signs once. A copy of the key file that falls behind (a restored backup, a second machine, a CI runner with
its own copy) will sign with leaves another copy already used, and nothing in a signature reveals that. Keep one copy
that signs.

- A key file with a second name (a hard link) is refused, because two names could sign with one leaf.
- Temporary copies of the key left by a signer that was killed mid-write are removed the next time the key signs.
- Before a restored or copied key signs again, run
  `python -m entrovouch.no_egress_auditor --key PATH --advance-key N`, with `N` at least the number of signatures the
  other copy could have made. It marks those leaves spent and saves that before anything else happens.

## What a signature shows

With the root pinned, a signature shows that the report came from the holder of that key and that its bytes are
unchanged. It says nothing about whether the verdict is correct. The algorithm name and the public root are inside
the signed bytes, so editing either gives `TAMPERED`.

The root is 64 hex digits, in either case; anything else is refused with exit 2.

`verify_report` returns `ok` as `True` for `ATTESTED` only; `UNSIGNED` and `UNVERIFIED` are `False`. `TAMPERED` covers:

- a body changed after signing;
- a signature from a key other than the root you pinned;
- a body naming a different signer than its signature;
- a removed signature;
- a report of another kind, such as a CBOM handed to the no-egress verifier.

A report you did not pin a root for, and an unsigned report, are not evidence of origin. To check one, re-run the tool
on the same tree and compare the findings digest.

# Signing

One signer signs reports: Lamport-Merkle over SHA3-256. Its security rests on the preimage and collision resistance of SHA3-256, and on SHA3-256 as a
pseudorandom function for deriving the one-time secrets from the seed.
Each leaf is one-time, and the leaf index is saved before any secret is revealed. A signature is about 16.7 KB, or about 36 KB as
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

`integrity_tag` is always empty and sits outside the signed body: removing or emptying it changes nothing, and
any other value gives `TAMPERED`.

With the root pinned, a signature shows that the report came from the holder of that key and that its bytes are
unchanged. It says nothing about whether the verdict is correct. The algorithm name and the public root are inside
the signed bytes, so editing either gives `TAMPERED`.

The root is 64 hex digits, in either case, with surrounding whitespace ignored; anything else is refused with exit 2.

`verify_report` returns `ok` as `True` for `ATTESTED` only; `UNSIGNED` and `UNVERIFIED` are `False`. `TAMPERED` covers:

- a body changed after signing;
- a signature from a key other than the root you pinned;
- a body naming a different signer than its signature;
- a removed signature;
- an `integrity_tag` that is not empty;
- a report of another kind, such as a CBOM handed to the no-egress verifier.

A report you did not pin a root for, and an unsigned report, are not evidence of origin. To check one, re-run the tool
on the same tree and compare the findings digest.

## RFC 8554 and RFC 9858 (LMS and HSS)

`entrovouch.lms` is a separate module. It verifies LMS and HSS signatures for the SHA-256 parameter sets RFC 8554
defines and for the SHA-256/192, SHAKE256/256 and SHAKE256/192 sets RFC 9858 adds, and signs with an LMS key derived
from a seed as RFC 8554 Appendix A describes, using the RFC 8554 SHA-256 sets at heights 5 and 10 only. It verifies
both test cases of RFC 8554 Appendix F and reproduces test case 2 byte for byte; it verifies the 4 test cases of
RFC 9858 Appendix A (SHA-256/192, SHAKE256/192 and SHAKE256/256) without reproducing them, since it does not sign
with those sets; and it gives the published answer on all 8 LMS sigVer vectors NIST publishes in its ACVP-Server
repository, which cover two SHA-256/192 sets. That is the
whole of its conformance claim, and running NIST's vectors is not CAVP validation. It is not validated under NIST
SP 800-208, which allows LMS signing only inside a hardware module. Its key is a file with the same one-time rule as
the report signer: the next unused leaf is written before a signature is computed, a used leaf is refused, and a
state file that moved backwards while the key is loaded is refused; a copied or restored file can still bring a used leaf back, so call
`advance` past every leaf the copy may have missed. It does not sign reports, and the report format does not use it.

## Issuance log

`entrovouch.tlog` records each report an issuer enters in it as one line,
`entrovouch/issuance/v1 <findings_digest> <content_hash>`, in a Merkle tree hashed as RFC 9162 Section 2.1 defines.
A report signed and never entered leaves no trace in the log.
The directory is laid out as C2SP tlog-tiles describes: `checkpoint`, hash tiles of height 8 under `tile/<L>/<N>`,
partial tiles under `tile/<L>/<N>.p/<W>` and entry bundles under `tile/entries/<N>`. The checkpoint is a C2SP signed
note: origin, tree size and root, then a signature line.

- **The log key is not the report key.** The checkpoint is signed with this package's Lamport-Merkle signer under a
  key kept in its own file, outside the log directory. A report signed by the log key is refused. `append_all` enters
  several reports under one checkpoint.
- **How many checkpoints the log key signs.** Each checkpoint uses one leaf of the log key, so a key of height h
  signs at most 2^h checkpoints. `IssuanceLog.create` makes a key of height 10 unless given `key_height` (at most 16)
  and signs the empty checkpoint with the first leaf, so a new key leaves 2^h - 1 appends. When no leaf is left,
  `append` raises `TlogError` and the signed checkpoint is not changed. A log keeps its key: a new key has a new
  verifier key and starts a new log, nothing signed links that log to the old one, and buyers pin the new verifier
  key.
- **The log key is stateful, like the report key.** It is a one-time-signature key in a file, and the same rule
  applies: keep one copy of it. A copied or restored copy signs with leaves another copy already used. A second
  signature under one leaf reveals about half of that leaf's secret values not yet revealed and weakens it toward
  forgery; each further signature under it reveals more, and a few make forging a checkpoint under it practical.
  Before a restored or copied log key signs again, run
  `python -m entrovouch.no_egress_auditor --key PATH --advance-key N` on it, with `N` at least the number of
  checkpoints the other copy could have signed. Do not roll the log directory back either: a copy of it older than
  a checkpoint already handed out, appended to, signs trees that do not extend that checkpoint, which is a fork.
- **One key, one log.** `IssuanceLog.create` makes a new key and refuses a key file that already exists at
  `key_path`, which may be another log's key or the report key, unless given `reuse_key=True`; then it loads that key
  and ignores `key_height`. One key file used for two logs makes them a fork when they share an origin.
- **What is entered.** `IssuanceLog.append(report, report_root)` enters a report only if it verifies `ATTESTED` under
  the report root you pin. It writes the entry bundles, then the tiles, then the checkpoint, and it does not sign a
  tree smaller than, or inconsistent with, the last checkpoint. Before it signs, it reads the new tree back and
  refuses unless every file it wrote holds exactly the bytes written, the stored entries past the last checkpoint are
  the ones being appended, the entries carried from below it hash to the last checkpoint's tile, and the root of the
  stored tiles equals the root computed from the last checkpoint's tree and those entries. If an append raises, read
  the log's state before retrying: where a platform reports an error after the new checkpoint is in place, the
  append has happened. It never rewrites or removes a
  file a checkpoint covers, and it leaves older partial tiles in place. An append that stops before signing can
  leave files no checkpoint covers, including a full tile; readers take the file named for the size they read
  before a full one, and the next append that writes the same name replaces it.
- **What a buyer checks, offline.** Pin the log's origin and verifier key through a channel you trust, as you pin the
  report root. Check the report itself with `python -m entrovouch.verify` (or `verify_report`): it is intact and signed
  under the report root you pin. `proof_bundle(index)` gives the signed checkpoint, the entry and an inclusion proof.
  `verify_bundle(bundle, vkey, report=report)` checks the checkpoint's signature against the verifier key, the
  inclusion proof against its root, and that the entry's findings digest and content hash are the report's; without
  `report` it does not check which report the entry names, and a `report` that is not a dict raises `TlogError`. It
  does not check the report's signature. `verify_log_dir(directory, vkey)` recomputes every tile the checkpoint's tree
  uses from the entries. Both return the origin and do not compare it with an expected one: compare it with the one
  you pinned.
- **Forks.** `detect_fork(cp_a, cp_b, vkey, proof)` compares two checkpoints of one origin, and raises `TlogError`
  for two with different origins. Equal sizes with different roots give `True`: the key signed two trees that cannot both be true,
  which happens when the issuer keeps two logs, when the log key leaked or was copied, and when the log directory was
  restored from a copy older than a checkpoint already handed out and then appended to. Equal sizes with the
  same root give `False`. Different sizes give `False` when the consistency proof given verifies, and `None` when no
  proof is given or it does not verify, since a failing proof does not show that no proof exists. A checkpoint of size
  0 is consistent with every checkpoint and gives `False`, with or without a proof.
- **The verifier key.** `<key name>+<key ID>+<base64 key>`, where the key is the byte 0xff, a 32-byte algorithm
  identifier (SHA-256 of `entrovouch/lamport-merkle-sha3-256/v1`) and the signer's root. signed-note reserves 0xff for
  signature types it assigns no identifier and recommends following it with a longer identifier unlikely to collide,
  which is what this key does. It defines key encodings only for its own types, verifiers must ignore signatures from
  unknown keys, and a client must reject a note on which no signature from a known key verifies. So a signed-note
  client that does not implement this signature type cannot be given this key, ignores the signature, and rejects the
  checkpoint. This follows from the signed-note rules; no such client was run. Checking these checkpoints needs this
  tool.
- **What it does not do.** The log is files in a directory and has no witnesses: nothing here stops someone with
  write access from replacing it, and an issuer can show different buyers different histories. Only buyers who
  compare checkpoints, or keep the checkpoints they have seen and ask for consistency proofs between them, can detect
  it: no consistency proof verifies once the log has been replaced with a different history.

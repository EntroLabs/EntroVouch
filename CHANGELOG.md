# Changelog

Every report carries the version that produced it (`tool_version`). From 1.1.0 on, the version changes whenever a
report on some tree can change, so two reports of one version came from the same detection rules; reports labelled
1.0.0 came from several revisions of the code and can differ. Each entry says what can make a report differ from the
version before.

## Unreleased

Nothing in a report changes: no detection rule, scope statement or report field differs from 1.1.3.

- `entrovouch.tlog` keeps an issuance log: one line for each report the issuer enters, `entrovouch/issuance/v1
  <findings_digest> <content_hash>`, in a Merkle tree hashed as RFC 9162 defines and laid out as C2SP tlog-tiles
  describes, with checkpoints signed by a separate log key. It enters only a report that verifies `ATTESTED` under the
  root you pin; a report signed and never entered leaves no trace in it. It never rewrites or removes a file a
  checkpoint covers, reads the new tree back before it signs, and never signs a checkpoint smaller than, or
  inconsistent with, the last one; nothing stops someone with write access from replacing the directory.
  `verify_bundle(bundle, vkey, report=report)` checks offline that a checkpoint the log key signed includes an entry
  naming that report (the report's own signature is checked by `verify_report`), and `verify_log_dir` checks the
  whole directory; both return the log's origin without comparing it with an expected one. The log has no witnesses:
  an issuer can show different buyers different histories, and only buyers who compare checkpoints or ask for
  consistency proofs between them can detect it. `detect_fork` gives `True` for two checkpoints of one size and one
  key with different roots, `False` for consistent ones, and `None` for different sizes with no consistency proof or
  one that does not verify. `IssuanceLog.create` makes a new log key and refuses a key file that already exists unless
  given `reuse_key=True`. A log key of height h signs at most 2^h checkpoints, the first of them the empty one. The
  checkpoints use this package's signer: a signed-note client that does not implement its signature type rejects them
  (this follows from the signed-note rules; no such client was run).
- `entrovouch.lms` also verifies the RFC 9858 parameter sets (SHA-256/192, SHAKE256/256 and SHAKE256/192). It signs
  with the RFC 8554 SHA-256 sets at heights 5 and 10 only. Its verifier refuses a public key whose tree and one-time
  key types use different hashes. It gives the published answer on the 8 LMS sigVer vectors NIST publishes in its
  ACVP-Server repository, and verifies the 4 test cases of RFC 9858 Appendix A (SHA-256/192, SHAKE256/192 and
  SHAKE256/256); that is not CAVP validation.

## 1.1.3

- A Python import of a radio or peripheral-link library is reported as `peripheral-link`: Bluetooth (`bleak`,
  `bluetooth`, `bluepy`, `pygatt`, `simplepyble`), mesh and Zigbee radios (`meshtastic`, `zigpy`, `zigpy_*`), a CAN
  bus (`can`), a serial line (`serial`) and USB (`usb`). Data can leave the device over such a link, so a tree whose
  only outbound channel is one of them is no longer `CLEAN`; the finding is not network egress and means review.
  These names are no longer listed in `unlisted_imports`. The scope statement names the kind, so every report's
  findings digest changes.
- `entrovouch.lms` verifies RFC 8554 LMS and HSS signatures, makes LMS signatures, verifies both test cases of
  the RFC's Appendix F and reproduces the second byte for byte. It is not validated under NIST SP 800-208, it does not sign reports, and the report signer and the
  report format are unchanged.
- `key_provenance` lists a JSON file nested deeper than 900 levels in `files_not_parsed`, so its verdict is `REVIEW`,
  not `NOTHING-FOUND`: the file's values were not read. Its scope statement says so.

## 1.1.2

Not released on its own; these changes ship in 1.1.3.

- On Windows, a folder whose name ends in a dot or a space is read like any other folder, as it is on Linux and
  macOS, through its extended-length path; a link or junction with such a name is counted and not followed.
- A TOML manifest (`pyproject.toml`, `Pipfile`) nested deeper than 100 levels is reported as not parsed, on every
  Python version and from every caller.
- A conda package URL keeps the name as conda writes it (`pkg:conda/ruamel.yaml`), the channel named in
  `channel::name` as the `channel` qualifier, and nothing of a `[...]` selector (`scipy[version=">=1.2"]` is
  `pkg:conda/scipy`).
- A `<` inside an HTML tag's attribute value (`<img alt="x < y" src=...>`, `<img src=https://h/a.png?a<b>`) is read
  as part of the value, and the load is reported; markup with unclosed tags is read in linear time.
- `sbom` names a manifest of an ecosystem it does not read (`go.mod`, `Cargo.toml`, `pom.xml`, ...) and says
  `INCOMPLETE`.
- Python that Python cannot decode is listed as not parsed by `cbom` and `key_provenance`, as the auditor does.
- Python source longer than 4,194,304 characters once decoded is reported as not parsed.
- An adapter refuses a folder given as its output before doing any work, with the message the scanners give.
- `timestamp check` reads the imprint and the nonce from the TSTInfo the token's signature covers, in a response or
  a bare timestamp token; any other structure is reported as holding the digest, not as an imprint match.
- Every command answers `--version`.
- The markdown report says "1 more was not read" for one file.

## 1.1.1

- The audited folder's own name is read from its parent folder's listing, so macOS gives one report however the
  path was typed.
- One nesting limit on every Python version and stack: an expression nested deeper than 1,000 levels, or JSON
  deeper than 900, is reported as not parsed.

## 1.1.0

- One tree gives one report on every system: directories skipped by their path inside the tree, files ordered by
  the bytes of their normalised path, line endings folded in the subject digest, links and junctions counted and
  not followed.
- A tree in which nothing was read is `NOT-ANALYSED` (exit 2), never `CLEAN`; every report lists what it did not
  read.
- More file types and forms read; the full list is in [docs/WHAT_IS_READ.md](docs/WHAT_IS_READ.md).
- CSAF 2.0 VEX output, and `verify`, which checks a signed report against a pinned root.

## 1.0.0

- The no-egress auditor, the CBOM generator, the key-provenance check and the SBOM, with reports signed by a
  hash-based Lamport-Merkle signer; SARIF, in-toto, CycloneDX, VEX and RFC 3161 timestamp adapters.

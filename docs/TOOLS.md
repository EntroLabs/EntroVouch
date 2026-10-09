# What each tool reads and reports

The detail behind the README's `## Use` section. The reading rules of `no_egress_auditor` are in
[WHAT_IS_READ.md](WHAT_IS_READ.md), and the adapters are in [ADAPTERS.md](ADAPTERS.md).

## Output

Each scanner takes a directory, prints a markdown report, writes JSON with `--json` and markdown with `--md`, and
takes `--label`. Output files are written with LF line endings on every system.

These are errors before anything is signed:

- an output whose folder does not exist, or an output that is a folder;
- an output that is the signing key's own file, or another output of the same run;
- a CycloneDX `--serial` that is not `urn:uuid:` and a UUID.

A file name that is not valid UTF-8 is written escaped. Text taken from the audited tree (names, paths, lines) is
escaped in the markdown, and an address in it is set as code, so a file in the tree cannot put a link, an image or a
tag into a report.

## `key_provenance`

It reads:

- Python, key files, `.env` and `.envrc` files, and configuration files;
- private-key armour in any text file up to 16 MiB, written out or base64-encoded (including a base64 service-account
  JSON file, wherever the armour starts in the encoded data), on one line, wrapped over lines (a YAML scalar
  continued, strings joined across lines) or encoded twice;
- notebook cells, output and metadata;
- zip files (with bytes in front allowed, as in a zipapp), tar, gzip, bzip2, xz and lzma files, recognised by their
  bytes, and archives inside archives.

Armour with no key under it, such as a placeholder like `<paste your key here>`, is not reported as a key in any file.
What the tool did not read, or read only in part, is listed.

Its verdict is always `REVIEW`: whether key material anyone can derive is a defect depends on who receives the
artifact, and source code cannot tell you that. Its report carries a content hash and is not signed. A key handed to
a MAC as bytes (`KEY.encode()`, `bytes(KEY, "utf-8")`), by position or as `key=`, is traced back to its literal. It
does not detect a password written inside a connection URL (`postgresql://user:secret@host`).

## `cbom`

`cbom` knows cryptography by the libraries, calls and algorithm names on its lists. Code that uses a cryptography
package not on them, or does its cryptography in a native library, is not in the CBOM, so `NOTHING-VULNERABLE-FOUND`
means nothing it knows was found vulnerable.

It reports `REVIEW-NEEDED` when nothing it found is classified vulnerable or broken and something needs a person to
classify it: a library whose algorithm is chosen at the call, a cipher mode, or a verification switch.

- A hash named by a string is read in every spelling hashlib accepts (`'SHA-1'`, `'sha-256'`, `'md5-sha1'`), through
  `hashlib.new`, `hmac.new`, `hashlib.file_digest` and their from-imports (`from hmac import HMAC`), including a name
  bound once to a hash's name.
- Falcon counts as the signature scheme only with its parameter set or its FIPS 206 name (`Falcon-512`, `FN-DSA`),
  never as the web framework.
- A JWT decoded with its signature check turned off is found through any import of PyJWT or python-jose, and through
  an options dict bound to a name.

## Both `cbom` and `key_provenance`

A Python file either tool cannot parse is listed in `files_not_parsed`. Its contents were not read, so the result
cannot be `NOTHING-VULNERABLE-FOUND` or `NOTHING-FOUND`.

A tree in which `key_provenance` read nothing but archives it could not open (an encrypted zip, a `.7z`, or an
archive holding only such an archive) is `NOT-ANALYSED`, exit 2. An archive holding one it cannot open is listed as
not fully read.

## `sbom`

`sbom` emits CycloneDX 1.6 from the dependencies the tree declares, before any build and at the top level only.
[Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) (the Cyber Resilience Act), Annex I
Part II(1), asks for a software bill of materials in a commonly used machine-readable format covering at least the
top-level dependencies, from 11 December 2027. This one covers that scope, read from the declarations rather than
from a build. Incident reporting under the same Act is outside this command.

It does not hash a built artifact, does not walk transitive dependencies, and does not claim conformance to the CISA
2026 minimum elements. The document labels those gaps `unknown`.

`sbom` exits 0 if it ran and read every manifest; whether the BOM lists components is in the document. A manifest it
could not open or parse makes the verdict `INCOMPLETE` and the exit code 1, and is named in the document's unknown
fields.

Every command lists a file it could not open (permissions, a lock held by another program) and never reports a clean
result over it. The auditor reports such a file as `unparseable-source`, and the subject digest records it as unread.

Every command applies one nesting limit on every Python version and machine. Python whose expressions nest deeper
than 1,000 levels, and JSON nested deeper than 900, is not read and is reported the same way as a file that will not
parse. The reasons are in [WHAT_IS_READ.md](WHAT_IS_READ.md).

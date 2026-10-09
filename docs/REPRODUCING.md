# Reproducing a report

## The three values on a report

| Field | Reproduces? | What it answers |
|---|---|---|
| `findings_digest` | yes, across runs, processes and machines | *Does this tool, on this tree, still say this?* |
| `subject_digest` | yes, per tree | *Which tree was audited?* |
| `content_hash` | no, by design | *Is this the exact artifact I was handed?* |

All three are printed on the report, each labelled. `content_hash` covers the time the report was issued, so it
differs on every run. Two reports with the same findings digest and different content hashes are the same result,
issued twice. `key_provenance` has no findings digest; re-run it and read the findings.

`subject_digest` is an order-independent SHA3-256 over every file the audit read, also carried as the in-toto
`subject`. Files the audit did not read (a skipped directory, a link, a file type it has no reader for) are not
covered by it.

## The label

`--label` names the subject inside the signed body, so `findings_digest` covers it. Without that, two different trees
with the same findings would give the same digest. Pass our label to reproduce our value. Pass your own
(`org/repo@commit`) when you audit your own code, and expect a different digest. If you leave `--label` out, the
report names the directory (`sample_service`) and gives a valid digest that will not match our table.

A signature over a free-text label attests the label as written. It does not prove that the label describes the tree,
so compare digests on the same tree with the same label.

## One tree, one report

Five things that differ between machines are taken out of the result.

- **Where the tree sits.** Directories are skipped by their path inside the tree, never by the folders above it.
- **How the tree's path was typed.** The tree is known by the name its folder is stored under, read from the
  listing of the folder above it. On a file system that ignores case (Windows, macOS), `REQUESTS` and `requests`
  reach one folder, and both give the report for the stored name.
- **File order.** Paths use forward slashes, are normalised to Unicode NFC and are ordered by their UTF-8 bytes, so
  Windows (which sorts without regard to case) and Linux give one order. NFC follows the Unicode version of the Python
  that runs the tool (14.0 on 3.11, 16.0 on 3.14), so a name holding a character that only a newer version composes
  can normalise differently between them. On Windows, a file whose name ends in a dot or a space is read by its
  extended path; a directory with such a name is listed with the skipped directories, its files counted and not read.
- **Line endings.** The subject digest folds CRLF to LF in text files, so a checkout that converted line endings
  matches one that did not. A binary file is hashed byte for byte. A file git treats as text by its own test (no NUL
  byte, no lone CR, few control bytes, such as Cython source or a protocol-0 pickle) is folded as text, at any size.
- **How deep the parser goes.** Python 3.11 to 3.14 accept different nesting depths, and 3.14's depends on the
  stack it finds. Every tool applies one lower limit (1,000 levels of Python expressions, 900 of JSON), so a file
  nested past it is reported as not read on every version and machine. Details:
  [WHAT_IS_READ.md](WHAT_IS_READ.md).

Each file is read as one version for the whole run. If it changes while it is being read, the run stops with exit 2
rather than report on two versions.

What sits inside a skipped directory (`.git/`, a cache, `node_modules/`) is listed in the report and left out of
`findings_digest`, so a fresh clone of the commit gives the auditor's digest. The folders a build, a notebook or a
coverage run leaves (`*.egg-info/`, `.eggs/`, `.ipynb_checkpoints/`, `htmlcov/`, `_build/` and others) are skipped.
A folder this tool does not know is read, so output another tool leaves in a used checkout can still make the digest
differ from a fresh clone's.

A link is counted and not read. Where git checks a link out as a text file, that file counts as the link when its text
is only a path (no space, quote or other character a command needs) naming a file in the tree or a place outside it.
A stand-in of any other shape is read, so on Windows it can add a finding but never hide one. The files alone decide
this; git's index, which the tree's author writes, does not.

The rules are tested on Windows and on Linux (Ubuntu 24.04, ext4), including an ext4 folder set to ignore case,
which keeps a path's typed case as macOS does. A test pins the digests of one tree, and every system gives the same
values. The authors have not run macOS on a machine of their own. The test workflow runs the suite, including that
pinned-digest test, on macOS for every push to `main` and every pull request; for version 1.1.1 it passed on macOS
with Python 3.11, 3.12, 3.13 and 3.14 in
[run 37998124472](https://github.com/EntroLabs/EntroVouch/actions/runs/37998124472). If a digest ever differs between
systems, check the operating system first.

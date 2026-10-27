# Changelog

Every report carries the version that produced it (`tool_version`). From 1.1.0 on, the version changes whenever a
report on some tree can change, so two reports of one version came from the same detection rules; reports labelled
1.0.0 came from several revisions of the code and can differ. Each entry says what can make a report differ from the
version before.

## 1.1.4

Every report's `findings_digest` differs from 1.1.3's on every tree, because the digest covers `tool_version`; the
findings themselves differ only where this entry says.

A report changes on a tree that imports `profiling`, the standard-library module Python 3.15 added (PEP 799):
1.1.3 listed it among the unlisted imports, and 1.1.4 knows it as standard library on every Python.

Two more changes follow Python 3.15's start-up rules. A `.pth` line that begins with `import` after leading spaces
or tabs is reported as `startup-exec` and analysed, because 3.15 strips each line before deciding to run it; 1.1.3
reported only lines that begin with `import` as written. `.start` files (PEP 829) are read: each `pkg.mod:callable`
line, which 3.15 calls at interpreter start, is reported as `startup-exec`, and the SARIF form's description of
`startup-exec` says so. They are read as `site` reads them: only a name ending in `.start` in that case, as UTF-8
(a file that does not decode has no entry points), with entry names that may begin with any letter; a `.start`
file holding a NUL byte is `unanalysed-artifact`, as a `.pth` file is.

### Programs started from Python

Programs started from Python are resolved alike whichever call starts them.

**Bound names.** 1.1.3 read the program from an argv list whose first word is a literal, inline or bound
(`ARGS = ["curl", url]`), for `os.execv*`, `os.spawnv*` and `pty.spawn` as for `subprocess`. It gave no finding when
the program was a bound name that no literal argv spells out (`os.execv(PROG, [PROG, url])`,
`os.execlp(PROG, PROG, url)`, `os.spawnlp(...)`, `asyncio.create_subprocess_exec(PROG, url)`), nor for
`asyncio.create_subprocess_exec(*ARGS)` with a bound list. 1.1.4 reads a program name bound once to a literal
(`PROG = "curl"`) in place in all of these. A name bound once to a process function (`runner = subprocess.run`,
`sh = os.system`) is that function.

**`executable=`.** The `executable=` keyword of `subprocess` names the program that runs, and is judged in place of
the argv's first word. With `shell=True` it is the shell, and the shell string is reported as before.
- `sys.executable` is Python however it is reached: `from sys import executable`, an alias of sys, `os.sys`,
  `sys._base_executable`, `getattr(sys, "executable")`, `str(...)`, `os.fsencode(...)` or `pathlib.Path(...)` of
  one, or a name bound once to one (a from-imported name the file binds again is not).
- `shutil.which("x")` is x, and the argv's own first word is read too, since it runs when x is absent.
- The third positional argument of `Popen`, and of the calls that pass their arguments to it, is the executable as
  the keyword is, and a name bound to `None` there leaves the argv's own program.
- Any other value not spelled out is a program the line does not spell out. Read as the argv's own first word, a
  line that reaches the network gets one `unresolved-call` naming that word; otherwise an address on another machine
  handed to it is `external-url`.

**Names written as they are.** A literal string is read as written even when it holds U+0000 to U+0003, and a
program name holding one is named with its control picture (U+2400 to U+2403).

**`unlisted_programs`.** A new report field, covered by the findings digest, names each program the tree's Python
starts that is not on the auditor's started-program lists (`PY_NET_BINARIES`, `git`, the shells, Python, the
browser openers and the wrappers). A program those lists do not name but the command rules for script and CI lines
judge (`cargo build`, `mvn package`, `rclone copy`) is named there too, beside the finding those rules give. The field
is written only when it names something, so a report on a tree that starts no such program is unchanged.

### Wrappers

After wrappers (`sudo`, `env`, `timeout`, `nice`, `chroot`, `xargs`, `strace`, `time` and the others, up to 32 in a
row; a line still a wrapper after that is an unknown program) the program is found as their manuals read the line.

- **Options.** An option documented as taking a value skips it, with option clusters read as getopt reads them
  (`sudo -iu root`, `sudo -uroot`). A documented flag takes none, nor does a cluster that reaches an option whose
  optional value is attached only (`xargs -ia`) (`watch -d`, `timeout -f`, `env --block-signal`, and `nice -5`, the
  older `-ADJUSTMENT` form). A long option is read by its unambiguous abbreviation as getopt_long reads it
  (`timeout --kill 1`, `sudo --us root`). An option with its value attached (`-n5`) is followed by no value.
- **A wrapper's own argument** (`chroot NEWROOT`, `timeout DURATION`) is skipped and the program follows it. An
  option whose arity is not documented may also take the word in that place.
- **`timeout DURATION`.** A DURATION timeout's number reader refuses runs nothing: `5 `, `git`, and a negative
  number in DURATION's place (`timeout -- -5 cmd`; before `--`, `-5` is read as an option). Leading whitespace, a
  sign, hexadecimal and `inf` are numbers to it, a number too large for a float is infinite, `-0` is zero, and the
  unit is lower case. A `--` after DURATION is the command, which fails, so nothing runs, unless the word in
  DURATION's place is one the line does not spell out, which may be an option that `--` ends: `timeout x -- 5 curl`
  runs curl when x is `--foreground`.
- **`--`.** After `--` every word is an operand and options are not read again, unless `--` may be the value of an
  option before it whose arity is not documented (`env x -- -v cmd`).
- **`env -S`** splits its string as GNU env 8.32 does: on spaces and tabs only (a newline stays inside a word);
  quotes, and inside single quotes a backslash before a letter env does not know is refused; `\_` between words, the
  escapes env knows, and a word beginning with `#` ending the string. `-Sstring`, `-iS`, `-iSstring` and the
  abbreviations of `--split-string` are read too. A string env refuses, such as one with an unknown escape, an
  unterminated quote or `$` other than `${NAME}`, runs nothing, unless the refusal depends on a value the line does
  not spell out. An `-S` whose string the line does not spell out leaves the program unknown. The string's words and
  the words after it are read again as env's options until env's first operand: a word holding `=` that is not an
  option (a setting), or the command (`env A=1 -u X cmd` runs `-u`, as GNU env does). An f-string is split the same
  way: a word whose written start is an option or a setting is that option or setting, any other word holding a value
  the line does not spell out (or `${NAME}`) may be the program itself, and under `env` a `NAME=value` after `--` is
  still a setting.
- **Options after which nothing runs** (`sudo -l`, `sudo -e`, `sudo -v`, `command -v`, `ionice -p`, `doas -C`,
  `time -V`, the GNU wrappers' `--help` and `--version`, and `env -0`, after which env refuses a command), also
  inside an option cluster (`sudo -lu root`, `command -pv`) or abbreviated (`sudo --li`): no program is read, unless
  a word whose meaning is not settled comes before it.
- **f-string option words.** While a wrapper's options are read, an f-string with a placeholder whose literal start
  is an option or a `NAME=` setting is that option or setting. When the start settles how many words it takes (a
  setting, an option with `=`, or a short-option cluster in which a letter documented as taking a value comes before
  the placeholder: `f"-n{level}"`, `f"-iu{u}"`, `f"--user={u}"`, `f"PATH={p}"`) its value is attached. Any other
  option start (`f"--{o}"`, `f"-i{o}"`) is an option whose arity is not documented, never the program, except under a
  wrapper none of whose options takes a separate value (`setsid`, `nohup`, `command`) or for an option whose optional
  value is attached only (`xargs -i`, `watch -d`), where it takes no word after it. Every other rule sees it, as
  before, as a word the line does not spell out, and an f-string with no placeholder is a literal.
- **Words the line does not spell out.** Such a word, followed by one of its wrapper's own options, a setting, a
  number or `--`, is read as an option (under `env`, followed by a program name, as a setting). Anywhere else after a
  wrapper it is read as the program, and an address handed to that unknown program is `external-url`. That reading's
  findings are the line's.
- **Two readings are not made.** An option whose arity is not documented is not read as taking a following word that
  begins with `-` (`env f"--{o}" -u ssh` reads `-u` as an option), and a value the line does not spell out is not read
  as possibly empty (`f"-u{x}"`, `env -S f"{x}git fetch"`).
- The wrappers after the path given to `os.execv` are read as for the other calls.

### Readings that are not settled, and child interpreters

Where the reading above finds nothing but an address, and another reading makes a network program run (an option
whose arity is not documented, or `sudo -h`, read the other way, or a word the line does not spell out read as an
option), the line gets one `unresolved-call` that says so and names that program, in place of the address finding.

Code handed to a child interpreter that way (`python -c`) is read, once for each distinct code string in each file
(what it yields depends on the file it is in), so it is never left unread. What it does is reported as found when the
program after the wrappers is a word the line does not spell out, and otherwise named in that `unresolved-call`.

- The interpreter's own options are read as CPython reads them: clusters, attached values, `-W` and `-X` values
  (which take the next word, `-c` included) and an unlisted long option's value, ending at `--`, `-h`, `-V` or a
  `--help` option, after which no code runs. The `py` launcher's `-V:TAG` and `-3.14` select a version and are
  passed over. In an `env -S` string holding `${NAME}`, a `-c` after `-W` may also follow a value env drops, and is
  read that way when the reading that keeps every word finds no code.
- Interpreters include free-threaded and debug builds (`python3.14t`, `python3-dbg`, `python_d`), versioned PyPy and
  GraalPy.
- Code written as an f-string is read by its written parts when they parse. A `-c` after `-m mod` or a script name is
  that program's argument, and a module run with `-m` that executes its own `-c` is not read.
- The search is bounded: at most 64 such parses a line, and bounded in steps and in depth. When it stops before it is
  done, up to 64 literal words that could start a command are read as the program in turn, other than the value of an
  option of the wrapper they follow (read where the word before stands, a word the line does not spell out
  included). Only words that can start the program under some reading are taken (a word after the program has
  started, or an address, never is), each child interpreter's code is read once, and the line is flagged when one of
  them reaches the network or, past those 64, when the rest name a program this tool has a rule for: a network
  program, `git`, a shell, an interpreter or a browser opener.

### What is recorded

A program is recorded only as the wrappers' syntax reads it, and only when the line names it: never a word the line
does not spell out in the program's place, an empty name, an option word, a setting, a number or an address, and not
on a line that gets that `unresolved-call` or whose wrappers leave more than one place the program could start. A
program started with no arguments (`subprocess.run("pandoc")`) is recorded and gets no finding. An address on another
machine handed to such a program is reported as `external-url`, unless a rule names what the program does
(`rclone copy`).

### Containers the file builds

A method called on a container the file builds itself (a dict, list or set literal or comprehension, or a `queue` or
`collections` object bound once, named through an import the file does not rebind) is no longer reported as
`unresolved-call`, but only in a file that cannot change what that container or its module is. That is a file that:
- does not reach the module system at all: no `sys`, `importlib`, `builtins`, `__builtins__`, `__import__`, `imp` or
  `runpy`, as a name, an import or an attribute such as `os.sys`;
- cannot rebind any of its names (`globals()[...] = ...`, `from x import *`);
- uses no reflection a reading cannot follow (`setattr`, `delattr`, `vars`, `globals`, `locals`, `exec`, `eval`,
  `compile`, `__dict__`, `__class__`, `__mro__`, `__bases__`, `__code__`, a frame's globals, `mock.patch` or
  `monkeypatch`, `import_module`, `attrgetter`, `getattr` with a name the line does not spell out);
- stores no attribute named like a method it calls on one of its containers or like the class it builds one from
  (`q.get = ...`, `type(q).get = ...`, `m.Queue = ...`);
- does not rebind the module's name (by assignment, another import under that name, `for`, `with ... as`, a
  parameter, `except ... as`, a `def`, a `class`, a `match` capture, a type parameter or `del`) or patch it in place
  (`queue.Queue = ...`, `vars(queue)[...] = ...`);
- and sits in a tree that holds no module named `queue`, `collections`, `_queue` or `_collections` outside `.git` and
  `node_modules`, in folders the audit skips by name (such as `.venv` and `build`) included.

The rule reads one file: another module that patches `queue` is not seen.

### Other changes

A Python file holding an expression nested too deeply to follow is reported as `unparseable-source` (not analysed),
and the rest of the tree is audited.

An in-toto Statement's predicate keeps the signer the report names (`signature_algorithm`, `public_root`), which are
inside the signed body, so a Statement whose signature block is removed verifies `TAMPERED`, not `UNSIGNED`, and one
whose predicate names a signer other than its signature block is `TAMPERED`. A Statement with those two predicate
fields removed as well reads `UNSIGNED`, as a 1.1.3 Statement does; neither verifies. A Statement written by 1.1.3, whose
predicate names no signer, verifies as before. `signer.verify_signature` reads an `expected_root` written in capitals
or with surrounding space as the same root, as `verify_report` and the command line already did, and
`attestation.verify_statement` refuses a root that is not 64 hex digits with `ValueError`, as `verify_report` does,
for a Statement that is otherwise well formed and signed (a malformed or unsigned one is still `TAMPERED` or
`UNSIGNED`, as before). In `key_provenance`, a zip member compressed
with a method other than stored, deflate, bzip2 or lzma (zstd, method 93, which Python 3.14 can open and 3.13
cannot) is not opened on any Python, and its archive is listed as not fully read, so one tree gives one report. No
other detection rule, scope statement or report field differs from 1.1.3.

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
  key with different roots, `False` for consistent ones (a checkpoint of size 0 is consistent with every one), and
  `None` for different sizes with no consistency proof or one that does not verify. `IssuanceLog.create` makes a new log key and refuses a key file that already exists unless
  given `reuse_key=True`. A log key of height h signs at most 2^h checkpoints, the first of them the empty one. The
  checkpoints use this package's signer: a signed-note client that does not implement its signature type rejects them
  (this follows from the signed-note rules; no such client was run).
- `entrovouch.lms` also verifies the RFC 9858 parameter sets (SHA-256/192, SHAKE256/256 and SHAKE256/192). It signs
  with the RFC 8554 SHA-256 sets at heights 5 and 10 only. Its verifier refuses a public key whose tree and one-time
  key types use different hashes. It gives the published answer on the 8 LMS sigVer vectors NIST publishes in its
  ACVP-Server repository, and verifies the 4 test cases of RFC 9858 Appendix A (SHA-256/192, SHAKE256/192 and
  SHAKE256/256); that is not CAVP validation.
- `verify_report` raises `ValueError` when `expected_root` is given and is not 64 hex digits. 1.1.3 answered
  `TAMPERED`, the same answer a root that did not sign the report gets; the command line already refused it.

## 1.1.3

- A Python import of a radio or peripheral-link library is reported as `peripheral-link`: Bluetooth (`bleak`,
  `bluetooth`, `bluepy`, `pygatt`, `simplepyble`), mesh and Zigbee radios (`meshtastic`, `zigpy`, `zigpy_*`), a CAN
  bus (`can`), a serial line (`serial`) and USB (`usb`). Data can leave the device over such a link, so a tree whose
  only outbound channel is one of them is no longer `CLEAN`; the finding is not network egress and means review.
  These names are no longer listed in `unlisted_imports`. The scope statement names the kind, so every report's
  findings digest changes.
- `entrovouch.lms` verifies RFC 8554 LMS and HSS signatures, makes LMS signatures, verifies both test cases of
  the RFC's Appendix F and reproduces the second byte for byte. No CAVP or CMVP validation against NIST SP 800-208 has been run, it does not sign reports, and the report signer and the
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

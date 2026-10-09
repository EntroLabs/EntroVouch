# What is read, and how

The detailed reading rules of `no_egress_auditor`. Each rule
is a statement of scope: what the auditor reads, how it reads it, and where it stops. `CLEAN` still means nothing
came to our attention; nothing here turns the analyser into a proof.

## JavaScript, TypeScript and markup

In JavaScript and TypeScript a quote straight after a letter (`Don't` in JSX text) opens no
string unless the word is one a string may follow (`from"https"` in minified code), a `'` or `"` string
ends on its line, a backquote may be JSX text or open a template (`sql` and a space before a backquote), and either
misreading would hide the code up to the next one: in a file with a closing or a self-closing tag anywhere in it the
file is read as plain JavaScript and as JSX, and what any reading keeps as code is checked. The JSX reading follows
the elements: a tag where an expression may start (`return <p>`, `=> <li>`, `(<div`, inside an attribute's braces)
opens an element whose text, up to its closing tag, is text whatever it holds (an apostrophe, a backquote, `/*`),
apart from its `{...}` expressions and the tags inside them; outside the elements it follows, a backquote after a
plain word and a space or straight after a tag's `>` is text. An element has text only where the file closes it
somewhere (`</Name>`), so a type parameter list (`const pick: <T>(xs: T[]) => T`) is not taken for one, and a bare
`<Name>` straight before `(` is read both as an element and as type parameters. The JSX reading is kept,
with the others' code where it keeps nothing. Elsewhere every
backquote opens a template (as is a
backquote or `/*` never closed, and `/*` straight after a name, `src/*`), and a regular expression is recognised by
what precedes it, the `)` of an `if`, `while` or `for` condition included; this is a heuristic, not an ECMAScript
parser, and the words of JSX text are read as code (`<p>Don't fetch(u) here</p>` is reported as a call). An import in a page's or component's `<script>` (an attribute may hold `<` and `>`), an Astro component's
front matter or an MDX file's top-level `import` is read as the same import in a `.js` file. Deno's `npm:x`
names the npm package `x`; a `jsr:` package is listed in `unlisted_js_imports`.

## Scripts, build files and Python

- **Scripts and build files are read for commands, not parsed.** Shell, PowerShell and
  batch scripts, Dockerfiles, Makefiles, `tox.ini` and pipeline definitions (GitHub Actions workflows and
  `action.yml`, GitLab (with the files it includes by path), Azure Pipelines (`azure-pipelines*.yml`, with the template files it names),
  Bitbucket, CircleCI, Jenkins, Travis, Drone, AppVeyor, Buildkite,
  Cloud Build, CodeBuild, Cirrus, Woodpecker, Codemagic, Bitrise) are checked
  line by line for download tools, package installers (PowerShell's `Install-Module` and `Save-Module`
  among them; and, where a command starts, the package managers, build tools and fetchers of other ecosystems:
  a bare `yarn`, `bun`, `pnpm dlx`, `poetry`, `pipenv`, `pdm`, `conda env create`, `bundle`, `composer`, `go mod
  download`, `python -m build` (not with `-n`), `cargo`, `mvn` and `gradle` (not with `-o`/`--offline`), `dotnet restore`, `terraform init`, `nix`,
  `rustup`, `nvm`, `pyenv`, `rclone`, `s3cmd`, `skopeo`, `ping`, `whois`, `nmap` and others; a build tool is reported
  as downloading what is not already on the machine) and remote git commands, `git lfs pull` among
  them (`script-network-command`), where a command starts: at the start of a line or after `&&`, `;`, `&`,
  `|` or `$(`, behind a key such as `run:`, a Dockerfile `RUN`, a wrapper such as `sudo -u deploy`,
  `busybox`, `env`, Windows `start /b`, PowerShell's `Start-Process` (read as PowerShell binds its parameters:
  `-FilePath` or the first positional is the program, `-ArgumentList` or the second its words) or `Invoke-Expression` (the string it runs), or a launcher such as `python -m`, `docker exec` or
  `git submodule foreach`. A command that opens an address on another machine in the default browser
  (`Start-Process "https://..."`, cmd's `start "" https://...`, `xdg-open`, `open`, the same in an argv list) reaches
  the network. A Dockerfile instruction in exec form (`RUN ["pip", "install", "requests"]`) is read as the command
  its words make.
  Each command of a line is judged on its own: one that asks a program about itself, installs offline or reaches
  only this machine (`curl --version && curl ... | sh`), or that only names a program (`hash curl && curl ... | sh`),
  does not speak for the commands after it. A line is reported once, for the first of its commands that reaches the
  network (`scp a host:/b && ssh host deploy` is reported for `scp`). An offline flag
  after `--`, or after the program a launcher runs (`npx some-cli --offline`, `go run ./cmd/x -mod=vendor`,
  `uv run python app.py --offline`), or after the quote that closes a command written in quotes
  (`bash -c 'yarn install' --offline`), is not the inner program's and does not make it offline. A program named by a
  variable with a default (`${CURL:-curl}`, `${GIT:-/usr/bin/git}`) is read as that default. A program may be
  named by a path
  (`/usr/bin/curl`), with `.exe` or `.cmd` (`git.exe pull`, `npm.cmd ci`), or in quotes as PowerShell's `&` and
  cmd run it (`& "C:\Program Files\Git\bin\git.exe" pull`); a Makefile recipe's `-`, `@` and `+` prefixes are set aside,
  and a program's own options and variables may stand before its subcommand (`git -C dir pull`, `npm --prefix web
  ci`, `terraform -chdir=infra init`, `pip $PIPFLAGS install x`). Dockerfile instructions are read in
  any case and after `ONBUILD`, a `HEALTHCHECK` command is a command, an `ADD` whose
  source is an address is a download too, and `FROM` an image or `COPY --from=` an image (not an earlier
  stage's name, not `scratch`) is a fetch the Dockerfile declares (`declared-remote-source`). Cloud, cluster, container and database clients (`aws`, `gcloud`,
  `gsutil`, `az`, `kubectl`, `helm`, `docker`, `podman`, `docker-compose`, `psql`, `mysql`, `pg_dump`, `mysqldump`, `mongodump`, `redis-cli`, `openssl`, `hg`, `svn`,
  `socat` and others) are judged with their arguments by the rules an argv list in Python is judged by
  (`docker logs`, `kubectl config`, `kubectl version --client`, `helm template ./chart` and `svn status` act on
  this machine, and any svn subcommand given a repository address reaches it; `docker run`,
  `build` and `compose` are reported as pulling an image when it is not already here (one built on this machine
  is, and nothing is with `--pull never` among docker's own options, before the image); a docker command after `DOCKER_HOST=` naming another machine talks to that machine; a database client
  given no host, a host on this machine or a socket directory is `loopback-call` (every host the command names
  counts: a later connection string or `--host` naming another machine decides; `ssh`, `scp` and `rsync` to this
  machine are not, when a jump host, a proxy command, a `HostName` option, a configuration file (`-F`) or port
  forwarding (`-L`, `-R`, `-W`, `-D`) may send traffic elsewhere), unless the file sets the host in
  the environment (`PGHOST`, `MYSQL_HOST`), loads a settings file into it (`. ./prod.env`, `set -a; . env`,
  `eval "$(cat prod.env)"`, `source <(grep -v '^#' prod.env)`, `env $(cat prod.env) psql`, `export "$line"` in a
  loop, `dotenv -f prod.env run -- psql`), or the command names a service file or an options file, which may name
  any host; `nc -l`, a socat that only listens and `python -m http.server` are `inbound-listener`; `git clone` of a path here and `git
  submodule status` reach nothing). PowerShell's .NET clients (`System.Net.WebClient` and its `.DownloadFile(`,
  `HttpClient`, a socket, a WebSocket) and its mail, remoting and lookup cmdlets (`Send-MailMessage`,
  `Invoke-Command -ComputerName`, `Test-NetConnection`, `Resolve-DnsName`) are commands, as is a UNC path
  (`\\server\share`) in a PowerShell or batch line or a machine given to Windows' remote administration tools
  (`psexec \\server`, `psexec @list.txt`, `net view \\server`, `sc \\server query`, `tasklist /s server`), any cmdlet given
  another computer (`-ComputerName`, `-Session`, `-ToSession`), `winrs -r:`, `mstsc /v:`, `wmic /node:` and the
  `/server:` tools, and in Python a UNC path given to a call that opens, copies or
  lists it (`open(r"\\fs01\x")`, `shutil.copy`, `Path(...).read_text()`, a path built from one with `/`, `os.path.join`, `+` or an f-string), or one
  written with forward slashes (`//fs01/share/x`), which is reported as reaching another machine on Windows only
  (through `smbclient`, on every system); `-EncodedCommand` text, wherever it stands among the options,
  is decoded and read. Bash's `/dev/tcp` is a connection. An install with
  `--no-index` or `--offline` that names no address (no `--find-links https://...`, no `git+...`, no wheel's URL), or
  with `--no-deps` naming only local files, reaches nothing and is not reported. In a Makefile, `$(shell ...)` and a `!=` assignment run their command when make reads the file.
  Deploy and publish commands (`vercel`, `netlify deploy`, `firebase` (its deploy and login), `fly deploy`, `sam deploy`, `cdk
  deploy`, `serverless deploy`, `heroku`, `hatch publish`, `flit publish`) and `ansible-playbook` are commands
  too, as are `uv run`, `hatch run` and `pixi run`, which make the environment first. **The programs are a
  list.** A program it does not name (an in-house deploy script, a tool newer than this build) gives no finding
  and, unlike an unknown import, which `unlisted_imports` names, is not named in the report. The same program named elsewhere on a line, where a command
  could take it as an argument (`mytool curl x`, `--downloader wget x`), is
  `script-network-word`: reported, with a claim that stops at the name. A name in text the line
  only prints (`echo`, `printf`), a value written after `=` or `,`, and a download tool's name
  with nothing after it (a word in a list of packages) are not reported. Python handed to an interpreter
  where a command starts, as `python -c "..."` (any quoting, `$'...'` and `$"..."` included; `py -3 -c` too),
  as a here-string (`python3 <<< '...'`) or as a here-document given to an interpreter with no script or with
  `-` or `/dev/stdin` as its script (`python3 - "$URL" <<EOF`, `uv run --with x python - <<EOF`,
  `docker exec -i app python - <<EOF`, `<<EOF python3`, a Dockerfile's `RUN python3 <<EOF` or `RUN <<EOF` whose
  body starts with a Python shebang, `python3 -c "$(cat <<EOF ...)"`, a second here-document on the same line,
  one inside a pipeline's block (`run: |`) or a recipe, read at the margin the block strips; the delimiter in any
  quoting, `<<\EOF`, `<<'EOF'` or `<<"E"OF`; a body with no terminator, which in a script the shell reads to the
  end of the file or of the body around it, checked as Python there while its lines stay command lines, so text
  taken for an opener cannot hide what follows; the interpreter's output sent elsewhere,
  `python3 - <<EOF > out.json`),
  piped in by `echo` or `printf`, or written to a `.py` file by a here-document (`cat > x.py <<EOF`, `tee x.py`,
  a Dockerfile's `COPY <<EOF /app/x.py`), with the interpreter named by a path (quoted or not), as `pythonw` or
  `ipython`, or by a variable (`$PYTHON`, `"${PYTHON:-python3}"`, make's `$(PYTHON)`), or in a Dockerfile's exec
  form (`RUN ["python", "-c", "..."]`), is checked as Python, quotes undone the
  way the shell undoes them; a command the shell runs inside it first (`$(...)`, a backquote, make's
  `$(shell ...)`) is also read as a command, and when it does not parse as Python the line is read as a script
  line. In a pipeline file a here-document ends inside its own step's block. A body read by a loop that runs each
  line (`while read c; do $c; done <<EOF`), or kept in a variable and run later (`CMD=$(cat <<EOF)`, then
  `$CMD`), is read as text. A GitHub Actions step whose shell is Python (`shell: python`, `python3 -u {0}`, or a workflow's or job's
  `defaults: run: shell:`) runs its `run:` as Python, and it is read as Python. Code handed to an action as an
  input (the JavaScript of `actions/github-script`'s `script:`) is not read; only its addresses are. Neither is
  Python held in another file's strings (a `package.json` script, a task runner's table in `pyproject.toml`, a
  PowerShell here-string piped to Python, a Makefile `SHELL` set to Python). A justfile recipe whose body starts
  with a Python shebang is read as Python. A Compose file (`compose.yaml` or
  `docker-compose.yml`) is read too, and an `image:` its service does not build here is a declared source. A
  here-document handed to `su`, `chroot` or a shell named by a variable (`$SHELL`, `${SHELL:-sh}`, `$BASH`, `$0`)
  is read as commands. A body written to a file is read as text unless the file is a script, a build recipe or a
  pipeline file (`> run.sh`, `> Dockerfile.prod`, `>> tox.ini`, a Dockerfile's `COPY <<EOF /entry.sh`) or has no
  extension (a well-known text file such as `/etc/motd` or `LICENSE` excepted). In a Jenkinsfile (`Jenkinsfile`,
  `Jenkinsfile.*`, `*.jenkinsfile`) each `sh`, `bat` or `powershell` step's string is a command, the `httpRequest`
  step, a checkout (`checkout scm`, the `git` step) and a Groovy read of an address (`new URL(u).text`,
  `.toURL().openStream()`) are commands, and a
  `docker { image '...' }` agent is an image the job runs in (`declared-remote-source`). A line
  continues with the file's own character: `\` in a POSIX shell and a Dockerfile (or what its `# escape=`
  directive names), `^` in cmd, a backquote in PowerShell; `powershell -Command` and `cmd /c` run what
  follows.
  A pipeline's `uses:` step (an action the CI service fetches) is not reported. No shell is parsed. A variable is
  read only where it names a program: one with a default written in place (`${CURL:-curl}`); one a shell, batch or
  PowerShell script sets to one word, or a Dockerfile's `ENV` or `ARG` sets once (a later assignment outside a
  conditional replaces an earlier one); and a Makefile variable the file sets (`=`, `:=`, `?=` when unset, `+=`,
  `define`, a value naming its own old one, conditional branches read once per value). A command whose program is
  a variable the file does not resolve, run with a subcommand that fetches (`$(INSTALLER) install`, `"$VCS" pull`),
  is `unresolved-call`: which program runs is not shown. Any other variable is left as written.
  Configuration data (`.json`, `.yaml`, `.toml`), lockfiles and other languages (Go, Rust,
  Java, PHP, Ruby) are not read: they are counted in `not_scanned`.
- **Python is read the way Python reads it.** The file's encoding cookie and BOM are
  honoured (so a `# coding:` line cannot hide an import from the auditor that the interpreter
  executes), the extension is matched without regard to case, a file with no extension, `.cgi` or `.fcgi` and a
  Python shebang (`python`, `pypy`, or `uv run`) is Python, as are `SConstruct`, `SConscript`, `.wsgi`, `.tac` and
  `.rpy` files (a Python shebang on any other extension is not read), notebook code cells are Python, in nbformat 3
  and 4 (a `%` or `!` counts as a magic or an escape only where a statement starts, never inside brackets or a
  string; with `!`, `%system`, `%sx`, `%pip` and
  `%uv` lines reported, `%load` and `%loadpy` of an address reported as a fetch (of a variable, as not
  resolved), `%sql` and `%%sql` with a connection string reported as a connection, a cell under `%%bash`, `%%sh`
  or `%%script` reported as a program, a cell under `%%html` (or its alias `%%HTML`), `%%svg` or `%%markdown` read as markup and one
  under `%%javascript` as JavaScript, a cell in another language (`%%R`, `%%julia`, `%%sql`, `%%cython` and
  the like) reported as not analysed, a `%%writefile` cell's findings marked as text written
  to a file (a cell written to a script read as that script, one written to another file that is not Python as
  text), the code after `%time`, `%timeit`, `%prun` and `%debug` read as the Python it is, and the
  modules `%aimport`, `%load_ext`, `%reload_ext` and `%run -m` load read as imports), the IPython
  calls an exported notebook holds (`get_ipython().run_cell_magic(...)`, `run_line_magic(...)`, `magic(...)`,
  `ex(...)`, `run_cell(...)`, through a name the shell is bound to as well) are read the same way, Python inside
  them included, and `.pth` start-up lines are Python. A `.py` file saved by Databricks (`# Databricks notebook
  source`, its `# MAGIC` lines) or by Jupytext (`# %%` or `#%%` cell markers) is read as the notebook it is, its
  text cells (`%md`, `# %% [markdown]`) as markup: an escape or
  magic it holds as a comment (`# !wget ...`, `# %pip install x`) runs when the notebook does and is read as one,
  so in such a file a comment that starts with `# !` is read as an escape. An IPython help request (`obj?`,
  `??obj`) runs nothing. A configuration that names a class to load where a
  framework loads it by name (a dict's `class` or `()` key, as in logging's dictConfig; a `MIDDLEWARE` or
  `INSTALLED_APPS` list) is reported when the class is a network handler or comes from a network package
  (`'logging.handlers.HTTPHandler'`, `'rollbar.logger.RollbarHandler'`); the same text elsewhere is text. A network
  submodule reached through its package's name (`import http`, then `http.client.HTTPSConnection(...)`) is a
  network import. A name lookup (`socket.getaddrinfo`, an event loop's `getaddrinfo` or `getnameinfo`) asks a
  resolver and is reported as one, and as `loopback-call` when the name is this machine's. A notebook
  in any other layout, or one whose kernel speaks another language (its metadata says R, Julia...), is not
  analysed, and says so. A markdown cell is read as markup, and a cell's saved HTML, SVG, markdown or JavaScript output as
  markup or JavaScript: what a notebook shows and runs when it is opened. `cbom` and `key_provenance` read
  Python in all of these forms, every cell except one handed to another program or displayed as markup
  (`%%html`, `%%markdown`, `%%latex`, `%%svg`, `%%javascript`); a finding in a notebook is at its cell's number.
  Text is decoded the way the program that reads it decodes it: UTF-8, or UTF-16 and UTF-32 by their byte-order
  mark (Windows PowerShell runs a UTF-16 script, pip reads a UTF-16 requirements file); without a mark, as UTF-8, which is how pip reads it. Importing
  `_winapi` or `_posixsubprocess`, private modules that start processes directly, is reported. A local module shadows an import only when the scan reads
  it: a link or a link stand-in with that name shadows nothing.

## `.pth` files, local modules and newer syntax

- **`.pth` files are read as what they are.** Python runs every `.pth` line that begins
  with `import` at interpreter start. Each such line is reported as `startup-exec` and
  analysed like source. A `.pth` that an install step writes later is not in the tree and
  is not seen. Binary files that share the extension (model checkpoints) are not scanned.
- **A local module of the same name is not a network import.** `motor.py` at the top of
  the audited tree shadows the package; the name is listed in `shadowed_imports` rather than
  vanished. Audit a folder above it and `motor.py` is no longer at the top, so `import motor`
  is reported.
  The same holds for the tree's own top-most package: auditing the `celery` repository
  does not report every `from celery import ...` in it as a dependency on celery, and an import of a
  module the tree holds at its root or under a source folder is the tree's own code where Python would import it
  from the tree: under a top-level package of the tree's own, in an ordinary package inside a namespace folder a
  project in the tree installs (`nats-core/src/nats/client/` beside `nats-core/pyproject.toml`), or under a
  namespace several distributions share (`google`, `azure`, `opentelemetry`). A module lying loose in such
  folders (`src/twisted/plugins/x.py`, a plugin for an installed package) is reached through that package. A package whose `__init__.py` extends its path shares its name with
  what is installed, so only the modules the tree holds are its own (a name imported from the package itself,
  `from azure import x`, is taken as the tree's, since its `__init__.py` is). A namespace folder no project here installs,
  beside an installed ordinary package of that name (`src/boto3/s3/` with no `__init__.py`), is not, since the
  installed package wins. A package nested inside
  another package (a vendored copy) does not get this treatment.
- **The audit is as new as the Python that runs it.** A file written in syntax newer
  than the running Python is `unparseable-source`, not analysed. Every report records
  `parser_python`; run the audit with a Python at least as new as the code. On files
  every supported version can parse, the findings digest is the same under each. The same holds
  for letters: each Python carries its own Unicode version, so a letter added to Unicode after the
  oldest supported Python's version is a letter only to a newer Python. The JavaScript and link rules
  decide by ASCII and are unaffected; in Python source and in patterns that match words, a tree that
  writes such a letter right against a name can be read differently by different Pythons.

## Arguments, addresses and what a finding says

- **An argument is read when the source spells it out.** A literal list, a literal
  string, `"curl -s x".split()`, or a name bound once in the file to one of those. A
  command assembled at run time is not resolved.
- **A finding says only what the line supports.** A request or client object built from a
  literal address is `network-target` (nothing is sent at that line), not a call. A call or
  a download command, a connection string or a port check whose literal address is this
  machine (`localhost`, `127.0.0.1`) is `loopback-call`: network code, and nothing leaves the machine at that line.
  A connection string for this machine is not read that way when the host may be set somewhere else: a keyword on the
  call (`host=`, `service=`, a `connect_args` that sets a host, keywords spread from a mapping with `**`), or, for a
  string that names no host (`postgresql:///db`), a service or options file in it (`?service=prod`), the file naming
  the variable libpq or the MySQL client reads for one (`os.environ["PGHOST"] = ...`), loading a settings file into
  the environment (`load_dotenv()`) or updating the environment from a mapping (`os.environ.update(cfg)`). A name the file may rebind as a whole
  (`from settings import *`, `globals().update(...)`, `setattr(sys.modules[__name__], ...)`, `exec(...)`, or the
  namespace handed to a call) is not read for the literal it was first bound to. A
  protocol library (`h2`, `h11`) is evidence of a network stack, not a connection. In a
  page, only what a browser acts on counts: tags, scripts, styles and template
  expressions. Text a page displays, vocabulary identifiers (`itemtype`, RDF), metadata
  tags and an address on this machine (`localhost`, `127.0.0.1`) are not external
  references. An anchor is `external-link`: nothing loads until someone follows it. A URL in
  markup is `html-external` (a load) only where the page fetches from it: a `src`, `srcset` or
  `poster`, an object's `data`, the `href` of a stylesheet link or of an SVG `use`, `image` or
  `script`, a CSS `url(...)` or `@import`, a refresh, or a script line that fetches or navigates.
  Anywhere else in markup it is `external-url`, which says no load was shown. An address is read as a browser reads
  it, tabs and line breaks inside it dropped and a backslash taken for a slash (`https:\\host\p.png`). A `data:` URI
  fetches nothing; one that holds script or a page, written out or base64-encoded, is `dynamic-exec`, its code not
  read (in JavaScript too: `new Worker("data:text/javascript,...")`), and an SVG image or an XML document counts only where it is
  opened as a document (a frame, an object, an embed), never in an `img` or a CSS `url(...)`. A postMessage origin or an
  origin comparison is not a request; on a line that also calls `fetch`, a WebSocket or `sendBeacon`, or jQuery's
  `$.ajax` (or `jQuery.ajax`), the call is what is reported. A character reference for a letter, a digit or an
  address's punctuation inside a tag is read as that character (`h&#116;tps://`, `https:&#47;&#47;`); CSS escapes (a
  `\68` for an `h`) are not decoded.
- **A call is reported where the file shows its address.** A fetch, a connection or a
  download by a call this tool knows by name, whose address is written in the file (a literal,
  or a name bound once in the file to one), is reported at its line. That covers `http`,
  `https`, `ws` and `ftp` addresses, and object-store, hub, remote file system and stream
  addresses (`s3://`, `gs://`, `az://`, `hf://`, `hdfs://`, `rtsp://` and the like) handed to a
  reader such as `read_csv`, `load_dataset` or `VideoCapture` or a writer such as `to_csv` or `to_parquet`, and a
  database connection string handed to pandas' `read_sql` or `to_sql`. An address handed to a call the
  tool does not know by name (a client's own constructor) is reported through the import of
  that client's package, or, when no list names the package, appears in `unlisted_imports`.
  A call whose address is computed while running
  (`requests.get(url)`, `urlopen(req)`, `session.post(u)`) gets no finding at its line: the
  import of its package is what reports it. So the import findings answer *whether* the code
  can reach the network; the call findings are a partial answer to *where*.
- **A call is judged by what it is called on.** `get`, `post`, `request` and the other
  fetch-named methods given an address are reported as `network-call` only when the object they are called on
  traces back, within the file, to a network package (`requests.Session()`, a name bound by
  `with httpx.Client() as c`, a parameter annotated `httpx.Client`, `self.s` assigned from one).
  When it does not (a parameter with no type, a fixture, a cache, a mapping, the project's own
  helper), the call is `unresolved-call`: still reported, and the sentence says that whether it
  reaches the network is not shown. Tracing stops at the file: a client handed in from another
  file is not followed. A method named like asyncio's server or connection call is taken as
  asyncio's in a file that uses asyncio or on an event loop; a server-named one on an object
  the file does not trace, with no asyncio in the file, is `unresolved-call`. An address with
  no host (`ftp:///x`) names neither this machine nor another one, and is `unresolved-call`. The SAX parser's `parse`
  (positional or `source=`, on the module or on a parser the file binds, `self.p` included) fetches its source with
  urllib when it is an address: given a literal file name, an open file or an `InputSource` holding a stream it
  reads this machine, given anything else it is `unresolved-call`. (`xml.dom.pulldom.parse` opens a name as a file.)

## What is listed as not read

- **A file that will not parse is reported, not skipped** (`unparseable-source`). An
  unanalysed region is not "nothing found." A warning the audited file would raise when
  compiled (an invalid escape in a string) is that file's, not the auditor's: it is not
  printed, and running Python with warnings turned into errors does not change a report.
- **What was not read is listed.** Every no-egress report carries `not_scanned`: the directories the
  scan skips by name wherever they sit inside the tree (`.git`, `build`, `dist`, `venv`,
  `.venv`, `node_modules`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.hypothesis`,
  `.ruff_cache`, `.tox`, `.nox`, `.ipynb_checkpoints`, `.eggs`, `*.egg-info`, `htmlcov`, `_build`, and a
  worktree's `.git` file) with the
  number of files under each, the files of types it
  has no reader for, by extension, and the links it met and did not follow: symbolic links,
  Windows junctions, and a directory reached a second time through a mount. A link that Git
  on Windows checked out as a one-line text file naming its target is counted as a link too:
  a small file whose whole content is one relative path, written only with letters, digits and
  `._~@+-/`, naming a file or folder inside the tree spelled exactly as its folder lists it, is counted
  as a link and not read, as is one naming a path into or onto a skipped directory (`build`, `node_modules/...`)
  whether or not that directory is there. That is decided from the tree alone: where the tree sits and whether the
  file system ignores case make no difference. A file judged by its size must keep that size while
  it is read, or the run stops. Text of that
  shape cannot import, call or name an address. In a manifest a bare word is a declaration, so
  there the text must be a path with a `/`, which pip reads as a location and not a package.
  `files_not_read` is the count of all three, printed beside the files scanned, so a `CLEAN`
  that rests on one file out of forty says so. A tree in which nothing was read is `NOT-ANALYSED`,
  exit 2, never `CLEAN`. Compiled modules, shared libraries, executables, wheels, archives
  and pickled objects in the tree are `unanalysed-artifact` findings; an executable or a shared library with no
  extension or a version for one (`bin/tool`, `libx.so.1`), or one named as a script, a JavaScript, TypeScript or markup file
  (`tool.sh`, `app.js`), is recognised by its first bytes (ELF, Mach-O, PE).

## Manifests

- **A declared dependency is not a call site.** `stripe` in `pyproject.toml` is
  `declared-network-dependency`. Names the import list does not know stay invisible
  here too: declared-intent uses the same list; it does not secretly complete it.
  Manifests read: `pyproject.toml` (PEP 621, build requirements, dependency groups, dynamic dependencies and optional
  dependencies read from the files `[tool.setuptools.dynamic]` or Hatch's requirements-txt hook names, in the scope
  the manifest gives them (a file named like a development file is then the product's), and otherwise recorded as
  not read; a dependency list that is not a list, as PEP 621 requires, is recorded as not read,
  Poetry, uv, PDM sources and groups, Hatch environments, Pixi dependencies), requirement and constraint files
  (a `requirements/` directory and `-e` lines included; in the SBOM a constraints file adds no component, and a
  development, test, lint or docs requirements file is not the product's), `setup.cfg` (with its `[easy_install]` index and the files a `file:` value names),
  `setup.py` literals (`setup` imported under any name; a list or a string a name is bound to, in each branch of an
  `if` too, with what `.append`, `.extend`, `+=`, `.update` and an item assignment add to it and what `.remove` takes
  out, either branch of a condition, a requirements string over several lines, `"a b".split()`, a comprehension
  that copies a list, and the keywords of a dict passed as `**`; each name is followed once and a value is read to
  10,000 items, so a file whose names double costs a bounded time; an `install_requires` computed as setup.py runs is read from a requirements file the script names beside it
  or in a folder it names, or from a function returning a list literal, and otherwise recorded as not read, as is a
  requirement list or `extras_require` changed with a value this tool does not resolve; test and build requirements
  are read where they are literals and their gaps are not recorded, as they are not the product's), `Pipfile`, conda environment files, `package.json`
  (with `overrides`, `resolutions` and `pnpm.overrides`, and a script that runs `node -e` code reaching the
  network), `tox.ini` `deps` (each package once, at its first line), a noxfile's `session.install(...)`, `.npmrc`,
  `pip.conf`, `.gitmodules`. Lockfiles
  are not read. Requirement files
  are read the way pip reads them: a line ending in `\` continues on the next, and a `-r` or `-c`
  include is recognised in every spelling pip accepts (`-rfile`, `--requirement=file`, an
  unambiguous abbreviation). It is followed to a file the scan itself reads; one outside the tree,
  behind a link or in a skipped directory is listed as not read, and one given as a URL is a remote
  source. conda flow lists (`dependencies: [a, b]`) read like block lists. In the SBOM only an exact
  version is a version: a range, a wildcard, a tag such as `latest` or a partial version is
  `unknown`, and a dependency installed from a file, a link, a repository, a URL or an npm alias
  gets no registry package URL, nor does one a Poetry, Pipfile or uv table takes from git, a URL, a path,
  another index (Poetry's `source =`) or the workspace: a registry name would point a scanner at whatever
  package of that name the registry holds. A requirement given only as a path or an archive's address (`./pkg`,
  `-e ../lib`, `dist/x.whl`, `file:../w`, `https://host/u-1.0.tar.gz`) names no package in the file: it is listed
  among the document's unknown fields, not as a component (the project itself, `-e .`, is neither). A Poetry version written bare (`2.31.0`) is exact, as Poetry reads it,
  and a name declared in two tables is reported at each. A package URL's version is the normal form PEP 440 gives
  it (`01.0` is `1.0`), percent-encoded (`+local` is `%2Blocal`), and its name is lowercased with `_` written as
  `-`, as the package-url rule for PyPI says (`pkg:pypi/zope.interface`).

## Inbound and outbound

- **Outbound and inbound are different findings.** A server started through
  `socketserver`, `http.server`, `create_server` or `asyncio.start_server` is
  `inbound-listener`, never egress. A raw socket's `bind` and `listen`, and a web framework's
  `run(host=...)`, are not reported at their line; the import of their package is.


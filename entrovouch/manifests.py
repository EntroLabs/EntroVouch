"""The tree walk and the declared-dependency manifests.

Shared by every scanner, so the four tools cannot drift onto different readings of
the same tree or the same pyproject.toml.

`tree_files` is the one place a tree is walked. It decides what is skipped by the
path INSIDE the tree (never by where the tree sits on disk), does not follow
symbolic links, and returns files in one order on every operating system.
"""
from __future__ import annotations

import ast
import bisect
import functools
import warnings
import configparser
import json
import os
import posixpath
import re
import stat
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path
from . import _reads

# Directories skipped by name wherever they appear inside the audited tree.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build",
    # tool caches and tool-made environments
    ".mypy_cache", ".pytest_cache", ".hypothesis", ".ruff_cache", ".tox", ".nox",
    # what installing in place and running a notebook leave in a checkout
    ".ipynb_checkpoints", ".eggs",
    # coverage.py's HTML report and the documentation builders' output (Sphinx, Jupyter Book)
    "htmlcov", "_build",
}


def is_skipped_dir(name: str) -> bool:
    """A directory skipped by its name: tool output, caches, environments, git's own data. `x.egg-info/` is what
    `pip install -e .` writes."""
    return name in SKIP_DIRS or name.endswith(".egg-info")

MANIFEST_EXACT = {"pyproject.toml", "package.json", "setup.cfg"}
# Read for declared dependencies or for the remote sources they name.
MANIFEST_EXTRA = {"pipfile", "environment.yml", "environment.yaml", ".npmrc", "pip.conf", "pip.ini",
                  ".gitmodules", "setup.py"}
# Directories whose .txt and .in files are requirement files whatever they are called.
_REQUIREMENTS_DIRS = {"requirements", "requirements.d", "reqs"}
# Requirement-file options and specifier forms that name a host to fetch from.
_REQ_INCLUDE_RE = re.compile(r"^(?:-r|--requirement|-c|--constraint)[=\s]+(\S+)", re.IGNORECASE)
_EDITABLE_RE = re.compile(r"^(?:-e|--editable)(?:\s+|=)", re.IGNORECASE)
_VCS_URL_RE = re.compile(r"^(?:git|hg|svn|bzr)\+[a-z]+://|^(?:https?|ftp)://", re.IGNORECASE)
_NPM_REMOTE_RE = re.compile(r"^(?:git\+|github:|gitlab:|bitbucket:|https?://|git://|file:)|^[\w.-]+/[\w.-]+(?:#|$)")
_INSTALL_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}
_SCRIPT_NET_RE = re.compile(r"(?<![\w.-])(curl|wget|aria2c|nc|ncat|ssh|scp|rsync|git\s+(?:clone|pull|fetch)|"
                            r"npx|pip3?\s+install|(?:npm|pnpm|yarn|bun)\s+(?:install|i|ci|add)"
                            r"|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)(?![\w.-])", re.IGNORECASE)
_URL_VALUE_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*)://", re.IGNORECASE)


def _parse_quietly(src: str, filename: str = "<unknown>") -> ast.AST:
    """`ast.parse` with the audited file's own compile-time warnings set aside. An invalid escape in
    someone else's string (`"\\d"`) is their warning, not this tool's output; and under `-W error` it
    would turn a file that parses into one reported as unparseable."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(src, filename=filename)



@dataclass(frozen=True)
class DeclaredDep:
    """One requirement line (or package.json key) as the author wrote it."""
    file: str
    line: int
    name: str
    spec: str
    ecosystem: str          # "pypi" | "npm" | "conda"
    scope: str = "required"  # "required" | "optional" | "dev" | "build"
    extra: str = ""         # optional-extra or group name, if any
    source: str = ""        # where it is installed from when not the registry: git, url, path, index, workspace


@dataclass(frozen=True)
class ManifestError:
    file: str
    line: int
    detail: str


@dataclass(frozen=True)
class RemoteSource:
    """A manifest line that names a host something will be fetched from, or a script
    that fetches when it runs. Not a dependency; a declared network action."""
    file: str
    line: int
    kind: str       # index-url | url-requirement | vcs-requirement | install-script | script | registry | submodule
    detail: str


@dataclass
class ManifestScan:
    deps: list
    errors: list
    files: list       # (Path, posix rel) of every manifest read
    remotes: list     # RemoteSource
    paths: list = field(default_factory=list)   # (posix rel, line, path): requirements given only as a path


@dataclass
class TreeWalk:
    files: list       # (posix rel, Path), in the canonical order
    skipped: dict     # "path/of/skipped-dir/" -> number of files under it
    symlinks: int     # symbolic links met and not followed


def _sort_key(rel: str) -> bytes:
    return rel.encode("utf-8", "backslashreplace")


# ASCII on purpose: `\w` follows the Unicode database of the running Python, so a name in a newer script would be a
# link on one version and a file on another
_LINK_TEXT_RE = re.compile(r"(?:\.\.?/)*[A-Za-z0-9_.~@+-]+(?:/[A-Za-z0-9_.~@+-]+)*")


_LINK_TEXT_MAX = 1024


def _is_link_placeholder(full: str, root: str, listing: dict) -> bool:
    """A file that is a symbolic link checked out as text: one short line, no line break, naming a
    relative path that exists inside the tree. `docs/config.py` holding `../app/config.py` is the usual shape.

    Decided from the tree alone, so the same tree gives the same answer wherever it sits and on every file system:
    the path must stay inside the tree, and each part of it must exist with exactly that spelling (a listing is
    compared, so a file system that ignores case does not make `MAIN.PY` name `main.py`)."""
    try:
        if os.path.getsize(full) > _LINK_TEXT_MAX:
            # decided by size alone: a later read of this file in the run must agree, or the run stops
            _reads.require_more_than(full, _LINK_TEXT_MAX)
            return False
        raw = _reads.read_bytes(full)
    except OSError:
        return False
    if len(raw) > _LINK_TEXT_MAX:
        return False
    if not raw or b"\n" in raw or b"\r" in raw or b"\0" in raw:
        return False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    # Only the characters of a path: no spaces, brackets, quotes, `=` or `:`. Text made of these alone cannot import a
    # module, call a function, pass an argument or name an address, so treating such a file as a link hides nothing
    # this tool would report.
    if not _LINK_TEXT_RE.fullmatch(text):
        return False
    if text == os.path.basename(full) or text.startswith("-"):
        return False        # names itself, or is an option (`-rdeps/net.txt` in a requirements file is an include)
    # In a manifest a bare word (`requests`) or `.` is a declaration, not a link. A link there names another file
    # by a path with a separator, which pip reads as a local path and which names no package.
    if "/" not in text and is_manifest_path(os.path.basename(os.path.dirname(full)) + "/" + os.path.basename(full)):
        return False
    own = os.path.relpath(full, root).replace(os.sep, "/")
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(own), text))
    if joined in (".", "..", own):
        return False        # names this file or the tree itself
    if joined.startswith("../"):
        return True         # a link out of the tree (`vendor` -> `../shared`): on Linux it is a link, not read
    if any(is_skipped_dir(part) for part in joined.split("/")):
        # into or onto a skipped directory (`bin/eslint` -> `../node_modules/.bin/eslint`, a file holding `build`):
        # whether that directory exists depends on the checkout (a fresh clone has no `node_modules/` or `build/`),
        # so its existence decides nothing
        return True
    return _exists_exactly(root, joined, listing)


def _exists_exactly(root: str, rel: str, listing: dict) -> bool:
    """Every part of `rel` is in its directory's listing with exactly that spelling."""
    cur = root
    for part in rel.split("/"):
        names = listing.get(cur)
        if names is None:
            try:
                names = set(os.listdir(cur))
            except OSError:
                names = set()
            listing[cur] = names
        if part not in names:
            return False
        cur = os.path.join(cur, part)
    return True


_LINK_TAGS = {getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C), getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)}


def _is_link(full: str) -> bool:
    """A symbolic link, or a Windows junction or volume mount point. `os.path.islink` is False for a junction, and
    `os.walk` follows one; it needs no administrator rights to create and can point anywhere, itself included.
    Other reparse points (a cloud-storage placeholder, a deduplicated file) are ordinary files and are read."""
    if os.path.islink(full):
        return True
    try:
        return getattr(os.lstat(full), "st_reparse_tag", 0) in _LINK_TAGS
    except OSError:
        return False


def tree_files(target: Path) -> TreeWalk:
    """Every regular file under `target`; see `_walk_tree`. Walked once per run, so each pass of one audit (the
    source, then the manifests) sees the same files."""
    return _reads.once_per_run(("tree_files", _reads._key(target)), lambda: _walk_tree(Path(target)))


def _extended_path(dirpath: str, name: str) -> str:
    """`dirpath/name` as a Windows extended-length path (`\\\\?\\C:\\...`), which keeps a trailing dot or space."""
    base = os.path.abspath(dirpath)
    if base.startswith("\\\\?\\"):
        return base + "\\" + name
    if base.startswith("\\\\"):
        return "\\\\?\\UNC\\" + base[2:] + "\\" + name
    return "\\\\?\\" + base + "\\" + name


def _walk_tree(target: Path) -> TreeWalk:
    """Every regular file under `target` outside the skipped directories.

    * A directory is skipped by its name INSIDE the tree. The folders above
      `target` play no part, so the same tree gives the same answer wherever it
      sits on disk.
    * Symbolic links, Windows junctions and mount points are counted and not followed:
      a link can point outside the tree, or at the tree itself, and what it points at
      differs from machine to machine. A directory reached a second time (a bind mount
      of a folder above it) is counted the same way and not walked again. Git on Windows
      usually checks a link out as a small text file holding the link's target;
      such a file is counted as the link it stands for, so one repository gives one
      report on both systems.
    * Relative paths use forward slashes, are normalised to Unicode NFC, and are
      ordered by their UTF-8 bytes, so the order is the same on Windows, Linux
      and macOS.
    """
    target = Path(target)
    files: list[tuple[str, Path]] = []
    skipped: dict[str, int] = {}
    symlinks = 0
    root = str(target)
    listing: dict = {}           # directory -> names, for the link stand-in rule
    seen: set[tuple[int, int]] = set()
    try:
        st = os.stat(root)
        seen.add((st.st_dev, st.st_ino))
    except OSError:
        pass
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        parts = [] if rel_dir == "." else rel_dir.replace("\\", "/").split("/")
        keep: list[str] = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if os.name == "nt" and d[-1:] in (".", " "):
                # a directory Windows cannot open by an ordinary path: listed, with its files, as not read
                count = _count_files(_extended_path(dirpath, d))
                skipped["/".join(parts + [d]) + "/"] = max(count, 1)
                continue
            if _is_link(full):
                symlinks += 1
                continue
            try:
                st = os.stat(full)
                ident = (st.st_dev, st.st_ino)
            except OSError:
                ident = None
            if ident is not None and ident[1] and ident in seen:
                symlinks += 1          # the same directory again: a mount of a folder already walked
                continue
            if ident is not None:
                seen.add(ident)
            if is_skipped_dir(d):
                count = _count_files(full)
                if count:
                    skipped["/".join(parts + [d]) + "/"] = count
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.name == "nt" and name[-1:] in (".", " "):
                # Windows drops a trailing dot or space from an ordinary path (`run.` opens `run`): the file is reached
                # by its extended-length path, which keeps the name as stored
                full = _extended_path(dirpath, name)
            if _is_link(full):
                symlinks += 1
                continue
            if not os.path.isfile(full):
                continue
            rel = unicodedata.normalize("NFC", "/".join(parts + [name]))
            if name == ".git" or name == ".coverage" or name.startswith(".coverage."):
                # a worktree's or a submodule's pointer to its repository (`gitdir: <a path on this machine>`), and the
                # data file a test run with coverage leaves: what a checkout holds, not what it ships; skipped like the
                # `.git/` directory of a clone
                skipped[rel] = 1
                continue
            if _is_link_placeholder(full, root, listing):
                symlinks += 1
                continue
            files.append((rel, Path(full)))
    # Two names the file system keeps apart can be one name after NFC (`é` written as one code point and as two):
    # those keep the form they are stored in, so each finding names its own file and the order does not depend on
    # how the file system lists them.
    counts: dict[str, int] = {}
    for rel, _ in files:
        counts[rel] = counts.get(rel, 0) + 1
    if any(c > 1 for c in counts.values()):
        files = [(os.path.relpath(str(full), root).replace(os.sep, "/") if counts[rel] > 1 else rel, full)
                 for rel, full in files]
    files.sort(key=lambda item: _sort_key(item[0]))
    return TreeWalk(files=files, skipped=dict(sorted(skipped.items())), symlinks=symlinks)


def _count_files(top: str) -> int:
    """Files under a skipped directory, counted without following any link, junction or repeated directory."""
    count, seen = 0, set()
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if _is_link(full):
                continue
            try:
                st = os.stat(full)
                ident = (st.st_dev, st.st_ino)
            except OSError:
                continue
            if ident[1] and ident in seen:
                continue
            seen.add(ident)
            keep.append(d)
        dirnames[:] = keep
        count += len(filenames)
    return count


def is_requirements_filename(name: str) -> bool:
    """`requirements.txt`, `requirements-dev.txt`, `dev-requirements.txt`, `requirements.in`,
    `constraints.txt`: a pip requirement or constraint file by its name."""
    n = name.lower()
    if not n.endswith((".txt", ".in")):
        return False
    stem = n.rsplit(".", 1)[0]
    return "requirements" in stem or stem.startswith("constraints")


def is_requirements_path(rel: str) -> bool:
    """A requirement file by name, or any `.txt` / `.in` file directly inside a
    directory named `requirements` (the `requirements/base.txt` layout)."""
    parts = rel.lower().split("/")
    if is_requirements_filename(parts[-1]):
        return True
    return len(parts) > 1 and parts[-2] in _REQUIREMENTS_DIRS and parts[-1].endswith((".txt", ".in"))


def is_manifest_path(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    return name in MANIFEST_EXACT or name in MANIFEST_EXTRA or is_requirements_path(rel)


def _strip_editable(spec: str) -> str:
    s = spec.strip()
    m = _EDITABLE_RE.match(s)
    return s[m.end():].strip() if m else s


def requirement_name(spec: str) -> str | None:
    """'stripe[foo]>=2.0; python_version>\"3\"' -> 'stripe'; 'pkg @ https://h/x.whl' -> 'pkg';
    'git+https://h/x.git#egg=name' -> 'name'; '-e git+https://h/x.git' -> 'x'. None if not a requirement."""
    s = _strip_editable(spec)
    if not s or s.startswith("#") or s.startswith("-"):
        return None
    if _VCS_URL_RE.match(s):
        m = re.search(r"[#&]egg=([\w.-]+)", s)
        if m:
            return m.group(1)
        tail = s.split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
        tail = tail.split("@", 1)[0]
        if not re.match(r"(?i)(?:git|hg|svn|bzr)\+", s):
            # a file at an address: a wheel's name is its first part (PEP 427); an archive's (`u-1.0.tar.gz`) is not
            # settled by its file name, and pip reads it from the archive
            return tail.split("-", 1)[0] or None if tail.lower().endswith(".whl") else None
        return re.sub(r"\.git$|-[0-9][^-]*-py.*$", "", tail) or None
    if s.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", s):
        return None     # a local path (`-e .`), not a named requirement
    s = s.split("#", 1)[0].strip()
    s = s.split(";", 1)[0].strip()
    if not s:
        return None
    s = s.split("@", 1)[0].strip()          # direct-URL form: name @ URL
    s = re.split(r"[<>=!~\[\s]", s, maxsplit=1)[0].strip()
    s = s.strip("\"'")
    if "/" in s or "\\" in s:
        return None     # a path (`requirements/base.txt`, `libs/pkg`): pip installs a location, not a package
    # a project name is ASCII letters, digits, `.`, `_` and `-` (PEP 508); anything else (a control character, a NUL
    # from a file that is not text) names no package pip would install
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", s):
        return None
    return s


def _package_source_option(s: str) -> bool:
    """A pip option that names where packages come from: `-i`, `-f` (spaced or attached), `--index-url`,
    `--extra-index-url`, `--find-links`, `--trusted-host`, and any abbreviation pip's parser accepts for them
    (`--index`, `--extra`, `--find`, `--trusted`)."""
    if re.match(r"-[if](?:\s|\S)", s, re.IGNORECASE):
        return True
    m = re.match(r"--([a-z-]+)(?:=|\s|$)", s, re.IGNORECASE)
    if not m:
        return False
    given = m.group(1).lower()
    wanted = {"index-url", "extra-index-url", "find-links", "trusted-host"}
    matches = [o for o in _PIP_FILE_LONG_OPTIONS if o.startswith(given)]
    return given in wanted or (len(matches) == 1 and matches[0] in wanted)


def _requirement_remote(line: str) -> tuple[str, str] | None:
    """(kind, detail) when a requirement line names a host to fetch from."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    s = _strip_editable(raw)
    if _VCS_URL_RE.match(s):
        return "vcs-requirement", f"requirement fetched from a URL: {raw[:120]}"
    if _package_source_option(s):
        return "index-url", f"package index or download location set in the manifest: {raw[:120]}"
    body = s.split("#", 1)[0].split(";", 1)[0]
    # `pkg @ file:///${PROJECT_ROOT}/..` is a path on this machine; `file://server/share/...` names another host
    if "@" in body and re.search(r"@\s*file://(?:localhost)?/", body, re.IGNORECASE):
        return None
    if "@" in body and re.search(r"@\s*(?:[a-z]+\+)?[a-z]+://", body, re.IGNORECASE):
        return "url-requirement", f"requirement installed from a URL: {raw[:120]}"
    return None


def pep503_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def pinned_pypi_version(spec: str) -> str | None:
    """Only an exact pin (`==` / `===`). A range is not a component version."""
    m = re.search(r"===?\s*([^\s,;'\")}\]]+)", spec)
    if not m:
        return None
    ver = m.group(1).strip()
    # PEP 440 allows a leading `v` (`==v1.16.0` is 1.16.0)
    ver = ver[1:] if ver[:1] in ("v", "V") and ver[1:2].isdigit() else ver
    # one exact version: `==2.*` is a range written with ==, and a quote or a brace is not part of a version
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+!_-]*", ver) or ver.endswith("."):
        return None
    return ver


def pinned_npm_version(ver: str) -> str | None:
    v = (ver or "").strip()
    v = v[1:].strip() if v.startswith("=") else v
    v = v[1:] if v[:1] in ("v", "V") and v[1:2].isdigit() else v
    # one exact semver version; a range, a tag (`latest`), a partial version (`1.2`), a union (`1 || 2`), a file, a
    # link, a repository, a URL or an alias is not a component version
    if re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", v):
        return v
    return None


def _line_of_spec(text: str, spec: str, name: str, used: set | None = None) -> int:
    """Line of a PEP 621 requirement: the quoted spec itself first, then the bare name.

    `_line_of(name)` alone would take the first line that CONTAINS the name, which can be the project's own
    `name = "..."` line. The quoted requirement is where the dependency is declared."""
    for q in ('"', "'"):
        i = _line_of(text, q + spec, default=0, used=used)
        if i:
            return i
    return _line_of(text, name)


def _line_of_key(text: str, key: str, default: int = 1, section: str | None = None) -> int:
    """Line of a TOML key (`requests = "^2.31"`), not the first line that merely mentions the name (a description).
    With `section` (`packages`, `tool.poetry.group.dev.dependencies`), the key inside that table: a name listed in two
    tables is reported at each."""
    first, by_section = _toml_key_lines(text)
    if section is not None:
        at = by_section.get((tuple(p.strip() for p in section.split(".")), key))
        if at:
            return at
    return first.get(key) or _line_of(text, key, default)


def _unquote_key(k: str) -> str:
    """A key as written before `=`, without one quote at either end (`"requests"` and `requests` are one key)."""
    k = k.strip()
    if k[:1] in "\"'":
        k = k[1:]
    if k[-1:] in "\"'":
        k = k[:-1]
    return k


@functools.lru_cache(maxsize=8)
def _toml_key_lines(text: str) -> tuple[dict, dict]:
    """For each key written at the start of a line (`requests = "^2"`): the first line it is on, and the first line it
    is on inside each table (`[tool.poetry.dependencies]`, the table's name split at its dots). One pass per text."""
    first: dict[str, int] = {}
    by_section: dict[tuple, int] = {}
    table = None
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"\s*\[", line):
            head = re.match(r"\s*\[\s*([^\[\]]+?)\s*\]\s*(?:#.*)?$", line)
            table = tuple(p.strip() for p in head.group(1).split(".")) if head else None
            continue
        if "=" not in line:
            continue
        k = _unquote_key(line.split("=", 1)[0])
        if not k or k != k.strip():
            continue
        first.setdefault(k, i)
        if table is not None:
            by_section.setdefault((table, k), i)
    return first, by_section


# table keys that install from somewhere other than the public index (Poetry names its other index `source`)
_TABLE_SOURCES = ("git", "hg", "svn", "bzr", "url", "path", "file", "index", "source", "workspace")


def _table_source(v) -> str:
    """Where a dependency written as a table (`{git = "..."}`, `{path = "../lib"}`) is installed from, or ""."""
    if isinstance(v, dict):
        return next((f for f in _TABLE_SOURCES if v.get(f)), "")
    return ""


def _exact_spec(name: str, v) -> str:
    """A Poetry or Pipfile version as a requirement: a bare version (`"2.31.0"`) is exact in Poetry."""
    version = v.get("version") if isinstance(v, dict) else v
    if not isinstance(version, str):
        return name
    version = version.strip()
    if re.fullmatch(r"[0-9][0-9A-Za-z.+!_-]*", version):
        return f"{name}=={version}"
    return f"{name} {version}".strip()


def _line_of(text: str, needle: str, default: int = 1, used: set | None = None) -> int:
    """First non-comment line containing needle. Comments that *mention*
    a package name must not steal the line number of the real requirement."""
    if not needle:
        for i, line in enumerate(text.splitlines(), 1):
            if not line.lstrip().startswith("#") and (used is None or (needle, i) not in used):
                if used is not None:
                    used.add((needle, i))
                return i
        return default
    lines = _split_lines(text)
    if lines.offsets is None:
        lines.offsets = [0]
        for ln in lines.lines[:-1]:
            lines.offsets.append(lines.offsets[-1] + len(ln))
        lines.joined = "".join(lines.lines)
    joined, offsets = lines.joined, lines.offsets
    pos = joined.find(needle)
    while pos >= 0:
        i = bisect.bisect_right(offsets, pos)        # 1-based line number
        line = lines.lines[i - 1]
        start = offsets[i - 1]
        if pos + len(needle) <= start + len(line) and not line.lstrip().startswith("#") and (
                used is None or (needle, i) not in used):
            if used is not None:
                used.add((needle, i))
            return i
        pos = joined.find(needle, start + len(line) if pos + len(needle) <= start + len(line) else pos + 1)
    return default


class _Lines:
    __slots__ = ("lines", "offsets", "joined")

    def __init__(self, lines: list[str]):
        self.lines, self.offsets, self.joined = lines, None, ""


@functools.lru_cache(maxsize=8)
def _split_lines(text: str) -> _Lines:
    """`text.splitlines()` once per text, with each line's offset filled in on first use."""
    return _Lines(text.splitlines())


def iter_manifest_files(target: Path):
    """Yield (path, posix-rel, text) for every manifest under target, in the canonical order. A manifest that cannot
    be opened is left out here; `collect_manifests` reports it."""
    for p, rel, text in _manifest_texts(target):
        if not isinstance(text, OSError):
            yield p, rel, text


def _manifest_texts(target: Path):
    """(path, posix-rel, text) for every manifest under target, in the canonical order; the error in place of the
    text for one that cannot be opened (permissions, a lock held by another program)."""
    for rel, p in tree_files(target).files:
        if not is_manifest_path(rel):
            continue
        try:
            text = _reads.read_text(p)
        except OSError as exc:
            text = exc
        yield p, rel, text


def _unreadable(rel: str, exc: OSError, what: str = "the dependencies it declares") -> ManifestError:
    return ManifestError(rel, 0, f"could not be opened ({type(exc).__name__}), so {what} were NOT read")


def _requirements_includes(text: str) -> list[tuple[int, str]]:
    """(line, path) for every `-r other.txt` / `-c constraints.txt` in a requirements file. An include given as a
    URL is not a file in the tree: it is reported as a remote source instead."""
    out: list[tuple[int, str]] = []
    for i, line in _logical_lines(text):
        target = _include_target(line)
        if target and not _URL_INCLUDE_RE.match(target):
            out.append((i, target))
    return out


# a URL a pip include would fetch; `file:` names this machine, so it is a path (inside the tree or not read)
_URL_INCLUDE_RE = re.compile(r"^(?!file:)[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def _remotes_from_requirements(text: str, rel: str) -> list[RemoteSource]:
    out: list[RemoteSource] = []
    for i, line in _logical_lines(text):
        target = _include_target(line)
        if target and _URL_INCLUDE_RE.match(target):
            out.append(RemoteSource(rel, i, "url-requirement",
                                    f"requirements file fetched from a URL: {line.strip()[:120]}"))
            continue
        hit = _requirement_remote(line)
        if hit:
            out.append(RemoteSource(rel, i, hit[0], hit[1]))
    return out


def _without_comment(line: str) -> str:
    """A requirement line without its comment. pip reads `#` as a comment at the start or after whitespace;
    `#egg=` inside a URL is part of the URL."""
    return re.sub(r"(?:^|\s)#.*$", "", line).strip()


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Lines as pip reads a requirements file: a line ending in a backslash continues on the next one (pip's
    `join_lines`), and the joined line keeps the number of its first physical line."""
    return [(i, line) for i, line, _ in _joined_lines(text)]


def _joined_lines(text: str) -> list[tuple[int, str, bool]]:
    """`_logical_lines`, with whether each line was joined from more than one."""
    out: list[tuple[int, str, bool]] = []
    held: list[str] = []
    first = 0
    for i, line in enumerate(text.splitlines(), 1):
        comment = re.match(r"(^|\s+)#.*$", line) is not None
        if line.endswith("\\") and not comment:
            if not held:
                first = i
            held.append(line[:-1])
            continue
        if held:
            held.append(line if not comment else " " + line)
            out.append((first, "".join(held), True))
            held = []
        else:
            out.append((i, line, False))
    if held:
        out.append((first, "".join(held), True))
    return out


# One PEP 508 requirement without its marker: a name, extras, and comparisons
_ONE_REQUIREMENT_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*(?:\[[^\]]*\])?\s*"
    r"(?:\(?\s*(?:~=|===|==|!=|<=|>=|<|>)\s*[^\s,;()]+(?:\s*,\s*(?:~=|===|==|!=|<=|>=|<|>)\s*[^\s,;()]+)*\s*\)?)?")


def _requirement_spec(line: str) -> str:
    """The requirement itself, without its comment or pip's per-requirement options (`--hash=...`) after it."""
    return re.split(r"\s+--?[A-Za-z]", _without_comment(line), maxsplit=1)[0].strip()


def _unreadable_joined(line: str) -> bool:
    """A line joined from several that is not one requirement: pip refuses it, so no name is taken from it."""
    spec = _requirement_spec(line)
    if not spec or spec.startswith(("-", ".", "/")) or " @ " in spec or "@" in spec.split(";")[0] or _VCS_URL_RE.match(spec):
        return False
    return not _ONE_REQUIREMENT_RE.fullmatch(spec.split(";", 1)[0].strip())


# pip's requirement-file options, so an abbreviated long option is matched the way pip's parser matches it
_PIP_FILE_LONG_OPTIONS = ("index-url", "extra-index-url", "no-index", "constraint", "requirement", "editable",
                          "find-links", "no-binary", "only-binary", "prefer-binary", "require-hashes", "pre",
                          "trusted-host", "use-feature", "global-option", "hash", "config-settings")


def _include_target(line: str) -> str | None:
    """The file a `-r` / `-c` line includes, in every spelling pip accepts: `-r f`, `-rf`, `--requirement f`,
    `--requirement=f`, and any unambiguous abbreviation of the long option (`--requirem f`, `--cons f`)."""
    s = _without_comment(line)
    m = re.match(r"-([rc])(?:\s+|(?=[^\s=]))(\S+)", s)
    if m:
        return m.group(2)
    m = re.match(r"--([a-z-]+)(?:=|\s+)(\S+)", s, re.IGNORECASE)
    if m:
        given = m.group(1).lower()
        matches = [o for o in _PIP_FILE_LONG_OPTIONS if o.startswith(given)]
        if given in ("requirement", "constraint") or (len(matches) == 1 and matches[0] in ("requirement", "constraint")):
            return m.group(2)
    return None


def _requirement_errors(text: str, rel: str) -> list[ManifestError]:
    """Lines continued with a backslash that pip cannot read as one requirement."""
    return [ManifestError(rel, i, f"a continued requirement line pip cannot read as one requirement: "
                                  f"{_requirement_spec(line)[:120]!r}")
            for i, line, joined in _joined_lines(text) if joined and _unreadable_joined(line)]


def _requirements_scope(rel: str) -> str:
    """What a requirements file declares, by its name: a constraints file only pins versions and adds nothing
    (`constraints.txt`); one for development, tests, linting, typing or documentation is not the product's
    (`dev-requirements.txt`, `requirements/test.txt`); any other is required."""
    low = rel.lower()
    if "constraint" in low.rsplit("/", 1)[-1]:
        return "constraint"
    if re.search(r"(?:^|[-_./])(?:dev|develop|devel|test|tests|testing|lint|linting|docs?|typing|mypy|ci|bench)(?:[-_./]|$)",
                 low):
        return "dev"
    return "required"


def _deps_from_requirements(text: str, rel: str, scope: str | None = None) -> list[DeclaredDep]:
    """The requirements a file declares, in the scope its name gives them, or in `scope` when a manifest names the
    file as where its dependencies come from (a file named like a development file is then the product's)."""
    out: list[DeclaredDep] = []
    scope = scope or _requirements_scope(rel)
    for i, line, joined in _joined_lines(text):
        if _include_target(line) or (joined and _unreadable_joined(line)):
            continue
        name = requirement_name(line)
        if not name:
            continue
        spec = _requirement_spec(line)
        out.append(DeclaredDep(
            file=rel, line=i, name=name, spec=spec,
            ecosystem="pypi", scope=scope,
        ))
    return out


def _dynamic_requirement_files(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """(each requirement file a pyproject.toml's dynamic dependencies come from, with the scope it declares, and the
    dynamic fields whose source is not named here). setuptools' `[tool.setuptools.dynamic]` (`dependencies =
    {file = [...]}` and each optional group's) and hatch's requirements-txt hook
    (`[tool.hatch.metadata.hooks.requirements_txt]`) are read; Poetry's own table is read elsewhere."""
    import tomllib
    try:
        data = tomllib.loads(text)
    except Exception:
        return [], []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    dynamic = project.get("dynamic") if isinstance(project.get("dynamic"), list) else []
    if "dependencies" not in dynamic and "optional-dependencies" not in dynamic:
        return [], []
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    files: list[tuple[str, str]] = []
    named = {"required": False, "optional": False}

    def take(v, scope: str) -> None:
        if isinstance(v, dict):
            v = v.get("file", v.get("files"))
        found = [v] if isinstance(v, str) else [x for x in v if isinstance(x, str)] if isinstance(v, list) else []
        files.extend((f, scope) for f in found)
        named[scope] = named[scope] or bool(found)

    for table in (((tool.get("setuptools") or {}).get("dynamic") or {}) if isinstance(tool.get("setuptools"), dict) else {},
                  (((((tool.get("hatch") or {}).get("metadata") or {}).get("hooks") or {}).get("requirements_txt") or {})
                   if isinstance(tool.get("hatch"), dict) else {})):
        if not isinstance(table, dict):
            continue
        take(table.get("dependencies", table.get("files")), "required")
        opt = table.get("optional-dependencies")
        for v in (opt.values() if isinstance(opt, dict) else ()):
            take(v, "optional")
    poetry = (tool.get("poetry") or {}) if isinstance(tool.get("poetry"), dict) else {}
    unresolved = []
    if "dependencies" in dynamic and not named["required"] and not poetry.get("dependencies"):
        unresolved.append("dependencies")
    if "optional-dependencies" in dynamic and not named["optional"] and not poetry.get("extras"):
        unresolved.append("optional-dependencies")
    return files, unresolved


def _path_requirements(text: str, rel: str) -> list[tuple[str, int, str]]:
    """Requirements given only as a path or an archive's address (`./pkg`, `-e ../lib`, `dist/x.whl`, `file:../w`,
    `https://h/u-1.0.tar.gz`): pip installs what is there, named by that project's own metadata, which this file does
    not show. The project itself (`.`, `-e .`) is not one."""
    out = []
    for i, line, joined in _joined_lines(text):
        if _include_target(line) or (joined and _unreadable_joined(line)) or requirement_name(line):
            continue
        path = _EDITABLE_RE.sub("", line.split(" #", 1)[0].strip()).strip()
        word = path.split()[0] if path else ""
        if word.rstrip("/\\") in ("", ".", "file:.") or word.startswith(("-", "#")):
            continue
        if (word.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:[\\/]", word) or "/" in word
                or word.lower().endswith((".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2"))):
            out.append((rel, i, word))
    return out


def _pep508_list(specs, text: str, rel: str, scope: str, extra: str = "",
                 used: set | None = None) -> tuple[list[DeclaredDep], list[RemoteSource]]:
    """A list of PEP 508 strings from pyproject.toml: the dependencies and any that name a URL."""
    deps: list[DeclaredDep] = []
    remotes: list[RemoteSource] = []
    if specs is not None and not isinstance(specs, list):
        # `dependencies = "requests"`: not the list PEP 621 requires, which a build refuses; recorded as not read
        return deps, [ManifestError(rel, _line_of(text, "dependencies") if scope == "required" else 1,
                                    f"pyproject.toml gives {'dependencies' if scope == 'required' else 'an extra'} as "
                                    "something other than a list, which PEP 621 does not allow, so it was NOT read")]
    if specs is None:
        return deps, remotes
    for spec in specs:
        if not isinstance(spec, str):
            continue        # `{include-group = "..."}` tables name another group, not a package
        name = requirement_name(spec) or spec
        line = _line_of_spec(text, spec, name.split("[", 1)[0], used)
        hit = _requirement_remote(spec)
        if hit:
            remotes.append(RemoteSource(rel, line, hit[0], hit[1]))
        deps.append(DeclaredDep(file=rel, line=line, name=name, spec=spec, ecosystem="pypi",
                                scope=scope, extra=extra))
    return deps, remotes


def _poetry_table(block, text: str, rel: str, scope: str, extra: str = "",
                  section: str | None = None, ecosystem: str = "pypi") -> tuple[list[DeclaredDep], list[RemoteSource]]:
    """A `[tool.poetry...dependencies]` table (or a table of the same shape: Pixi's): names, and entries fetched from
    a repository or URL."""
    deps: list[DeclaredDep] = []
    remotes: list[RemoteSource] = []
    if not isinstance(block, dict):
        return deps, remotes
    for k, v in block.items():
        if k == "python":
            continue
        spec = _exact_spec(str(k), v)
        line = _line_of_key(text, k, section=section)
        # `websockets = {version = "^12", optional = true}`: installed only with an extra that names it
        optional = scope == "required" and isinstance(v, dict) and v.get("optional") is True
        deps.append(DeclaredDep(file=rel, line=line, name=str(k), spec=spec, ecosystem=ecosystem,
                                scope="optional" if optional else scope, extra=extra, source=_table_source(v)))
        if isinstance(v, dict):
            for field in ("git", "url"):
                where = v.get(field)
                if isinstance(where, str) and where:
                    remotes.append(RemoteSource(rel, line, "vcs-requirement" if field == "git" else "url-requirement",
                                                f"dependency {k!r} fetched from {where[:120]}"))
    return deps, remotes


def _deps_from_pyproject(text: str, rel: str) -> tuple[list[DeclaredDep], list]:
    """Returns (deps, notes) where notes holds ManifestError and RemoteSource items."""
    import tomllib
    try:
        data = tomllib.loads(text)
    except Exception:
        return [], [ManifestError(rel, 1, "pyproject.toml could not be parsed")]

    out: list[DeclaredDep] = []
    notes: list = []
    used: set = set()          # each place a requirement is written is reported once

    def take(pair) -> None:
        out.extend(pair[0])
        notes.extend(pair[1])

    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    take(_pep508_list(project.get("dependencies"), text, rel, "required", used=used))
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra, specs in optional.items():
            take(_pep508_list(specs, text, rel, "optional", str(extra), used=used))
    # What the build itself installs before any of the project's own code runs.
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    take(_pep508_list(build.get("requires"), text, rel, "build", used=used))
    # PEP 735 dependency groups.
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group, specs in groups.items():
            take(_pep508_list(specs, text, rel, "dev", str(group), used=used))

    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    take(_poetry_table(poetry.get("dependencies"), text, rel, "required", section="tool.poetry.dependencies"))
    take(_poetry_table(poetry.get("dev-dependencies"), text, rel, "dev", "dev", section="tool.poetry.dev-dependencies"))
    pgroups = poetry.get("group")
    if isinstance(pgroups, dict):
        for group, body in pgroups.items():
            if isinstance(body, dict):
                take(_poetry_table(body.get("dependencies"), text, rel, "dev", str(group),
                                   section=f"tool.poetry.group.{group}.dependencies"))
    for src in poetry.get("source") or []:
        url = src.get("url", "") if isinstance(src, dict) else ""
        if url:
            notes.append(RemoteSource(rel, _line_of(text, url), "index-url", f"package source {url[:120]}"))

    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    for idx in uv.get("index") or []:
        url = idx.get("url", "") if isinstance(idx, dict) else ""
        if url:
            notes.append(RemoteSource(rel, _line_of(text, url), "index-url", f"package index {url[:120]}"))
    for key in ("index-url", "extra-index-url", "find-links"):
        val = uv.get(key)
        for url in ([val] if isinstance(val, str) else val if isinstance(val, list) else []):
            if isinstance(url, str) and url:
                notes.append(RemoteSource(rel, _line_of(text, url), "index-url", f"package index {url[:120]}"))
    sources = uv.get("sources")
    if isinstance(sources, dict):
        for name, where in sources.items():
            if isinstance(where, dict):
                for field in ("git", "url"):
                    loc = where.get(field)
                    if isinstance(loc, str) and loc:
                        notes.append(RemoteSource(rel, _line_of(text, loc),
                                                  "vcs-requirement" if field == "git" else "url-requirement",
                                                  f"dependency {name!r} fetched from {loc[:120]}"))
    take(_pep508_list(uv.get("dev-dependencies"), text, rel, "dev", "dev", used=used))
    # PDM: its package sources and its development groups
    pdm = tool.get("pdm") if isinstance(tool.get("pdm"), dict) else {}
    for src in pdm.get("source") or []:
        url = src.get("url", "") if isinstance(src, dict) else ""
        if isinstance(url, str) and url:
            notes.append(RemoteSource(rel, _line_of(text, url), "index-url", f"package source {url[:120]}"))
    pdm_dev = pdm.get("dev-dependencies")
    if isinstance(pdm_dev, dict):
        for group, specs in pdm_dev.items():
            take(_pep508_list(specs, text, rel, "dev", str(group), used=used))
    # Hatch: what each environment installs
    hatch_envs = (tool.get("hatch") or {}).get("envs") if isinstance(tool.get("hatch"), dict) else None
    if isinstance(hatch_envs, dict):
        for env, body in hatch_envs.items():
            if isinstance(body, dict):
                for key in ("dependencies", "extra-dependencies"):
                    take(_pep508_list(body.get(key), text, rel, "dev", str(env), used=used))
    # Pixi: conda packages and PyPI packages, for the project and for each feature
    pixi = tool.get("pixi") if isinstance(tool.get("pixi"), dict) else {}
    features = pixi.get("feature") if isinstance(pixi.get("feature"), dict) else {}
    tables = [("tool.pixi", pixi)] + [(f"tool.pixi.feature.{f}", b) for f, b in features.items() if isinstance(b, dict)]
    for section, body in tables:
        for key, ecosystem in (("dependencies", "conda"), ("pypi-dependencies", "pypi")):
            take(_poetry_table(body.get(key), text, rel, "required", section=f"{section}.{key}", ecosystem=ecosystem))
    if isinstance(sources, dict):
        from_uv = {pep503_name(str(n)): _table_source(w) for n, w in sources.items() if _table_source(w)}
        out[:] = [replace(d, source=from_uv[pep503_name(d.name)])
                  if d.ecosystem == "pypi" and not d.source and pep503_name(d.name) in from_uv else d for d in out]
    # an extra that names the project itself (`all = ["demo[aws]"]`) adds that extra's own requirements, read above;
    # the project is not a dependency of itself
    own = project.get("name") or poetry.get("name")
    if isinstance(own, str) and own:
        out[:] = [d for d in out if not (d.ecosystem == "pypi" and pep503_name(d.name) == pep503_name(own))]
    return out, notes


_NODE_EVAL_RE = re.compile(r"""\bnode(?:\.exe)?\s+(?:--?[\w-]+\s+)*(?:-e|--eval|-p|--print)\s+(["'])(.*?)\1""", re.S)


def _node_eval_reaches_network(cmd: str) -> bool:
    """A script command runs `node -e '<code>'` whose code imports or calls the network, read by the auditor's
    JavaScript rules."""
    from .no_egress_auditor import _js_expression_findings, _js_import_findings, _strip_js_comments
    for m in _NODE_EVAL_RE.finditer(cmd):
        code = m.group(2)
        src = _strip_js_comments(code)
        found = _js_import_findings(src, "", None) + _js_expression_findings(code, src, "")
        if any(f.kind in ("network-import", "network-call") for f in found):
            return True
    return False


def _remotes_from_package_json(text: str, rel: str) -> list[RemoteSource]:
    """Scripts that fetch, and dependencies installed from a URL or a repository."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[RemoteSource] = []
    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for name, cmd in scripts.items():
            if not isinstance(cmd, str):
                continue
            from .no_egress_auditor import _blank_leading_options      # (the auditor imports this module)
            hit = _SCRIPT_NET_RE.search(cmd) or _SCRIPT_NET_RE.search(_blank_leading_options(cmd))
            if not hit and _node_eval_reaches_network(cmd):
                # `"prepare": "node -e \"require('https').get(...)\""`: the script runs JavaScript that does
                kind = "install-script" if name in _INSTALL_SCRIPTS else "script"
                when = "at install time" if name in _INSTALL_SCRIPTS else "when it is invoked"
                out.append(RemoteSource(rel, _line_of(text, f'"{name}"'), kind,
                                        f"npm script `{name}` runs JavaScript (`node -e`) that reaches the network "
                                        f"{when}"))
                continue
            if not hit:
                continue
            if name in _INSTALL_SCRIPTS:
                out.append(RemoteSource(rel, _line_of(text, f'"{name}"'), "install-script",
                                        f"npm lifecycle script `{name}` runs {' '.join(hit.group(1).split())!r} at install time"))
            else:
                out.append(RemoteSource(rel, _line_of(text, f'"{name}"'), "script",
                                        f"npm script `{name}` runs {' '.join(hit.group(1).split())!r} when it is invoked"))
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(field) or {}
        if not isinstance(block, dict):
            continue
        for name, ver in block.items():
            if isinstance(ver, str) and _NPM_REMOTE_RE.match(ver.strip()) and not ver.strip().startswith("file:"):
                out.append(RemoteSource(rel, _line_of(text, f'"{name}"'), "vcs-requirement",
                                        f"dependency {name!r} installed from {ver.strip()[:100]!r}, not from the registry"))
    # npm `overrides`, yarn `resolutions` and pnpm's `pnpm.overrides` replace a package anywhere in the tree with
    # what they name, which may be a URL or a repository
    pnpm = data.get("pnpm") if isinstance(data.get("pnpm"), dict) else {}
    for field, block in (("overrides", data.get("overrides")), ("resolutions", data.get("resolutions")),
                         ("pnpm.overrides", pnpm.get("overrides"))):
        stack = [block]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for name, ver in node.items():
                if isinstance(ver, dict):
                    stack.append(ver)
                elif isinstance(ver, str) and _NPM_REMOTE_RE.match(ver.strip()) and not ver.strip().startswith(
                        ("file:", "$")):
                    out.append(RemoteSource(rel, _line_of(text, ver.strip()), "vcs-requirement",
                                            f"{field} replaces {name!r} with {ver.strip()[:100]!r}, not from the "
                                            "registry"))
    return out


def _deps_from_pipfile(text: str, rel: str) -> tuple[list[DeclaredDep], list[RemoteSource]]:
    import tomllib
    try:
        data = tomllib.loads(text)
    except Exception as exc:
        return [], [ManifestError(rel, getattr(exc, "lineno", None) or 1,
                                  "Pipfile could not be parsed as TOML, so the packages it declares were NOT read")]
    deps: list[DeclaredDep] = []
    remotes: list[RemoteSource] = []
    for section, scope in (("packages", "required"), ("dev-packages", "dev")):
        block = data.get(section) or {}
        if isinstance(block, dict):
            for name, spec in block.items():
                # `{version = "==2.31.0", extras = [...]}`: the version is the requirement; the table is not
                version = spec.get("version") if isinstance(spec, dict) else None
                shown = spec if isinstance(spec, str) else (version if isinstance(version, str)
                                                            else json.dumps(spec, sort_keys=True))
                line = _line_of_key(text, name, section=section)
                deps.append(DeclaredDep(file=rel, line=line, name=str(name), spec=f"{name} {shown}",
                                        ecosystem="pypi", scope=scope, source=_table_source(spec)))
                if isinstance(spec, dict):
                    for field in ("git", "hg", "svn", "file", "url"):
                        loc = spec.get(field)
                        if isinstance(loc, str) and _URL_VALUE_RE.match(loc):
                            remotes.append(RemoteSource(rel, line, "vcs-requirement",
                                                        f"dependency {name!r} fetched from {loc[:120]}"))
    for src in data.get("source") or []:
        url = src.get("url", "") if isinstance(src, dict) else ""
        if url and "pypi.org" not in url:
            remotes.append(RemoteSource(rel, _line_of(text, url), "index-url", f"package source {url[:120]}"))
    return deps, remotes


def _flow_items(body: str) -> list[str]:
    """The items of a YAML flow list body (the text inside `[...]`), split at top-level commas only, so a nested
    `{pip: [a, b]}` stays one item."""
    items, depth, cur, quote = [], 0, "", ""
    for ch in body:
        if quote:
            cur += ch
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            items.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        items.append(cur.strip())
    return [i.strip().strip("\"'") for i in items if i.strip()]


def _expand_flow_lists(text: str) -> list[tuple[int, str]]:
    """conda environment lines with YAML flow lists written out as block lists, line numbers kept:
    `dependencies: [python=3.11, requests]`, `- pip: [requests, httpx]` and `dependencies: [python, {pip: [x]}]`
    read the same as their block forms."""
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line, number = lines[i], i + 1
        m = re.match(r"^(\s*)(-\s+)?([\w.-]+)\s*:\s*\[(.*)$", line)
        if not m:
            out.append((number, line))
            i += 1
            continue
        body = m.group(4)
        while body.count("[") + 1 > body.count("]") and i + 1 < len(lines):   # a flow list may run over lines
            i += 1
            body += " " + lines[i].strip()
        inner = body[:body.rfind("]")] if "]" in body else body
        indent = m.group(1) + ("  " if m.group(2) else "")
        out.append((number, f"{m.group(1)}{m.group(2) or ''}{m.group(3)}:"))
        for item in _flow_items(inner):
            nested = re.match(r"^\{\s*([\w.-]+)\s*:\s*\[(.*)\]\s*\}$", item)
            if nested:                       # `{pip: [a, b]}`: a mapping item holding its own list
                out.append((number, f"{indent}  - {nested.group(1)}:"))
                out.extend((number, f"{indent}      - {x}") for x in _flow_items(nested.group(2)))
            else:
                out.append((number, f"{indent}  - {item}"))
        i += 1
    return out


def _deps_from_environment_yml(text: str, rel: str) -> tuple[list[DeclaredDep], list[RemoteSource]]:
    """conda environment files: `- name=version` under dependencies, a nested `- pip:` list,
    and channels given as a URL."""
    out: list[DeclaredDep] = []
    remotes: list[RemoteSource] = []
    section = ""
    in_pip = False
    for i, raw in _expand_flow_lists(text):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith((" ", "\t", "-")):
            section = stripped.split(":", 1)[0].strip().lower()
            in_pip = False
            continue
        if not stripped.startswith("-"):
            continue
        item = stripped[1:].strip()
        if section == "channels":
            if _URL_VALUE_RE.match(item):
                remotes.append(RemoteSource(rel, i, "index-url", f"conda channel {item[:120]}"))
            continue
        if section != "dependencies":
            continue
        if item.endswith(":") and item[:-1].strip() == "pip":
            in_pip = True
            continue
        indent = len(line) - len(line.lstrip())
        if in_pip and indent <= 2:
            in_pip = False
        if in_pip:
            hit = _requirement_remote(item)
            if hit:
                remotes.append(RemoteSource(rel, i, hit[0], hit[1]))
            name = requirement_name(item)
        else:
            name = re.split(r"[=<>!~ ]", item, maxsplit=1)[0].strip() or None
            if name and "::" in name:
                name = name.split("::", 1)[1]
        if name:
            out.append(DeclaredDep(file=rel, line=i, name=name, spec=item, ecosystem="pypi" if in_pip else "conda"))
    return out, remotes


_SETUP_LIST_KEYWORDS = {"install_requires": "required", "setup_requires": "build", "tests_require": "dev"}


def _literal_strings(node: ast.AST) -> list[tuple[int, str]]:
    """(line, value) for the string constants of a list or tuple literal."""
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    return [(e.lineno, e.value) for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]


_SETUP_MAX_ITEMS = 10_000      # requirements one expression of a setup.py is read to
_SETUP_MAX_CHARS = 10_000      # characters one string of it is read to
_SETUP_MAX_DEPTH = 200         # names followed through one another
_SETUP_MAX_WORK = 200_000      # values one setup.py is read through
_SETUP_TOO_MANY = (f"setup.py declares more than {_SETUP_MAX_ITEMS:,} requirements, so those past the first "
                   f"{_SETUP_MAX_ITEMS:,} were NOT read")


def _unread() -> ast.AST:
    """An expression that stands for a value not read (a change made with an operator other than `+`)."""
    return ast.Call(func=ast.Name(id="<not read>", ctx=ast.Load()), args=[], keywords=[])


def _setup_names(tree: ast.AST) -> set:
    """The names `setup` is called by in a setup.py: `setup`, and any it is imported as (`from setuptools import setup
    as s`)."""
    names = {"setup"}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in ("setuptools", "distutils"):
            names |= {a.asname for a in n.names if a.name == "setup" and a.asname}
    return names


def _setup_resolver(tree: ast.AST):
    """For a setup.py: `resolve(node)` gives (the (line, requirement) pairs an expression stands for, whether every
    piece of it was read, whether a list it names is changed as the file runs with something that is not read);
    `dict_of(name, node=None)` gives ({key: [value nodes]}, every binding a dict, a change not read); `derived_from(v,
    name)` says a value is built only from that dict (`sum(extras.values(), [])`), which adds nothing new.

    Every value assigned to a name at any depth counts (`extra = {...}` in each branch of an `if`), with what `.append`,
    `.extend`, `.insert`, `.add`, `+=` and slice assignment add to it and the items assigned into it
    (`kw["install_requires"] = reqs`), or added to an item (`kw["install_requires"].append(x)`,
    `extras.setdefault("aws", []).append(x)`). A `.remove` takes a literal out only when it runs whatever happens: a
    statement of the file's own body, after every line that adds to the list. One in a branch, or followed by an
    addition, leaves the value listed (it may be the one installed)."""
    assigned: dict[str, list] = {}
    additions: dict[str, list] = {}
    removals: dict[str, list] = {}
    items: dict[str, list] = {}
    body_calls = {id(s.value) for s in getattr(tree, "body", []) if isinstance(s, ast.Expr)}
    added_on: dict[str, int] = {}       # the last line that adds to a list or binds it

    def item_of(t: ast.AST):
        """(dict name, key) of `d["k"]` or `d.setdefault("k", ...)`; None for anything else."""
        if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and isinstance(t.slice, ast.Constant) \
                and isinstance(t.slice.value, str):
            return t.value.id, t.slice.value
        if isinstance(t, ast.Call) and isinstance(t.func, ast.Attribute) and t.func.attr == "setdefault" \
                and isinstance(t.func.value, ast.Name) and t.args and isinstance(t.args[0], ast.Constant) \
                and isinstance(t.args[0].value, str):
            return t.func.value.id, t.args[0].value
        return None

    def add_to(name: str, value, line: int) -> None:
        additions.setdefault(name, []).append(value)
        added_on[name] = max(added_on.get(name, 0), line)

    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                if isinstance(t, ast.Name):
                    assigned.setdefault(t.id, []).append(n.value)
                    added_on[t.id] = max(added_on.get(t.id, 0), n.lineno)
                elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                    key = t.slice.value if isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str) else None
                    items.setdefault(t.value.id, []).append((key, n.value))
                    if isinstance(t.slice, ast.Slice):
                        add_to(t.value.id, n.value, n.lineno)                       # `deps[:0] = extra`
                    elif isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, int):
                        add_to(t.value.id, ast.List(elts=[n.value]), n.lineno)      # `deps[0] = "x"`
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
            add_to(n.target.id, n.value if isinstance(n.op, (ast.Add, ast.BitOr)) else None, n.lineno)
        elif isinstance(n, ast.AugAssign) and item_of(n.target):
            # `kw["install_requires"] += [...]`: what is added to the item
            d, key = item_of(n.target)
            items.setdefault(d, []).append((key, n.value if isinstance(n.op, (ast.Add, ast.BitOr)) else _unread()))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr in ("append", "insert", "extend", "add") and n.args:
            arg = n.args[-1]
            value = arg if n.func.attr == "extend" else ast.List(elts=[arg])
            if isinstance(n.func.value, ast.Name):
                add_to(n.func.value.id, value, n.lineno)
            elif item_of(n.func.value):
                d, key = item_of(n.func.value)
                items.setdefault(d, []).append((key, value))
                if isinstance(n.func.value, ast.Call) and len(n.func.value.args) > 1:
                    items[d].append((key, n.func.value.args[1]))                    # setdefault's default
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.attr == "remove" and n.args:
            # `deps.remove("boto3")`: a literal it takes out, when the statement always runs (one held in a name, or
            # one in a branch, is left listed)
            if isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) and id(n) in body_calls:
                removals.setdefault(n.func.value.id, []).append((n.lineno, n.args[0].value))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.attr == "setdefault" and len(n.args) == 2 and isinstance(n.args[0], ast.Constant) \
                and isinstance(n.args[0].value, str):
            # `kw.setdefault("install_requires", deps)`: an item set as the file runs (when the key is not there yet)
            items.setdefault(n.func.value.id, []).append((n.args[0].value, n.args[1]))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) \
                and n.func.attr == "update":
            # `kw.update(install_requires=[...])`, `kw.update({...})`: items set as the file runs; a set's
            # `.update([...])` adds to it
            for k in n.keywords:
                items.setdefault(n.func.value.id, []).append((k.arg, k.value))
            for a in n.args:
                if isinstance(a, ast.Dict):
                    for k, val in zip(a.keys, a.values):
                        key = k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else None
                        items.setdefault(n.func.value.id, []).append((key, val))
                else:
                    items.setdefault(n.func.value.id, []).append((None, a))
                    add_to(n.func.value.id, a, n.lineno)

    def derived_from(v: ast.AST, name: str) -> bool:
        # built from the dict's own values and nothing else (`sum(extras.values(), [])`); a value that adds a literal
        # of its own (`R["base"] + ["rich"]`) is not
        names = {x.id for x in ast.walk(v) if isinstance(x, ast.Name)}
        if not (name in names and names <= {name, "list", "set", "sum", "sorted", "tuple"}):
            return False
        keys = {id(x.slice) for x in ast.walk(v) if isinstance(x, ast.Subscript)}
        return not any(isinstance(x, ast.Constant) and isinstance(x.value, str) and id(x) not in keys
                       for x in ast.walk(v))

    dicts: dict[str, tuple] = {}

    def dict_of(name: str, node: ast.AST | None = None):
        # each named dict once; one met again while it is being read (`K = {**K}`) holds nothing more
        if node is None:
            if name in dicts:
                return dicts[name]
            dicts[name] = ({}, True, [])
            dicts[name] = dict_items(name, None)
            return dicts[name]
        return dict_items(name, node)

    def dict_items(name: str, node: ast.AST | None):
        found: dict[str, list] = {}
        complete = True

        def take(v) -> bool:
            if isinstance(v, ast.Dict):
                ok = True
                for k, val in zip(v.keys, v.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        found.setdefault(k.value, []).append(val)
                    elif k is None and isinstance(val, ast.Name) and val.id != name:
                        # `{**extras, "webdriver": [...]}`: the items of the dict unpacked here, then the others
                        inner, inner_ok, _ = dict_of(val.id)
                        for ik, ivals in inner.items():
                            # a value already taken (`{**D0, **D0}`) is taken once
                            have = found.setdefault(ik, [])
                            held = {id(x) for x in have}
                            new = [x for x in ivals if id(x) not in held]
                            if len(have) + len(new) > _SETUP_MAX_ITEMS:
                                return False
                            have.extend(new)
                        ok = ok and inner_ok
                    else:
                        ok = False
                return ok
            if isinstance(v, ast.Call) and getattr(v.func, "id", "") == "dict" and not v.args:
                ok = True
                for k in v.keywords:
                    if k.arg is None:
                        ok = False
                    else:
                        found.setdefault(k.arg, []).append(k.value)
                return ok
            if isinstance(v, ast.IfExp):
                return take(v.body) & take(v.orelse)
            return False
        values = [node] if node is not None else assigned.get(name, [])
        if not values:
            complete = False
        for v in values:
            complete = take(v) and complete
        changes = []                    # items set as the file runs: (key, value), the key None when it is not shown
        for key, val in (items.get(name, []) if node is None else []):
            changes.append((key, val))
            if key is not None:
                found.setdefault(key, []).append(val)
        return found, complete, changes

    def change_not_read(name: str, changes: list, keys=None) -> bool:
        # a change to one of `keys` (any key when None) that is not read: an item whose key is not shown, or a value
        # neither read nor built from the dict itself (`extras['all'] = make_all()`)
        def read(key, val) -> bool:
            if key == "extras_require" and keys is not None:
                # a dict of lists: read when every binding of it is a dict
                return dict_of(val.id)[1] if isinstance(val, ast.Name) else dict_of("", val)[1]
            return derived_from(val, name) or resolve(val, frozenset({name}))[1]
        return any((key is None and keys is None) or ((keys is None or key in keys) and key is not None
                   and not read(key, val)) for key, val in changes)

    # Each name is resolved once (a name met again while it is being resolved stands for nothing new), a list longer
    # than `_SETUP_MAX_ITEMS` or a string longer than `_SETUP_MAX_CHARS` is not read whole, and names are followed
    # `_SETUP_MAX_DEPTH` deep: a setup.py whose names double (`A1 = A0 + A0`) costs a bounded amount of work.
    # A value read while another it depends on was still being read (`a = b` and `b = a + [...]`) is partial: it is not
    # kept, so the answer does not depend on which keyword is read first. Every value read counts towards
    # `_SETUP_MAX_WORK`, past which the rest is not read.
    name_lists: dict[str, tuple] = {}
    item_lists: dict[tuple, tuple] = {}
    name_strings: dict[str, str | None] = {}
    depth = [0]
    reading: list = []          # the names and items being read, outermost first
    met_again: set = set()      # those met again while still being read
    work = [0]
    setup_names = _setup_names(tree)
    setup_line = min((n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call) and (
        n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")) in setup_names), default=None)

    def kept(key, memo: dict, result: tuple) -> tuple:
        """Keep a finished value unless it was read while one it depends on was still being read."""
        reading.pop()
        met_again.discard(key)
        if met_again & set(reading):
            del memo[key]
        else:
            memo[key] = result
        return result

    def string_value(v: ast.AST, seen: frozenset = frozenset()) -> str | None:
        """A string the expression always is: a literal, a name bound only to one, or strings added together."""
        if isinstance(v, ast.Constant):
            return v.value if isinstance(v.value, str) else None
        if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
            left = string_value(v.left, seen)
            right = string_value(v.right, seen) if left is not None else None
            if left is None or right is None or len(left) + len(right) > _SETUP_MAX_CHARS:
                return None
            return left + right
        if isinstance(v, ast.Name) and v.id in assigned and len(assigned[v.id]) == 1 and v.id not in additions:
            if v.id in name_strings:
                return name_strings[v.id]
            if depth[0] >= _SETUP_MAX_DEPTH:
                return None
            name_strings[v.id] = None           # met again while being read: not a string this can tell
            depth[0] += 1
            try:
                name_strings[v.id] = string_value(assigned[v.id][0], seen)
            finally:
                depth[0] -= 1
            return name_strings[v.id]
        return None

    def capped(out: list, complete: bool, bad: bool) -> tuple[list, bool, bool]:
        return (out[:_SETUP_MAX_ITEMS], False, bad) if len(out) > _SETUP_MAX_ITEMS else (out, complete, bad)

    def resolve(v: ast.AST, seen: frozenset = frozenset()) -> tuple[list, bool, bool]:
        work[0] += 1
        if work[0] > _SETUP_MAX_WORK:
            return [], False, False
        if isinstance(v, ast.Constant):
            if isinstance(v.value, str) and "\n" in v.value.strip():
                # `install_requires="""requests\nboto3"""`: setuptools reads a string one requirement a line
                return [(v.lineno + k, ln.strip()) for k, ln in enumerate(v.value.split("\n"))
                        if ln.strip() and not ln.strip().startswith("#")], True, False
            if isinstance(v.value, str):
                return [(v.lineno, v.value.strip())], True, False
            return [], v.value is None, False
        if isinstance(v, ast.Starred):
            return resolve(v.value, seen)
        if isinstance(v, (ast.List, ast.Tuple, ast.Set)):
            out, complete, bad = [], True, False
            for e in v.elts:
                got, c, b = resolve(e, seen)
                out.extend(got)
                complete, bad = complete and c, bad or b
                if len(out) > _SETUP_MAX_ITEMS:
                    break
            return capped(out, complete, bad)
        if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
            text = string_value(v)
            if text is not None:
                return [(v.lineno, text)], True, False      # `"ujson>=1.35" + env_dependency`: one string
            (lg, lc, lb) = resolve(v.left, seen)
            (rg, rc, rb) = resolve(v.right, seen) if len(lg) <= _SETUP_MAX_ITEMS else ([], False, False)
            return capped(lg + rg, lc and rc, lb or rb)
        if isinstance(v, ast.Call) and getattr(v.func, "id", "") in ("list", "set", "sorted", "tuple") and len(v.args) == 1:
            return resolve(v.args[0], seen)
        if isinstance(v, ast.IfExp):
            # either branch may be the one installed (`["pywin32"] if win else []`): both are declared
            (bg, bc, bb), (og, oc, ob) = resolve(v.body, seen), resolve(v.orelse, seen)
            return capped(bg + og, bc and oc, bb or ob)
        if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "split" and not v.args \
                and not v.keywords and isinstance(v.func.value, ast.Constant) and isinstance(v.func.value.value, str):
            return [(v.lineno, w) for w in v.func.value.value.split()], True, False      # `"requests boto3".split()`
        if isinstance(v, ast.ListComp) and len(v.generators) == 1 and not v.generators[0].ifs \
                and isinstance(v.generators[0].target, ast.Name) and isinstance(v.elt, ast.Name) \
                and v.elt.id == v.generators[0].target.id:
            return resolve(v.generators[0].iter, seen)      # `[p for p in [...]]`: the list itself
        if isinstance(v, ast.Subscript) and isinstance(v.value, ast.Name) and isinstance(v.slice, ast.Constant):
            memo = (v.value.id, repr(v.slice.value))
            if memo in seen or depth[0] >= _SETUP_MAX_DEPTH:
                return [], memo in seen, False      # an item met again while it is read adds nothing new
            if memo in item_lists:
                if memo in reading:
                    met_again.add(memo)
                return item_lists[memo]
            d, _, _ = dict_of(v.value.id)
            if v.slice.value not in d:
                return [], False, False
            item_lists[memo] = ([], True, False)        # met again while being read: it adds nothing new
            reading.append(memo)
            out, complete, bad = [], True, False
            depth[0] += 1
            try:
                for val in d[v.slice.value]:
                    if derived_from(val, v.value.id):
                        continue
                    got, c, b = resolve(val, seen | {memo})
                    out.extend(got)
                    complete, bad = complete and c, bad or b
                    if len(out) > _SETUP_MAX_ITEMS:
                        break
            finally:
                depth[0] -= 1
            return kept(memo, item_lists, capped(out, complete, bad))
        if isinstance(v, ast.Name):
            if v.id in name_lists:
                if v.id in reading:
                    met_again.add(v.id)
                return name_lists[v.id]
            if v.id not in assigned:
                return [], False, False
            if depth[0] >= _SETUP_MAX_DEPTH:
                return [], False, False
            name_lists[v.id] = ([], True, False)    # met again while being read: it adds nothing new
            reading.append(v.id)
            out, complete, bad = [], True, False
            depth[0] += 1
            try:
                for val in assigned[v.id]:
                    got, c, b = resolve(val, seen | {v.id})
                    out.extend(got)
                    complete, bad = complete and c, bad or b
                    if len(out) > _SETUP_MAX_ITEMS:
                        break
                for val in additions.get(v.id, []):
                    # a change to the list: one that is not read leaves what it adds unread
                    got, c, b = resolve(val, seen | {v.id}) if val is not None else ([], False, False)
                    out.extend(got)
                    complete, bad = complete and c, bad or b or not c
                    if len(out) > _SETUP_MAX_ITEMS:
                        break
            finally:
                depth[0] -= 1
            # a removal after the last line that adds to the list and before `setup()` is called, of one entry each
            for line, spec in removals.get(v.id, []):
                if line > added_on.get(v.id, 0) and (setup_line is None or line < setup_line):
                    at = next((k for k, (_l, s_) in enumerate(out) if s_ == spec), None)
                    if at is not None:
                        out = out[:at] + out[at + 1:]
            return kept(v.id, name_lists, capped(out, complete, bad))
        return [], False, False

    return resolve, dict_of, derived_from, change_not_read


def _deps_from_setup_py(text: str, rel: str) -> tuple[list[DeclaredDep], list[RemoteSource]]:
    """The literal keyword arguments of `setup(...)`: `install_requires`, `setup_requires`,
    `tests_require`, `extras_require` and `dependency_links`. Read from the syntax tree, so a
    requirement with an extras bracket is read whole. Lists computed at run time are not resolved."""
    try:
        tree = _parse_quietly(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # (the auditor's Python pass reports the file as unparseable; this says what is lost for the inventory)
        return [], [ManifestError(rel, 1, SETUP_PY_UNPARSEABLE)]
    try:
        return _setup_py_declarations(tree, rel)
    except RecursionError:
        return [], [ManifestError(rel, 1, "setup.py nests its values too deeply to be read here, so the requirements "
                                          "it declares were NOT read")]


SETUP_PY_UNPARSEABLE = "setup.py does not parse as Python, so the requirements it declares were NOT read"


def _setup_py_declarations(tree: ast.AST, rel: str) -> tuple[list[DeclaredDep], list]:
    deps: list[DeclaredDep] = []
    remotes: list[RemoteSource] = []
    errors: list[ManifestError] = []

    def too_many(line: int) -> None:
        if not any(e.detail == _SETUP_TOO_MANY for e in errors):
            errors.append(ManifestError(rel, line, _SETUP_TOO_MANY))

    added: set = set()

    def add(line: int, spec: str, scope: str, extra: str = "") -> None:
        if (line, spec, scope, extra) in added:
            return              # one requirement written once, reached more than one way (`A1 = A0 + A0`)
        added.add((line, spec, scope, extra))
        if len(deps) >= _SETUP_MAX_ITEMS:
            too_many(line)
            return
        hit = _requirement_remote(spec)
        if hit:
            remotes.append(RemoteSource(rel, line, hit[0], hit[1]))
        name = requirement_name(spec)
        if name:
            deps.append(DeclaredDep(file=rel, line=line, name=name, spec=spec, ecosystem="pypi",
                                    scope=scope, extra=extra))

    resolve, dict_of, derived_from, change_not_read = _setup_resolver(tree)
    setup_names = _setup_names(tree)

    def changed(name: str, line: int) -> None:
        errors.append(ManifestError(rel, line, f"`{name}` is changed as setup.py runs with values this tool does not "
                                               "resolve, so what they add was NOT read"))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")) not in setup_names:
            continue
        keywords: list[tuple[str, ast.AST, bool]] = []
        for kw in node.keywords:
            if kw.arg is not None:
                keywords.append((kw.arg, kw.value, True))
                continue
            # `setup(**kw)`: the keywords of a dict the file binds (`kw = dict(...)`, `kw = {...}`, items set later)
            d, complete, changes = (dict_of(kw.value.id) if isinstance(kw.value, ast.Name)
                                    else dict_of("", kw.value))
            bad = isinstance(kw.value, ast.Name) and change_not_read(
                kw.value.id, changes, set(_SETUP_LIST_KEYWORDS) | {"extras_require"})
            if not complete and not d:
                errors.append(ManifestError(rel, node.lineno, "setup() takes keyword arguments from `**` an expression "
                                                              "this tool does not resolve, so the requirements they may "
                                                              "declare were NOT read"))
                continue
            if bad:
                changed(kw.value.id if isinstance(kw.value, ast.Name) else "**", node.lineno)
            keywords += [(k, val, False) for k, vals in d.items() for val in vals]
        for arg, value, direct in keywords:
            if arg in _SETUP_LIST_KEYWORDS:
                pairs, complete, bad = resolve(value)
                if len(pairs) >= _SETUP_MAX_ITEMS and not complete:
                    too_many(value.lineno)
                for line, spec in pairs:
                    add(line, spec, _SETUP_LIST_KEYWORDS[arg])
                if arg != "install_requires":
                    continue                # test and build requirements are not the product's
                if bad:
                    changed(value.id if isinstance(value, ast.Name) else arg, value.lineno)
                # (an incomplete `install_requires`, written in setup() or given through `**`, is read from the file it
                # names, or recorded as not read, by `_setup_py_computed`)
            elif arg == "extras_require":
                if isinstance(value, ast.Name):
                    d, _, changes = dict_of(value.id)
                    bad = change_not_read(value.id, changes)
                elif isinstance(value, (ast.Dict, ast.Call, ast.IfExp)):
                    d, _, _ = dict_of("", value)
                    bad = False
                else:
                    continue
                for extra, vals in d.items():
                    for val in vals:
                        if isinstance(value, ast.Name) and derived_from(val, value.id):
                            continue
                        pairs, complete, b = resolve(val)
                        if len(pairs) >= _SETUP_MAX_ITEMS and not complete:
                            too_many(value.lineno)
                        bad = bad or b
                        for line, spec in pairs:
                            add(line, spec, "optional", extra)
                if bad:
                    changed(value.id if isinstance(value, ast.Name) else "extras_require", value.lineno)
            elif arg == "dependency_links":
                for line, url in _literal_strings(value):
                    remotes.append(RemoteSource(rel, line, "index-url", f"dependency link {url[:120]}"))
    return deps, remotes + errors


def _setup_py_computed(text: str) -> tuple[int, list[str], list[tuple[int, str]]] | None:
    """When `setup(install_requires=...)` is computed as setup.py runs (`install_requires=reqs()`): its line, the
    string literals in the file that may name the file it is read from, and the requirements a function of the file
    returns as a literal list (`def get_requires(): return ['a', 'b']`). None when it is a literal (or `None`), a name
    bound once to a literal, or absent."""
    try:
        tree = _parse_quietly(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    try:
        return _setup_install_computed(tree)
    except RecursionError:
        return None             # (`_deps_from_setup_py` records the file as not read)


def _setup_install_computed(tree: ast.AST):
    setup_names = _setup_names(tree)
    resolver = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")) not in setup_names:
            continue
        resolver = resolver or _setup_resolver(tree)
        resolve, dict_of = resolver[:2]
        # `install_requires=...` written in setup(), or an item of a dict given as `**`
        values = [kw.value for kw in node.keywords if kw.arg == "install_requires"]
        for kw in node.keywords:
            if kw.arg is None:
                d = dict_of(kw.value.id)[0] if isinstance(kw.value, ast.Name) else dict_of("", kw.value)[0]
                values += d.get("install_requires", [])
        for v in values:
            read = resolve(v)
            if _returns_none(tree, v) or read[1] or len(read[0]) >= _SETUP_MAX_ITEMS:
                continue            # (a list read to the limit is recorded as such where it is read)
            names = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                     and 0 < len(n.value) < 200 and "\n" not in n.value and not n.value.endswith((".py", ".md", ".rst"))]
            return v.lineno, names, _literal_list_returned(tree, v)
    return None


def _returns_none(tree: ast.AST, call: ast.AST) -> bool:
    """`call` calls a function of the file, with no arguments, whose only return gives `None`: it declares nothing."""
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and not call.args and not call.keywords):
        return False
    fn = next((f for f in getattr(tree, "body", []) if isinstance(f, ast.FunctionDef) and f.name == call.func.id), None)
    returns = [r for r in ast.walk(fn) if isinstance(r, ast.Return)] if fn is not None else []
    return len(returns) == 1 and (returns[0].value is None or (isinstance(returns[0].value, ast.Constant)
                                                               and returns[0].value.value is None))


def _literal_list_returned(tree: ast.AST, call: ast.AST) -> list[tuple[int, str]]:
    """(line, value) of the strings a function of the file returns as a list literal, when `call` calls it with no
    arguments: `return [...]`, or a name bound to a list literal in the function and returned."""
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and not call.args and not call.keywords):
        return []
    fn = next((f for f in getattr(tree, "body", []) if isinstance(f, ast.FunctionDef) and f.name == call.func.id), None)
    if fn is None:
        return []
    returns = [r for r in ast.walk(fn) if isinstance(r, ast.Return)]
    if len(returns) != 1 or returns[0].value is None:
        return []
    # what it returns, read as the file's other values are (a list it appends to included); all of it, or nothing
    pairs, complete, _ = _setup_resolver(fn)[0](returns[0].value)
    return pairs if complete else []


def _requirement_lines_only(text: str) -> bool:
    """Is every line of `text` a requirement, an option, a comment or blank: a requirements file under any name?"""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return bool(lines) and all(ln.startswith("-") or requirement_name(ln) for ln in lines)


def _remotes_from_config(text: str, rel: str, low: str) -> list[RemoteSource]:
    out: list[RemoteSource] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if low == ".gitmodules":
            m = re.match(r"url\s*=\s*(\S+)", line)
            if m:
                out.append(RemoteSource(rel, i, "submodule", f"git submodule from {m.group(1)[:120]}"))
        elif low == ".npmrc":
            m = re.match(r"(?:@[\w.-]+:)?registry\s*=\s*(\S+)", line)
            if m:
                out.append(RemoteSource(rel, i, "registry", f"npm registry set to {m.group(1)[:120]}"))
        else:  # pip.conf / pip.ini
            m = re.match(r"(?:extra-)?index-url\s*=\s*(\S+)|find-links\s*=\s*(\S+)", line, re.IGNORECASE)
            if m:
                out.append(RemoteSource(rel, i, "index-url", f"pip index set to {(m.group(1) or m.group(2))[:120]}"))
    return out


def _deps_from_package_json(text: str, rel: str) -> tuple[list[DeclaredDep], list[ManifestError]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return [], [ManifestError(rel, 1, "package.json could not be parsed")]
    if not isinstance(data, dict):
        return [], []
    out: list[DeclaredDep] = []
    used: set = set()          # a package named in two blocks is reported at each place
    # devDependencies carry scope "dev": the egress auditor reports a network package among
    # them, and the SBOM leaves them out (a product inventory that mixes test tooling with
    # run-time dependencies misdescribes the product). Disclosed in the SBOM scope statement.
    for field, scope in (
        ("dependencies", "required"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "optional"),
        ("devDependencies", "dev"),
    ):
        block = data.get(field) or {}
        if not isinstance(block, dict):
            continue
        for name, ver in block.items():
            spec = f"{name}@{ver}" if ver is not None else str(name)
            out.append(DeclaredDep(
                file=rel, line=_line_of(text, f'"{name}"', used=used),
                name=str(name), spec=spec, ecosystem="npm", scope=scope,
            ))
    return out, []


def _setup_cfg_files(text: str) -> list[tuple[int, str, str]]:
    """(line, file, scope) for each requirements file a setup.cfg names with `file:` (`install_requires = file:
    requirements.in`, an extra's `file: a.txt, b.txt`), which setuptools reads the requirements from."""
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    parser.optionxform = lambda o: o.lower().replace("-", "_")     # `install-requires`, as setuptools reads it
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    out: list[tuple[int, str, str]] = []

    def take(value: str, scope: str) -> None:
        value = value.strip()
        if value.startswith("file:"):
            for f in value[len("file:"):].split(","):
                if f.strip():
                    out.append((_line_of(text, value.splitlines()[0]), f.strip(), scope))

    if parser.has_section("options"):
        for key, scope in (("install_requires", "required"), ("setup_requires", "build"), ("tests_require", "dev")):
            if parser.has_option("options", key):
                take(parser.get("options", key), scope)
    if parser.has_section("options.extras_require"):
        for _extra, value in parser.items("options.extras_require"):
            take(value, "optional")
    return out


def _deps_from_setup_cfg(text: str, rel: str) -> tuple[list[DeclaredDep], list[RemoteSource]]:
    """`[options]` install_requires / setup_requires / tests_require / dependency_links and every
    `[options.extras_require]` entry, on one line or continued over several."""
    deps: list[DeclaredDep] = []
    remotes: list[RemoteSource] = []
    # strict, as setuptools reads it: a section or an option written twice is refused, not read by its last value
    parser = configparser.RawConfigParser(strict=True, interpolation=None)
    parser.optionxform = lambda o: o.lower().replace("-", "_")     # `install-requires`, as setuptools reads it
    try:
        parser.read_string(text)
    except (configparser.DuplicateSectionError, configparser.DuplicateOptionError) as exc:
        return deps, [ManifestError(rel, _ini_error_line(exc),
                                    "setup.cfg writes a section or an option twice, which setuptools refuses, so the "
                                    "requirements it declares were NOT read")]
    except configparser.Error as exc:
        return deps, [ManifestError(rel, _ini_error_line(exc),
                                    "setup.cfg could not be parsed, so the requirements it declares were NOT read")]

    def add(spec: str, scope: str, extra: str = "") -> None:
        spec = spec.split(" #", 1)[0].strip()
        if not spec or spec.startswith("file:"):
            return                  # `file: requirements.in` names where the requirements are: read there
        line = _line_of(text, spec)
        hit = _requirement_remote(spec)
        if hit:
            remotes.append(RemoteSource(rel, line, hit[0], hit[1]))
        name = requirement_name(spec)
        if name:
            deps.append(DeclaredDep(file=rel, line=line, name=name, spec=spec, ecosystem="pypi",
                                    scope=scope, extra=extra))

    def lines(value: str) -> list[str]:
        return [ln.strip() for ln in value.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    if parser.has_section("options"):
        for key, scope in (("install_requires", "required"), ("setup_requires", "build"), ("tests_require", "dev")):
            if parser.has_option("options", key):
                for spec in lines(parser.get("options", key)):
                    add(spec, scope)
        if parser.has_option("options", "dependency_links"):
            for url in lines(parser.get("options", "dependency_links")):
                remotes.append(RemoteSource(rel, _line_of(text, url), "index-url", f"dependency link {url[:120]}"))
    if parser.has_section("options.extras_require"):
        for extra, value in parser.items("options.extras_require"):
            for spec in lines(value):
                add(spec, "optional", extra)
    # `[easy_install]` sets where setup.py's own installs fetch from
    if parser.has_section("easy_install"):
        for key in ("index_url", "index-url", "find_links", "find-links"):
            if parser.has_option("easy_install", key):
                for url in lines(parser.get("easy_install", key).replace(" ", "\n")):
                    remotes.append(RemoteSource(rel, _line_of(text, url), "index-url",
                                                f"easy_install package index {url[:120]}"))
    return deps, remotes


def _included_rel(rel: str, inc: str) -> str | None:
    """The path inside the tree that `-r inc` in the file `rel` names, or None when it leaves the tree."""
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(rel), inc.replace("\\", "/")))
    if joined == ".." or joined.startswith(("../", "/")) or posixpath.isabs(joined) or re.match(r"^[A-Za-z]:", joined):
        return None
    return unicodedata.normalize("NFC", joined)


def _ini_error_line(exc: Exception) -> int:
    """The line an INI parse error names, or 1."""
    line = getattr(exc, "lineno", None)
    if not line and getattr(exc, "errors", None):
        line = exc.errors[0][0]
    return line if isinstance(line, int) and line > 0 else 1


def _deps_from_tox_ini(text: str, rel: str) -> list:
    """The requirements each `[testenv...]` section of tox.ini installs (`deps =`), factor prefixes (`py312: x`) set
    aside; includes, substitutions and local paths are not packages."""
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        return [ManifestError(rel, _ini_error_line(exc),
                              "tox.ini could not be parsed, so the requirements its environments install were NOT read")]
    out: list[DeclaredDep] = []
    used: set = set()
    named: set = set()          # a test matrix names one package in many environments: each package once, at first
    for section in parser.sections():
        if not section.startswith("testenv") or not parser.has_option(section, "deps"):
            continue
        for raw in parser.get(section, "deps").splitlines():
            spec = re.sub(r"^[\w,.!-]+:\s+", "", raw.split(" #", 1)[0].strip())
            if not spec or spec.startswith(("-", "{", ".", "/", "#")) or "{" in spec:
                continue
            name = requirement_name(spec)
            if name and pep503_name(name) not in named:
                named.add(pep503_name(name))
                out.append(DeclaredDep(file=rel, line=_line_of(text, spec, used=used), name=name, spec=spec,
                                       ecosystem="pypi", scope="dev", extra=section))
    return out


def _deps_from_noxfile(text: str, rel: str) -> list[DeclaredDep]:
    """The packages a noxfile's sessions install by name: `session.install("httpx", "pytest>=8")`."""
    try:
        tree = _parse_quietly(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    out: list[DeclaredDep] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                "install", "conda_install"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and not a.value.startswith(("-", ".", "/")):
                    name = requirement_name(a.value)
                    if name:
                        out.append(DeclaredDep(file=rel, line=a.lineno, name=name, spec=a.value,
                                               ecosystem="conda" if node.func.attr == "conda_install" else "pypi",
                                               scope="dev"))
    return out


def collect_manifests(target: Path) -> ManifestScan:
    """Every declared dependency, parse error, remote source and manifest file under target.

    `-r other.txt` and `-c other.txt` lines in a requirements file are followed when the
    file is inside the target; what they include is attributed to the included file."""
    target = Path(target)
    scan = ManifestScan(deps=[], errors=[], files=[], remotes=[])
    seen: set[str] = set()
    # An include is followed only to a file the walk reads, named by its path inside the tree: never through a link,
    # into a skipped directory or out of the tree, so the same tree gives the same answer on every system.
    walked = {rel: p for rel, p in tree_files(target).files}

    def read_requirements(p: Path, rel: str, text: str, scope: str | None = None) -> None:
        if rel in seen:
            if scope:
                # read already, in the scope its name gives it: a manifest names it as where its dependencies come
                # from, so they are in that manifest's scope
                scan.deps[:] = [replace(d, scope=scope) if d.file == rel and d.scope in ("dev", "constraint") else d
                                for d in scan.deps]
            return
        seen.add(rel)
        scan.deps.extend(_deps_from_requirements(text, rel, scope))
        scan.paths.extend(_path_requirements(text, rel))
        scan.errors.extend(_requirement_errors(text, rel))
        scan.remotes.extend(_remotes_from_requirements(text, rel))
        for line, inc in _requirements_includes(text):
            q_rel = _included_rel(rel, inc)
            if q_rel not in walked:
                scan.errors.append(ManifestError(
                    rel, line, f"included requirements file {inc!r} was not read: it is outside the tree, a link, "
                               "in a skipped directory, or missing"))
                continue
            if q_rel in seen:
                continue
            q = walked[q_rel]
            try:
                included = _reads.read_text(q)
            except OSError as exc:
                seen.add(q_rel)
                scan.errors.append(_unreadable(q_rel, exc))
                continue
            scan.files.append((q, q_rel))
            read_requirements(q, q_rel, included)

    def read_named(owner: str, line: int, f: str, scope: str) -> None:
        """Read the requirements file `f`, named by the manifest `owner` as where its dependencies (`scope`) come
        from, by its path beside that manifest."""
        q_rel = posixpath.normpath(posixpath.join(owner.rpartition("/")[0], f.strip()))
        what = {"required": "dependencies", "optional": "optional dependencies", "build": "build requirements",
                "dev": "test requirements"}.get(scope, "requirements")
        if q_rel not in walked:
            scan.errors.append(ManifestError(owner, line, f"the {what} are read from {f!r}, which was not read: "
                                                          "it is outside the tree, a link, in a skipped directory, "
                                                          "or missing"))
            return
        if q_rel in seen:
            read_requirements(walked[q_rel], q_rel, "", scope)
            return
        try:
            named_text = _reads.read_text(walked[q_rel])
        except OSError as exc:
            seen.add(q_rel)
            scan.errors.append(_unreadable(q_rel, exc))
            return
        scan.files.append((walked[q_rel], q_rel))
        read_requirements(walked[q_rel], q_rel, named_text, scope)

    for p, rel, text in _manifest_texts(target):
        if isinstance(text, OSError):
            if rel not in seen:
                seen.add(rel)
                scan.errors.append(_unreadable(rel, text))
            continue
        low = p.name.lower()
        if low == "pyproject.toml":
            scan.files.append((p, rel))
            d, notes = _deps_from_pyproject(text, rel)
            scan.deps += d
            scan.errors += [n for n in notes if isinstance(n, ManifestError)]
            scan.remotes += [n for n in notes if isinstance(n, RemoteSource)]
            # `dynamic = ["dependencies"]`: the requirement files the build backend reads them from
            files, unresolved = _dynamic_requirement_files(text)
            for f, scope in files:
                read_named(rel, 1, f, scope)
            base = rel.rpartition("/")[0]
            if not any((f"{base}/{n}" if base else n) in walked for n in ("setup.py", "setup.cfg")):
                # (setuptools also takes them from a `setup.py` or `setup.cfg` beside it, which are read)
                for field_name in unresolved:
                    scan.errors.append(ManifestError(rel, 1, f"the {field_name.replace('-', ' ')} are dynamic "
                                                             f"(`dynamic = [\"{field_name}\"]`) and the source the build "
                                                             "backend reads them from is not one this tool reads, so "
                                                             "they were NOT read"))
        elif low == "package.json":
            scan.files.append((p, rel))
            d, e = _deps_from_package_json(text, rel)
            scan.deps += d
            scan.errors += e
            scan.remotes += _remotes_from_package_json(text, rel)
        elif low == "setup.cfg":
            scan.files.append((p, rel))
            d, r = _deps_from_setup_cfg(text, rel)
            scan.deps += d
            scan.errors += [n for n in r if isinstance(n, ManifestError)]
            scan.remotes += [n for n in r if isinstance(n, RemoteSource)]
            for line, f, scope in _setup_cfg_files(text):
                read_named(rel, line, f, scope)
        elif low == "setup.py":
            scan.files.append((p, rel))
            d, r = _deps_from_setup_py(text, rel)
            scan.deps += d
            scan.errors += [n for n in r if isinstance(n, ManifestError)]
            scan.remotes += [n for n in r if isinstance(n, RemoteSource)]
            computed = _setup_py_computed(text)
            if computed:
                # `install_requires=reqs()`: read the requirements file the script names, when it names one beside
                # it; otherwise the list is computed as setup.py runs and is NOT shown here
                line, names, returned = computed
                base = rel.rpartition("/")[0]
                # a name the script uses for a folder of the tree (`os.path.join('requirements', *f)`)
                folders = [n.strip("/") for n in dict.fromkeys(names) if "://" not in n and any(
                    w.startswith(posixpath.normpath(posixpath.join(base, n.strip("/"))) + "/") for w in walked)]
                named = []
                for n in dict.fromkeys(names):
                    if "://" in n:
                        continue
                    for cand in [n] + [f"{d}/{n}" for d in folders]:
                        q_rel = posixpath.normpath(posixpath.join(base, cand))
                        if q_rel in walked and q_rel != rel and cand not in named:
                            try:
                                if _requirement_lines_only(_reads.read_text(walked[q_rel])):
                                    named.append(cand)
                                    break
                            except OSError:
                                pass
                for n in named:
                    read_named(rel, line, n, "required")
                for spec_line, spec in returned:
                    name = requirement_name(spec)
                    if name:
                        scan.deps.append(DeclaredDep(file=rel, line=spec_line, name=name, spec=spec, ecosystem="pypi",
                                                     scope="required"))
                if not named and not returned:
                    scan.errors.append(ManifestError(rel, line, "`install_requires` is computed when setup.py runs, "
                                                                "from no source this tool could tie to a file in the "
                                                                "tree, so the requirements it declares were NOT read"))
        elif low == "pipfile":
            scan.files.append((p, rel))
            d, r = _deps_from_pipfile(text, rel)
            scan.deps += d
            scan.errors += [n for n in r if isinstance(n, ManifestError)]
            scan.remotes += [n for n in r if isinstance(n, RemoteSource)]
        elif low in ("environment.yml", "environment.yaml"):
            scan.files.append((p, rel))
            d, r = _deps_from_environment_yml(text, rel)
            scan.deps += d
            scan.remotes += r
        elif low in (".gitmodules", ".npmrc", "pip.conf", "pip.ini"):
            scan.files.append((p, rel))
            scan.remotes += _remotes_from_config(text, rel, low)
        elif is_requirements_path(rel):
            if rel in seen:
                continue
            scan.files.append((p, rel))
            read_requirements(p, rel, text)
    # Test runners' own installs: `deps =` in tox.ini and `session.install(...)` in a noxfile. They are read as a script
    # and as Python too, so they are not listed as manifest files; their declarations are added here.
    for rel, p in walked.items():
        name = rel.rsplit("/", 1)[-1].lower()
        if name in ("tox.ini", "noxfile.py"):
            try:
                text = _reads.read_text(p)
            except OSError as exc:
                if name == "tox.ini":           # a noxfile is Python: the source pass reports it
                    scan.errors.append(_unreadable(rel, exc, "the requirements its environments install"))
                continue
        if name == "tox.ini":
            tox = _deps_from_tox_ini(text, rel)
            scan.deps += [d for d in tox if isinstance(d, DeclaredDep)]
            scan.errors += [e for e in tox if isinstance(e, ManifestError)]
        elif name == "noxfile.py":
            scan.deps += _deps_from_noxfile(text, rel)
    # One order on every operating system, whatever order the includes were met in.
    scan.files.sort(key=lambda item: _sort_key(item[1]))
    return scan


def collect_declared_deps(target: Path) -> tuple[list[DeclaredDep], list[ManifestError], list[tuple[Path, str]]]:
    """All declared deps, parse errors, and (path, rel) of manifests read."""
    scan = collect_manifests(target)
    return scan.deps, scan.errors, scan.files

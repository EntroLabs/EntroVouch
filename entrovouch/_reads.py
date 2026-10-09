"""One version of each file per run.

The subject digest and the analysis must describe the same bytes. Read twice, a file rewritten between the two reads
gives a report whose digest binds one version and whose verdict (or whose decision about what kind of file it is)
describes another. During a run every read of a file goes through `read_bytes`: the first read records the hash of
the bytes, and every later read, whatever it is for (a type check, the analysis, the digest), must hash the same or
the run stops with `FileChangedDuringRun`. A run holds one hash per file and the last file read, never the tree.
Outside a run nothing is recorded.
"""
import contextlib
import contextvars
import hashlib
import io
import os
import tokenize

_SEEN: contextvars.ContextVar = contextvars.ContextVar("entrovouch_reads", default=None)
# Results computed once per run (the walk of the tree), so every pass of one run sees the same files.
_MEMO: contextvars.ContextVar = contextvars.ContextVar("entrovouch_memo", default=None)
# The file read last in this run, so the reads one file gets in a row (its type check, its analysis, its digest) are
# one read from disk. One file at most is held.
_LAST: contextvars.ContextVar = contextvars.ContextVar("entrovouch_last", default=None)


class FileChangedDuringRun(RuntimeError):
    """A file's bytes differ from the bytes this run already read."""


def suffix_of(path) -> str:
    """The file's extension as Python 3.11 to 3.13 give it: a name ending in a dot (`run.`) has none. Python 3.14 gives
    `.` there, which would read the same tree differently by interpreter."""
    s = path.suffix
    return "" if s == "." else s


def _key(path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


@contextlib.contextmanager
def one_read_per_file():
    """Inside this block every read of a file gives the same bytes, or the run stops."""
    if _SEEN.get() is not None:         # already inside a run: the outer run's versions hold
        yield
        return
    token, memo_token, last_token = _SEEN.set({}), _MEMO.set({}), _LAST.set(None)
    try:
        yield
    finally:
        _LAST.reset(last_token)
        _MEMO.reset(memo_token)
        _SEEN.reset(token)


def _read(path) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


_CHUNK = 1 << 20
# A file larger than this is never held whole for a type check or a digest: it is hashed as it is read.
_HOLD_LIMIT = 16 << 20


def _record(path, sha: bytes, size: int) -> None:
    """Inside a run: the first read of `path` sets its version; every later read must match it."""
    seen = _SEEN.get()
    if seen is None:
        return
    k = _key(path)
    floor = _MEMO.get().get(("more_than", k))
    if floor is not None and size <= floor:
        raise FileChangedDuringRun(f"{path} changed while it was being audited (it was judged by its size); run "
                                   "again on a tree that is not being written to")
    if seen.setdefault(k, sha) != sha:
        raise FileChangedDuringRun(f"{path} changed while it was being audited; run again on a tree that is "
                                   "not being written to")


def read_bytes(path) -> bytes:
    seen = _SEEN.get()
    if seen is not None:
        last = _LAST.get()
        if last is not None and last[0] == _key(path):
            return last[1]                          # the same bytes as the read just before: nothing to check
    data = _read(path)
    if seen is not None:
        _record(path, hashlib.sha256(data).digest(), len(data))
        _LAST.set((_key(path), data))
    return data


def _stream(path, head: int = 0, into=None) -> tuple[bytes, bytes, int]:
    """(sha256, first `head` bytes, size) of a file read in chunks; each chunk also goes to `into`."""
    h, first, size = hashlib.sha256(), b"", 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            if len(first) < head:
                first += chunk[:head - len(first)]
            h.update(chunk)
            size += len(chunk)
            if into is not None:
                into.update(chunk)
    return h.digest(), first, size


def digest_into(path, hasher) -> None:
    """Feed a file's bytes to `hasher` without holding the file, checked against the run's version of it."""
    last = _LAST.get()
    if _SEEN.get() is not None and last is not None and last[0] == _key(path):
        hasher.update(last[1])
        return
    sha, _, size = _stream(path, 0, hasher)
    _record(path, sha, size)


def require_more_than(path, n: int) -> None:
    """A decision was made from the size of `path` alone: any read of it in this run must hold more than `n` bytes."""
    memo = _MEMO.get()
    if memo is not None:
        memo[("more_than", _key(path))] = n


def once_per_run(key, compute):
    """`compute()`, run once per run for `key`; outside a run, every time."""
    memo = _MEMO.get()
    if memo is None:
        return compute()
    if key not in memo:
        memo[key] = compute()
    return memo[key]


def read_head(path, n: int) -> bytes:
    """The first `n` bytes. Inside a run the whole file is read and checked, so a decision made from its first bytes
    is made about the same version the analysis and the digest see; outside a run, a short read."""
    if _SEEN.get() is not None:
        try:
            large = os.path.getsize(path) > _HOLD_LIMIT
        except OSError:
            large = False
        if not large:
            return read_bytes(path)[:n]
        sha, first, size = _stream(path, n)
        _record(path, sha, size)
        return first
    with open(path, "rb") as fh:
        return fh.read(n)


def decode_text(data: bytes) -> str:
    """Bytes as the text a program reading them sees: UTF-32 and UTF-16 by their byte-order mark (Windows PowerShell
    runs a UTF-16 script; pip reads a UTF-16 requirements file), otherwise UTF-8 (a UTF-8 byte-order mark dropped).
    Without a byte-order mark neither pip nor PowerShell reads a file as UTF-16, and neither does this. Undecodable
    bytes become U+FFFD; universal newlines."""
    import codecs
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        enc = "utf-32"
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        enc = "utf-16"
    elif data.startswith(codecs.BOM_UTF8):
        enc = "utf-8-sig"
    else:
        enc = "utf-8"
    text = data.decode(enc, "replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def read_text(path) -> str:
    """The file's text, from the one version, decoded as `decode_text` decodes it."""
    return decode_text(read_bytes(path))


def read_python_source(path) -> str:
    """`tokenize.open(path).read()`, from the one version: the encoding cookie and BOM honoured, universal newlines."""
    data = read_bytes(path)
    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    with io.TextIOWrapper(io.BytesIO(data), encoding, line_buffering=True) as fh:
        return fh.read()

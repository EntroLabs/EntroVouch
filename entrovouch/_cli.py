"""The exit-code contract every command keeps.

0 is a clean result and 1 is "the scan ran and found something". A crash must never reach either: a pipeline
that reads 1 as findings would report a broken run as a finished one. Anything a command does not handle itself
ends here as exit 2 with one line on stderr.
"""
import sys


def run(main) -> int:
    # a file name that is not valid UTF-8 (kept by Python as a lone surrogate) is printed escaped, never a crash
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass
    try:
        return main()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("error: interrupted; nothing was completed", file=sys.stderr)
        return 2
    except Exception as exc:  # the contract: never 0 or 1 for a run that did not finish
        print(f"error: the command did not complete ({type(exc).__name__}: {exc}); this is not a result",
              file=sys.stderr)
        return 2


def write_text(path, text: str) -> None:
    """An output file, written with LF line endings on every system, so one report is one file everywhere. A file
    name that is not valid UTF-8 is written escaped, never a crash."""
    from pathlib import Path
    if not Path(path).resolve().parent.is_dir():
        print(f"error: the folder for {path} does not exist; nothing was written", file=sys.stderr)
        raise SystemExit(2)
    Path(path).write_text(text, encoding="utf-8", errors="backslashreplace", newline="\n")


def _same_file(a, b) -> bool:
    """Do two existing paths name one file (a hard link, another spelling)?"""
    import os
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _own_output(path) -> bool:
    """Is an existing file one this tool wrote: a markdown report headed `# ENTROVOUCH`, or a JSON document whose
    `tool` (a report) or `metadata` (a CycloneDX document) names it? A source file that only mentions the name is
    not."""
    import json
    try:
        with open(path, "rb") as f:
            text = f.read().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if text.startswith("# ENTROVOUCH"):
        return True
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return False
    return isinstance(doc, dict) and "ENTROVOUCH" in json.dumps([doc.get("tool"), doc.get("metadata")])


def missing_folder(*paths, key=None, inputs=(), tree=None) -> str | None:
    """An error line for the first output that cannot be written, checked before anything is signed (a signature
    spends a one-time key): its folder does not exist, it is a folder, it is the signing key or the key's lock file,
    it is a file this run reads (`inputs`: a report converted onto itself would be destroyed), a file of the tree
    being scanned that this tool did not write (`tree`: a source file would be overwritten), or two outputs name the
    same file."""
    from pathlib import Path
    guarded = set()
    if key is not None:
        k = Path(key).resolve()
        guarded = {k, Path(str(k) + ".lock")}
    read = {Path(p).resolve() for p in inputs if p is not None}
    seen: dict = {}
    for path in paths:
        if path is None:
            continue
        full = Path(path).resolve()
        if not full.parent.is_dir():
            return f"error: the folder for {path} does not exist"
        if full.is_dir():
            return f"error: {path} is a folder, not a file to write"
        if full in guarded:
            return f"error: {path} is the signing key's own file; writing a report there would destroy the key"
        if full in read or (full.exists() and any(_same_file(full, r) for r in read)):
            # (the same file under another name too: a hard link)
            return f"error: {path} is a file this run reads; writing there would destroy it"
        if tree is not None and full.is_file() and not _own_output(full) and (
                full.is_relative_to(Path(tree).resolve()) or full.stat().st_nlink > 1):
            # (a hard link may join a file outside the tree to one inside it)
            inside = full.is_relative_to(Path(tree).resolve())
            if inside or _linked_into(full, Path(tree)):
                return (f"error: {path} is a file of the tree being scanned, not one this tool wrote; writing there "
                        "would overwrite it")
        if full in seen:
            return f"error: {seen[full]} and {path} name the same file; each output needs its own"
        seen[full] = path
    return None


def _linked_into(path, tree, limit: int = 200_000) -> bool:
    """Is `path` (a file with more than one name) the same file as one in the tree, under any name? Read to `limit`
    files; a tree larger than that is answered yes, so an output is never written through a link it could not
    rule out."""
    import os
    try:
        st = os.stat(path)
    except OSError:
        return False
    seen = 0
    for dirpath, _dirs, files in os.walk(tree):
        for f in files:
            seen += 1
            if seen > limit:
                return True
            try:
                q = os.stat(os.path.join(dirpath, f))
            except OSError:
                continue
            if (q.st_ino, q.st_dev) == (st.st_ino, st.st_dev) and q.st_ino:
                return True
    return False


def uuid_urn(value) -> str | None:
    """An error line when a CycloneDX serial number is not `urn:uuid:` followed by an RFC 4122 UUID."""
    import re
    if value is None or re.fullmatch(r"urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                                     r"[0-9a-fA-F]{12}", value):
        return None
    return f"error: --serial must be urn:uuid: followed by a UUID (got {value!r})"

"""Local state coordination. Lock files are permanent; never unlink them.

Cooperating writers on a local filesystem only. Copying or restoring old signing
state can still reuse a one-time key; this is not hardware rollback protection.
"""
import os
import re
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def state_lock(path):
    path = Path(path).resolve()
    with open(str(path) + '.lock', 'a+b') as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b'\0')
            handle.flush()
        handle.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


# Windows refuses to replace or open a file while another process holds it open without
# sharing: a second signer reading the state, a backup tool, a virus scanner. That is a
# short wait, not a failure, so both operations are retried for a bounded time.
_BUSY_WAIT_SECONDS = 10.0


def _retry_while_busy(operation):
    deadline = time.monotonic() + _BUSY_WAIT_SECONDS
    delay = 0.005
    while True:
        try:
            return operation()
        except PermissionError:
            if os.name != 'nt' or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.2)


def _replace(name, path):
    _retry_while_busy(lambda: os.replace(name, path))


def read_state_text(path):
    """The state file's text, waiting out a moment in which another process is replacing it."""
    return _retry_while_busy(lambda: Path(path).read_text(encoding='utf-8'))


_MKSTEMP_PART = re.compile(r'[a-z0-9_]{8}')


def remove_stale_temps(path):
    """Temporary copies of the state left by a writer that was killed between writing and renaming. They hold the
    seed, so they are removed. Call only while holding `state_lock(path)`: no live writer can own one then."""
    path = Path(path)
    prefix = path.name + '.'
    with os.scandir(path.parent) as entries:
        # exactly `<name>.<8 characters from mkstemp>.tmp`: no other key's temporary file has that shape
        stale = [e.path for e in entries if e.name.startswith(prefix) and e.name.endswith('.tmp')
                 and _MKSTEMP_PART.fullmatch(e.name[len(prefix):-len('.tmp')])]
    for name in stale:
        try:
            os.unlink(name)
        except OSError:
            pass


def atomic_write(path, data):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _replace(name, path)
        if os.name != 'nt':
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)

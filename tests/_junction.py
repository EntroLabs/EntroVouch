"""Windows junctions for the tests that need one.

The standard library can make a junction without a shell only through `_winapi`, a private module that can also
start processes. The auditor reports that import, so this one helper holds it, and the repository test allows that
one finding in this file and nothing else.
"""
from __future__ import annotations

import sys
from pathlib import Path


def make_junction(link: Path, target: Path) -> bool:
    """Create `link` as a junction to the folder `target`. False where junctions cannot be made."""
    if sys.platform != "win32":
        return False
    import _winapi
    try:
        _winapi.CreateJunction(str(target), str(link))
    except OSError:
        return False
    return True

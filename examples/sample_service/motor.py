"""Local module named `motor`.

`motor` is also an async MongoDB driver on the blocklist. Python's own
resolution order means this file shadows that package for imports in this
tree, so `import motor` in drive.py is NOT a network import. The auditor
must list the name in `shadowed_imports` rather than vanish it or flag it.
"""


def steps_for(degrees: int, step_angle: float = 1.8) -> int:
    if step_angle <= 0:
        raise ValueError("step_angle must be positive")
    return int(round(degrees / step_angle))

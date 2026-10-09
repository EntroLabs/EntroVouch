"""Single source of truth for the package version.

`tool_version` is a field of every report, so it travels to whoever receives the
audit, and a reader reproducing the run compares it. One constant, imported
everywhere, and `tests/test_version.py` asserts that every place agrees.

The version changes whenever a report can legitimately change on the same tree:
a new file type read, a new finding kind, a changed detail string. Two reports
that carry the same version must come from the same detection rules.
"""

__version__ = "1.1.0"

"""Single source of truth for the package version.

WHY THIS FILE EXISTS
--------------------
Before 2026-08-19 the version was written in three places and disagreed:
`__init__.__version__` said 1.1.0, `no_egress_auditor.AuditReport.tool_version`
said 1.1.0, and `cbom.CBOM.tool_version` said 1.0.0 — while the release itself
was tagged v1.0.0. Four claims, three values.

That is not cosmetic. `tool_version` is a **field of the report**, so it travels
to whoever receives the audit, and a reader reproducing the run compares it. Two
sibling tools in one package reporting different versions of that package is the
same class of defect that has broken a real outreach pack before: a report the
recipient cannot line up with a tool they can obtain.

One constant, imported everywhere, plus `tests/test_version.py` asserting they
agree — so the next divergence fails a test instead of shipping.
"""

__version__ = "1.0.0"

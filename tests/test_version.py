"""The version must agree everywhere it is claimed.

Before 2026-08-19 it did not: __init__ said 1.1.0, the auditor's report field said
1.1.0, and the CBOM's said 1.0.0, while the release was v1.0.0. `tool_version` is a
REPORT FIELD, so a disagreement travels to whoever receives the audit and breaks the
one thing the report is for — being reproducible by its recipient.
"""
import entrovouch
from entrovouch._version import __version__
from entrovouch.no_egress_auditor import AuditReport
from entrovouch.cbom import CBOM


def test_package_version_matches_shared_constant():
    assert entrovouch.__version__ == __version__


def test_audit_report_declares_the_package_version():
    assert AuditReport.__dataclass_fields__["tool_version"].default == __version__


def test_cbom_declares_the_package_version():
    assert CBOM.__dataclass_fields__["tool_version"].default == __version__


def test_both_tools_agree_with_each_other():
    """The reproducibility failure in miniature: two tools, one package, two versions."""
    assert (AuditReport.__dataclass_fields__["tool_version"].default
            == CBOM.__dataclass_fields__["tool_version"].default)


def test_public_api_resolves():
    """The documented public API must be importable from the package root."""
    for name in ("audit", "verify_report", "build_cbom", "render_cbom_markdown"):
        assert callable(getattr(entrovouch, name))

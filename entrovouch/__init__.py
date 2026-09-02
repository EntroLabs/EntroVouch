"""ENTROVOUCH — sovereign supply-chain toolkit: no-egress auditor + CBOM generator."""
from ._version import __version__
from .no_egress_auditor import audit, verify_report, verify_any, render_markdown, AuditReport
from .cbom import build_cbom, verify_cbom, CBOM, CryptoUse
from .cbom import render_markdown as render_cbom_markdown
from .signer import MerkleSigner, verify_signature, ALGORITHM
from .sarif import to_sarif
from .attestation import to_statement
from .cyclonedx import to_cyclonedx
from .sbom import build_sbom, to_cyclonedx as to_cyclonedx_sbom, SBOM

# Eager imports, deliberately.
#
# `python -m entrovouch.no_egress_auditor` — the invocation the README documents
# first — prints a runpy RuntimeWarning because this package has already imported
# the module runpy is about to execute. That is cosmetic and standard Python.
#
# It was briefly "fixed" on 2026-08-19 with PEP 562 lazy exports via
# importlib.import_module. That silenced the warning and broke something that
# matters far more: this auditor flags dynamic import as `dynamic-exec`, correctly,
# because it is a genuine blind spot for static analysis. So the tool stopped
# passing its own audit — while its own docstring invites the reader to run it on
# its own source, and the README says "clone it and check our work".
#
# A warning on stdout costs a reader nothing. An auditor that cannot pass its own
# audit costs it the only thing it sells. Reverted, and recorded here so the trade
# is not re-made by someone who only sees the warning.

__all__ = [
    # auditing
    "audit", "verify_report", "verify_any", "render_markdown", "AuditReport",
    # cryptographic bill of materials
    "build_cbom", "verify_cbom", "render_cbom_markdown", "CBOM", "CryptoUse",
    # signing — HASH-BASED (Lamport-Merkle) is the default.
    #
    "MerkleSigner", "verify_signature", "ALGORITHM",
    # interoperable output
    "to_sarif", "to_statement", "to_cyclonedx",
    "build_sbom", "to_cyclonedx_sbom", "SBOM",
    "__version__",
]

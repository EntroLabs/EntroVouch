"""ENTROVOUCH: no-egress auditor, cryptographic inventory, key provenance and SBOM, with signed reports."""
from ._version import __version__

# Exports load on first use, through ordinary import statements inside `__getattr__` (PEP 562).
#
# Importing every module here made `python -m entrovouch.<tool>` load the module before runpy ran it, which Python
# reports as a RuntimeWarning on every run and which `-W error` turns into a crash. A plain `from . import x` inside
# a function is a static import the auditor reads like any other; it is not dynamic import, so the package still
# passes its own audit.

_EXPORTS = {
    # auditing
    "audit": ("no_egress_auditor", "audit"),
    "verify_report": ("no_egress_auditor", "verify_report"),
    "verify_any": ("no_egress_auditor", "verify_any"),
    "render_markdown": ("no_egress_auditor", "render_markdown"),
    "AuditReport": ("no_egress_auditor", "AuditReport"),
    # cryptographic bill of materials
    "build_cbom": ("cbom", "build_cbom"),
    "verify_cbom": ("cbom", "verify_cbom"),
    "render_cbom_markdown": ("cbom", "render_markdown"),
    "CBOM": ("cbom", "CBOM"),
    "CryptoUse": ("cbom", "CryptoUse"),
    # signing (Lamport-Merkle over SHA3-256)
    "MerkleSigner": ("signer", "MerkleSigner"),
    "verify_signature": ("signer", "verify_signature"),
    "ALGORITHM": ("signer", "ALGORITHM"),
    # interoperable output
    "to_sarif": ("sarif", "to_sarif"),
    "to_statement": ("attestation", "to_statement"),
    "to_cyclonedx": ("cyclonedx", "to_cyclonedx"),
    "build_sbom": ("sbom", "build_sbom"),
    "verify_sbom": ("sbom", "verify_sbom"),
    "to_cyclonedx_sbom": ("sbom", "to_cyclonedx"),
    "SBOM": ("sbom", "SBOM"),
}

__all__ = [*_EXPORTS, "__version__"]


def _module(name: str):
    if name == "no_egress_auditor":
        from . import no_egress_auditor as m
    elif name == "cbom":
        from . import cbom as m
    elif name == "signer":
        from . import signer as m
    elif name == "sarif":
        from . import sarif as m
    elif name == "attestation":
        from . import attestation as m
    elif name == "cyclonedx":
        from . import cyclonedx as m
    else:
        from . import sbom as m
    return m


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module 'entrovouch' has no attribute {name!r}")
    module, attr = _EXPORTS[name]
    value = getattr(_module(module), attr)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))

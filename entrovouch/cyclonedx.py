#!/usr/bin/env python3
"""
ENTROVOUCH — CycloneDX 1.6 CBOM export.

WHY THIS EXISTS, AND WHY THE TIMING MATTERS
-------------------------------------------
CycloneDX added native cryptographic-asset support in 1.6 and was published as
**ECMA-424**. It is the schema regulators, procurement teams and PQC-migration
tooling already read.

**Executive Order 14412, "Securing the Nation Against Advanced Cryptographic
Attacks," signed 22 June 2026, directs CISA with NIST to publish the minimum
elements for a CBOM within 270 days — approximately 19 March 2027.**

A bespoke CBOM format therefore becomes non-compliant on a **known date**. This
module is not a nicety; it is the difference between an inventory a buyer can
submit and one they have to translate.

⚠️ SCOPE, STATED RATHER THAN IMPLIED. This emits CycloneDX 1.6
`cryptographic-asset` components from what the CBOM generator found. It does
NOT claim conformance with the CISA/NIST minimum elements, **because those have
not been published yet.** When they are, this file is where the delta lands.
Anyone told this is "EO 14412 compliant" today is being told something nobody
can currently know.

WHAT IS DELIBERATELY NOT CLAIMED
--------------------------------
CycloneDX models an `assetType` of `algorithm`, `certificate`, `protocol` or
`related-crypto-material`. This tool finds **algorithms referenced in source**.
It does not enumerate certificates, protocol suites, or key material, and it
therefore emits only `algorithm` components. A CBOM that silently emitted empty
certificate sections would read as coverage it does not have.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ._version import __version__

__all__ = ["to_cyclonedx", "SPEC_VERSION", "NIST_QUANTUM_SECURITY_LEVEL"]

SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# CycloneDX `primitive` enum values, mapped from this tool's category vocabulary.
_PRIMITIVE = {
    "hash": "hash",
    "mac": "mac",
    "signature": "signature",
    "kem": "kem",
    "cipher": "block-cipher",
    "rng": "drbg",
    "library": "other",
}

# CycloneDX `cryptoProperties.classicalSecurityLevel` is a bit-strength integer
# and `nistQuantumSecurityLevel` is 0-6. We do NOT invent bit strengths we did
# not measure; only the quantum level is asserted, and only where the mapping is
# unambiguous. Everything else is carried as an explicit property instead of
# being guessed into a numeric field.
NIST_QUANTUM_SECURITY_LEVEL = {
    "SAFE": 3,               # PQC-standardised or hash-based at >=192-bit
    "GROVER-REDUCED": 1,     # symmetric/hash, halved by Grover but not broken
    "VULNERABLE": 0,         # Shor-breakable public-key
    "BROKEN": 0,             # already broken classically
    "WEAK-RNG": 0,
    "REVIEW": 0,
}

_STATE = {
    "SAFE": "active",
    "GROVER-REDUCED": "active",
    "VULNERABLE": "deactivated",
    "BROKEN": "compromised",
    "WEAK-RNG": "deactivated",
    "REVIEW": "active",
}


def _bom_ref(use: dict) -> str:
    f = str(use.get("file", "")).replace("\\", "/")
    return f"crypto/{use.get('primitive','unknown')}/{f}#{use.get('line', 0)}"


def _component(use: dict) -> dict:
    quantum = use.get("quantum", "REVIEW")
    name = use.get("primitive", "unknown")
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(use),
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": _PRIMITIVE.get(use.get("category", ""), "other"),
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
                "cryptoFunctions": ["unknown"],
                "nistQuantumSecurityLevel": NIST_QUANTUM_SECURITY_LEVEL.get(quantum, 0),
            },
            "oid": "",
        },
        "evidence": {
            "occurrences": [{
                "location": str(use.get("file", "")).replace("\\", "/"),
                "line": use.get("line", 0),
            }]
        },
        "properties": [
            # The tool's own verdict vocabulary is carried verbatim rather than
            # being flattened into the numeric field above. A consumer who knows
            # this tool gets the precise finding; one who does not still gets a
            # standard-shaped component.
            {"name": "entrovouch:quantumStatus", "value": quantum},
            {"name": "entrovouch:state", "value": _STATE.get(quantum, "active")},
            {"name": "entrovouch:detail", "value": str(use.get("detail", ""))},
        ],
    }


def to_cyclonedx(cbom_dict: dict, serial_number: str | None = None) -> dict:
    """Convert an ENTROVOUCH CBOM (as a dict) into a CycloneDX 1.6 BOM."""
    components = [_component(u) for u in (cbom_dict.get("components") or [])]

    bom: dict = {
        "bomFormat": _BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": cbom_dict.get("scanned_at_utc", ""),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "ENTROVOUCH CBOM generator",
                    "version": cbom_dict.get("tool_version", __version__),
                }]
            },
            "component": {
                "type": "application",
                "name": cbom_dict.get("target", "unknown"),
                "bom-ref": "subject",
            },
            "properties": [
                {"name": "entrovouch:verdict",
                 "value": cbom_dict.get("verdict", "")},
                {"name": "entrovouch:filesScanned",
                 "value": str(cbom_dict.get("files_scanned", 0))},
                # The limits travel INSIDE the standard artifact. A CBOM that
                # arrives without its scope reads as a completeness claim.
                {"name": "entrovouch:scopeStatement",
                 "value": cbom_dict.get("scope_statement", "")},
                {"name": "entrovouch:findingsDigest",
                 "value": cbom_dict.get("findings_digest", "")},
                {"name": "entrovouch:subjectDigest",
                 "value": cbom_dict.get("subject_digest", "")},
                # Said plainly, in the artifact, because the deadline invites
                # exactly this overclaim.
                {"name": "entrovouch:minimumElementsConformance",
                 "value": "NOT CLAIMED - CISA/NIST minimum elements under "
                          "EO 14412 are unpublished as of this build"},
            ],
        },
        "components": components,
    }

    if serial_number:
        bom["serialNumber"] = serial_number

    digest = cbom_dict.get("subject_digest") or cbom_dict.get("content_hash")
    if digest:
        bom["metadata"]["component"]["hashes"] = [
            {"alg": "SHA3-256", "content": digest}
        ]
    return bom


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Convert an ENTROVOUCH CBOM (JSON) to CycloneDX 1.6.")
    ap.add_argument("cbom", type=Path, help="CBOM .json")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--serial", default=None,
                    help="BOM serial number (urn:uuid:...). Omitted if unset; "
                         "this tool will not invent one.")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    bom = to_cyclonedx(json.loads(args.cbom.read_text(encoding="utf-8")),
                       serial_number=args.serial)
    text = json.dumps(bom, indent=2)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(bom['components'])} cryptographic assets)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

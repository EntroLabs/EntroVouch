#!/usr/bin/env python3
"""
ENTROVOUCH — Software Bill of Materials from declared manifests.

A CycloneDX 1.6 SBOM of the dependencies the tree *declares*, not of the
binaries it would produce. The EU CRA (Annex I Part II(1)) asks for an SBOM
in a commonly used machine-readable format covering at least top-level
dependencies. This is that artifact. It is not a CISA 2026-complete SBOM.

WHAT THIS DOES
--------------
Reads pyproject.toml, requirements*.txt, setup.cfg and package.json. Emits one
CycloneDX `library` component per declared name. Exact pins (`==1.2.3`, npm
without a range operator) become `version` and a PURL with `@version`. Ranges
stay in a property; we do not invent a version we did not see.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
- Hash an executable artifact. CISA 2026 Component Hash Value is the hash of
  the built component, not of a manifest line. We do not have that file, so
  the field is labelled **unknown** (not withheld).
- Enumerate transitive dependencies. Coverage under CISA 2026 is "all
  components, including transitives, no minimum depth." A manifest parser
  cannot satisfy that. The BOM says `top-level-declared-only`.
- Invent licenses or producers. Unknown, labelled as such.
- Open a network connection to resolve, download or query a registry.

Generation context is `pre-build`. A source-manifest SBOM is permitted under
CISA 2026; it is not equivalent to one produced from the finished binary, and
the document says so rather than letting a consumer assume otherwise.

Usage:
    python -m entrovouch.sbom <target_dir> [--json out.json] [--cdx out.cdx.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ._version import __version__
from .manifests import (
    DeclaredDep, collect_declared_deps, pep503_name,
    pinned_npm_version, pinned_pypi_version,
)
from .no_egress_auditor import (
    _DEFAULT_COVENANT, _file_digest, _sign, _subject_name,
    _tree_digest, canonical_body, reproducible_body,
)
from .signer import UNSIGNED, MerkleSigner, SignerError

SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# CISA 2026 generation-context vocabulary, three values. Manifest parsing is
# the earliest: information obtained prior to a build.
_GENERATION_CONTEXT = "pre-build"

_SCOPE = (
    "Software Bill of Materials from declared top-level dependencies in "
    "pyproject.toml, requirements*.txt, setup.cfg and package.json. "
    "Generation context: pre-build (source manifests). Transitive "
    "dependencies are NOT enumerated. Component hashes of executable "
    "artifacts are UNKNOWN — this tool does not see a build. Licenses and "
    "component producers are UNKNOWN unless present in the declaration, "
    "which they almost never are. npm devDependencies are omitted. "
    "package-lock.json / poetry.lock / uv.lock are not read (a lockfile is "
    "a resolved graph; this pass is the declaration). CISA 2026 Minimum "
    "Elements conformance is NOT CLAIMED. Unknown fields are labelled "
    "unknown-to-author, not withheld."
)


@dataclass
class SbomComponent:
    name: str
    ecosystem: str
    spec: str
    file: str
    line: int
    scope: str
    extra: str = ""
    version: str = ""          # exact pin only; empty means unknown
    purl: str = ""
    version_status: str = "unknown"   # "pinned" | "unknown"
    hash_status: str = "unknown"
    license_status: str = "unknown"
    producer_status: str = "unknown"


@dataclass
class SBOM:
    tool: str = "ENTROVOUCH SBOM"
    tool_version: str = __version__
    target: str = ""
    scanned_at_utc: str = ""
    files_scanned: int = 0
    verdict: str = "DECLARED"   # DECLARED | EMPTY
    components: list = field(default_factory=list)
    unknown_fields: list = field(default_factory=list)
    generation_context: str = _GENERATION_CONTEXT
    coverage: str = "top-level-declared-only"
    scope_statement: str = _SCOPE
    cisa_2026_conformance: str = (
        "NOT CLAIMED — source-manifest SBOM; component hashes, transitive "
        "coverage and licenses are labelled unknown rather than filled"
    )
    subject: list = field(default_factory=list)
    subject_digest: str = ""
    findings_digest: str = ""
    content_hash: str = ""
    integrity_tag: str = ""
    signature: dict | None = None
    signature_algorithm: str = UNSIGNED
    public_root: str = ""


def _purl(dep: DeclaredDep, version: str) -> str:
    if dep.ecosystem == "npm":
        name = dep.name
        # CycloneDX / package-url: scoped packages are %40scope/name
        if name.startswith("@") and "/" in name:
            scope, pkg = name[1:].split("/", 1)
            base = f"pkg:npm/%40{scope}/{pkg}"
        else:
            base = f"pkg:npm/{name}"
        return f"{base}@{version}" if version else base
    n = pep503_name(dep.name)
    base = f"pkg:pypi/{n}"
    return f"{base}@{version}" if version else base


def _version_of(dep: DeclaredDep) -> str:
    if dep.ecosystem == "npm":
        # "axios@1.6.0" or "@scope/pkg@1.6.0" — version is after the last @
        ver = dep.spec.rsplit("@", 1)[-1] if dep.spec.count("@") else ""
        if ver == dep.spec:  # no @version
            ver = ""
        return pinned_npm_version(ver) or ""
    return pinned_pypi_version(dep.spec) or ""


def _component(dep: DeclaredDep) -> SbomComponent:
    version = _version_of(dep)
    return SbomComponent(
        name=dep.name,
        ecosystem=dep.ecosystem,
        spec=dep.spec,
        file=dep.file,
        line=dep.line,
        scope=dep.scope,
        extra=dep.extra,
        version=version,
        purl=_purl(dep, version),
        version_status="pinned" if version else "unknown",
        hash_status="unknown",
        license_status="unknown",
        producer_status="unknown",
    )


def build_sbom(target: Path | str, covenant_text: str = _DEFAULT_COVENANT,
               signer: "MerkleSigner | None" = None,
               label: str | None = None) -> SBOM:
    target = Path(target)
    deps, errors, files = collect_declared_deps(target)
    tree = [(rel, _file_digest(p)) for p, rel in files]

    comps = [_component(d) for d in deps]
    # Stable order: ecosystem, name, file, line.
    comps.sort(key=lambda c: (c.ecosystem, c.name.lower(), c.file, c.line))

    unknowns = [
        "component-hash (no executable artifact)",
        "component-license",
        "component-producer",
        "transitive-dependencies",
    ]
    if any(c.version_status == "unknown" for c in comps):
        unknowns.append("component-version (declared as a range, not a pin)")

    rep = SBOM(
        target=label or _subject_name(target),
        scanned_at_utc=datetime.now(timezone.utc).isoformat(),
        files_scanned=len(files),
        verdict="DECLARED" if comps else "EMPTY",
        components=[asdict(c) for c in comps],
        unknown_fields=unknowns,
    )
    if errors:
        # Parse failures are coverage gaps. Recorded, not silent.
        rep.unknown_fields.append(
            "unparseable-manifest: " + "; ".join(e.detail for e in errors)
        )

    rep.subject_digest = _tree_digest(tree)
    rep.subject = [{"name": rep.target, "digest": {"sha3-256": rep.subject_digest}}]
    rep.findings_digest = hashlib.sha3_256(
        reproducible_body(asdict(rep))).hexdigest()
    if signer is not None:
        rep.signature_algorithm = signer.algorithm
        rep.public_root = signer.public_root
    ch, tag = _sign(asdict(rep), covenant_text)
    rep.content_hash = ch
    rep.integrity_tag = tag
    if signer is not None:
        rep.signature = signer.sign(canonical_body(asdict(rep)))
        if rep.signature.get("algorithm", rep.signature_algorithm) != rep.signature_algorithm:
            raise SignerError(
                "signer.algorithm disagrees with the algorithm in its own signature"
            )
    return rep


def to_cyclonedx(sbom_dict: dict, serial_number: str | None = None) -> dict:
    """CycloneDX 1.6 software BOM. Not a CBOM."""
    components = []
    for c in sbom_dict.get("components") or []:
        name = c.get("name") or "unknown"
        ref = f"pkg/{c.get('ecosystem','pypi')}/{name}#{c.get('file','')}:{c.get('line', 0)}"
        comp: dict = {
            "type": "library",
            "bom-ref": ref.replace("\\", "/"),
            "name": name,
            "purl": c.get("purl") or "",
            "scope": "optional" if c.get("scope") == "optional" else "required",
            "properties": [
                {"name": "entrovouch:declaredSpec", "value": str(c.get("spec", ""))},
                {"name": "entrovouch:ecosystem", "value": str(c.get("ecosystem", ""))},
                {"name": "entrovouch:manifest", "value": str(c.get("file", ""))},
                {"name": "entrovouch:versionStatus", "value": str(c.get("version_status", "unknown"))},
                {"name": "entrovouch:componentHash", "value": "unknown"},
                {"name": "entrovouch:componentLicense", "value": "unknown"},
                {"name": "entrovouch:componentProducer", "value": "unknown"},
                {"name": "entrovouch:unknownKind", "value": "unknown-to-author"},
            ],
        }
        if c.get("version"):
            comp["version"] = c["version"]
        if c.get("extra"):
            comp["properties"].append(
                {"name": "entrovouch:optionalExtra", "value": str(c["extra"])}
            )
        components.append(comp)

    bom: dict = {
        "bomFormat": _BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": sbom_dict.get("scanned_at_utc", ""),
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "ENTROVOUCH SBOM",
                    "version": sbom_dict.get("tool_version", __version__),
                }]
            },
            "component": {
                "type": "application",
                "name": sbom_dict.get("target", "unknown"),
                "bom-ref": "subject",
            },
            "properties": [
                {"name": "entrovouch:verdict",
                 "value": sbom_dict.get("verdict", "")},
                {"name": "entrovouch:generationContext",
                 "value": sbom_dict.get("generation_context", _GENERATION_CONTEXT)},
                {"name": "entrovouch:coverage",
                 "value": sbom_dict.get("coverage", "top-level-declared-only")},
                {"name": "entrovouch:scopeStatement",
                 "value": sbom_dict.get("scope_statement", "")},
                {"name": "entrovouch:findingsDigest",
                 "value": sbom_dict.get("findings_digest", "")},
                {"name": "entrovouch:subjectDigest",
                 "value": sbom_dict.get("subject_digest", "")},
                {"name": "entrovouch:cisa2026MinimumElements",
                 "value": sbom_dict.get("cisa_2026_conformance", "")},
                {"name": "entrovouch:unknownFields",
                 "value": "; ".join(sbom_dict.get("unknown_fields") or [])},
            ],
        },
        "components": components,
    }
    if serial_number:
        bom["serialNumber"] = serial_number
    digest = sbom_dict.get("subject_digest") or sbom_dict.get("content_hash")
    if digest:
        bom["metadata"]["component"]["hashes"] = [
            {"alg": "SHA3-256", "content": digest}
        ]
    return bom


def render_markdown(rep: SBOM) -> str:
    lines = [
        f"# ENTROVOUCH SBOM — {rep.verdict}",
        "",
        f"- **Target:** `{rep.target}`",
        f"- **Scanned:** {rep.scanned_at_utc}",
        f"- **Manifests read:** {rep.files_scanned}",
        f"- **Declared components:** {len(rep.components)}",
        f"- **Generation context:** `{rep.generation_context}` (source manifests, before build)",
        f"- **Coverage:** `{rep.coverage}`",
        f"- **CISA 2026 minimum elements:** {rep.cisa_2026_conformance}",
        f"- **Findings digest (reproduces):** `{rep.findings_digest[:32]}…`",
        f"- **Subject digest (binds the manifests):** `{rep.subject_digest[:32]}…`",
        f"- **Content hash (this issuance only, does NOT reproduce):** "
        f"`{rep.content_hash[:32]}…`",
    ]
    if rep.signature:
        lines += [
            f"- **Signed by:** `{rep.public_root[:32]}…` ({rep.signature_algorithm})",
        ]
    else:
        lines += [f"- **Signature:** {UNSIGNED}"]
    lines += [
        "",
        f"> **Scope:** {rep.scope_statement}",
        "",
        "**Unknown (not withheld):** " + "; ".join(rep.unknown_fields),
        "",
    ]
    if rep.components:
        lines += [
            "## Declared components",
            "",
            "| Name | Ecosystem | Version | Scope | Manifest | Spec |",
            "|---|---|---|---|---|---|",
        ]
        for c in rep.components:
            ver = c.get("version") or "unknown"
            lines.append(
                f"| `{c['name']}` | {c['ecosystem']} | `{ver}` | {c['scope']} | "
                f"`{c['file']}` | `{c['spec']}` |"
            )
    else:
        lines.append("**No declared dependencies in the manifests this tool reads.**")
    lines += ["", "*ENTROVOUCH SBOM — declared top-level only. For the People.*"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ENTROVOUCH SBOM — CycloneDX 1.6 from declared manifests")
    ap.add_argument("target", type=Path, help="directory to inventory")
    ap.add_argument("--json", type=Path, default=None, help="write ENTROVOUCH JSON")
    ap.add_argument("--md", type=Path, default=None, help="write markdown")
    ap.add_argument("--cdx", type=Path, default=None,
                    help="write CycloneDX 1.6 JSON (the CRA-shaped artifact)")
    ap.add_argument("--covenant", type=Path, default=None,
                    help="IGNORED (kept so old invocations do not crash).")
    ap.add_argument("--key", type=Path, default=None,
                    help="signing identity. WITHOUT THIS THE SBOM IS UNSIGNED.")
    ap.add_argument("--label", default=None,
                    help="identity of the subject in the report")
    ap.add_argument("--serial", default=None,
                    help="CycloneDX serial number (urn:uuid:...). Omitted if unset.")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    cov = args.covenant.read_text(encoding="utf-8") if args.covenant else _DEFAULT_COVENANT
    signer = MerkleSigner.load(args.key) if args.key else None
    if signer is None:
        print("warning: no --key given; SBOM will be UNSIGNED", file=sys.stderr)
    rep = build_sbom(args.target, cov, signer=signer, label=args.label)
    payload = asdict(rep)
    if args.json:
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.md:
        args.md.write_text(render_markdown(rep), encoding="utf-8")
    if args.cdx:
        cdx = to_cyclonedx(payload, serial_number=args.serial)
        args.cdx.write_text(json.dumps(cdx, indent=2), encoding="utf-8")
    print(render_markdown(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

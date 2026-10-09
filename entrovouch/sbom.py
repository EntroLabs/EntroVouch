#!/usr/bin/env python3
"""
ENTROVOUCH: Software Bill of Materials from declared manifests.

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
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import _reads
from ._cli import missing_folder, run, uuid_urn, write_text
from ._version import __version__
from .manifests import (
    DeclaredDep, _requirement_remote, collect_manifests, pep503_name,
    pinned_npm_version, pinned_pypi_version,
)
from .no_egress_auditor import (
    _file_digest, _sign, _subject_name,
    _tree_digest, canonical_body, markdown_cell, markdown_code, reproducible_body, verify_report,
)
from .signer import UNSIGNED, MerkleSigner, SignerError

SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# CISA 2026 generation-context vocabulary, three values. Manifest parsing is
# the earliest: information obtained prior to a build.
_GENERATION_CONTEXT = "pre-build"

_SCOPE = (
    "Software Bill of Materials from declared top-level dependencies in "
    "pyproject.toml (PEP 621 and Poetry), requirement files, setup.cfg, setup.py, "
    "Pipfile, conda environment files and package.json. Development groups, build "
    "requirements and npm devDependencies are declared but are not product "
    "dependencies, and are left out. "
    "Generation context: pre-build (source manifests). Transitive "
    "dependencies are NOT enumerated. Component hashes of executable "
    "artifacts are UNKNOWN: this tool does not see a build. Licenses and "
    "component producers are UNKNOWN unless present in the declaration, "
    "which they almost never are. "
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
    verdict: str = "DECLARED"   # DECLARED | EMPTY | INCOMPLETE
    components: list = field(default_factory=list)
    unknown_fields: list = field(default_factory=list)
    generation_context: str = _GENERATION_CONTEXT
    coverage: str = "top-level-declared-only"
    scope_statement: str = _SCOPE
    cisa_2026_conformance: str = (
        "NOT CLAIMED: source-manifest SBOM; component hashes, transitive "
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
    # Installed from a URL or a repository, not from the index: a `pkg:pypi/...` name would point a scanner at
    # whatever package of that name the public index holds, which may be someone else's (dependency confusion).
    if dep.source:
        return ""                  # installed from git, a URL, a path, another index or the workspace
    remote = _requirement_remote(dep.spec) if dep.ecosystem == "pypi" else None
    if remote and remote[0] in ("vcs-requirement", "url-requirement"):
        return ""
    if dep.ecosystem == "pypi" and re.search(r"@\s*file:", dep.spec, re.IGNORECASE):
        return ""                  # a local file or folder, not the index
    if dep.ecosystem == "npm":
        name = dep.name
        if ":" in _npm_requested(dep) or "/" in _npm_requested(dep):
            return ""              # a file, a link, a repository, a URL or an alias: not this name on the registry
        # CycloneDX / package-url: scoped packages are %40scope/name
        if name.startswith("@") and "/" in name:
            scope, pkg = name[1:].split("/", 1)
            base = f"pkg:npm/%40{scope.lower()}/{pkg.lower()}"     # the package-url rule for npm: lowercased
        else:
            base = f"pkg:npm/{name.lower()}"
        return f"{base}@{_purl_version(version)}" if version else base
    n = pep503_name(dep.name)
    if dep.ecosystem == "conda":
        return f"pkg:conda/{n}@{_purl_version(version)}" if version else f"pkg:conda/{n}"
    # the package-url rule for PyPI: lowercased, `_` written as `-` (a `.` stays: `pkg:pypi/zope.interface`)
    base = f"pkg:pypi/{dep.name.strip().lower().replace('_', '-')}"
    return f"{base}@{_purl_version(pep440_normal(version))}" if version else base


# A version as PEP 440 lets it be written (its appendix's pattern): epoch, release, pre-release, post-release,
# development release and local label, each in any of the spellings PEP 440 accepts.
_PEP440_RE = re.compile(r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    """, re.VERBOSE)
_PEP440_PRE = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "preview": "rc", "pre": "rc", "c": "rc", "rc": "rc"}


def pep440_normal(version: str) -> str:
    """The normal form PEP 440 gives a version for comparison and lookup: lower case, no `v` prefix, no leading zeros
    (`01.0` is `1.0`), and every other spelling it accepts written its one way (`1.0alpha1` is `1.0a1`, `1.0c1` is
    `1.0rc1`, `1.0-1` and `1.0_post1` are `1.0.post1`, `1.0-dev` is `1.0.dev0`, `1.0+Ubuntu-1` is `1.0+ubuntu.1`).
    A version PEP 440 does not accept is kept as written, apart from its case, a `v` prefix and leading zeros."""
    v = version.strip().lower()
    m = _PEP440_RE.fullmatch(v)
    if m is None:
        v = v[1:] if v[:1] == "v" and v[1:2].isdigit() else v
        m = re.match(r"([\d.]*)(.*)", v, re.S)
        release, rest = m.group(1), m.group(2)
        if release:
            release = ".".join(str(int(p)) if p.isdigit() else p for p in release.split("."))
        return release + rest
    out = f"{int(m.group('epoch'))}!" if m.group("epoch") and int(m.group("epoch")) else ""
    out += ".".join(str(int(p)) for p in m.group("release").split("."))
    if m.group("pre"):
        out += _PEP440_PRE[m.group("pre_l")] + str(int(m.group("pre_n") or 0))
    if m.group("post"):
        out += ".post" + str(int(m.group("post_n1") or m.group("post_n2") or 0))
    if m.group("dev"):
        out += ".dev" + str(int(m.group("dev_n") or 0))
    if m.group("local"):
        out += "+" + ".".join(str(int(p)) if p.isdigit() else p for p in re.split(r"[-_.]", m.group("local")))
    return out


def _purl_version(version: str) -> str:
    """A version as package-url writes it: characters outside the unreserved set percent-encoded (`+local` is
    `%2Blocal`)."""
    from urllib.parse import quote
    return quote(version, safe="-._~")


def _npm_requested(dep: DeclaredDep) -> str:
    """What package.json asks for: "axios@1.6.0" or "@scope/pkg@1.6.0" -> the text after the name and its @."""
    prefix = dep.name + "@"
    return dep.spec[len(prefix):] if dep.spec.startswith(prefix) else ""


def _version_of(dep: DeclaredDep) -> str:
    if dep.ecosystem == "npm":
        return pinned_npm_version(_npm_requested(dep)) or ""
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


def build_sbom(target: Path | str,
               signer: "MerkleSigner | None" = None,
               label: str | None = None) -> SBOM:
    """The declared-dependency inventory of `target`. Each manifest is read as one version for the whole run, so
    the components and the subject digest describe the same bytes. A target that is not a folder is refused: an
    inventory of nothing would read as a tree that declares nothing."""
    if not Path(target).is_dir():
        raise NotADirectoryError(f"{target} is not a directory")
    with _reads.one_read_per_file():
        return _build_sbom(target, signer, label)


def _build_sbom(target: Path | str,
                signer: "MerkleSigner | None" = None,
                label: str | None = None) -> SBOM:
    target = Path(target)
    scan = collect_manifests(target)
    deps, errors, files = scan.deps, scan.errors, scan.files
    tree = [(rel, _file_digest(p)) for p, rel in files]

    # Development groups and build requirements are declared, and are not part of the
    # product: the inventory lists what the product depends on. Stated in the scope.
    comps = [_component(d) for d in deps if d.scope not in ("dev", "build", "constraint")]   # a constraint adds nothing
    # One declaration read twice (a package.json naming a package under both `peerDependencies` and
    # `optionalDependencies`) is one component
    unique: dict = {}
    for c in comps:
        unique.setdefault(tuple(sorted(asdict(c).items())), c)
    comps = list(unique.values())
    # Stable order: ecosystem, name, file, line.
    comps.sort(key=lambda c: (c.ecosystem, c.name.lower(), c.file.encode("utf-8", "backslashreplace"), c.line, c.spec))

    unknowns = [
        "component-hash (no executable artifact)",
        "component-license",
        "component-producer",
        "transitive-dependencies",
    ]
    if any(c.version_status == "unknown" for c in comps):
        unknowns.append("component-version (declared as a range, not a pin)")
    # a requirement given only as a path names no package here: listed, not left out
    unknowns += [f"{rel}:{line} installs {path} from {'an address' if '://' in path else 'a path'}: its name and version "
                 "are that project's, not declared here" for rel, line, path in scan.paths]

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
            "unparseable-manifest: " + "; ".join(f"{e.file}: {e.detail}" for e in errors)
        )
        # a manifest that could not be read or parsed may declare what the inventory does not list
        rep.verdict = "INCOMPLETE"

    rep.subject_digest = _tree_digest(tree)
    rep.subject = [{"name": rep.target, "digest": {"sha3-256": rep.subject_digest}}]
    rep.findings_digest = hashlib.sha3_256(
        reproducible_body(asdict(rep))).hexdigest()
    if signer is not None:
        rep.signature_algorithm = signer.algorithm
        rep.public_root = signer.public_root
    ch, tag = _sign(asdict(rep))
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
    refs: dict[str, int] = {}
    for c in sbom_dict.get("components") or []:
        name = c.get("name") or "unknown"
        ref = f"pkg/{c.get('ecosystem','pypi')}/{name}#{c.get('file','')}:{c.get('line', 0)}"
        refs[ref] = refs.get(ref, 0) + 1
        if refs[ref] > 1:
            ref += f"~{refs[ref]}"     # a bom-ref names one component: a second listing at one place gets its own
        comp: dict = {
            "type": "library",
            "bom-ref": ref.replace("\\", "/"),
            "name": name,
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
        if c.get("purl"):
            comp["purl"] = c["purl"]
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
    # (the subject digest is this tool's digest over the files it read, not a hash of any artifact: it is carried as
    # the `entrovouch:subjectDigest` property above, never as the component's `hashes`)
    return bom


def verify_sbom(report_dict: dict, expected_root: str | None = None) -> tuple[bool, str]:
    """Verify an SBOM. Returns `(ok, status)` with the same four statuses as `verify_report`:
    ATTESTED / UNVERIFIED / UNSIGNED / TAMPERED. A report of another kind is TAMPERED here."""
    return verify_report(report_dict, expected_root=expected_root, expected_tool="ENTROVOUCH SBOM")


def render_markdown(rep: SBOM) -> str:
    lines = [
        f"# ENTROVOUCH SBOM: {rep.verdict}",
        "",
        f"- **Target:** {markdown_code(rep.target, in_table=False)}",
        f"- **Scanned:** {rep.scanned_at_utc}",
        f"- **Manifests read:** {rep.files_scanned}",
        f"- **Declared components:** {len(rep.components)}",
        f"- **Generation context:** `{rep.generation_context}` (source manifests, before build)",
        f"- **Coverage:** `{rep.coverage}`",
        f"- **CISA 2026 minimum elements:** {rep.cisa_2026_conformance}",
        f"- **Findings digest (reproduces):** `{rep.findings_digest}`",
        f"- **Subject digest (binds the manifests):** `{rep.subject_digest}`",
        f"- **Content hash (this issuance only, does NOT reproduce):** "
        f"`{rep.content_hash[:32]}…`",
    ]
    if rep.signature:
        lines += [
            f"- **Signed by:** `{rep.public_root}` ({rep.signature_algorithm})",
        ]
    else:
        lines += [f"- **Signature:** {UNSIGNED}"]
    lines += [
        "",
        f"> **Scope:** {rep.scope_statement}",
        "",
        "**Unknown (not withheld):** " + "; ".join(markdown_cell(u, in_table=False) for u in rep.unknown_fields),
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
                f"| {markdown_code(c['name'])} | {c['ecosystem']} | {markdown_code(ver)} | {c['scope']} | "
                f"{markdown_code(c['file'])} | {markdown_code(c['spec'])} |"
            )
    else:
        lines.append("**No declared dependencies in the manifests this tool reads.**")
    lines += ["", "*ENTROVOUCH SBOM: declared top-level only. For the People.*"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ENTROVOUCH SBOM: CycloneDX 1.6 from declared manifests")
    ap.add_argument("target", type=Path, help="directory to inventory")
    ap.add_argument("--json", type=Path, default=None, help="write ENTROVOUCH JSON")
    ap.add_argument("--md", type=Path, default=None, help="write markdown")
    ap.add_argument("--cdx", type=Path, default=None,
                    help="write CycloneDX 1.6 JSON (the CRA-shaped artifact)")
    ap.add_argument("--key", type=Path, default=None,
                    help="signing identity. WITHOUT THIS THE SBOM IS UNSIGNED.")
    ap.add_argument("--label", default=None,
                    help="identity of the subject in the report")
    ap.add_argument("--serial", default=None,
                    help="CycloneDX serial number (urn:uuid:...). Omitted if unset.")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    if args.key and not args.key.is_file():
        what = "is a folder, not a key file" if args.key.is_dir() else "does not exist"
        print(f"error: signing key {args.key} {what}", file=sys.stderr)
        return 2
    problem = missing_folder(args.json, args.md, args.cdx, key=args.key, tree=args.target) or uuid_urn(args.serial)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    signer = MerkleSigner.load(args.key) if args.key else None
    if signer is None:
        print("warning: no --key given; SBOM will be UNSIGNED", file=sys.stderr)
    rep = build_sbom(args.target, signer=signer, label=args.label)
    payload = asdict(rep)
    if args.json:
        write_text(args.json, json.dumps(payload, indent=2))
    if args.md:
        write_text(args.md, render_markdown(rep))
    if args.cdx:
        cdx = to_cyclonedx(payload, serial_number=args.serial)
        write_text(args.cdx, json.dumps(cdx, indent=2))
    print(render_markdown(rep))
    return 1 if rep.verdict == "INCOMPLETE" else 0


if __name__ == "__main__":
    raise SystemExit(run(main))

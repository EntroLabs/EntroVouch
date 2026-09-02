"""Declared-dependency manifests.

Shared by the no-egress auditor (network names only) and the SBOM exporter
(every declared name). Parsing lives here so the two tools cannot drift onto
different readings of the same pyproject.toml.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# Keep in step with no_egress_auditor.SKIP_DIRS. Duplicated so this module
# does not import the auditor (the auditor imports us).
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".mypy_cache",
}

MANIFEST_EXACT = {"pyproject.toml", "package.json", "setup.cfg"}


@dataclass(frozen=True)
class DeclaredDep:
    """One requirement line (or package.json key) as the author wrote it."""
    file: str
    line: int
    name: str
    spec: str
    ecosystem: str          # "pypi" | "npm"
    scope: str = "required"  # "required" | "optional"
    extra: str = ""         # optional-extra name, if any


@dataclass(frozen=True)
class ManifestError:
    file: str
    line: int
    detail: str


def is_requirements_filename(name: str) -> bool:
    n = name.lower()
    return n == "requirements.txt" or (
        n.startswith("requirements") and n.endswith(".txt")
    )


def requirement_name(spec: str) -> str | None:
    """'stripe[foo]>=2.0; python_version>\"3\"' -> 'stripe'. None if not a req."""
    s = spec.strip()
    if not s or s.startswith("#") or s.startswith("-"):
        return None
    s = s.split("#", 1)[0].strip()
    s = s.split(";", 1)[0].strip()
    if not s:
        return None
    s = re.split(r"[<>=!~\[]", s, maxsplit=1)[0].strip()
    s = s.strip("\"'")
    return s or None


def pep503_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def pinned_pypi_version(spec: str) -> str | None:
    """Only an exact pin (`==` / `===`). A range is not a component version."""
    m = re.search(r"===?\s*([0-9][^\s,;\]]*)", spec)
    if not m:
        return None
    ver = m.group(1).strip()
    return ver or None


def pinned_npm_version(ver: str) -> str | None:
    v = (ver or "").strip()
    if not v or v[0] in "^~*><=" or "*" in v or v.lower().endswith(".x"):
        return None
    return v


def _line_of(text: str, needle: str, default: int = 1) -> int:
    """First non-comment line containing needle. Comments that *mention*
    a package name must not steal the line number of the real requirement."""
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if needle in line:
            return i
    return default


def iter_manifest_files(target: Path):
    """Yield (path, posix-rel, text) for every manifest under target."""
    try:
        paths = sorted(target.rglob("*"))
    except OSError:
        return
    for p in paths:
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        name = p.name
        if name.lower() not in MANIFEST_EXACT and not is_requirements_filename(name):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(target)).replace("\\", "/")
        yield p, rel, text


def _deps_from_requirements(text: str, rel: str) -> list[DeclaredDep]:
    out: list[DeclaredDep] = []
    for i, line in enumerate(text.splitlines(), 1):
        name = requirement_name(line)
        if not name:
            continue
        out.append(DeclaredDep(
            file=rel, line=i, name=name, spec=line.strip(),
            ecosystem="pypi", scope="required",
        ))
    return out


def _deps_from_pyproject(text: str, rel: str) -> tuple[list[DeclaredDep], list[ManifestError]]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover — 3.10
        return _deps_from_requirements(text, rel), []

    try:
        data = tomllib.loads(text)
    except Exception:
        return [], [ManifestError(rel, 1, "pyproject.toml could not be parsed")]

    out: list[DeclaredDep] = []
    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        if not isinstance(spec, str):
            continue
        name = requirement_name(spec) or spec
        out.append(DeclaredDep(
            file=rel, line=_line_of(text, name.split("[", 1)[0]),
            name=name, spec=spec, ecosystem="pypi", scope="required",
        ))
    optional = project.get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for extra, specs in optional.items():
            if not isinstance(specs, list):
                continue
            for spec in specs:
                if not isinstance(spec, str):
                    continue
                name = requirement_name(spec) or spec
                out.append(DeclaredDep(
                    file=rel, line=_line_of(text, name.split("[", 1)[0]),
                    name=name, spec=spec, ecosystem="pypi",
                    scope="optional", extra=str(extra),
                ))
    tool = (data.get("tool") or {}).get("poetry") or {}
    deps = tool.get("dependencies") or {}
    if isinstance(deps, dict):
        for k, v in deps.items():
            if k == "python":
                continue
            spec = k if not isinstance(v, str) else f"{k} {v}".strip()
            out.append(DeclaredDep(
                file=rel, line=_line_of(text, k),
                name=k, spec=spec, ecosystem="pypi", scope="required",
            ))
    return out, []


def _deps_from_package_json(text: str, rel: str) -> tuple[list[DeclaredDep], list[ManifestError]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], [ManifestError(rel, 1, "package.json could not be parsed")]
    if not isinstance(data, dict):
        return [], []
    out: list[DeclaredDep] = []
    # devDependencies omitted on purpose: a product SBOM that mixes test
    # tooling with runtime deps is how this format starts lying. Disclosed
    # in the SBOM scope statement.
    for field, scope in (
        ("dependencies", "required"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "optional"),
    ):
        block = data.get(field) or {}
        if not isinstance(block, dict):
            continue
        for name, ver in block.items():
            spec = f"{name}@{ver}" if ver is not None else str(name)
            out.append(DeclaredDep(
                file=rel, line=_line_of(text, f'"{name}"'),
                name=str(name), spec=spec, ecosystem="npm", scope=scope,
            ))
    return out, []


def _deps_from_setup_cfg(text: str, rel: str) -> list[DeclaredDep]:
    in_requires = False
    collected: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_requires = stripped.lower() in ("[options]", "[options.extras_require]")
            continue
        if not in_requires:
            continue
        if stripped.lower().startswith("install_requires"):
            rest = stripped.split("=", 1)[-1].strip()
            if rest:
                collected.append((i, rest))
            continue
        if stripped and not stripped.startswith("#") and "=" not in stripped.split("#")[0]:
            collected.append((i, stripped))
    out: list[DeclaredDep] = []
    for i, spec in collected:
        name = requirement_name(spec)
        if name:
            out.append(DeclaredDep(
                file=rel, line=i, name=name, spec=spec.strip(),
                ecosystem="pypi", scope="required",
            ))
    return out


def collect_declared_deps(target: Path) -> tuple[list[DeclaredDep], list[ManifestError], list[tuple[Path, str]]]:
    """All declared deps, parse errors, and (path, rel) of manifests read."""
    deps: list[DeclaredDep] = []
    errors: list[ManifestError] = []
    files: list[tuple[Path, str]] = []
    for p, rel, text in iter_manifest_files(target):
        files.append((p, rel))
        low = p.name.lower()
        if low == "pyproject.toml":
            d, e = _deps_from_pyproject(text, rel)
            deps += d
            errors += e
        elif low == "package.json":
            d, e = _deps_from_package_json(text, rel)
            deps += d
            errors += e
        elif low == "setup.cfg":
            deps += _deps_from_setup_cfg(text, rel)
        elif is_requirements_filename(p.name):
            deps += _deps_from_requirements(text, rel)
    return deps, errors, files

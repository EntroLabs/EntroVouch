"""SBOM from declared manifests — the CRA-shaped artifact.

This is not a CISA 2026-complete SBOM. The tests pin the honesty: we emit
what we saw, we label what we did not, we do not invent a version from a range.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from entrovouch.sbom import build_sbom, to_cyclonedx


def _write(tmp_path: Path, name: str, text: str) -> None:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")


def test_stripe_range_is_a_component_with_unknown_version(tmp_path):
    _write(tmp_path, "pyproject.toml",
           "[project]\nname='x'\nversion='0'\n"
           "dependencies=['stripe>=2.0']\n")
    rep = build_sbom(tmp_path, label="t")
    names = {c["name"] for c in rep.components}
    assert names == {"stripe"}
    c = rep.components[0]
    assert c["version"] == ""
    assert c["version_status"] == "unknown"
    assert c["hash_status"] == "unknown"
    assert c["purl"] == "pkg:pypi/stripe"
    assert ">=2.0" in c["spec"]
    assert rep.verdict == "DECLARED"
    assert "NOT CLAIMED" in rep.cisa_2026_conformance
    assert "component-hash" in " ".join(rep.unknown_fields)


def test_exact_pin_becomes_version_and_purl(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.32.3\n")
    c = build_sbom(tmp_path).components[0]
    assert c["name"] == "requests"
    assert c["version"] == "2.32.3"
    assert c["version_status"] == "pinned"
    assert c["purl"] == "pkg:pypi/requests@2.32.3"


def test_optional_extra_is_in_the_sbom_and_labelled(tmp_path):
    _write(tmp_path, "pyproject.toml",
           "[project]\nname='x'\nversion='0'\n"
           "dependencies=[]\n"
           "[project.optional-dependencies]\n"
           "test=['pytest>=7']\n")
    c = build_sbom(tmp_path).components[0]
    assert c["name"] == "pytest"
    assert c["scope"] == "optional"
    assert c["extra"] == "test"


def test_package_json_omits_dev_dependencies(tmp_path):
    _write(tmp_path, "package.json", json.dumps({
        "name": "x",
        "dependencies": {"axios": "1.6.0"},
        "devDependencies": {"eslint": "9.0.0"},
    }))
    names = {c["name"] for c in build_sbom(tmp_path).components}
    assert names == {"axios"}
    c = build_sbom(tmp_path).components[0]
    assert c["version"] == "1.6.0"
    assert c["purl"] == "pkg:npm/axios@1.6.0"


def test_caret_range_is_not_a_pin(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies":{"axios":"^1.6.0"}}')
    c = build_sbom(tmp_path).components[0]
    assert c["version"] == ""
    assert c["version_status"] == "unknown"


def test_empty_tree_is_empty_not_a_failure(tmp_path):
    (tmp_path / "app.py").write_text("x=1\n", encoding="utf-8")
    rep = build_sbom(tmp_path)
    assert rep.verdict == "EMPTY"
    assert rep.components == []


def test_findings_digest_reproduces(tmp_path):
    _write(tmp_path, "requirements.txt", "click==8.1.0\n")
    a = build_sbom(tmp_path, label="t").findings_digest
    b = build_sbom(tmp_path, label="t").findings_digest
    assert a == b
    assert a != build_sbom(tmp_path, label="t").content_hash


def test_cyclonedx_shape_is_software_not_crypto(tmp_path):
    _write(tmp_path, "requirements.txt", "click==8.1.0\n")
    bom = to_cyclonedx(asdict(build_sbom(tmp_path, label="t")))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["lifecycles"] == [{"phase": "pre-build"}]
    assert bom["components"][0]["type"] == "library"
    assert "cryptoProperties" not in bom["components"][0]
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert "NOT CLAIMED" in props["entrovouch:cisa2026MinimumElements"]
    assert props["entrovouch:coverage"] == "top-level-declared-only"
    assert "component-hash" in props["entrovouch:unknownFields"]


def test_does_not_invent_a_serial_number(tmp_path):
    _write(tmp_path, "requirements.txt", "click==8.1.0\n")
    bom = to_cyclonedx(asdict(build_sbom(tmp_path)))
    assert "serialNumber" not in bom


def test_cli_writes_cdx(tmp_path):
    import os
    import subprocess
    import sys
    _write(tmp_path, "requirements.txt", "click==8.1.0\n")
    out = tmp_path / "bom.cdx.json"
    env = dict(os.environ)
    repo = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = str(repo)
    r = subprocess.run(
        [sys.executable, "-m", "entrovouch.sbom", str(tmp_path), "--cdx", str(out)],
        cwd=repo, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    assert r.returncode == 0, r.stderr
    bom = json.loads(out.read_text(encoding="utf-8"))
    assert bom["components"][0]["name"] == "click"

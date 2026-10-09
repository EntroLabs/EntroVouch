# ENTROVOUCH SBOM: DECLARED

- **Target:** `entrovouch/examples/sample_service`
- **Scanned:** 2026-10-09T21:24:51.525637+00:00
- **Manifests read:** 1
- **Declared components:** 1
- **Generation context:** `pre-build` (source manifests, before build)
- **Coverage:** `top-level-declared-only`
- **CISA 2026 minimum elements:** NOT CLAIMED: source-manifest SBOM; component hashes, transitive coverage and licenses are labelled unknown rather than filled
- **Findings digest (reproduces):** `eba24423f97e712ce825afc682a023c89308d14fbc1850120ab32cd8af307cc4`
- **Subject digest (binds the manifests):** `899cdc1ae105d7e57072041b1e0d3b38096d7470e01d6c500ff4621e8b1fbdc5`
- **Content hash (this issuance only, does NOT reproduce):** `782b65d8f5f3aafce0d5f69d30ec9775…`
- **Signature:** UNSIGNED - content hash only, origin NOT attested

> **Scope:** Software Bill of Materials from declared top-level dependencies in pyproject.toml (PEP 621 and Poetry), requirement files, setup.cfg, setup.py, Pipfile, conda environment files and package.json. Development groups, build requirements and npm devDependencies are declared but are not product dependencies, and are left out. Generation context: pre-build (source manifests). Transitive dependencies are NOT enumerated. Component hashes of executable artifacts are UNKNOWN: this tool does not see a build. Licenses and component producers are UNKNOWN unless present in the declaration, which they almost never are. package-lock.json / poetry.lock / uv.lock are not read (a lockfile is a resolved graph; this pass is the declaration). CISA 2026 Minimum Elements conformance is NOT CLAIMED. Unknown fields are labelled unknown-to-author, not withheld.

**Unknown (not withheld):** component-hash \(no executable artifact\); component-license; component-producer; transitive-dependencies; component-version \(declared as a range, not a pin\)

## Declared components

| Name | Ecosystem | Version | Scope | Manifest | Spec |
|---|---|---|---|---|---|
| `stripe` | pypi | `unknown` | required | `pyproject.toml` | `stripe>=2.0` |

*ENTROVOUCH SBOM: declared top-level only. For the People.*
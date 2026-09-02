# ENTROVOUCH SBOM — DECLARED

- **Target:** `entrovouch/examples/sample_service`
- **Scanned:** 2026-09-01T22:33:55.223326+00:00
- **Manifests read:** 1
- **Declared components:** 1
- **Generation context:** `pre-build` (source manifests, before build)
- **Coverage:** `top-level-declared-only`
- **CISA 2026 minimum elements:** NOT CLAIMED — source-manifest SBOM; component hashes, transitive coverage and licenses are labelled unknown rather than filled
- **Findings digest (reproduces):** `f955eb1e217a7f9df1c88e70ea642b83…`
- **Subject digest (binds the manifests):** `cac9b2a514b4fa6fb587333ac25d3862…`
- **Content hash (this issuance only, does NOT reproduce):** `bc4fe3092711d7b04995de25e4464e04…`
- **Signature:** UNSIGNED - content hash only, origin NOT attested

> **Scope:** Software Bill of Materials from declared top-level dependencies in pyproject.toml, requirements*.txt, setup.cfg and package.json. Generation context: pre-build (source manifests). Transitive dependencies are NOT enumerated. Component hashes of executable artifacts are UNKNOWN — this tool does not see a build. Licenses and component producers are UNKNOWN unless present in the declaration, which they almost never are. npm devDependencies are omitted. package-lock.json / poetry.lock / uv.lock are not read (a lockfile is a resolved graph; this pass is the declaration). CISA 2026 Minimum Elements conformance is NOT CLAIMED. Unknown fields are labelled unknown-to-author, not withheld.

**Unknown (not withheld):** component-hash (no executable artifact); component-license; component-producer; transitive-dependencies; component-version (declared as a range, not a pin)

## Declared components

| Name | Ecosystem | Version | Scope | Manifest | Spec |
|---|---|---|---|---|---|
| `stripe` | pypi | `unknown` | required | `pyproject.toml` | `stripe>=2.0` |

*ENTROVOUCH SBOM — declared top-level only. For the People.*
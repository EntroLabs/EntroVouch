# Schemas used by the tests

These files are the published schemas the tests validate this project's output against. They are included
unchanged, so the tests run offline, and each is pinned by a prefix of its SHA-256 in the test that uses it.
The tools themselves never read them.

| File | What it is | Published at | Terms |
|---|---|---|---|
| `bom-1.6.schema.json` | CycloneDX 1.6 BOM schema | http://cyclonedx.org/schema/bom-1.6.schema.json | Apache License 2.0 (stated in the file) |
| `jsf-0.82.schema.json` | JSON Signature Format 0.82, referenced by the CycloneDX schema | http://cyclonedx.org/schema/jsf-0.82.schema.json | Apache License 2.0 (stated in the file) |
| `spdx.schema.json` | SPDX licence identifiers, referenced by the CycloneDX schema | http://cyclonedx.org/schema/spdx.schema.json | Apache License 2.0 (CycloneDX) |
| `sarif-2.1.0.schema.json` | SARIF 2.1.0 schema | OASIS Open, https://docs.oasis-open.org/sarif/sarif/v2.1.0/ | Copyright OASIS Open; distributed by OASIS |
| `csaf-2.0.schema.json` | CSAF 2.0 schema | OASIS Open, https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json | Copyright OASIS Open; distributed by OASIS |

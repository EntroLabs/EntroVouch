# sample_service — a fixture, not a product

A deliberately small tree with a realistic mix. It exists so a reader can run
the auditors, get findings that are not trivially empty, and compare their
output to the report committed beside it.

Nothing here is shipped software. Do not import it. Do not install it.

| File | Contains | Found by |
|---|---|---|
| `collector.py` | a real network import and an outbound POST | no-egress auditor (`network-import`) |
| `pyproject.toml` | `stripe` declared, never imported | no-egress auditor (`declared-network-dependency`) |
| `urls.py` | `from urllib.parse import urlparse` | **nothing — parse is not a socket** |
| `motor.py` + `drive.py` | local module named `motor` | **nothing as network-import; name in `shadowed_imports`** |
| `pricing.py` | pure computation, no egress | **nothing — the negative case** |
| `tokens.py` | MD5, `random`, in-source HMAC key, JWT RS256, pyca `hashes.MD5()`, PEM armour | CBOM, key provenance |

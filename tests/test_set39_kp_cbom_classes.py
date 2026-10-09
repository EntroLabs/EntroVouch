"""cbom and key_provenance on set 39: the false classes found, each with the true neighbour that must still be reported."""
from __future__ import annotations

from pathlib import Path

from entrovouch.cbom import build_cbom
from entrovouch.key_provenance import scan_key_provenance

BODY = "MIIEowIBAAKCAQEAs1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi/fGHG4CLw98+Yo"


def _get(item, field):
    return item[field] if isinstance(item, dict) else getattr(item, field)


def _write(tmp_path: Path, files: dict) -> None:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _kp(tmp_path, files):
    _write(tmp_path, files)
    return [(_get(f, "file"), _get(f, "line"), _get(f, "kind")) for f in scan_key_provenance(tmp_path).findings]


def _cb(tmp_path, files):
    _write(tmp_path, files)
    return [(_get(c, "file"), _get(c, "line"), _get(c, "primitive")) for c in build_cbom(tmp_path).components]


PEM_CASES = {
    "search.py": 'i = text.find(b"-----BEGIN EC PRIVATE KEY-----")\n',
    "doc.py": '"""Read the file before the "-----BEGIN RSA PRIVATE KEY-----" line."""\n',
    "test_out.py": 'assert lines[0] == b"-----BEGIN RSA PRIVATE KEY-----"\n',
    "real.py": f'KEY = """-----BEGIN RSA PRIVATE KEY-----\n{BODY}\n-----END RSA PRIVATE KEY-----\n"""\n',
    "joined.py": f'B64 = b"{BODY}"\nPEM = b"-----BEGIN RSA PRIVATE KEY-----\\n" + B64 + b"\\n-----END RSA PRIVATE KEY-----"\n',
}


def test_armour_holds_a_key_only_with_a_body(tmp_path):
    for found in (_kp(tmp_path / "kp", PEM_CASES), _cb(tmp_path / "cb", PEM_CASES)):
        files = {f for f, _, _ in found}
        assert {"real.py", "joined.py"} <= files
        assert not files & {"search.py", "doc.py", "test_out.py"}


NAMES = '''import hmac
PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
ext_key_description_oid = "1.3.6.1.4.1.11129.2.1.17"
primary_key = "mdb"
HKDF_INFO_HMAC = b"CTAP2 HMAC key"
key_handle = b"\\3" * 64
expected_seed_mask = "aabbccddeeff00112233"
TEST_KEY_SIZE = """<?xml version="1.0"?><KeySize>256</KeySize>"""
options = server.register_begin(user, resident_key_requirement="required")
def make_plugin(path, key_attribute=""):
    return path
SECRET_KEY = "dev"
api_secret = "test_api_secret"
'''


def test_identifiers_named_with_a_key_word_are_not_keys(tmp_path):
    lines = {line for _, line, _ in _kp(tmp_path, {"cfg.py": NAMES})}
    assert not lines & set(range(2, 11))
    assert {12, 13} <= lines


RFC6979 = '''import hmac
def generate_k(order, x, hash_func, data):
    k = b"\\x00" * 32
    k = hmac.new(k, digestmod=hash_func)
    k.update(x)
    k = k.digest()
    v = hmac.new(k, data, hash_func).digest()
    return v
'''


def test_a_key_reassigned_from_secret_material_is_not_a_literal(tmp_path):
    found = [(line, kind) for _, line, kind in _kp(tmp_path, {"rfc6979.py": RFC6979})]
    assert any(line == 4 for line, _ in found)          # the first HMAC really is keyed by zero bytes
    assert not any(line == 7 for line, _ in found)      # by now K came from the private key


WORKFLOW = """jobs:
  t:
    steps:
      - uses: actions/cache@v4
        with:
          key: sessions-${{ github.sha }}
          path: .cache
      - env:
          API_TOKEN: 9f8e7d6c5b4a39281706f5e4d3c2b1a0
"""


def test_a_pipeline_value_built_at_run_time_is_not_a_literal(tmp_path):
    lines = {line for _, line, _ in _kp(tmp_path, {".github/workflows/ci.yml": WORKFLOW})}
    assert 6 not in lines and 9 in lines


NACL = '''from nacl import exceptions as exc
import nacl.encoding
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl.signing import SigningKey
import nacl.bindings
from nacl import pwhash
'''


def test_pynacl_is_classified_by_the_module_imported(tmp_path):
    found = {}
    for _, line, prim in _cb(tmp_path, {"n.py": NACL}):
        found.setdefault(line, set()).add(prim)
    assert 1 not in found and 2 not in found                      # helpers hold no primitive
    assert any("secret-key" in p for p in found[3])
    assert any("hashing" in p for p in found[4])
    assert "libsodium/NaCl (Curve25519/Ed25519)" in found[5]
    assert any("chosen at the call" in p for p in found[6])
    assert any("password hashing" in p for p in found[7])


MESSAGES = '''raise UnsupportedAlgorithm(f"Unrecognized RSA PKCS1 signature alg {alg}")
"""Load RSA private key."""
X = "RSA PUBLIC KEY"
ALG = "RS256"
'''


def test_a_message_naming_an_algorithm_is_not_a_use_of_it(tmp_path):
    lines = {line for _, line, _ in _cb(tmp_path, {"m.py": MESSAGES})}
    assert 1 not in lines and 2 not in lines
    assert {3, 4} <= lines                       # a PEM type name and a JWS algorithm are still read

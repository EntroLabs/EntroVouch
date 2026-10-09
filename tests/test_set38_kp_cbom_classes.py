"""key_provenance and cbom on code they had never seen (set 38): the false classes found, each with the true
neighbour that must still be reported.
"""
from __future__ import annotations

from pathlib import Path

from entrovouch.cbom import build_cbom
from entrovouch.key_provenance import scan_key_provenance


def _get(item, field):
    return item[field] if isinstance(item, dict) else getattr(item, field)


def _kp(tmp_path: Path, files: dict) -> list:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return [(_get(f, "file"), _get(f, "line"), _get(f, "kind")) for f in scan_key_provenance(tmp_path).findings]


def _cb(tmp_path: Path, files: dict) -> list:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return [(_get(c, "file"), _get(c, "line"), _get(c, "primitive")) for c in build_cbom(tmp_path).components]


WORKFLOW = """jobs:
  release:
    steps:
      - env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TWINE_PASSWORD: ${{ secrets.PYPI_PASSWORD }}
          API_TOKEN: 9f8e7d6c5b4a39281706f5e4d3c2b1a0
"""


def test_a_pipeline_secret_reference_is_not_a_literal_key(tmp_path):
    found = _kp(tmp_path, {".github/workflows/release.yml": WORKFLOW})
    assert (".github/workflows/release.yml", 5, "literal-key") not in found
    assert (".github/workflows/release.yml", 6, "literal-key") not in found
    assert (".github/workflows/release.yml", 7, "literal-key") in found      # a real value written in the file


NAMES = """DEFAULT_TOKEN_MODEL = "app.MqttToken"
FLAG_KEY = "sample-flag"
TEST_FLAG_KEY = "test_flag"
_VECTOR_KEY = "value"
SECRET_KEY = "dev"
API_TOKEN = "0ba349286c780fe53d8b4617d90e2d01"
ctx = EvaluationContext(targeting_key="user-123")
client = Client(api_key="sk-test-123456")
"""


def test_a_key_word_naming_something_else_is_not_key_material(tmp_path):
    found = {line for _, line, _ in _kp(tmp_path, {"app/settings.py": NAMES})}
    assert not found & {1, 2, 3, 4, 7}
    assert {5, 6, 8} <= found


DERIVED = """def bucket(flag_definition, parent_key):
    salt = flag_definition.key + "rollout"
    seed = "abcdefgh" + "ijklmnop"
    key = b"\\x00" + parent_key
    secret = "I=" + str(os.getenv("APP_SECRET"))
    GOOD_KEY = "WPUSH" + ("a" * 27)
    chap_password = b"0x" + bytes(range(15))
    password = "{SHA}" + sha1(as_bytes("password")).hexdigest()
    return salt, seed
"""


def test_a_value_built_from_a_variable_is_not_a_literal(tmp_path):
    found = {line for _, line, _ in _kp(tmp_path, {"flags.py": DERIVED})}
    assert not found & {2, 4, 5}                 # a variable or an environment read decides the value
    assert {3, 6, 7, 8} <= found                 # literals, or functions applied only to literals


HASHER = '''import hashlib
class LegacyPBKDF2Hasher:
    def verify(self, password, salt):
        msg = "Use Argon2/Bcrypt for new hashes."
        return hashlib.pbkdf2_hmac("sha256", password, salt, 1)
def test_pbkdf2_verify_rejects_mismatched_checksum():
    assert check("not-a-scrypt-hash") is False
    assert check("$scrypt$ln=4,r=1,p=1$c2FsdA$Y2hlY2s")
SUITES = "ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA"
'''


def test_a_phrase_or_a_test_name_is_not_a_use_of_an_algorithm(tmp_path):
    found = _cb(tmp_path, {"tests/test_hasher.py": HASHER})
    lines = {line for _, line, _ in found}
    assert not lines & {4, 6, 7}
    assert {2, 5, 9} <= lines                              # the hasher class, the KDF call, a cipher-suite list


VERIFY = """import requests
def encoding(response):
    return get_encoding_from_response(response, verify=False)
def fetch(url):
    return requests.get(url, verify=False)
with created_client(port=9440, secure=True, verify=False) as client:
    pass
"""


NAMES_THAT_ARE_ALGORITHMS = '''SUITE = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
CFG = "region=us-east-1,audience=https://a,signing_algorithm=HS256"
KEY = "ssh -i /path/to/id_ed25519"
raise Exception("Ed25519 key not held in ssh-agent")
SKIP = "no Argon2 library"
'''


def test_a_one_word_identifier_is_never_read_as_a_phrase(tmp_path):
    lines = {line for _, line, _ in _cb(tmp_path, {"suites.py": NAMES_THAT_ARE_ALGORITHMS})}
    assert {1, 2, 3} <= lines                    # an IANA suite name, a config string, a key path
    assert not lines & {4, 5}                    # an error message and a skip reason


MORE_VERIFY = """import jwt
payload = jwt.decode(token, verify=False)
conn.set_ssl(get_ssl_host(), verify=False)
async with http_session_cls(verify=False) as session:
    pass
session = make(verify=False, insecure=True)
packet = MockPacket(AccountingRequest, verify=False)
"""


def test_verify_false_names_what_it_switches_off(tmp_path):
    found = {(line, prim) for _, line, prim in _cb(tmp_path, {"v.py": MORE_VERIFY})}
    assert (2, "JWT signature verification disabled (verify=False)") in found
    for line in (3, 4, 6):
        assert (line, "TLS certificate verification disabled (verify=False)") in found, line
    assert (7, "verify=False on a call not shown to be TLS") in found


def test_verify_false_is_tls_only_where_the_call_is_shown_to_be(tmp_path):
    found = {(line, prim) for _, line, prim in _cb(tmp_path, {"m.py": VERIFY})}
    assert (3, "verify=False on a call not shown to be TLS") in found
    assert (5, "TLS certificate verification disabled (verify=False)") in found
    assert (6, "TLS certificate verification disabled (verify=False)") in found

"""Tests for the key-provenance detector.

The two load-bearing cases are `test_catches_the_historical_defect` (it must
catch the exact code that produced it) and `test_does_not_flag_the_fix` (a
detector that fires on the correct pattern trains people to ignore it).
"""
import pytest

from entrovouch.key_provenance import scan_key_provenance, render_markdown


def _write(tmp_path, name, src):
    (tmp_path / name).write_text(src, encoding="utf-8")
    return tmp_path


# ------------------------------------------------------- the historical case
HISTORICAL = '''
import hashlib, hmac
_DEFAULT_COVENANT = "Optimize systems for people, not margin extraction. One Covenant. Always."

def _sign(body, covenant_text):
    key = hashlib.sha3_256(covenant_text.encode("utf-8")).digest()
    return hmac.new(key, body, hashlib.sha3_256).hexdigest()

def _sign_default(body):
    key = hashlib.sha3_256(_DEFAULT_COVENANT.encode("utf-8")).digest()
    return hmac.new(key, body, hashlib.sha3_256).hexdigest()
'''


def test_catches_the_historical_defect(tmp_path):
    """The exact construction this package shipped until 2026-08-14."""
    rep = scan_key_provenance(_write(tmp_path, "old_signer.py", HISTORICAL))
    assert rep.verdict == "REVIEW"
    kinds = {f["kind"] for f in rep.findings}
    assert "derived-from-constant" in kinds, rep.findings


def test_catches_a_bare_literal_key(tmp_path):
    """The classic construction: a signing secret as a source literal.

    Fixture deliberately neutral. An earlier version used a real identifier
    from a private sibling project -- in a PUBLIC repository, which turned a
    test fixture into reconnaissance for a system nobody outside can see.
    The detector does not care what the string says.
    """
    src = '_SIGNING_SECRET = b"example-service-signing-key-v1"\n'
    rep = scan_key_provenance(_write(tmp_path, "m.py", src))
    assert [f["kind"] for f in rep.findings] == ["literal-key"]


def test_catches_hmac_keyed_directly_by_a_literal(tmp_path):
    src = 'import hmac, hashlib\nx = hmac.new(b"hunter2hunter2hunter2", b"m", hashlib.sha256)\n'
    rep = scan_key_provenance(_write(tmp_path, "m.py", src))
    assert any(f["kind"] == "literal-key" for f in rep.findings)


# -------------------------------------------------------- must NOT fire
def test_does_not_flag_the_fix(tmp_path):
    """The corrected form. A detector that flags the remedy is worse than
    no detector — it teaches people to ignore it."""
    src = '''
import os, hmac, hashlib
_KEY_ENV = "EXAMPLE_PATCH_SIGNING_KEY"

def _signing_key():
    raw = os.environ.get(_KEY_ENV)
    if not raw:
        raise RuntimeError("no key")
    return raw.encode("utf-8")

def sign(m):
    return hmac.new(_signing_key(), m, hashlib.sha256).hexdigest()
'''
    rep = scan_key_provenance(_write(tmp_path, "m.py", src))
    assert rep.findings == [], rep.findings
    assert rep.verdict == "NO-PUBLIC-KEY-MATERIAL"


def test_does_not_flag_a_locally_generated_key(tmp_path):
    """ENTROAUDIT's correct pattern: os.urandom into a gitignored keyfile."""
    src = '''
import os, hmac, hashlib
from pathlib import Path
_KEYFILE = Path(".claim_hmac_key")

def _local_key():
    if not _KEYFILE.exists():
        _KEYFILE.write_bytes(os.urandom(32))
    return _KEYFILE.read_bytes()

def sign(m):
    return hmac.new(_local_key(), m, hashlib.sha256).hexdigest()
'''
    rep = scan_key_provenance(_write(tmp_path, "m.py", src))
    assert rep.findings == []


@pytest.mark.parametrize("name", [
    "KEY_ID", "SIGNING_ALGORITHM", "SECRET_FILE", "TOKEN_HEADER",
    "KEY_ORDER", "PASSWORD_FIELD", "SALT_COLUMN",
])
def test_non_key_material_names_are_not_flagged(tmp_path, name):
    rep = scan_key_provenance(_write(tmp_path, "m.py", f'{name} = "value"\n'))
    assert rep.findings == [], f"{name} should not read as key material"


def test_unrelated_literals_are_not_flagged(tmp_path):
    src = 'VERSION = "1.2.3"\nGREETING = "hello"\nPATH_PREFIX = "/api"\n'
    assert scan_key_provenance(_write(tmp_path, "m.py", src)).findings == []


# ------------------------------------------------------------- reporting
def test_clean_tree_reports_clean(tmp_path):
    rep = scan_key_provenance(_write(tmp_path, "m.py", "x = 1\n"))
    assert rep.verdict == "NO-PUBLIC-KEY-MATERIAL"
    assert "No key material" in render_markdown(rep)


def test_scope_statement_states_its_own_blind_spots(tmp_path):
    rep = scan_key_provenance(_write(tmp_path, "m.py", "x = 1\n"))
    md = render_markdown(rep)
    assert "environment variable" in rep.scope_statement
    assert "neither complete nor authoritative" in rep.scope_statement
    assert "Scope:" in md


def test_review_is_not_an_accusation(tmp_path):
    rep = scan_key_provenance(_write(tmp_path, "m.py", HISTORICAL))
    assert all(f["verdict"] == "REVIEW" for f in rep.findings)
    assert "REVIEW means review" in render_markdown(rep)


def test_unparseable_file_does_not_crash(tmp_path):
    rep = scan_key_provenance(_write(tmp_path, "bad.py", "def (((\n"))
    assert rep.files_scanned == 1 and rep.findings == []


# ------------------------------- ordinary-sense suppression (measured FPs)
@pytest.mark.parametrize("src", [
    'key = "low"\n',                                    # dict lookup key
    'ROBOTS_TOKEN_ONLY = "robots_token_only"\n',        # enum member
    'TOKEN_MANIPULATION = "token_manipulation"\n',      # enum member
    'keys = "abc"\n',
])
def test_ordinary_programming_nouns_suppressed(tmp_path, src):
    """These four shapes were the bulk of a measured 31-finding estate run.
    A detector that fires on them gets ignored."""
    assert scan_key_provenance(_write(tmp_path, "m.py", src)).findings == []


@pytest.mark.parametrize("src,why", [
    ('_SIGNING_SECRET = b"example-service-signing-key-v1"\n', "qualified name"),
    ('PERSON_KEY = b"person-key-out-of-proposer-reach"\n', "qualified name"),
    ('API_SECRET = "s3cr3t-value-here"\n', "value is not the name"),
])
def test_suppression_does_not_swallow_real_key_material(tmp_path, src, why):
    assert scan_key_provenance(_write(tmp_path, "m.py", src)).findings != [], why


# ------------- second-run FP classes (measured on the estate, 2026-08-14)
@pytest.mark.parametrize("src", [
    "key_expr = ''\n",                      # sort-key expression in a compiler
    'key_expression = "x.name"\n',
    'retrieve_token = "<RETRIEVE>"\n',      # tokenizer symbol, not a credential
    'mask_token = "<MASK>"\n',
])
def test_second_run_false_positive_classes_suppressed(tmp_path, src):
    assert scan_key_provenance(_write(tmp_path, "m.py", src)).findings == []


@pytest.mark.parametrize("src", [
    'API_TOKEN = "ghp_realLookingCredentialValue123456"\n',
    '_SIGNING_SECRET = b"example-service-signing-key-v1"\n',
])
def test_credential_tokens_still_caught(tmp_path, src):
    """The suppression keys off BRACKETED values, so real tokens survive it."""
    assert scan_key_provenance(_write(tmp_path, "m.py", src)).findings != []

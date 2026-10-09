#!/usr/bin/env python3
"""
ENTROVOUCH: key provenance detector.

Answers one question a CBOM does not: **where does the key come from?**

A cryptographic inventory that reports "HMAC-SHA3-256: SAFE" is telling the
truth about the primitive and nothing about the security of the deployment. The
primitive is quantum-safe; the deployment is worthless if the key is a string
literal on line 30. Every existing check in this package would have passed the
defect that produced it.

THE SHAPE IT LOOKS FOR
----------------------
A MAC or signature keyed by something the source itself contains: a literal, a
constant, a hash of either, a key file committed beside the code. Such a key is
public to anyone holding the source, so the artifact it protects proves integrity
and never origin. A self-attestation can legitimately work that way; a document
handed to a counterparty cannot.

WHY THE VERDICT IS `REVIEW` AND NOT `VULNERABLE`
------------------------------------------------
A publicly-derived key is legitimate for a self-attestation and indefensible for
a compliance artifact, and no static analysis can tell which one it is looking
at: that depends on who receives the document, which is not in the source.
Reporting these as VULNERABLE would be an overclaim in the opposite direction.
`REVIEW` means review. It is not a pass, and it is not an accusation.
"""
from __future__ import annotations

import ast
import hashlib
import sys
import warnings
import json
import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path

from ._cli import missing_folder, run, write_text
from .manifests import tree_files
from . import _reads
from .no_egress_auditor import (
    _DISPLAY_CELL_MAGICS, _PROGRAM_CELL_MAGICS,
    _read_python_source, _subject_name, canonical_body, tree_listing_digest, markdown_cell, markdown_code, python_units,
    NotPythonNotebook,
)
from ._version import __version__
from ._pem import armour_with_key

# Files that are key material by name, and where PEM armour is looked for.
_KEY_FILE_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"}
_KEY_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".der"}
_PEM_TEXT_SUFFIXES = {".json", ".yaml", ".yml", ".txt", ".cfg", ".ini", ".toml", ".env", ".conf", ".crt", ".pem", ".key", ".ppk", ".asc", ""}
_PEM_PRIVATE_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")


class _Base64Armour:
    """Private-key armour found base64-encoded (a Kubernetes Secret's `data:`), shaped like the match the PEM search
    returns: `group(0)` names it, `start()` is where the encoded text begins."""

    def __init__(self, text: str, at: int) -> None:
        self._text, self._at = text, at

    def group(self, _k: int = 0) -> str:
        return self._text

    def start(self) -> int:
        return self._at


# "-----BEGIN" in base64 at each of the three byte offsets it can fall at in the encoded data (whatever comes before
# it in that data changes the characters around it, never these), and a run of base64 characters
_B64_BEGIN_MARKERS = ("LS0tLS1CRUdJTi", "tLS0tQkVHSU4", "LS0tLUJFR0lO")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# base64 wrapped over lines (`base64` writes 76 characters a line, `openssl base64` 64): consecutive lines that hold
# nothing else, read as one run
_B64_WRAPPED_RE = re.compile(r"(?:^[ \t]*[A-Za-z0-9+/]{16,}={0,2}[ \t]*\r?\n){2,}(?:[ \t]*[A-Za-z0-9+/]+={0,2}[ \t]*$)?",
                             re.MULTILINE)


def _stable_base64(data: bytes) -> tuple[str, ...]:
    """The base64 characters that encode `data` whatever bytes stand before and after it, at each of the three byte
    offsets it can fall at: the groups wholly inside it."""
    import base64
    out = []
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + data + b"\0\0").decode()
        first, last = -(-k // 3), (k + len(data)) // 3
        out.append(enc[first * 4:last * 4])
    return tuple(out)


# the same, for armour encoded twice (a Kubernetes Secret holding a base64 file): the first markers encoded again
_B64_TWICE_MARKERS = tuple(m for inner in _B64_BEGIN_MARKERS for m in _stable_base64(inner.encode()))


def has_base64_armour_marker(text: str) -> bool:
    """Could `text` hold private-key armour base64-encoded, wherever in the encoded data the armour starts (a PEM
    file encoded whole, or one inside an encoded JSON service-account file), on one line or wrapped over several,
    once or twice?"""
    markers = _B64_BEGIN_MARKERS + _B64_TWICE_MARKERS
    if any(m in text for m in markers):
        return True
    if "\n" not in text:
        return False
    joined = re.sub(r"[ \t]*\r?\n[ \t]*", "", text)
    return any(m in joined for m in markers)


# what may stand between the pieces of one base64 value written over several lines: a line break and indentation (a
# YAML scalar continued), and the quotes, `+` and `\` of strings joined across lines (`"LS0t..."\n    "MIIE..."`)
_B64_GLUE_RE = re.compile(r"""["']?[ \t]*[+,]?[ \t]*\\?\r?\n[ \t]*["']?""")


def _base64_runs(text: str):
    """(offset, run) for each run of base64 in `text`: runs wrapped over lines joined first (ending at the first line
    that ends in `=`, and also without a short last line, which may be a word such as a here-document's `EOF`), then
    runs on one line, then runs found with the glue between lines removed."""
    seen = set()

    def once(at, run):
        if run not in seen:
            seen.add(run)
            yield at, run
    for b in _B64_WRAPPED_RE.finditer(text):
        lines = [ln.strip() for ln in b.group(0).splitlines() if ln.strip()]
        end = next((k + 1 for k, ln in enumerate(lines) if ln.endswith("=")), len(lines))
        yield from once(b.start(), "".join(lines[:end]))
        if end == len(lines) and len(lines) > 2 and len(lines[-1]) < len(lines[0]):
            yield from once(b.start(), "".join(lines[:-1]))
    for b in _B64_RUN_RE.finditer(text):
        yield from once(b.start(), b.group(0))
    if "\n" in text and has_base64_armour_marker(text):
        deglued = _B64_GLUE_RE.sub("", text)
        for b in _B64_RUN_RE.finditer(deglued):
            if has_base64_armour_marker(b.group(0)):
                head = text.find(b.group(0)[:16])
                yield from once(head if head >= 0 else 0, b.group(0))


def pem_with_body(text: str, _depth: int = 0):
    """The first private-key armour in `text` that holds a key (see `_pem`), written out or base64-encoded (the
    encoded data may hold other text before it, as a service-account JSON file does; it may be wrapped over lines,
    or encoded twice)."""
    m = armour_with_key(text, _PEM_PRIVATE_RE)
    if m or not has_base64_armour_marker(text):
        return m
    import base64
    for at, whole in _base64_runs(text):
        if not has_base64_armour_marker(whole):
            continue
        run = whole.rstrip("=")
        if len(run) % 4 == 1:
            run = run[:-1]                  # one character past a whole group cannot be decoded
        run += "=" * (-len(run) % 4)
        try:
            decoded = base64.b64decode(run, validate=True).decode("utf-8", "replace")
        except ValueError:
            continue
        # armour written out, or inside a JSON string with its line breaks escaped (`"private_key": "-----BEGIN...\n"`)
        inner = armour_with_key(decoded, _PEM_PRIVATE_RE) or armour_with_key(decoded.replace("\\n", "\n"),
                                                                             _PEM_PRIVATE_RE)
        if not inner and _depth == 0 and has_base64_armour_marker(decoded):
            inner = pem_with_body(decoded, 1)       # encoded twice
        if inner:
            label = inner.group(0) if not isinstance(inner, _Base64Armour) else inner.group(0).removesuffix(
                " (base64-encoded)")
            return _Base64Armour(f"{label} (base64-encoded)", at)
    return None
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_CONFIG_SUFFIXES = {".yaml", ".yml", ".toml", ".ini", ".cfg", ".json", ".properties", ".jwk", ".jwks"}
_CONFIG_LINE_RE = re.compile(r"""^\s*(?:-\s+(?=[A-Za-z_][\w.-]*=))?["']?([A-Za-z_][\w.-]*)["']?\s*[:=]\s*["']?([^"'\n]+?)["']?,?\s*$""")
# A value that only names where the secret comes from is not a literal: `${{ secrets.PYPI_TOKEN }}` (a pipeline's
# secret store), `{{ vault_password }}` (a template variable), `$TOKEN`, `${TOKEN}`.
_PLACEHOLDER_RE = re.compile(r"^(?:\$\{?[\w]+\}?|\$?\{\{[^{}]*\}\}$|<[^>]*>|your[-_ ]|xxx+|change[-_ ]?me|replace[-_ ]?me"
                             r"|todo$|none$|null$|example)", re.IGNORECASE)
_KEY_MAX_BYTES = 16 << 20        # the reader's own limit for a file it holds whole
# A folder of translations holds labels: `PASSWORD: Contraseña` names a form field, not a password
_TRANSLATION_FOLDERS = {"locale", "locales", "_locales", "i18n", "l10n", "lang", "langs", "languages", "translations"}
# the file a framework names for its interface text: Home Assistant and Android `strings`, a browser extension's `messages`
_TRANSLATION_FILES = {"strings.json", "strings.xml", "messages.json"}


def _label_table(rel: str) -> bool:
    parts = rel.split("/")
    return any(part.lower() in _TRANSLATION_FOLDERS for part in parts[:-1]) or parts[-1].lower() in _TRANSLATION_FILES


def _bare_key_word(var: str, value: str) -> bool:
    """A setting named only `key` or `token` (a CloudFormation `Key: Application` tag, a grammar's `"token":
    "Refreshable"`) holding a value with no digit in it: key material has a digit (hex, base64, a number), a name, a
    header or a type word does not."""
    if str(var).strip().lower() in ("key", "token") and not any(c.isdigit() for c in value):
        return True
    # `secret_key: "password"`, a vault input naming the field to read: the value names another field, not itself
    # (a lower-case field name beside a lower-case noun; `RUSTFS_SECRET_KEY=password` in a compose file is a weak password)
    if value in _CREDENTIAL_NOUNS and value not in str(var).lower() and str(var) == str(var).lower():
        return True
    return _is_mapping_key(str(var), value)


_CREDENTIAL_NOUNS = {"username", "user", "password", "passwd", "token", "secret", "apikey", "api_key", "access_token",
                     "client_id", "client_secret"}


def _address_or_bracket_token(value) -> bool:
    """A value that is not a credential by its shape: an address without credentials in it (`https://idp.example.com`),
    a lexical token in brackets (`[START_ENT]`), a command substitution (`$(curl ...)`), a tag (`@@dbt_version`), a
    path to a file (`config/ssl/server.key`), a column type (`varbinary(16)`), a mask (`dapiXXXXXXXXXXXX`), or text of
    several lines (a fixture). A key written on several lines is private-key armour, which is judged apart."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if re.fullmatch(r"\[[A-Z0-9_ ]+\]", v) or v.startswith(("$(", "`", "@@")):
        return True
    lines = [x.strip() for x in v.splitlines() if x.strip()]
    key_body = len(lines) >= 2 and re.fullmatch(r"\S{2,}", lines[-1]) is not None and all(
        re.fullmatch(r"[A-Za-z0-9+/=]{16,}", x) for x in lines[:-1])
    if len(v.splitlines()) >= 2 and not v.startswith("-----BEGIN") and not key_body:
        return True                    # (lines of base64 or hex are a key body written bare: judged, not skipped)
    if re.fullmatch(r"[\w.~-]*(?:/[\w.~-]+)+\.[A-Za-z]{2,5}", v) or re.fullmatch(r"\w+\(\d+(?:,\s*\d+)?\)", v):
        return True
    if re.search(r"[Xx*]{8,}", v):
        return True
    # an expression in a path language (`a[0].b`, `a."k.c"`): brackets or quotes inside a few word characters and dots
    # (the brackets hold an index, not a long run of characters: `[abcdef12345678]` is a token in brackets)
    if re.fullmatch(r"""[\w.\[\]"'*-]{1,60}""", v) and (
            re.search(r"""["']""", v) or v.startswith(".") or v.endswith(".")
            or (re.search(r"[\[\]]", v) and all(len(g) <= 4 for g in re.findall(r"\[([^\]]*)\]", v))
                and (len(v) <= 5 or not re.search(r"[\[\]]", re.sub(r"\[[^\]]*\]", "", v))))):
        return True
    m = re.match(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)", v)
    return bool(m) and "@" not in m.group(1)


def _env_name_to_field(key: str, value) -> bool:
    """`{"PVE_PASSWORD": "password"}`: an environment-variable name mapped to the name of the field it fills. The value is
    the tail of the key, written in lower case; a key with no prefix (`PASSWORD`) or a value that is more than the tail
    is not this."""
    return (isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", key) is not None
            and re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*", value) is not None and key.lower().endswith("_" + value))


def _restates_name(name: str, value) -> bool:
    """A constant whose value is its own name written another way (`NO_TOKEN = 'NO-TOKEN\\r\\n'`, `KEY_SCHEMA =
    'KeySchema'`, `TABLE_KEY = 'Table'`): a sentinel, an enum member or an API field name, not a secret."""
    if not isinstance(value, str):
        return False
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    forms = {re.sub(r"[\s-]+", "_", x).lower() for x in (value.strip(), spaced)}    # `DataStream-Salt`, `KeySchema`
    want = name.strip("_").lower()
    if not want:
        return False
    # `TABLE_KEY = 'Table'` names a field. Only a `_key` suffix is dropped, and only from a name that says nothing about
    # a secret: `SECRET_KEY = 'secret'` and `ADMIN_PASSWORD = 'admin'` are weak credentials, not labels.
    stem = re.sub(r"_key$", "", want)
    return want in forms or (stem != want and stem in forms and not re.search(
        r"secret|passw|token|private|signing|hmac|salt|seed|auth|api|master|session|access|license", stem))
# Constructors whose first argument is key material.
_KEY_CTORS = {"Fernet", "MultiFernet", "AES", "AESGCM", "AESCCM", "AESOCB3", "AESSIV", "ChaCha20", "ChaCha20Poly1305",
              "Camellia", "TripleDES", "SigningKey", "PrivateKey", "Ed25519PrivateKey"}

# String literals with the published shape of a provider credential. The shape is the
# evidence: these prefixes are assigned by the provider and do not occur by accident.
_CREDENTIAL_SHAPES = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "an AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "a GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "a GitHub fine-grained token"),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "a live payment-provider secret key"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}"), "a Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "a Google API key"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"), "a bearer token"),
]
_ENV_READERS = {("os", "getenv"), ("environ", "get"), ("os", "environ"), ("environ", "setdefault"),
                ("", "getenv")}
# calls that set an environment variable: `os.putenv("SECRET_KEY", "...")`
_ENV_WRITERS = {("os", "putenv"), ("", "putenv")}


def _as_assigned(node: ast.AnnAssign) -> ast.Assign:
    """`api_key: str = "..."` is the same binding as `api_key = "..."`, at module, class and function level and in a
    dataclass. A dataclass field's `field(default="...")` binds that default."""
    value = node.value
    if isinstance(value, ast.Call) and (_dotted(value.func) or "").rsplit(".", 1)[-1] in ("field", "Field"):
        default = next((kw.value for kw in value.keywords if kw.arg == "default"), None)
        if default is None and value.args and (_dotted(value.func) or "").endswith("Field"):
            default = value.args[0]          # pydantic's Field(default, ...)
        if default is not None:
            value = default
    return ast.copy_location(ast.Assign(targets=[node.target], value=value, type_comment=None), node)


def _annotated_as_assigned(tree: ast.AST) -> ast.AST:
    """Every annotated binding with a value, as a plain one. Iterative: a deep expression (500 joined literals in
    generated code) must not exhaust the recursion limit, as a recursive visitor does."""
    for node in list(ast.walk(tree)):
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for k, item in enumerate(value):
                    if isinstance(item, ast.AnnAssign) and item.value is not None:
                        value[k] = _as_assigned(item)
    return tree

__all__ = ["KeyFinding", "scan_key_provenance", "render_markdown"]

# Names that indicate a value is key material rather than an identifier.
_KEY_NAME = re.compile(
    r"(?:^|_)(secret|key|signing|hmac|token|password|passphrase|salt|seed)(?:$|_)",
    re.IGNORECASE,
)
# ...minus names that conventionally hold a NON-secret (an id, a filename, the
# name of an env var). Without this the detector fires on `_KEY_ENV = "APP_KEY"`,
# which is the correct pattern, and a detector that flags the fix is worse than
# no detector.
_NOT_KEY_MATERIAL = re.compile(
    r"(?:_env$|_envvar$|_var$|_id$|_name$|_file$|_filename$|_path$|_url$|_header$"
    # a value a key produced, or where to fetch one: `hmac_digest`, `token_endpoint`
    r"|_digest$|_checksum$|_signature$|_endpoint$"
    r"|_field$|_column$|_prefix$|_suffix$|_order$|_algo$|_algorithm$"
    # a sort or mapping key expression, a repr, a parser slice, an algorithm name
    r"|_expr$|_exprs$|_expression$|_fn$|_func$|_getter$|_placeholder$"
    r"|_repr$|_str$|_derivation$|_kind$|_type$|_mode$"
    # a key word naming something else: `token_model` is a model class, `KEY_CLASS` a class
    r"|_model$|_models$|_class$|_cls$|_module$"
    # an attribute, a requirement or a validation named by a key word; a key handle (an identifier); a mask; an
    # info label (`HKDF_INFO_HMAC`, `_INFO_EXTRA_KEY`)
    r"|_attribute$|_attr$|_requirement$|_validation$|_handle$|_mask$|(?:^|_)info(?:_|$))",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# THE PREFIX AND THE VALUE. An upper-case `*_KEY` constant whose value is an
# identifier, a dunder or an env-var name is a MAPPING key, not key material:
#
#     CONFIGFILE_KEY = 'pydantic-mypy'        ROOT_KEY = '__root__'
#     ENV_VAR_KEY    = "TOX_PARALLEL_ENV"     meta_schema_key = "meta schema id"
#
# Two structural tests tell those apart from a secret, instead of a suffix list
# that grows one real-world name at a time. Neither may suppress
# `SECRET_KEY = "dev"`, a true positive whose value is also a plain identifier:
# the value test is limited to shapes a secret never takes, and the name test
# looks at what is being KEYED rather than at the word "key".
# ---------------------------------------------------------------------------

# Values a secret never has: a dunder, or an ENV_VAR_SHAPED_NAME.
_NON_SECRET_VALUE = re.compile(r"^(?:__\w+__|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+"
                               # a URN, an OID, an option word, an XML document: identifiers, never secrets
                               r"|(?i:urn:[\w:.-]+|required|preferred|discouraged|optional)|\d+(?:\.\d+){3,}"
                               r"|\s*<\?xml\b(?s:.*))$")

# `<thing>_KEY` where <thing> is what is being keyed, not a secrecy qualifier.
# `SECRET_KEY`, `API_KEY`, `SIGNING_KEY`, `TEST_KEY` are untouched by design.
# words that say a name is cryptographic, or that its value is a stand-in for a key (`test_key = "foo"`): a lowercase
# word under such a name can still be a key
_CRYPTO_QUALIFIER = re.compile(
    r"(?:^|_)(aes|rsa|hmac|api|auth|access|private|master|session|license|jwt|encrypt\w*|decrypt\w*|crypt\w*|cipher|"
    r"sign\w*|ssh|gpg|pgp|ecdsa|ed25519|admin|client|service|shared|symmetric|wallet|fernet|gcm|des|ecc|dsa|test|dev|prod|demo|dummy|fake|mock|default|example|my|static|fixed|hardcoded)(?:$|_)",
    re.IGNORECASE)
_STORE_ENTRY_KEY = re.compile(r"(?:^|_)(?:redis|memcached|memcache|lock|queue|topic)_key$", re.IGNORECASE)
_KEYED_THING = re.compile(
    r"(?:^|_)(config|configfile|metadata|meta|root|env|envvar|var|schema|markup|"
    r"mode|cache|index|sort|group|lookup|dict|map|section|option|setting|entry|"
    r"item|record|node|param|arg|validator|partition|bucket|shard|"
    # a feature flag, a vector's entry, the subject a flag is evaluated for: identifiers, not secrets
    r"flag|feature|vector|targeting|target|metric|label|event|primary|foreign|resident)"
    r"[a-z0-9_]*_key$",
    re.IGNORECASE,
)


def _parse_quietly(src: str, filename: str = "<unknown>") -> ast.AST:
    """`ast.parse` with the audited file's own compile-time warnings set aside. An invalid escape in
    someone else's string (`"\\d"`) is their warning, not this tool's output; and under `-W error` it
    would turn a file that parses into one reported as unparseable."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(src, filename=filename)



def _is_mapping_key(name: str, value) -> bool:
    """True when a `*_key` name holds a MAPPING key rather than key material.

    Two independent tests, either sufficient:
      * the VALUE is a dunder or an env-var-shaped constant name
      * the NAME says what is being keyed (`CONFIGFILE_KEY`, `meta_schema_key`)

    Deliberately NOT another entry in a suffix list. The suffix list grows one
    real-world name at a time and can never be finished; these two tests are
    properties of the shape.
    """
    if isinstance(value, str) and _NON_SECRET_VALUE.match(value):
        return True
    if _KEYED_THING.search(name):
        return True
    # the name of an entry in a store or a queue (`redis_key`, `lock_key`): where a thing is kept, not what unlocks it.
    # Only these endings: `s3_secret_access_key` and `blob_key` end in a different word and stay findings.
    if _STORE_ENTRY_KEY.search(name):
        return True
    # a name whose only key word is `key`, with nothing in it that says what kind of key, holding a lowercase word:
    # `provider_key = "mysql"`, `child_list_key = "content"` name a field or a table; key material is named for what it is
    # (`aes_key`, `api_key`) and is not usually a lowercase word. A value with digits in it and no separator
    # (`bedcfb5a011ebc84`, `abc123webhookkey`) is not a word: hex and tokens look like that.
    word = isinstance(value, str) and (
        (re.fullmatch(r"[a-z][a-z0-9_.-]{0,39}", value) and (not re.search(r"\d", value) or re.search(r"[_.-]", value)))
        or re.fullmatch(r"[a-z]+(?:[A-Z][a-z]+)+|[A-Z][a-z]+(?:[A-Z][a-z]+)*", value))   # (`shuffleId`, `FooForum`, `Table`)
    if word and not _CRYPTO_QUALIFIER.search(name):
        words = {w.lower() for w in re.findall(r"(?i)secret|key|signing|hmac|token|password|passphrase|salt|seed", name)}
        return words <= {"key"}
    return False

# WHERE KEY MATERIAL ACTUALLY SITS, PER FUNCTION.
#
# Each entry maps (module, function) -> (positional index or None, keyword name).
# `None` means the function takes key material ONLY as a keyword argument, so no
# positional argument may ever be read as a key.
#
# These are the real CPython signatures, confirmed by `inspect.signature`:
#     hmac.new(key, msg=None, digestmod='')          -> key is positional 0
#     hashlib.pbkdf2_hmac(hash_name, password, ...)  -> password is positional 1
#     hashlib.scrypt(password, *, salt, n, r, p)     -> password is positional 0
#     hashlib.blake2b(data=b'', *, key=b'', ...)     -> KEY IS KEYWORD-ONLY
#
# blake2b/blake2s take their key ONLY as a keyword, so a plain
#     hashlib.blake2b(b"just hashing data")
# must never have its DATA read as a key. Hashing a byte string is among the most
# common operations in Python, and a false positive there costs more than the finding
# is worth: this tool's claim is that REVIEW means review, and published work puts tool
# abandonment at false-positive rates above 20-30%. Positional-vs-keyword is the
# difference between naming a secret and naming a string somebody hashed.
_KEY_ARG = {
    ("hmac", "new"):          (0, "key"),
    ("hmac", "HMAC"):         (0, "key"),
    ("hmac", "digest"):       (0, "key"),
    ("hashlib", "pbkdf2_hmac"): (1, "password"),
    ("hashlib", "scrypt"):    (0, "password"),
    ("hashlib", "blake2b"):   (None, "key"),
    ("hashlib", "blake2s"):   (None, "key"),
    ("jwt", "encode"):        (1, "key"),
    ("jwt", "decode"):        (1, "key"),
    # pycryptodome's ciphers: `AES.new(key, mode)`; ChaCha20 and Salsa20 take their key only by keyword
    ("AES", "new"):           (0, "key"),
    ("DES3", "new"):          (0, "key"),
    ("DES", "new"):           (0, "key"),
    ("Blowfish", "new"):      (0, "key"),
    ("ARC4", "new"):          (0, "key"),
    ("CAST", "new"):          (0, "key"),
    ("ChaCha20", "new"):      (None, "key"),
    ("ChaCha20_Poly1305", "new"): (None, "key"),
    ("Salsa20", "new"):       (None, "key"),
    ("itsdangerous", "Signer"): (0, "secret_key"),
    ("itsdangerous", "URLSafeSerializer"): (0, "secret_key"),
    ("itsdangerous", "TimestampSigner"): (0, "secret_key"),
}
_CIPHER_MODULES = {"AES", "DES3", "DES", "Blowfish", "ARC4", "CAST", "ChaCha20", "ChaCha20_Poly1305", "Salsa20"}
_HASHES = {"sha3_256", "sha3_512", "sha256", "sha512", "shake_256", "md5", "sha1"}


def _is_ordinary_programming_noun(name: str, value) -> bool:
    """Suppress the two idioms that make 'key' and 'token' ambiguous words.

    Most occurrences of `key` and `token` in ordinary code are `key = "low"` (a
    dict lookup key) or `TOKEN_MANIPULATION = "token_manipulation"` (an enum
    member). A detector that cries wolf on the ordinary sense of a word trains
    its reader to skip it, which costs more than the findings are worth.

    Suppressed:
      1. ENUM IDIOM: the value is just the name restated
         (`ROBOTS_TOKEN_ONLY = "robots_token_only"`). Nobody writes a secret
         that way.
      2. BARE GENERIC LOCALS: a lowercase `key` / `keys` / `token` with no
         qualifier. Real key material is nearly always named for what it is
         (`_SIGNING_SECRET`, `PERSON_KEY`, `_KEYFILE`); an unqualified
         lowercase `key` is overwhelmingly a mapping key.

    Both are recall costs, taken deliberately and stated: a secret literally
    assigned to a bare `key` local is missed.
    """
    if not isinstance(value, str):
        return False
    if _restates_name(name, value):
        return True
    if name.lower() in {"key", "keys", "token", "tokens"} and not name.startswith("_"):
        return True
    # LEXICAL TOKENS, not credentials. `retrieve_token = "<RETRIEVE>"` is a
    # tokenizer symbol; in compiler and ML code this is the DOMINANT sense of the
    # word. Bracketed values are the reliable signal: nobody writes a secret as
    # "<RETRIEVE>".
    if "token" in name.lower() and value.startswith("<") and value.endswith(">"):
        return True
    return False


@dataclass
class KeyFinding:
    file: str
    line: int
    kind: str          # literal-key | derived-from-literal | derived-from-constant | derived-from-parameter | key-file-in-tree
    detail: str
    verdict: str = "REVIEW"


@dataclass
class KeyProvenanceReport:
    tool: str = "ENTROVOUCH key-provenance detector"
    tool_version: str = __version__
    target: str = ""
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    # Python files that would not parse: NOT scanned for key material. Never rounds to NOTHING-FOUND.
    files_not_parsed: list = field(default_factory=list)
    # every file in the tree, by name and content: matched by VEX and CSAF against the CBOM
    tree_listing_digest: str = ""
    # what was not read for key material: skipped directories (with their file counts), files over the size limit,
    # and symbolic links
    not_scanned: dict = field(default_factory=dict)
    verdict: str = "NOTHING-FOUND"    # NOTHING-FOUND | REVIEW | NOT-ANALYSED
    # SHA3-256 over the canonical body: an edited report is refused by the adapters that read it. Unkeyed, so it
    # shows a change after writing, not who wrote it; this report is not signed.
    content_hash: str = ""
    scope_statement: str = (
        "Detects key material that originates in the source tree rather than in "
        "secret storage: string/bytes literals (directly or through a hex, base64 or "
        "repeat transform) bound to key-shaped names (plainly, with a type annotation, as a "
        "dataclass field default, as an attribute or configuration entry such as "
        "app.config['SECRET_KEY'], in a tuple of names, with :=, or with setattr) or to default "
        "arguments of functions and lambdas (a name bound by a for loop is not read), literal "
        "keys handed to MAC, KDF, cipher, token and JWT constructors or passed as a "
        "key-shaped keyword argument or dictionary value, a literal default for an "
        "environment variable with a key-shaped name or a literal it is set to, string literals with the published "
        "shape of a provider credential, MAC/KDF keys "
        "derived by hashing a literal, a module-level constant or a function parameter "
        "(a key hashed from an argument is exactly as secret as the least secret value "
        "any call site passes, which source cannot show), private-key files, PEM "
        "private-key armour holding a key body in any text file in the tree, this package's own signing-key files, and "
        "secrets assigned in .env and configuration files (JSON read as JSON). "
        "Static and name-based, so it is neither complete nor authoritative: a key read "
        "from a file outside the tree, an environment variable or a KMS is invisible to "
        "it (correctly), a secret assigned to an unconventionally-named variable is "
        "missed, and a password written inside a connection URL is not detected. Every finding is REVIEW, never a verdict: whether publicly-derivable key "
        "material is a defect depends on who receives the artifact, which is not knowable "
        "from source. NOTHING-FOUND means nothing came to this tool's attention in the "
        "files it read, and what it did not read (skipped directories, files over 16 MiB, what compressed "
        "archives hold, symbolic links) is "
        "listed in not_scanned; a Python file that would not parse is "
        "listed in files_not_parsed and makes the "
        "verdict REVIEW; NOT-ANALYSED means no file was read, or only archives this tool could not open."
    )


def _module_level_str_constants(tree: ast.AST) -> dict[str, str]:
    """Module-level NAME = "literal" bindings, so a key derived from one is
    traceable to a literal even when the derivation is a line away."""
    out: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        v = _literal_string(node.value) if isinstance(node, ast.Assign) else None
        if v is not None:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = v if isinstance(v, str) else v.decode("utf-8", "replace")
    return out


def _literal_string(node: ast.AST, depth: int = 0) -> str | bytes | None:
    """The string an expression of literals always is: a literal, literals added together, or one repeated a written
    number of times (`"x" * 32`). None for anything else, or for a value longer than 4,096 characters."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value
    if depth > 20 or not isinstance(node, ast.BinOp):
        return None
    if isinstance(node.op, ast.Add):
        a, b = _literal_string(node.left, depth + 1), _literal_string(node.right, depth + 1)
        ok = a is not None and b is not None and type(a) is type(b) and len(a) + len(b) <= 4096
        return a + b if ok else None
    if isinstance(node.op, ast.Mult):
        for s, n in ((node.left, node.right), (node.right, node.left)):
            v = _literal_string(s, depth + 1)
            if v is not None and isinstance(n, ast.Constant) and type(n.value) is int and 0 < n.value \
                    and len(v) * n.value <= 4096:
                return v * n.value
    return None


def _decided_at_run_time(node: ast.AST) -> bool:
    """A plain variable (`flag.key`, `parent_key`, `cfg["k"]`) or an environment read inside the expression: its value
    is not written in the source. A function applied to literals (`sha1(b"password")`, `"a" * 27`) still is."""
    called = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and (_dotted(n.func) or "").rsplit(".", 1)[-1] in ("getenv", "getenvb"):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"                 and (_dotted(n.func.value) or "").endswith("environ"):
            return True
        if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript)) and id(n) not in called                 and not _inside_called(n, node, called):
            return True
    return False


def _inside_called(target: ast.AST, root: ast.AST, called: set) -> bool:
    """`target` is part of a callee chain: `os` and `os.path` in `os.path.join(...)`."""
    for n in ast.walk(root):
        if id(n) in called:
            if any(sub is target for sub in ast.walk(n)):
                return True
    return False


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _unwrap_literal_transform(node: ast.AST) -> ast.AST:
    """`bytes.fromhex("..")`, `base64.b64decode("..")`, `b".." * 16`, `"..".encode()`, `bytearray(b"..")`:
    the value is still decided by a literal in the source."""
    for _ in range(4):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in {"fromhex", "b64decode", "urlsafe_b64decode", "a85decode", "b85decode", "b32decode",
                        "b16decode", "bytearray", "bytes", "encode", "decode", "strip", "lower", "upper"}:
                if name in {"encode", "decode", "strip", "lower", "upper"} and isinstance(fn, ast.Attribute):
                    node = fn.value
                    continue
                if node.args:
                    node = node.args[0]
                    continue
            return node
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and (
                _decided_at_run_time(node.left) or _decided_at_run_time(node.right)):
            return node     # `flag.key + "rollout"`: the value is decided by `flag.key`, not by the literal
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add)):
            left, right = node.left, node.right
            node = left if isinstance(left, (ast.Constant, ast.Call, ast.BinOp)) and not (
                isinstance(left, ast.Constant) and isinstance(left.value, int)) else right
            continue
        return node
    return node


def _is_literal_behind(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes))
    inner = _unwrap_literal_transform(node)
    return isinstance(inner, ast.Constant) and isinstance(inner.value, (str, bytes)) and len(str(inner.value)) >= 4


def _describe(node: ast.AST, consts: dict[str, str]) -> tuple[str, str] | None:
    """If `node` evaluates to something derivable from the source, say how."""
    # `bytes(32)`: thirty-two zero bytes, a key written in the source as plainly as a literal
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("bytes", "bytearray") \
            and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Constant) \
            and type(node.args[0].value) is int:
        return "literal-key", f"key argument is {node.func.id}({node.args[0].value}): that many zero bytes"
    # `KEY.encode()`, `KEY.encode("utf-8")`, `bytes(KEY, "utf-8")`: the same key, as bytes
    while isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Attribute) and node.func.attr == "encode")
            or (isinstance(node.func, ast.Name) and node.func.id in ("bytes", "bytearray") and node.args)):
        node = node.func.value if isinstance(node.func, ast.Attribute) else node.args[0]
    # sha3_256("literal").digest()  /  hashlib.sha3_256(NAME).digest()
    inner = node
    if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) \
            and inner.func.attr in {"digest", "hexdigest"}:
        inner = inner.func.value
    if isinstance(inner, ast.Call):
        fn = inner.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if name in _HASHES and inner.args:
            arg = inner.args[0]
            # .encode() unwrap
            if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) \
                    and arg.func.attr == "encode":
                arg = arg.func.value
            if isinstance(arg, ast.Constant) and isinstance(arg.value, (str, bytes)):
                return "derived-from-literal", f"{name}(<string literal in source>)"
            if isinstance(arg, ast.Name) and arg.id in consts:
                return ("derived-from-constant",
                        f"{name}({arg.id}) where {arg.id} is a module-level literal")
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return "literal-key", "key argument is a literal"
    if _is_literal_behind(node):
        return "literal-key", "key argument is a literal behind a hex/base64/repeat transform"
    if isinstance(node, ast.Name) and node.id in consts and not _restates_name(node.id, consts[node.id]):
        return "derived-from-constant", f"key is {node.id}, a module-level literal"
    return None


def _derivations(tree: ast.AST, consts: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Map every NAME: module-level *or* local: to how it was derived, when the
    derivation is visible in source.

    Locals count as much as module constants. In

        def sign(body, label):
            key = hashlib.sha3_256(label.encode()).digest()
            return hmac.new(key, body, hashlib.sha3_256)

    the key is a LOCAL derived from a PARAMETER, and a detector that tracked only
    module constants would call that file clean.
    """
    out: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        hit = _describe(node.value, consts)
        if hit is None and isinstance(node.value, (ast.Call, ast.Attribute)):
            hit = _describe_parameter_hash(node.value)
        if hit is None:
            continue
        for t in node.targets:
            if isinstance(t, ast.Name):
                out[t.id] = hit
    return out


def _last_assignment_is_derived(tree: ast.AST, name: str, line: int, consts: dict[str, str]) -> bool:
    """The last assignment to `name` before `line`, in the function that holds `line`, is one `_derivations` reads.
    RFC 6979 starts K at zero bytes and then sets it from an HMAC of the private key: after that, K is not a literal."""
    scope = tree
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.lineno <= line <= (fn.end_lineno or fn.lineno):
            if scope is tree or fn.lineno >= scope.lineno:
                scope = fn
    last = None
    for n in ast.walk(scope):
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and n.lineno <= line:
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(isinstance(x, ast.Name) and x.id == name for x in targets) and (last is None or n.lineno >= last.lineno):
                if n.lineno < line or not (isinstance(n.value, ast.Call) and n.value.lineno == line):
                    last = n
    if last is None:
        return True        # bound outside the function: the file-wide derivation stands
    if isinstance(last, ast.AugAssign) or last.value is None:
        return False
    return _describe(last.value, consts) is not None or _is_literal_behind(last.value)


def _describe_parameter_hash(node: ast.AST) -> tuple[str, str] | None:
    """`sha3_256(<name>.encode()).digest()` where <name> is not a known constant.

    Reported because a MAC key produced by hashing an argument is exactly as
    secret as the least secret thing any call site passes: which source cannot
    show. Nothing in such a function is wrong in isolation; a default supplied one
    frame up can still be public.
    """
    inner = node
    if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) \
            and inner.func.attr in {"digest", "hexdigest"}:
        inner = inner.func.value
    if not isinstance(inner, ast.Call):
        return None
    fn = inner.func
    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
    if name not in _HASHES or not inner.args:
        return None
    arg = inner.args[0]
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) \
            and arg.func.attr == "encode":
        arg = arg.func.value
    if isinstance(arg, ast.Name):
        return ("derived-from-parameter",
                f"{name}({arg.id}) - key secrecy depends on every call site, "
                "which source cannot show")
    return None


def _literal_value(node: ast.AST):
    inner = _unwrap_literal_transform(node)
    return inner.value if isinstance(inner, ast.Constant) else ""


def _secret_like(value) -> bool:
    """A literal long enough to be a secret and not a placeholder, an identifier restated,
    or an environment-variable name."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return False
    v = value.strip()
    return len(v) >= 8 and not _PLACEHOLDER_RE.match(v) and not _NON_SECRET_VALUE.match(v) and " " not in v


def _blank_literal(value) -> bool:
    """An empty string, or one of punctuation and space alone (`password = ""`, `split_token = "|"`): a variable that has not
    been given its value yet, or a separator. Nothing is hardcoded in it."""
    if isinstance(value, bytes):
        return not value          # (b"\x00" * 32 is a key of zero bytes, and a finding; only b"" is blank)
    return isinstance(value, str) and not any(c.isalnum() for c in value)


def _numeric_seed(name: str, value) -> bool:
    """`seed='0'`: a seed for a random generator that a test fixes is a number, not key material."""
    return isinstance(value, str) and value.isdigit() and len(value) <= 6 and re.search(r"(?i)(?:^|_)seed$", name) is not None


def _key_shaped(name: str, value) -> bool:
    return bool(_KEY_NAME.search(name)) and not _NOT_KEY_MATERIAL.search(name) and not _numeric_seed(name, value) \
        and not _is_ordinary_programming_noun(name, value) and not _is_mapping_key(name, value)


def _scan_python(path: Path, rel: str, not_parsed: list | None = None, source: str | None = None,
                 cell: int | None = None) -> list[KeyFinding]:
    """Key material in Python source: the file's own, or `source` (a notebook cell, a `.pth` file's start-up lines).
    A finding in a notebook cell is reported at the cell's number."""
    try:
        if source is not None:
            src = source
        else:
            try:
                src = _read_python_source(path)
            except (SyntaxError, LookupError, UnicodeDecodeError):
                src = _reads.read_text(path)
        tree = _parse_quietly(src, str(path))
    except (SyntaxError, ValueError, RecursionError, MemoryError, OSError) as exc:
        # A file that will not parse was not scanned for keys; it is listed, never counted as holding none.
        if not_parsed is not None:
            where = (f"cell {cell} of this notebook" if _reads.suffix_of(path).lower() == ".ipynb"
                     else f"the magic text at line {cell} of this file") if cell else "this file"
            not_parsed.append({"file": rel, "line": cell or getattr(exc, "lineno", None) or 0,
                               "detail": f"could not parse {where} as Python "
                                         f"({type(exc).__name__}), so it was NOT scanned for key material"})
        return []
    found = _scan_python_tree(tree, rel, src)
    return [KeyFinding(f.file, cell, f.kind, f.detail, f.verdict) for f in found] if cell else found


def _scan_python_tree(tree: ast.AST, rel: str, src: str) -> list[KeyFinding]:
    tree = _annotated_as_assigned(tree)
    consts = _module_level_str_constants(tree)
    derived = _derivations(tree, consts)
    out: list[KeyFinding] = []
    # calls whose result is assigned to a key-shaped name: `signing_key = os.getenv("K", "literal")`
    env_defaults_for_keys = {
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
        and any(isinstance(t, ast.Name) and _key_shaped(t.id, "") for t in node.targets)}

    # 1. a literal (or a transformed literal) assigned to a key-shaped name, as a module or class
    #    attribute, a local, or a default argument
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _is_literal_behind(node.value):
            lit = _unwrap_literal_transform(node.value)
            value = lit.value if isinstance(lit, ast.Constant) else ""
            for t in node.targets:
                # `os.environ["SECRET_KEY"] = "..."`
                if isinstance(t, ast.Subscript) and (_dotted(t.value) or "").rsplit(".", 1)[-1] == "environ" \
                        and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str) \
                        and _KEY_NAME.search(t.slice.value) and not _NOT_KEY_MATERIAL.search(t.slice.value) \
                        and _secret_like(value):
                    out.append(KeyFinding(rel, node.lineno, "literal-key",
                                          f"environment variable {t.slice.value} is set to a literal in source"))
                # (a string of punctuation alone, `split_token = "..."`, is a separator, not a secret)
                if isinstance(t, ast.Name) and _key_shaped(t.id, value) and not _address_or_bracket_token(value) \
                        and not _blank_literal(value):
                    how = "a literal" if isinstance(node.value, ast.Constant) else "a literal behind a transform"
                    out.append(KeyFinding(rel, node.lineno, "literal-key", f"{t.id} is assigned {how} in source"))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            positional = args.posonlyargs + args.args
            for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                if _is_literal_behind(default) and _key_shaped(arg.arg, _literal_value(default)) \
                        and not _blank_literal(_literal_value(default)):
                    out.append(KeyFinding(rel, node.lineno, "literal-key",
                                          f"default argument {arg.arg} of {node.name}() is a literal"))
            for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                if default is not None and _is_literal_behind(default) and _key_shaped(arg.arg, _literal_value(default)) \
                        and not _blank_literal(_literal_value(default)):
                    out.append(KeyFinding(rel, node.lineno, "literal-key",
                                          f"default argument {arg.arg} of {node.name}() is a literal"))
        elif isinstance(node, ast.Call):
            fn = node.func
            ctor = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if ctor in _KEY_CTORS and node.args and _is_literal_behind(node.args[0]):
                out.append(KeyFinding(rel, node.lineno, "literal-key",
                                      f"{ctor}(...) is constructed with a literal key"))
            # a literal passed under a key-shaped keyword: `Client(api_key="...")`
            known = _KEY_ARG.get((getattr(getattr(fn, "value", None), "id", ""), ctor))
            for kw in node.keywords:
                if known and kw.arg == known[1]:
                    continue        # reported once, by the MAC/KDF pass below
                if kw.arg and _is_literal_behind(kw.value):
                    value = _literal_value(kw.value)
                    if _key_shaped(kw.arg, value) and _secret_like(value):
                        out.append(KeyFinding(rel, node.lineno, "literal-key",
                                              f"keyword argument {kw.arg} of {ctor or 'a call'}(...) is a literal"))
            # a literal default for an environment variable with a key-shaped name:
            # `os.environ.get("SECRET_KEY", "dev-secret")`, `os.getenv("API_TOKEN", "...")`
            recv = fn.value if isinstance(fn, ast.Attribute) else None
            recv_name = recv.attr if isinstance(recv, ast.Attribute) else getattr(recv, "id", "")
            # the default is the second argument or the `default=` keyword: `os.getenv("K", default="...")`
            given = node.args[1] if len(node.args) >= 2 else \
                next((kw.value for kw in node.keywords if kw.arg == "default"), None)
            if ((recv_name, ctor) in _ENV_READERS or (recv_name, ctor) in _ENV_WRITERS) and given is not None \
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str) \
                    and _is_literal_behind(given):
                var, value = node.args[0].value, _literal_value(given)
                named = _KEY_NAME.search(var) and not _NOT_KEY_MATERIAL.search(var)
                if (node in env_defaults_for_keys or named) and _secret_like(value):
                    what = "is set to a literal in source" if (recv_name, ctor) in _ENV_WRITERS \
                        else "has a literal default in source" if ctor == "setdefault" else None
                    out.append(KeyFinding(rel, node.lineno, "literal-key",
                                          f"environment variable {var} {what}" if what else
                                          f"the default for environment variable {var} is a literal in source"))
        elif isinstance(node, ast.Dict):
            # a literal under a key-shaped dictionary key: `{"api_key": "..."}`
            for key, val in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and _is_literal_behind(val):
                    value = _literal_value(val)
                    if _key_shaped(key.value, value) and _secret_like(value) and not _env_name_to_field(key.value, value):
                        out.append(KeyFinding(rel, getattr(val, "lineno", node.lineno), "literal-key",
                                              f"dictionary key {key.value!r} holds a literal"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for rx, what in _CREDENTIAL_SHAPES:
                if rx.search(node.value) and not re.search(r"[Xx*]{8,}", node.value):    # (a mask is no credential)
                    out.append(KeyFinding(rel, node.lineno, "literal-key",
                                          f"a string literal has the shape of {what}"))
                    break

    # 1a. the other ways Python binds a literal to a key-shaped name: an attribute or a configuration entry
    #     (`app.secret_key = ...`, `app.config["SECRET_KEY"] = ...`), a tuple of names, `:=`, `setattr`, and a
    #     lambda's default. The value must look like a secret, as for a dictionary value.
    def _bound(target: ast.AST) -> tuple[str, str] | None:
        if isinstance(target, ast.Name):
            return target.id, target.id
        if isinstance(target, ast.Attribute):
            return target.attr, f"{_dotted(target) or '...' + '.' + target.attr}"
        if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) \
                and isinstance(target.slice.value, str) \
                and (_dotted(target.value) or "").rsplit(".", 1)[-1] != "environ":
            return target.slice.value, f"{_dotted(target.value) or '...'}[{target.slice.value!r}]"
        return None

    def _report(line: int, target: ast.AST | None, value_node: ast.AST, name_text: tuple[str, str] | None = None):
        bound = name_text or (_bound(target) if target is not None else None)
        if not bound or not _is_literal_behind(value_node):
            return
        value = _literal_value(value_node)
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        # an HTTP header name (`Content-Type`) or a dotted setting name (`sasl.oauthbearer.method`) is a label; a mask
        # (`********`) hides a secret rather than holding one; an address is where a token is fetched; a public key
        # or an endpoint named with a key word is not secret material
        if re.fullmatch(r"[A-Z][A-Za-z0-9]*(?:-[A-Z][A-Za-z0-9]*)+|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}|(.)\1+",
                        text) or re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", text) \
                or re.search(r"(?:^|_)(?:public|endpoint|uri|plugin)(?:$|_)", bound[0], re.IGNORECASE):
            return
        # a name whose only key word is `key` holding a plain identifier (`self.collection_key = "projects"`,
        # `JWT_REFRESH_JSON_KEY = "TestRefreshKey"`) names a mapping key or a field, not key material
        words = {w.lower() for w in re.findall(r"(?i)secret|key|signing|hmac|token|password|passphrase|salt|seed",
                                               bound[0])}
        if words <= {"key"} and re.fullmatch(r"[A-Za-z_]+", text):
            return
        if _key_shaped(bound[0], value) and _secret_like(value):
            out.append(KeyFinding(rel, line, "literal-key", f"{bound[1]} is assigned a literal in source"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, (ast.Attribute, ast.Subscript)):
                    _report(node.lineno, target, node.value)
                elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(node.value, (ast.Tuple, ast.List)) \
                        and len(target.elts) == len(node.value.elts):
                    for te, ve in zip(target.elts, node.value.elts):
                        _report(node.lineno, te, ve)
        elif isinstance(node, ast.NamedExpr):
            _report(node.lineno, node.target, node.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr" \
                and len(node.args) == 3 and isinstance(node.args[1], ast.Constant) \
                and isinstance(node.args[1].value, str):
            _report(node.lineno, None, node.args[2],
                    (node.args[1].value, f"setattr(..., {node.args[1].value!r}, ...)"))
        elif isinstance(node, ast.Lambda):
            args = node.args
            positional = args.posonlyargs + args.args
            pairs = list(zip(positional[len(positional) - len(args.defaults):], args.defaults)) \
                + [(a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is not None]
            for arg, default in pairs:
                _report(node.lineno, None, default, (arg.arg, f"default argument {arg.arg} of a lambda"))

    # 1b. a key-shaped name assigned the hash of a literal or constant, with no MAC call in sight
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and not _is_literal_behind(node.value):
            hit = _describe(node.value, consts)
            if hit and hit[0] != "literal-key":
                for t in node.targets:
                    if isinstance(t, ast.Name) and _key_shaped(t.id, ""):
                        out.append(KeyFinding(rel, node.lineno, hit[0], f"{t.id} is {hit[1]}"))
    # 1c. PEM private-key armour inside Python source, with a key body after it
    m = pem_with_body(src)
    if m:
        out.append(KeyFinding(rel, src.count("\n", 0, m.start()) + 1, "key-file-in-tree",
                              f"{m.group(0)} inside Python source"))

    # 2. a MAC or KDF keyed by something the source already contains (`hmac.new(key=K, msg=m)` has no positional
    # argument at all)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not (node.args or node.keywords):
            continue
        fn = node.func
        if not isinstance(fn, ast.Attribute):
            continue
        mod = getattr(fn.value, "id", "")
        spec = _KEY_ARG.get((mod, fn.attr))
        if spec is not None:
            pos, kwname = spec
            key_arg = None
            # The keyword form is checked FIRST and is authoritative: an explicit
            # `key=` outranks any positional guess, and for blake2b it is the ONLY
            # place a key can appear.
            for kw in node.keywords:
                if kw.arg == kwname:
                    key_arg = kw.value
                    break
            if key_arg is None and pos is not None and len(node.args) > pos:
                key_arg = node.args[pos]
            if key_arg is None:
                continue          # no key material passed -> nothing to report
            hit = _describe(key_arg, consts)
            if hit is None and isinstance(key_arg, ast.Name) and _last_assignment_is_derived(tree, key_arg.id,
                                                                                            node.lineno, consts):
                hit = derived.get(key_arg.id)          # local chain: key = h(...)
            if hit is None:
                hit = _describe_parameter_hash(key_arg)  # inline: hmac.new(h(x), ...)
            if hit:
                kind, how = hit
                # a MAC or signer keyed this way proves integrity but not origin; a cipher keyed this way protects
                # nothing from anyone holding the source
                cipher = fn.attr == "new" and mod in _CIPHER_MODULES
                out.append(KeyFinding(
                    rel, node.lineno, kind,
                    f"{mod}.{fn.attr}() keyed by {how} - reproducible by anyone holding the source; "
                    + ("what it encrypts is readable by anyone holding the source" if cipher
                       else "proves integrity, NOT origin")))
    return out


_JSON_KEY = re.compile(r'"((?:[^"\\\n]|\\.)*)"\s*:\s*')


def _json_places(text: str) -> dict:
    """Where each `"key": "string"` pair is written: {(key, value): [line, line, ...]} in file order, built in one
    pass. A pair written at lines 7 and 544 is reported at 7 and at 544, never twice at 7."""
    dec = json.JSONDecoder()
    places: dict = {}
    line, last = 1, 0
    for m in _JSON_KEY.finditer(text):
        if text[m.end():m.end() + 1] != '"':
            continue                   # only a string value can be reported; an object is not decoded here
        try:
            key = json.loads(f'"{m.group(1)}"')
            value = dec.raw_decode(text, m.end())[0]
        except ValueError:
            continue
        line += text.count("\n", last, m.start())
        last = m.start()
        places.setdefault((key, value), []).append(line)
    for lines in places.values():
        lines.reverse()                # popped from the end, so the first place comes out first
    return places


def _json_line(places: dict, var: str, value: str) -> int:
    """The first not-yet-reported line where `"var": value` is written."""
    lines = places.get((var, value))
    return lines.pop() if lines else 1


# archives this tool does not open, by their first bytes: 7z, rar, zstd, lz4, compress (.Z)
_OTHER_ARCHIVE_PREFIXES = (b"7z\xbc\xaf\x27\x1c", b"Rar!", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18", b"\x1f\x9d")
_ARCHIVE_MEMBER_LIMIT = 16 << 20       # bytes read from one member
_ARCHIVE_TOTAL_LIMIT = 64 << 20        # bytes read from one archive


_ARCHIVE_DEPTH = 4                     # archives inside archives, opened this many levels deep


def _container_kind(data: bytes) -> str | None:
    """What kind of archive or compressed stream `data` is, by its first bytes: zip, gzip, bzip2, xz, lzma (the
    older .lzma format), tar. None for anything else."""
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:3] == b"\x5d\x00\x00":
        return "lzma"
    if data[257:262] == b"ustar":
        return "tar"
    # a zip with bytes in front of it (a `.pyz` zipapp's `#!` line, a self-extracting archive): its end record
    # is near the end of the file and its first entry somewhere after the prefix, however long the prefix is
    if b"PK\x05\x06" in data[-(1 << 16) - 22:] and b"PK\x03\x04" in data:
        return "zip"
    return None


def _decompress_all(data: bytes, kind: str, limit: int) -> tuple[bytes, bool]:
    """Every member of a gzip, bzip2, xz or lzma file one after another (pigz, pbzip2 and `cat` write several), up to
    `limit` bytes of output. Returns (output, whole): `whole` is False when the limit cut it short."""
    import bz2
    import lzma
    import zlib
    out, rest = [], data
    total = 0
    while rest:
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif kind == "bzip2":
            d = bz2.BZ2Decompressor()
        else:
            d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE if kind == "lzma" else lzma.FORMAT_XZ)
        chunk = d.decompress(rest, limit - total + 1)
        total += len(chunk)
        out.append(chunk)
        if total > limit:
            return b"".join(out)[:limit], False
        if kind == "gzip":
            if d.unconsumed_tail:
                return b"".join(out), False
            rest = d.unused_data
            if not d.eof:
                break
        else:
            if not d.eof:
                if not d.needs_input:
                    return b"".join(out), False
                break
            rest = d.unused_data
        # members follow one another with nothing between; what follows that is not another member is padding
        if not rest or _container_kind(rest) != kind or kind == "lzma":
            break
    return b"".join(out), True


def _archive_armour(raw: bytes, rel: str) -> tuple[list[KeyFinding], bool, bool, bool]:
    """Private-key armour inside an archive or a compressed file (zip, tar, gzip, bzip2, xz, lzma), recognised by its
    bytes and opened within the limits above, archives inside archives included. Returns (findings, opened, whole,
    read): `whole` is False when a limit, or an archive inside it this tool cannot open (an encrypted zip, a `.7z`),
    left part of it unread; `read` is False when nothing in it was read at all."""
    found: list[KeyFinding] = []
    state = {"budget": _ARCHIVE_TOTAL_LIMIT, "whole": True, "read": False}
    opened = _search_container(raw, rel, "", 0, state, found)
    return found, opened, state["whole"], state["read"]


def _search_container(data: bytes, rel: str, where: str, depth: int, state: dict, found: list) -> bool:
    """Search one archive or compressed stream; True when `data` was one and was opened."""
    import io
    import lzma
    import tarfile
    import zipfile
    import zlib
    kind = _container_kind(data)
    if kind is None:
        return False
    if depth >= _ARCHIVE_DEPTH:
        state["whole"] = False
        return True
    members: list[tuple[str, bytes]] = []
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    if state["budget"] <= 0:
                        state["whole"] = False
                        break
                    take = min(_ARCHIVE_MEMBER_LIMIT, state["budget"])
                    with zf.open(info) as fh:
                        body = fh.read(take + 1)
                    if len(body) > take:
                        body, state["whole"] = body[:take], False
                    state["budget"] -= len(body)
                    members.append((info.filename, body))
        elif kind == "tar":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
                for info in tf:
                    if not info.isfile():
                        continue
                    if state["budget"] <= 0:
                        state["whole"] = False
                        break
                    take = min(_ARCHIVE_MEMBER_LIMIT, state["budget"])
                    fh = tf.extractfile(info)
                    body = fh.read(take + 1) if fh else b""
                    if len(body) > take:
                        body, state["whole"] = body[:take], False
                    state["budget"] -= len(body)
                    members.append((info.name, body))
        else:
            body, whole = _decompress_all(data, kind, max(state["budget"], 0))
            state["budget"] -= len(body)
            state["whole"] = state["whole"] and whole
            members.append(("", body))
    except (zipfile.BadZipFile, tarfile.TarError, NotImplementedError, RuntimeError, OSError, EOFError, ValueError,
            zlib.error, lzma.LZMAError):
        if not members:
            if depth:
                state["whole"] = False      # an archive inside one, which cannot be opened: listed as not fully read
                return True
            return False
        state["whole"] = False
    for name, body in members:
        # a member is named where it sits: `'id_rsa' inside 'backup.tar' inside this compressed file`
        inside = f"{name!r} inside {where or 'this archive'}" if name else (where or "this compressed file")
        if _search_container(body, rel, inside, depth + 1, state, found):
            continue
        if any(body.startswith(h) for h in _OTHER_ARCHIVE_PREFIXES):
            state["whole"] = False          # a `.7z`, `.rar` or zstd stream inside: this tool does not open it
            continue
        state["read"] = True
        text = _reads.decode_text(body)
        if "PRIVATE KEY" in text or has_base64_armour_marker(text):
            m = pem_with_body(text)
            if m:
                found.append(KeyFinding(rel, 1, "key-file-in-tree",
                                        f"{m.group(0)} {'in' if name else 'inside'} {inside}"))
    return True


def _cell_text(value) -> str:
    """The text a notebook keeps in a cell's outputs or a markdown cell: a list of lines is one text, as Jupyter
    writes printed output."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if all(isinstance(v, str) for v in value):
            return "".join(value)
        return "\n".join(_cell_text(v) for v in value)
    if isinstance(value, dict):
        return "\n".join(_cell_text(v) for v in value.values())
    return ""


def _notebook_text_armour(p: Path, rel: str, every_cell: bool = False) -> list[KeyFinding]:
    """Private-key armour a notebook keeps outside its code: printed into a cell's saved output, or written in a
    markdown cell. Reported at the cell's number."""
    try:
        data = json.loads(_reads.read_text(p))
    except (OSError, ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    cells = data.get("cells")
    if not isinstance(cells, list):
        cells = [c for w in data.get("worksheets") or [] if isinstance(w, dict)
                 for c in (w.get("cells") or []) if isinstance(w.get("cells"), list)]
    out: list[KeyFinding] = []
    for number, cell in enumerate(cells, start=1):
        if not isinstance(cell, dict):
            continue
        code = cell.get("cell_type") == "code"
        source = _cell_text(cell.get("source", cell.get("input", "")))
        first = next((ln.strip() for ln in source.splitlines() if ln.strip()), "")
        m_magic = re.match(r"%%(\w+|!)", first)
        # a code cell handed to another program or displayed (`%%bash`, `%%html`) is not read as Python: its text is
        # searched here instead
        handed_over = bool(m_magic) and m_magic.group(1) in _PROGRAM_CELL_MAGICS | _DISPLAY_CELL_MAGICS | {"!"}
        handed_over = handed_over or every_cell        # another language's notebook: its code is text here
        text = "\n".join(_cell_text(v) for k, v in cell.items()
                         if not (code and k in ("source", "input") and not handed_over))
        if "PRIVATE KEY" in text or has_base64_armour_marker(text):
            m = pem_with_body(text)
            if m:
                where = "text" if (not code or (handed_over and m.group(0) in source)) else "saved output"
                out.append(KeyFinding(rel, number, "key-file-in-tree", f"{m.group(0)} in cell {number}'s {where}"))
    # the notebook's own metadata travels with it too
    meta = _cell_text(data.get("metadata"))
    if "PRIVATE KEY" in meta or has_base64_armour_marker(meta):
        m = pem_with_body(meta)
        if m:
            out.append(KeyFinding(rel, 0, "key-file-in-tree", f"{m.group(0)} in the notebook's metadata"))
    return out


_ARCHIVE_NAMES = (".zip", ".jar", ".whl", ".egg", ".pyz", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".lzma", ".lz",
                  ".zst", ".7z", ".rar")


def _archive_contents(raw: bytes, rel: str, unread: dict | None) -> list[KeyFinding]:
    """Armour inside an archive recognised by its bytes, whatever the file is named. One that cannot be opened, or
    was opened and only partly read, is recorded in `unread`."""
    inner, opened, whole, read = _archive_armour(raw, rel)
    if not opened and unread is not None and (
            raw[:4] == b"PK\x03\x04" or any(raw.startswith(h) for h in _OTHER_ARCHIVE_PREFIXES)
            # named as an archive and not opened (an `.lzma` written with other settings): listed, not passed over
            or rel.lower().endswith(_ARCHIVE_NAMES)):
        unread.setdefault("archives_not_opened", []).append(rel)
    elif opened and not whole and unread is not None:
        # opened, and a limit (size, depth) or an archive inside it left part of what it holds unread
        unread.setdefault("archives_not_fully_read", []).append(rel)
        if not read:
            # nothing in it was read at all: as good as not opened, where the verdict is concerned
            unread.setdefault("archives_read_nothing", []).append(rel)
    return inner


# A JSON Web Key's type and a private member, in JSON, YAML, a Python or JavaScript literal, or prose
_JWK_KTY_RE = re.compile(r"""["']?\bkty["']?\s*[:=]\s*["']?(RSA|EC|OKP|oct)\b""")
# a key value is base64url of a key's length, quoted or (in YAML) not; a value that goes on as a call or an attribute
# (`to_base64url_uint(numbers.d)`) is code that computes it, not the key
_JWK_SECRET_RE = {"d": re.compile(r"""["']?\bd["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{22,})(?![\w(\[-]|\.\w)"""),
                  "k": re.compile(r"""["']?\bk["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{22,})(?![\w(\[-]|\.\w)""")}


def _looks_like_key_material(value: str) -> bool:
    """Base64url of random bytes mixes upper case, lower case and digits; a name (`JWT_PRIVATE_D_FROM_VAULT`) or a
    phrase (`modular_inverse_of_e_mod_lambda`) does not. A key value of 22 characters lacks one of the three about once
    in forty; one of 43 characters (a 256-bit key) less than once in a thousand."""
    return (any(c.isupper() for c in value) and any(c.islower() for c in value)
            and any(c.isdigit() for c in value))


def _jwk_text_findings(rel: str, text: str) -> list[KeyFinding]:
    """A private or symmetric JSON Web Key written in any text: `kty` naming the key type and, within the same
    object (up to its closing brace), the private member `d` (or `k` for `oct`), with a value that looks like key
    material. One finding per file, at the first such key. Every search is bounded to the window around the key type,
    so text that repeats `kty` takes time in proportion to its length."""
    if "kty" not in text:
        return []
    # where each member's key-like values stand (start and end of the match), found once for the whole text
    values = {member: [(v.start(), v.end()) for v in rx.finditer(text) if _looks_like_key_material(v.group(1))]
              for member, rx in _JWK_SECRET_RE.items()}
    if not values["d"] and not values["k"]:
        return []
    for m in _JWK_KTY_RE.finditer(text):
        start = text.rfind("{", max(0, m.start() - 4001), m.start())
        end = text.find("}", m.end(), m.end() + 4001)
        if start < 0 or end < 0 or "\n\n" in text[start:m.start()]:
            # no object around it (a YAML mapping): the lines near the key type, up to a blank line
            nl = text.rfind("\n", max(0, m.start() - 2001), m.start())
            line_start = nl + 1 if nl >= 0 else max(0, m.start() - 2000)
            start = max(text.rfind("\n\n", max(0, line_start - 2001), m.start()), line_start - 2000, 0)
            stop = text.find("\n\n", m.end(), m.end() + 2001)
            end = min(stop if stop >= 0 else len(text), m.end() + 2000)
        member = "k" if m.group(1) == "oct" else "d"
        spans = values[member]
        k = bisect.bisect_left(spans, (start, -1))
        if k < len(spans) and spans[k][1] <= end:
            what = ("a symmetric JSON Web Key (`oct`, with its secret `k`)" if member == "k"
                    else f"a private JSON Web Key ({m.group(1)}, with its private member `d`)")
            return [KeyFinding(rel, text.count("\n", 0, m.start()) + 1, "key-file-in-tree", what)]
    return []


def _private_jwk(data, _depth: int = 0) -> tuple[str, str] | None:
    """(what it is, the member that holds the secret) for the first private JSON Web Key in `data`: an RSA, EC or OKP
    key carrying `d` (the private exponent or scalar), or a symmetric `oct` key carrying `k`. A JWK set's `keys` and
    any other nesting are searched."""
    stack = [(data, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            kty = item.get("kty")
            if kty in ("RSA", "EC", "OKP") and isinstance(item.get("d"), str) and item["d"]:
                return f"a private JSON Web Key ({kty}, with its private member `d`)", "d"
            if kty == "oct" and isinstance(item.get("k"), str) and item["k"]:
                return "a symmetric JSON Web Key (`oct`, with its secret `k`)", "k"
            if depth < 32:
                stack += [(v, depth + 1) for v in item.values() if isinstance(v, (dict, list))]
        elif isinstance(item, list) and depth < 32:
            stack += [(v, depth + 1) for v in item if isinstance(v, (dict, list))]
    return None


def _not_readable(unread: dict | None, rel: str, exc: OSError) -> None:
    """Record a file that could not be opened (`PermissionError`, a sharing violation), by the kind of error."""
    if unread is not None:
        unread.setdefault("not_readable", []).append((rel, type(exc).__name__))


def _scan_key_files(p: Path, rel: str, read: list | None = None, unread: dict | None = None) -> list[KeyFinding]:
    """Private-key files by name, PEM private-key armour in text files, and secrets in .env files. A file not read
    is recorded in `unread` (`too_large`)."""
    out: list[KeyFinding] = []
    name = p.name.lower()
    suffix = _reads.suffix_of(p).lower()
    try:
        size = p.stat().st_size
    except OSError as exc:
        _not_readable(unread, rel, exc)
        return out
    named_key = name in _KEY_FILE_NAMES or suffix in _KEY_FILE_SUFFIXES
    is_env = name in (".env", ".envrc") or name.startswith(".env.") or name.endswith(".env")
    if size > _KEY_MAX_BYTES:
        if named_key:          # its name says what it is; nothing needs reading
            out.append(KeyFinding(rel, 1, "key-file-in-tree",
                                  "a file named like key material is in the tree (too large to read)"))
        elif unread is not None:
            unread.setdefault("too_large", []).append(rel)
        return out
    if not (named_key or is_env or suffix in _PEM_TEXT_SUFFIXES or suffix in _CONFIG_SUFFIXES):
        # any other text file (source in another language, documentation, a test fixture): private-key armour that
        # holds a key body
        try:
            text = _reads.read_text(p)
        except OSError as exc:
            _not_readable(unread, rel, exc)
            return out
        # a file with NUL bytes is searched too: armour pasted into it is still armour. An archive is recognised by
        # its bytes, whatever its name (`.war`, `.docx`, `.apk` are zip files): zip and gzip are opened and what
        # they hold is searched, within the size limit; any other archive is named in not_scanned.
        raw = _reads.read_bytes(p)
        inner = _archive_contents(raw, rel, unread)
        if read is not None:
            read.append(rel)
        if inner:
            return out + inner          # found inside: the same armour seen in the stored bytes is not repeated
        if "PRIVATE KEY" in text or has_base64_armour_marker(text):
            m = pem_with_body(text)
            if m:
                out.append(KeyFinding(rel, text.count("\n", 0, m.start()) + 1, "key-file-in-tree",
                                      f"{m.group(0)} in a file committed to the tree"))
        if not out:
            out += _jwk_text_findings(rel, text)
        return out
    try:
        text = _reads.read_text(p)
        raw = _reads.read_bytes(p)
    except OSError as exc:
        _not_readable(unread, rel, exc)
        if named_key:          # its name says what it is, read or not
            out.append(KeyFinding(rel, 1, "key-file-in-tree",
                                  "a file named like key material is in the tree (it could not be opened)"))
        return out
    if read is not None:
        read.append(rel)
    if _container_kind(raw) is not None or any(raw.startswith(h) for h in _OTHER_ARCHIVE_PREFIXES):
        # an archive under a text or key file's name (`backup.txt`, `keys.json`): what it holds is searched
        inner = _archive_contents(raw, rel, unread)
        if inner:
            return out + inner
        if named_key:
            out.append(KeyFinding(rel, 1, "key-file-in-tree",
                                  "a file named like key material is in the tree (contents not recognised as PEM)"))
        return out
    # armour that holds a key, written out or base64-encoded: a header with no key under it (`<paste your key here>`)
    # is a placeholder, as it is in a README
    m = pem_with_body(text)
    if m:
        out.append(KeyFinding(rel, text.count("\n", 0, m.start()) + 1, "key-file-in-tree",
                              f"{m.group(0)} in a file committed to the tree"))
    elif named_key:
        out.append(KeyFinding(rel, 1, "key-file-in-tree",
                              "a file named like key material is in the tree (contents not recognised as PEM)"))
    if not m and suffix not in (".json", ".jwk", ".jwks"):
        jwk_found = _jwk_text_findings(rel, text)
        if jwk_found:
            return [f for f in out if not f.detail.startswith("a file named like key material")] + jwk_found
    if suffix in (".json", ".jwk", ".jwks"):
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            data = None                 # not JSON, or nested deeper than the parser goes: its text was searched above
        if isinstance(data, dict) and {"seed", "height", "next_index"} <= set(data):
            out.append(KeyFinding(rel, 1, "key-file-in-tree",
                                  "an ENTROVOUCH signing-key file (seed, height, next_index) is in the tree"))
            return out
        jwk = _private_jwk(data)
        if jwk:
            out = [f for f in out if not f.detail.startswith("a file named like key material")]
            out.append(KeyFinding(rel, text.count("\n", 0, max(text.find('"' + jwk[1] + '"'), 0)) + 1,
                                  "key-file-in-tree", jwk[0]))
            return out
        stack = [data]
        places = None          # built on the first finding
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for var, value in item.items():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
                    elif isinstance(value, str) and _KEY_NAME.search(str(var)) and not _NOT_KEY_MATERIAL.search(str(var)) \
                            and _secret_like(value) and not _label_table(rel) and not _bare_key_word(var, value):
                        if places is None:
                            places = _json_places(text)
                        line = _json_line(places, var, value)
                        out.append(KeyFinding(rel, line, "literal-key",
                                              f"{var} is assigned a value in a configuration file in the tree"))
            elif isinstance(item, list):
                stack.extend(v for v in item if isinstance(v, (dict, list)))
        return out
    if is_env or suffix in _CONFIG_SUFFIXES:
        what = "an env file" if is_env else "a configuration file"
        for i, line in enumerate(text.splitlines(), 1):
            mm = _ENV_LINE_RE.match(line) if is_env else _CONFIG_LINE_RE.match(line)
            if not mm or line.lstrip().startswith(("#", ";", "//")):
                continue
            var, value = mm.group(1), mm.group(2).strip().strip("'\",")
            if "${{" in value or "{{" in value:
                continue    # `key: sessions-${{ github.sha }}`: the value is built when the pipeline runs
            if value.startswith("-----BEGIN"):
                continue    # armour: judged above by whether a key stands under it (a placeholder body is no key)
            if _KEY_NAME.search(var) and not _NOT_KEY_MATERIAL.search(var) and len(value) >= 8 \
                    and not _PLACEHOLDER_RE.match(value) and not _NON_SECRET_VALUE.match(value) \
                    and not _label_table(rel) and not _bare_key_word(var, value) and not _address_or_bracket_token(value):
                out.append(KeyFinding(rel, i, "literal-key", f"{var} is assigned a value in {what} in the tree"))
    return out


def scan_key_provenance(target: Path, label: str | None = None) -> KeyProvenanceReport:
    """Where the key material in `target` comes from. Each file is read as one version for the whole run."""
    with _reads.one_read_per_file():
        return _scan_key_provenance(target, label)


def _scan_key_provenance(target: Path, label: str | None = None) -> KeyProvenanceReport:
    target = Path(target)
    rep = KeyProvenanceReport(target=label or _subject_name(target))
    findings: list[KeyFinding] = []
    not_parsed: list[dict] = []
    scanned = 0
    read: list[str] = []          # key, .env and configuration files read
    unread: dict = {}             # what was not read: `too_large`
    walk = tree_files(target)
    for rel, p in walk.files:
        try:
            units = python_units(p)
        except ValueError as exc:
            scanned += 1
            if isinstance(exc, NotPythonNotebook):
                # its code is not Python; its text (cells, outputs, metadata) is still searched for key armour
                not_parsed.append({"file": rel, "line": 0,
                                   "detail": f"could not read this notebook ({exc.args[0]}) as code, so its cells "
                                             "were searched for private-key armour only"})
                try:
                    findings += _notebook_text_armour(p, rel, every_cell=True)
                except RecursionError:
                    pass
                continue
            not_parsed.append({"file": rel, "line": 0,
                               "detail": "could not read this notebook (not JSON, or not a notebook layout this tool reads), so it was NOT scanned for key material"})
            continue
        except OSError as exc:
            _not_readable(unread, rel, exc)
            if p.name.lower() in _KEY_FILE_NAMES or _reads.suffix_of(p).lower() in _KEY_FILE_SUFFIXES:
                # its name says what it is, read or not
                findings.append(KeyFinding(rel, 1, "key-file-in-tree",
                                           "a file named like key material is in the tree (it could not be opened)"))
            continue
        if units is not None:
            scanned += 1
            for src, cell in units:
                findings += _scan_python(p, rel, not_parsed, source=src, cell=cell)
                if cell is None:
                    findings += _jwk_text_findings(rel, src)     # a JSON Web Key written as a dict literal
            if _reads.suffix_of(p).lower() == ".ipynb":
                try:
                    findings += _notebook_text_armour(p, rel)
                except RecursionError:
                    # cell text nested deeper than Python's stack: the code cells were read; the rest is listed
                    not_parsed.append({"file": rel, "line": 0,
                                       "detail": "a notebook's output or metadata nested too deeply to read"})
        else:
            findings += _scan_key_files(p, rel, read, unread)
    scanned += len(read)
    for rel, why in sorted(unread.get("not_readable", [])):
        # a file the run could not open (permissions, a lock held by another program): never a clean result
        not_parsed.append({"file": rel, "line": 0,
                           "detail": f"could not be opened ({why}), so it was NOT scanned for key material"})
    rep.tree_listing_digest = tree_listing_digest(walk.files)
    rep.not_scanned = {"skipped_directories": dict(sorted(walk.skipped.items())),
                       "too_large": sorted(unread.get("too_large", [])),
                       "archives_not_opened": sorted(unread.get("archives_not_opened", [])),
                       "archives_not_fully_read": sorted(unread.get("archives_not_fully_read", [])),
                       "symbolic_links": walk.symlinks}
    rep.files_scanned = scanned
    rep.findings = [f.__dict__ for f in findings]
    rep.files_not_parsed = not_parsed
    if findings or not_parsed:
        rep.verdict = "REVIEW"
    elif scanned == 0 or scanned <= len(set(unread.get("archives_not_opened", []))
                                        | set(unread.get("archives_read_nothing", []))):
        # nothing read, or nothing read but archives this tool could not open (an encrypted zip, a `.7z`)
        rep.verdict = "NOT-ANALYSED"
    else:
        rep.verdict = "NOTHING-FOUND"
    rep.content_hash = hashlib.sha3_256(canonical_body(dict(rep.__dict__))).hexdigest()
    return rep


_cell = markdown_cell


def _not_read_lines(ns: dict) -> list[str]:
    """What was not read for key material, named so a reader knows what NOTHING-FOUND does not cover."""
    out = []
    skipped = ns.get("skipped_directories") or {}
    if skipped:
        shown = ", ".join(markdown_code(k, in_table=False) for k in list(skipped)[:12])
        more = f", and {len(skipped) - 12} more" if len(skipped) > 12 else ""
        out.append(f"- **Skipped directories (not read):** {shown}{more}")
    if ns.get("too_large"):
        shown = ", ".join(markdown_code(k, in_table=False) for k in ns["too_large"][:12])
        out.append(f"- **Files too large to read ({len(ns['too_large'])}):** {shown}")
    if ns.get("archives_not_opened"):
        shown = ", ".join(markdown_code(k, in_table=False) for k in ns["archives_not_opened"][:12])
        out.append(f"- **Archives not opened ({len(ns['archives_not_opened'])}):** {shown}")
    if ns.get("archives_not_fully_read"):
        shown = ", ".join(markdown_code(k, in_table=False) for k in ns["archives_not_fully_read"][:12])
        out.append(f"- **Archives opened but not read to the end, past a size or depth limit "
                   f"({len(ns['archives_not_fully_read'])}):** {shown}")
    if ns.get("symbolic_links"):
        out.append(f"- **Symbolic links not followed:** {ns['symbolic_links']}")
    return out


def render_markdown(rep: KeyProvenanceReport) -> str:
    lines = [f"# ENTROVOUCH Key Provenance: {rep.verdict}", "",
             f"- **Target:** {markdown_code(rep.target, in_table=False)}",
             f"- **Files scanned:** {rep.files_scanned} (Python in every form the auditor reads, and every other "
             f"text file)",
             f"- **Findings:** {len(rep.findings)}",
             *([f"- **Python files NOT parsed:** {len(rep.files_not_parsed)} (not scanned for key material)"]
               if rep.files_not_parsed else []),
             *_not_read_lines(rep.not_scanned or {}),
             "",
             f"> **Scope:** {rep.scope_statement}", ""]
    if rep.findings:
        lines += ["| File | Line | Kind | Detail |", "|---|---|---|---|"]
        for f in rep.findings:
            lines.append(f"| {markdown_code(f['file'])} | {f['line']} | {f['kind']} | {_cell(f['detail'])} |")
        lines += ["", "**REVIEW means review.** Publicly-derivable key material is "
                  "legitimate for a self-attestation and indefensible for an artifact "
                  "handed to a counterparty. Source cannot distinguish the two."]
    elif rep.verdict == "NOT-ANALYSED":
        lines.append("**No Python file was read**, so this report says nothing about where keys come from.")
    elif not rep.files_not_parsed:
        lines.append("**Nothing came to this tool's attention** in the files it read. That is limited assurance; "
                     "see the scope statement.")
    if rep.files_not_parsed:
        lines += ["", "## Files not parsed (NOT scanned for key material)", "",
                  "| File | Line | Why |", "|---|---|---|"]
        for d in rep.files_not_parsed:
            lines.append(f"| {markdown_code(d['file'])} | {d['line']} | {_cell(d['detail'])} |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse, sys, json
    ap = argparse.ArgumentParser(description="ENTROVOUCH key-provenance detector")
    ap.add_argument("target", type=Path)
    ap.add_argument("--json", type=Path, default=None, help="write the JSON report")
    ap.add_argument("--md", type=Path, default=None, help="write the markdown report")
    ap.add_argument("--label", default=None)
    args = ap.parse_args(argv)
    try:  # a non-ASCII path in a report must not crash a console or a redirected stdout on Windows
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    problem = missing_folder(args.json, args.md, tree=args.target)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    rep = scan_key_provenance(args.target, label=args.label)
    md = render_markdown(rep)
    if args.json:
        write_text(args.json, json.dumps(rep.__dict__, indent=2))
    if args.md:
        write_text(args.md, md)
    print(md)
    if rep.verdict == "NOT-ANALYSED":
        return 2
    return 1 if rep.verdict == "REVIEW" else 0


if __name__ == "__main__":
    raise SystemExit(run(main))

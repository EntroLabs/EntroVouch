#!/usr/bin/env python3
"""
ENTROVOUCH — key provenance detector.

Answers one question a CBOM does not: **where does the key come from?**

A cryptographic inventory that reports "HMAC-SHA3-256 — SAFE" is telling the
truth about the primitive and nothing about the security of the deployment. The
primitive is quantum-safe; the deployment is worthless if the key is a string
literal on line 30. Every existing check in this package would have passed the
defect that produced it.

THE DEFECT THAT PRODUCED THIS MODULE (2026-08-14, in this very package)
-----------------------------------------------------------------------
`no_egress_auditor` signed its reports with
`hmac.new(sha3_256(covenant_text), body, sha3_256)` where `covenant_text`
defaulted to a string literal published in this repository. The key was public.
A forged CLEAN verdict for a codebase that was never audited verified
successfully. The README described the arrangement as a feature.

The idea was inherited, and the inheritance is the interesting part. Its origin
(`ENTROATTEST/entroattest/pq_attest.py`) states the rule **correctly and
completely**: a Covenant-derived MAC is right for a structural SELF-attestation
and wrong for anything handed to a counterparty. What travelled was the
conclusion — *"authenticity comes from Covenant binding, not key secrecy"* —
with the precondition left behind. **A caveat kept in a different file from the
code it governs is not a caveat.**

WHY THE VERDICT IS `REVIEW` AND NOT `VULNERABLE`
------------------------------------------------
Because the origin was right. A publicly-derived key is legitimate for a
self-attestation and indefensible for a compliance artifact, and **no static
analysis can tell which one it is looking at** — that depends on who receives
the document, which is not in the source. Reporting these as VULNERABLE would be
the same overclaim in the opposite direction. This package's own rule applies:
`REVIEW` means review. It is not a pass, and it is not an accusation.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .no_egress_auditor import SKIP_DIRS

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
    r"|_field$|_column$|_prefix$|_suffix$|_order$|_algo$|_algorithm$"
    # Added 2026-08-14 after a second estate run: `key_expr` (a sort-key
    # EXPRESSION in a compiler) read as key material. "key" means a mapping or
    # sort key far more often than a secret.
    r"|_expr$|_exprs$|_expression$|_fn$|_func$|_getter$"
    # Added 2026-08-31 from the 20-repository measurement: `key_repr` (a repr
    # string), `token_str` (a parser slice), `key_derivation` ("hmac", which
    # names an ALGORITHM).
    r"|_repr$|_str$|_derivation$|_kind$|_type$|_mode$)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# ⭐ THE PREFIX AND THE VALUE, added 2026-08-31 — and the reason is a measurement.
#
# Run over 20 well-known Python repositories, this detector produced 23 findings
# of which **16 were false positives: a 70% rate**, against a published tool-
# abandonment threshold of 20-30%. Every one was the same shape:
#
#     CONFIGFILE_KEY = 'pydantic-mypy'        ROOT_KEY = '__root__'
#     ENV_VAR_KEY    = "TOX_PARALLEL_ENV"     meta_schema_key = "meta schema id"
#
# An UPPERCASE `*_KEY` constant whose value is an identifier, a dunder or an
# env-var name. **That is a MAPPING key, not key material.**
#
# 🔴 The rule that produced them judged only the NAME, and only its SUFFIX. It
# never looked at the VALUE, which is the stronger signal, and it had no notion
# of a PREFIX — so `_NOT_KEY_MATERIAL` could only ever grow one entry at a time
# behind an unbounded set of real-world names. Two structural tests replace that
# treadmill.
#
# ⚠️ Neither test may suppress `SECRET_KEY = "dev"`, which is a TRUE positive
# whose value is also a plain identifier. That is why the value test is limited
# to shapes a secret never takes, and the name test looks at what is being
# KEYED rather than at the word "key".
# ---------------------------------------------------------------------------

# Values a secret never has: a dunder, or an ENV_VAR_SHAPED_NAME.
_NON_SECRET_VALUE = re.compile(r"^(?:__\w+__|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$")

# `<thing>_KEY` where <thing> is what is being keyed, not a secrecy qualifier.
# `SECRET_KEY`, `API_KEY`, `SIGNING_KEY`, `TEST_KEY` are untouched by design.
_KEYED_THING = re.compile(
    r"(?:^|_)(config|configfile|metadata|meta|root|env|envvar|var|schema|markup|"
    r"mode|cache|index|sort|group|lookup|dict|map|section|option|setting|entry|"
    r"item|record|node|param|arg|validator|partition|bucket|shard)"
    r"[a-z0-9_]*_key$",
    re.IGNORECASE,
)


def _is_mapping_key(name: str, value) -> bool:
    """True when a `*_key` name holds a MAPPING key rather than key material.

    Two independent tests, either sufficient:
      * the VALUE is a dunder or an env-var-shaped constant name
      * the NAME says what is being keyed (`CONFIGFILE_KEY`, `meta_schema_key`)

    ⭐ Deliberately NOT another entry in a suffix list. The suffix list grows one
    real-world name at a time and can never be finished; these two tests are
    properties of the shape.
    """
    if isinstance(value, str) and _NON_SECRET_VALUE.match(value):
        return True
    return bool(_KEYED_THING.search(name))

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
# blake2b/blake2s are the reason this table exists. They were grouped with the
# KDFs and read through a shared "argument 1, else argument 0" rule, so a plain
#     hashlib.blake2b(b"just hashing data")
# reported its DATA as a literal key. Hashing a byte string is among the most
# common operations in Python, and a false positive there is far more expensive
# than the finding is worth: this tool's entire claim is that REVIEW means
# review. A detector that cries wolf on ordinary code trains its reader to skip
# it, and published work puts tool abandonment at false-positive rates above
# 20-30%. Positional-vs-keyword is not a detail here; it is the difference
# between naming a secret and naming a string somebody hashed.
_KEY_ARG = {
    ("hmac", "new"):          (0, "key"),
    ("hmac", "digest"):       (0, "key"),
    ("hashlib", "pbkdf2_hmac"): (1, "password"),
    ("hashlib", "scrypt"):    (0, "password"),
    ("hashlib", "blake2b"):   (None, "key"),
    ("hashlib", "blake2s"):   (None, "key"),
}
_HASHES = {"sha3_256", "sha3_512", "sha256", "sha512", "shake_256", "md5", "sha1"}


def _is_ordinary_programming_noun(name: str, value) -> bool:
    """Suppress the two idioms that make 'key' and 'token' ambiguous words.

    Measured on this estate: an unsuppressed run produced 31 findings across
    2,030 files, of which most were `key = "low"` (a dict lookup key) and
    `TOKEN_MANIPULATION = "token_manipulation"` (an enum member). **A detector
    that cries wolf on the ordinary sense of a word trains its reader to skip
    it**, which costs more than the findings are worth.

    Suppressed:
      1. ENUM IDIOM — the value is just the name restated
         (`ROBOTS_TOKEN_ONLY = "robots_token_only"`). Nobody writes a secret
         that way.
      2. BARE GENERIC LOCALS — a lowercase `key` / `keys` / `token` with no
         qualifier. Real key material in this estate is consistently named
         (`_SIGNING_SECRET`, `PERSON_KEY`, `_KEYFILE`); an unqualified
         lowercase `key` is overwhelmingly a mapping key.

    Both are recall costs, taken deliberately and stated: a secret literally
    assigned to a bare `key` local is missed.
    """
    if not isinstance(value, str):
        return False
    if value.strip().lower().replace("-", "_") == name.strip("_").lower():
        return True
    if name.lower() in {"key", "keys", "token", "tokens"} and not name.startswith("_"):
        return True
    # LEXICAL TOKENS, not credentials. `retrieve_token = "<RETRIEVE>"` is a
    # tokenizer symbol; in compiler and ML code this is the DOMINANT sense of the
    # word. Bracketed values are the reliable signal — nobody writes a secret as
    # "<RETRIEVE>". Found on the second estate run, in an ML training script.
    if "token" in name.lower() and value.startswith("<") and value.endswith(">"):
        return True
    return False


@dataclass
class KeyFinding:
    file: str
    line: int
    kind: str          # literal-key | derived-from-literal | derived-from-constant
    detail: str
    verdict: str = "REVIEW"


@dataclass
class KeyProvenanceReport:
    target: str = ""
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    verdict: str = "NO-PUBLIC-KEY-MATERIAL"
    scope_statement: str = (
        "Detects key material that originates in the source tree rather than in "
        "secret storage: string/bytes literals assigned to key-shaped names, and "
        "MAC/KDF keys derived by hashing a literal, a module-level constant, or a "
        "function parameter (a key hashed from an argument is exactly as secret as "
        "the least secret value any call site passes, which source cannot show). "
        "Static and name-based, so it is neither complete nor authoritative: a "
        "key read from a file, an environment variable or a KMS is invisible to "
        "it (correctly), and a secret assigned to an unconventionally-named "
        "variable is missed. Every finding is REVIEW, never a verdict — whether "
        "publicly-derivable key material is a defect depends on who receives the "
        "artifact, which is not knowable from source."
    )


def _module_level_str_constants(tree: ast.AST) -> dict[str, str]:
    """Module-level NAME = "literal" bindings, so a key derived from one is
    traceable to a literal even when the derivation is a line away."""
    out: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, (str, bytes)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    v = node.value.value
                    out[t.id] = v if isinstance(v, str) else v.decode("utf-8", "replace")
    return out


def _describe(node: ast.AST, consts: dict[str, str]) -> tuple[str, str] | None:
    """If `node` evaluates to something derivable from the source, say how."""
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
    if isinstance(node, ast.Name) and node.id in consts:
        return "derived-from-constant", f"key is {node.id}, a module-level literal"
    return None


def _derivations(tree: ast.AST, consts: dict[str, str]) -> dict[str, tuple[str, str]]:
    """Map every NAME — module-level *or* local — to how it was derived, when the
    derivation is visible in source.

    This exists because the defect that produced this module did not assign a key
    to a module constant. It read:

        def _sign(body, covenant_text):
            key = hashlib.sha3_256(covenant_text.encode()).digest()
            return hmac.new(key, body, hashlib.sha3_256)

    The key is a LOCAL, derived from a PARAMETER. A detector that only tracked
    module constants reported this file clean — which it did, on the first run.
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


def _describe_parameter_hash(node: ast.AST) -> tuple[str, str] | None:
    """`sha3_256(<name>.encode()).digest()` where <name> is not a known constant.

    Reported because a MAC key produced by hashing an argument is exactly as
    secret as the least secret thing any call site passes — which source cannot
    show. That is the honest description of the historical bug: nothing in
    `_sign` was wrong in isolation; the default supplied one frame up was public.
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


def _scan_python(path: Path, rel: str) -> list[KeyFinding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                         filename=str(path))
    except (SyntaxError, ValueError):
        return []

    consts = _module_level_str_constants(tree)
    derived = _derivations(tree, consts)
    out: list[KeyFinding] = []

    # 1. literal assigned to a key-shaped name
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, (str, bytes)):
            for t in node.targets:
                if isinstance(t, ast.Name) and _KEY_NAME.search(t.id) \
                        and not _NOT_KEY_MATERIAL.search(t.id) \
                        and not _is_ordinary_programming_noun(t.id, node.value.value)                         and not _is_mapping_key(t.id, node.value.value):
                    out.append(KeyFinding(
                        rel, node.lineno, "literal-key",
                        f"{t.id} is assigned a literal in source"))

    # 2. a MAC or KDF keyed by something the source already contains
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
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
            if hit is None and isinstance(key_arg, ast.Name):
                hit = derived.get(key_arg.id)          # local chain: key = h(...)
            if hit is None:
                hit = _describe_parameter_hash(key_arg)  # inline: hmac.new(h(x), ...)
            if hit:
                kind, how = hit
                out.append(KeyFinding(
                    rel, node.lineno, kind,
                    f"{mod}.{fn.attr}() keyed by {how} - reproducible by anyone "
                    "holding the source; proves integrity, NOT origin"))
    return out


def scan_key_provenance(target: Path, label: str | None = None) -> KeyProvenanceReport:
    rep = KeyProvenanceReport(target=label or target.name)
    findings: list[KeyFinding] = []
    scanned = 0
    for p in sorted(target.rglob("*.py")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        scanned += 1
        findings += _scan_python(p, str(p.relative_to(target)))
    rep.files_scanned = scanned
    rep.findings = [f.__dict__ for f in findings]
    rep.verdict = "REVIEW" if findings else "NO-PUBLIC-KEY-MATERIAL"
    return rep


def render_markdown(rep: KeyProvenanceReport) -> str:
    lines = [f"# ENTROVOUCH Key Provenance — {rep.verdict}", "",
             f"- **Target:** `{rep.target}`",
             f"- **Python files scanned:** {rep.files_scanned}",
             f"- **Findings:** {len(rep.findings)}", "",
             f"> **Scope:** {rep.scope_statement}", ""]
    if rep.findings:
        lines += ["| File | Line | Kind | Detail |", "|---|---|---|---|"]
        for f in rep.findings:
            lines.append(f"| `{f['file']}` | {f['line']} | {f['kind']} | {f['detail']} |")
        lines += ["", "**REVIEW means review.** Publicly-derivable key material is "
                  "legitimate for a self-attestation and indefensible for an artifact "
                  "handed to a counterparty. Source cannot distinguish the two."]
    else:
        lines.append("**No key material originating in the source tree was found.**")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse, sys, json
    ap = argparse.ArgumentParser(description="ENTROVOUCH key-provenance detector")
    ap.add_argument("target", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--label", default=None)
    args = ap.parse_args(argv)
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    rep = scan_key_provenance(args.target, label=args.label)
    if args.json:
        args.json.write_text(json.dumps(rep.__dict__, indent=2), encoding="utf-8")
    print(render_markdown(rep))
    return 1 if rep.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

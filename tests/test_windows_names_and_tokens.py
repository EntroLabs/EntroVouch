"""Names Windows shortens, timestamp tokens carrying a second TSTInfo, TOML strings with escaped quotes, conda channels."""
from __future__ import annotations

import os
import subprocess
import sys
import unicodedata
from dataclasses import asdict
from pathlib import Path

import pytest

from entrovouch import sbom
from entrovouch._parse import MAX_TOML_DEPTH, NestingTooDeep, load_toml
from entrovouch.manifests import tree_files
from entrovouch.no_egress_auditor import audit
from entrovouch.timestamp import (_NO_TST, _der_bool, _der_int, _der_octet, _der_oid, _der_seq, _tlv, _tst_nonce,
                                  report_digest)

windows = pytest.mark.skipif(os.name != "nt", reason="only Windows shortens a name ending in a dot or a space")
LONG = "\\\\?\\"


def _mk(base: Path, rel: str, text: str | None = None) -> None:
    path = LONG + str(base) + "\\" + rel.replace("/", "\\")
    if text is None:
        os.mkdir(path)
    else:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


# ---------------------------------------------------------------- the walk
@windows
def test_a_file_ending_in_a_dot_inside_a_folder_ending_in_a_dot_is_read(tmp_path):
    _mk(tmp_path, "x.")
    _mk(tmp_path, "x./run.", "#!/usr/bin/env python3\nimport socket\n")
    r = asdict(audit(tmp_path, label="t"))
    assert ("x./run.", "network-import") in {(f["file"], f["kind"]) for f in r["findings"]}


@windows
def test_a_junction_ending_in_a_dot_is_counted_and_not_followed(tmp_path):
    from _junction import make_junction
    outside = tmp_path / "outside"
    tree = tmp_path / "tree"
    outside.mkdir()
    tree.mkdir()
    (outside / "leak.py").write_text("import socket\n", encoding="utf-8")
    (tree / "ok.py").write_text("x = 1\n", encoding="utf-8")
    assert make_junction(Path(LONG + str(tree) + "\\j."), outside)
    assert make_junction(Path(LONG + str(tree) + "\\loop."), tree)
    walk = tree_files(tree)
    assert [rel for rel, _ in walk.files] == ["ok.py"]
    assert walk.symlinks == 2
    assert audit(tree, label="t").verdict == "CLEAN"


@windows
def test_a_link_stand_in_inside_a_dot_folder_is_counted_as_on_linux(tmp_path):
    _mk(tmp_path, "x.")
    _mk(tmp_path, "x./a.py", "x = 1\n")
    _mk(tmp_path, "x./ph", "a.py")
    _mk(tmp_path, "xx")
    _mk(tmp_path, "xx/a.py", "x = 1\n")
    _mk(tmp_path, "xx/ph", "a.py")
    walk = tree_files(tmp_path)
    assert [rel for rel, _ in walk.files] == ["x./a.py", "xx/a.py"]
    assert walk.symlinks == 2


@windows
def test_two_names_one_after_nfc_inside_a_dot_folder_keep_their_folder(tmp_path):
    _mk(tmp_path, "x.")
    one, two = unicodedata.normalize("NFC", "café"), unicodedata.normalize("NFD", "café")
    _mk(tmp_path, f"x./{one}.py", "x = 1\n")
    _mk(tmp_path, f"x./{two}.py", "x = 2\n")
    rels = sorted(rel for rel, _ in tree_files(tmp_path).files)
    assert rels == sorted([f"x./{one}.py", f"x./{two}.py"])


@windows
def test_a_namespace_package_under_a_dot_folder_is_read_where_it_is(tmp_path):
    _mk(tmp_path, "proj.")
    _mk(tmp_path, "proj./pyproject.toml", '[project]\nname = "pkg"\n')
    _mk(tmp_path, "proj./pkg")
    _mk(tmp_path, "proj./pkg/__init__.py", "__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n")
    _mk(tmp_path, "proj./pkg/m.py", "from pkg import requests_shim\n")
    (tmp_path / "proj").mkdir()                 # the name Windows would shorten `proj.` to, holding nothing
    (tmp_path / "proj" / "pkg").mkdir()
    (tmp_path / "proj" / "pkg" / "__init__.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "proj" / "pyproject.toml").write_text('[project]\nname = "p"\n', encoding="utf-8")
    from entrovouch.no_egress_auditor import _local_top_level_modules
    walk = tree_files(tmp_path)
    extended: set[str] = set()
    _local_top_level_modules(tmp_path, frozenset(rel for rel, _ in walk.files), extended, dict(walk.files))
    assert "pkg" in extended


# ---------------------------------------------------------------- the timestamp nonce
def _tst(digest: bytes, nonce: int | bytes) -> bytes:
    field = nonce if isinstance(nonce, bytes) else _der_int(nonce)
    return _der_seq(_der_int(1), _der_oid((1, 2, 3, 4)),
                    _der_seq(_der_seq(_der_oid((2, 16, 840, 1, 101, 3, 4, 2, 1)), _tlv(0x05, b"")), _der_octet(digest)),
                    _der_int(42), _tlv(0x18, b"20261009120000Z"), _der_bool(False), field)


def _token(digest: bytes, nonce: int | bytes, *, planted: int | None = None) -> bytes:
    """A TimeStampToken: a ContentInfo of type signedData whose content is a TSTInfo."""
    encap = _der_seq(_der_oid((1, 2, 840, 113549, 1, 9, 16, 1, 4)), _tlv(0xA0, _der_octet(_tst(digest, nonce))))
    unsigned = _tlv(0xA1, _der_seq(_der_oid((1, 2, 3)), _tlv(0x31, _tst(digest, planted)))) if planted is not None else b""
    signer = _der_seq(_der_int(1), unsigned)
    signed = _der_seq(_der_int(3), _tlv(0x31, b""), encap, _tlv(0x31, signer))
    return _der_seq(_der_oid((1, 2, 840, 113549, 1, 7, 2)), _tlv(0xA0, signed))


def _response(digest: bytes, nonce: int | bytes, *, planted: int | None = None, extra: bytes = b"") -> bytes:
    """A TimeStampResp: a status, then the token."""
    return _der_seq(_der_seq(_der_int(0)), _token(digest, nonce, planted=planted), extra)


def test_a_tstinfo_outside_the_signed_content_is_not_read():
    """An unsigned attribute is not covered by the signature: a TSTInfo planted there with another nonce must not
    replace the one the signature covers."""
    digest = bytes(range(32))
    assert _tst_nonce(_response(digest, 7), digest) == 7
    assert _tst_nonce(_response(digest, 7, planted=99), digest) == 7
    assert _tst_nonce(_response(bytes(32), 7), digest) is _NO_TST


def test_a_nonce_with_no_content_octets_is_not_a_nonce():
    digest = bytes(range(32))
    assert _tst_nonce(_response(digest, b"\x02\x00"), digest) is _NO_TST
    assert _tst_nonce(_response(digest, 0), digest) == 0


def test_the_cli_reads_only_the_signed_nonce(tmp_path):
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    token = tmp_path / "t.tsr"
    token.write_bytes(_response(report_digest(report), 7, planted=99))
    run = [sys.executable, "-m", "entrovouch.timestamp", "check", str(report), "--token", str(token), "--nonce"]
    assert subprocess.run(run + ["7"], capture_output=True, text=True).returncode == 0
    r = subprocess.run(run + ["99"], capture_output=True, text=True)
    assert r.returncode == 1 and "does NOT echo the nonce" in r.stdout


# ---------------------------------------------------------------- TOML strings
@pytest.mark.parametrize("text", [
    'a = """ \\""" ' + "[" * 150 + ' """\n',
    "a = '''x'''''\nb = 1\n",
    'a = """x"""""\nb = 1\n',
])
def test_brackets_inside_a_string_with_escaped_quotes_are_not_nesting(text):
    import tomllib
    assert load_toml(text) == tomllib.loads(text)


def test_an_escaped_quote_does_not_hide_deep_nesting():
    text = 's = """\\""""\nx = ' + "[" * (MAX_TOML_DEPTH + 1) + "]" * (MAX_TOML_DEPTH + 1) + "\n"
    with pytest.raises(NestingTooDeep):
        load_toml(text)


# ---------------------------------------------------------------- conda package URLs
def test_a_conda_channel_is_a_qualifier_and_a_bracket_is_not_part_of_the_name(tmp_path):
    (tmp_path / "environment.yml").write_text(
        'dependencies:\n  - conda-forge::NumPy==1.26.4\n  - scipy[version=">=1.2"]\n', encoding="utf-8")
    purls = sorted(c["purl"] for c in asdict(sbom.build_sbom(tmp_path))["components"])
    assert purls == ["pkg:conda/numpy@1.26.4?channel=conda-forge", "pkg:conda/scipy"]


# ---------------------------------------------------------------- every command names its version
@pytest.mark.parametrize("tool", ["attestation", "cbom", "csaf", "cyclonedx", "key_provenance", "no_egress_auditor",
                                  "sarif", "sbom", "timestamp", "verify", "vex"])
def test_every_command_answers_version(tool):
    from entrovouch._version import __version__
    r = subprocess.run([sys.executable, "-m", f"entrovouch.{tool}", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == f"entrovouch {__version__}", (tool, r.stdout, r.stderr)


def test_a_real_shaped_token_is_judged_by_its_own_imprint():
    """A token for report A, with report B's digest added outside its TSTInfo, does not carry B's imprint."""
    from entrovouch.timestamp import token_contains_digest
    a, b = bytes(range(32)), bytes(range(1, 33))
    assert token_contains_digest(_response(a, 7), a) is True
    tampered = _response(a, 7, extra=_der_octet(b))
    assert token_contains_digest(tampered, a) is True
    assert token_contains_digest(tampered, b) is False


def test_a_bare_timestamp_token_is_read_like_a_response(tmp_path):
    """`openssl ts -reply -token_out` writes the TimeStampToken alone (a ContentInfo), without the response's status."""
    from entrovouch.timestamp import token_contains_digest
    digest = bytes(range(32))
    bare = _token(digest, 7, planted=99)
    assert _tst_nonce(bare, digest) == 7
    assert token_contains_digest(bare, digest) is True
    assert token_contains_digest(bare, bytes(32)) is False
    report = tmp_path / "r.json"
    report.write_text("{}", encoding="utf-8")
    token = tmp_path / "t.tsr"
    token.write_bytes(_token(report_digest(report), 7))
    r = subprocess.run([sys.executable, "-m", "entrovouch.timestamp", "check", str(report), "--token", str(token),
                        "--nonce", "7"], capture_output=True, text=True)
    assert r.returncode == 0 and "IMPRINT match" in r.stdout and "-token_in" in r.stdout, r.stdout

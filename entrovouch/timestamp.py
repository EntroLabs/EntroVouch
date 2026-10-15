#!/usr/bin/env python3
"""
RFC 3161 trusted timestamps: request generation and imprint checking.

A signature proves WHO issued a report and THAT its bytes are unaltered. It says
nothing about WHEN. Any date inside the report is a field the issuer wrote, and an
issuer who can write a date can write a different one.

That matters beyond tidiness. The EU Cyber Resilience Act (Regulation (EU)
2024/2847) requires a manufacturer's technical documentation to be **kept current**.
"Current" is a claim about time, and a self-asserted timestamp cannot support it.
RFC 3161 is the published answer: a Timestamp Authority signs `hash + time`, so the
time comes from a third party rather than from the party being audited.

THIS MODULE MAKES NO NETWORK CALLS, AND THAT IS THE WHOLE DESIGN CONSTRAINT.
--------------------------------------------------------------------------------
Fetching a timestamp means opening a socket to a TSA. This package's central claim
is that it performs zero network operations: a claim a reader verifies by running
the auditor on this source. **A tool that acquired a network client to prove it has
no network client would be self-refuting.**

So the work is split, and the split is the honest part:

    1. WE build the RFC 3161 request           (offline, here)
    2. YOU send it to a TSA of your choosing   (curl, one command, out of band)
    3. WE check the response binds our report  (offline, here)

You choose the authority. We never learn who you asked, because we never ask.

WHAT THIS DOES NOT DO, STATED PLAINLY
----------------------------------------
It does **not** verify the TSA's signature on the returned token. Doing that means
parsing CMS/PKCS#7 and validating an X.509 chain against a trust root: real work,
and more importantly a **trust root this package would have to import**, which is
the property the rest of it is built to avoid.

What it verifies is narrower and worth stating exactly: **that the token's message
imprint is the digest of your report.** That catches a token pasted from a different
document, which is the realistic mistake. It does not catch a forged token, and a
forged token is exactly what signature verification would catch.

So the honest description is: this makes a timestamp CHECKABLE, not VERIFIED.
Feed the token to `openssl ts -verify` with your TSA's certificate for the other
half. The report says which half it did.

Usage:
    python -m entrovouch.timestamp request  report.json --out req.tsq
    #   curl -s -H "Content-Type: application/timestamp-query" \\
    #        --data-binary @req.tsq <your-tsa-url> -o resp.tsr
    python -m entrovouch.timestamp check    report.json --token resp.tsr
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path

from ._cli import missing_folder, run
from ._version import __version__
from .no_egress_auditor import (
    CBOM_TOOL, KEY_PROVENANCE_TOOL, NO_EGRESS_TOOL, SBOM_TOOL, _kind_problem, report_problem,
    strict_json_loads,
)

_REPORT_TOOLS = (NO_EGRESS_TOOL, CBOM_TOOL, SBOM_TOOL, KEY_PROVENANCE_TOOL)

# SHA-256, id-sha256: RFC 8017 / NIST. Encoded as an OID below.
_OID_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)


# ---------------------------------------------------------------------------
# Minimal DER. Only the shapes RFC 3161 needs, hand-built rather than imported.
#
# A general ASN.1 library is the obvious move and is deliberately not taken:
# it would be the package's first runtime dependency, and "no dependencies" is a
# property a reader can check in seconds. The subset below is small enough to
# read in full, which is the point.
# ---------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(v: int) -> bytes:
    if v == 0:
        return _tlv(0x02, b"\x00")
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return _tlv(0x02, b)


def _der_oid(parts: tuple[int, ...]) -> bytes:
    first = 40 * parts[0] + parts[1]
    out = bytearray([first])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunk = []
        while p:
            chunk.insert(0, (p & 0x7F) | 0x80)
            p >>= 7
        chunk[-1] &= 0x7F
        out.extend(chunk)
    return _tlv(0x06, bytes(out))


def _der_seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _der_octet(b: bytes) -> bytes:
    return _tlv(0x04, b)


def _der_bool(v: bool) -> bytes:
    return _tlv(0x01, b"\xff" if v else b"\x00")


def build_request(digest: bytes, *, nonce: int | None = None,
                  cert_req: bool = True) -> tuple[bytes, int]:
    """An RFC 3161 TimeStampReq over `digest`. Returns (DER bytes, nonce).

    The nonce is drawn from `secrets` and returned so the caller can check the
    response echoes it. **A nonce is the only thing standing between you and a
    replayed token**, so it is on by default rather than optional.

    `cert_req=True` asks the TSA to include its certificate in the response. It
    costs a few kilobytes and is what makes the token verifiable later by
    `openssl ts -verify` without hunting for the certificate separately.
    """
    if len(digest) != 32:
        raise ValueError(f"expected a 32-byte SHA-256 digest, got {len(digest)}")
    if nonce is None:
        nonce = secrets.randbits(64)
    message_imprint = _der_seq(
        _der_seq(_der_oid(_OID_SHA256), _tlv(0x05, b"")),   # AlgorithmIdentifier + NULL params
        _der_octet(digest),
    )
    req = _der_seq(
        _der_int(1),                 # version v1
        message_imprint,
        _der_int(nonce),
        _der_bool(cert_req),
    )
    return req, nonce


# ---------------------------------------------------------------------------
# Response checking: imprint only, and the docstring says so.
# ---------------------------------------------------------------------------
def _is_der_sequence(token: bytes) -> bool:
    """The file is one DER SEQUENCE whose stated length is the file's length, as every timestamp response is.
    Catches a file that only happens to hold the digest (a copy of the report's hash, a text file)."""
    if len(token) < 2 or token[0] != 0x30:
        return False
    n = token[1]
    if n < 0x80:
        return 2 + n == len(token)
    width = n & 0x7F
    if width == 0 or width > 4 or len(token) < 2 + width:
        return False
    return 2 + width + int.from_bytes(token[2:2 + width], "big") == len(token)


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]] | None:
    """The (tag, content start, content end) of each DER element between `start` and `end`; None when they do not
    tile that span exactly."""
    out, k = [], start
    while k < end:
        if k + 2 > end:
            return None
        tag, n = data[k], data[k + 1]
        if n < 0x80:
            head, length = 2, n
        else:
            width = n & 0x7F
            if width == 0 or width > 4 or k + 2 + width > end:
                return None
            head, length = 2 + width, int.from_bytes(data[k + 2:k + 2 + width], "big")
        if k + head + length > end:
            return None
        out.append((tag, k + head, k + head + length))
        k += head + length
    return out


def _is_timestamp_request(token: bytes) -> bool:
    """The file is a TimeStampReq (what `request` writes), not a response, even inside SEQUENCEs of one element each:
    a version INTEGER, then a messageImprint that opens with its algorithm (a SEQUENCE). A response opens with its
    status, whose INTEGER is followed by text or nothing. A request holds the report's digest too, so the imprint
    test alone cannot tell the two apart."""
    if not _is_der_sequence(token):
        return False
    kids = _der_children(token, *(_der_children(token, 0, len(token)) or [(0, 0, 0)])[0][1:])
    while kids is not None and len(kids) == 1 and kids[0][0] == 0x30:
        kids = _der_children(token, kids[0][1], kids[0][2])
    if not kids or len(kids) < 2 or kids[0][0] != 0x02 or kids[1][0] != 0x30:
        return False
    imprint = _der_children(token, kids[1][1], kids[1][2])
    return bool(imprint) and imprint[0][0] == 0x30


_NO_TST = object()


_OID_SIGNED_DATA = (1, 2, 840, 113549, 1, 7, 2)
_OID_TST_INFO = (1, 2, 840, 113549, 1, 9, 16, 1, 4)


def _signed_tst_fields(token: bytes):
    """The fields of the TSTInfo the token's signature covers, as (tag, start, end), or None when the token has no
    such structure: TimeStampResp (or a bare TimeStampToken, as `openssl ts -reply -token_out` writes it),
    timeStampToken (signedData), [0], SignedData, encapContentInfo of type id-ct-TSTInfo, [0], OCTET STRING, TSTInfo
    (RFC 3161 section 2.4.2, RFC 5652 section 5)."""
    def kids(start, end):
        return _der_children(token, start, end) or []

    top = kids(0, len(token))
    if len(top) != 1 or top[0][0] != 0x30:
        return None
    resp = kids(top[0][1], top[0][2])
    if len(resp) == 2 and resp[0][0] == 0x06 and resp[1][0] == 0xA0:
        info = resp                                         # a bare TimeStampToken: the ContentInfo itself
    elif len(resp) < 2 or resp[1][0] != 0x30:
        return None
    else:
        info = kids(resp[1][1], resp[1][2])                 # a TimeStampResp: status, then the ContentInfo
    if len(info) != 2 or token[info[0][1] - 2:info[0][2]] != _der_oid(_OID_SIGNED_DATA) or info[1][0] != 0xA0:
        return None
    sd = kids(info[1][1], info[1][2])
    if len(sd) != 1 or sd[0][0] != 0x30:
        return None
    fields = kids(sd[0][1], sd[0][2])                       # version, digestAlgorithms, encapContentInfo, ...
    if len(fields) < 3 or fields[0][0] != 0x02 or fields[1][0] != 0x31 or fields[2][0] != 0x30:
        return None
    encap = kids(fields[2][1], fields[2][2])
    if len(encap) != 2 or token[encap[0][1] - 2:encap[0][2]] != _der_oid(_OID_TST_INFO) or encap[1][0] != 0xA0:
        return None
    octet = kids(encap[1][1], encap[1][2])
    if len(octet) != 1 or octet[0][0] != 0x04:
        return None
    tst = kids(octet[0][1], octet[0][2])
    if len(tst) != 1 or tst[0][0] != 0x30:
        return None
    return kids(tst[0][1], tst[0][2])


def _is_bare_token(token: bytes) -> bool:
    """The file is a TimeStampToken on its own (a ContentInfo), not a TimeStampResp around one."""
    top = _der_children(token, 0, len(token)) or []
    inner = _der_children(token, top[0][1], top[0][2]) if len(top) == 1 and top[0][0] == 0x30 else None
    return bool(inner) and len(inner) == 2 and inner[0][0] == 0x06 and inner[1][0] == 0xA0


def _signed_imprint(token: bytes) -> bytes | None:
    """The messageImprint digest of the TSTInfo the token's signature covers, or None when there is none."""
    fields = _signed_tst_fields(token)
    if not fields or len(fields) < 3 or fields[2][0] != 0x30:
        return None
    imprint = _der_children(token, fields[2][1], fields[2][2])
    if not imprint or len(imprint) != 2 or imprint[1][0] != 0x04:
        return None
    return token[imprint[1][1]:imprint[1][2]]


def _tst_nonce(token: bytes, digest: bytes):
    """The nonce of the token's TSTInfo when its messageImprint holds `digest`: an int, None when it has no nonce,
    or `_NO_TST` when the token carries no TSTInfo with this imprint.

    Only the TSTInfo the signature covers counts, reached by the token's own structure (RFC 3161 section 2.4.2, RFC
    5652 section 5): TimeStampResp, then timeStampToken (a ContentInfo of type signedData), then [0], SignedData,
    encapContentInfo of type id-ct-TSTInfo, then [0], OCTET STRING, TSTInfo. A TSTInfo-shaped value anywhere else
    (an unsigned attribute, a certificate) is not read: it is not covered by the signature."""
    fields = _signed_tst_fields(token)
    return _NO_TST if fields is None else _tst_fields(token, fields, digest)


def _tst_fields(token: bytes, kids, digest: bytes):
    """The nonce when `kids` are a TSTInfo's fields with this imprint (None when it has no nonce), else `_NO_TST`."""
    if len(kids) < 5 or [k[0] for k in kids[:5]] != [0x02, 0x06, 0x30, 0x02, 0x18]:
        return _NO_TST
    imprint = _der_children(token, kids[2][1], kids[2][2])
    if not imprint or len(imprint) != 2 or imprint[0][0] != 0x30 or imprint[1][0] != 0x04 \
            or token[imprint[1][1]:imprint[1][2]] != digest:
        return _NO_TST
    rest = kids[5:]
    if rest and rest[0][0] == 0x30:                  # accuracy
        rest = rest[1:]
    if rest and rest[0][0] == 0x01:                  # ordering
        rest = rest[1:]
    if rest and rest[0][0] == 0x02:
        if rest[0][2] == rest[0][1]:
            return _NO_TST                                   # an INTEGER with no content octets is not DER
        return int.from_bytes(token[rest[0][1]:rest[0][2]], "big", signed=True)
    return None


def token_contains_digest(token: bytes, digest: bytes) -> bool:
    """Does this timestamp token carry `digest` as its message imprint?

    A DELIBERATELY SHALLOW CHECK, AND NAMING THE SHALLOWNESS IS THE POINT.
    A token shaped as RFC 3161 gives it is judged by the `messageImprint` of the
    TSTInfo its signature covers, so this digest written anywhere else in it does
    not count. Any other structure is judged by whether it holds the 32-byte
    digest. Either way it is not a signature check.

    What it catches: a token from a different report, a truncated token, a token
    pasted from the wrong file, the request file given in place of the response.
    **What it cannot catch: a forged token.** Use
    `openssl ts -verify -in token.tsr -data report.json -CAfile tsa-ca.pem` for
    that, with the TSA certificate you chose to trust.
    """
    if len(digest) != 32:
        raise ValueError("expected a 32-byte SHA-256 digest")
    if not _is_der_sequence(token) or _is_timestamp_request(token):
        return False
    signed = _signed_imprint(token)
    if signed is not None:
        # a token with a TSTInfo is judged by that TSTInfo's imprint: this digest elsewhere in it does not count
        return signed == digest
    return digest in token


def report_digest(report_path: Path) -> bytes:
    """SHA-256 over the report file's bytes, exactly as it sits on disk.

    Deliberately the FILE bytes and not a re-serialisation of the parsed JSON.
    A timestamp must bind the artifact somebody actually holds; re-serialising
    would bind a document that only this tool ever produced, and the two differ
    on key order and whitespace.
    """
    return hashlib.sha256(report_path.read_bytes()).digest()


def _nonce(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("a nonce is a whole number of zero or more")
    return value


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m entrovouch.timestamp",
        description="RFC 3161 timestamp request/check. Performs NO network operations.")
    ap.add_argument("--version", action="version", version=f"entrovouch {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("request", help="build a TimeStampReq for a report")
    r.add_argument("report", type=Path)
    r.add_argument("--out", type=Path, required=True, metavar="req.tsq")
    r.add_argument("--no-cert", action="store_true",
                   help="do not ask the TSA to embed its certificate")

    c = sub.add_parser("check", help="check a token's imprint binds the report")
    c.add_argument("report", type=Path)
    c.add_argument("--token", type=Path, required=True, metavar="resp.tsr")
    c.add_argument("--nonce", type=_nonce, default=None,
                   help="the nonce `request` printed; the token must echo it, or it may be a replay")

    args = ap.parse_args(argv)
    if getattr(args, 'out', None) is not None:
        clash = missing_folder(args.out, inputs=(args.report, getattr(args, 'token', None)))
        if clash and ("reads" in clash or "is a folder" in clash):   # a missing folder is named when written
            print(clash, file=sys.stderr)       # a report converted onto itself would be destroyed
            return 2
    if not args.report.is_file():
        print(f"error: no such report: {args.report}", file=sys.stderr)
        return 2

    raw = args.report.read_bytes()
    parsed = None
    # A JSON report in UTF-16 or UTF-32 is read by some JSON readers and by none of this tool's: it is refused
    # rather than timestamped as if it were not a report.
    if json.detect_encoding(raw) not in ("utf-8", "utf-8-sig"):
        try:
            wide = raw.decode(json.detect_encoding(raw))
        except (UnicodeDecodeError, LookupError):
            wide = ""
        if wide.lstrip("﻿ \t\r\n").startswith("{"):
            print("error: this file is a JSON document in UTF-16 or UTF-32; a report of this tool is UTF-8. "
                  "Not timestamped.", file=sys.stderr)
            return 2
    # A file that opens as a JSON object presents itself as a report, so it must be one exactly: strict UTF-8, strict
    # JSON (no key twice, no trailing bytes), and intact. Anything else is timestamped as the bytes it is.
    if raw.removeprefix(b"\xef\xbb\xbf").lstrip(b" \t\r\n").startswith(b"{"):
        if raw.startswith(b"\xef\xbb\xbf"):
            # `verify` and every converter refuse a report with a byte-order mark; one that is not usable there is
            # not timestamped here either
            print("error: this file opens as a JSON report with a UTF-8 byte-order mark; a report of this tool has "
                  "none. Not timestamped.", file=sys.stderr)
            return 2
        try:
            parsed = strict_json_loads(raw.decode("utf-8-sig"))
        except (ValueError, RecursionError) as exc:
            print(f"error: this file opens as a JSON report but is not one exactly ({str(exc)[:120]}); a report "
                  "edited after it was issued reads this way. Not timestamped.", file=sys.stderr)
            return 2
    problem = None
    if isinstance(parsed, dict):
        # a document that names one of this tool's report kinds must be one exactly, its hash included
        tool = parsed.get("tool")
        if isinstance(tool, str) and tool in _REPORT_TOOLS:
            problem = _kind_problem(parsed, tool)
        problem = problem or report_problem(parsed)
    if problem:
        print("error: " + problem.replace("Not converted.", "Not timestamped."), file=sys.stderr)
        return 2
    digest = hashlib.sha256(raw).digest()      # the bytes that were checked, never a second read

    if args.cmd == "request":
        req, nonce = build_request(digest, cert_req=not args.no_cert)
        if not Path(args.out).resolve().parent.is_dir():
            print(f"error: the folder for {args.out} does not exist; nothing was written", file=sys.stderr)
            return 2
        args.out.write_bytes(req)
        print(f"wrote {args.out}  ({len(req)} bytes)")
        print(f"report digest : {digest.hex()}")
        print(f"nonce         : {nonce}")
        print()
        print("Send it to a Timestamp Authority you choose. This tool will not:")
        print(f'  curl -s -H "Content-Type: application/timestamp-query" \\')
        print(f'       --data-binary @{args.out} <tsa-url> -o resp.tsr')
        return 0

    token = args.token.read_bytes()
    if _is_timestamp_request(token):
        print(f"report digest    : {digest.hex()}")
        print(f"token            : {args.token} ({len(token)} bytes)")
        print()
        print("This file is a timestamp REQUEST (what `request` writes), not the response a Timestamp")
        print("Authority sends back. A request holds the report's digest, so it proves nothing about time.")
        return 1
    ok = token_contains_digest(token, digest)
    print(f"report digest    : {digest.hex()}")
    print(f"token            : {args.token} ({len(token)} bytes)")
    print(f"imprint present  : {'YES' if ok else 'NO'}")
    if args.nonce is not None:
        # the nonce field of the TSTInfo that carries this report's imprint, and no other INTEGER in the token
        nonce_ok = _tst_nonce(token, digest) == args.nonce
        print(f"nonce echoed     : {'YES' if nonce_ok else 'NO'}")
        if not nonce_ok:
            print()
            print("This token does NOT echo the nonce you sent. It may be a replayed token, or the answer")
            print("to another request.")
            return 1
    print()
    if ok:
        if _signed_imprint(token) is not None:
            print("The token's TSTInfo carries this report's digest. That is an IMPRINT match,")
        else:
            print("The token holds this report's digest, but it is neither an RFC 3161 response nor a timestamp")
            print("token, so no TSTInfo was found to read it from. That is containment, not an IMPRINT match,")
        print("and not a signature verification: this tool does not validate the TSA's")
        print("certificate chain, and says so rather than implying it did.")
        if args.nonce is None:
            print("The nonce was not checked: pass --nonce with the value `request` printed.")
        print("For the other half:")
        given = "-token_in -in" if _is_bare_token(token) else "-in"
        print(f"  openssl ts -verify {given} {args.token} -data {args.report} -CAfile <tsa-ca.pem>")
        return 0
    if not _is_der_sequence(token):
        print("This file is not a timestamp response (not one DER structure of its own length). It may be")
        print("truncated, or not a token at all.")
        return 1
    print("This token does NOT carry this report's digest. It belongs to a")
    print("different document, or it is truncated.")
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run(main))

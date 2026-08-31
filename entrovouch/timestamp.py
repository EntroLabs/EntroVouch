#!/usr/bin/env python3
"""
RFC 3161 trusted timestamps — request generation and imprint checking.

A signature proves WHO issued a report and THAT its bytes are unaltered. It says
nothing about WHEN. Any date inside the report is a field the issuer wrote, and an
issuer who can write a date can write a different one.

That matters beyond tidiness. The EU Cyber Resilience Act (Regulation (EU)
2024/2847) requires a manufacturer's technical documentation to be **kept current**.
"Current" is a claim about time, and a self-asserted timestamp cannot support it.
RFC 3161 is the published answer: a Timestamp Authority signs `hash + time`, so the
time comes from a third party rather than from the party being audited.

⛔ THIS MODULE MAKES NO NETWORK CALLS, AND THAT IS THE WHOLE DESIGN CONSTRAINT.
--------------------------------------------------------------------------------
Fetching a timestamp means opening a socket to a TSA. This package's central claim
is that it performs zero network operations — a claim a reader verifies by running
the auditor on this source. **A tool that acquired a network client to prove it has
no network client would be self-refuting.**

So the work is split, and the split is the honest part:

    1. WE build the RFC 3161 request           (offline, here)
    2. YOU send it to a TSA of your choosing   (curl, one command, out of band)
    3. WE check the response binds our report  (offline, here)

You choose the authority. We never learn who you asked, because we never ask.

⚠️ WHAT THIS DOES NOT DO, STATED PLAINLY
----------------------------------------
It does **not** verify the TSA's signature on the returned token. Doing that means
parsing CMS/PKCS#7 and validating an X.509 chain against a trust root — real work,
and more importantly a **trust root this package would have to import**, which is
the property the rest of it is built to avoid.

What it verifies is narrower and worth stating exactly: **that the token's message
imprint is the digest of your report.** That catches a token pasted from a different
document, which is the realistic mistake. It does not catch a forged token, and a
forged token is exactly what signature verification would catch.

⭐ So the honest description is: this makes a timestamp CHECKABLE, not VERIFIED.
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

from ._version import __version__

# SHA-256, id-sha256 — RFC 8017 / NIST. Encoded as an OID below.
_OID_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)


# ---------------------------------------------------------------------------
# Minimal DER. Only the shapes RFC 3161 needs, hand-built rather than imported.
#
# ⭐ A general ASN.1 library is the obvious move and is deliberately not taken:
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
# Response checking — imprint only, and the docstring says so.
# ---------------------------------------------------------------------------
def token_contains_digest(token: bytes, digest: bytes) -> bool:
    """Does this timestamp token carry `digest` as its message imprint?

    ⚠️ A DELIBERATELY SHALLOW CHECK, AND NAMING THE SHALLOWNESS IS THE POINT.
    It searches the DER for the 32-byte imprint rather than parsing CMS to reach
    the `messageImprint` field. That is sound for the question asked — the digest
    of your report either appears in this token or it does not — and it is not a
    signature check.

    What it catches: a token from a different report, a truncated token, a token
    pasted from the wrong file. **What it cannot catch: a forged token.** Use
    `openssl ts -verify -in token.tsr -data report.json -CAfile tsa-ca.pem` for
    that, with the TSA certificate you chose to trust.
    """
    if len(digest) != 32:
        raise ValueError("expected a 32-byte SHA-256 digest")
    return digest in token


def report_digest(report_path: Path) -> bytes:
    """SHA-256 over the report file's bytes, exactly as it sits on disk.

    ⭐ Deliberately the FILE bytes and not a re-serialisation of the parsed JSON.
    A timestamp must bind the artifact somebody actually holds; re-serialising
    would bind a document that only this tool ever produced, and the two differ
    on key order and whitespace.
    """
    return hashlib.sha256(report_path.read_bytes()).digest()


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

    args = ap.parse_args(argv)
    if not args.report.is_file():
        print(f"error: no such report: {args.report}", file=sys.stderr)
        return 2

    digest = report_digest(args.report)

    if args.cmd == "request":
        req, nonce = build_request(digest, cert_req=not args.no_cert)
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
    ok = token_contains_digest(token, digest)
    print(f"report digest    : {digest.hex()}")
    print(f"token            : {args.token} ({len(token)} bytes)")
    print(f"imprint present  : {'YES' if ok else 'NO'}")
    print()
    if ok:
        print("The token carries this report's digest. That is an IMPRINT match,")
        print("not a signature verification — this tool does not validate the TSA's")
        print("certificate chain, and says so rather than implying it did.")
        print("For the other half:")
        print(f"  openssl ts -verify -in {args.token} -data {args.report} -CAfile <tsa-ca.pem>")
        return 0
    print("This token does NOT carry this report's digest. It belongs to a")
    print("different document, or it is truncated.")
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

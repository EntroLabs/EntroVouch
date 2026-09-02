"""Negative case: urllib.parse cannot open a socket.

A matcher that fires on the `urllib` root reports this as egress. The auditor
must stay silent here — parsing a URL is ordinary, and a false positive on
ordinary code is how a tool gets ignored.
"""
from urllib.parse import urlparse, urljoin


def event_path(endpoint: str, name: str) -> str:
    parsed = urlparse(endpoint)
    return urljoin(parsed.path.rstrip("/") + "/", name)

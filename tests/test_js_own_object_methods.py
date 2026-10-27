"""A `fetch` method called on an object is `unresolved-call`, the file's own object included.

Whether `api.fetch(u)` is still the file's own function at the call takes scope and data-flow analysis: a second key
can replace the first, a regular expression literal can hold the brace that ends the object, the name can be
rebound by destructuring or `Reflect.set`, and a `function fetch` in an inner scope is not the one shorthand names.
This reader does not do that analysis, and a wrong guess hides the browser's fetch behind a CLEAN verdict, so every
such call is reported and its sentence says that whether it reaches the network is not shown. The browser's own
fetch (`fetch(...)`, `window.fetch`, `globalThis.fetch`) is a network call.
"""
import time
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, src: str, name: str = "app.js") -> list:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return [f["kind"] for f in audit(tmp_path, label="t").findings]


@pytest.mark.parametrize("src", [
    # what looks like the file's own method
    "const handlers = { fetch: () => 1 };\nhandlers.fetch();\n",
    "let api = {\n  async fetch(id) { return id; },\n  other: 2,\n};\napi.fetch(3);\n",
    "var store = { 'fetch': function () { return 1; } };\nstore.fetch();\n",
    "function fetch() { return 1; }\nconst o = { fetch };\no.fetch();\n",
    # and the forms in which it is not
    "const api = { fetch };\napi.fetch(u);\n",
    "const api = { fetch: window.fetch };\napi.fetch(u);\n",
    "const api = { fetch() { return 1; }, fetch: window.fetch };\napi.fetch(u);\n",
    "const api = { fetch: () => 1, get fetch() { return window.fetch; } };\napi.fetch(u);\n",
    "const api = { fetch() { return 1; }, r: /}/, ...client };\napi.fetch(u);\n",
    "const api = { fetch() { return 1; } };\nReflect.set(api, 'fetch', other);\napi.fetch(u);\n",
    "let api = { fetch() { return 1; } };\n[api] = [other];\napi.fetch(u);\n",
    "function wrap() { function fetch() { return 1; } return 0; }\nconst api = { fetch };\napi.fetch(u);\n",
    "const api = { fetch() { return 1; } };\nfunction go(api) { return api.fetch(u); }\n",
    "client.fetch(u);\n",
])
def test_a_fetch_method_on_any_object_is_an_unresolved_call(tmp_path, src):
    assert _kinds(tmp_path, src) == ["unresolved-call"], src


def test_a_long_line_of_open_brackets_is_read_in_linear_time(tmp_path):
    """`a[a[a[...` (80 KB) is read in well under a second; a reassignment regex that scanned to the end of the line
    from every `ident[` took 7.5 s on it."""
    t = time.perf_counter()
    _kinds(tmp_path, "x=1;" + "a[" * 40000 + "\n")
    assert time.perf_counter() - t < 3.0


@pytest.mark.parametrize("src", [
    "const h = { fetch: () => 1 };\nfetch('/x');\n",
    "const h = { fetch: () => 1 };\nwindow.fetch('/x');\n",
    "const h = { fetch: () => 1 };\nglobalThis.fetch('/x');\n",
])
def test_the_browsers_fetch_is_still_a_network_call(tmp_path, src):
    assert "network-call" in _kinds(tmp_path, src)

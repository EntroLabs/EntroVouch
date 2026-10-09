"""Precision: exception-only submodules, methods named `exec`, socket versus asyncio calls, XML namespaces
and URLs in comments.

These cases are tuning data: the tool is fitted to them, so they are not a measure of its precision on unseen
code. Each test pins the false claim AND the true positive beside it.
"""
from entrovouch.no_egress_auditor import audit


def _findings(tmp_path, files):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    rep = audit(tmp_path)
    get = lambda f, k: f[k] if isinstance(f, dict) else getattr(f, k)   # noqa: E731
    return [(get(f, "file").replace("\\", "/"), get(f, "line"), get(f, "kind"), get(f, "detail")) for f in rep.findings]


def _at(out, file, line):
    return [f for f in out if f[0] == file and f[1] == line]


def test_urllib_error_is_exceptions_only_but_urllib_request_is_network(tmp_path):
    out = _findings(tmp_path, {"a.py": "import urllib.error\n", "b.py": "import urllib.request\n"})
    assert not _at(out, "a.py", 1)
    assert _at(out, "b.py", 1)[0][2] == "network-import"


def test_method_named_exec_is_not_called_the_builtin(tmp_path):
    out = _findings(tmp_path, {"a.py": "session.exec(select(Hero))\napp.exec()\nexec(code)\neval(expr)\n"
                                       "import builtins\nbuiltins.exec(code)\n"})
    for line in (1, 2):
        (f,) = _at(out, "a.py", line)
        assert f[2] == "method-named-exec" and "not the builtin" in f[3]     # still reported, under its own kind
    for line in (3, 4, 6):
        (f,) = _at(out, "a.py", line)
        assert f[3].endswith("dynamic code execution")


def test_socket_create_connection_is_a_socket_even_when_asyncio_is_imported(tmp_path):
    out = _findings(tmp_path, {"a.py": "import asyncio\nimport socket\n"
                                       "socket.create_connection(('h', 1))\n"
                                       "socket.create_server(('', 8000))\n"
                                       "async def m():\n    await asyncio.open_connection('h', 1)\n"})
    (c,) = _at(out, "a.py", 3)
    assert c[2] == "network-call" and "asyncio" not in c[3] and "socket" in c[3]
    (s,) = _at(out, "a.py", 4)
    assert s[2] == "inbound-listener"
    (a,) = _at(out, "a.py", 6)
    assert "asyncio network connection" in a[3]


def test_xml_namespace_is_not_an_external_url_but_a_real_src_is(tmp_path):
    html = ('<html xmlns="http://www.w3.org/1999/xhtml" xmlns:py="http://genshi.edgewall.org/">\n'
            '<svg xmlns="http://www.w3.org/2000/svg"><image href="https://cdn.example/x.png"/></svg>\n'
            '<script src="https://cdn.example/lib.js"></script>\n')
    out = _findings(tmp_path, {"page.html": html})
    assert not _at(out, "page.html", 1)
    assert _at(out, "page.html", 2) and _at(out, "page.html", 3)            # the real references stay


def test_urls_in_comments_are_not_references_but_code_after_them_is(tmp_path):
    js = ('/*\n * Examples at http://famspam.example/facebox/\n */\n'
          '// see https://docs.example/page\n'
          'fetch("https://api.example/collect"); // https://ignored.example\n'
          'var u = "https://cdn.example/lib.js";\n')
    tpl = '{#\nhttps://stackoverflow.example/q/1\n#}\n<a href="https://real.example">x</a>\n'
    out = _findings(tmp_path, {"app.js": js, "layout.html": tpl})
    js_lines = {f[1] for f in out if f[0] == "app.js"}
    assert js_lines == {5, 6}, js_lines
    html_lines = {f[1] for f in out if f[0] == "layout.html"}
    assert html_lines == {4}, html_lines

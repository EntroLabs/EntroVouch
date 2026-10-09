"""In markup, a URL is reported as a load only where the page fetches from it.

A page fetches from a `src`, a `srcset`, a `poster`, an object's `data`, the `href` of a stylesheet link or
of an SVG `use`/`image`/`script`, a CSS `url(...)` or `@import`, and a script statement that fetches or
navigates. A URL anywhere else in markup (a data attribute, a title, a variable in an inline script, a
diagram's anchor) is still reported, as `external-url`, with a sentence that says no load was shown.
Each case asserts both halves.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return sorted({f["kind"] for f in audit(tmp_path).findings})


@pytest.mark.parametrize("name,text", [
    ("p.html", '<img src="https://h.example/a.png">\n'),
    ("p.html", '<img\n  alt="x"\n  srcset="https://h.example/a.png 2x">\n'),
    ("p.html", '<video poster="https://h.example/p.jpg"></video>\n'),
    ("p.html", '<object data="https://h.example/x.swf"></object>\n'),
    ("p.html", '<link rel="stylesheet" href="https://h.example/s.css">\n'),
    ("p.html", '<script src="//cdn.h.example/a.js"></script>\n'),
    ("p.html", '<meta http-equiv="refresh" content="0; url=https://h.example/">\n'),
    ("d.svg", '<svg><use xlink:href="https://h.example/i.svg#a"/></svg>\n'),
    ("d.svg", '<svg><image href="https://h.example/i.png"/></svg>\n'),
    ("d.svg", '<svg><style>@font-face { src: url("https://h.example/f.woff2") }</style></svg>\n'),
    ("p.html", '<p style="background:url(https://h.example/b.png)">x</p>\n'),
    ("s.css", 'body { background: url("https://h.example/b.png") }\n'),
    ("s.css", '@import "https://h.example/base.css";\n'),
    ("p.html", '<script>\nvar s = document.createElement("script"); s.src = "https://h.example/a.js";\n</script>\n'),
    ("p.html", '<script>\nimport("https://h.example/m.js");\n</script>\n'),
    ("C.vue", '<template><img :src="\'https://h.example/a.png\'"></template>\n'),
    # an analytics snippet: the URL is handed to a function that sets `src` on another line
    ("p.html", "<script>\n(function(i,s,o,g,r){a=s.createElement(o);a.async=1;a.src=g;"
               "m=s.getElementsByTagName(o)[0];m.parentNode.insertBefore(a,m)\n"
               "})(window,document,'script','https://h.example/analytics.js','ga');\n</script>\n"),
    ("p.html", '<script>\nvar u="//h.example/";\nvar g=d.createElement("script"); g.src=u+"p.js";\n</script>\n'),
    # a template name bound to an address and used where the page loads from
    ("t.html.j2", '{%- macro mathjax(url="https://h.example/mathjax.js") -%}\n<script src="{{ url }}"></script>\n'
                  '{%- endmacro %}\n'),
    ("t.html", '{% set cdn = "https://h.example/lib" %}\n<script src="{{ cdn }}/a.js"></script>\n'),
    # a macro whose parameters sit on separate lines; the second is read into a script that imports it
    ("m.html.j2", '{%- macro m(\nurl="https://h.example/a.mjs",\nelk_url="https://h.example/b.mjs"\n) -%}\n'
                  '<script type="module">\nconst a = (await import("{{ url }}")).default;\n'
                  'const b = "{{ elk_url }}";\nawait import(b);\n</script>\n{%- endmacro %}\n'),
])
def test_a_url_in_a_load_position_is_a_load(tmp_path, name, text):
    assert "html-external" in _kinds(tmp_path, name, text), text


@pytest.mark.parametrize("name,text", [
    ("p.html", '<div data-endpoint="https://h.example/api"></div>\n'),
    ("p.html", '<script>\nvar API = "https://h.example/v1";\n</script>\n'),
    ("d.svg", '<svg><a xlink:href="https://h.example/help" target="_blank"><text>?</text></a>'
              '<g data-x="https://h.example/y"/></svg>\n'),
    ("s.css", 'a[href^="https://h.example/"] { color: red }\nb { content: "https://h.example/x" }\n'),
    ("p.html", '<script>\nconst ns = "https://h.example/ns/1.0";\n</script>\n'),
    # a script whose only mention of a loading call is inside a string loads nothing
    ("p.html", '<script>\nvar help = "use document.createElement(\'script\') here";\nvar u = "https://h.example/x";\n</script>\n'),
    # a template name bound to an address but used only in a link
    ("t.html", '{% set issue = "https://h.example/issues/1" %}\n<a href="{{ issue }}">report</a>\n'),
    ("p.html", "<base href='https://h.example/'>\n"),
])
def test_a_url_outside_a_load_position_is_reported_with_the_smaller_claim(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    found = audit(tmp_path).findings
    assert found and "html-external" not in {f["kind"] for f in found}, text
    assert any(f["kind"] in ("external-url", "external-link") for f in found), text
    for f in found:
        if f["kind"] == "external-url":
            assert "NOT shown" in f["detail"]


def test_one_line_holding_both_kinds_is_a_load(tmp_path):
    assert "html-external" in _kinds(
        tmp_path, "p.html", '<div data-x="https://h.example/a"><img src="https://h.example/b.png"></div>\n')

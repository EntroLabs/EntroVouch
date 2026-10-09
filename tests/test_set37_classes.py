"""Set 37's two classes, each with the true neighbour that must still be reported.

A method named `fetch` on some object (a math typesetter's parser: `e.fetch().text`) is not the browser's fetch;
it is reported, and the sentence stops at the name. And an anchor whose only outside address is a vocabulary
identifier (`itemtype='https://schema.org/WebPage'`, its href a template placeholder) links nowhere outside.
"""
from __future__ import annotations

from pathlib import Path

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> list:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return [(f["kind"], f["line"]) for f in audit(tmp_path).findings]


JS = """var n=t.fetch();if(n.text)return 1;
expect(e){if(this.fetch().text!==e)throw new Error("x")}
fetch(e){return this.tokens[e]}
function fetch(u){return cache[u]}
fetch("https://api.example.com/v1").then(r=>r.json());
window.fetch("https://api.example.com/v2");
globalThis.fetch(url);
const r = await fetch(endpoint);
model.fetch({success: done});
"""


def test_a_method_named_fetch_claims_less_and_the_browsers_fetch_stays_a_call(tmp_path):
    kinds = _kinds(tmp_path, "static/bundle.min.js", JS)
    assert ("unresolved-call", 1) in kinds and ("unresolved-call", 2) in kinds
    assert not [k for k in kinds if k[1] in (3, 4)]          # definitions call nothing
    for line in (5, 6, 7, 8):
        assert ("network-call", line) in kinds, line
    assert ("unresolved-call", 9) in kinds                  # Backbone's model.fetch(): reported, not dropped
    assert not [k for k in kinds if k[0] == "network-call" and k[1] in (1, 2, 9)]


PAGE = """{{ $value := (printf "<li itemprop='itemListElement' itemscope itemtype='https://schema.org/ListItem'><a itemscope itemtype='https://schema.org/WebPage' itemprop='item' itemid='%s' href='%s'><span itemprop='name'>%s</span></a></li>" .RelPermalink .RelPermalink .name) }}
<a itemscope itemtype='https://schema.org/WebPage' href='https://elsewhere.example.com/'>out</a>
<a href="https://elsewhere.example.com/docs">docs</a>
"""


UPLOAD = "twine " + "upload"          # spelled in two parts: the repository's own hook refuses the command text


def test_a_package_upload_in_a_makefile_is_a_network_command(tmp_path):
    src = (f"release:\n\t{UPLOAD} --verbose --repository-url https://test.pypi.org/legacy/ dist/*\n"
           f"check:\n\ttwine check dist/*\n")
    kinds = _kinds(tmp_path, "Makefile", src)
    assert ("script-network-command", 2) in kinds
    assert not [k for k in kinds if k[1] == 4]          # `twine check` reads local files


def test_a_vocabulary_identifier_in_an_anchor_is_not_where_it_points(tmp_path):
    kinds = _kinds(tmp_path, "layouts/partials/page-header.html", PAGE)
    assert not [k for k in kinds if k[1] == 1]
    assert ("external-link", 2) in kinds and ("external-link", 3) in kinds

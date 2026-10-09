"""Precision: code that looks like network use and is not, with the real case beside it.

Covers relative imports, pure submodules, server-package submodules, URLs in HTML comments and manifest line
numbers. Each test pins one false claim AND the true positive next to it, so precision cannot be bought by
losing recall.
"""
from entrovouch.no_egress_auditor import audit
from entrovouch.manifests import collect_declared_deps


def _kinds_at(tmp_path, files):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    rep = audit(tmp_path)
    get = lambda f, k: f[k] if isinstance(f, dict) else getattr(f, k)   # noqa: E731
    return {(get(f, "file").replace("\\", "/"), get(f, "line"), get(f, "kind")) for f in rep.findings}


def test_relative_import_named_like_a_network_package_is_not_flagged(tmp_path):
    kinds = _kinds_at(tmp_path, {"pkg/__init__.py": "", "pkg/segment.py": "X = 1\n",
                                 "pkg/align.py": "from .segment import X\n",
                                 "pkg/real.py": "import segment\n"})
    assert not any(f == "pkg/align.py" for f, _, _ in kinds)
    assert ("pkg/real.py", 1, "network-import") in kinds          # the absolute import is still caught


def test_from_urllib_import_parse_is_the_pure_submodule(tmp_path):
    kinds = _kinds_at(tmp_path, {"a.py": "from urllib import parse\n", "b.py": "from urllib import request\n"})
    assert not any(f == "a.py" for f, _, _ in kinds)
    assert ("b.py", 1, "network-import") in kinds


def test_server_submodule_is_a_dependency_not_a_bound_socket(tmp_path):
    kinds = _kinds_at(tmp_path, {"a.py": "from uvicorn.config import Config\n",
                                 "b.py": "from uvicorn.server import Server\n",
                                 "c.py": "import wsgiref.validate\n",
                                 "d.py": "from wsgiref.simple_server import make_server\n"})
    assert ("a.py", 1, "network-dependency") in kinds and ("a.py", 1, "inbound-listener") not in kinds
    assert ("c.py", 1, "network-dependency") in kinds and ("c.py", 1, "inbound-listener") not in kinds
    assert ("b.py", 1, "inbound-listener") in kinds
    assert ("d.py", 1, "inbound-listener") in kinds


def test_url_inside_an_html_comment_is_not_an_external_reference(tmp_path):
    kinds = _kinds_at(tmp_path, {"page.html": "<!-- taken from https://example.com/x -->\n"
                                              "<p>hi</p>\n"
                                              "<script src=\"https://cdn.example.com/a.js\"></script>\n"})
    assert ("page.html", 1, "html-external") not in kinds
    assert ("page.html", 3, "html-external") in kinds             # line numbers survive the comment blanking


def test_pep621_dependency_is_located_at_its_requirement_not_the_project_name(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "flask-example-celery"\nversion = "1"\ndependencies = [\n  "celery[redis]>=5",\n]\n',
        encoding="utf-8")
    deps, _, _ = collect_declared_deps(tmp_path)
    celery = [d for d in deps if d.name.startswith("celery")]
    assert celery and celery[0].line == 5

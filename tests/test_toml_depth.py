"""One TOML nesting limit on every Python version and every stack, like Python's and JSON's."""
from __future__ import annotations

import sys

import pytest

from entrovouch._parse import MAX_TOML_DEPTH, NestingTooDeep, load_toml
from entrovouch.manifests import _deps_from_pyproject


def _nested(kind: str, n: int) -> str:
    if kind == "array":
        return "x = " + "[" * n + "]" * n + "\n"
    return "x = " + "{a = " * n + "1" + "}" * n + "\n"


def _at_depth(frames: int, fn):
    return fn() if frames == 0 else _at_depth(frames - 1, fn)


@pytest.mark.parametrize("kind", ["array", "inline table"])
@pytest.mark.parametrize("frames", [0, 300, 600])
def test_the_limit_is_read_from_any_caller_and_one_more_is_refused(kind, frames):
    assert _at_depth(frames, lambda: load_toml(_nested(kind, MAX_TOML_DEPTH))) is not None
    with pytest.raises(NestingTooDeep):
        _at_depth(frames, lambda: load_toml(_nested(kind, MAX_TOML_DEPTH + 1)))


def test_brackets_in_strings_and_comments_are_not_nesting():
    text = 'a = ["]]]", \'[[[\'] # [[[\nb = """x\n[["""\n[t]\nc = {d = [1, {e = 2}]}\n' + "# " + "[" * 500 + "\n"
    assert load_toml(text) == {"a": ["]]]", "[[["], "b": "x\n[[", "t": {"c": {"d": [1, {"e": 2}]}}}


def test_a_pyproject_nested_past_the_limit_is_reported_not_read():
    text = '[project]\nname = "p"\ndependencies = ["requests"]\n' + _nested("array", MAX_TOML_DEPTH + 1)
    deps, notes = _deps_from_pyproject(text, "pyproject.toml")
    assert deps == [] and any("could not be parsed" in str(n) for n in notes)
    deps, notes = _deps_from_pyproject(text.replace(_nested("array", MAX_TOML_DEPTH + 1), ""), "pyproject.toml")
    assert [d.name for d in deps] == ["requests"]

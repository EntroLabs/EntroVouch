"""Parse Python source the same way on every Python version and every machine.

Python 3.11 to 3.13 refuse an expression nested deeper than about 2,990 levels, and on 3.11 that budget shrinks with
how deep the calling code already is (2,900 levels fail inside a test runner). Python 3.14 sets the limit from the
stack it finds, so the same file parses on one machine and not on another (37,000 levels on a 1 MB Windows stack, more
on a Linux runner). A report must not depend on any of that, so every tool applies one limit here: an expression
nested deeper than MAX_EXPRESSION_DEPTH levels is not parsed, on any version, on any stack, from any caller.
"""
from __future__ import annotations

import ast
import json
import re
import warnings

# Measured: at this limit Python 3.11, 3.13 and 3.14 give the same three reports for files 250 to 1,010 levels deep in
# eight forms, called from 0, 100, 300 and 600 frames deep; at 2,900, Python 3.11's reports changed with the caller.
MAX_EXPRESSION_DEPTH = 1000


class NestingTooDeep(RecursionError):
    """Source whose expressions nest deeper than MAX_EXPRESSION_DEPTH. A RecursionError, so every caller that treats a
    parse that ran out of depth as a file it could not read treats this one the same way."""


def _expression_depth_exceeds(tree: ast.AST, limit: int) -> bool:
    """Is any chain of nested expressions longer than `limit`? Walked with a list, never recursion, so a tree as deep
    as any parser accepts is measured without overflowing the stack."""
    work: list[tuple[ast.AST, int]] = [(tree, 0)]
    while work:
        node, depth = work.pop()
        for child in ast.iter_child_nodes(node):
            d = depth + 1 if isinstance(child, ast.expr) else 0
            if d > limit:
                return True
            work.append((child, d))
    return False


def parse_python(src: str, filename: str = "<unknown>") -> ast.AST:
    """`ast.parse` with the audited file's own compile-time warnings set aside, and the depth limit above.

    An invalid escape in someone else's string (`"\\d"`) is their warning, not this tool's output; under `-W error` it
    would turn a file that parses into one reported as unparseable."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(src, filename=filename)
    if _expression_depth_exceeds(tree, MAX_EXPRESSION_DEPTH):
        raise NestingTooDeep(f"expressions nested deeper than {MAX_EXPRESSION_DEPTH} levels")
    return tree


# JSON has the same problem: `json.loads` accepts 990 levels of nesting on Python 3.11, 2,998 on 3.13, and on 3.14 as
# many as the stack allows (16,896 on a 1 MB stack, over 400,000 on a large one). One limit below all of them.
MAX_JSON_DEPTH = 900
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.S)       # unrolled, so a long string is one run
_JSON_BRACKET = re.compile(r"[\[\]{}]")


def _json_depth_exceeds(text: str, limit: int) -> bool:
    """Do brackets outside strings nest deeper than `limit`? Strings are set aside first, so a bracket inside one
    (or a base64 image in a notebook) is not counted and is not walked character by character."""
    depth = 0
    for m in _JSON_BRACKET.finditer(_JSON_STRING.sub('""', text)):
        if m.group() in "[{":
            depth += 1
            if depth > limit:
                return True
        else:
            depth -= 1
    return False


def load_json(text: str, **kwargs):
    """`json.loads` with one nesting limit on every Python version and every stack. Nesting past the limit raises
    NestingTooDeep, a RecursionError, which is what every caller already treats as a file it could not read."""
    if _json_depth_exceeds(text, MAX_JSON_DEPTH):
        raise NestingTooDeep(f"JSON nested deeper than {MAX_JSON_DEPTH} levels")
    return json.loads(text, **kwargs)

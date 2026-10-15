# Contributing

Issues and pull requests are welcome. A security problem goes through [SECURITY.md](SECURITY.md), not an issue.

**A report of a wrong finding** is most useful with a small input that reproduces it, the command, the version
(`--version` on any command) and what the finding should have said. A finding that is true but unwanted is not a
false finding; [docs/WHAT_IS_READ.md](docs/WHAT_IS_READ.md) says what each tool reads and reports.

**A change to the tools** comes with a test that fails without it. A fix for a false finding asserts both halves:
the false finding is gone, and a true one next to it is still reported. Anything that can change a report on any
tree changes the version (the rule is in `entrovouch/_version.py`) and regenerates `examples/` with
`python examples/regenerate.py`.

**Before a pull request:**

```bash
python -m pytest -q
```

The suite runs on Python 3.11 to 3.14 with `pytest` alone; `pip install -e ".[test]"` adds the property-based and
schema tests. The package itself takes no dependencies outside the standard library, and a test enforces that.

Contributions are accepted under the project's [Apache License 2.0](LICENSE).

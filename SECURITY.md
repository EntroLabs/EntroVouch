# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: open the **Security** tab of this repository and choose
**Report a vulnerability**. Please do not open a public issue for it.

A useful report names the version (`python -m entrovouch.verify --version` prints it, and every report carries
it as `tool_version`), the command you ran, a small input that shows the problem, and what you expected instead.

We aim to acknowledge a report within 14 days and to agree a disclosure date with you before anything is
published. A fix ships as a new version.

## What counts

These tools make claims a buyer relies on, so a wrong claim is in scope, not only a crash:

- a signed report that `verify` accepts after its findings or its signature were changed, or that verifies
  against a root other than the one its issuer published;
- a report that says `CLEAN` over code it did not read;
- a tree that gives two different `findings_digest` values on two machines, except as
  [docs/REPRODUCING.md](docs/REPRODUCING.md) states;
- any of these tools opening a network connection, executing the code it audits, or writing outside the paths
  it is given.

A network call the auditor does not report is a detection limit, not a vulnerability, unless the documentation
says that form is caught. Report it as an ordinary issue; [docs/WHAT_IS_READ.md](docs/WHAT_IS_READ.md) lists what
is read.

## Supported versions

The latest release receives fixes. The tools have no runtime dependencies beyond Python 3.11 or later.

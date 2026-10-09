"""In a script, a network program is a command only where a command starts.

`curl` at the start of a line, after `&&`, `;`, `|`, `$(`, after `RUN`, `run:`, `sudo`, `env X=1`, or first in
an argv list is run there: `script-network-command`. The same name elsewhere on the line (an option's value,
an argument, a word in text) is still reported, as `script-network-word`, with a claim that stops at the name.
"""
from pathlib import Path

import pytest

from entrovouch.no_egress_auditor import audit


def _kinds(tmp_path: Path, name: str, text: str) -> set:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return {f["kind"] for f in audit(tmp_path).findings}


@pytest.mark.parametrize("name,text", [
    ("b.sh", "#!/bin/sh\ncurl -fsS https://h.example/x -o x\n"),
    ("b.sh", "#!/bin/sh\nset -e && git fetch origin main\n"),
    ("b.sh", "#!/bin/sh\nV=$(curl -s https://h.example/v)\n"),
    ("b.sh", "#!/bin/sh\ncat list | xargs -n1 wget -q\n"),
    ("b.sh", "#!/bin/sh\nsudo -E pip install requests\n"),
    ("b.sh", "#!/bin/sh\nenv HTTPS_PROXY=x pip install requests\n"),
    ("b.sh", "#!/bin/sh\ntimeout 30 ssh host uptime\n"),
    ("b.sh", "#!/bin/sh\nif curl -fs https://h.example/ok; then echo up; fi\n"),
    ("b.sh", "#!/bin/sh\nsh -c 'git fetch origin'\n"),
    ("Dockerfile", "FROM x\nRUN apt-get update && apt-get install -y curl\n"),
    ("Dockerfile", 'FROM x\nCMD ["curl", "-f", "https://h.example/"]\n'),
    (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: pip install -e .\n"),
    (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: |\n          git fetch --tags\n"),
    ("docker-compose.yml", 'services:\n  a:\n    healthcheck:\n      test: ["CMD", "curl", "-f", "https://h.example/"]\n'),
    ("Makefile", "deps:\n\t@pip install -r requirements.txt\n"),
    ("tox.ini", "[testenv]\ncommands =\n    pip install -e .\n"),
    ("tox.ini", "[testenv]\ncommands =\n    static: pip install --editable .[dev]\n"),
    ("b.sh", "#!/bin/sh\npython -m pip install -e .\n"),
    ("b.sh", "#!/bin/sh\n/opt/venv/bin/python3.12 -I -m pip install requests\n"),
    ("Makefile", "deps:\n\t$(PYTHON) -m pip install -e .\n"),
    (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: ${{ matrix.python }} -m pip install -U pip\n"),
    ("b.sh", "#!/bin/sh\nif [ -f r.txt ]; then python -m pip install -r r.txt; fi\n"),
    ("b.sh", '#!/bin/sh\ndocker exec "$C" apt-get update -qq\n'),
    ("b.sh", "#!/bin/sh\nPIP_CONSTRAINT= hatch env run -e test -- pip install x\n"),
    ("b.sh", '#!/bin/sh\nUV_EXCLUDE_NEWER="7 days" uv pip compile pyproject.toml -o out.txt\n'),
    ("b.sh", "#!/bin/sh\nbash -lc 'pacman -S git --noconfirm'\n"),
    ("Dockerfile", "FROM x\nRUN --mount=type=cache,target=/root/.cache/pip pip install -r r.txt\n"),
    ("roll.ps1", "& $venv\\python -m pip install --upgrade pip\n"),
    (".github/workflows/ci.yml", "env:\n  CIBW_BEFORE_ALL_LINUX: apt install -y gcc\n"),
    ("b.sh", "#!/bin/sh\npython -Im pip install dist/x.whl\n"),
    ("b.sh", "#!/bin/sh\npython -W ignore -m pip install --upgrade pip\n"),
    ("Dockerfile", "FROM x\nRUN /venv/bin/python${PYTHON_VERSION} -m pip install --upgrade pip\n"),
    ("Makefile", "vm:\n\tmultipass exec box -- sudo snap install glances\n"),
    ("b.sh", "#!/bin/sh\nhatch -e test run pip install orjson\n"),
    ("tox.ini", "[testenv]\ncommands =\n    - {envpython} -m pip install pandas\n"),
    ("b.sh", "#!/bin/sh\ncase $PY in\n  pypy3.11) pip install x ;;\nesac\n"),
    ("roll.ps1", "& $venv_dir\\$bin_path\\pip install build\n"),
    # a variable standing where a wrapper stands (`$SUDO` is `sudo` or nothing)
    ("b.sh", "#!/bin/sh\n$SUDO apt-get update\n"),
    ("b.sh", "#!/bin/sh\nrsync -avz build/ deploy@h.example:/srv/www/\n"),
    ("b.sh", "#!/bin/sh\nrsync -a out/ $TARGET\n"),
    ("Makefile", "deploy:\n\tscp dist/x.tar.gz h.example:/srv/\n"),
    # options between a package manager and its subcommand
    ("Dockerfile", "FROM x\nRUN apt-get -y update\n"),
    ("b.sh", "#!/bin/sh\npip -q install requests\n"),
    ("b.sh", "#!/bin/sh\nyum -y install git\n"),
    # a quoted string that opens where a command starts is a command line of its own
    (".github/workflows/ci.yml", 'jobs:\n  a:\n    steps:\n      - run: "pip install -e ."\n'),
    ("b.sh", "#!/bin/sh\nsh -c 'set -e; git fetch origin'\n"),
    ("b.sh", '#!/bin/sh\necho "$(curl -s https://h.example/v)"\n'),
    ("b.sh", '#!/bin/sh\nV="`wget -qO- https://h.example/v`"\n'),
    ("Makefile", "dist:\n\t$(PYTHON_ENV_VARS) build/venv/bin/python -m pip install dist/x.tar.gz\n"),
])
def test_a_program_where_a_command_starts_is_run(tmp_path, name, text):
    assert "script-network-command" in _kinds(tmp_path, name, text), text


@pytest.mark.parametrize("name,text", [
    (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: pytest --run-optional-tests ssh --cov\n"),
    ("b.sh", "#!/bin/sh\npython tool.py --transport ssh --host h\n"),
    ("b.sh", '#!/bin/sh\necho "curl https://h.example/x" > run.sh\n'),
    ("b.sh", '#!/bin/sh\nheader "git clone"\n'),
    ("b.sh", "#!/bin/sh\npython tool.py -m ssh --host h\n"),                  # an option's value, not a module run
    # a comment in a syntax this tool does not blank is still not where a command starts
    ("Jenkinsfile", "pipeline {\n  // then run curl -fsS https://h.example/x by hand\n}\n"),
    ("b.sh", "#!/bin/sh\n: 'curl -fsS https://h.example/x would fetch it'\n"),
    # a `|` inside a quoted pattern is part of the pattern: nothing after it is run (set 23)
    (".github/workflows/hook.yml", "hook:\n  command: \"if echo x | grep -qE '(git commit|git fetch|gh pr view)'; "
                                   "then exit 1; fi\"\n"),
    ("b.sh", "#!/bin/sh\ngrep -E 'pip install|curl -s' build.log\n"),
    # escaped backticks are text (set 25): release notes in a JSON payload
    ("release.sh", '#!/bin/sh\necho "{\\"body\\": \\"Install: \\`\\`\\`pip install pkg==1\\`\\`\\`\\"}" > notes.json\n'),
    # a script written with echo names curl; it does not run it here (set 25)
    ("Dockerfile", "FROM x\nRUN ( echo '#!/bin/bash'; echo 'curl -fs http://localhost:8080/ready' ) > /usr/local/bin/ready\n"),
    # the name is looked up, not run (set 24)
    ("b.sh", "#!/bin/sh\nif ! [ -x \"$(command -v curl)\" ]; then echo missing; fi\n"),
    ("b.sh", "#!/bin/sh\nwhich wget >/dev/null || exit 1\n"),
    # a Makefile variable holds the command; it runs where it is used (set 23)
    ("Makefile", "FETCH=docker-machine scp $(HOST):$(OUT)/*.pickle ./\nall:\n\techo done\n"),
])

def test_a_program_named_elsewhere_is_reported_with_the_smaller_claim(tmp_path, name, text):
    kinds = _kinds(tmp_path, name, text)
    assert "script-network-word" in kinds and "script-network-command" not in kinds, text


def test_a_copy_between_local_paths_reaches_nothing(tmp_path):
    """`rsync -a docs/_build/html/ docs/gh-pages/current/` copies on this machine (set 24)."""
    for line in ("rsync -a docs/_build/html/ docs/gh-pages/current/", "scp a.txt b.txt"):
        kinds = _kinds(tmp_path, "b.sh", f"#!/bin/sh\n{line}\n")
        assert "script-network-command" not in kinds and "script-network-word" not in kinds, line

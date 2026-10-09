"""A program's options or variables before its subcommand; Makefile assignments (`+=`, a value naming its old one,
`define`, `private`, comments, `$(strip)`, `?=`, a quiet prefix); a command whose program is a variable the file does
not resolve; Dockerfile exec form and `ENV` programs; batch, PowerShell and Python programs named by variables; ctypes
libraries and functions bound to names; Windows remote administration; database clients run bare or after a
launcher; browser openers in argv lists and after `cmd /c`; nested archives key_provenance cannot open; wrappers that
run what follows; ssh forwarding; the environment set from a mapping; setup.cfg dash names; `.envrc` and YAML list
secrets; argparse option names in cbom; UNC f-strings with a bound server; malformed notebooks and manifests; a
missing output folder; the key height a signer accepts. Each test asserts both halves where there are two."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from entrovouch import cbom, key_provenance, sbom
from entrovouch.no_egress_auditor import audit
from entrovouch.signer import MerkleSigner, SignerError


def _write(root: Path, rel: str, body) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
    return p


def _report(root: Path) -> list[tuple[str, int, str, str]]:
    return [(f["file"], f["line"], f["kind"], f["detail"]) for f in audit(root, label="t").findings]


def _found(root: Path) -> list[tuple[str, int, str]]:
    return [(f, n, k) for f, n, k, _ in _report(root)]


# ---------------------------------------------------------------- options before the subcommand
@pytest.mark.parametrize("line", [
    "npm --prefix web ci", "yarn --cwd docs install", "terraform -chdir=infra init",
    "apt-get -o Acquire::Retries=3 update", "uv --quiet sync", "gem --verbose install rake", "go -C sub mod download",
    "bundle --quiet install", "composer --no-interaction install", "dotnet --nologo restore",
    "pip --trusted-host h install x", "pip $PIPFLAGS install requests", "git $GITFLAGS pull",
    "npm ${{ inputs.flags }} install", "uv -q pip install x",
])
def test_an_option_before_the_subcommand_hides_nothing(tmp_path, line):
    _write(tmp_path, "run.sh", "#!/bin/sh\n" + line + "\n")
    assert ("run.sh", 2, "script-network-command") in _found(tmp_path)


@pytest.mark.parametrize("line", ["npm --offline ci", "pip --no-index install x", "npm --version",
                                  "echo npm --prefix web"])
def test_an_option_that_keeps_a_command_local_is_still_read(tmp_path, line):
    _write(tmp_path, "run.sh", "#!/bin/sh\n" + line + "\n")
    assert not any(k == "script-network-command" for _, _, k in _found(tmp_path))


def test_a_remote_daemon_option_is_not_set_aside():
    from entrovouch.no_egress_auditor import _blank_leading_options
    assert _blank_leading_options("docker -H tcp://h:2375 ps") == "docker -H tcp://h:2375 ps"
    assert _blank_leading_options("npm --prefix web ci").split() == ["npm", "ci"]


def test_options_before_a_subcommand_in_argv_lists_and_package_scripts(tmp_path):
    _write(tmp_path, "a.py", "import subprocess\nsubprocess.run(['npm', '--prefix', 'web', 'install'])\n")
    _write(tmp_path, "package.json", '{"scripts": {"postinstall": "npm --prefix web install", "build": "npm run x"}}')
    found = _found(tmp_path)
    assert ("a.py", 2, "subprocess-net-binary") in found
    assert [k for f, _, k in found if f == "package.json"] == ["declared-remote-source"]


# ---------------------------------------------------------------- Makefile assignments
@pytest.mark.parametrize("makefile, line", [
    ("FETCH = git\nFETCH += -C repo\nall:\n\t$(FETCH) pull\n", 4),
    ("FETCH = git\nFETCH := $(FETCH) -C repo\nall:\n\t$(FETCH) pull\n", 4),
    ("define FETCH\ngit\nendef\nall:\n\t$(FETCH) pull\n", 5),
    ("private VCS = git\nall:\n\t$(VCS) pull\n", 3),
    ("VCS = git # the vcs\nall:\n\t$(VCS) pull\n", 3),
    ("VCS = $(strip git)\nall:\n\t$(VCS) pull\n", 3),
    ("GITCMD = git\nGITCMD ?= hg\nall:\n\t$(GITCMD) pull\n", 4),
    ("ifeq ($(V),1)\n  AT =\nelse\n  AT = @\nendif\nall:\n\t$(AT)git pull\n", 7),
    ("all:\n\t$(Q)npm install\n", 2),
    ("VCS = git\nall:\n\t$(VCS) $(if $(V),-v) pull\n", 3),
])
def test_makefile_assignments_are_read(tmp_path, makefile, line):
    _write(tmp_path, "Makefile", makefile)
    assert ("Makefile", line, "script-network-command") in _found(tmp_path)


def test_a_question_mark_assignment_does_not_replace_a_value(tmp_path):
    _write(tmp_path, "Makefile", "GITCMD = git\nGITCMD ?= hg\nall:\n\t$(GITCMD) pull\n")
    assert any("git pull" in d for _, n, _, d in _report(tmp_path) if n == 4)


# ---------------------------------------------------------------- a program the file does not resolve
@pytest.mark.parametrize("rel, body, line", [
    ("Makefile", "INSTALLER := $(shell which pip3)\ninstall:\n\t$(INSTALLER) install requests\n", 3),
    ("Makefile", "install:\n\t$(INSTALLER) install requests\n", 2),
    ("Makefile", "include tools.mk\ninstall:\n\t$(INSTALLER) install requests\n", 3),
    ("run.sh", '#!/bin/sh\n"$VCS" pull\n', 2),
    ("Makefile", "TOOLS := git\nall:\n\t$(firstword $(TOOLS)) pull\n", 3),
])
def test_an_unresolved_program_with_a_fetching_subcommand(tmp_path, rel, body, line):
    _write(tmp_path, rel, body)
    hit = [d for f, n, k, d in _report(tmp_path) if n == line and k == "unresolved-call"]
    assert hit and "NOT shown" in hit[0]


def test_an_unresolved_program_with_a_local_subcommand_is_quiet(tmp_path):
    _write(tmp_path, "run.sh", '#!/bin/sh\n"$TOOL" build\necho "$VCS pull"\nT=ls\nT=cat\n"$T" install x\n')
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- Dockerfile
@pytest.mark.parametrize("instruction, words", [
    ('RUN ["pip", "install", "requests"]', "pip install"),
    ('RUN ["/bin/sh", "-c", "pip install requests"]', "pip install"),
    ('RUN [ "npm", "ci" ]', "npm ci"),
    ('HEALTHCHECK CMD ["curl", "-f", "http://example.com/"]', "curl"),
])
def test_dockerfile_exec_form(tmp_path, instruction, words):
    _write(tmp_path, "Dockerfile", "FROM scratch\n" + instruction + "\n")
    hit = [d for _, n, k, d in _report(tmp_path) if n == 2 and k == "script-network-command"]
    assert hit and words in hit[0]


def test_dockerfile_exec_form_of_a_local_program_is_quiet(tmp_path):
    _write(tmp_path, "Dockerfile", 'FROM scratch\nCMD ["python", "app.py"]\nRUN ["echo", "a\\"b"]\n')
    assert _found(tmp_path) == []


def test_dockerfile_env_and_arg_programs(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM scratch\nENV PIP_CMD=pip\nARG TOOL=curl\nRUN ${PIP_CMD} install requests\n"
                                   "RUN $TOOL -o x https://a.example.com/x\n")
    found = _found(tmp_path)
    assert ("Dockerfile", 4, "script-network-command") in found and ("Dockerfile", 5, "script-network-command") in found


# ---------------------------------------------------------------- variables in batch, PowerShell and Python
@pytest.mark.parametrize("rel, body, line", [
    ("b.bat", "set VCS=git\n%VCS% pull\n", 2),
    ("b.cmd", 'set "VCS=git"\n%VCS% pull\n', 2),
    ("a.ps1", '$vcs = "git"\n& $vcs pull\n', 2),
])
def test_a_windows_script_program_named_by_a_variable(tmp_path, rel, body, line):
    _write(tmp_path, rel, body)
    hit = [d for f, n, k, d in _report(tmp_path) if n == line and k == "script-network-command"]
    assert hit and "git pull" in hit[0]


def test_a_python_argv_element_bound_to_a_string(tmp_path):
    _write(tmp_path, "a.py", "import subprocess\nGIT = 'git'\nsubprocess.run([GIT, 'pull'])\n"
                             "LS = 'ls'\nsubprocess.run([LS, '-l'])\n")
    found = _found(tmp_path)
    assert ("a.py", 3, "git-remote") in found and not any(n == 5 for _, n, _ in found)


# ---------------------------------------------------------------- native libraries
@pytest.mark.parametrize("body, words", [
    ("import ctypes\nf = ctypes.windll.urlmon.URLDownloadToFileW\n", "a function of a native library"),
    ("import ctypes\nlib = ctypes.cdll['libcurl.so']\n", "loads a native library"),
    ("import ctypes\nlib = ctypes.WinDLL\n", "loader"),
    ("import ctypes\nlib = getattr(ctypes.windll, 'urlmon')\n", "loads a native library"),
    ("from ctypes import windll\nwindll.urlmon.URLDownloadToFileW(0, 'u', 'p', 0, 0)\n", "windll.urlmon."),
    ("import _ctypes\nh = _ctypes.LoadLibrary('urlmon')\n", "native library"),
])
def test_native_library_forms(tmp_path, body, words):
    _write(tmp_path, "a.py", body)
    hit = [d for _, n, k, d in _report(tmp_path) if n == 2 and k == "native-call"]
    assert hit and words in hit[0]


# ---------------------------------------------------------------- Windows remote administration
@pytest.mark.parametrize("rel, line", [
    ("a.bat", "tasklist /s fs01"), ("a.bat", "schtasks /query /s fs01"), ("a.bat", "taskkill /s fs01 /im x.exe"),
    ("a.bat", r"psexec -s \\fs01 cmd"), ("a.bat", "psexec @computers.txt cmd"), ("a.bat", "wmic /node:fs01 process list"),
    ("a.bat", "mstsc /v:fs01"), ("a.bat", "winrs -r:fs01 dir"), ("a.bat", "qwinsta /server:fs01"),
    ("a.ps1", "Get-Service -ComputerName fs01"), ("a.ps1", "Invoke-Command -Session $s -ScriptBlock { 1 }"),
    ("a.ps1", "Copy-Item a -ToSession $s -Destination b"),
])
def test_windows_remote_administration_forms(tmp_path, rel, line):
    _write(tmp_path, rel, line + "\n")
    assert (rel, 1, "script-network-command") in _found(tmp_path)


@pytest.mark.parametrize("rel, line", [("a.bat", "tasklist /s localhost"), ("a.ps1", "Get-Service -ComputerName localhost"),
                                       ("a.ps1", "Get-Help Invoke-Command"), ("a.bat", "tasklist /v")])
def test_windows_administration_on_this_machine_is_not_network(tmp_path, rel, line):
    _write(tmp_path, rel, line + "\n")
    assert not any(k == "script-network-command" for _, _, k in _found(tmp_path))


# ---------------------------------------------------------------- bare database clients, browser openers
@pytest.mark.parametrize("line, kind", [
    ("dotenv -f prod.env run -- psql", "script-network-command"),
    ("dotenvx run -- psql", "script-network-command"),
    ("psql", "loopback-call"),
])
def test_a_database_client_run_bare(tmp_path, line, kind):
    _write(tmp_path, "run.sh", line + "\n")
    assert ("run.sh", 1, kind) in _found(tmp_path)


def test_other_programs_run_bare_reach_nothing(tmp_path):
    _write(tmp_path, "run.sh", "#!/bin/sh\ndocker\nfor t in psql mysql; do echo $t; done\n")
    assert _found(tmp_path) == []


@pytest.mark.parametrize("rel, body, line", [
    ("a.py", "import subprocess\nsubprocess.run(['xdg-open', 'https://example.com/x'])\n", 2),
    ("a.py", "import subprocess\nsubprocess.Popen(['open', 'https://example.com/x'])\n", 2),
    ("a.bat", "cmd.exe /c start https://example.com\n", 1),
    ("b.bat", "start https://example.com\n", 1),
])
def test_an_address_opened_in_a_browser(tmp_path, rel, body, line):
    _write(tmp_path, rel, body)
    hit = [d for f, n, k, d in _report(tmp_path) if n == line]
    assert hit and "default browser" in hit[0]


def test_opening_a_local_file_or_address_is_quiet(tmp_path):
    _write(tmp_path, "a.py", "import subprocess\nsubprocess.run(['open', 'report.html'])\n"
                             "subprocess.run(['xdg-open', 'http://localhost:8000/'])\n")
    assert _found(tmp_path) == []


# ---------------------------------------------------------------- nested archives key_provenance cannot open
def _zip(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in members.items():
            z.writestr(k, v)
    return buf.getvalue()


def _encrypted_zip() -> bytes:
    raw = bytearray(_zip({"id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"}))
    raw[6] |= 1
    raw[raw.find(b"PK\x01\x02") + 8] |= 1
    return bytes(raw)


@pytest.mark.parametrize("inner", [_encrypted_zip(), b"7z\xbc\xaf\x27\x1c" + bytes(64)])
def test_an_unopenable_archive_inside_an_archive_is_listed(tmp_path, inner):
    _write(tmp_path, "outer.zip", _zip({"inner.bin": inner}))
    rep = key_provenance.scan_key_provenance(tmp_path)
    assert rep.verdict == "NOT-ANALYSED" and rep.not_scanned["archives_not_fully_read"] == ["outer.zip"]


def test_an_archive_with_readable_members_beside_an_unopenable_one(tmp_path):
    _write(tmp_path, "outer.zip", _zip({"inner.zip": _encrypted_zip(), "notes.txt": "nothing here\n"}))
    rep = key_provenance.scan_key_provenance(tmp_path)
    assert rep.verdict == "NOTHING-FOUND" and rep.not_scanned["archives_not_fully_read"] == ["outer.zip"]


# ---------------------------------------------------------------- wrappers, forwarding, environment
@pytest.mark.parametrize("line", ["runuser -u app -- git pull", "strace -f curl https://a.example.com",
                                  "torsocks curl https://a.example.com", "proxychains4 git pull",
                                  "microdnf install -y curl"])
def test_wrappers_that_run_what_follows(tmp_path, line):
    _write(tmp_path, "run.sh", "#!/bin/sh\n" + line + "\n")
    assert ("run.sh", 2, "script-network-command") in _found(tmp_path)


@pytest.mark.parametrize("line", ["ssh -L 8080:db.internal:5432 localhost", "ssh -W db.internal:22 localhost",
                                  "ssh -D 1080 localhost", "ssh -R 9000:localhost:9000 localhost"])
def test_ssh_forwarding_through_this_machine_is_not_loopback(tmp_path, line):
    _write(tmp_path, "run.sh", "#!/bin/sh\n" + line + "\n")
    found = _found(tmp_path)
    assert ("run.sh", 2, "script-network-command") in found and not any(k == "loopback-call" for _, _, k in found)


def test_the_environment_set_from_a_mapping(tmp_path):
    _write(tmp_path, "db.py", "import os, psycopg2\nfor k, v in cfg.items():\n    os.environ[k] = v\n"
                              "c = psycopg2.connect('postgresql:///db')\n")
    assert ("db.py", 4, "unresolved-call") in _found(tmp_path)


# ---------------------------------------------------------------- manifests, secrets, cbom, UNC, notebooks
def test_setup_cfg_dash_names(tmp_path):
    _write(tmp_path, "setup.cfg", "[metadata]\nname = x\n[options]\ninstall-requires =\n    requests==2.31.0\n")
    assert [c["purl"] if isinstance(c, dict) else c.purl for c in sbom.build_sbom(tmp_path).components] \
        == ["pkg:pypi/requests@2.31.0"]


def test_a_string_dependency_list_is_not_read(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "x"\ndependencies = "requests"\n')
    hit = [d for f, n, k, d in _report(tmp_path) if k == "unparseable-source"]
    assert hit and "NOT read" in hit[0]


@pytest.mark.parametrize("rel, body", [
    (".envrc", "export SECRET_KEY=8f3a9c2e7b1d4f6a0c5e9b2d7f1a3c8e\n"),
    ("docker-compose.yml", "services:\n  web:\n    environment:\n      - SECRET_KEY=8f3a9c2e7b1d4f6a0c5e9b2d7f1a3c8e\n"),
])
def test_secrets_in_envrc_and_yaml_lists(tmp_path, rel, body):
    _write(tmp_path, rel, body)
    assert any(f["kind"] == "literal-key" for f in key_provenance.scan_key_provenance(tmp_path).findings)


def test_an_argparse_option_name_is_not_an_algorithm(tmp_path):
    _write(tmp_path, "a.py", "import argparse\np = argparse.ArgumentParser()\np.add_argument('--rsa-key')\n")
    _write(tmp_path, "b.py", "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                             "k = rsa.generate_private_key(65537, 2048)\n")
    comps = cbom.build_cbom(tmp_path).components
    assert {c["file"] for c in comps} == {"b.py"}


@pytest.mark.parametrize("body, line", [
    ("SERVER = 'fs01'\nopen(f'\\\\\\\\{SERVER}\\\\share\\\\x.txt').read()\n", 2),
    ("import sqlite3\nsqlite3.connect(r'\\\\fs01\\share\\db.sqlite')\n", 2),
    ("import zipfile\nzipfile.ZipFile(r'\\\\fs01\\share\\x.zip')\n", 2),
])
def test_more_unc_forms(tmp_path, body, line):
    _write(tmp_path, "a.py", body)
    assert ("a.py", line, "network-call") in _found(tmp_path)


def test_local_paths_through_the_same_calls_are_quiet(tmp_path):
    _write(tmp_path, "a.py", "import sqlite3, zipfile\nname = 'x'\nsqlite3.connect('db.sqlite')\n"
                             "zipfile.ZipFile('x.zip')\nopen(f'{name}/data').read()\n")
    assert _found(tmp_path) == []


@pytest.mark.parametrize("notebook", [{"cells": [[1]]}, {"cells": [{"cell_type": "code", "source": 5}],
                                                          "nbformat": 4, "metadata": {}}])
def test_a_malformed_notebook_is_not_analysed(tmp_path, notebook):
    _write(tmp_path, "a.ipynb", json.dumps(notebook))
    assert ("a.ipynb", 0, "unparseable-source") in _found(tmp_path)


def test_localhost_with_a_trailing_dot_is_one_claim(tmp_path):
    _write(tmp_path, "a.js", "fetch('http://localhost./x');\n")
    assert [k for _, _, k in _found(tmp_path)] == ["loopback-call"]


def test_timestamp_names_a_missing_output_folder(tmp_path, capsys):
    from entrovouch import timestamp
    _write(tmp_path, "t/a.py", "x = 1\n")
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(audit(tmp_path / "t", label="t").__dict__, default=str), encoding="utf-8")
    code = timestamp.main(["request", str(rep), "--out", str(tmp_path / "nodir" / "x.tsq")])
    assert code == 2 and "does not exist" in capsys.readouterr().err


def test_a_folder_given_as_a_report(tmp_path, capsys):
    from entrovouch import sarif
    (tmp_path / "d").mkdir()
    assert sarif.main([str(tmp_path / "d")]) == 2 and "is a folder" in capsys.readouterr().err


def test_a_key_taller_than_a_signer_builds_quickly_is_refused(tmp_path):
    with pytest.raises(SignerError):
        MerkleSigner.create(tmp_path / "k.json", height=17)
    state = tmp_path / "s.json"
    state.write_text(json.dumps({"seed": "00" * 32, "height": 20, "next_index": 0}), encoding="utf-8")
    with pytest.raises(SignerError):
        MerkleSigner.load(state)


# ---------------------------------------------------------------- what the old sets showed
def test_make_runs_its_own_targets(tmp_path):
    _write(tmp_path, "Makefile", "release:\n\t$(MAKE) install\n\t$(MAKE) -C sub update\n")
    assert _found(tmp_path) == []


def test_branches_that_run_the_same_program_resolve(tmp_path):
    _write(tmp_path, "install", '#!/bin/sh -e\nif [ -z "$CI" ]; then\n    PIP="$VENV/bin/pip"\nelse\n    PIP="pip"\nfi\n'
                                '"$PIP" install -r requirements.txt\n')
    hit = [d for f, n, k, d in _report(tmp_path) if n == 7]
    assert hit and "pip install" in hit[0] and "NOT shown" not in hit[0]


@pytest.mark.parametrize("body", ["nav:\n  - Signing: signing.md\n  - Verifying: verify.md\n",
                                  "items:\n  - key: dulwich.porcelain.status_with_long_name\n"])
def test_a_yaml_list_of_mappings_is_not_an_assignment(tmp_path, body):
    _write(tmp_path, "mkdocs.yml", body)
    assert key_provenance.scan_key_provenance(tmp_path).findings == []


# ---------------------------------------------------------------- a detector's own pattern is not a key body
_ARMOUR_LINE = "-----BEGIN OPENSSH PRIVATE KEY-----"


def test_the_bare_start_of_a_key_body_after_armour_is_not_a_key(tmp_path):
    # a key detector's own source: armour named in a docstring, a body pattern written as a regular expression
    _write(tmp_path, "pem.py", '"""Names ' + _ARMOUR_LINE + ' and holds no key."""\nimport re\n'
           "BODY = re.compile(r'(?:M[IHC][A-Za-z0-9+/]{2,}|b3BlbnNzaC1r)')\n")
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings == []
    assert cbom.build_cbom(tmp_path, label="t").components == []


@pytest.mark.parametrize("body", ["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "MIIEowIBAAKCAQEAu1SU1LfV"])
def test_a_short_real_key_start_after_armour_is_still_a_key(tmp_path, body):
    _write(tmp_path, "k.txt", _ARMOUR_LINE + "\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n")
    assert [f["kind"] for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings] == ["key-file-in-tree"]


# ---------------------------------------------------------------- labels, tag keys and separators are not keys
@pytest.mark.parametrize("rel, body", [
    ("locale/ar.yaml", "PASSWORD: Passw0rdLabelValue99\napi_key: ShodanKey1234567\n"),
    ("src/i18n/en.json", '{"password": "Passw0rdLabelValue99", "secret_token": "TokenLabel123456"}\n')])
def test_a_translation_table_holds_labels_not_keys(tmp_path, rel, body):
    _write(tmp_path / "a", rel, body)
    _write(tmp_path / "b", rel.replace("locale/", "config/").replace("i18n/", "settings/"), body)
    assert key_provenance.scan_key_provenance(tmp_path / "a", label="t").findings == []
    assert {f["kind"] for f in key_provenance.scan_key_provenance(tmp_path / "b", label="t").findings} == {"literal-key"}


@pytest.mark.parametrize("rel, tag, material", [
    ("t.json", '{"Tags": [{"Key": "Application", "Value": "x"}]}\n', '{"Key": "8f14e45fceea167a5a36dedd4bea2543"}\n'),
    ("t.yaml", "Tags:\n  - Key: StackName\n    Value: x\n", "key: 8f14e45fceea167a5a36dedd4bea2543\n")])
def test_a_setting_named_only_key_needs_a_value_with_a_digit(tmp_path, rel, tag, material):
    _write(tmp_path / "tag", rel, tag)
    _write(tmp_path / "material", rel, material)
    assert key_provenance.scan_key_provenance(tmp_path / "tag", label="t").findings == []
    assert [f["kind"] for f in key_provenance.scan_key_provenance(tmp_path / "material", label="t").findings] == ["literal-key"]


def test_a_separator_named_token_is_not_a_secret_and_a_short_password_still_is(tmp_path):
    _write(tmp_path, "a.py", 'split_token = "..."\nTOKEN_SEPARATOR = ", "\npassword = "x1"\n')
    assert [(f["line"], f["kind"]) for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings] \
        == [(3, "literal-key")]


# ---------------------------------------------------------------- installs and imports that stay on this machine
def test_a_wheel_in_the_working_folder_installed_without_dependencies_stays_here(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM scratch\nRUN pip install --no-deps --no-cache-dir app-*.whl\n"
                                   "RUN pip install --no-deps requests\nRUN pip install app-*.whl\n")
    assert [n for _, n, k, _ in _report(tmp_path) if k == "script-network-command"] == [3, 4]


def test_npx_told_not_to_install_fetches_nothing(tmp_path):
    _write(tmp_path, "Makefile", "A = npx --no-install apidoc\n\nall:\n\t$(A) --x\n\tnpx --no-install apidoc\n\tnpx apidoc\n"
                                 "\tnpx --no-install-x apidoc\n")
    assert [n for _, n, k, _ in _report(tmp_path) if k == "script-network-command"] == [6, 7]


def test_a_folder_beside_a_test_does_not_hide_an_import(tmp_path):
    # `tests/trio/` holds tests and has no `__init__.py`: Python takes the installed `trio` before a namespace folder,
    # so the import is the library's. A top-level module of the same name is still the tree's own.
    _write(tmp_path, "tests/trio/test_a.py", "x = 1\n")
    _write(tmp_path, "tests/test_b.py", "import trio\n")
    _write(tmp_path, "src/eng/async_drivers/gevent.py", "x = 1\n")
    _write(tmp_path, "src/eng/async_drivers/gevent_uwsgi.py", "import gevent\n")
    _write(tmp_path, "motor.py", "x = 1\n")
    _write(tmp_path, "use.py", "import motor\n")
    found = sorted((f, n) for f, n, k, _ in _report(tmp_path) if k == "network-import")
    assert found == [("src/eng/async_drivers/gevent_uwsgi.py", 1), ("tests/test_b.py", 1)]


# ---------------------------------------------------------------- a field named `*_key` holding a lowercase word
@pytest.mark.parametrize("src, flagged", [
    ('provider_key = "mysql"\n', False), ('child_list_key = "content"\n', False), ('key = "pages"\n', False),
    ('aes_key = "mysecretvalue"\n', True), ('api_key = "mysecretvalue"\n', True),
    ('storage_key = "Xk9mQ2vL8pR4tN7w"\n', True), ('provider_key = "Xk9mQ2vL8pR4tN7w"\n', True),
    ('secret_key = "mysecretvalue"\n', True)])
def test_a_key_named_field_holding_a_lowercase_word_is_not_key_material(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    found = key_provenance.scan_key_provenance(tmp_path, label="t").findings
    assert bool(found) is flagged, (src, found)


# ---------------------------------------------------------------- type words, sentinels and placeholders are not tokens
@pytest.mark.parametrize("rel, body, flagged", [
    ("g.json", '{"token": "Refreshable"}\n', False), ("g.json", '{"token": "ghp8f14e45fceea167a5a36dedd4"}\n', True),
    ("g.yaml", "token: Refreshable\n", False), ("g.yaml", "token: ghp8f14e45fceea167a5a36dedd4\n", True)])
def test_a_setting_named_only_token_needs_a_value_with_a_digit(tmp_path, rel, body, flagged):
    _write(tmp_path, rel, body)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged


@pytest.mark.parametrize("src, flagged", [
    ("NO_TOKEN = 'NO-TOKEN\\r\\n'\ntoken_value = NO_TOKEN\n", False),
    ("AUTH_TOKEN = 'auth-token'\n", False),
    ("AUTH_TOKEN_PLACEHOLDER = 'AUTHORIZATION TOKEN'\n", False),
    ("AUTH_TOKEN = 'valid_unit_test_token'\n", True),
    ("SIGNING_KEY = 'NO-TOKEN'\ntoken_value = SIGNING_KEY\n", True)])
def test_a_constant_that_restates_its_own_name_is_a_sentinel_not_a_secret(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged


# ---------------------------------------------------------------- dataset ids, addresses and bracketed tokens
@pytest.mark.parametrize("rel, body, flagged", [
    ("run.yaml", "eval_key: dl19-passage\n", False), ("run.yaml", "eval_key: msmarco-v1-passage.dev\n", False),
    ("run.yaml", "eval_key: Xk9mQ2vL8pR4tN7wZ3\n", True), ("run.yaml", "aes_key: dl19passagevalue\n", True),
    ("run.json", '{"eval_key": "dl19-passage"}\n', False), ("run.json", '{"eval_key": "Xk9mQ2vL8pR4tN7wZ3"}\n', True)])
def test_a_key_named_setting_holding_an_identifier_is_not_key_material(tmp_path, rel, body, flagged):
    _write(tmp_path, rel, body)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged


@pytest.mark.parametrize("src, flagged", [
    ('ID_TOKEN_ISSUER = "https://idp.example.com"\n', False), ('ENT_START_TOKEN = "[START_ENT]"\n', False),
    ('API_TOKEN = "https://user:pw12345678@host.example/x"\n', True), ('API_TOKEN = "[abcdef12345678]"\n', True)])
def test_an_address_or_a_bracketed_token_is_not_a_secret(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged


@pytest.mark.parametrize("rel, body", [
    ("v.json", '{"key" : "bedcfb5a011ebc84600fcb296c15af0d"}\n'), ("v.yaml", "key: bedcfb5a011ebc84600fcb296c15af0d\n"),
    ("v.yaml", "storage_key: bedcfb5a011ebc84600fcb296c15af0d\n"), ("v.py", 'WEBHOOK_KEY = "abc123webhookkey"\n'),
    ("v.py", 'provider_key = "deadbeefcafe1234"\n')])
def test_hex_and_tokens_are_not_taken_for_words(tmp_path, rel, body):
    # a value with digits in it and no separator is hex or a token, whatever the name beside it
    _write(tmp_path, rel, body)
    assert key_provenance.scan_key_provenance(tmp_path, label="t").findings


# ---------------------------------------------------------------- one instruction with comment lines in it; redis-cli's words
def test_a_comment_line_inside_a_continued_dockerfile_instruction_does_not_end_it(tmp_path):
    _write(tmp_path, "Dockerfile", "FROM scratch\nRUN apt-get install -y x \\\n    # a comment\n    && echo one \\\n"
                                   "    # another\n    && pip3 install y \\\n    && echo two\n")
    # one instruction, one finding, reported at the line the instruction opens on
    assert [(n, k) for _, n, k, _ in _report(tmp_path) if k.startswith("script")] == [(2, "script-network-command")]


@pytest.mark.parametrize("line, kind", [
    ('t=`echo | redis-cli type "$key"`', "loopback-call"), ('redis-cli get "$KEY"', "loopback-call"),
    ('redis-cli -a "$PW" get k', "loopback-call"), ('redis-cli -h "$HOST" get k', "script-network-command"),
    ('redis-cli -h cache.example.com get k', "script-network-command")])
def test_a_variable_word_after_redis_cli_is_its_command_not_its_host(tmp_path, line, kind):
    _write(tmp_path, "x.sh", line + "\n")
    assert [k for _, _, k, _ in _report(tmp_path)] == [kind]


# ---------------------------------------------------------------- a step's `with:` inputs are not commands
def test_a_step_input_that_names_programs_is_not_a_command(tmp_path):
    _write(tmp_path, ".github/workflows/t.yml",
           "jobs:\n  x:\n    steps:\n      - uses: a/b@v1\n        with:\n          packages: curl git python39\n"
           "          server: https://example.com/x\n      - uses: a/c@v1\n        with:\n          run: curl git\n"
           "      - run: curl git\n")
    got = [(n, k) for _, n, k, _ in _report(tmp_path)]
    assert (6, "script-network-command") not in got                     # the input list
    assert (7, "external-url") in got                                    # an address in an input is still a finding
    assert (10, "script-network-command") in got                         # `run` among the inputs is a command key
    assert (11, "script-network-command") in got                         # and a step's own `run`


def test_the_lines_of_a_block_scalar_and_an_address_in_a_step_input_stay_read(tmp_path):
    _write(tmp_path, ".github/workflows/t.yml",
           "jobs:\n  x:\n    uses: o/r/.github/workflows/t.yml@main\n    with:\n      names: |\n"
           "        lint:tox -e lint\n        docs\n      note: see\n        https://example.com/a\n"
           "      tool: tox\n")
    got = [(n, k) for _, n, k, _ in _report(tmp_path)]
    assert (6, "script-network-command") in got          # a line of a block scalar is not an input value
    assert (9, "external-url") in got                    # an address on a continuation line is still reported
    assert (10, "script-network-command") not in got     # `tool: tox` is an input naming a program


# ---------------------------------------------------------------- an API's field names written as constants
@pytest.mark.parametrize("src, flagged", [
    ("KEY_SCHEMA = 'KeySchema'\n", False), ("CLIENT_REQUEST_TOKEN = 'ClientRequestToken'\n", False),
    ("TABLE_KEY = 'Table'\n", False), ("watch_key = 'shuffleId'\n", False), ("exclusive_start_key = 'FooForum'\n", False),
    ("AUTH_TOKEN = 'authToken9'\n", True), ("SIGNING_KEY = 'KeySchema'\n", True), ("api_key = 'fooForum'\n", True),
    ("storage_key = 'XkmQvLpRtNwZ'\n", True)])
def test_a_field_name_written_as_a_constant_is_not_a_secret(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


# ---------------------------------------------------------------- fixtures, paths, masks and a parameter named exec
# An invented token in the shape of a Databricks API token, assembled at run time so this file does not hold one
# (GitHub's push protection blocks a token of that shape, invented or not).
_FAKE_DATABRICKS_TOKEN = "dapi" + "8f14e45fceea167a5a36dedd4bea2543"

@pytest.mark.parametrize("src, flagged", [
    ('seed_csv = """id,msg\n1,hello\n2,there\n"""\n', False),
    ('primary_key_constraint_sql = """\nalter table t\nadd primary key (id)\n"""\n', False),
    ('server_ssl_key = "config/ssl/domain/server.key"\n', False), ('hash_key = "varbinary(16)"\n', False),
    ('DBT_TAG_KEY = "@@dbt_materialized"\n', False), ('api_token = "dapiXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n', False),
    ('api_token = "$(curl -s https://idp.example.com/token)"\n', False),
    ('api_token = "' + _FAKE_DATABRICKS_TOKEN + '"\n', True), ('hash_key = "0x1A5F2C3AED089D414CDA644D83608EAD"\n', True)])
def test_text_paths_masks_and_substitutions_are_not_credentials(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


def test_a_value_that_is_a_command_substitution_in_a_pipeline_is_not_a_literal_token(tmp_path):
    _write(tmp_path / "a", "action.yml", "runs:\n  steps:\n    - run: |\n        ID_TOKEN=$(curl -sLS https://x.example/t)\n")
    _write(tmp_path / "b", "ci.yml", "env:\n  API_TOKEN: " + _FAKE_DATABRICKS_TOKEN + "\n")
    assert key_provenance.scan_key_provenance(tmp_path / "a", label="t").findings == []
    assert [f["kind"] for f in key_provenance.scan_key_provenance(tmp_path / "b", label="t").findings] == ["literal-key"]


def test_a_parameter_named_exec_is_not_the_builtin(tmp_path):
    _write(tmp_path, "a.py", "def run(exec, default):\n    return exec()\n\n\ndef bad(code):\n    return eval(code)\n")
    got = [(n, k) for _, n, k, _ in _report(tmp_path)]
    assert (2, "method-named-exec") in got and (2, "dynamic-exec") not in got
    assert (6, "dynamic-exec") in got                    # the builtin eval beside it is still reported


def test_a_parameter_named_exec_in_another_function_does_not_hide_the_builtin(tmp_path):
    _write(tmp_path, "a.py", "def f():\n    exec('x = 1')\n\n\nasync def g(arg, exec=False):\n    return exec\n\n\n"
                             "def outer(exec):\n    def inner():\n        return exec('y')\n    return inner\n")
    got = {(n, k) for _, n, k, _ in _report(tmp_path)}
    assert (2, "dynamic-exec") in got and (11, "method-named-exec") in got and (11, "dynamic-exec") not in got


def test_a_module_level_name_exec_hides_the_builtin_everywhere_in_the_file(tmp_path):
    _write(tmp_path, "a.py", "exec = print\n\n\ndef f():\n    exec('x')\n")
    got = {(n, k) for _, n, k, _ in _report(tmp_path)}
    assert (5, "method-named-exec") in got and (5, "dynamic-exec") not in got


@pytest.mark.parametrize("src, flagged", [
    ('DATASTREAM_SALT = "DataStream-Salt"\n', False), ('EVENTS_SALT = "Events-Salt"\n', False),
    ('OTHER_SALT = "Other-Thing"\n', True)])
def test_a_protocol_label_that_spells_its_own_name_is_not_a_secret(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


_BODY64 = "MIIG5AIBAAKCAYEAuljmNv5LsBRvH2DM3TrCSpR5v540tOMI4qh+IxOfxjROoIDZ"


@pytest.mark.parametrize("src", [
    'root_key_der = base64.b64decode(\n    """\n' + _BODY64 + "\n" + _BODY64 + '\njsvxvqVnkIhWeuP9GIb6X=="\n""")\n',
    'private_key_headerless = """\n' + _BODY64 + "\n" + _BODY64 + '\nZm9v\n"""\n',
    'clear_key = """\n308201ab020100025a00b94a7f7075ab9e79e8196f47be707781e80dd965cf16\n0c951a870b71783b6aaabbd550c0e65e5a3dfe15b8620009f6d7e5efec42a3f0\n6fe2\n"""\n'])
def test_a_key_body_written_on_several_lines_is_still_a_key(tmp_path, src):
    _write(tmp_path, "a.py", "import base64\n" + src)
    assert [f["kind"] for f in key_provenance.scan_key_provenance(tmp_path, label="t").findings] == ["literal-key"], src


@pytest.mark.parametrize("src, flagged", [
    ('SECRET_KEY = "secret"\n', True), ('MYSQL_PASSWORD = "mysql"\n', True), ('ADMIN_PASSWORD = "admin"\n', True),
    ('API_KEY = "Api"\n', True), ('TABLE_KEY = "Table"\n', False), ('ID_KEY = "Id"\n', False)])
def test_a_weak_credential_that_repeats_its_name_is_still_a_credential(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


@pytest.mark.parametrize("src, flagged", [
    ("{'PVE_PASSWORD': 'password', 'PVE_TOKEN_VALUE': 'token_value'}\n", False),
    ("{'DB_API_KEY': 'api_key', 'DB_CLIENT_SECRET': 'client_secret'}\n", False),
    ("{'DB_PASSWORD': 'hunter2hunter2'}\n", True), ("{'DB_PASSWORD': 'passwords'}\n", True),
    ("{'DB_PASSWORD': 'Password'}\n", True), ("{'PVE_TOKEN_VALUE': 'my_token_value'}\n", True)])
def test_a_map_from_environment_names_to_field_names_is_not_a_secret(tmp_path, src, flagged):
    _write(tmp_path, "a.py", "x = " + src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


@pytest.mark.parametrize("rel, src, flagged", [
    ("custom_components/x/strings.json", '{"config": {"step": {"user": {"data": {"password": "Password"}}}}}\n', False),
    ("app/_locales/en/messages.json", '{"password": {"message": "Password"}}\n', False),
    ("app/config.json", '{"password": "Password1234"}\n', True)])
def test_the_file_a_framework_keeps_its_interface_text_in_is_a_label_table(tmp_path, rel, src, flagged):
    _write(tmp_path, rel, src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, rel


@pytest.mark.parametrize("src, flagged", [
    ("TaskLockParams(redis_key='_SampleDummyTask_7e857f231830ca0fd6cf829d99f43961-run')\n", False),
    ("lock_key = 'resource-4f9a1c2e7b'\n", False), ("s3_secret_access_key = 'somesecret'\n", True),
    ("S3_SECRET_KEY = 'rustfs12345'\n", True), ("BLOB_KEY = b'657f48f84c437cc1'\n", True),
    ("hash_key = '7e857f231830ca0fd6cf829d99f43961'\n", True), ("stream_key = '7e857f231830ca0fd6cf829d99f43961'\n", True),
    ("api_key = '7e857f231830ca0fd6cf829d99f43961'\n", True)])
def test_the_name_of_an_entry_in_a_store_is_not_a_secret(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


@pytest.mark.parametrize("src, flagged", [
    ('password = ""\n', False), ("cloud_password = ''\n", False), ('split_token = " | "\n', False),
    ('def f(password_cloud="", *, super_secret_key=b""):\n    return password_cloud\n', False),
    ('password = "x"\n', True), ('def f(password="hunter2hunter2"):\n    return password\n', True),
    ('key = b"\\x00" * 32\n', True), ('seed = b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"\n', True),
    ('def f(*, signing_key="a1b2"):\n    return signing_key\n', True)])
def test_an_empty_value_is_a_variable_not_yet_given_its_value(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


@pytest.mark.parametrize("src, flagged", [
    ("jp_key = 'a.\"k.c\".'\n", False), ("jp_key = 'a[0].b[1]'\n", False), ("jp_key = '.a'\n", False),
    ("jp_key = 'a[x]'\n", False), ("jp_key = \"a.'k.c'\"\n", False),
    ("MYSQL_PASSWORD = 'test]password'\n", True), ("jp_key = 'a['\n", False), ("jp_key = 'a[]]'\n", False),
    ("api_key = 'a1b2c3d4e5f6a7b8c9d0e1f2'\n", True), ("api_key = 'eyJhbGciOi.eyJzdWIiOi.SflKxw'\n", True),
    ("x = {'hmac_digest': 'sha256=9ec8272937a36a4b4427d4f9ab7b0425856c5ef5d7e1b496f864aaf99c1910ca'}\n", False),
    ("x = {'hmac_key': '9ec8272937a36a4b4427d4f9ab7b0425856c5ef5d7e1b496f864aaf99c1910ca'}\n", True),
    ("token_endpoint = '/users/me/awx-tokens/'\n", False), ("def f(*, seed='0'):\n    return seed\n", False),
    ("def f(*, seed='7e857f231830ca0fd6'):\n    return seed\n", True)])
def test_a_path_expression_a_digest_and_a_seed_number_are_not_key_material(tmp_path, src, flagged):
    _write(tmp_path, "a.py", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src


@pytest.mark.parametrize("src, flagged", [
    ("input:\n  secret_path: secret/myapp\n  secret_key: \"password\"\n", False),
    ("input:\n  secret_key: \"username\"\n", False),
    ("environment:\n  RUSTFS_SECRET_KEY: password\n", True),
    ("db:\n  password: \"hunter2hunter2\"\n", True), ("db:\n  secret_key: \"hunter2hunter2\"\n", True)])
def test_a_vault_input_naming_the_field_to_read_is_a_label(tmp_path, src, flagged):
    _write(tmp_path, "tasks/main.yml", src)
    assert bool(key_provenance.scan_key_provenance(tmp_path, label="t").findings) is flagged, src

"""key_provenance recall: one credential planted per tree, in forms people write, and which of them it reports.

The README's `key_provenance` recall row, pinned both ways. Forty trees, each holding one credential and nothing
else that looks like one. 33 are in files the tool reads (Python, `.env` and `.envrc`, configuration files, key
files, notebooks); 7 are in files it does not read for literal keys (JavaScript, a Dockerfile, a shell script, Java,
Terraform, and a literal key inside a zip and inside a tar.gz, where only private-key armour is searched).

We wrote these forms knowing how the tool works, so code written by someone else may do worse. If a later build
reports one of the misses, this fails on purpose: the README row and this set change together, and a fixed form
becomes tuning data, so a fresh set is needed for the figure.

Values shaped like a provider's tokens are assembled at run time, so the source holds no string a secret scanner
would mistake for a live credential.
"""
from __future__ import annotations

import base64
import io
import json
import random
import tarfile
import zipfile
from pathlib import Path

from entrovouch.key_provenance import scan_key_provenance

_AL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _forms() -> tuple[dict[str, str], dict[str, tuple[str, str, bytes]]]:
    rng = random.Random(20261010)

    def r(n, al=_AL):
        return "".join(rng.choice(al) for _ in range(n))

    def b64(n):
        return base64.b64encode(bytes(rng.randrange(256) for _ in range(n))).decode()

    def pem(kind):
        body = b64(600)
        return (f"-----BEGIN {kind}-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
                + f"\n-----END {kind}-----\n")

    akia = "AK" + "IA" + r(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    ghp = "gh" + "p_" + r(36)
    skl = "sk" + "_live_" + r(24)
    oai = "sk" + "-" + r(48)
    files = {
        "py_module_const/app.py": f'API_KEY = "{r(32)}"\n',
        "py_settings/settings.py": f'DEBUG = False\nSECRET_KEY = "{r(50)}"\n',
        "py_boto_kwargs/s3.py": f'import boto3\nc = boto3.client("s3", aws_access_key_id="{akia}", '
                                f'aws_secret_access_key="{r(40)}")\n',
        "py_func_local/db.py": f'def connect():\n    password = "{r(20)}"\n    return password\n',
        "py_hmac_positional/sign.py": f'import hmac, hashlib\ndef sign(m):\n'
                                      f'    return hmac.new(b"{r(32)}", m, hashlib.sha256).hexdigest()\n',
        "py_jwt_positional/auth.py": f'import jwt\ndef make(p):\n    return jwt.encode(p, "{r(32)}", algorithm="HS256")\n',
        "py_environ_default/pay.py": f'import os\nos.environ.setdefault("STRIPE_SECRET_KEY", "{skl}")\n',
        "py_dict_literal/cfg.py": f'CONFIG = {{"api_token": "{r(32)}", "region": "eu"}}\n',
        "py_getenv_default/db.py": f'import os\nDB_PASSWORD = os.getenv("DB_PASSWORD", "{r(20)}")\n',
        "py_default_arg/client.py": f'def connect(host, token="{r(32)}"):\n    return host, token\n',
        "py_bearer_header/api.py": f'HEADERS = {{"Authorization": "Bearer {r(40)}"}}\n',
        "py_class_attr/conf.py": f'class Settings:\n    secret = "{r(32)}"\n',
        "py_b64decode/keys.py": f'import base64\nKEY = base64.b64decode("{b64(32)}")\n',
        "py_fernet/crypt.py": "from cryptography.fernet import Fernet\n"
                              f'F = Fernet(b"{b64(32).replace("+", "-").replace("/", "_")}")\n',
        "py_auth_tuple/fetch.py": f'import requests\ndef get(u):\n    return requests.get(u, auth=("admin", "{r(20)}"))\n',
        "py_pem_string/tls.py": f'KEY = """{pem("RSA PRIVATE KEY")}"""\n',
        "py_conn_url/settings.py": f'DATABASE_URL = "postgresql://app:{r(20)}@db.internal:5432/app"\n',
        "env_api_key/.env": f"OPENAI_API_KEY={oai}\n",
        "env_password/.env": f"DATABASE_PASSWORD={r(20)}\n",
        "envrc_export/.envrc": f"export GITHUB_TOKEN={ghp}\n",
        "yaml_api_key/config.yaml": f"service:\n  api_key: {r(32)}\n",
        "json_client_secret/config.json": json.dumps({"client_id": "app", "client_secret": r(32)}, indent=2) + "\n",
        "toml_secret/settings.toml": f'[app]\nsecret_key = "{r(32)}"\n',
        "ini_password/app.ini": f"[db]\nuser = app\npassword = {r(20)}\n",
        "properties_password/application.properties": f"spring.datasource.password={r(20)}\n",
        "compose_env/docker-compose.yml": f"services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD={r(20)}\n",
        "ci_env/.github/workflows/ci.yml": f"on: push\nenv:\n  API_TOKEN: {r(32)}\njobs: {{}}\n",
        "k8s_secret/secret.yaml": f"apiVersion: v1\nkind: Secret\ndata:\n  password: {b64(24)}\n",
        "keyfile_rsa/id_rsa": pem("RSA PRIVATE KEY"),
        "keyfile_ec/server.key": pem("EC PRIVATE KEY"),
        "keyfile_openssh/deploy_key": pem("OPENSSH PRIVATE KEY"),
        "service_account/sa.json": json.dumps({"type": "service_account", "private_key": pem("PRIVATE KEY")}) + "\n",
        "notebook_cell/analysis.ipynb": json.dumps({
            "cells": [{"cell_type": "code", "metadata": {}, "outputs": [], "execution_count": 1,
                       "source": [f'api_key = "{r(32)}"\n']}],
            "metadata": {}, "nbformat": 4, "nbformat_minor": 5}),
        "js_const/app.js": f'const apiKey = "{r(32)}";\n',
        "dockerfile_env/Dockerfile": f"FROM python:3.12\nENV API_KEY={r(32)}\n",
        "shell_export/deploy.sh": f"#!/bin/sh\nexport AWS_SECRET_ACCESS_KEY={r(40)}\n",
        "java_field/App.java": f'class App {{ static final String PASSWORD = "{r(20)}"; }}\n',
        "terraform/main.tf": f'resource "x" "y" {{\n  password = "{r(20)}"\n}}\n',
    }
    archives = {
        "archive_zip": ("bundle.zip", "app/.env", f"API_SECRET={r(32)}\n".encode()),
        "archive_targz": ("release.tar.gz", "pkg/settings.py", f'SECRET_KEY = "{r(50)}"\n'.encode()),
    }
    return files, archives


# The twelve forms the tool does not report. Five are in files it reads; the connection URL is a documented limit.
MISSED_IN_FILES_READ = {"py_auth_tuple", "py_b64decode", "py_conn_url", "py_default_arg", "properties_password"}
MISSED_FILES_NOT_READ = {"js_const", "dockerfile_env", "shell_export", "java_field", "terraform",
                         "archive_zip", "archive_targz"}


def test_key_provenance_recall_is_what_the_readme_says(tmp_path):
    files, archives = _forms()
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text.encode("utf-8"))
    for case, (name, member, data) in archives.items():
        (tmp_path / case).mkdir()
        if name.endswith(".zip"):
            with zipfile.ZipFile(tmp_path / case / name, "w") as z:
                z.writestr(member, data)
        else:
            with tarfile.open(tmp_path / case / name, "w:gz") as t:
                info = tarfile.TarInfo(member)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    cases = sorted({rel.split("/")[0] for rel in files} | set(archives))
    assert len(cases) == 40

    missed = {c for c in cases if not scan_key_provenance(tmp_path / c, label=c).findings}
    assert missed == MISSED_IN_FILES_READ | MISSED_FILES_NOT_READ, (
        f"key_provenance recall changed: missed now {sorted(missed)}; update the README's recall line, and treat a "
        "form that is now reported as tuning data")
    assert len(cases) - len(missed) == 28

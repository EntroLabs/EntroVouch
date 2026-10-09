#!/usr/bin/env python3
"""
ENTROVOUCH no-egress auditor.

Reports, mechanically and repeatably, the network capability a codebase contains:
network-capable imports and calls, shell and process spawns that reach a network
binary, dynamic code loading, external references in markup, declared network
dependencies, and the regions of the tree it could not read. The report carries a
reproducible findings digest and can be signed.

Pure standard library. The auditor performs no network operation itself, which is
a property you can check by running it on its own source.

SCOPE, which travels with every report: this is static analysis of a
Turing-complete language. It underapproximates. It names the network surface it
knows and is silent about the rest, so CLEAN means nothing came to its attention,
never that nothing is there. Files and directories it does not read are listed in
the report under `not_scanned`.

Usage:
    python -m entrovouch.no_egress_auditor <target_dir> [--json out.json] [--md out.md]
Exit code 0 = CLEAN. 1 = FINDINGS. 2 = could not run, or nothing was scanned.
"""
from __future__ import annotations

import argparse
import ast
import base64
import bisect
import contextvars
import functools
import warnings
import hashlib
import hmac
import os
import posixpath
import json
import re
import sys
import textwrap
import tokenize
import unicodedata
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from ._cli import missing_folder, run, write_text
from ._stdlib_names import STDLIB_MODULE_NAMES
from ._version import __version__
from .signer import (ALGORITHM, UNSIGNED, MerkleSigner, SignerError,
                     verify_signature)
from .manifests import SETUP_PY_UNPARSEABLE, SKIP_DIRS, collect_manifests, is_manifest_path, is_skipped_dir, tree_files
from . import _reads

# ---------------------------------------------------------------------------
# Policy: the names this tool knows. Detection is list-based, and the list is
# published so a reader can check it against their own dependencies.
# ---------------------------------------------------------------------------
FORBIDDEN_IMPORT_MODULES = {
    "urllib", "urllib.request", "requests", "httpx",
    "aiohttp", "http.client", "httplib", "socket", "ftplib", "smtplib",
    "telnetlib", "poplib", "imaplib", "websocket", "websockets",
    "socks", "sockshandler",                         # PySocks: sockets through a SOCKS proxy
    "grpc", "paramiko", "pycurl",
    # Telemetry / analytics / APM: egress by definition, and the category a
    # "no telemetry" claim is actually about.
    "sentry_sdk", "posthog", "mixpanel", "analytics", "segment",
    "datadog", "ddtrace", "newrelic", "bugsnag", "rollbar",
    "opentelemetry", "elasticapm", "amplitude", "scout_apm", "statsd",
    # Cloud SDKs: a client object is a network client whether or not it is called
    "boto3", "botocore", "google.cloud", "googleapiclient", "azure",
    "firebase_admin", "supabase",
    # HTTP transports: the libraries `requests` and `httpx` are built on.
    "urllib3", "httpcore",
    # The standard library's own network surface.
    "xmlrpc.client", "xmlrpc", "webbrowser", "asyncore", "asynchat",
    "multiprocessing.connection",
    # Message buses, brokers and database drivers. "Where does my data go" is
    # the question this tool answers, and a database client is an answer to it.
    "zmq", "pyzmq", "pika", "kafka", "confluent_kafka", "redis", "pymongo",
    "psycopg2", "psycopg", "mysql", "MySQLdb", "cassandra", "elasticsearch",
    "clickhouse_driver", "paho", "stomp", "nats",
    # Async network frameworks.
    "tornado", "twisted", "gevent", "eventlet", "trio",
    # Hosted-model API clients: egress is their entire purpose.
    "openai", "anthropic", "cohere", "replicate", "together", "groq", "mistralai",
    # Model/artifact hubs and experiment trackers: these fetch or upload on
    # default code paths, which is precisely the non-obvious egress a "no
    # telemetry" claim is about.
    "huggingface_hub", "transformers", "datasets", "timm",
    "wandb", "mlflow", "comet_ml", "neptune", "clearml",
    # ------------------------------------------------------------------
    # Grouped by category, because a list that has "HTTP clients" and no "SaaS
    # SDKs" is complete in one dimension and absent in another.
    #
    # SELECTION RULE: a name goes in only if opening a network connection is
    # what the package is FOR. Ambiguous cases are left out: `sqlalchemy` and
    # `pyodbc` are routinely pointed at a local file or driver, and a false
    # positive costs more than the finding is worth.
    # ------------------------------------------------------------------
    # More HTTP clients and fetchers
    "httplib2", "requests_oauthlib", "requests_html", "mechanize", "httpx_ws",
    # Object storage / remote filesystems
    "minio", "s3fs", "gcsfs", "adlfs", "smart_open", "dropbox",
    # SaaS API clients -- egress is the entire purpose
    "stripe", "twilio", "sendgrid", "slack_sdk", "slack", "github3", "github",
    "gitlab", "jira", "atlassian", "notion_client", "praw", "tweepy",
    "discord", "telegram",
    # Async database drivers and infrastructure clients, beside their sync equivalents above.
    "asyncpg", "aiomysql", "motor", "aioredis", "etcd3", "consul", "hvac",
    "pyodbc", "pymssql", "cx_Oracle", "oracledb", "asyncssh",
    "kubernetes", "docker", "neo4j", "influxdb", "influxdb_client", "couchdb",
    # Mail and identity
    "aiosmtplib", "imapclient", "exchangelib", "O365", "msal",
    # Brokers and task queues -- a broker URL is a network address
    "aiokafka", "kombu", "celery", "nsq",
    # Remote execution and file transfer
    "fabric", "netmiko", "napalm", "pysftp", "scp", "ftputil", "tftpy",
    # Directory, name and wire protocols
    "ldap3", "ldaptor", "dns", "aiodns", "thrift", "zeep", "suds", "gql",
    "sseclient", "socketio", "engineio", "autobahn", "pyngrok",
    "scapy", "impacket", "opcua", "asyncua",
    # Browser automation and crawlers: these fetch URLs by construction
    "selenium", "playwright", "scrapy", "feedparser",
    # Metrics exporters -- same category as statsd/datadog above
    "prometheus_client",
    # Hosted-model and agent frameworks whose default paths call a provider, and
    # local model servers reached over HTTP
    "langchain_openai", "langchain_anthropic", "langchain_google_genai", "langchain_community",
    "langchain_core", "litellm", "google.generativeai", "google.genai", "vertexai", "ollama",
    "gradio", "gradio_client", "streamlit", "modal", "runpod",
    # Dataset, model and artifact fetchers
    "tensorflow_datasets", "tensorflow_hub", "torch.hub", "kaggle", "gdown", "nltk.downloader",
    "spacy.cli", "fsspec", "requests_cache", "pyppeteer", "wget",
    # Vector and search services reached over the network
    # (held-out names used to measure tier A-prime are deliberately NOT added here)
    "pinecone", "weaviate", "meilisearch", "typesense",
    # More database and protocol clients
    "pymysql", "snowflake", "smbclient", "pysnmp", "zeroconf", "win32inet", "win32wnet",
    "aiohttp_sse", "httpx_sse", "yfinance", "pandas_datareader", "alpha_vantage", "ccxt",
    # The standard library's own network surface, continued
    # (`ensurepip` is not here: it installs the pip bundled with Python, offline; `RobotFileParser.read()` fetches)
    "_socket", "pip", "nntplib", "antigravity", "multiprocessing.managers", "urllib.robotparser",
    # Python 2 spellings, still met in code that supports both
    "urllib2", "xmlrpclib",
}

# Protocol libraries: they encode and decode a wire protocol and cannot open a socket
# themselves. Importing one is evidence a network stack is present, not a connection.
PROTOCOL_LIBRARIES = {"h11", "h2", "hpack", "hyperframe", "wsproto"}

# Server frameworks. Importing one is evidence that the package serves requests,
# not a bound socket at that line; reported as a server dependency.
INBOUND_FRAMEWORKS = {
    "flask", "fastapi", "django", "bottle", "falcon", "sanic", "starlette", "quart",
    "cherrypy", "pyramid", "litestar", "blacksheep", "robyn", "aiohttp.web",
}

# The standard library's logging handlers that send every record over the network.
NETWORK_LOG_HANDLERS = {"HTTPHandler", "SocketHandler", "DatagramHandler", "SMTPHandler", "SysLogHandler"}
_CLASS_KEYS = {"class", "()", "handler_class", "BACKEND", "backend", "class_name", "cls"}
_CLASS_LIST_NAME_RE = re.compile(r"(?:^|_)(?:MIDDLEWARE|MIDDLEWARE_CLASSES|INSTALLED_APPS|EXTENSIONS)$")
_DOTTED_CLASS_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")
_LOG_HANDLER_NAME_RE = re.compile(r"(?:ext://)?(?:logging\.)?handlers\.(" + "|".join(sorted(NETWORK_LOG_HANDLERS)) + r")")

# Code loaders: what they run is decided by data, not by the source in front of the
# auditor. Reported as a boundary of the analysis, like exec and eval.
LOADER_CALLS = {
    ("pickle", "loads"): "unpickling runs the constructors the data names",
    ("pickle", "load"): "unpickling runs the constructors the data names",
    ("pickle", "Unpickler"): "unpickling runs the constructors the data names",
    ("marshal", "loads"): "loads compiled code objects from bytes",
    ("marshal", "load"): "loads compiled code objects from bytes",
    ("runpy", "run_path"): "runs a file as Python whatever its name",
    ("runpy", "run_module"): "runs a module by name",
    ("zipimport", "zipimporter"): "imports Python from an archive",
    ("code", "InteractiveInterpreter"): "runs source handed to it",
    ("code", "InteractiveConsole"): "runs source handed to it",
    ("code", "interact"): "runs source handed to it",
    (None, "spec_from_file_location"): "loads Python from a file with any extension",
    (None, "exec_module"): "executes a module loaded from a spec",
}
# Foreign-function interfaces: a native library does whatever it does.
FFI_CALLS = {("ctypes", "CDLL"), ("ctypes", "WinDLL"), ("ctypes", "OleDLL"), ("ctypes", "PyDLL"),
             ("ctypes", "LoadLibrary"), (None, "dlopen"), ("_ctypes", "LoadLibrary"), ("_ctypes", "dlopen"),
             ("ctypes", "LibraryLoader")}
FFI_ATTR_ROOTS = {"cdll", "windll", "oledll", "pydll"}

# Callables that fetch when handed a URL. Only a URL LITERAL in the call is reported.
URL_SINK_NAMES = {
    "read_csv", "read_json", "read_parquet", "read_excel", "read_html", "read_table", "read_feather",
    "read_pickle", "read_xml", "open", "urlopen", "Request", "urlretrieve", "download", "download_file",
    "download_url_to_file", "retrieve", "fetch", "load", "imread", "open_url", "VideoCapture", "get", "post",
    "put", "patch", "delete", "head", "request", "load_dataset", "from_url", "read_text", "read_bytes",
    "read_orc", "clone_from", "get_file", "csv", "parquet", "orc", "cp", "mv", "read_stata", "read_sas", "read_spss",
    "read_fwf", "ExcelWriter",
} | {"to_csv", "to_json", "to_parquet", "to_excel", "to_feather", "to_pickle", "to_orc", "to_xml"}

# Keywords that name where a call reads from or sends to (an address given by keyword is read as a positional one is)
_ADDRESS_KEYWORDS = {"url", "uri", "filepath_or_buffer", "path_or_buf", "io"}
# keywords that are an address for one callee only (`get_file(origin=...)`; elsewhere `origin=` is a CORS header)
_ADDRESS_KEYWORDS_BY_CALL = {"get_file": {"origin"}, **{
    # pandas' readers and writers name their file `path`, `path_or_buffer` or `excel_writer`
    name: {"path", "path_or_buffer", "excel_writer"} for name in (
        "read_stata", "read_sas", "read_fwf", "ExcelWriter", "read_parquet", "read_feather", "read_orc", "read_pickle", "read_excel", "read_xml", "read_json", "read_table",
        "to_csv", "to_json", "to_parquet", "to_excel", "to_feather", "to_pickle", "to_orc", "to_xml")}}
# Names a mapping usually has. `get` on one of them looks a value up; it fetches nothing.
MAPPING_RECEIVERS = {"environ", "env", "config", "cfg", "conf", "settings", "defaults", "options", "opts", "kwargs",
                     "params", "headers", "data", "cache", "mapping", "registry", "meta", "metadata", "attrs"}
# The usual names of HTTP test doubles: requests_mock, responses, httpretty, respx, aioresponses, httpx_mock.
_TEST_DOUBLE_NAME_RE = re.compile(r"mock|^responses$|^rsps$|^httpretty$|^respx$|^aioresponses$", re.IGNORECASE)
# The usual names of a request factory (Django's `RequestFactory`, DRF's `APIRequestFactory`): its
# `get` and `post` build a request object for a view to be called with.
_REQUEST_FACTORY_NAME_RE = re.compile(r"^(?:rf|factory|request_factory|api_rf|arf)$|factory$", re.IGNORECASE)
_MOCK_CONSTRUCTORS = {"Mock", "MagicMock", "AsyncMock", "NonCallableMock", "NonCallableMagicMock", "create_autospec"}
# Keyword arguments that describe a reply to be returned. A call to a real HTTP client has none of them.
MOCK_REPLY_KEYWORDS = {"status", "status_code", "body", "text", "callback", "exc", "match", "adding_headers",
                       "content_type", "match_querystring", "reason", "complete_qs"}
# Sink names that build an object for an address and send nothing themselves.
TARGET_BUILDERS = {"Request", "from_url"}
# Sink names that fetch whatever receives them: a name bound to a URL is followed for these.
UNAMBIGUOUS_FETCHERS = {"urlopen", "urlretrieve", "Request", "read_csv", "read_json", "read_parquet", "read_excel",
                        "read_pickle",
                        "read_html", "read_table", "read_feather", "read_xml", "download_file", "download_url_to_file",
                        "open_url", "load_dataset", "clone_from", "get_file", "read_orc", "to_csv", "to_json",
                        "to_parquet", "to_excel", "to_feather", "to_pickle", "to_orc", "to_xml", "read_stata",
                        "read_sas", "read_spss", "read_fwf", "ExcelWriter"}

# Submodules that are PURE even though their parent package is network-capable.
# `urllib.parse` is string manipulation and cannot open a socket; parsing a URL is
# ordinary in almost any codebase. Exact matches here are never reported.
NON_NETWORK_SUBMODULES = {
    "urllib.parse",
    # Python 2's urllib kept its pure string helpers at the package top (`from urllib import quote`).
    # `urllib.urlopen` / `urlretrieve` are deliberately NOT here: those are requests.
    "urllib.quote", "urllib.quote_plus", "urllib.unquote", "urllib.unquote_plus", "urllib.urlencode",
    # Exception classes only (URLError, HTTPError): it cannot open a socket.
    "urllib.error",
}
# The transports a client library sends through: a patch on one of them replaces what that library reaches
# (requests sends through urllib3, which sends through http.client).
_TRANSPORT_LAYERS = {
    "requests": {"urllib3", "http.client"},
    "urllib3": {"http.client"},
    "urllib": {"http.client"},
    "botocore": {"urllib3", "http.client"},
    "boto3": {"botocore", "urllib3", "http.client"},
}
# A client class's transport method, named in a test's patch target: what a request reaches when it is replaced.
_TRANSPORT_PATCH_RE = re.compile(
    r"\.(?:HTTPAdapter|BaseAdapter|HTTPConnectionPool|HTTPSConnectionPool|PoolManager|Session|HTTPConnection"
    r"|HTTPSConnection|AsyncClient|Client|ClientSession)\.(?:send|urlopen|request|_make_request|getresponse|_request)$")
# The pure names at the top of `urllib`: Python 2's string and path helpers (a frozen API) and Python 3's pure
# submodules. A line importing only these fetches nothing; any other name, known or not, keeps the network claim.
URLLIB_PURE_NAMES = {
    "quote", "quote_plus", "unquote", "unquote_plus", "urlencode", "pathname2url", "url2pathname", "basejoin",
    "splittype", "splithost", "splituser", "splitpasswd", "splitport", "splitnport", "splitquery", "splittag",
    "splitattr", "splitvalue", "unwrap", "toBytes", "parse", "error", "response",
}

# INBOUND network surface: a bound, listening socket.
#
# Kept SEPARATE from egress on purpose. Strictly, a server is not exfiltration,
# so calling it "egress" would be wrong. But a buyer asking for "on-prem, no
# telemetry" means something that a listening port is squarely part of, and
# silently omitting it because the tool's name says "egress" would answer the
# narrow question while missing the one actually being asked. Reported under its
# own kind, with its own scope line, so the reader sees which is which.
INBOUND_IMPORT_MODULES = {
    "socketserver", "wsgiref", "http.server", "xmlrpc.server", "smtpd",
    "SocketServer", "BaseHTTPServer", "SimpleHTTPServer", "CGIHTTPServer", "SimpleXMLRPCServer",
    "uvicorn", "gunicorn", "waitress", "hypercorn", "daphne",
}

# The submodules of those packages that actually BIND a socket. Any other submodule (`uvicorn.config`,
# `wsgiref.validate`, `hypercorn.typing`) is evidence the server package is present, not a bound socket.
INBOUND_ENTRY_SUBMODULES = {
    "wsgiref.simple_server", "uvicorn.server", "uvicorn.main", "hypercorn.trio", "hypercorn.asyncio",
    "gunicorn.app", "waitress.server", "daphne.server",
}

# Packages whose bare import brings in nothing by itself in Python 3, and the attributes
# through which code that imported them that way reaches the network.
_EMPTY_PACKAGES = {
    "urllib": {"urlopen", "urlretrieve", "request", "URLopener", "FancyURLopener"},
    "wsgiref": {"simple_server"},
}

# asyncio is deliberately NOT an import-level finding. It is overwhelmingly used
# for concurrency, not sockets, so flagging `import asyncio` would manufacture
# false positives. The network CALLS are unambiguous, so those are what get flagged.
ASYNCIO_NET_CALLS = {
    "open_connection", "start_server", "create_connection", "create_server",
    "open_unix_connection", "start_unix_server", "sock_connect",
    "create_datagram_endpoint", "sock_sendall", "sock_sendto", "create_unix_connection", "create_unix_server",
}
# A name lookup asks a resolver, which is the network unless the name is this machine's. Judged on the modules and
# objects that provide it: socket and its green and async counterparts, and an event loop.
_LOOKUP_CALLS = {"getaddrinfo", "getnameinfo"}
_LOOKUP_MODULES = {"socket", "asyncio", "trio", "anyio", "gevent", "eventlet"}
ASYNCIO_SERVER_CALLS = {"start_server", "create_server", "start_unix_server", "create_unix_server"}
# Packages whose connection objects carry asyncio's server method names: asyncssh's `conn.start_server(...)` asks the
# far host to listen. In a file that imports one, the name on an object the file does not trace is not asyncio's.
SERVER_NAME_PROVIDERS = {"asyncssh"}
# Programs that talk to one server and default to this machine when no host is given (redis-cli: 127.0.0.1).
DEFAULT_LOCAL_HOST_TOOLS = {"redis-cli": ("-h", "--host", "-u", "--uri")}
# Clients whose `-h` is the host to connect to, not help.
HOST_H_TOOLS = {"psql", "mysql", "redis-cli", "mosquitto_pub", "mosquitto_sub", "pg_dump", "pg_dumpall",
                "pg_restore", "mysqldump"}
# `npm run` with nothing after it lists the package's scripts.
SCRIPT_RUNNERS = {"npm", "pnpm", "yarn"}
# Standard-library calls that open or accept a connection from a module that is not
# itself an import-level finding: (module, function) -> (kind, what it does).
STDLIB_NET_CALLS = {
    ("ssl", "get_server_certificate"): ("network-call", "connects to a host and fetches its certificate"),
    ("pydoc", "browse"): ("inbound-listener", "starts a local documentation server (INBOUND, not egress)"),
    ("pydoc", "serve"): ("inbound-listener", "starts a local documentation server (INBOUND, not egress)"),
    ("logging.config", "listen"): ("inbound-listener", "binds a socket that accepts logging configuration "
                                                       "(INBOUND, not egress)"),
    ("xml.sax", "parse"): ("network-call", "the SAX parser fetches a system identifier given as a URL"),
}
# Programs that run the program named after them: the argv that matters starts later.
ARGV_WRAPPERS = {"env", "sudo", "doas", "nohup", "timeout", "nice", "ionice", "time", "stdbuf", "setsid",
                 "xargs", "busybox", "command", "exec", "chroot", "unbuffer", "watch", "strace"}
FORBIDDEN_GIT_SUBCOMMANDS = {"fetch", "pull", "push", "clone", "remote", "submodule", "ls-remote", "send-email",
                             "imap-send"}
# `git remote` subcommands that contact the remote; the rest read or edit local configuration.
GIT_REMOTE_CONTACTING = {"update", "prune", "show", "set-head"}
# The Mercurial subcommands that talk to another repository; the rest act on the one on this machine.
HG_REMOTE_SUBCOMMANDS = {"clone", "pull", "push", "incoming", "in", "outgoing", "out", "fetch", "identify", "id"}
# Windows certutil verbs that fetch from a URL. (Mozilla NSS ships a different program with the same name that only
# edits a local certificate database.)
CERTUTIL_NETWORK_VERBS = {"urlcache", "url", "verifyctl", "syncwithwu", "urlfetch"}
# First arguments with which a package manager or cloud tool only reports on itself.
LOCAL_ONLY_FIRST_ARGS = {"--version", "-V", "-v", "version", "--help", "-h", "help", "--prefix", "--cellar",
                         "--repository", "--cache", "config", "cache", "list", "ls", "show", "freeze", "check",
                         "configure", "completion"}
_SHORT_ABOUT_ITSELF = {"-v", "-V", "-h"}


def _asks_about_itself(args: list[str], words=LOCAL_ONLY_FIRST_ARGS) -> bool:
    """The program is asked about itself or its local settings (`pip --version`, `brew --prefix`, `npm config ...`):
    the first argument is one of `words`. A short `-v`, `-V` or `-h` counts only standing alone: followed by more it is
    verbose or a host for many programs (`curl -v URL`, `psql -v ON_ERROR_STOP=1 -h db`). And an address among the
    arguments (`svn ls https://...`, `svn list ^/branches`) is reached whatever the first word is."""
    if not args or args[0] not in words:
        return False
    if args[0] in _SHORT_ABOUT_ITSELF and len(args) > 1:
        return False
    return not any(_svn_repository_address(a) for a in args[1:] if isinstance(a, str))


_SERVICE_CLIENTS = {"aws", "gcloud", "gsutil", "az", "kubectl", "helm"}
_SERVICE_CLIENT_LOCAL_ARGS = {"--version", "-v", "version", "--help", "-h", "help", "config", "configure", "completion"}
# two-word subcommands that read or write this machine's settings only
_SERVICE_CLIENT_LOCAL_PAIRS = {("auth", "list"), ("auth", "configure-docker"), ("components", "list"),
                               # helm's repository list and the search of its locally cached repository indexes
                               ("repo", "list"), ("repo", "ls"), ("repo", "remove"), ("repo", "rm"), ("repo", "index"),
                               ("search", "repo")}
# subcommands of a cluster client that work on files here: always, or when the chart or folder named is a path
_SERVICE_LOCAL_SUBCOMMANDS = {"helm": {"lint", "package", "create", "env", "verify", "plugin"},
                              "kubectl": {"plugin"}}
_SERVICE_LOCAL_WITH_PATH = {"helm": {"template", "show", "inspect", "dependency"}, "kubectl": {"kustomize"}}
# Database clients and the options that name their host. Given none, each talks to this machine (a local socket or
# localhost); a host named in a connection string or a `host=` setting counts as given.
_DB_CLIENT_HOST_FLAGS = {"psql": ("-h", "--host"), "mysql": ("-h", "--host"), "mongosh": ("--host",),
                         "mongo": ("--host",), "redis-cli": ("-h", "-u", "--uri"),
                         # the dump and restore programs beside them, which connect the same way
                         "pg_dump": ("-h", "--host"), "pg_dumpall": ("-h", "--host"), "pg_restore": ("-h", "--host"),
                         "mysqldump": ("-h", "--host"), "mongodump": ("--host", "--uri"),
                         "mongorestore": ("--host", "--uri")}
# options of each whose value is something other than where to connect (psql's `-d` may be a connection string)
_DB_CLIENT_OTHER_VALUE_OPTIONS = {
    "psql": ("-c", "--command", "-f", "--file", "-U", "--username", "-p", "--port", "-v", "--set", "-o", "--output",
             "-F", "--field-separator", "-R", "--record-separator", "-P", "--pset", "-T", "--table-attr", "-L",
             "--log-file"),
    "mysql": ("-e", "--execute", "-u", "--user", "-P", "--port", "-D", "--database"),
    "mongosh": ("--eval", "-u", "--username", "-p", "--password", "--port", "-f", "--file"),
    "mongo": ("--eval", "-u", "--username", "-p", "--password", "--port"),
    "redis-cli": ("-p", "-a", "-n", "--user", "--pass", "-r", "-i", "--port"),
    "pg_dump": ("-f", "--file", "-F", "--format", "-U", "--username", "-p", "--port", "-n", "--schema", "-N",
                "--exclude-schema", "-t", "--table", "-T", "--exclude-table", "-j", "--jobs", "-Z", "--compress",
                "-E", "--encoding", "--role"),
    "pg_dumpall": ("-f", "--file", "-U", "--username", "-p", "--port", "-l", "--database", "--role"),
    "pg_restore": ("-f", "--file", "-F", "--format", "-U", "--username", "-p", "--port", "-n", "--schema", "-t",
                   "--table", "-j", "--jobs", "-I", "--index", "-P", "--function", "-T", "--trigger", "--role"),
    "mysqldump": ("-u", "--user", "-P", "--port", "-r", "--result-file", "--tables", "--where", "-w"),
    "mongodump": ("-u", "--username", "-p", "--password", "--port", "-d", "--db", "-c", "--collection", "-o",
                  "--out", "-q", "--query", "--archive"),
    "mongorestore": ("-u", "--username", "-p", "--password", "--port", "-d", "--db", "-c", "--collection",
                     "--archive", "--dir", "--nsInclude", "--nsExclude")}


def _subcommand_words(args: list[str]) -> list[str]:
    """The words after a client's global options: an option with `=` is one word; a long option followed by a word
    that is not an option takes that word as its value."""
    k = 0
    while k < len(args) and args[k].startswith("-"):
        k += 2 if (args[k].startswith("--") and "=" not in args[k] and k + 1 < len(args)
                   and not args[k + 1].startswith("-")) else 1
    return args[k:]


def _host_of(given: str) -> str | None:
    """The host in a value given to a host option: a name, a URL's host, or `localhost` for a directory (a Unix
    socket on this machine). None when it holds a variable."""
    given = given.strip("'\"")
    if "$" in given:
        return None
    if given.startswith("/"):
        return "localhost"
    if "://" in given:
        if re.match(r"[a-z][a-z0-9+.-]*:///", given, re.I):
            return "localhost"
        m = _DSN_HOST_RE.match(given)
        return m.group(1).strip("[]") if m else None
    return given


def _db_client_host(exe: str, args: list[str]) -> str | None:
    """The host a database client is given: "" when none is, None when it is not known here. A value held in a
    variable is unknown wherever a host could be (a positional argument may be a connection string); only the value of
    an option that names something else (the SQL to run, the user) is set aside."""
    flags = _DB_CLIENT_HOST_FLAGS[exe]
    # Every host the command names is collected: a later one can override an earlier (a connection string's host
    # overrides psql's `-h`; mysql takes the last `--host`), so one host that leaves this machine decides.
    hosts: list[str] = []
    skip_next = False
    for k, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a == _ARGV_HOLE:
            prev = args[k - 1] if k else ""
            other = _DB_CLIENT_OTHER_VALUE_OPTIONS.get(exe, ())
            # the value of an option that names something else, alone (`-F`) or last in a run of flags (`-AtqwlF`)
            if prev in other or (re.fullmatch(r"-[A-Za-z]{2,}", prev or "") and "-" + prev[-1] in other):
                continue
            if exe == "redis-cli" and prev not in flags:
                continue                # redis-cli's positional words are its command (`get "$key"`), never its host
            return None
        if a.startswith("-") and a not in flags and not any(a.startswith(f) for f in flags) and "$" in a:
            continue                    # an option given a variable value (`-u$USER`, `-p${PW}`): not a host
        if a in _DB_CLIENT_OTHER_VALUE_OPTIONS.get(exe, ()):
            skip_next = True            # its value is the SQL to run, the user, a file: not a host
            continue
        given = None
        if a in flags:
            given = args[k + 1] if k + 1 < len(args) and args[k + 1] != _ARGV_HOLE else None
            if not given or _host_of(given) is None:
                return None
            hosts.append(_host_of(given))
            skip_next = True
            continue
        for f in flags:
            if a.startswith(f + "="):
                given = a.split("=", 1)[1]
            elif len(f) == 2 and a.startswith(f) and len(a) > 2:
                given = a[2:]
            if given is not None:
                break
        if given is not None:
            if _host_of(given) is None:
                return None
            hosts.append(_host_of(given))
            continue
        if a.startswith(("--defaults-file", "--defaults-extra-file", "--login-path", "--defaults-group-suffix")):
            return None                 # an options file names the host
        if "://" in a and exe != "redis-cli":       # redis-cli's positional words are its command
            # every host the connection string names (`postgresql:///db` names none: a socket on this machine)
            named = _dsn_hosts(a)
            if named is None:
                return None
            hosts += named
            continue
        if exe == "redis-cli":
            continue
        if re.search(r"(?:^|\s)service\s*=", a):
            return None                 # a service file entry names the host
        conns = re.findall(r"(?:^|\s)(?:host|hostaddr)\s*=\s*([^\s'\"]+)", a)
        if conns:
            hosts += ["localhost" if h.startswith("/") else h for h in conns]
            continue
        if "$" in a:
            return None
    if hosts:
        return next((h for h in hosts if not _THIS_MACHINE_HOST_RE.fullmatch(h)), hosts[-1])
    # no host given: this machine, unless the file sets the client's host in the environment
    return None if _DB_HOST_ELSEWHERE.get() else ""
# Subcommands of docker (and of `docker compose`) that neither pull nor push: they act on what is here.
DOCKER_LOCAL_SUBCOMMANDS = {"logs", "ps", "stop", "kill", "rm", "rmi", "inspect", "exec", "start", "restart", "images",
                            "stats", "top", "port", "wait", "down", "config", "version", "info", "cp", "tag", "diff",
                            "logout", "save", "load", "commit", "attach", "pause", "unpause", "rename", "update", "events",
                            "history", "export"}
# docker subcommands that reach a registry only for an image that is not on this machine
_CONTAINER_PULLING_SUBCOMMANDS = {"run", "build", "create", "compose", "buildx", "container", "image", "builder"}
# docker's (and podman's) management commands: the subcommands of each that pull, push or build; every other one acts
# on what is on this machine
DOCKER_MANAGEMENT_NETWORK = {"container": {"run", "create"}, "image": {"pull", "push", "build"},
                             "buildx": {"build", "bake", "imagetools"}, "builder": {"build"},
                             "manifest": {"inspect", "push", "create"}, "plugin": {"install", "upgrade", "push"},
                             "volume": set(), "network": set(), "context": set(), "system": set(), "secret": set(),
                             "trust": {"sign", "inspect"}, "swarm": {"join"}, "machine": {"init"}}
_COMPOSE_FLAGS_WITH_VALUE = {"-f", "--file", "-p", "--project-name", "--env-file", "--profile", "--project-directory"}


# `python3 -m http.server 8000`: a web server for the folder (INBOUND)
_PYTHON_WEB_SERVER_RE = re.compile(
    r"(?<![\w./-])(?:python[\d.]*|py)(?:\.exe)?\s+(?:-\S+\s+)*-m\s+(http\.server|SimpleHTTPServer)\b")

# docker's own options, written before its subcommand
_DOCKER_GLOBAL_VALUE_FLAGS = {"-H", "--host", "-c", "--context", "--config", "-l", "--log-level", "--tlscacert",
                              "--tlscert", "--tlskey"}
_DOCKER_GLOBAL_SWITCHES = {"-D", "--debug", "--tls", "--tlsverify"}

_DOCKER_RUN_SWITCHES = {"--detach", "--interactive", "--tty", "--rm", "--privileged", "--init", "--publish-all",
                        "--read-only", "--sig-proxy", "--no-healthcheck", "--oom-kill-disable", "--quiet",
                        "--disable-content-trust", "--help"}


def _pulls_never(elts, options_from: int | None = None) -> bool:
    """`--pull never` or `--pull=never`: the container runs from an image already on this machine, or not at all.
    With `options_from` (the word after `docker run`), only docker's own options count: they end at the image, and a
    `--pull never` after it is the container's (`docker run img sync --pull never`)."""
    words = [str(w) for w in elts]
    if options_from is not None:
        k = options_from
        while k < len(words):
            w = words[k]
            if not w.startswith("-"):
                break                               # the image
            if w == "--pull" and k + 1 < len(words):
                if words[k + 1] == "never":
                    return True
                k += 2
                continue
            if w == "--pull=never":
                return True
            boolean = "=" in w or w in _DOCKER_RUN_SWITCHES or re.fullmatch(r"-[ditPq]+", w)
            k += 1 if boolean else 2                # an option with a value takes the next word (`-v a:b`, `--name x`)
        return False
    return "--pull=never" in words or any(w == "--pull" and k + 1 < len(words) and words[k + 1] == "never"
                                          for k, w in enumerate(words))


def _compose_subcommand(rest: list) -> str:
    """The subcommand of `docker compose` (or `docker-compose`), after compose's own flags (`-f c.yml down`)."""
    k = 0
    while k < len(rest) and rest[k].startswith("-"):
        k += 1 if "=" in rest[k] or rest[k] not in _COMPOSE_FLAGS_WITH_VALUE else 2
    return rest[k] if k < len(rest) else ""
HADOOP_YARN_SUBCOMMANDS = {"application", "applicationattempt", "container", "node", "queue", "logs", "jar",
                           "rmadmin", "top", "classpath", "daemonlog", "resourcemanager", "nodemanager"}
# Flags after which a shell interpreter runs what follows.
SHELL_COMMAND_FLAGS = {"-c", "-ic", "-lc", "-ec", "-xc", "/c", "/k", "-command", "-encodedcommand", "-file", "-f"}

# Network binaries reachable through an argv list with NO shell=True.
# `subprocess.run(["curl", url])` spawns no shell, so a shell=True test alone would
# not see it. Matched on the basename, so "/usr/bin/curl" and "curl.exe" both hit.
PY_NET_BINARIES = {
    "curl", "wget", "aria2c", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
    "rsync", "ftp", "telnet", "git", "hg", "svn", "pip", "pip3", "pipx", "uv", "uvx",
    "conda", "mamba", "npm", "npx", "yarn", "pnpm", "gh", "apt", "apt-get", "dnf", "yum", "brew",
    "docker", "podman", "kubectl", "helm", "terraform", "pulumi", "aws", "gcloud", "az",
    "certutil", "bitsadmin", "nslookup", "dig", "host", "ping", "traceroute", "tracert",
    "smbclient", "mosquitto_pub", "mosquitto_sub", "psql", "mysql", "redis-cli", "mongosh", "openssl",
    "pg_dump", "pg_dumpall", "pg_restore", "mysqldump", "mongodump", "mongorestore",
    "gsutil", "socat", "docker-compose", "podman-compose",
}
# Subversion keeps a working copy on this machine; these subcommands talk to the repository.
def _svn_repository_address(word: str) -> bool:
    """A repository svn reaches over the network: a URL other than `file://`, or `^/` (the working copy's own
    repository, which is wherever its URL points)."""
    w = word.strip("'\"")
    return w.startswith("^/") or ("://" in w and not w.lower().startswith("file://"))


def _openssl_connects(args: list[str]) -> bool:
    """`openssl s_client`, `s_time`, and `ocsp` given a responder to ask (`-url`, `-host`) open a connection; every
    other subcommand works on files here (`ocsp -port` serves, which is inbound)."""
    if any(s in ("s_client", "s_time") for s in args):
        return True
    return "ocsp" in args and any(a in ("-url", "-host") or a.startswith(("-url=", "-host=")) for a in args)


def _kubectl_asks_the_server(exe: str, args: list[str]) -> bool:
    """`kubectl version` reports the server's version as well as its own; only `--client` keeps it here."""
    if exe != "kubectl":
        return False
    return _subcommand_words(args)[:1] == ["version"] and not any(
        a == "--client" or (a.startswith("--client=") and a.split("=", 1)[1].lower() != "false") for a in args)


SVN_REMOTE_SUBCOMMANDS = {"checkout", "co", "update", "up", "commit", "ci", "export", "import", "list", "ls", "log",
                          "switch", "sw", "merge", "mergeinfo", "cat", "blame", "praise", "annotate", "ann", "relocate",
                          "copy", "cp", "mkdir", "propget", "pg", "proplist", "pl"}
# socat address types that open or accept a network connection (`TCP:host:80`, `OPENSSL:host:443`, `UDP-LISTEN:53`)
_SOCAT_NET_ADDRESS_RE = re.compile(r"^(?:tcp|udp|ssl|openssl|sctp|dccp|socks4a?|socks5|proxy|ip|udp-sendto|vsock)"
                                   r"[\w-]*:", re.IGNORECASE)
# A connection string for a database or broker: a host, not a file.
# (a SQLAlchemy URL names its driver after `+`: `postgresql+psycopg2://`, `mssql+pyodbc://`, `oracle+oracledb://`)
DSN_RE = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|rediss|amqps?|kafka|mssql|oracle|snowflake"
                    r"|clickhouse|cassandra|neo4j|bolt|nats|mqtt|ldaps?|ftps?|sftp|ssh|smb|wss?|cockroachdb|trino|presto"
                    r"|bigquery|redshift|db2|ibm_db_sa|teradatasql|vertica|hana|databricks|exasol|firebird|sybase|spanner"
                    r"|singlestoredb|crate)(?:\+[\w-]+)?://", re.IGNORECASE)
# Keywords and environment variables that set a database client's host apart from its connection string
_DSN_HOST_KEYWORDS = {"host", "hostaddr", "service", "connect_args", "read_default_file", "read_default_group",
                      "unix_socket", "server", "address"}
# (the variables libpq and the MySQL client library read for a host the connection string leaves out; a name an
# application chooses, `REDIS_HOST`, is read only by that application's own code)
_DSN_HOST_ENVIRONMENT = {"PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "MYSQL_HOST"}


def _sets_dsn_environment(n: ast.AST) -> bool:
    """A node that names or may set the variable a database client reads for its host: the name written out
    (`os.environ["PGHOST"] = h`, `os.environ.update(PGHOST=h)`), a settings file loaded into the environment
    (`load_dotenv()`, `read_env()`), or the environment updated from a mapping (`os.environ.update(cfg)`,
    `os.environ |= cfg`)."""
    if isinstance(n, ast.Constant):
        return n.value in _DSN_HOST_ENVIRONMENT
    if isinstance(n, ast.keyword):
        return n.arg in _DSN_HOST_ENVIRONMENT
    if isinstance(n, ast.AugAssign):
        return (_dotted_name(n.target) or "").endswith("environ")
    if isinstance(n, ast.Assign):
        # `os.environ[k] = v` with a key not written out (`for k, v in cfg.items(): ...`)
        return any(isinstance(t, ast.Subscript) and (_dotted_name(t.value) or "").endswith("environ")
                   and not isinstance(t.slice, ast.Constant) for t in n.targets)
    if isinstance(n, ast.Call):
        name = _dotted_name(n.func) or ""
        if name.rsplit(".", 1)[-1] in ("load_dotenv", "read_env", "read_dotenv", "load_envs"):
            return True
        if name.rsplit(".", 1)[-1] == "putenv" and n.args and not isinstance(n.args[0], ast.Constant):
            return True
        if name.endswith("environ.update"):
            return any(not isinstance(a, ast.Dict) for a in n.args) or any(k.arg is None for k in n.keywords)
    return False


def _sets_dsn_host(kw: ast.keyword, dsn: str) -> bool:
    """A keyword on a client call that sets where it connects apart from the connection string `dsn`: `host=h`,
    `service=s`, `read_default_file=f`, or `connect_args` holding one of those (or not written out). A keyword whose
    value is that connection string itself sets nothing else."""
    if kw.arg is None:
        return True                     # `connect(dsn, **options)`: the mapping may hold any keyword, `host` among them
    if kw.arg not in _DSN_HOST_KEYWORDS or (isinstance(kw.value, ast.Constant) and kw.value.value == dsn):
        return False
    if kw.arg == "connect_args" and isinstance(kw.value, ast.Dict):
        return any(not isinstance(k, ast.Constant) or k.value in _DSN_HOST_KEYWORDS for k in kw.value.keys)
    return True
# Calls that connect to the connection string they are given and run there (pandas' SQL readers and writer)
_DSN_RUNNERS = {"read_sql", "read_sql_query", "read_sql_table", "to_sql"}
DSN_SINK_NAMES = {"create_engine", "create_async_engine", "connect", "MongoClient", "AsyncIOMotorClient", "Redis",
                  "StrictRedis", "from_url", "Connection", "connection", "BlockingConnection", "URLParameters",
                  "KafkaProducer", "KafkaConsumer", "Client", "AsyncClient", "Engine"}


def _parse_quietly(src: str, filename: str = "<unknown>") -> ast.AST:
    """`ast.parse` with the audited file's own compile-time warnings set aside. An invalid escape in
    someone else's string (`"\\d"`) is their warning, not this tool's output; and under `-W error` it
    would turn a file that parses into one reported as unparseable."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(src, filename=filename)


# Distributions whose name is not the module they install (`pip install grpcio` gives `import grpc`)
_DISTRIBUTION_MODULES = {
    "grpcio": "grpc", "psycopg2-binary": "psycopg2", "psycopg-binary": "psycopg", "psycopg-pool": "psycopg",
    "kafka-python": "kafka", "kafka-python-ng": "kafka", "confluent-kafka": "confluent_kafka",
    "websocket-client": "websocket", "python-socketio": "socketio", "paho-mqtt": "paho", "elastic-apm": "elasticapm",
    "dnspython": "dns", "mysql-connector-python": "mysql", "mysql-connector": "mysql", "mysqlclient": "MySQLdb",
    "python-telegram-bot": "telegram", "pygithub": "github", "python-gitlab": "gitlab", "discord-py": "discord",
    "snowflake-connector-python": "snowflake", "influxdb-client": "influxdb_client", "sentry-sdk": "sentry_sdk",
    "slack-sdk": "slack_sdk", "google-api-python-client": "googleapiclient", "redis-py-cluster": "rediscluster",
}
# Families of distributions that each install a module under one listed package (`google-cloud-storage` is
# `google.cloud.storage`, `azure-storage-blob` is `azure.storage.blob`)
_DISTRIBUTION_FAMILIES = {"google-cloud-": "google.cloud", "azure-": "azure",
                          # the interface and SDK send nothing; only the exporters do, as for an import
                          "opentelemetry-exporter-": "opentelemetry"}


def _dist_candidates(name: str) -> set[str]:
    """PEP 503-ish variants of a distribution name for blocklist lookup, lower-cased."""
    raw = name.strip()
    if not raw:
        return set()
    norm = re.sub(r"[-_.]+", "-", raw.lower())
    und = norm.replace("-", "_")
    dotted = norm.replace("-", ".")
    out = {raw.lower(), norm, und, dotted}
    module = _DISTRIBUTION_MODULES.get(norm)
    if module:
        out.add(module.lower())
    out.update(root for prefix, root in _DISTRIBUTION_FAMILIES.items() if norm.startswith(prefix))
    if raw.startswith("@") and "/" in raw:
        out.add(raw.lower().split("/", 1)[0])        # an npm scope: `@sentry/node` is under `@sentry`
    return out


@functools.lru_cache(maxsize=1)
def _listed_lower() -> tuple[frozenset[str], frozenset[str]]:
    """The listed modules and their top-level names, lower-cased (`MySQLdb`, `O365`)."""
    listed = {m.lower() for m in FORBIDDEN_IMPORT_MODULES | JS_NET_MODULES | INBOUND_IMPORT_MODULES
              | PROTOCOL_LIBRARIES}
    return frozenset(listed), frozenset(m.split(".")[0] for m in listed)


def _declared_is_network(pkg: str) -> bool:
    """True when a declared dependency names a known network package.

    Exact / normalised match against the same lists the import checker uses, by module name or by the distribution
    name that installs it. Deliberately does NOT treat every `google-*` as `google.cloud`: a prefix that wide is how
    this tool manufactures false positives; `google-cloud-*` is the family that installs `google.cloud`.
    """
    cands = _dist_candidates(pkg)
    listed, roots = _listed_lower()
    return bool(cands & listed or cands & roots)


def _check_manifests(target: Path) -> tuple[list["Finding"], list[tuple[str, str]]]:
    """Scan declared-dependency manifests. Returns (findings, tree entries)."""
    scan = collect_manifests(target)
    deps, errors, files = scan.deps, scan.errors, scan.files
    tree = [(rel, _file_digest(p)) for p, rel in files]
    findings: list[Finding] = []
    for e in errors:
        if e.detail == SETUP_PY_UNPARSEABLE:
            continue        # the Python pass reports the file as unparseable
        findings.append(Finding(e.file, e.line, "unparseable-source", e.detail))
    for r in scan.remotes:
        findings.append(Finding(r.file, r.line, "git-remote" if r.kind == "submodule" else "declared-remote-source",
                                r.detail))
    for d in deps:
        if _declared_is_network(d.name):
            # `h2`, `h11`: a protocol library encodes and decodes; it cannot open a socket itself
            protocol = bool(_dist_candidates(d.name) & {m.lower() for m in PROTOCOL_LIBRARIES})
            findings.append(Finding(
                d.file, d.line, "declared-network-dependency",
                f"declared dependency {d.name!r} names a protocol library, which encodes and decodes and cannot "
                f"open a socket itself - not a call site; the tree depends on it" if protocol else
                f"declared dependency {d.name!r} names a known network package "
                f"- not a call site; the tree depends on it",
            ))
    return findings, tree


# Packages whose top level is an interface that sends nothing by itself, and the parts of them
# that do send. Importing the interface is evidence the package is present, not a network import.
INTERFACE_PACKAGES = {"opentelemetry": {"exporter", "exporters"}}


# CPython's private modules that start a process directly, below `subprocess`: what they run is not resolved here.
_PRIVATE_PROCESS_MODULES = {"_winapi", "_posixsubprocess"}
_PRIVATE_PROCESS_DETAIL = ("imports {}, a private standard-library module that starts processes directly; what it "
                           "runs is NOT resolved by this line")


# Compatibility layers that give standard-library modules other names (`six.moves.http_client` is `http.client`)
_COMPAT_PREFIXES = ("six.moves", "future.moves", "future.backports")
_COMPAT_NAMES = {"http_client": "http.client", "xmlrpc_client": "xmlrpc.client", "xmlrpc_server": "xmlrpc.server",
                 "BaseHTTPServer": "http.server", "SimpleHTTPServer": "http.server", "CGIHTTPServer": "http.server",
                 "SocketServer": "socketserver", "urllib_request": "urllib.request", "urllib_parse": "urllib.parse",
                 "urllib_error": "urllib.error", "urllib_robotparser": "urllib.robotparser",
                 "http_cookiejar": "http.cookiejar", "http_cookies": "http.cookies", "urllib2": "urllib.request",
                 "httplib": "http.client", "xmlrpclib": "xmlrpc.client"}


def _compat_module(name: str) -> str:
    """The standard-library module a compatibility layer's name stands for (`six.moves.urllib.request` is
    `urllib.request`); any other name unchanged. The layer's own package (`six.moves`) is returned as it is."""
    for prefix in _COMPAT_PREFIXES:
        if name.startswith(prefix + "."):
            first, _, rest = name[len(prefix) + 1:].partition(".")
            base = _COMPAT_NAMES.get(first, first)
            return base + ("." + rest if rest else "")
    return name


def _classify_module(name: str) -> str | None:
    """'network' | 'dependency' | 'inbound' | None for a dotted module name.

    THE DISTINCTION THIS FUNCTION EXISTS TO MAKE: importing a network package
    and importing one of its pure submodules are DIFFERENT CLAIMS, and conflating
    them is a false positive.

        from requests.structures import CaseInsensitiveDict

    tells you requests is a dependency. It is not a network call: that module is a
    dict subclass with zero network tokens in its source. Reporting it as
    `network-import` says a socket may open at that line, and no socket can.

    `requests.structures`, `requests.compat`, `urllib3.exceptions`, `urllib3.util`
    and `trio.testing` are all of that shape.

    THE RULE IS STRUCTURAL, NOT AN ALLOWLIST. Enumerating every pure submodule of
    every network package on PyPI is not a thing anyone can finish. The rule instead:

      * the module is listed EXACTLY  -> `network` (a real entry point:
        `urllib.request`, `http.client`, `requests`, `urllib3`)
      * only its ROOT is listed       -> `dependency` (evidence the package is
        present; not a claim that this line reaches the network)

    Recall is preserved: a reader still learns the package is there. What changes
    is that the tool stops asserting a network call it cannot support.
    """
    if not name:
        return None
    if name in NON_NETWORK_SUBMODULES:
        return None
    root = name.split(".")[0]
    if root in INTERFACE_PACKAGES:
        # `from opentelemetry import trace` takes the interface. Only an exporter sends anything.
        parts = name.split(".")[1:]
        return "network" if any(part in INTERFACE_PACKAGES[root] for part in parts) else "dependency"
    if name in FORBIDDEN_IMPORT_MODULES:
        return "network"
    # a module inside a listed package that is itself a dotted name (`google.cloud.storage` under `google.cloud`,
    # `spacy.cli.download` under `spacy.cli`): the listed package is a network client and its modules are its parts
    parts = name.split(".")
    if any(".".join(parts[:k]) in FORBIDDEN_IMPORT_MODULES for k in range(2, len(parts))):
        return "network"
    if name in INBOUND_IMPORT_MODULES or name in INBOUND_ENTRY_SUBMODULES:
        return "inbound"
    if root in FORBIDDEN_IMPORT_MODULES:
        return "dependency"
    if root in PROTOCOL_LIBRARIES:
        return "protocol"
    if root in INBOUND_IMPORT_MODULES or root in INBOUND_FRAMEWORKS or name in INBOUND_FRAMEWORKS:
        return "inbound-dependency"   # server package present; this line binds nothing
    if name.startswith("sklearn.datasets.fetch_"):
        return "network"              # the scikit-learn fetchers download on first use
    return None


def _argv_basename(s: str) -> str:
    """Basename of an argv[0], normalized. '/usr/bin/curl' and 'curl.exe' -> 'curl'."""
    base = s.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
    return base[:-4] if base.endswith(".exe") else base
SUBPROCESS_CALLERS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
# Programs an argv list hands its words to that are judged as their command line is on a script line
_ARGV_SCRIPT_JUDGED = {"pip", "pip3", "pipx", "uv", "uvx", "conda", "mamba", "npm", "npx", "yarn", "pnpm", "terraform",
                       "ping", "traceroute", "tracert", "dig", "nslookup", "host", "brew", "apt", "apt-get", "dnf",
                       "yum", "gh"}
# Their subcommands that act on this machine only (in an argv list, a subcommand not named here and not judged by
# the script rules keeps the claim a network program gets)
_ARGV_LOCAL_SUBCOMMANDS = {
    "pip": {"uninstall", "list", "show", "freeze", "check", "cache", "config", "debug", "hash", "inspect", "help",
            "completion"},
    "pipx": {"list", "uninstall", "uninstall-all", "ensurepath", "environment", "completions"},
    "uv": {"venv", "version", "help", "cache", "generate-shell-completion"},
    "conda": {"info", "list", "activate", "deactivate", "config", "clean", "remove", "uninstall", "run"},
    "npm": {"run", "run-script", "test", "start", "stop", "restart", "ls", "list", "config", "cache", "version", "pack",
            "prefix", "root", "bin", "why", "help", "rebuild", "explain"},
    "yarn": {"run", "test", "start", "build", "lint", "workspace", "workspaces", "why", "config", "cache", "bin",
             "version", "node", "exec", "list"},
    "pnpm": {"run", "test", "start", "build", "lint", "exec", "list", "ls", "why", "config", "store", "root", "bin"},
    "terraform": {"fmt", "validate", "version", "show", "output", "console", "graph", "workspace", "state", "taint",
                  "untaint", "help"},
    "brew": {"list", "leaves", "config", "doctor", "info", "--prefix", "--cellar", "--repository", "shellenv", "help"},
    "apt": {"list", "show", "search", "policy", "help"}, "apt-get": {"check", "clean", "autoclean", "help"},
    "dnf": {"list", "info", "help", "history"}, "yum": {"list", "info", "help", "history"},
    "gh": {"help", "completion", "config", "alias", "--version"},
}
_ARGV_LOCAL_SUBCOMMANDS["pip3"] = _ARGV_LOCAL_SUBCOMMANDS["pip"]
_ARGV_LOCAL_SUBCOMMANDS["mamba"] = _ARGV_LOCAL_SUBCOMMANDS["conda"]
OS_SHELL_CALLERS = {"system", "popen"}
# Every other way the standard library starts a process from a literal argv or command.
SPAWN_CALLERS = {
    "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "posix_spawn", "posix_spawnp", "create_subprocess_exec", "create_subprocess_shell", "spawn", "startfile",
}
SHELL_INTERPRETERS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
_PYTHON_EXE_RE = re.compile(r"^(?:python[0-9.]*w?|py|pyw|pypy[0-9]*|ipython[0-9]*)$")
# Words in a shell string that reach the network: binaries, and PowerShell's download cmdlets.
_SHELL_NET_WORD_RE = re.compile(
    # .NET names are written after a dot: `(New-Object System.Net.WebClient).DownloadFile(...)`
    r"(?:(?<![\w.-])|(?<=\.)(?=Download|WebClient|Net\.WebClient))"
    r"(curl|wget|aria2c|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|telnet|nslookup|dig|host|ping"
    r"|certutil|bitsadmin|pip3?|uv|uvx|pipx|conda|mamba|npm|npx|yarn|pnpm|gh|twine\s+upload"
    r"|git\s+(?:push|pull|fetch|clone|ls-remote)"
    r"|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer|DownloadString|DownloadFile|DownloadData|WebClient"
    r"|(?:Install|Save|Update)-(?:Module|Package|Script|PSResource)"
    r"|Net\.WebClient)(?![\w.-])",
    re.IGNORECASE,
)
# .NET's network clients in PowerShell (and in a command string handed to it): a client made with `New-Object` or a
# type literal, or one of WebClient's transfer methods called on any object.
_DOTNET_NET_RE = re.compile(
    r"""(?:\bNew-Object\s+(?:-TypeName\s+)?['"]?|\[)(?:System\.)?Net\.(?:WebClient|WebRequest|HttpWebRequest|FtpWebRequest"""
    r"""|Http\.HttpClient|Sockets\.(?:TcpClient|UdpClient|Socket)|Mail\.SmtpClient|Dns|WebSockets\.ClientWebSocket)\b"""
    r"""|\.\s*(?:DownloadString|DownloadFile|DownloadData|UploadString|UploadFile|UploadData|UploadValues)"""
    r"""(?:TaskAsync|Async)?\s*\(""",
    re.IGNORECASE)
_PYTHON_NET_MODULES_FOR_M = {"pip", "http.server", "urllib.request", "ftplib", "smtplib", "wsgiref.simple_server"}

# HTML/JS external-reference patterns (case-insensitive).
# A scheme followed by the start of a host. `"ws://" + location.host` names no host and is
# a protocol prefix, not an address.
URL_RE = re.compile(r"""\b(?:https?|wss?|ftps?)://(?=[^\s"'`<>,;)\]\\+])""", re.IGNORECASE)
# Addresses of object stores, hubs, distributed file systems and media streams, written where a call reads them
# (`pd.read_csv('s3://bucket/x.csv')`, `cv2.VideoCapture('rtsp://cam/stream')`); group 1 is the scheme, 2 the host
_STORAGE_URL_RE = re.compile(r"""^\s*(s3[an]?|gs|gcs|az|abfss?|adl|wasbs?|hf|hdfs|webhdfs|rtsps?|rtmps?|oci|r2|swift)"""
                             r"""://([^/\s:'"?#]*)""", re.IGNORECASE)
# Calls that read such an address when they are given one
_STORAGE_READERS = {"read_csv", "read_json", "read_parquet", "read_excel", "read_table", "read_feather", "read_xml",
                    "read_pickle", "read_orc", "read_text", "read_bytes", "load_dataset", "VideoCapture", "open",
                    "load", "download", "download_file", "imread", "from_url", "csv", "parquet", "orc", "cp", "mv", "head", "ls",
                    "to_csv", "to_json", "to_parquet", "to_excel", "to_feather", "to_pickle", "to_orc", "to_xml",
                    "read_stata", "read_sas", "read_spss", "read_fwf", "ExcelWriter"}
DATA_URI_RE = re.compile(r"""data:[^;'"\s]*;base64""", re.IGNORECASE)
# a `data:` URI whose content is code: script, or a page that may hold script, base64-encoded or written out
# (`data:text/html;charset=utf-8,...`, `data:text/javascript,...`); a media type followed by neither `;` nor `,` is
# prose naming one
_DATA_URI_CODE_RE = re.compile(r"data:\s*(?:text/(?:javascript|ecmascript|html)|application/(?:x-)?(?:javascript|ecmascript)"
                               r"|application/xhtml\+xml)(?=\s*[;,])", re.IGNORECASE)
# An SVG image runs its script only as a document of its own (a frame, an object, an embed); in an `img` or a CSS
# `url(...)` it is drawn as a picture and runs nothing.
_DATA_URI_SVG_RUNS_RE = re.compile(r"<(?:iframe|frame|object|embed)\b[^>]*data:\s*(?:image/svg\+xml|text/xml|application/xml)",
                                   re.IGNORECASE)
ENTITY_SCHEME_RE = re.compile(r"""&#x?0*(104|68);t?tp""", re.IGNORECASE)  # entity-encoded http
NET_CALL_RE = re.compile(r"""\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon)\s*\("""
                         r"""|\bnew\s+(?:XMLHttpRequest|WebSocket|EventSource)\b|\bnavigator\.sendBeacon\b"""
                         r"""|(?:\$|\bjQuery)\.(?:ajax|get|post|getJSON|getScript)\s*\(""")
# The attribute value may be unquoted: HTML allows it and minifiers write it that way.
SRC_HREF_RE = re.compile(r"""(?:src|href|action|data|poster|srcset)\s*=\s*['"]?(?:https?:)?//""", re.IGNORECASE)
# A protocol-relative reference (`//cdn.example/x.js`) loads from the page's scheme.
PROTO_REL_RE = re.compile(r"""['"(=]//[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:[:/]|['")>\s]|$)""", re.IGNORECASE)
# Stylesheets: `@import url(...)` and `url(...)` fetch when the sheet is applied.
CSS_URL_RE = re.compile(r"""(?:@import\s+(?:url\()?\s*['"]?|url\(\s*['"]?)(?:https?:)?//""", re.IGNORECASE)
# A tag and its attributes, across lines. Attribute values may be quoted either way or not at all.
# a tag and its attributes; a quoted value may hold `>` (`<img v-if="n > 0" src=...>`), and a quote with no partner is a
# character (each piece is taken atomically, so a tag that never closes costs one pass)
_MARKUP_TAG_RE = re.compile(r"""<([A-Za-z][\w:.-]*)\b((?>[^<>"']+|"[^"<]*"|'[^'<]*'|["'])*)>""", re.S)
_MARKUP_ATTR_RE = re.compile(r"""([@:\w.-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s"'<>]+)""")
# Attributes the page fetches from when it renders, and the tags whose `href` is a fetch, not a link.
_LOAD_ATTRS = {"src", "srcset", "imagesrcset", "poster", "background", "codebase", "manifest", "lowsrc", "dynsrc",
               "archive"}
_HREF_LOAD_TAGS = {"link", "use", "image", "script", "feimage"}
def _page_has_relative_load(text: str) -> bool:
    """Does the page load something by a relative address (`<img src="logo.png">`, a stylesheet `href="a.css"`)?
    Such a load comes from the page's `<base href>` when it has one."""
    for m in _MARKUP_TAG_RE.finditer(text):
        tag = m.group(1).lower().rsplit(":", 1)[-1]
        for a in _MARKUP_ATTR_RE.finditer(m.group(2)):
            attr = a.group(1).lower().rsplit(":", 1)[-1]
            value = a.group(2).strip("'\"").strip()
            if (attr in _LOAD_ATTRS or (attr == "href" and tag in _HREF_LOAD_TAGS)) and value \
                    and not re.match(r"[a-z][\w+.-]*:|//|#|\{", value, re.I):
                return True
    return False


# A script statement that fetches or navigates: the URL on its line is where it goes.
_MARKUP_FETCH_RE = re.compile(
    r"""\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts)\s*\(|\bnew\s+(?:XMLHttpRequest|"""
    r"""WebSocket|EventSource|Worker|Image)\b|\bimport\s*\(|\.src\s*=|\blocation(?:\.href)?\s*=|\.open\s*\(|"""
    r"""(?:\$|\bjQuery)\.(?:get|post|ajax|getJSON|getScript)\s*\(|\baxios\b"""
    # a module script's static import of an address (`import x from 'https://...'`)
    r"""|\bimport\b[\w\s{},*$]*?(?:\bfrom\s*)?['"](?:https?:)?//""")
# Code in a script block that loads what it holds: it builds an element that fetches, sets a source,
# inserts a node, or fetches outright.
_SCRIPT_BLOCK_LOADS_RE = re.compile(
    r"""createElement\s*\(\s*['"](?:script|img|iframe|link|image)['"]|\.insertBefore\s*\(|\.appendChild\s*\(|"""
    r"""\.src\s*=|setAttribute\s*\(\s*['"](?:src|href)['"]|\bnew\s+(?:Image|XMLHttpRequest|WebSocket|EventSource|Worker)\b|"""
    r"""\bfetch\s*\(|sendBeacon\s*\(|\bimportScripts\s*\(|\bimport\s*\(""")
# An anchor the user must click. Nothing is fetched by loading the page.
ANCHOR_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*(['"])(?:https?:)?//[^'"]*\1[^>]*>""", re.IGNORECASE)
# A URL string that is only a postMessage target origin or compared against an `origin` makes no request.
# Stripped before the URL test, so anything else on the line (a fetch, a src, a second URL) still counts.
ORIGIN_ONLY_URL_RE = re.compile(
    r"""postMessage\s*\((?:[^;()]|\([^()]*\))*?,\s*(['"`])https?://[^'"`\s]*\1\s*\)"""
    r"""|\b[\w.]*origin\w*\s*[!=]==?\s*(['"`])https?://[^'"`\s]*\2"""
    r"""|(['"`])https?://[^'"`\s]*\3\s*[!=]==?\s*[\w.]*origin\w*\b""",
    re.IGNORECASE,
)
_XMLNS_ATTR_RE = re.compile(r"""\bxmlns(?::[\w-]+)?\s*=\s*(['"])https?://[^'"]*\1""", re.IGNORECASE)
# Attributes whose value is an identifier in a vocabulary (microdata, RDFa, RDF, XML Schema), not an address to load.
_VOCAB_ATTR_RE = re.compile(
    r"""\b(?:itemtype|itemid|vocab|typeof|property|prefix|profile|datatype|cite|rdf:\w+|xsi:\w+|xml:lang)\s*=\s*(['"])[^'"]*\1""",
    re.IGNORECASE)
_PAGE_EXTS = {".html", ".htm", ".xhtml", ".svg", ".j2", ".jinja", ".jinja2", ".njk", ".hbs", ".ejs", ".twig", ".erb"}
# What a browser or a template engine acts on: script and style blocks, tags, template expressions.
_PAGE_TAG_RE = re.compile(r"<[^<>]*>")
# an opening tag whose quoted attribute values may hold `<` and `>` (`<iframe src="data:text/html,<b>x</b>">`); a
# value is bounded, so an unclosed quote costs a bounded scan
_PAGE_QUOTED_TAG_RE = re.compile(r"""<[A-Za-z][^<>"']*(?:(?:"[^"]{0,4096}"|'[^']{0,4096}')[^<>"']*)*>""")


def _page_active_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of each part of a page a browser or template engine acts on, leftmost first: a `<script>` or
    `<style>` block with its closing tag, a tag, a `{{ ... }}` or `{% ... %}` expression. One pass: a closing
    delimiter is searched for at most once past any point, so text full of unclosed openers stays linear."""
    spans, pos, n = [], 0, len(text)
    closer_at: dict[str, int] = {}          # the next place each closer was found at (or n when there is none)

    def close_after(key: str, start: int) -> int:
        at = closer_at.get(key, -1)
        if at < start:
            if key in ("}}", "%}"):
                k = text.find(key, start)
                at = k if k >= 0 else n
            else:
                c = _BLOCK_CLOSE_RE[key].search(text, start)
                at = c.start() if c else n
            closer_at[key] = at
        return at

    nexts = {"<": text.find("<"), "{{": text.find("{{"), "{%": text.find("{%")}
    while True:
        for key in nexts:
            if 0 <= nexts[key] < pos:
                nexts[key] = text.find(key, pos)
        live = [(at, key) for key, at in nexts.items() if at >= 0]
        if not live:
            return spans
        at, key = min(live)
        if key == "<":
            opener = _BLOCK_OPEN_RE.match(text, at)
            if opener:
                name = opener.group(1).lower()
                c = close_after(name, opener.end())
                if c < n:
                    end = _BLOCK_CLOSE_RE[name].match(text, c).end()
                    spans.append((at, end))
                    pos = end
                    continue
            tag = _PAGE_QUOTED_TAG_RE.match(text, at) or _PAGE_TAG_RE.match(text, at)
            if tag:
                spans.append((at, tag.end()))
                pos = tag.end()
            else:
                pos = at + 1
                nexts["<"] = text.find("<", pos)
            continue
        c = close_after("}}" if key == "{{" else "%}", at + 2)
        if c < n:
            spans.append((at, c + 2))
            pos = c + 2
        else:
            nexts[key] = -1             # no closer anywhere after: no later opener of this kind closes either
            pos = at + 1


def _delimited_spans(text: str, pairs: tuple) -> list[tuple[int, int]]:
    """(start, end) of each `open ... close` span for the (open, close) pairs given, leftmost first and the first
    close after each open, as `re.finditer` with `open.*?close|...` finds them, in one pass."""
    spans, pos = [], 0
    nexts = {o: text.find(o) for o, _ in pairs}
    closes = dict(pairs)
    while True:
        for o in nexts:
            if 0 <= nexts[o] < pos:
                nexts[o] = text.find(o, pos)
        live = [(at, -len(o), o) for o, at in nexts.items() if at >= 0]
        if not live:
            return spans
        at, _, o = min(live)
        c = text.find(closes[o], at + len(o))
        if c < 0:
            nexts[o] = -1           # nothing closes it, so nothing later of this kind closes either
            continue
        spans.append((at, c + len(closes[o])))
        pos = c + len(closes[o])


def _blank_spans(text: str, spans: list, repl) -> str:
    """`text` with each span replaced by `repl(span_text)`."""
    out, last = [], 0
    for a, b in spans:
        out.append(text[last:a])
        out.append(repl(text[a:b]))
        last = b
    out.append(text[last:])
    return "".join(out)


_MARKUP_COMMENT_PAIRS = (("<!--", "-->"), ("{#", "#}"))


def _newlines_only(s: str) -> str:
    return "\n" * s.count("\n")


def _spaces_keep_newlines(s: str) -> str:
    return re.sub(r"[^\n]", " ", s)


_PAGE_INERT_TAG_RE = re.compile(
    r"""<!DOCTYPE[^<>]*>|<meta\b[^<>]*>"""
    r"""|<link\b[^<>]*\brel\s*=\s*['"]?(?:canonical|alternate|author|license|next|prev|me|help|search)\b"""
    # `rel="alternate stylesheet"` is a stylesheet the browser loads
    r"""(?![\w\s-]*\b(?:stylesheet|icon|preload|prefetch|modulepreload|manifest)\b)[^<>]*>""",
    re.S | re.I)
# A letter, digit or address punctuation written as a character reference (`h&#116;tps`, `https:&#47;&#47;host`,
# `&#x68;ttps`, `https&colon;//host`): the page reads it as the character, so it is read as the character here (a
# quote or an angle bracket is left as written, so a tag keeps the shape it has)
_PUNCT_ENTITY_RE = re.compile(r"&#(?:0*(\d{1,7})(?!\d)|[xX]0*([0-9a-fA-F]{1,6})(?![0-9a-fA-F]));?|&(sol|colon|period);")
_PUNCT_ENTITY_CHARS = {"sol": "/", "colon": ":", "period": "."}
_ENTITY_DECODED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/:.-_@?#=%&+~")


def _entity_char(e: re.Match) -> str:
    """The character a reference `_PUNCT_ENTITY_RE` matched stands for, or the reference itself when it is not one of
    the characters an address is written with."""
    if e.group(3):
        return _PUNCT_ENTITY_CHARS[e.group(3).lower()]
    code = int(e.group(1)) if e.group(1) else int(e.group(2), 16)
    ch = chr(code) if code < 128 else ""
    return ch if ch in _ENTITY_DECODED and ch else e.group(0)


_SCHEME_NO_SLASH_RE = re.compile(r"""(=\s*['"]?)(https?|wss?|ftp):/?(?=[A-Za-z0-9][\w-]*\.[\w.-]*[A-Za-z]{2})""",
                                 re.IGNORECASE)


def _decode_punctuation_entities(text: str) -> str:
    """`text` with the letters, digits and punctuation of an address written as character references inside a tag (an
    attribute's value) read as those characters. The text of a script or a style is not decoded by the browser and is left as it is."""
    if "&" not in text and ":" not in text:
        return text

    def tag(m: re.Match) -> str:
        t = m.group(0)
        if "&" in t:
            t = _PUNCT_ENTITY_RE.sub(_entity_char, t)
        # `src="https:host/x"`: a browser reads a special scheme with no slashes as `https://host/x`
        return _SCHEME_NO_SLASH_RE.sub(lambda s: s.group(1) + s.group(2) + "://", t) if ":" in t else t
    return re.sub(r"<[A-Za-z][^<>]*>", tag, text)
_QUOTED_URL_RE = re.compile(r"""(['"`])https?://[^'"`\s]*\1""", re.IGNORECASE)


_URL_NO_HOST_RE = re.compile(r"""\b(?:https?|wss?|ftps?):///""", re.IGNORECASE)
# (the user information ends at the last `@` before the path, query or fragment: `http://a@b@host/`, never one after
# them: `http://evil.example.com#@localhost` is evil.example.com)
_URL_HOST_RE = re.compile(r"""\b(?:https?|wss?|ftps?)://(?:[^\s"'`<>/?#]*@)?(\[[^\]]*\]|[^\s"'`<>/:?#)\]\\+,;@]+)""", re.IGNORECASE)
_LOOPBACK_HOST_RE = re.compile(
    r"""localhost\.?|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|[\w-]+\.localhost\.?"""
    # the page's own host, written as a template: `ws://${location.host}/ws`
    r"""|\$\{\s*(?:window\.|document\.)?location\.host(?:name)?\s*\}"""
    # this machine's own name in a shell line: `http://$(hostname):8081`, `$(hostname -f)`, `$HOSTNAME`
    # (bash's own `$HOSTNAME` only: a lower-case `$hostname` is an ordinary variable and may hold any host)
    # (a URL's host is read up to the first `)` or space, so `$(hostname -f)` arrives as `$(hostname`)
    r"""|\$\(\s*hostname\b[^)]*\)?|(?-i:\$\{?HOSTNAME\}?)""", re.IGNORECASE)


# The W3C's namespace names (`http://www.w3.org/2000/svg`, `.../1999/xhtml`, `.../XML/1998/namespace`).
# Code hands them to `createElementNS` and to XML parsers as identifiers. Nothing fetches them.
_NAMESPACE_NAME_RE = re.compile(r"""https?://www\.w3\.org/(?:\d{4}|XML)/""", re.IGNORECASE)


_XML_QNAME_RE = re.compile(r"""\{[a-z][a-z0-9+.-]*:[^{}\s]*\}[\w.-]*$""", re.IGNORECASE)


_DATA_SCRIPT_TYPE_RE = re.compile(r"""\btype\s*=\s*['"]?[\w./+-]*json""", re.IGNORECASE)
# `a[href^='https://docs.python.org/']`: an attribute selector with an address in it.
_CSS_SELECTOR_URL_RE = re.compile(r"""\[\s*[\w-]+\s*[~|^$*]?=\s*['"]?[^\]\n]*://[^\]\n]*\]""")
# Attributes whose value is text shown to a person.
_SHOWN_TEXT_ATTR_RE = re.compile(r"""\b(?:title|alt|placeholder|aria-label)\s*=\s*(['"])[^'"]*\1""", re.IGNORECASE)
_DSN_HOST_RE = re.compile(r"""^[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?(\[[^\]]*\]|[^\s/:?#,]+)""", re.IGNORECASE)


def _dsn_hosts(text: str) -> list[str] | None:
    """Every host a connection string names: each of a comma-separated list (`postgresql://a,b:5433/db`), and a
    `host=` or `hostaddr=` in its query (which libpq takes over the address part). A directory is a socket on this
    machine (`localhost`). None when the text is not a connection string; empty when it names no host
    (`postgresql:///db`)."""
    from urllib.parse import parse_qsl
    m = re.match(r"(?i)[a-z][a-z0-9+.-]*://([^/?#]*)[^?#]*(?:\?([^#]*))?", text.strip().strip("'\""))
    if not m:
        return None
    hosts = []
    for h in m.group(1).rpartition("@")[2].split(","):
        if h.startswith("[") and "]" in h:
            h = h[:h.index("]") + 1]            # an IPv6 address keeps its brackets, as hosts are written in a URL
        elif h.count(":") == 1:
            h = h.split(":", 1)[0]
        if h:
            hosts.append(h)
    for key, value in parse_qsl(m.group(2) or "", keep_blank_values=False):
        if key.lower() in ("host", "hostaddr"):
            hosts += [h for h in value.split(",") if h]
    # a directory (`/var/run/postgresql`, or written as `%2Fvar%2Frun%2Fpostgresql`) is a socket on this machine
    return ["localhost" if h.startswith("/") or h.lower().startswith("%2f") else h for h in hosts]


def _dsn_is_loopback(text: str) -> bool:
    """`clickhouse://localhost`, `amqp://guest:guest@127.0.0.1:5672/`: every host it names is this machine. One that
    names no host (`postgresql:///db`) connects to the PostgreSQL or MySQL client's default, a socket on this
    machine (another service's client with no host goes to its own default, which may be anywhere)."""
    hosts = _dsn_hosts(text)
    if re.match(r"(?i)\s*['\"]?(?:unix|[a-z]+\+(?:socket|unix))://", text):
        return True             # `redis+socket:///tmp/redis.sock`, `unix:///var/run/x.sock`: a socket on this machine
    if hosts == []:
        return re.match(r"(?i)\s*['\"]?(?:postgres(?:ql)?|mysql|mariadb)(?:\+[\w-]+)?://", text) is not None
    return bool(hosts) and all(_LOOPBACK_HOST_RE.fullmatch(h) is not None for h in hosts)


def _has_external_url(text: str) -> bool:
    """A URL whose host is not this machine. `http://localhost:8000` and `ws://127.0.0.1` are
    addresses, and they are not external references. Neither is a W3C namespace name."""
    for m in _URL_HOST_RE.finditer(text):
        if _LOOPBACK_HOST_RE.fullmatch(m.group(1)) or _NAMESPACE_NAME_RE.match(text, m.start()):
            continue
        return True
    return False


# A host that names no place by itself: one label with no dot (`elasticsearch`, a compose service or a hosts entry)
# or a variable (`${es_node_name}`). Where it points is decided where the line runs.
_UNSHOWN_HOST_RE = re.compile(r"[A-Za-z][\w-]*|\$\{?\w+\}?")


# A command that opens an address in the default browser: `Start-Process "https://..."`, cmd's `start "" https://...`,
# `Invoke-Item`, `explorer`, `xdg-open`, macOS's `open`
_URL_OPENER_RE = re.compile(
    r"""(?i)(?:^|[;&|({]\s*|(?<![\w-])/[ck]\s+)(?:start-process|saps|start|invoke-item|ii|explorer(?:\.exe)?|xdg-open|open)"""
    r"""(?:\s+"[^"]*"(?=\s+['"]?(?:https?|ftp)://))?(?:\s+-filepath)?\s+['"]?(?:https?|ftp)://""")


# ssh options that send a connection somewhere other than the host written: a jump host (`-J`, `ProxyJump`), a proxy
# command, a `HostName` that replaces the host, a `Host` block chosen from a configuration file (`-F`); for rsync, the
# same inside its remote shell (`-e "ssh -J bastion"`, `--rsh=...`)
_SSH_ROUTED_RE = re.compile(r"""(?i)(?<![\w-])-J\s*\S|proxyjump|proxycommand|(?<![\w-])-o\s*['"]?hostname\b"""
                            # forwarding (`-L 8080:db:5432`, `-R`, `-W db:22`, `-D 1080`): the far end connects on
                            r"""|(?<![\w-])-[LRWD]\s*\S|localforward|remoteforward|dynamicforward""")


def _ssh_routed(tool: str, args: str) -> bool:
    """`ssh -J bastion localhost`, `scp -o ProxyJump=b localhost:/x .`, `ssh -F conf localhost`: where the command
    connects is not the host it names."""
    tool = tool.lower().rsplit("/", 1)[-1]
    if tool == "rsync":
        shell = re.search(r"""(?:(?<!\S)-e\s*|--rsh[=\s])(?:"([^"]*)"|'([^']*)'|(\S+))""", args)
        if not shell:
            return False
        args = shell.group(1) or shell.group(2) or shell.group(3) or ""
    return bool(_SSH_ROUTED_RE.search(args) or re.search(r"(?<![\w-])-F(?:\s|\S)", args))


def _script_url_finding(rel: str, lineno: int, text: str) -> Finding:
    """The finding for a script line holding an address that is not this machine's: `external-url`, or, when every
    such address has a host that names no place by itself, the smaller claim."""
    hosts = [m.group(1) for m in _URL_HOST_RE.finditer(text)
             if not (_LOOPBACK_HOST_RE.fullmatch(m.group(1)) or _NAMESPACE_NAME_RE.match(text, m.start()))]
    if hosts and all(_UNSHOWN_HOST_RE.fullmatch(h) for h in hosts):
        return Finding(rel, lineno, "unresolved-call",
                       f"an address whose host ({hosts[0]}) is a name resolved where the line runs (a compose service, "
                       "a hosts entry or a variable); whether it is this machine or another is NOT shown")
    if hosts and _URL_OPENER_RE.search(text):
        return Finding(rel, lineno, "script-network-command",
                       "opens an address on another machine in the default browser, which fetches it")
    return Finding(rel, lineno, "external-url", "external URL in a script, build recipe or pipeline file")


def _strip_origin_only_urls(line: str) -> str:
    """Blank just the origin URL string in each match (the last quoted URL), keeping the rest of the call, so
    `postMessage(fetch("https://e.com"), "https://o.com")` still shows its fetch URL."""
    def blank(m: re.Match) -> str:
        s = m.group(0)
        u = list(_QUOTED_URL_RE.finditer(s))[-1]
        return s[:u.start()] + '""' + s[u.end():]
    return ORIGIN_ONLY_URL_RE.sub(blank, line)


TEXT_EXTS = {".py", ".pyw"}
# Path-configuration files. Python's `site` module reads every `*.pth` in a site
# directory at interpreter start and EXECUTES each line that begins with `import`.
# Those lines are Python source in a file that is not named like Python source.
PTH_EXTS = {".pth"}
_PTH_SNIFF_BYTES = 8192
NOTEBOOK_EXTS = {".ipynb"}
# Markup, stylesheets and templates: checked by pattern for external references.
MARKUP_EXTS = {".html", ".htm", ".xhtml", ".vue", ".svelte", ".astro", ".mdx", ".svg", ".css",
               ".j2", ".jinja", ".jinja2", ".njk", ".hbs", ".ejs", ".twig", ".erb"}
# JavaScript and TypeScript share the source-aware checker (see _check_ecmascript):
# comments are stripped first, so a licence header or a JSDoc link is not a finding.
JS_EXTS = {".js", ".mjs", ".cjs", ".jsx"}
TS_EXTS = {".ts", ".tsx", ".mts", ".cts"}
# Executable content this tool cannot read. Each one found is reported, never passed over.
ARTIFACT_EXTS = {".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib", ".whl", ".egg", ".zip", ".jar",
                 ".pyz", ".pyx", ".pxd", ".wasm",
                 # executables, object code and other languages' compiled output
                 ".exe", ".msi", ".o", ".a", ".lib", ".class", ".node",
                 # archives: whatever they hold was not read
                 ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
                 # serialised objects that run code when they are loaded
                 ".pkl", ".pickle", ".joblib", ".pt", ".ckpt"}
# Read as text: a file's digest is taken with CRLF line endings folded to LF, so a checkout
# that converted line endings gives the same subject digest as one that did not.
# Artifacts are hashed byte for byte.
_SHEBANG_SNIFF_BYTES = 256
# Scripts, build recipes and pipeline definitions: checked line by line for commands
# that reach the network. By extension, by file name, or by a shell shebang.
SCRIPT_EXTS = {".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".psm1", ".bat", ".cmd"}
SCRIPT_NAMES = {"dockerfile", "containerfile", "makefile", "gnumakefile", "justfile", "procfile",
                "tox.ini", ".gitlab-ci.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml", "jenkinsfile",
                # other hosted CI services' pipeline files, and a GitHub action's own definition
                ".travis.yml", ".drone.yml", "appveyor.yml", ".appveyor.yml", "cloudbuild.yaml", "cloudbuild.yml",
                "buildspec.yml", "buildspec.yaml", ".cirrus.yml", ".woodpecker.yml", "codemagic.yaml", "bitrise.yml",
                "action.yml", "action.yaml"}
_PIPELINE_DIRS = (".github/workflows/", ".circleci/", ".gitlab/ci/", ".buildkite/", ".woodpecker/",
                  ".azure-pipelines/")
_BARE_TOOLS = {"curl", "wget", "aria2c", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet",
               "nslookup", "dig", "certutil", "bitsadmin", "uvx", "npx"}
_YAML_LABEL_RE = re.compile(r"^-?\s*(?:name|description|title|summary)\s*:")
# `xargs`, its options (`-n1`, `-a urls.txt`, `-I {}`, `-P 4`, `--null`) and then the program it runs, ending where
# that program is named
_XARGS_RUNS_RE = re.compile(r"(?:^|[|;&(]|\s)xargs(?:\s+(?:-[aEdeIiLlnPs](?:\s*[^\s-]\S*)?|-[\w-]+|--[\w-]+(?:=\S+)?))*\s+$")
# ` # ...` to the end of a line is a comment in shell, Make, Dockerfiles and YAML.
_TRAILING_COMMENT_RE = re.compile(r"(?:^|\s|(?<=[;&|]))#.*$")     # `true;#x` comments out `x` too
_SCRIPT_NET_COMMAND_RE = re.compile(
    # (the variable forms are bounded: a run of unclosed `$(` must not make one line quadratic)
    r"(?<![\w./-])(?:(?:[\w.~${}()-]{0,256}/)*(?:bin|sbin|Scripts|\$[A-Za-z_]\w*|\$\{[^}/\n]{0,256}\}|\$\([^)/\n]{0,256}\))/)?"
    r"(pkg\s+install|pacman\s+-S\w*|zypper\s+install|choco\s+install|winget\s+install|snap\s+install"
    r"|curl|wget|aria2c|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|telnet|nslookup|dig"
    # options may stand between a package manager and its subcommand: `apt-get -y update`, `pip -q install`
    # Windows certutil only with a verb that fetches (`-urlcache`); NSS certutil (`-d <db> -A`) works on a local file
    r"|certutil(?=[^\n]*?[\s/-](?:urlcache|url|verifyctl|syncwithwu|urlfetch)\b)|bitsadmin|pip(?:3(?:\.\d+)?)?(?:\s+-{1,2}[\w=.-]+)*\s+(?:install|download)|pipx\s+(?:install|run)|uv\s+pip(?=\s+(?:install|sync|compile)\b)|uv\s+(?:add|sync|tool)|uvx"
    r"|(?:conda|mamba)(?:\s+-{1,2}[\w=.-]+)*\s+install|npm(?:\s+-{1,2}[\w=.-]+)*\s+(?:install|i|ci|publish|add|it|install-test|install-ci-test|isntall)(?![\w-])|npx|yarn\s+(?:add|install)|pnpm\s+(?:add|install|i)"
    r"|apt(?:-get)?(?:\s+-{1,2}[\w=.-]+)*\s+(?:install|update)|apk(?:\s+-{1,2}[\w=.-]+)*\s+add"
    r"|dnf(?:\s+-{1,2}[\w=.-]+)*\s+install|yum(?:\s+-{1,2}[\w=.-]+)*\s+install|brew\s+install|gem\s+install"
    r"|cargo\s+install|go\s+(?:get|install)|docker\s+(?:pull|push|login)|podman\s+(?:pull|push)"
    r"|git(?:\s+(?:-[Cc]\s+\S+|--(?:git-dir|work-tree|namespace|config-env)(?:=|\s+)\S+|--[\w-]+(?:=\S+)?|-[pP]))*"
    r"\s+(?:clone|pull|fetch|push|submodule(?=(?:\s+-{1,2}[\w=-]+)*\s+(?:update|add)\b)|ls-remote"
    r"|lfs\s+(?:pull|fetch|push|clone)|remote\s+(?:update|prune|show|set-head)|archive(?=[^\n;&|]*\s--remote\b)|send-email|imap-send|(?:svn|p4)\s+(?:fetch|clone|rebase|dcommit|sync|submit|init)|maintenance\s+run(?=[^\n;&|]*--task=prefetch))"
    r"|gh\s+\w+|twine(?:\s+-{1,2}[\w=.-]+)*\s+upload"
    r"|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer|DownloadString|DownloadFile|Net\.WebClient"
    r"|(?:Install|Save|Update)-(?:Module|Package|Script|PSResource)|Install-PackageProvider|scoop\s+(?:install|update)"
    # PowerShell cmdlets that mail, resolve, probe, fetch help or modules, or run on another computer
    r"|Send-MailMessage|Enter-PSSession|New-PSSession|Test-NetConnection|Test-Connection|Resolve-DnsName|Update-Help"
    r"|Find-(?:Module|Package|Script|PSResource)|Publish-(?:Module|Script|PSResource)"
    # a cmdlet given another computer (`-ComputerName`, `-Session`, `-ToSession`, `-FromSession`, `-CimSession`), and
    # Windows' remote shells and consoles (`winrs -r:host`, `mstsc /v:host`, `wmic /node:host`)
    r"|[A-Z][a-z]+-[A-Z][A-Za-z]+(?=[^\n;|]*\s-(?:ComputerName|Cn|Session|ToSession|FromSession|CimSession)\s+"
    r"(?!localhost\b|\.(?:\s|$)|127\.0\.0\.1\b|\$env:COMPUTERNAME\b)\S)"
    r"|winrs(?=\s+-r(?:emote)?:)|mstsc(?=\s+/v:)|wmic(?=\s+/node:)"
    r"|(?:qwinsta|rwinsta|quser|qprocess|logoff|msg)(?=[^\n;|&]*\s/server:(?!localhost\b)\w))"
    # not part of a longer word, and not a URL scheme (`ssh://host`) or a setting's name (`ssh=`)
    r"(?:\.exe)?(?![\w.-]|://|=|/|\\|:\S)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# ECMAScript / TypeScript egress surface
#
# Bare module specifiers that can reach the network. Matched on the package
# ROOT, so "@sentry/node" matches the "@sentry" scope entry and
# "axios/lib/adapters/http" matches "axios".
# ---------------------------------------------------------------------------
JS_NET_MODULES = {
    # Node builtins
    "http", "https", "http2", "net", "tls", "dgram", "dns", "cluster",
    "node:http", "node:https", "node:http2", "node:net", "node:tls",
    "node:dgram", "node:dns",
    # HTTP clients
    "axios", "node-fetch", "got", "superagent", "request", "undici", "ky",
    "phin", "needle", "bent", "wretch",
    # Realtime / sockets
    "ws", "socket.io", "socket.io-client", "sockjs", "sockjs-client",
    "eventsource", "pusher-js", "ably",
    # GraphQL / RPC clients
    "apollo-client", "@apollo", "graphql-request", "urql", "grpc", "@grpc",
    # Telemetry / analytics -- the category the Python blocklist misses too
    "@sentry", "posthog-js", "posthog-node", "mixpanel", "mixpanel-browser",
    "@segment", "analytics-node", "@datadog", "dd-trace", "newrelic",
    "bugsnag", "@bugsnag", "rollbar", "@opentelemetry", "elastic-apm-node",
    "@amplitude", "amplitude-js", "logrocket", "@sentry/browser",
    # Cloud SDKs (egress by definition)
    "aws-sdk", "@aws-sdk", "@google-cloud", "googleapis", "@azure",
    "firebase", "@firebase", "@supabase",
    # The Python and JavaScript lists are kept aligned by category, so a reader
    # can predict from one what the other catches.
    # Database and cache clients
    "pg", "mysql", "mysql2", "mongodb", "mongoose", "redis", "ioredis",
    "cassandra-driver", "@elastic/elasticsearch", "neo4j-driver",
    # Mail, messaging and brokers
    "nodemailer", "mqtt", "amqplib", "kafkajs", "nats", "bullmq",
    # SaaS API clients
    "stripe", "twilio", "@sendgrid", "@slack", "@octokit", "openai",
    "@anthropic-ai", "algoliasearch",
    # fetch polyfills -- these ARE the network call under another name
    "isomorphic-fetch", "cross-fetch", "whatwg-fetch", "unfetch",
    # Browser automation and crawlers
    "puppeteer", "playwright", "selenium-webdriver", "cheerio-httpcli",
}

# child_process is the JS analogue of Python's subprocess: a shell string or an
# argv list can invoke curl/wget/nc and leave the process entirely.
JS_PROCESS_MODULES = {"child_process", "node:child_process"}

# import/require detection. Covers: import x from 'm'; import 'm';
# import * as x from 'm'; import {a} from 'm'; export ... from 'm';
# require('m'); await import('m').
# The clause between `import` (or `export`) and `from` holds no second `import` or `export`: bounding it there keeps a
# file of many unfinished imports linear rather than quadratic.
_JS_IMPORT_RE = re.compile(
    r"""(?:\bimport\b(?:(?!\bimport\b)[^;'"])*?\bfrom\s*|\bimport\s*|\bexport\b(?:(?!\b(?:import|export)\b)[^;'"])*?\bfrom\s*|"""
    r"""\brequire\s*(?:\.\s*call\s*\(\s*[\w$.]+\s*,\s*|\(\s*)|\bimport\s*\(\s*"""
    # `createRequire(import.meta.url)("https")`: the function createRequire returns is require
    r"""|\bcreateRequire\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\(\s*)(?:['"]([^'"]+)['"]|`([^`$\n]+)`)"""
    # a string joined to more (`require("ht" + "tps")`) is not the module's name: the name is computed
    r"""(?!\s*\+)""",
    re.MULTILINE,
)


def _js_imports(src: str):
    """(match, module, type_only) for each import or require that is code: one inside a string literal is text.
    A TypeScript `import type` / `export type` is erased when compiled, so it loads nothing (`type_only`), though it
    still names a package the tree depends on. A template literal with no `${` (`` require(`https`) ``) names its
    module as plainly as a quoted one."""
    blank = _strip_js_comments(src, blank_strings=True)
    for m in _JS_IMPORT_RE.finditer(src):
        if blank[m.start()] != src[m.start()]:
            continue
        spec = m.group(1) if m.group(1) is not None else m.group(2)
        if m.group(2) is not None and not re.match(r"(?:require|import|createRequire)\s*[(.]", m.group(0)):
            continue                # a template literal is a module name only in `require(...)` / `import(...)`
        yield m, spec, re.match(r"(?:import|export)\s+type\b", m.group(0)) is not None

# Direct network call expressions.
# NOTE the \b placement: it anchors ONLY the identifier-initial alternatives,
# so `prefetchData(` does not match `fetch(`. It deliberately does NOT wrap the
# jQuery branch -- `$` is a non-word character, so a leading \b would require a
# word boundary that ` $.ajax(` never provides, and the pattern would never fire.
_JS_NET_CALL_RE = re.compile(
    r"""(?:\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon|importScripts"""
    r"""|axios(?:\.(?:get|post|put|patch|delete|head|request|all))?"""
    r"""|https?\.(?:get|request)|net\.(?:connect|createConnection)"""
    # the runtimes' own clients: Deno and Bun open connections without importing anything
    r"""|Deno\.(?:connect|connectTls|startTls|listen|listenTls|serve|resolveDns)|Bun\.(?:connect|listen|serve))"""
    r"""|(?:\$|\bjQuery)\.(?:ajax|get|post|getJSON|getScript))\s*(?:\?\.\s*)?\("""
    # `new XMLHttpRequest` with no parentheses is valid and is what minifiers emit; a
    # reference to sendBeacon or a bracketed global (`window["fetch"]`) is the same call.
    r"""|\bnew\s+(?:XMLHttpRequest|WebSocket|EventSource|WebTransport|RTCPeerConnection)\b|\bnavigator\.sendBeacon\b"""
    r"""|\[\s*['"`](?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)['"`]\s*\]"""
    # `const {fetch: f} = globalThis`: the browser's fetch taken under another name
    # (the brace's end is checked first, once, so a long line of words costs one pass)
    r"""|\{(?=[^{}]*\}\s*=\s*(?:window|globalThis|self|global)\b)[^{}]*?\bfetch\b""",
)
_JS_GLOBAL_OWNERS = {"window", "globalThis", "self", "global", "top", "parent"}


def _js_net_calls(code: str) -> tuple[bool, bool]:
    """(a network call is on the line, only a method named `fetch` on some object is).

    `fetch(url)` and `window.fetch(url)` are the browser's fetch. `parser.fetch()` is a method of whatever `parser`
    is. `fetch(e) { ... }` and `function fetch(` define a function; nothing is called there.
    """
    strong = method = False
    for m in _JS_NET_CALL_RE.finditer(code):
        if not m.group(0).startswith("fetch"):
            strong = True
            continue
        close = _js_close_paren(code, m.end() - 1)
        if close is not None and code[close + 1:close + 40].lstrip().startswith("{"):
            continue                                                  # a method or function definition
        before = code[max(0, m.start() - 200):m.start()].rstrip()
        if before.endswith("function") or before.endswith("async function"):
            continue
        if before.endswith("."):
            owner = re.search(r"([\w$]+)\s*\??\.$", before)
            if not (owner and owner.group(1) in _JS_GLOBAL_OWNERS):
                method = True
                continue
        strong = True
    return strong, method


def _js_close_paren(code: str, open_at: int) -> int | None:
    depth = 0
    for k in range(open_at, min(len(code), open_at + 2000)):
        if code[k] == "(":
            depth += 1
        elif code[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return None


_JS_BRACKET_CALL_RE = re.compile(r"""\[\s*['"`](?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)['"`]\s*\]""")
# A string literal on one line, and a URL inside one that comes after at least two words of prose:
# `"Unsupported use. Try https://example.org/help"` is a message someone reads, not an address fetched.
_JS_STRING_RE = re.compile(r"""(["'])((?:\\.|(?!\1)[^\\\n])*)\1""")
def _prose_before_url(text: str) -> bool:
    """`text` ends in two words and a space, as a sentence does before a URL it names: the last word starts with two
    letters, the one before holds two. (Read as words, in linear time: the regular expression this replaces,
    `[A-Za-z]{2,}[^\\s]*\\s+[A-Za-z]{2,}[^\\s]*\\s+$`, backtracked in cubic time over a long run of letters.)"""
    if not text or not text[-1].isspace():
        return False
    parts = text.split()
    return len(parts) >= 2 and re.match(r"[A-Za-z]{2}", parts[-1]) is not None \
        and re.search(r"[A-Za-z]{2}", parts[-2]) is not None


def _blank_prose_urls(js: str) -> str:
    """Blank a URL that sits inside a sentence in a string literal. Same length, same lines.

    Strings are read as `_JS_STRING_RE` reads them, a line at a time: a quote that does not close on its line is read
    again from after it, up to `_JS_LINE_RETRIES` times a line (after that the line's quotes are characters), so one
    long line of quotes costs a bounded number of passes."""
    def blank(body: str) -> str:
        out, last = [], 0
        for u in re.finditer(r"""(?:https?|wss?|ftps?)://[^\s"'`<>]*""", body):
            if _prose_before_url(body[:u.start()]):
                out.append(body[last:u.start()] + " " * (u.end() - u.start()))
                last = u.end()
        out.append(body[last:])
        return "".join(out)

    lines = js.split("\n")
    for k, line in enumerate(lines):
        if "://" not in line:
            continue
        pieces, last, i, fails, n = [], 0, 0, 0, len(line)
        while i < n:
            q = line[i]
            if q not in "\"'":
                i += 1
                continue
            j = i + 1
            while j < n and line[j] != q:
                j += 2 if line[j] == "\\" else 1
            if j < n:
                body = line[i + 1:j]
                if "://" in body:
                    pieces.append(line[last:i + 1] + blank(body))
                    last = j
                i = j + 1
                continue
            fails += 1
            if fails > _JS_LINE_RETRIES:
                break
            i += 1
        pieces.append(line[last:])
        lines[k] = "".join(pieces)
    return "\n".join(lines)


# `import(expr)` where the specifier is not a string literal: what is loaded is decided at run time.
_JS_DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*(?!['"`)])""")
# A `/` begins a regular-expression literal after one of these characters or words; elsewhere it divides.
_JS_REGEX_PREV_CHARS = set("(,=:[!&|?{};+-*%<>~^")
_JS_REGEX_PREV_WORDS = {"return", "typeof", "case", "in", "of", "do", "else", "void", "delete", "throw",
                        "new", "instanceof", "yield", "await", "default"}
# JSX in a file: a closing tag (`</div>`, a fragment's `</>`) or a self-closing one (`<Foo bar={x} />`)
_JSX_TAG_RE = re.compile(r"</[A-Za-z][\w.:-]*\s*>|</>|<[A-Za-z][\w.:-]*(?:\s[^<>]*?)?/>")
# Words a string literal may follow with nothing between (`from"https"`, `import"./a.js"` in minified code).
_JS_STRING_PREV_WORDS = _JS_REGEX_PREV_WORDS | {"from", "import"}


# The start of a JSX element's opening tag: a name, type arguments if any (`<Field<Values> ...>`), then a space, `/`,
# `>` or `{` (not a TypeScript type parameter list: `<T,>`, `<T extends U>`)
_JSX_OPEN_TAG_RE = re.compile(r"<[A-Za-z][\w.:-]*(?:<(?:[^<>\n]|<(?:[^<>\n]|<[^<>\n]*>)*>)*>)?(?![ \t]+extends\b)(?=[\s/>{])")
# A tag with nothing but a name, straight before `(` on its line: an element whose text opens with `(`
# (`<small>(optional)</small>`), or a type parameter list (`const pick: <T>(xs: T[]) => T`)
_JSX_OR_TYPE_PARAMS_RE = re.compile(r"<[A-Za-z][\w.:-]*>[ \t]*\(")
# A closing tag (`</div>`, `</>`)
_JSX_CLOSE_TAG_RE = re.compile(r"</\s*(?:[A-Za-z][\w.:-]*)?\s*>")
# Words an element may follow, as an expression may (`return <p>`, `default <App/>`)
_JSX_BEFORE_WORDS = {"return", "yield", "default", "case", "await", "else", "do", "throw", "in", "of"}


def _jsx_tag_name(opening: str) -> str:
    """The name an opening tag gives (`<Foo.Bar` is `Foo.Bar`; `<Field<Values>` is `Field`)."""
    return re.match(r"<([A-Za-z][\w.:-]*)", opening).group(1)


def _jsx_text_backquote(src: str, i: int, word: str) -> bool:
    """The backquote at `i` sits in JSX text the reading did not follow: after a space that follows a word no expression
    continues from (a keyword such as `return` or `case` may precede a template). (Straight after a `>` it is a
    template: an element's own text is followed, and `styled.div<{...}>` is followed by one.)"""
    j = i - 1
    if j < 0 or src[j] not in " \t":
        return False
    while j >= 0 and src[j] in " \t":
        j -= 1
    return j >= 0 and _js_ident_char(src[j]) and bool(word) and word not in _JS_STRING_PREV_WORDS \
        and word not in ("default", "extends", "export", "yield", "as", "satisfies", "keyof", "infer", "is", "asserts",
                         "readonly", "unique", "return", "typeof", "await")


def _js_ident_char(c: str) -> bool:
    """A character that continues a JavaScript identifier, decided the same way under every Python: ASCII letters,
    digits, `_` and `$`, and every character beyond ASCII (whose Unicode class differs between Python versions)."""
    return c.isascii() and (c.isalnum() or c in "_$") or not c.isascii()

# child_process invocations.
_JS_PROCESS_CALL_RE = re.compile(
    r"""\b(?:child_process\s*\.\s*)?(?:exec|execSync|execFile|execFileSync"""
    r"""|spawn|spawnSync|fork)\s*\(""",
)

_JS_BARE_PROCESS_RE = re.compile(r"""(?<![.\w$])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(""")

# Dynamic code execution -- undecidable payload, flagged unconditionally.
_JS_DYNAMIC_RE = re.compile(r"""(?:\beval\s*\(|\bnew\s+Function\s*\(|\bvm\s*\.\s*(?:runInThisContext|runInNewContext"""
                            r"""|runInContext|compileFunction)\s*\(|\bnew\s+vm\s*\.\s*Script\s*\("""
                            r"""|\bnew\s+Worker\s*\([^\n]*\beval\s*:\s*true)""")
# `require(name)` with a name computed while running (not a string literal, not a template with no
# substitution); `require.resolve(...)` looks a path up and loads nothing
_JS_DYNAMIC_REQUIRE_RE = re.compile(r"""(?<![\w$.])(?<!function )require\s*\(\s*(?:(?![\s)'"]|`[^`$]*`)"""
                                    r"""|(['"`])[^'"`\n]*\1\s*\+)""")
# Setting `src` on an element this file creates loads the address it is given (`new Image().src = u`).
_JS_ELEMENT_CREATE_RE = re.compile(
    r"""\bnew\s+Image\b|\bcreateElement\s*\(\s*['"`](?:img|script|iframe|link|audio|video|source|embed|object)['"`]""",
    re.IGNORECASE)
_JS_SRC_ASSIGN_RE = re.compile(r"""\.\s*src\s*=(?!=)""")
# a name bound to an element that loads its `src`: `const img = document.createElement('img')`, `s = new Image()`
_JS_ELEMENT_NAME_RE = re.compile(
    r"""\b([\w$]+)\s*=\s*(?:new\s+Image\b|(?:[\w$.]+\.)?createElement\s*\(\s*['"`](?:img|script|iframe|audio|video|source|embed)['"`])""",
    re.IGNORECASE)


def _created_element_src_re(src: str) -> re.Pattern | None:
    """The pattern of a `src` set on an element this file creates: on a name bound to one, or on the creation itself
    (`document.head.appendChild(document.createElement("script")).src = u`, `(new Image).src = u`). None when the file
    creates none."""
    if not _JS_ELEMENT_CREATE_RE.search(src):
        return None
    names = sorted({m.group(1) for m in _JS_ELEMENT_NAME_RE.finditer(src)})
    # `.src = u` or `.setAttribute('src', u)`
    sets = r"""\s*\.\s*(?:src\s*=(?!=)|setAttribute\s*\(\s*['"`]src['"`]\s*,)"""
    on_name = r"(?<![\w$.])(?:" + "|".join(re.escape(n) for n in names) + r")" + sets if names else None
    on_creation = r"""(?:createElement\s*\(\s*['"`]\w+['"`]\s*\)|new\s+Image\s*(?:\(\s*\))?)\s*\)*""" + sets
    return re.compile(f"{on_name}|{on_creation}" if on_name else on_creation, re.IGNORECASE)
_JS_LOCAL_SRC_RE = re.compile(r"""\s*(?:['"`]\s*(?:data|blob|javascript|about):|(['"`])\1|[\w$.]+\.toDataURL\s*\("""
                              r"""|URL\.createObjectURL\s*\(|null\b|undefined\b)""", re.IGNORECASE)

# A network binary invoked through child_process -- the exact gap measured in
# the Python auditor (argv-list form without shell=True is invisible there).
_JS_NET_BINARY_RE = re.compile(
    r"""['"](?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|ftp|telnet)['"\s]""",
)


# Node's own modules. Importing one of these is not importing a third-party package.
NODE_BUILTIN_MODULES = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "test", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib",
}


def _js_is_unlisted(spec: str) -> bool:
    """A bare specifier that names a third-party package this tool has no entry for. Relative
    paths, path aliases (`@/x`, `~/x`, `#x`), URLs, Node's own modules and listed names are not."""
    if not spec or spec[0] in "./~#" or spec.startswith(("@/", "node:", "http:", "https:", "data:", "file:", "virtual:")):
        return False
    if not re.fullmatch(r"(?:@[\w.-]+/)?[\w.-]+(?:/[\w./-]+)?", spec):
        return False
    root = _js_module_root(spec)
    first = spec.split("/")[0] if not spec.startswith("@") else "/".join(spec.split("/")[:2])
    if root in JS_NET_MODULES or spec in JS_NET_MODULES or first in JS_NET_MODULES or root in JS_PROCESS_MODULES:
        return False
    return first.split("/")[0] not in NODE_BUILTIN_MODULES


def _js_module_root(spec: str) -> str:
    """Package root of a bare specifier. '@scope/pkg/sub' -> '@scope'."""
    if spec.startswith("@"):
        return spec.split("/")[0]
    return spec.split("/")[0]


def _js_code_only(src: str) -> str:
    """The same text with comments AND the contents of string literals blanked.

    What is left is code: a call named `fetch(` here is a call, and the word `WebSocket`
    inside a block of embedded data is gone. Quotes, line breaks and the `${...}` parts of
    a template literal are kept, since those parts are code. Used only to decide whether a
    line CALLS something; addresses are still read from the text with its strings intact.
    """
    return _strip_js_comments(src, blank_strings=True)


def _strip_js_comments(src: str, blank_strings: bool = False) -> str:
    """Blank out comments, PRESERVING string literals and line numbers.

    Strings are kept deliberately: a hardcoded URL inside a string literal is
    real egress evidence, while the same URL in a JSDoc block is not. Blanking
    comments to spaces (and keeping newlines) means reported line numbers still
    point at the real line.

    Regular-expression literals are recognised by what precedes the `/` (an
    operator, an opening bracket, or a keyword such as `return`), and copied
    through whole, so the `//` inside `/^https?:\\/\\//` is not read as a comment.
    This is a heuristic, not an ECMAScript tokeniser: a regex literal beginning
    `/*`, or one that follows the `)` of anything but an `if`/`while`/`for` condition,
    is still misread. A quote straight after a letter (`Don't` in JSX text) opens no
    string unless the word is one a string may follow (`from"x"`); a `'` or `"` string
    ends on its line; a backquote or `/*` still open at the end of the file was text.

    A backquote after a plain word and a space is JSX text (`<p>Press ` to open</p>`) or a tagged template
    (`sql `SELECT 1``), and either misreading hides the code up to the next backquote. In a file that may hold JSX
    (a closing or a self-closing tag anywhere in it) the text is read both ways and what either reading keeps as code
    is kept: the two readings are aligned character for character with the file, so they merge by position.
    """
    plain = _scan_js(src, blank_strings, False)
    if _JSX_TAG_RE.search(src) is None:
        return plain
    # Two JSX readings: one opens every element it can; the other takes a bare `<Name>` straight before `(` for a
    # type parameter list, which the first reads as an element. A reading that wrongly opens an element only blanks
    # text, and the others keep the code.
    readings = [_scan_js(src, blank_strings, True)]
    if _JSX_OR_TYPE_PARAMS_RE.search(src):
        readings.append(_scan_js(src, blank_strings, True, type_params=True))
    readings.append(plain)
    if any(len(r) != len(plain) for r in readings):
        return plain
    if blank_strings:
        # code in any reading is code
        return "".join(next((c for c in cs if c != " "), " ") for cs in zip(*readings))
    # With strings kept: the first reading, with what each other reading reads as code where those before it kept
    # nothing, and the '...' and "..." strings inside that code (`require("nodemailer")` after JSX text one reading
    # took for a comment). A string an earlier reading keeps (`require("axios")` after a glob the plain reading took
    # for a comment) stays, and text a later reading took for a template's but an earlier one for a comment stays a
    # comment.
    merged = readings[0]
    for k, kept in enumerate(readings[1:], 1):
        code = _scan_js(src, True, k < len(readings) - 1, type_params=True) if k < len(readings) - 1 \
            else _scan_js(src, True, False)
        merged = _js_fill(merged, kept, code)
    return merged


def _js_fill(base: str, kept: str, code: str) -> str:
    """`base`, with `kept` (another reading, strings kept) where `base` holds nothing and that reading has code
    (`code` is it with strings blanked), each '...' or "..." string inside that code taken whole."""
    out: list[str] = []
    i, n = 0, len(base)
    while i < n:
        a, cb = base[i], code[i]
        if a != " " or cb == " ":
            out.append(a)
            i += 1
            continue
        out.append(kept[i])
        if cb in "'\"":
            # that reading's string, through its closing quote (strings end on their line)
            j = i + 1
            while j < n and code[j] != cb and code[j] != "\n":
                j += 1
            if j < n and code[j] == cb:
                out.append(kept[i + 1:j + 1])
                i = j + 1
                continue
        i += 1
    return "".join(out)


_JS_LINE_RETRIES = 32      # failed string or regular-expression openings followed on one line


def _scan_js(src: str, blank_strings: bool, jsx: bool, type_params: bool = False) -> str:
    """One reading of `_strip_js_comments`. With `jsx`, the JSX elements are followed: a tag where an expression may
    start (`return <p>`, `=> <li>`, `(<div`) opens an element whose children are text, apart from the `{...}`
    expressions and the tags inside them, until its closing tag; text is blanked, so nothing in it (an apostrophe, a
    backquote, `/*`, `//`) opens a string, a template or a comment. Outside the elements this reading follows, a
    backquote after a plain word and a space, or straight after a tag's `>`, is text. Without `jsx`, every backquote
    outside a string or comment opens a template."""
    out: list[str] = []
    i, n = 0, len(src)
    in_line = in_block = False
    quote: str | None = None
    prev = ""          # last significant character copied outside a comment
    word = ""          # the identifier or keyword that character ends, if any
    run_start = -1     # where the identifier being read began (its text is taken only when it is needed)
    parens: list[bool] = []     # for each open `(`: does it follow `if`, `while`, `for` or `with`?
    after_control = False       # the last `)` closed such a condition: a `/` after it starts a regex
    quote_at = quote_out = -1   # where the open '...' or "..." string began, in src and in out
    block_at = block_out = -1   # where the open /* comment began
    no_template = no_block = False      # a backquote or `/*` that never closed was text: later ones are too
    # The JSX elements this reading is inside: "children" (the text of an element), ["tag", braces] (an opening tag's
    # attributes), ["expr", braces] (a `{...}` inside children)
    elements: list = []
    # An element has text only where the file closes it: `</Name>` somewhere in the file (`</>` for a fragment). A
    # tag that is never closed (`<T>` of a type parameter list) is read as one with no text.
    closed_names = {m.group(1) for m in re.finditer(r"</\s*([A-Za-z][\w.:-]*)?\s*>", src)} if jsx else set()
    closed_names.discard(None)
    fragments_close = jsx and "</>" in src
    # A `'` or `"` string that does not close on its line is read again from after its quote, and a `/` that may begin
    # a regular expression is followed to the end of its line: on one long line of quotes or slashes that is quadratic.
    # After `_JS_LINE_RETRIES` such attempts on a line, the rest of that line's quotes and slashes are characters.
    string_fails = regex_fails = 0
    string_fail_at = regex_fail_at = -1     # the line end the failures counted are on
    no_string_until = no_regex_until = -1

    def current_word() -> str:
        if run_start >= 0:
            return src[run_start:i] if i - run_start <= 24 else "<identifier>"
        return word

    while True:
        if i >= n:
            # A template literal or block comment still open at the end of the file was text (a backquote in JSX
            # text, `/*` in prose): read again from after its opening, as code.
            if quote == "`":
                del out[quote_out:]
                out.append("`")
                i, quote, no_template = quote_at + 1, None, True
                prev, word, run_start = "`", "", -1
                continue
            if quote in ("'", '"'):
                string_fails = string_fails + 1 if string_fail_at == n else 1
                string_fail_at = n
                if string_fails > _JS_LINE_RETRIES:
                    no_string_until = n
                del out[quote_out:]                     # a quote on the last line, never closed: text
                out.append(src[quote_at])
                i, quote = quote_at + 1, None
                prev, word, run_start = "'", "", -1
                continue
            if in_block:
                del out[block_out:]
                out.append("/")
                i, in_block, no_block = block_at + 1, False, True
                prev, word, run_start = "/", "", -1
                continue
            break
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if elements and elements[-1] == "children" and not (in_line or in_block or quote):
            # an element's text: blanked, up to a `{` expression or a tag
            if c == "{":
                elements.append(["expr", 1])
                out.append(c)
                prev, word, run_start = c, "", -1
                i += 1
                continue
            if c == "<":
                close = _JSX_CLOSE_TAG_RE.match(src, i)
                if close:
                    out.append(close.group(0))
                    elements.pop()
                    i = close.end()
                    prev, word, run_start = ")", "", -1      # an element is a finished expression
                    continue
                if nxt == ">" and fragments_close:
                    out.append("<>")                           # a fragment
                    elements.append("children")
                    i += 2
                    continue
                opening = _JSX_OPEN_TAG_RE.match(src, i)
                if opening and not (type_params and _JSX_OR_TYPE_PARAMS_RE.match(src, i)):
                    out.append(c)
                    elements.append(["tag", 0, _jsx_tag_name(opening.group(0))])
                    prev, word, run_start = c, "", -1
                    i += 1
                    continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if not (in_line or in_block or quote) and c == "/" and nxt not in "/*" and i >= no_regex_until and (
                prev == "" or prev in _JS_REGEX_PREV_CHARS or current_word() in _JS_REGEX_PREV_WORDS
                or (prev == ")" and after_control)) and not (elements and elements[-1][0] == "tag" and nxt == ">"):
            # a regular-expression literal: copy to its closing `/`, honouring escapes and classes
            j, in_class = i + 1, False
            while j < n and src[j] != "\n":
                ch = src[j]
                if ch == "\\" and j + 1 < n:
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            if j >= n or src[j] != "/":
                # no closing `/` on this line: counted, and past the limit the line's slashes are characters
                regex_fails = regex_fails + 1 if regex_fail_at == j else 1
                regex_fail_at = j
                if regex_fails > _JS_LINE_RETRIES:
                    no_regex_until = j
            if j < n and src[j] == "/":
                out.append(src[i:j + 1])
                i = j + 1
                prev, word, run_start = ")", "", -1
                continue
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                in_block = False
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif quote in ("'", '"') and c == "\n":
            string_fails = string_fails + 1 if string_fail_at == i else 1
            string_fail_at = i
            if string_fails > _JS_LINE_RETRIES:
                no_string_until = i
            # JavaScript strings end on their line: this quote was text (an apostrophe in JSX, a quote in a
            # regex the heuristic missed). Read again from after it, as code.
            del out[quote_out:]
            out.append(src[quote_at])
            i = quote_at + 1
            quote = None
            prev, word, run_start = "'", "", -1
        elif quote and blank_strings:
            if c == "\\" and i + 1 < n:
                out.append("  " if src[i + 1] != "\n" else " \n")
                i += 2
            elif c == quote:
                out.append(c)
                quote = None
                i += 1
            elif quote == "`" and c == "$" and nxt == "{":
                # the expression inside a template literal is code: copy it through to its closing brace
                depth, j = 0, i + 1
                while j < n:
                    if src[j] == "{":
                        depth += 1
                    elif src[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                out.append(src[i:j + 1])
                i = j + 1
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
        else:
            top = elements[-1] if elements else None
            # (in code, in an element's `{...}`, or in the braces of an opening tag's attribute: `title={<span>..`)
            if jsx and c == "<" and (top is None or top[0] == "expr" or (top[0] == "tag" and top[1] > 0)) and (
                    prev in ("", "(", "=", ",", ":", "?", "[", "{", "!", "&", "|", ";", ">")
                    or current_word() in _JSX_BEFORE_WORDS) and ((nxt == ">" and fragments_close) or (
                    _JSX_OPEN_TAG_RE.match(src, i) and not (type_params and _JSX_OR_TYPE_PARAMS_RE.match(src, i)))):
                # an element where an expression may start: `return <p>`, `=> <li>`, `(<div`, `? <A/> :`, `<>`
                if nxt == ">":
                    out.append("<>")
                    elements.append("children")
                    i += 2
                else:
                    out.append(c)
                    elements.append(["tag", 0, _jsx_tag_name(_JSX_OPEN_TAG_RE.match(src, i).group(0))])
                    i += 1
                prev, word, run_start = c, "", -1
                continue
            if top is not None and top != "children" and c in "{}":
                # braces inside an opening tag's attributes, or inside a `{...}` expression of an element's children
                top[1] += 1 if c == "{" else -1
                if top[0] == "expr" and top[1] == 0:
                    elements.pop()                  # back to the element's text
                    out.append(c)
                    prev, word, run_start = c, "", -1
                    i += 1
                    continue
            if top is not None and top != "children" and top[0] == "tag" and top[1] == 0 and c == ">":
                # the end of an opening tag: a self-closing one (`/>`) is a finished expression, any other starts its
                # element's text
                closed = "".join(out[-4:]).rstrip().endswith("/")
                tag = elements.pop()
                if not closed and tag[2] in closed_names:
                    elements.append("children")
                out.append(c)
                prev, word, run_start = ")", "", -1
                i += 1
                continue
            in_code = top is None
            if c == "/" and nxt == "/":
                out.append("  ")
                in_line = True
                i += 2
            elif c == "/" and nxt == "*" and jsx and i and _js_ident_char(src[i - 1]):
                # `src/*` or `lib/*.js` in JSX text the JSX reading did not follow: there a comment does not start
                # straight after a name (in code it does, `return/*#__PURE__*/x()`, and the plain reading reads it so)
                out.append(c)
                prev, word, run_start = c, "", -1
                i += 1
            elif c == "/" and nxt == "*" and not no_block:
                block_at, block_out = i, len(out)
                out.append("  ")
                in_block = True
                i += 2
            elif c in "\"'" and i and _js_ident_char(src[i - 1]) and current_word() not in _JS_STRING_PREV_WORDS:
                # straight after a letter a quote opens no string (`Don't` in JSX text): JavaScript would need an
                # operator between an identifier and a string literal
                out.append(c)
                prev, word, run_start = c, "", -1
                i += 1
            elif c == "`" and jsx and in_code and _jsx_text_backquote(src, i, current_word()):
                # `<p>Press ` to open</p>` in text this reading did not follow: after a plain word and a space, or
                # straight after a tag's `>`, a backquote is text; a template literal follows an operator, a
                # bracket, a keyword or a tag name
                out.append(c)
                prev, word, run_start = c, "", -1
                i += 1
            elif c in "\"'`" and not (c == "`" and no_template) and not (c != "`" and i < no_string_until):
                quote = c
                quote_at, quote_out = i, len(out)
                out.append(c)
                prev, word, run_start = c, "", -1
                i += 1
            else:
                out.append(c)
                if c.isspace():
                    if run_start >= 0:
                        word, run_start = current_word(), -1
                elif _js_ident_char(c):
                    if run_start < 0:
                        run_start = i
                    prev = c
                else:
                    if c == "(":
                        parens.append(current_word() in ("if", "while", "for", "with"))
                    after_control = c == ")" and bool(parens) and parens.pop()
                    word, run_start, prev = "", -1, c
                i += 1
    return "".join(out)


def _check_ecmascript(path: Path, rel: str, unlisted: set[str] | None = None) -> list[Finding]:
    """Source-aware egress check for TypeScript (and TS-family) files.

    Deliberately NOT the HTML regex path: comments are stripped first, so a
    licence header or a JSDoc @see link does not become a finding, while a URL
    in a string literal still does.
    """
    out: list[Finding] = []
    try:
        raw = _reads.read_text(path)
    except OSError:
        return out
    src = _strip_js_comments(raw)
    out += _js_import_findings(src, rel, unlisted)
    # the element's tag is a string (`createElement('img')`): read with comments blanked and strings kept
    created = _created_element_src_re(src)
    out += _js_expression_findings(raw, src, rel, created)
    return out


_JS_PACKAGE_NAME_RE = re.compile(r"@[\w.-]+/[\w.-]+|[\w.-]+")


def _line_starts(text: str) -> list[int]:
    """The offset at which each line begins: `bisect_right(starts, offset)` is the line of an offset, in one lookup
    rather than a count from the start of the text."""
    return [0] + [m.end() for m in re.finditer(r"\n", text)]


def _js_import_findings(src: str, rel: str, unlisted: set[str] | None) -> list[Finding]:
    """Imports and requires of network-capable packages in JavaScript with its comments blanked (`src`), and the
    bare specifiers no list names, added to `unlisted`."""
    out: list[Finding] = []
    starts = _line_starts(src)
    for m, spec, type_only in _js_imports(src):
        if spec.startswith(".") or spec.startswith("/"):
            continue  # relative/absolute local import
        if spec.startswith(("jsr:", "npm:")):
            # Deno's registry specifiers: `npm:axios@1` names the npm package `axios`; `jsr:@std/http@1` a JSR
            # package, which no list names. A version or a path after the package name is set aside.
            name = _JS_PACKAGE_NAME_RE.match(spec[4:])
            if not name:
                continue
            if spec.startswith("jsr:"):
                if unlisted is not None:
                    unlisted.add("jsr:" + name.group(0))
                continue
            spec = name.group(0)
        line = bisect.bisect_right(starts, m.start())
        if re.match(r"(?:https?:)?//", spec, re.I) and not type_only:
            # `import { serve } from 'https://deno.land/...'`: the runtime fetches the module when it loads
            here = not _has_external_url(spec if spec[:2] != "//" else "https:" + spec)
            out.append(Finding(rel, line, "loopback-call" if here else "network-import",
                               f"imports a module from {spec[:120]!r}; the module is fetched when it loads"
                               + ("; it is on this machine" if here else "")))
            continue
        root = _js_module_root(spec)
        if unlisted is not None and _js_is_unlisted(spec):
            unlisted.add("/".join(spec.split("/")[:2 if spec.startswith("@") else 1]))
        if type_only:
            continue                # erased when compiled: it names a dependency and loads nothing
        if root in JS_NET_MODULES or spec in JS_NET_MODULES:
            out.append(Finding(rel, line, "network-import", f"imports {spec!r}"))
        elif root in JS_PROCESS_MODULES or spec in JS_PROCESS_MODULES:
            out.append(Finding(rel, line, "subprocess-shell",
                               f"imports {spec!r}: can invoke a network binary"))
    return out


def _js_expression_findings(raw: str, src: str, rel: str, created: re.Pattern | None = None) -> list[Finding]:
    """Calls, process starts, dynamic code and addresses, line by line. `raw` is the file's text, `src` the same
    with comments blanked; `created` the pattern of `src` set on an element the file creates, which loads it."""
    out: list[Finding] = []
    # A process can only be started by a file that loads `child_process`. In any other file
    # `.exec(` is a regular expression's method and `fork(` is somebody's function. In a file
    # that does load it, the call is recognised by the name the module was bound to
    # (`cp.exec(`) or by a bare name (`exec(`, after destructuring), never by `anything.exec(`.
    process_re = None
    if any(spec in JS_PROCESS_MODULES and not type_only for _, spec, type_only in _js_imports(src)):
        aliases = set(re.findall(r"""\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['"](?:node:)?child_process['"]\s*\)""", src))
        aliases |= set(re.findall(r"""\bimport\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*['"](?:node:)?child_process['"]""", src))
        aliases.add("child_process")
        names = "|".join(sorted(re.escape(a) for a in aliases))
        process_re = re.compile(r"(?:\b(?:" + names + r")\s*\.\s*|(?<![.\w$]))"
                                r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(")

    # Expression-level. Whether a line CALLS something is read from the code with string
    # contents blanked; the bracketed form (`window["fetch"]`) names the call in a string,
    # so that one is read from the text with strings intact.
    code_lines = _js_code_only(raw).splitlines()
    for i, line in enumerate(src.splitlines(), 1):
        code = code_lines[i - 1] if i <= len(code_lines) else line
        strong, method_fetch = _js_net_calls(code)
        if strong and not _JS_BRACKET_CALL_RE.search(line) and _js_calls_only_loopback(line):
            out.append(Finding(rel, i, "loopback-call",
                               "network call given an address on this machine; nothing leaves it at this line"))
        elif strong or _JS_BRACKET_CALL_RE.search(line):
            out.append(Finding(rel, i, "network-call", "network call expression"))
        elif method_fetch:
            # `parser.fetch()`, `model.fetch()`: a method named like the browser's fetch, on an object the line
            # does not show to be a network client. Reported, and the sentence stops at the name.
            out.append(Finding(rel, i, "unresolved-call",
                               "a method named fetch is called on an object; whether it reaches the network is NOT "
                               "shown by this line"))
        elif created is not None and created.search(line) and not any(
                # an image made from data in the page (`data:`, a canvas, a blob) loads nothing from elsewhere
                _JS_LOCAL_SRC_RE.match(line, s.end()) for s in created.finditer(line)):
            out.append(Finding(rel, i, "unresolved-call",
                               "sets src on an element this file creates (an image, a script, a frame or media); the "
                               "element loads the address it is given, and where that is is NOT shown by this line"))
        # with no `child_process` in sight, only a bare call that names a network binary is one
        if (process_re or _JS_BARE_PROCESS_RE).search(line) and (process_re is not None or _JS_NET_BINARY_RE.search(line)):
            detail = "child_process invocation"
            if _JS_NET_BINARY_RE.search(line):
                detail += " of a network binary (curl/wget/nc/ssh/...)"
            out.append(Finding(rel, i, "subprocess-shell", detail))
        dyn = _JS_DYNAMIC_RE.search(line)
        if dyn:
            out.append(Finding(rel, i, "dynamic-exec",
                               "eval / new Function" if re.match(r"eval|new\s+Function", dyn.group(0))
                               else "code run from a string (vm or a Worker with eval)"))
        elif _JS_DYNAMIC_REQUIRE_RE.search(line):
            # `require(name)`: a module chosen while running, which no list can judge (as Python's
            # `importlib.import_module(name)` is reported)
            out.append(Finding(rel, i, "dynamic-exec",
                               "loads a module whose name is computed while running (`require(...)` with no literal "
                               "name); what it loads is NOT shown"))
        if _JS_DYNAMIC_IMPORT_RE.search(line):
            out.append(Finding(rel, i, "dynamic-exec",
                               "import(...) of a specifier that is not a string literal; what loads is NOT resolved"))
        elif not dyn and _DATA_URI_CODE_RE.search(line):
            # `import("data:text/javascript,...")`, `new Worker("data:...")`: code carried in the address, not read
            out.append(Finding(rel, i, "dynamic-exec",
                               "a data: URI holding script or a page; the code it holds is NOT read"))
        stripped = _strip_origin_only_urls(line)
        if _has_external_url(stripped) or PROTO_REL_RE.search(stripped):
            out.append(Finding(rel, i, "external-url", "external URL in code or string"))
        elif stripped != line:
            out.append(Finding(rel, i, "external-url",
                               "URL string used only as a postMessage target origin or an origin comparison: "
                               "no request from this line"))
    return out


@dataclass
class Finding:
    file: str
    line: int
    kind: str          # see sarif.RULES for every kind and what each one claims
    detail: str


@dataclass
class AuditReport:
    tool: str = "ENTROVOUCH no-egress auditor"
    # The version changes whenever a report can legitimately change on the same
    # tree. It is what lets a reader tell "the code changed" from "the tool got
    # better".
    tool_version: str = __version__
    target: str = ""
    scanned_at_utc: str = ""
    files_scanned: int = 0
    # Files outside the skipped directories that this tool has no reader for. Beside
    # `files_scanned`, it says how much of the tree a verdict rests on.
    files_not_read: int = 0
    verdict: str = "CLEAN"                       # CLEAN | FINDINGS | NOT-ANALYSED
    findings: list = field(default_factory=list)
    scope_statement: str = (
        "Static analysis of Python (including notebooks, .pth files and shebang scripts), "
        "JavaScript, TypeScript, markup, stylesheets, shell, PowerShell and batch scripts, "
        "Dockerfiles, Makefiles, pipeline definitions and dependency manifests. It reports "
        "network-capable imports, calls that connect or listen, process spawns that reach a "
        "network binary, shell strings, dynamic code loading, native calls, external "
        "references, network commands in scripts, and declared network dependencies and "
        "remote sources. It does NOT prove zero egress: this is a Turing-complete language "
        "and the analysis underapproximates. Detection is BLOCKLIST-BASED, so it is complete "
        "only against names it knows: a renamed, vendored or dynamically-constructed "
        "module or argv entry is invisible. Measured against network libraries chosen "
        "without reference to the list, recall is 0%, so a PLAIN, unobfuscated `import X` "
        "of a library this tool does not name produces no finding, exactly like an obfuscated "
        "one. Check FORBIDDEN_IMPORT_MODULES against your own dependencies before reading "
        "anything into a CLEAN verdict. Every third-party module the Python in the tree "
        "imports that is on none of this tool's lists is named in `unlisted_imports` (for "
        "JavaScript and TypeScript packages, `unlisted_js_imports`): the "
        "verdict covers the names the tool knows, and that field lists the ones it does "
        "not. Files that fail to parse are reported as "
        "`unparseable-source` and were NOT analysed. Directories skipped by name, files of "
        "types this tool has no reader for (configuration data, other languages, "
        "lockfiles) and symbolic links are listed under `not_scanned` and counted in "
        "`files_not_read`; a tree in which nothing was read is NOT-ANALYSED rather than "
        "CLEAN. An import is NOT counted as a network import when the tree itself supplies "
        "a top-level module of that name, because that module shadows any installed "
        "package; every such name is listed in `shadowed_imports`, so a network client "
        "VENDORED into the tree root appears there rather than disappearing. Declared "
        "dependencies (pyproject.toml, requirement files, setup.cfg, setup.py, Pipfile, "
        "conda environment files, package.json) that name a known network package are "
        "reported as `declared-network-dependency`: evidence the tree depends on that "
        "package, not a claim that a call site reaches the network. An argument is "
        "resolved when the source spells it out or binds it once to a literal; anything "
        "built at run time (f-strings, concatenation, lists assembled in code) is not, except a file path whose "
        "UNC root is written in the file. "
        "The subject digest folds CRLF line endings to LF in text files, and file order "
        "is by path bytes, so the same tree gives the same report on every operating "
        "system and wherever it sits on disk. This report is DETECTION-grade evidence and "
        "does not support an unqualified claim of absence."
    )
    # WHAT WAS AUDITED, not merely what it was called. `target` is a free-text
    # label the auditor supplies; two entirely different trees can produce
    # byte-identical reports under the same label, so a signature over the body
    # alone attests the SENTENCE and not the SUBJECT. `subject` follows the
    # in-toto Statement shape ({name, digest{alg: hex}}) so the binding is the
    # one the supply-chain ecosystem already verifies, rather than a bespoke
    # field a consumer would have to be taught.
    subject: list = field(default_factory=list)
    # Imports NOT counted as network imports because the tree supplies a
    # top-level module of that name, which shadows any installed package.
    #
    # Recorded, not dropped: a reader cannot audit a decision they cannot see. A project
    # with its own `motor.py` gets the correct CLEAN verdict AND is told which names were
    # resolved locally, so a vendored network client sitting at the tree root shows up
    # here instead of vanishing.
    #
    # Part of the reproducible body: it is a property of the tree, not of this
    # issuance, so two honest runs agree on it.
    shadowed_imports: list = field(default_factory=list)
    # Third-party modules the Python in this tree imports that are on none of this tool's
    # lists, are not standard library and are not the tree's own. The tool says nothing
    # about what they do, and says so by naming them: a CLEAN verdict covers the names it
    # knows, and this is the list of the ones it does not. Part of the reproducible body.
    unlisted_imports: list = field(default_factory=list)
    # The same for JavaScript and TypeScript: bare package specifiers that are on none of the
    # lists and are not Node's own modules.
    unlisted_js_imports: list = field(default_factory=list)
    # The Python that parsed the tree, as major.minor. A file written in syntax newer than
    # this is `unparseable-source`, so two audits of such a tree under different Pythons can
    # differ. Issuance metadata: inside the signed body, outside the findings digest.
    parser_python: str = ""
    # What the audit did NOT read: directories it skips by name (with the number of
    # files under each) and files of types it does not scan (by extension). A
    # property of the tree, so it is part of the reproducible body.
    not_scanned: dict = field(default_factory=dict)
    # Order-independent digest over every file the audit actually read.
    subject_digest: str = ""
    # THE REPRODUCIBLE VALUE. Covers tool, version, subject, verdict and
    # findings -- and deliberately EXCLUDES `scanned_at_utc`, which is why it is
    # bit-identical across runs while `content_hash` is not. It is the value a
    # reader compares after re-running the tool.
    findings_digest: str = ""
    content_hash: str = ""
    # Always empty, outside the signed body: a signed report carrying anything here is refused. It is never
    # evidence of origin and `verify_report` does not consult it.
    integrity_tag: str = ""
    signature_algorithm: str = UNSIGNED
    signature: dict | None = None
    public_root: str = ""


# ---------------------------------------------------------------------------
# Python source checks (AST: a comment/docstring mentioning a module never fires)
# ---------------------------------------------------------------------------
# Folders that hold a project's packages and are put on the import path when it is installed (`src/<name>/`).
_SOURCE_ROOTS = {"src", "lib", "python", "source", "sources", "pysrc", "py"}


def _local_top_level_modules(target: Path, rels: frozenset[str] | None = None,
                              extended: set[str] | None = None) -> set[str]:
    """Top-level module names the SCANNED TREE ITSELF provides.

    The list holds ordinary English words as module names (`motor`, `docker`,
    `github`, `dns`, `scp`, `slack`, `consul`, `fabric`). A project with its own
    `motor.py` shadows any installed distribution of that name for code importing
    it; that is Python's own resolution order, so reporting `network-import` there
    would be factually wrong, not merely noisy.

    THE COST, STATED: this widens the vendoring blind spot the scope statement
    declares. A real network client vendored into the tree root as `stripe.py`
    becomes invisible; the name is listed in `shadowed_imports` so a reader sees it.
    Someone who can add files to the tree can evade detection far more cheaply than
    this. The trade buys correctness on honest codebases.

    Root-level modules and TOP-MOST packages only. `pkg/motor.py` does not shadow
    top-level `motor` for code outside `pkg`, and a package nested inside another
    package (`pkg/_vendor/requests/`) is importable only through its parent, so
    neither is treated as provided by the tree. A top-most package is: the audited
    directory itself when it is a package; a package directly under the root; and a
    package whose parent directory is not a package (the `src/<name>/` layout).
    Auditing the `celery` repository must not report every `from celery import ...`
    in it as a dependency on celery.

    Decided only from the files the walk reads (`rels`): a link, a link stand-in or a skipped directory is not read, so
    it cannot shadow anything, and what shadows is covered by the subject digest.
    """
    rels = rels or frozenset()
    names: set[str] = set()
    project_roots = {r.rpartition("/")[0] for r in rels
                     if r.rpartition("/")[2] in ("pyproject.toml", "setup.py", "setup.cfg") and "/" in r}
    if "__init__.py" in rels:
        names.add(_subject_name(target))
        if extended is not None and _extends_its_path(target, "__init__.py"):
            extended.add(_subject_name(target))
    for rel in rels:
        parts = rel.split("/")
        if len(parts) == 1:
            stem, dot, ext = rel.rpartition(".")
            if dot and "." + ext.lower() in TEXT_EXTS and stem:
                names.add(stem)
        elif parts[-1] == "__init__.py" and not any(is_skipped_dir(d) for d in parts[:-1]):
            if len(parts) == 2:
                names.add(parts[0])
                if extended is not None and _extends_its_path(target, rel):
                    extended.add(parts[0])
            elif "/".join(parts[:-2]) + "/__init__.py" not in rels and (
                    parts[-3].lower() in _SOURCE_ROOTS or "/".join(parts[:-2]) in project_roots):
                # `src/<name>/`, or a package directly inside a folder that is a project of its own (it holds
                # `pyproject.toml`, `setup.py` or `setup.cfg`: `psycopg/psycopg/` in a repository of several
                # packages): either is put on the import path when the project is installed. A package under any
                # other folder (`myapp/integrations/telethon/`) is not importable by its own name.
                names.add(parts[-2])
                if extended is not None and _extends_its_path(target, rel):
                    extended.add(parts[-2])
    return names


_EXTEND_PATH_RE = re.compile(r"\b(?:extend_path|declare_namespace)\s*\(")


def _extends_its_path(target: Path, rel: str) -> bool:
    """Is this `__init__.py` a namespace package's (`__path__ = pkgutil.extend_path(__path__, __name__)`,
    `pkg_resources.declare_namespace(__name__)`)? Then installed distributions add their modules to the same name, and
    a module the tree does not hold is imported from them. A file that cannot be read is taken as an ordinary package."""
    try:
        return _EXTEND_PATH_RE.search(_reads.read_python_source(target / rel)) is not None
    except (OSError, ValueError):
        return False


# Does the file being read name a database host in the environment (`PGHOST=...`, `env: {PGHOST: db}`,
# `os.environ["PGHOST"]`)? Then a database client given no host may connect anywhere.
_DB_HOST_ELSEWHERE: contextvars.ContextVar = contextvars.ContextVar("entrovouch_db_host_elsewhere", default=False)
# During an audit: (the set unknown Python imports are added to, the tree's own module names), for Python a check finds
# inside another file (a script's `python -c`, a here-document) and reads without the caller's set
_UNLISTED_SINK: contextvars.ContextVar = contextvars.ContextVar("entrovouch_unlisted_sink", default=None)
# During an audit: the files a GitLab pipeline includes by path, which are pipeline files whatever their names
_CI_INCLUDED: contextvars.ContextVar = contextvars.ContextVar("entrovouch_ci_included", default=frozenset())
# During an audit: the dotted names of the modules and packages the tree holds (at its root, or under `src/`)
_TREE_MODULES: contextvars.ContextVar = contextvars.ContextVar("entrovouch_tree_modules", default=frozenset())
# During an audit: the tree's top-level packages whose `__init__.py` extends its path (a namespace shared with what is
# installed under the same name)
_EXTENDED_ROOTS: contextvars.ContextVar = contextvars.ContextVar("entrovouch_extended_roots", default=frozenset())
_DB_ENV_RE = re.compile(r"""\b(?:PGHOST|PGHOSTADDR|PGSERVICE|PGSERVICEFILE|MYSQL_HOST)\b(?:\s*[:=]\s*['"]?([^\s'",}\]]*))?""")


def _db_host_elsewhere(text: str) -> bool:
    # a script that reads settings from another file (`. ./prod.env`, `source .env`, `. "$CONFIG_FILE"`) may take a
    # database host from it, so a client given no host on a line is not shown to talk to this machine (a file that
    # sets up something else, `. mongo.path`, does not count)
    # (`. env` after `set -a;` too, and a file read into the environment: `eval "$(cat prod.env)"`,
    # `export $(grep -v '^#' .env | xargs)`)
    # (and what a command prints: `source <(grep -v '^#' prod.env)`, `env $(cat prod.env) psql`, and a variable
    # holding a whole assignment exported: `while read -r l; do export "$l"; done < prod.env`)
    if re.search(r"(?mi)(?:^|[;&|(])[ \t]*(?:\.|source)[ \t]+(?:<\(|\S*(?:env|conf|cfg|settings|secret|credential))"
                 r"|\b(?:eval|export)\b[^\n]*\$\([^\n]*(?:env|conf|cfg|settings|secret|credential)"
                 r"|\benv[ \t]+(?:-\S+[ \t]+)*\"?(?:\$\(|`)|\bdotenvx?\b"
                 r"|\b(?:export|declare[ \t]+-\w*x\w*|typeset[ \t]+-\w*x\w*)[ \t]+(?:--[ \t]+)?\"?\$\{?\w+\}?\"?[ \t]*(?:[;&|)]|$)",
                 text):
        return True
    for m in _DB_ENV_RE.finditer(text):
        v = m.group(1)
        if not v or not (v.startswith("/") or _THIS_MACHINE_HOST_RE.fullmatch(v)):
            return True
    return False


# Calls that only read a namespace they are handed (`sorted(globals())`, `print(vars())`)
_NAMESPACE_READERS = {"sorted", "list", "len", "dict", "print", "repr", "str", "set", "tuple", "iter",
                      "enumerate", "pprint", "pformat", "id", "type", "isinstance", "hasattr", "getattr",
                      "eval", "dumps", "copy", "deepcopy", "items", "keys", "values", "filter", "map"}


def _is_module_object(node: ast.AST) -> bool:
    """`sys.modules[__name__]` or `sys.modules[...]`: a module object, whose attributes are its global names."""
    return isinstance(node, ast.Subscript) and (_dotted_name(node.value) or "") == "sys.modules"


def _is_namespace(node: ast.AST) -> bool:
    """`globals()`, `vars()`, `locals()` at module level, or `sys.modules[__name__].__dict__`: a module's names."""
    if isinstance(node, ast.Call) and not node.args and (_dotted_name(node.func) or "") in ("globals", "vars", "locals"):
        return True
    return isinstance(node, ast.Attribute) and node.attr == "__dict__" and _is_module_object(node.value)


def _bound_native_library_findings(tree: ast.AST, rel: str) -> list[Finding]:
    """`urlmon = ctypes.windll.urlmon`, `ws = windll.ws2_32` (from ctypes): reading the attribute loads the library, and
    what it is called for later goes through the name, so the binding is where the native call is reported."""
    uses_ctypes = any((isinstance(n, ast.Import) and any(a.name.split(".")[0] == "ctypes" for a in n.names))
                      or (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "ctypes")
                      for n in ast.walk(tree))
    if not uses_ctypes:
        return []

    def is_loader(node: ast.AST) -> bool:
        """`ctypes.windll`, or `windll` imported from ctypes"""
        return (isinstance(node, ast.Attribute) and node.attr in FFI_ATTR_ROOTS and isinstance(node.value, ast.Name)
                and node.value.id == "ctypes") or (isinstance(node, ast.Name) and node.id in FFI_ATTR_ROOTS)

    out = []
    seen: set[int] = set()
    for n in ast.walk(tree):
        # `ctypes.cdll['libcurl.so']`, wherever it stands: the item is the library, loaded as it is read
        if isinstance(n, ast.Call) and (_dotted_name(n.func) or "") == "getattr" and n.args and is_loader(n.args[0]) \
                and n.lineno not in seen:
            # `getattr(ctypes.windll, 'urlmon')`: the same library, named as text
            seen.add(n.lineno)
            out.append(Finding(rel, n.lineno, "native-call",
                               f"getattr({_dotted_name(n.args[0])}, ...): loads a native library; what it does is "
                               "outside static analysis"))
        if isinstance(n, ast.Subscript) and is_loader(n.value) and n.lineno not in seen:
            seen.add(n.lineno)
            out.append(Finding(rel, n.lineno, "native-call",
                               f"{_dotted_name(n.value)}[...]: loads a native library; what it does is outside static "
                               "analysis"))
        value = n.value if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) else None
        if not isinstance(value, ast.Attribute) or n.lineno in seen:
            continue
        if (_dotted_name(value) or "") in {f"ctypes.{c}" for c in ("CDLL", "WinDLL", "OleDLL", "PyDLL")}:
            # `lib = ctypes.WinDLL` then `lib("urlmon")`: the loader, bound to a name
            seen.add(n.lineno)
            out.append(Finding(rel, n.lineno, "native-call",
                               f"{_dotted_name(value)}: the native library loader, bound to a name and called through "
                               "it; what it loads is outside static analysis"))
            continue
        # the library, or a function of it (`f = ctypes.windll.urlmon.URLDownloadToFileW`), anywhere in the chain
        chain, root = [], value
        while isinstance(root, ast.Attribute) and not is_loader(root):
            chain.append(root.attr)
            root = root.value
        loader = (root.attr if isinstance(root, ast.Attribute) else root.id) if is_loader(root) else None
        if loader is None or not chain:
            continue
        seen.add(n.lineno)
        if len(chain) >= 2:
            out.append(Finding(rel, n.lineno, "native-call",
                               f"{_dotted_name(value)}: a function of a native library, bound to a name and called "
                               "through it; what it does is outside static analysis"))
        elif value.attr == "LoadLibrary":
            out.append(Finding(rel, n.lineno, "native-call",
                               f"{_dotted_name(value)}: the native library loader, bound to a name and called through "
                               "it; what it loads is outside static analysis"))
        elif loader in FFI_ATTR_ROOTS:
            out.append(Finding(rel, n.lineno, "native-call",
                               f"{_dotted_name(value)}: loads a native library, called through the name it is bound "
                               "to; what it does is outside static analysis"))
    return out


def _check_python(path: Path, rel: str, local_modules: frozenset[str] = frozenset(),
                  shadowed: set[str] | None = None, source: str | None = None,
                  unlisted: set[str] | None = None, own_names: frozenset[str] = frozenset(),
                  importable: frozenset[str] | None = None) -> list[Finding]:
    try:
        src = source if source is not None else _read_python_source(path)
    except (SyntaxError, ValueError, LookupError, RecursionError, MemoryError):
        src = None
    token = _DB_HOST_ELSEWHERE.set(_DB_HOST_ELSEWHERE.get() or (src is not None and _db_host_elsewhere(src)))
    sink = _UNLISTED_SINK.get()
    if unlisted is None and sink is not None:
        # Python written inside a script, a pipeline or an argv list: its unknown imports join the report's list,
        # and the tree's own names are the tree's own code there too
        unlisted, own_names, importable = sink[0], sink[1], None
    try:
        found = _check_python_source(path, rel, local_modules, shadowed, src if src is not None else source,
                                     unlisted, own_names, importable)
        if source is None and src is not None and ("# MAGIC" in src or "# %" in src or "#%%" in src or "# !" in src):
            # a notebook saved as a .py file (Databricks, Jupytext): its magic cells are written as comments
            for line, text, label in _py_notebook_magic_cells(src):
                found += _check_cell_text(path, rel, line, text, label, local_modules, shadowed, unlisted, own_names,
                                          importable)
        return found
    finally:
        _DB_HOST_ELSEWHERE.reset(token)


_DATABRICKS_HEADER_RE = re.compile(r"\A﻿?# Databricks notebook source[ \t]*$", re.MULTILINE)
_DATABRICKS_CELL_RE = re.compile(r"^# COMMAND -{5,}[ \t]*$")
_PERCENT_CELL_RE = re.compile(r"^#[ \t]?%%(?:[ \t].*|\[.*)?$")      # `# %%`, and `#%%` as editors write it
_JUPYTEXT_HEADER_RE = re.compile(r"\A(?:#!.*\n)?(?:#.*coding.*\n)?# ---[ \t]*\n(?:#.*\n){0,40}?#[ \t]+jupytext:", re.MULTILINE)
# Databricks magics that hand the cell to another language or program
_DATABRICKS_LANGUAGES = {"sql": "%%sql", "scala": "%%scala", "r": "%%R", "sh": "%%sh", "md": None, "md-sandbox": None}


def _py_notebook_magic_cells(src: str) -> list[tuple[int, str, str]]:
    """(line, cell text in IPython's spelling, label) for each magic cell of a notebook saved as Python source.

    Databricks writes `# Databricks notebook source` first, separates cells with `# COMMAND ----------` and writes a
    magic cell's lines after `# MAGIC `: `%sh` hands the cell to the shell, `%pip` installs, `%sql`, `%scala`, `%r`
    hand it to another language. Jupytext's percent format separates cells with `# %%` and writes IPython magics
    commented (`# !curl ...`, `# %pip install ...`, a `# %%bash` cell); they run when the file is opened as a
    notebook."""
    lines = src.splitlines()
    out: list[tuple[int, str, str]] = []
    if _DATABRICKS_HEADER_RE.match(src):
        start = 0
        for k in range(len(lines) + 1):
            if k < len(lines) and not _DATABRICKS_CELL_RE.match(lines[k]):
                continue
            magic = [(j, re.sub(r"^# MAGIC ?", "", lines[j])) for j in range(start, k) if lines[j].startswith("# MAGIC")]
            start = k + 1
            if not magic:
                continue
            first_line, first = magic[0][0] + 1, magic[0][1].strip()
            body = "\n".join(t for _, t in magic[1:])
            m = re.match(r"%([\w-]+)\s*(.*)$", first)
            if not m:
                continue
            word, rest = m.group(1).lower(), m.group(2)
            label = f"Databricks cell at line {first_line}"
            if word in _DATABRICKS_LANGUAGES:
                cell = _DATABRICKS_LANGUAGES[word]
                if cell is None:
                    # `%md`: text shown, not run, read as the markup it is (an image it shows is loaded)
                    out.append((first_line, "%%markdown\n" + (rest + "\n" if rest else "") + body, label))
                    continue
                out.append((first_line, f"{cell}\n" + (rest + "\n" if rest else "") + body, label))
            elif word == "python":
                out.append((first_line, (rest + "\n" if rest else "") + body, label))
            else:
                # a line magic (`%pip install x`, `%run ./other`, `%fs cp ...`), one per line; `%fs cp a b` is
                # `dbutils.fs.cp('a', 'b')`, read as that Python
                for j, t in magic:
                    fs = re.match(r"\s*%fs\s+([A-Za-z]\w*)((?:\s+\S+)*)\s*$", t)
                    if fs:
                        args = ", ".join(repr(a) for a in fs.group(2).split() if not a.startswith("-"))
                        out.append((j + 1, f"dbutils.fs.{fs.group(1)}({args})", label))
                    elif t.strip().startswith("%"):
                        out.append((j + 1, t.strip(), label))
        return out
    if not (_JUPYTEXT_HEADER_RE.match(src) or any(_PERCENT_CELL_RE.match(ln) for ln in lines)):
        return out
    k = 0
    markdown = False
    while k < len(lines):
        if _PERCENT_CELL_RE.match(lines[k]):
            # `# %% [markdown]` (or `[md]`) opens a text cell: what it holds is shown, not run
            markdown = re.search(r"\[(?:markdown|md|raw)\]", lines[k], re.I) is not None
            k += 1
            continue
        if markdown:
            # a text cell's lines are shown, not run: read as the markup they are, to the next cell marker
            body, j = [], k
            while j < len(lines) and not _PERCENT_CELL_RE.match(lines[j]):
                body.append(re.sub(r"^# ?", "", lines[j]) if lines[j].startswith("#") else lines[j])
                j += 1
            out.append((k + 1, "%%markdown\n" + "\n".join(body),
                        f"Jupytext text cell at line {k + 1} (shown when the file is opened as a notebook)"))
            markdown = False
            k = j
            continue
        cell_magic = re.match(r"^# (%%[A-Za-z][\w-]*.*)$", lines[k])
        if cell_magic:
            # `# %%bash` with its body commented under it, to the next cell marker
            body, j = [], k + 1
            while j < len(lines) and not _PERCENT_CELL_RE.match(lines[j]) and lines[j].startswith("#"):
                body.append(re.sub(r"^# ?", "", lines[j]))
                j += 1
            out.append((k + 1, cell_magic.group(1) + "\n" + "\n".join(body),
                        f"Jupytext cell at line {k + 1} (runs when the file is opened as a notebook)"))
            k = j
            continue
        # `# !curl ...`, `# %pip install x`: a program or a magic's name follows at once (`# != ...`, `# !!! NOTE`
        # and `# % of total` are prose)
        escape = re.match(r"""^(\s*)# (![A-Za-z./~$"'][^\n]*|%[A-Za-z][\w-]*(?:\s[^\n]*)?)$""", lines[k])
        if escape:
            out.append((k + 1, escape.group(2), f"Jupytext line {k + 1} (runs when the file is opened as a notebook)"))
        k += 1
    return out


def _check_python_source(path: Path, rel: str, local_modules: frozenset[str] = frozenset(),
                         shadowed: set[str] | None = None, source: str | None = None,
                         unlisted: set[str] | None = None, own_names: frozenset[str] = frozenset(),
                         importable: frozenset[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    try:
        src = source if source is not None else _read_python_source(path)
        tree = _parse_quietly(src, str(path))
    except (SyntaxError, ValueError, LookupError, RecursionError, MemoryError) as exc:
        # A file that could not be parsed is not a file nothing was found in. The
        # gap in coverage is reported as a finding so it reaches the reader, rather
        # than rounding to CLEAN. Its own kind: this is not evidence of egress and
        # must never be counted as such; it is evidence that a region of the tree
        # was not analysed.
        line = getattr(exc, "lineno", None) or 0
        out.append(Finding(rel, line, "unparseable-source",
                           f"could not parse this file, so it was NOT analysed "
                           f"({type(exc).__name__}); absence of findings here is "
                           f"not evidence of absence"))
        return out

    def _classify(name: str) -> str | None:
        """_classify_module, but a module the TREE ITSELF provides wins.

        A top-level `motor.py` in the scanned tree shadows any installed
        distribution of that name, so calling it a network import is wrong.
        See _local_top_level_modules for the trade this makes and its cost.
        """
        root = name.split(".")[0] if name else ""
        # NOT when the importing file IS the shadowing module. A root-level `wandb.py`
        # containing `import wandb` is a self-import, not a project providing `wandb` to
        # its other files. The conservative rule keeps the motor.py case (a DIFFERENT
        # file imports the local module) and gives up the ambiguous one, because
        # over-suppression here costs recall on the class this tool exists to catch.
        importer_is_the_module = (
            "/" not in rel and "\\" not in rel and rel[:-3] == root
            and rel.endswith(".py")
        )
        parts = name.split(".") if name else []
        # a top-level package whose `__init__.py` extends its path is shared with what is installed under that name:
        # only the root itself and the modules the tree holds are its own (`azure.myext`, not `azure.storage.blob`)
        shared_root = root in _EXTENDED_ROOTS.get() and len(parts) > 1 and not any(
            ".".join(parts[:k]) in _TREE_MODULES.get() for k in range(2, len(parts) + 1))
        if root and root in local_modules and not importer_is_the_module and root not in STDLIB_MODULE_NAMES \
                and not shared_root:
            # Only record it if it WOULD have been reported otherwise --
            # listing every local import would bury the interesting case.
            if _classify_module(name) is not None and shadowed is not None:
                shadowed.add(root)
            return None
        tree_modules = _TREE_MODULES.get()
        if tree_modules and "." in name and root not in STDLIB_MODULE_NAMES:
            # a module of a namespace package the tree holds (`google/cloud/storage/` with no `google/__init__.py`):
            # `from google.cloud.storage import blob` in that tree imports the tree's own code
            parts = name.split(".")
            if any(".".join(parts[:k]) in tree_modules for k in range(2, len(parts) + 1)):
                if _classify_module(name) is not None and shadowed is not None:
                    shadowed.add(".".join(parts[:2]))
                return None
        return _classify_module(name)

    def _note_unlisted(name: str, cls: str | None) -> None:
        """A third-party import this tool has no entry for: named in the report, not judged."""
        root = name.split(".")[0] if name else ""
        if unlisted is None or cls is not None or not root or root.startswith("_"):
            return
        # the tree's own code is what Python would import from the tree for this file: a top-level module or
        # package, or one beside the file. A same-named file elsewhere in the tree does not make a name the tree's own.
        parts = name.split(".")
        if any(".".join(parts[:k]) in _TREE_MODULES.get() for k in range(2, len(parts) + 1)):
            return                                  # the tree's own module in a namespace (`google.cloud.mylib`)
        if len(parts) > 1 and (root in _SHARED_NAMESPACES or root in _EXTENDED_ROOTS.get()):
            # a namespace shared with what is installed: a folder of that name here makes only the modules it holds
            # the tree's (`google.zzz` is still someone else's beside the tree's `google/mylib/`)
            if root not in STDLIB_MODULE_NAMES and _classify_module(root) is None:
                unlisted.add(root)
            return
        if root in STDLIB_MODULE_NAMES or root in local_modules or root in (
                own_names if importable is None else importable):
            return
        if _classify_module(root) is None:
            unlisted.add(root)

    # imports under `if TYPE_CHECKING:` are read by type checkers and never run: reported, and said to be
    type_only_lines = {n.lineno for node in ast.walk(tree) if isinstance(node, ast.If) and (
        _dotted_name(node.test) or "").rsplit(".", 1)[-1] == "TYPE_CHECKING"
        for stmt in node.body for n in ast.walk(stmt) if isinstance(n, (ast.Import, ast.ImportFrom))}

    def _report_import(line: int, shown: str, cls: str | None) -> None:
        if line in type_only_lines:
            shown += " (under `if TYPE_CHECKING:`: imported for type checkers, not when the program runs)"
        if cls == "network":
            out.append(Finding(rel, line, "network-import", shown))
        elif cls == "dependency" and (re.match(r"(?:from|import)\s+([\w.]+)", shown) or [None, ""])[1].split(".")[0] \
                in INTERFACE_PACKAGES:
            # `from opentelemetry.trace import ...`: the interface (API, SDK, an in-memory exporter) sends nothing;
            # only the package's exporters do
            out.append(Finding(rel, line, "network-dependency",
                               f"{shown}: part of an interface package that sends nothing itself (only its "
                               "exporters do); evidence the package is present, NOT a network call here"))
        elif cls == "dependency":
            out.append(Finding(rel, line, "network-dependency",
                               f"{shown}: submodule of a network-capable package; "
                               "evidence the dependency is present, NOT a network call here"))
        elif cls == "protocol":
            out.append(Finding(rel, line, "network-dependency",
                               f"{shown}: a protocol library; it encodes and decodes and cannot open a socket "
                               "itself. Evidence a network stack is present, NOT a network call here"))
        elif cls == "inbound":
            out.append(Finding(rel, line, "inbound-listener",
                               f"{shown}: binds a listening socket (INBOUND, not egress)"))
        elif cls == "inbound-dependency":
            out.append(Finding(rel, line, "network-dependency",
                               f"{shown}: a server package or one of its submodules; evidence it is present, "
                               "NOT a bound socket here"))

    # asyncio evidence for the method-name matches below: the names asyncio is bound to, and whether the
    # module imports anything from it (an event loop `loop.create_connection` has no asyncio receiver name).
    asyncio_aliases: set = set()
    socket_aliases: set = set()   # `socket.create_connection` shares asyncio's method name
    module_imports_asyncio = False
    module_imports_logging_handlers = False
    # What each local name stands for, so a call is judged by the module it reaches and not
    # by how the file spelled the import: `import subprocess as sp`, `from os import system`.
    module_alias: dict[str, str] = {}
    from_alias: dict[str, tuple[str, str]] = {}
    # Names bound exactly once in the file to a list, tuple or string literal: an argv or a
    # command held in a variable one line above the call that uses it.
    bound: dict[str, list] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    module_alias[a.asname] = a.name
                else:
                    module_alias.setdefault(a.name.split(".")[0], a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for a in node.names:
                from_alias[a.asname or a.name] = (node.module, a.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    bound.setdefault(t.id, []).append(node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name):
            bound.setdefault(node.target.id, []).append(getattr(node, "value", None))
    # attributes read off each plain name: `urllib.urlopen`, `urllib.request`, `wsgiref.simple_server`
    package_attrs: dict[str, set] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            package_attrs.setdefault(node.value.id, set()).add(node.attr)
    # Names of builtins this file binds to something else: a function it defines or an import.
    defined_functions = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    server_provider_imported = any(m.split(".")[0] in SERVER_NAME_PROVIDERS for m in module_alias.values()) or any(
        m.split(".")[0] in SERVER_NAME_PROVIDERS for m, _ in from_alias.values())
    in_provider_source = rel.replace("\\", "/").split("/", 1)[0] in SERVER_NAME_PROVIDERS
    rebound = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    rebound |= {k for k, (mod, _) in from_alias.items() if mod != "builtins"} | set(bound)
    # a parameter or a variable named like a builtin (`def f(exec): return exec()`) is that name, not the builtin,
    # inside that function only: `_local_names[id(call)]` holds the names the calls enclosing scopes bind
    _local_names: dict[int, frozenset] = {}

    def _scope_walk(parent, inherited):
        for child in ast.iter_child_nodes(parent):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                a = child.args
                names = set(inherited) | {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
                names |= {x.arg for x in (a.vararg, a.kwarg) if x}
                stack = list(child.body) if isinstance(child.body, list) else [child.body]
                while stack:
                    cur = stack.pop()
                    if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                        continue
                    if isinstance(cur, ast.Name) and isinstance(cur.ctx, ast.Store):
                        names.add(cur.id)
                    stack.extend(ast.iter_child_nodes(cur))
                _scope_walk(child, frozenset(names))
            else:
                if isinstance(child, ast.Call):
                    _local_names[id(child)] = inherited
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store) and not inherited:
                    rebound.add(child.id)             # a module-level or class-level variable: the whole file
                _scope_walk(child, inherited)

    _scope_walk(tree, frozenset())
    # names the file also binds another way: a parameter, a `for`, `with`, `except` or comprehension target, an
    # unpacked assignment. Such a name is not bound once: the value it holds where it is used is not the literal.
    direct = {id(t) for n in ast.walk(tree) if isinstance(n, ast.Assign) for t in n.targets} | {
        id(n.target) for n in ast.walk(tree) if isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr))}
    bound_otherwise = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
                       and id(n) not in direct} | {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)} | {
        n.name for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and n.name} | {
        # an import (`from local_settings import API_URL`), a function or class, a `case` pattern's capture
        (a.asname or a.name).split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in n.names if a.name != "*"} | {
        n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))} | {
        n.name for n in ast.walk(tree) if isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name} | {
        n.rest for n in ast.walk(tree) if isinstance(n, ast.MatchMapping) and n.rest}
    assigned: dict[str, ast.AST] = {
        k: v[0] for k, v in bound.items()
        if len(v) == 1 and k not in bound_otherwise and (isinstance(v[0], (ast.List, ast.Tuple))
                            or (isinstance(v[0], ast.Constant) and isinstance(v[0].value, str))
                            or _which_program(v[0]))}
    # `from settings import *` or `globals()[name] = ...` may bind any name of the module: an address one is not taken
    # for the value it holds where it is used (an argv list or a program's name still is)
    # (one written before the binding is overridden by it: `from common import *` then `url = "https://..."`)
    # (also `globals().update(...)`, `g = globals(); g[name] = ...`, `setattr(sys.modules[__name__], name, ...)`,
    # `config.apply(globals())`)
    namespace_aliases = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) and _is_namespace(n.value)
                         for t in n.targets if isinstance(t, ast.Name)}

    def names_namespace(node: ast.AST) -> bool:
        return _is_namespace(node) or (isinstance(node, ast.Name) and node.id in namespace_aliases)

    rebinds_all = [n.lineno for n in ast.walk(tree)
                   if (isinstance(n, ast.ImportFrom) and n.module != "__future__" and any(a.name == "*" for a in n.names))
                   or (isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store) and names_namespace(n.value))
                   or (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and n.func.attr in ("update", "setdefault", "__setitem__") and names_namespace(n.func.value))
                   or (isinstance(n, ast.Call) and (_dotted_name(n.func) or "") == "setattr" and n.args
                       and _is_module_object(n.args[0]))
                   # `exec(open("local_settings.py").read())` runs in this namespace
                   or (isinstance(n, ast.Call) and (_dotted_name(n.func) or "") in ("exec", "execfile") and len(n.args) == 1
                       and not n.keywords)
                   # `config.apply(globals())`: whatever is handed the namespace may bind in it
                   or (isinstance(n, ast.Call) and (_dotted_name(n.func) or "").rsplit(".", 1)[-1] not in _NAMESPACE_READERS
                       and any(names_namespace(a) for a in list(n.args) + [k.value for k in n.keywords]))]
    if rebinds_all:
        last = max(rebinds_all)
        assigned = {k: v for k, v in assigned.items()
                    if not (isinstance(v, ast.Constant) and isinstance(v.value, str) and "://" in v.value
                            and getattr(v, "lineno", 0) < last)}
    # names bound once, by an assignment only: what a path built with `/` is built from
    path_bound = {k: v for k, v in bound.items() if len(v) == 1 and k not in bound_otherwise}

    def dsn_env_named(_cache: list = []) -> bool:
        """The file names a database client's host variable (`os.environ["PGHOST"] = ...`), once worked out."""
        if not _cache:
            _cache.append(any(_sets_dsn_environment(n) for n in ast.walk(tree)))
        return _cache[0]

    # names bound once to `Mock()`, `MagicMock()`, `AsyncMock()` or `create_autospec(...)`
    mock_names = {k for k, v in bound.items()
                  if len(v) == 1 and k not in bound_otherwise and isinstance(v[0], ast.Call)
                  and (_dotted_name(v[0].func) or "").rsplit(".", 1)[-1] in _MOCK_CONSTRUCTORS}
    # A logging configuration names its handler classes as text (`'class': 'logging.handlers.HTTPHandler'` in a
    # dictConfig, `class=handlers.SocketHandler` in fileConfig): logging builds that handler and sends records with it.
    # Only where a configuration loads a class by its name: a dict's `class` or `()` key (logging's dictConfig, a
    # backend setting), or a list a framework imports in turn (`MIDDLEWARE`, `INSTALLED_APPS`). A handler named in a
    # denylist or compared in a test is text.
    named_classes: list[ast.Constant] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            named_classes += [v for k, v in zip(n.keys, n.values)
                              if isinstance(k, ast.Constant) and k.value in _CLASS_KEYS
                              and isinstance(v, ast.Constant) and isinstance(v.value, str)]
        elif isinstance(n, (ast.Assign, ast.AnnAssign)) and isinstance(n.value, (ast.List, ast.Tuple)) and any(
                isinstance(t, ast.Name) and _CLASS_LIST_NAME_RE.search(t.id)
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target])):
            named_classes += [e for e in n.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    for n in named_classes:
        if len(n.value) < 160:
            h = _LOG_HANDLER_NAME_RE.fullmatch(n.value.strip())
            dotted = None if h else _DOTTED_CLASS_RE.fullmatch(n.value.strip())
            if dotted:
                # a class loaded by name imports its module: an unknown one is named like any other import
                module = dotted.group(0).rsplit(".", 1)[0]
                _note_unlisted(module, _classify(module) or _classify(module.split(".")[0]))
            if dotted and "network" in (_classify(dotted.group(0).rsplit(".", 1)[0]), _classify(dotted.group(0).split(".")[0])):
                out.append(Finding(rel, n.lineno, "network-import",
                                   f"names {n.value.strip()!r} as a class a configuration loads by name: loading it "
                                   f"imports {dotted.group(0).split('.')[0]!r}, a network-capable module"))
            if h and h.group(1) == "SysLogHandler":
                out.append(Finding(rel, n.lineno, "unresolved-call",
                                   "names logging.handlers.SysLogHandler as a handler class: a logging configuration "
                                   "builds it and sends log records to the address it is given, which may be this "
                                   "machine; where they go is NOT resolved"))
            elif h:
                out.append(Finding(rel, n.lineno, "network-call",
                                   f"names logging.handlers.{h.group(1)} as a handler class: a logging configuration "
                                   "builds it and sends log records over the network"))
    # names bound to the notebook's shell: `ip = get_ipython()`
    ipython_names = {k for k, v in bound.items()
                     if any(isinstance(x, ast.Call) and isinstance(x.func, ast.Name) and x.func.id == "get_ipython"
                            for x in v)}
    # `with requests_mock.mock() as m:`, `with responses.RequestsMock() as rsps:`: the name is a
    # test double when every `with` that binds it opens one.
    with_bound: dict[str, list] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name):
                    with_bound.setdefault(item.optional_vars.id, []).append(item.context_expr)
    mock_names |= {k for k, v in with_bound.items() if k not in bound and all(
        isinstance(e, ast.Call) and any(_TEST_DOUBLE_NAME_RE.search(part)
                                        for part in (_dotted_name(e.func) or "").split(".")[:-1])
        for e in v)}
    # names bound only to a `...Cache(...)` object: its `get` looks a key up, and the key may be a URL
    cache_names = {k for k, v in bound.items() if v and all(
        isinstance(e, ast.Call) and (_dotted_name(e.func) or "").rsplit(".", 1)[-1].endswith("Cache") for e in v)}
    # What an object a fetch-named method is called on was made from: `self.session = requests.Session()`,
    # `async with aiohttp.ClientSession() as s`, `def f(client: httpx.Client)`. A `.get(url)` is reported
    # as a network call only when its receiver traces back to a network package; the same name on
    # anything else (a cache, a mapping, a test double, the project's own helper) is reported as
    # a call whose receiver is not resolved.
    self_attrs: dict[str, list] = {}
    annotated: dict[str, list] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in ("self", "cls"):
                    if getattr(node, "value", None) is not None:
                        self_attrs.setdefault(t.attr, []).append(node.value)
                    if isinstance(node, ast.AnnAssign):
                        self_attrs.setdefault(t.attr, []).append(node.annotation)
                elif isinstance(t, ast.Name) and isinstance(node, ast.AnnAssign):
                    annotated.setdefault(t.id, []).append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]:
                if getattr(arg, "annotation", None) is not None:
                    annotated.setdefault(arg.arg, []).append(arg.annotation)

    # names bound only to a module loaded by name: `pytest.importorskip("x")`, `importlib.import_module("x")`
    imported_by_call: dict[str, str] = {}
    for k, v in bound.items():
        mods = {e.args[0].value for e in v if isinstance(e, ast.Call) and e.args
                and (_dotted_name(e.func) or "").rsplit(".", 1)[-1] in ("importorskip", "import_module", "__import__")
                and isinstance(e.args[0], ast.Constant) and isinstance(e.args[0].value, str)}
        if len(mods) == 1 and len(v) == sum(1 for e in v if isinstance(e, ast.Call)):
            imported_by_call[k] = mods.pop()

    def _imported_as(dotted: str | None) -> str | None:
        """The full dotted name an imported name stands for (`Session` after `from requests import Session` is
        `requests.Session`), or None for a name this file never imports or one the tree supplies itself."""
        if not dotted:
            return None
        head, _, tail = dotted.partition(".")
        if head in from_alias:
            mod, imported = from_alias[head]
            full = f"{mod}.{imported}" + (f".{tail}" if tail else "")
        elif head in module_alias:
            full = module_alias[head] + (f".{tail}" if tail else "")
        elif imported_by_call.get(head):
            full = imported_by_call[head] + (f".{tail}" if tail else "")   # `requests = pytest.importorskip("requests")`
        else:
            return None         # a name this file never imports
        if full.split(".")[0] in local_modules:
            return None         # the tree supplies a module of that name itself
        return full

    def _names_network_package(dotted: str | None) -> bool:
        """`requests.Session`, `httpx.AsyncClient`, `Session` after `from requests import Session`."""
        full = _imported_as(dotted)
        if not full:
            return False
        parts = full.split(".")
        return any(".".join(parts[:i]) in FORBIDDEN_IMPORT_MODULES for i in range(1, len(parts) + 1))

    def _made_by_network_package(expr: ast.AST | None, depth: int = 0) -> bool:
        """Whether an expression is, or builds, an object from a network package."""
        if expr is None or depth > 3:
            return False
        if isinstance(expr, ast.Await):
            return _made_by_network_package(expr.value, depth + 1)
        if isinstance(expr, ast.Call):
            fnx = expr.func
            if isinstance(fnx, ast.Attribute) and isinstance(fnx.value, ast.Call):
                return _made_by_network_package(fnx.value, depth + 1)   # `requests.Session().get`
            return _names_network_package(_dotted_name(fnx)) or (
                isinstance(fnx, ast.Attribute) and _receiver_is_network(fnx.value, depth + 1))
        if isinstance(expr, ast.Subscript):                          # `Optional[httpx.Client]`
            return _made_by_network_package(expr.slice, depth + 1) or _made_by_network_package(expr.value, depth + 1)
        if isinstance(expr, ast.Tuple):
            return any(_made_by_network_package(e, depth + 1) for e in expr.elts)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):   # `httpx.Client | None`
            return _made_by_network_package(expr.left, depth + 1) or _made_by_network_package(expr.right, depth + 1)
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):   # a quoted annotation
            return _names_network_package(expr.value.strip())
        if isinstance(expr, (ast.Name, ast.Attribute)):
            return _receiver_is_network(expr, depth + 1)
        return False

    # Classes this file defines, and names it imports from the tree's own code (a relative import, or a
    # package the tree itself holds).
    defined_classes = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    # A module never imports itself by its own name: `import socks` inside `.../contrib/socks.py` is the installed
    # package (PySocks), unless the tree's top level holds a module of that name.
    self_stem = rel.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
    # (tested name by name, not built as a set: the tree's names are as many as its files, and a copy for every file
    # made the audit's time grow with the square of their number)
    def own_here(name: str) -> bool:
        return name in local_modules or (name in own_names and name != self_stem)
    own_imported: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and (n.level or own_here((n.module or "").split(".")[0])):
            own_imported |= {a.asname or a.name for a in n.names}
        elif isinstance(n, ast.Import):
            own_imported |= {a.asname or a.name.split(".")[0] for a in n.names
                             if own_here(a.name.split(".")[0])}

    def _project_object(recv: ast.AST, method: str) -> bool:
        """`self.create_connection` defined in this file, or an object built from the project's own code."""
        if isinstance(recv, ast.Name) and recv.id in ("self", "cls"):
            return method in defined_functions
        # `connections.create_connection(...)` after `from elasticsearch.dsl import connections` in a tree that holds
        # `elasticsearch/`: the module or object imported from the project's own code, used directly
        dotted = _dotted_name(recv) or ""
        if dotted and dotted.split(".")[0] in own_imported:
            return True
        if isinstance(recv, ast.Name):
            evidence = bound.get(recv.id, [])
            # `connections.Connections[Elasticsearch](...)`: a generic class given its type argument, then called
            return bool(evidence) and all(
                isinstance(e, ast.Call) and (_dotted_name(e.func.value if isinstance(e.func, ast.Subscript) else e.func)
                                             or "").split(".")[0] in (defined_classes | own_imported)
                for e in evidence)
        return False

    # Lines inside a test that patches the socket out: `with mock.patch("socket.socket", ...)` or a function
    # decorated with `@mock.patch("socket.create_connection")`.
    def _patches_socket(call: ast.AST) -> bool:
        if not isinstance(call, ast.Call) or not (_dotted_name(call.func) or "").split(".")[-1] in ("patch", "object"):
            return False
        first = call.args[0] if call.args else None
        return (isinstance(first, ast.Constant) and isinstance(first.value, str) and "socket" in first.value) or (
            isinstance(first, ast.Name) and first.id in socket_aliases | {"socket"})

    # Sockets this file binds to a literal address on this machine: `listener.bind(("127.0.0.1", 0))`. A call given
    # `listener.getsockname()` is given that address.
    loopback_bound = {n.func.value.id for n in ast.walk(tree)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "bind"
                      and isinstance(n.func.value, ast.Name) and n.args
                      and isinstance(n.args[0], (ast.Tuple, ast.List)) and n.args[0].elts
                      and isinstance(n.args[0].elts[0], ast.Constant) and isinstance(n.args[0].elts[0].value, str)
                      and _THIS_MACHINE_HOST_RE.fullmatch(n.args[0].elts[0].value)}
    bound_elsewhere = {n.func.value.id for n in ast.walk(tree)
                       if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "bind"
                       and isinstance(n.func.value, ast.Name)} - loopback_bound

    # Sockets this file makes as Unix sockets, `sock = socket.socket(socket.AF_UNIX)`, and binds to nothing else: an
    # event loop's `sock_connect(sock, path)` or `sock_sendall(sock, ...)` on one stays on this machine.
    def _socket_family(value: ast.AST) -> str | None:
        if isinstance(value, ast.Call) and (_dotted_name(value.func) or "").split(".")[-1] == "socket" and value.args:
            fam = value.args[0]
            return fam.attr if isinstance(fam, ast.Attribute) else fam.id if isinstance(fam, ast.Name) else "?"
        return None
    # A name is judged by its assignments in the innermost function that holds the call (a test file reuses `sock`
    # for TCP in one test and a Unix socket in the next), else by the module's own assignments.
    scopes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def _innermost(line: int):
        inside = [n for n in scopes if n.lineno <= line <= (n.end_lineno or n.lineno)]
        return max(inside, key=lambda n: n.lineno) if inside else None
    scoped_bound: dict = {}
    accepted: list = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    scoped_bound.setdefault((id(_innermost(n.lineno)), t.id), []).append(n.value)
                elif isinstance(t, ast.Tuple) and t.elts and isinstance(t.elts[0], ast.Name):
                    # `conn, addr = await loop.sock_accept(server)`: an accepted socket has its listener's family
                    v = n.value.value if isinstance(n.value, ast.Await) else n.value
                    if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr in (
                            "sock_accept", "accept"):
                        lst = v.args[0] if v.func.attr == "sock_accept" and v.args else v.func.value
                        if isinstance(lst, ast.Name):
                            accepted.append((n.lineno, t.elts[0].id, lst.id))
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            # `with socket.socket() as sock:`
            for i in n.items:
                if isinstance(i.optional_vars, ast.Name):
                    scoped_bound.setdefault((id(_innermost(n.lineno)), i.optional_vars.id), []).append(i.context_expr)
    for line, name, listener in accepted:
        scope = id(_innermost(line))
        scoped_bound.setdefault((scope, name), []).extend(
            scoped_bound.get((scope, listener)) or scoped_bound.get((id(None), listener)) or [None])

    def _unix_socket(name: str, line: int) -> bool:
        vals = scoped_bound.get((id(_innermost(line)), name)) or scoped_bound.get((id(None), name))
        return bool(vals) and all(v is not None and _socket_family(v) == "AF_UNIX" for v in vals)

    # Read from the code, not the text: `assertIn('AF_UNIX', repr(sock))` makes no Unix socket.
    makes_unix_sockets = any((isinstance(n, ast.Attribute) and n.attr == "AF_UNIX")
                             or (isinstance(n, ast.Name) and n.id == "AF_UNIX") for n in ast.walk(tree))

    def _family_unshown(call: ast.Call) -> bool:
        """`loop.sock_sendall(s, ...)` in a file that also makes Unix sockets, where `s` is not traced to an internet
        socket (`socket.socket()`, `AF_INET`, `AF_INET6`): whether it is a Unix socket on this machine is not shown."""
        if not (makes_unix_sockets and isinstance(call.func, ast.Attribute) and call.func.attr.startswith("sock_")
                and call.args):
            return False
        if not isinstance(call.args[0], ast.Name):
            return True
        name = call.args[0].id
        vals = scoped_bound.get((id(_innermost(call.lineno)), name)) or scoped_bound.get((id(None), name)) or []
        inet = vals and all(isinstance(v, ast.Call) and (_dotted_name(v.func) or "").split(".")[-1] == "socket"
                            and (not v.args or _socket_family(v) in ("AF_INET", "AF_INET6")) for v in vals)
        return not inet

    # A class is a stand-in only in a test file, and only when it does not inherit from a network package:
    # `class RetryingPool(urllib3.PoolManager)` in a module is a real transport, and so is any class outside tests.
    _parts = rel.replace("\\", "/").lower().split("/")
    in_test_file = (any(p in ("test", "tests", "testing") for p in _parts[:-1]) or _parts[-1].startswith("test_")
                    or _parts[-1].endswith("_test.py") or _parts[-1] == "conftest.py")
    stand_in_cache: list[set[str]] = []

    def _stand_in_classes() -> set[str]:
        # computed on first use: the tracing it needs is defined further down this function
        if not stand_in_cache:
            stand_in_cache.append({n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and in_test_file
                                   and not any(_made_by_network_package(b) for b in n.bases)})
        return stand_in_cache[0]

    def _stub_transport(recv: ast.AST, line: int) -> str | None:
        """`AuthorizedHttp(credentials, http=HttpStub(...))`: a client built over a transport that is an instance of a
        stand-in class a test file defines. Returns that class's name."""
        if not isinstance(recv, ast.Name) or not in_test_file:
            return None
        scope = id(_innermost(line))
        for v in scoped_bound.get((scope, recv.id)) or scoped_bound.get((id(None), recv.id)) or []:
            v = v.value if isinstance(v, ast.Await) else v
            if not isinstance(v, ast.Call):
                continue
            for kw in v.keywords:
                if kw.arg not in ("http", "session", "transport", "client", "pool_manager", "adapter"):
                    continue
                cands = [kw.value] if isinstance(kw.value, ast.Call) else (
                    scoped_bound.get((scope, kw.value.id)) or [] if isinstance(kw.value, ast.Name) else [])
                for c in cands:
                    cls = (_dotted_name(c.func) or "").split(".")[-1] if isinstance(c, ast.Call) else ""
                    if cls in _stand_in_classes():
                        return cls
        return None

    def _loopback_here(call: ast.Call) -> bool:
        if _literal_loopback_host(call):
            return True
        if isinstance(call.func, ast.Attribute) and call.func.attr.startswith("sock_") and call.args \
                and isinstance(call.args[0], ast.Name) and _unix_socket(call.args[0].id, call.lineno):
            return True
        return any(isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "getsockname"
                   and isinstance(a.func.value, ast.Name) and a.func.value.id in loopback_bound
                   and a.func.value.id not in bound_elsewhere for a in call.args[:2])

    patched_lines: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.With, ast.AsyncWith)) and any(_patches_socket(i.context_expr) for i in n.items):
            patched_lines.update(range(n.lineno, (n.end_lineno or n.lineno) + 1))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(_patches_socket(d) for d in n.decorator_list):
            patched_lines.update(range(n.lineno, (n.end_lineno or n.lineno) + 1))
    # Lines inside a test that patches a client's transport method: `@mock.patch("requests.adapters.HTTPAdapter.send")`.
    # A request made there goes to the patch, not to the network.
    # The patch replaces one library's transport. `wraps=` hands every call on to the real method, so it replaces
    # nothing; and a call on another library (httpx under a requests patch) is not affected by it.
    def _patched_transport(call: ast.AST) -> str | None:
        if not isinstance(call, ast.Call) or not (_dotted_name(call.func) or "").split(".")[-1] == "patch":
            return None
        if any(kw.arg == "wraps" for kw in call.keywords):
            return None
        first = call.args[0] if call.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and _TRANSPORT_PATCH_RE.search(first.value):
            return first.value
        return None
    transport_patched: dict[int, list[str]] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            targets = [t for t in (_patched_transport(i.context_expr) for i in n.items) if t]
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            targets = [t for t in (_patched_transport(d) for d in n.decorator_list) if t]
        else:
            continue
        for ln in range(n.lineno, (n.end_lineno or n.lineno) + 1) if targets else ():
            transport_patched.setdefault(ln, []).extend(targets)

    def _transport_patch_covers(line: int, fn: ast.AST) -> bool:
        """A transport patch in force at `line` replaces the transport the call at `line` goes through."""
        targets = transport_patched.get(line)
        if not targets:
            return False
        if isinstance(fn, ast.Attribute):
            roots = _package_roots(fn.value)
        else:
            full = _imported_as(_dotted_name(fn))
            roots = {full.split(".")[0]} if full else set()
        for target in targets:
            segs = set(target.split("."))
            if {"http", "client"} <= segs:
                segs.add("http.client")
            if any(r in segs or _TRANSPORT_LAYERS.get(r, set()) & segs for r in roots):
                return True
        return False
    # Lines inside `with mock.patch.object(policy, "resolve", ...)`: part of that object is replaced by the test, so
    # what a call on it reaches depends on the replacement.
    object_patched: dict[str, set[int]] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            for i in n.items:
                c = i.context_expr
                if isinstance(c, ast.Call) and (_dotted_name(c.func) or "").endswith("patch.object") and c.args \
                        and isinstance(c.args[0], ast.Name):
                    object_patched.setdefault(c.args[0].id, set()).update(
                        range(n.lineno, (n.end_lineno or n.lineno) + 1))

    # Lines run while a library that replaces the socket is switched on: httpretty (`@httpretty.activate`,
    # `@httprettified`, `with httpretty.enabled()`, `httpretty.enable()`) and mocket (`@mocketize`,
    # `with Mocketizer()`, `Mocket.enable()`). Each answers the addresses registered with it; whether
    # it passes the others to the network is set where it is switched on (`allow_net_connect=False`,
    # `strict_mode=True` refuse them).
    def _socket_double(call: ast.AST) -> tuple[str, bool] | None:
        expr = call.func if isinstance(call, ast.Call) else call
        dotted = _dotted_name(expr) or ""
        parts = dotted.split(".")
        if parts[-1] in ("httprettified", "enabled") and (len(parts) == 1 or parts[0] in ("httpretty", "HTTPretty")) \
                or (parts[-1] == "activate" and parts[0] in ("httpretty", "HTTPretty")):
            lib, key, refuse_when = "httpretty", "allow_net_connect", False
        elif parts[-1] in ("mocketize", "Mocketizer") and (len(parts) == 1 or parts[0] == "mocket"):
            lib, key, refuse_when = "mocket", "strict_mode", True
        else:
            return None
        if parts[-1] == "enabled" and len(parts) == 1:
            return None
        kws = call.keywords if isinstance(call, ast.Call) else []
        refuses = any(kw.arg == key and isinstance(kw.value, ast.Constant) and kw.value.value is refuse_when
                      for kw in kws)
        return lib, refuses

    # Plugins this file defines and registers by name: `Register.register("dummy", DummyConnectionPlugin)`, or under the
    # class's own `name` attribute. A connection opened by that name is the plugin's code.
    local_plugins: set[str] = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "register"
                and len(n.args) >= 2 and isinstance(n.args[1], ast.Name) and n.args[1].id in defined_classes):
            key = n.args[0]
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                local_plugins.add(key.value)
            elif isinstance(key, ast.Attribute) and isinstance(key.value, ast.Name) and key.value.id in defined_classes:
                local_plugins.add(f"{key.value.id}.{key.attr}")

    def _names_local_plugin(arg: ast.AST) -> bool:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value in local_plugins
        dotted = _dotted_name(arg) or ""
        return bool(dotted) and dotted in local_plugins

    # Request objects handed straight to a call that sends them: `urlopen(Request(url))`, `urlretrieve(Request(url))`,
    # `opener.open(Request(url))` on an opener this file builds from urllib.
    # (the opener's receiver is kept and judged where the finding is made, once the receiver rules exist)
    sent_on_build: dict[int, ast.AST | None] = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        sender = n.func.attr if isinstance(n.func, ast.Attribute) else (n.func.id if isinstance(n.func, ast.Name) else "")
        if sender in ("urlopen", "urlretrieve") or (sender == "open" and isinstance(n.func, ast.Attribute)):
            opener = n.func.value if sender == "open" else None
            for a in list(n.args[:1]) + [kw.value for kw in n.keywords if kw.arg in ("url", "fullurl")]:
                if isinstance(a, ast.Call):
                    built = a.func.attr if isinstance(a.func, ast.Attribute) else (
                        a.func.id if isinstance(a.func, ast.Name) else "")
                    if built in TARGET_BUILDERS:
                        sent_on_build[id(a)] = opener

    doubled: dict[int, tuple[str, bool]] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            for it in n.items:
                d = _socket_double(it.context_expr) if isinstance(it.context_expr, ast.Call) else None
                if d:
                    doubled.update((k, d) for k in range(n.lineno, (n.end_lineno or n.lineno) + 1))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in n.decorator_list:
                d = _socket_double(dec)
                if d:
                    doubled.update((k, d) for k in range(n.lineno, (n.end_lineno or n.lineno) + 1))
            if not isinstance(n, ast.ClassDef):
                for sub in ast.walk(n):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "enable" \
                            and (_dotted_name(sub.func.value) or "") in ("httpretty", "HTTPretty", "Mocket",
                                                                         "mocket.Mocket"):
                        lib = "mocket" if "ocket" in (_dotted_name(sub.func.value) or "") else "httpretty"
                        key, refuse_when = ("strict_mode", True) if lib == "mocket" else ("allow_net_connect", False)
                        refuses = any(kw.arg == key and isinstance(kw.value, ast.Constant)
                                      and kw.value.value is refuse_when for kw in sub.keywords)
                        doubled.update((k, (lib, refuses))
                                       for k in range(sub.lineno, (n.end_lineno or sub.lineno) + 1))

    def _internet_socket(expr: ast.AST) -> bool:
        """`sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)` in this file: an internet socket."""
        evidence = bound.get(expr.id, []) if isinstance(expr, ast.Name) else []
        if not evidence:
            return False
        for e in evidence:
            dotted = (_dotted_name(e.func) or "") if isinstance(e, ast.Call) else ""
            if not (dotted.split(".")[-1] == "socket" and dotted.split(".")[0] in socket_aliases | {"socket"}):
                return False
            family = e.args[0] if e.args else next((kw.value for kw in e.keywords if kw.arg == "family"), None)
            name = (_dotted_name(family) or "").rsplit(".", 1)[-1] if family is not None else "AF_INET"
            if name not in ("AF_INET", "AF_INET6"):
                return False
        return True

    def _bound_to_event_loop(recv: ast.AST) -> bool:
        """`loop = asyncio.get_event_loop()`, `self.lp = asyncio.new_event_loop()`: a name made an event loop."""
        if isinstance(recv, ast.Name):
            evidence = bound.get(recv.id, [])
        elif isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id in ("self", "cls"):
            evidence = self_attrs.get(recv.attr, [])
        else:
            return False
        return bool(evidence) and all(
            isinstance(e, ast.Call) and (_dotted_name(e.func) or "").rsplit(".", 1)[-1]
            in ("get_event_loop", "get_running_loop", "new_event_loop") for e in evidence)

    def _receiver_is_network(recv: ast.AST, depth: int = 0) -> bool:
        """Whether the object a method is called on traces back to a network package."""
        if depth > 3:
            return False
        if isinstance(recv, ast.Call):
            return _made_by_network_package(recv, depth + 1)
        dotted = _dotted_name(recv)
        if _names_network_package(dotted):
            return True                                   # `requests.get`, `http.client.HTTPConnection`
        if isinstance(recv, ast.Name):
            evidence = bound.get(recv.id, []) + with_bound.get(recv.id, []) + annotated.get(recv.id, [])
        elif isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id in ("self", "cls"):
            evidence = self_attrs.get(recv.attr, [])
        else:
            return False
        return any(_made_by_network_package(e, depth + 1) for e in evidence)

    def _package_roots(expr: ast.AST | None, depth: int = 0) -> set[str]:
        """The top-level packages an expression's object traces back to within this file (`httpx` for
        `httpx.Client().get`, `requests` for a name bound to `requests.Session()`). Empty when it cannot tell."""
        if expr is None or depth > 3:
            return set()
        if isinstance(expr, ast.Await):
            return _package_roots(expr.value, depth + 1)
        if isinstance(expr, ast.Call):
            fnx = expr.func
            if isinstance(fnx, ast.Attribute) and isinstance(fnx.value, ast.Call):
                return _package_roots(fnx.value, depth + 1)
            full = _imported_as(_dotted_name(fnx))
            if full:
                return {full.split(".")[0]}
            return _package_roots(fnx.value, depth + 1) if isinstance(fnx, ast.Attribute) else set()
        if isinstance(expr, (ast.Name, ast.Attribute)):
            full = _imported_as(_dotted_name(expr))
            if full:
                return {full.split(".")[0]}
            if isinstance(expr, ast.Name):
                evidence = bound.get(expr.id, []) + with_bound.get(expr.id, []) + annotated.get(expr.id, [])
            elif isinstance(expr.value, ast.Name) and expr.value.id in ("self", "cls"):
                evidence = self_attrs.get(expr.attr, [])
            else:
                return set()
            roots: set[str] = set()
            for e in evidence:
                roots |= _package_roots(e, depth + 1)
            return roots
        return set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "asyncio" or a.name.startswith("asyncio."):
                    asyncio_aliases.add(a.asname or "asyncio")
                    module_imports_asyncio = True
                elif a.name == "socket":
                    socket_aliases.add(a.asname or "socket")
                elif a.name == "logging.handlers":
                    module_imports_logging_handlers = True
        elif isinstance(node, ast.ImportFrom) and not node.level:
            top = (node.module or "").split(".")[0]
            if top == "asyncio":
                module_imports_asyncio = True
            if (node.module or "") == "logging.handlers" or (
                    (node.module or "") == "logging" and any(a.name == "handlers" for a in node.names)):
                module_imports_logging_handlers = True

    for node in ast.walk(tree):
        # network-capable imports
        if isinstance(node, ast.Import):
            for a in node.names:
                cls = _classify(_compat_module(a.name))
                # `import urllib` and `import wsgiref` load a package with nothing in it. They
                # are a finding only when the file goes on to use a part that reaches the network.
                if a.name in _EMPTY_PACKAGES and not (_EMPTY_PACKAGES[a.name] & package_attrs.get(a.asname or a.name, set())):
                    cls = None
                shown = f"import {a.name}"
                if cls not in ("network", "inbound"):
                    # `import http` then `http.client.HTTPSConnection(...)`: a network submodule reached through the
                    # package's name (`import http.cookies` binds `http` too)
                    bound_as = a.asname or a.name.split(".")[0]
                    root = a.name if a.asname else a.name.split(".")[0]
                    via = sorted(attr for attr in package_attrs.get(bound_as, ())
                                 if _classify(f"{root}.{attr}") == "network" and _classify(root) != "network")
                    if via:
                        cls, shown = "network", f"import {a.name}, used as {root}.{via[0]}"
                _report_import(node.lineno, shown, cls)
                _note_unlisted(a.name, cls)
                if a.name.split(".")[0] in _PRIVATE_PROCESS_MODULES:
                    out.append(Finding(rel, node.lineno, "native-call", _PRIVATE_PROCESS_DETAIL.format(a.name)))
        elif isinstance(node, ast.ImportFrom):
            # A RELATIVE import is the project's own module, whatever its name (`from .segment import Segment`
            # is not the Segment analytics SDK).
            if node.level:
                continue
            mod = _compat_module(node.module or "")
            if mod in _COMPAT_PREFIXES:
                # `from six.moves import http_client`: each name is a standard-library module under another name
                for a in node.names:
                    target = _compat_module(f"{mod}.{a.name}")
                    if target == f"{mod}.{a.name}":
                        continue
                    cls = _classify(target)
                    if target in _EMPTY_PACKAGES and not (
                            _EMPTY_PACKAGES[target] & package_attrs.get(a.asname or a.name, set())):
                        cls = None          # `from six.moves import urllib`: the package, used or not
                    _report_import(node.lineno, f"from {mod} import {a.name} ({target})", cls)
                continue
            cls = _classify(mod)
            # `from urllib import parse` is the same pure submodule as `from urllib.parse import ...`, spelled
            # differently: judge the names actually imported, not only the package they come from.
            if cls and node.names and all(f"{mod}.{a.name}" in NON_NETWORK_SUBMODULES for a in node.names):
                cls = None
            # `from urllib import unquote, splitquery`: Python 2 kept its pure string helpers at the package top, and
            # `from urllib import parse` takes a pure submodule. A line importing only such names fetches nothing.
            if mod == "urllib" and cls == "network" and node.names and all(
                    a.name in URLLIB_PURE_NAMES for a in node.names):
                cls = None
            # `from wsgiref import validate` takes a part of the package that binds nothing.
            if mod == "wsgiref" and cls == "inbound" and not any(a.name in ("simple_server", "*") for a in node.names):
                cls = "inbound-dependency"
            # `from wsgiref.simple_server import demo_app` takes an application; only a server binds.
            if mod == "wsgiref.simple_server" and cls == "inbound" and not any(
                    a.name in ("make_server", "*") or a.name.endswith("Server") for a in node.names):
                cls = "inbound-dependency"
            # `from http.server import BaseHTTPRequestHandler` and `from socketserver import ThreadingMixIn`
            # take a handler or a mix-in. Only a server class (or `test`, or `*`) can bind a socket.
            if mod in ("http.server", "socketserver", "SocketServer", "BaseHTTPServer", "SimpleHTTPServer",
                       "CGIHTTPServer") and cls == "inbound" and not any(
                    a.name == "*" or a.name == "test" or a.name.endswith("Server") for a in node.names):
                cls = "inbound-dependency"
            # `from http import client` names a listed module in two parts: judge the dotted names too.
            if cls not in ("network", "inbound") and mod:
                for a in node.names:
                    sub = _classify(f"{mod}.{a.name}")
                    if sub == "network" or (sub == "inbound" and cls != "network"):
                        cls = sub
                        if sub == "network":
                            break
            _report_import(node.lineno, f"from {mod} import ..." + (
                f" (written as {node.module})" if node.module and node.module != mod else ""), cls)
            _note_unlisted(mod, cls)
            if (mod or "").split(".")[0] in _PRIVATE_PROCESS_MODULES and not node.level:
                out.append(Finding(rel, node.lineno, "native-call", _PRIVATE_PROCESS_DETAIL.format(mod)))

        # process spawns, dynamic loading, native calls, URL sinks
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            recv_root = _attr_root_name(fn.value) if isinstance(fn, ast.Attribute) else None
            # The module the call reaches, whatever the file called it: `sp.run` after
            # `import subprocess as sp` and `system(...)` after `from os import system`.
            recv_mod = module_alias.get(recv_root, recv_root) if recv_root else None
            if isinstance(fn, ast.Name) and fn.id in from_alias:
                recv_mod, name = from_alias[fn.id]
            elif isinstance(fn, ast.Attribute):
                dotted = _dotted_name(fn.value)
                if dotted and "." in dotted:
                    head, _, tail = dotted.partition(".")
                    recv_mod = f"{module_alias.get(head, head)}.{tail}"
            recv_top = recv_mod.split(".")[0] if recv_mod else None
            from_import_call = isinstance(fn, ast.Name) and fn.id in from_alias
            # asyncio network calls: flagged at the CALL, never at the import.
            # `asyncio.open_connection(...)`, `loop.create_connection(...)` and a bare
            # `open_connection(...)` after `from asyncio import open_connection` all land
            # here; a bare `import asyncio` for concurrency does not.
            if name in _LOOKUP_CALLS and isinstance(fn, ast.Attribute):
                # `socket.getaddrinfo(h, 443)`, `loop.getaddrinfo(h, 80)`: a name lookup, which asks a resolver
                owner = _dotted_name(fn.value) or ""
                owner_root = module_alias.get(owner.split(".")[0], owner.split(".")[0]).split(".")[0]
                if owner_root in _LOOKUP_MODULES or owner.rsplit(".", 1)[-1] in ("loop", "_loop", "event_loop") \
                        or _bound_to_event_loop(fn.value):
                    target = node.args[0] if node.args else next(
                        (kw.value for kw in node.keywords if kw.arg in ("host", "sockaddr")), None)
                    if isinstance(target, ast.Tuple) and target.elts:
                        target = target.elts[0]
                    here = target is None or (isinstance(target, ast.Constant) and (
                        target.value is None or (isinstance(target.value, str)
                                                 and _THIS_MACHINE_HOST_RE.fullmatch(target.value) is not None)))
                    numeric = None
                    if name == "getaddrinfo" and isinstance(target, ast.Constant) and isinstance(target.value, str):
                        import ipaddress
                        try:
                            numeric = ipaddress.ip_address(target.value.strip("[]").split("%", 1)[0])
                        except ValueError:
                            numeric = None
                    if numeric is not None and not numeric.is_loopback and not numeric.is_unspecified:
                        pass        # `getaddrinfo("10.0.0.5", 80)`: a numeric address is parsed, not looked up
                    elif here or numeric is not None:
                        out.append(Finding(rel, node.lineno, "loopback-call",
                                           f"{owner}.{name}(...): looks up a name of this machine; nothing leaves it "
                                           "at this line"))
                    else:
                        out.append(Finding(rel, node.lineno, "network-call",
                                           f"{owner}.{name}(...): looks a name up, which asks a resolver on the "
                                           "network (DNS) unless the name is this machine's"))
            if name in ASYNCIO_NET_CALLS and (isinstance(fn, ast.Attribute)
                                              or (from_import_call and recv_top in ("asyncio", "socket"))):
                # The match is on the method NAME, so say only what the module shows: a wrapper with
                # that name can be real network code, and the claim is scoped to the evidence.
                recv = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else ""
                server = name in ASYNCIO_SERVER_CALLS
                is_socket = recv in socket_aliases or (from_import_call and recv_top == "socket")
                # asyncio's own call is made on asyncio or on an event loop. The same method name on another
                # object (an SSH connection, a project's handler) is that object's, and is judged as one.
                recv_tail = (_dotted_name(fn.value) or "").rsplit(".", 1)[-1] if isinstance(fn, ast.Attribute) else ""
                loop_like = recv_tail in ("loop", "_loop", "event_loop", "ev_loop") or (
                    isinstance(fn, ast.Attribute) and _bound_to_event_loop(fn.value))
                # `conn.start_server(...)` in a file that imports asyncssh, and `self.create_server(...)` in asyncssh's
                # own source (an SSH connection asking the far host to listen): the server-named method belongs to that
                # object, not to asyncio. A test's own `self.start_server()` / `cls.create_server()` starts a server
                # here and keeps its claim.
                other_owner = server and isinstance(fn, ast.Attribute) and recv not in asyncio_aliases and not loop_like \
                    and recv not in module_alias and recv not in from_alias and (
                        in_provider_source or (server_provider_imported and recv not in ("self", "cls")))
                is_asyncio = recv in asyncio_aliases or (from_import_call and recv_top == "asyncio") or (
                    (loop_like or module_imports_asyncio) and not is_socket and not other_owner)
                # `sock=` in place of a host and port. (`sock_connect(sock=s, address=...)` connects s itself.)
                sock_kw = next((kw.value for kw in node.keywords if kw.arg == "sock"), None) if name in (
                    "create_connection", "create_datagram_endpoint", "open_connection") else None
                if not server and sock_kw is not None and not _internet_socket(sock_kw):
                    # `create_datagram_endpoint(..., sock=self.socket)`: the call attaches to a socket made
                    # elsewhere (a netlink socket to the kernel, one end of a socketpair, a TCP connection)
                    # and opens nothing itself
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(..., sock=...): attaches to a socket made elsewhere; whether that "
                                       "socket reaches a network is NOT shown by this line"))
                elif is_socket and server:
                    out.append(Finding(rel, node.lineno, "inbound-listener",
                                       f"socket.{name}(...): binds a listening socket (INBOUND, not egress)"))
                elif is_socket and _loopback_here(node):
                    out.append(Finding(rel, node.lineno, "loopback-call",
                                       f"socket.{name}(...): connects to an address on this machine; "
                                       "nothing leaves it at this line"))
                elif is_socket:
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"socket.{name}(...): opens a socket connection"))
                elif (not server and recv not in asyncio_aliases and not loop_like and isinstance(fn, ast.Attribute)
                      and _names_network_package(_dotted_name(fn.value))):
                    # `websocket.create_connection(...)`: the name is shared with asyncio, the package is not
                    shown_pkg = _dotted_name(fn.value)
                    out.append(Finding(rel, node.lineno, "loopback-call" if _loopback_here(node) else "network-call",
                                       f"{shown_pkg}.{name}(...): a call into the network package {shown_pkg}"
                                       + ("; it connects to an address on this machine" if _loopback_here(node)
                                          else "")))
                elif (not server and isinstance(fn, ast.Attribute) and not loop_like and recv not in asyncio_aliases
                      and not _loopback_here(node) and node.lineno not in patched_lines
                      and not doubled.get(node.lineno, ("", False))[1] and _project_object(fn.value, name)):
                    # the project's own method, in a file that also uses asyncio: what it does is in the project's code
                    on = _dotted_name(fn.value) or "an object"
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(...): a method of the project's own code named like asyncio's connection "
                                       f"call; what {on}.{name} does is NOT shown by this line"))
                elif is_asyncio and server:
                    out.append(Finding(rel, node.lineno, "inbound-listener",
                                       f"{name}(...): asyncio server, binds a listening socket (INBOUND, not egress)"))
                elif is_asyncio and _loopback_here(node):
                    out.append(Finding(rel, node.lineno, "loopback-call",
                                       f"{name}(...): asyncio connection to an address on this machine; "
                                       "nothing leaves it at this line"))
                elif is_asyncio and name in ("open_unix_connection", "create_unix_connection") and (
                        recv in asyncio_aliases or from_import_call
                        or (isinstance(fn, ast.Attribute) and (_dotted_name(fn.value) or "").rsplit(".", 1)[-1]
                            in ("loop", "_loop", "event_loop"))):
                    # asyncio's own call, or an event loop's: a Unix socket is a path on this machine.
                    # The same method name on another object (an SSH connection) can reach a far host.
                    out.append(Finding(rel, node.lineno, "loopback-call",
                                       f"{name}(...): asyncio connection to a Unix socket on this machine; "
                                       "nothing leaves it at this line"))
                elif is_asyncio and _family_unshown(node):
                    on = node.args[0].id if isinstance(node.args[0], ast.Name) else "the socket"
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(...): this file also makes Unix sockets, and whether {on} is one (on "
                                       "this machine) or an internet socket is NOT shown"))
                elif is_asyncio:
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"{name}(...): asyncio network connection"))
                elif not server and _loopback_here(node):
                    out.append(Finding(rel, node.lineno, "loopback-call",
                                       f"{name}(...): connects to an address on this machine; "
                                       "nothing leaves it at this line"))
                elif not server and (node.lineno in patched_lines or doubled.get(node.lineno, ("", False))[1]):
                    lib = doubled[node.lineno][0] if node.lineno in doubled else "a test double"
                    out.append(Finding(rel, node.lineno, "network-target",
                                       f"{name}(...): called while {lib} replaces the socket; nothing reaches "
                                       "the network at this line"))
                elif not server and recv and node.lineno in object_patched.get(recv, ()):
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(...): called while the test replaces part of {recv} (patch.object); "
                                       "whether it reaches the network is NOT shown by this line"))
                elif not server and isinstance(fn, ast.Attribute) and _project_object(fn.value, name):
                    # the project's own method (`Connections.create_connection` builds a client and registers it):
                    # what it does is in the project's code, not shown by this line
                    on = _dotted_name(fn.value) or "an object"
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(...): a method of the project's own code named like asyncio's connection "
                                       f"call; what {on}.{name} does is NOT shown by this line"))
                elif not server and node.args and _names_local_plugin(node.args[0]):
                    # `task.host.open_connection("dummy", ...)` where this file defines the plugin class and registers it
                    # under that name: what opens is that plugin's code, in this file
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(...): opens a connection plugin this file defines and registers; what it "
                                       "opens is in that plugin, NOT shown by this line"))
                elif not server:
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"{name}(...): method named like asyncio's connection call; this module does "
                                       "not import asyncio, so what it opens is NOT resolved"))
                else:
                    # A server method on an object this file does not trace, with no asyncio here at all: paramiko's
                    # `Transport.start_server` negotiates on a socket accepted elsewhere and binds nothing.
                    on = (_dotted_name(fn.value) or "an object") if isinstance(fn, ast.Attribute) else name
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{name}(...): a method named like asyncio's "
                                       f"{'server' if server else 'connection'} call; what {on} is was NOT resolved, so "
                                       f"whether it {'binds a listening socket' if server else 'opens a connection'} "
                                       "is not shown"))
            # standard-library calls that connect or listen from a module that is not an import finding
            std = STDLIB_NET_CALLS.get((recv_mod, name)) if recv_mod else None
            reached = _resolves_to(fn, module_alias, from_alias) if name == "parse" else ""
            # (`xml.dom.pulldom.parse` is not one: it opens a name it is given as a file)
            sax_module = reached if reached == "xml.sax.parse" else (
                "xml.sax.parse" if recv_mod == "xml.sax" and name == "parse" else "")
            sax = bool(sax_module) or (name == "parse" and _is_sax_parser(
                fn.value if isinstance(fn, ast.Attribute) else None, module_alias, from_alias, bound, tree))
            if sax:
                # the SAX parser opens a source given as a name with urllib when it is an address: a literal file name
                # or an open file is read here, anything else is not shown
                shown = f"{sax_module}(...)" if sax_module else "parse(...) on a SAX parser"
                source = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "source"),
                                                             None)
                if isinstance(source, ast.Name) and isinstance(assigned.get(source.id), ast.Constant):
                    source = assigned[source.id]      # `FEED = "https://..."`, bound once, then `parse(FEED, h)`
                if any(URL_RE.search(s) for s in _string_args(node)) or (
                        isinstance(source, ast.Constant) and isinstance(source.value, str) and URL_RE.search(source.value)):
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"{shown}: the SAX parser fetches a system identifier given as a URL"))
                elif source is not None and not _local_xml_source(source, bound, tree):
                    out.append(Finding(rel, node.lineno, "unresolved-call",
                                       f"{shown}: the SAX parser fetches its source with urllib when it is an address; "
                                       "what it is given is NOT shown by this line"))
            elif std:
                out.append(Finding(rel, node.lineno, std[0], f"{recv_mod}.{name}(...): {std[1]}"))
            # subprocess.* : shell=True, shell strings, argv lists
            # A bare `run(...)` or `call(...)` that the file defines itself is the file's own helper,
            # not subprocess: its body is where the process is started, and that is reported there.
            own_helper = isinstance(fn, ast.Name) and fn.id in defined_functions and fn.id not in from_alias
            # `subprocess.run(...)`, a bare `run(...)`, or `Popen` on anything. A method called on what another call
            # returns (`_runner().run(...)`, invoke's own runner) is that object's method, not subprocess.
            subprocess_like = recv_top == "subprocess" or (recv_top is None and not isinstance(fn, ast.Attribute))
            if name in SUBPROCESS_CALLERS and not own_helper and (subprocess_like or name == "Popen"):
                # `shell=1` is as true as `shell=True`
                shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and bool(kw.value.value)
                            for kw in node.keywords)
                # the command is the first positional argument or the `args=` keyword
                commands = list(node.args[:1]) + [kw.value for kw in node.keywords if kw.arg == "args"]
                strings = [s for c in commands for s in (_literal_argv(c, assigned, split=False) or [])]
                if shell or name in ("getoutput", "getstatusoutput"):
                    hit = _SHELL_NET_WORD_RE.search(" ".join(strings)) if strings else None
                    extra = f"; the string invokes {hit.group(1)!r}" if hit else ""
                    out.append(Finding(rel, node.lineno, "subprocess-shell",
                                       f"{name}(shell=True): shell string can encode remote egress{extra}"))
                for c in commands:
                    resolved = assigned.get(c.id) if isinstance(c, ast.Name) else c
                    if shell and not isinstance(resolved, (ast.List, ast.Tuple)):
                        continue        # a shell string: reported above, not split into an argv
                    argv = _literal_argv(c, assigned)
                    # A one-word command string is a program started with no arguments at all:
                    # `Popen('docker')` prints its usage. (A list may hold arguments that are
                    # not literals, so a one-element LIST says nothing about how it is run.)
                    bare = isinstance(resolved, ast.Constant) and argv is not None and len(argv) == 1
                    if argv and not bare:
                        out += _argv_findings(rel, node.lineno, name, argv, local_modules)
            # os.system / os.popen shell strings, and IPython's `get_ipython().system(...)`
            # the notebook's shell, called directly (`get_ipython().system(...)`) or through a name bound to it
            on_ipython = isinstance(fn, ast.Attribute) and (
                (isinstance(fn.value, ast.Call) and isinstance(fn.value.func, ast.Name)
                 and fn.value.func.id == "get_ipython")
                or (isinstance(fn.value, ast.Name) and fn.value.id in ipython_names))
            ipython_shell = on_ipython and name in ("system", "getoutput", "system_raw", "system_piped")
            first_text = (node.args[0].value if node.args and isinstance(node.args[0], ast.Constant)
                          and isinstance(node.args[0].value, str) else None)
            if on_ipython and name in ("ex", "ev", "run_cell", "run_code", "runcode", "safe_execfile",
                                       "safe_run_module", "run_cell_async"):
                # code handed to the shell as text: read as a cell when it is written out, else not resolved
                if first_text is not None and name in ("ex", "ev", "run_cell", "run_cell_async"):
                    out += _check_cell_text(path, rel, node.lineno, first_text, f"get_ipython().{name}(...)",
                                            local_modules, shadowed, unlisted, own_names, importable)
                else:
                    out.append(Finding(rel, node.lineno, "dynamic-exec",
                                       f"get_ipython().{name}(...): runs code or a file the line does not spell out; "
                                       "what it runs is NOT resolved"))
            # the calls nbconvert writes for magics: `run_cell_magic('bash', '', '...')`, `run_line_magic('sx', '...')`,
            # and the older `magic('sx curl ...')`, which is a line magic given as one line
            call = name
            if on_ipython and name == "magic" and first_text is not None and first_text.lstrip("%").split():
                call = "run_line_magic"
                magic, _, body = first_text.lstrip("%").partition(" ")
            elif on_ipython and name in ("run_cell_magic", "run_line_magic") and first_text is not None:
                magic = first_text
                body_at = 2 if name == "run_cell_magic" else 1
                body = node.args[body_at].value if len(node.args) > body_at and isinstance(
                    node.args[body_at], ast.Constant) and isinstance(node.args[body_at].value, str) else ""
            else:
                magic = None
            if magic is not None:
                hit = _SHELL_NET_WORD_RE.search(body)
                extra = f"; it invokes {hit.group(1)!r}" if hit else ""
                if (call == "run_cell_magic" and magic in _PROGRAM_CELL_MAGICS) or (
                        call == "run_line_magic" and magic in ("system", "sx")):
                    out.append(Finding(rel, node.lineno, "subprocess-shell",
                                       f"get_ipython().{name}({magic!r}, ...): runs its text as a program{extra}"))
                elif call == "run_line_magic" and magic in ("pip", "conda", "mamba", "uv"):
                    out.append(Finding(rel, node.lineno, "subprocess-net-binary",
                                       f"get_ipython().{name}({magic!r}, ...): installs packages from a "
                                       "remote index"))
                elif call == "run_line_magic" and magic in ("load", "loadpy", "pycat") and _has_external_url(body):
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"get_ipython().{name}({magic!r}, <URL>): fetches the URL into the notebook"))
                elif call == "run_line_magic" and magic == "sql" and DSN_RE.search(body):
                    out.append(_dsn_finding(rel, node.lineno, f"get_ipython().{name}('sql', ...)", body))
                exported = _exported_magic_code(node)
                if exported:
                    out += _check_cell_text(path, rel, node.lineno, exported[2],
                                            f"get_ipython().{name}({magic!r}, ...)", local_modules, shadowed,
                                            unlisted, own_names, importable, written=magic in ("writefile", "file"))
            if (name in OS_SHELL_CALLERS and recv_top == "os") or ipython_shell:
                strings = [s for a in node.args[:1] for s in (_literal_argv(a, assigned, split=False) or [])]
                hit = _SHELL_NET_WORD_RE.search(" ".join(strings)) if strings else None
                extra = f"; the string invokes {hit.group(1)!r}" if hit else ""
                web = _PYTHON_WEB_SERVER_RE.search(" ".join(strings)) if strings and not hit else None
                if web:
                    # `!python -m http.server 8000`: a web server for the folder (INBOUND, not egress)
                    extra = f"; the string runs 'python -m {web.group(1)}', a web server for this folder (INBOUND)"
                shown = "get_ipython().system" if ipython_shell else f"os.{name}"
                out.append(Finding(rel, node.lineno, "subprocess-shell", f"{shown}(...): shell string{extra}"))
            # every other spawn: os.exec*/spawn*/posix_spawn/startfile, asyncio.create_subprocess_*, pty.spawn
            if name in SPAWN_CALLERS and recv_top in ("os", "asyncio", "pty", None):
                spawned = node
                if name.startswith(("exec", "spawn")) and node.keywords:
                    # `os.execvp(file="git", args=[...])`, `os.spawnvp(mode=..., file=..., args=...)`: the keywords in
                    # the order the positions take
                    named = {k.arg: k.value for k in node.keywords if k.arg}
                    spawned = ast.Call(func=node.func, keywords=[], args=list(node.args) + [
                        named[k] for k in ("mode", "file", "path", "args", "argv") if k in named])
                flat = _argv_strings(spawned, holes=True)
                for a in spawned.args:
                    if isinstance(a, ast.Name) and a.id in assigned:
                        flat += _literal_argv(a, assigned) or []
                if name == "startfile":
                    if any(URL_RE.search(s) for s in flat):
                        out.append(Finding(rel, node.lineno, "network-call",
                                           "os.startfile(<URL>): hands a URL to the operating system's handler"))
                elif name == "create_subprocess_shell":
                    hit = _SHELL_NET_WORD_RE.search(" ".join(flat)) if flat else None
                    extra = f"; the string invokes {hit.group(1)!r}" if hit else ""
                    out.append(Finding(rel, node.lineno, "subprocess-shell",
                                       f"asyncio.create_subprocess_shell(...): shell string{extra}"))
                elif flat:
                    if name.startswith(("exec", "spawn", "posix_spawn")) and recv_top in ("os", None) and name != "spawn":
                        # `os.spawnlp(os.P_WAIT, "git", "git", "pull")`, `os.execvp("git", ["git", "pull"])`: a mode
                        # first for spawn*, then the program, then the argv it is given, whose argv[0] names it (as it
                        # likes: `os.execlp("git", "git-sync", "pull")` runs git with the argument `pull`). The command
                        # is the program and the argv after argv[0].
                        if name.startswith("spawn") and flat[0] == _ARGV_HOLE:
                            flat = flat[1:]
                        if len(flat) >= 2 and flat[0] != _ARGV_HOLE and flat[1] != _ARGV_HOLE:
                            flat = [flat[0]] + flat[2:]
                    out += _argv_findings(rel, node.lineno, name, flat, local_modules)
            # dynamic exec/eval/compile/import: undecidable payloads, flagged unconditionally
            builtin_attr = (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                            and fn.value.id in {"builtins", "__builtins__"})
            bare_builtin = isinstance(fn, ast.Name) and fn.id in {"exec", "eval", "compile", "__import__"}
            if bare_builtin and (fn.id in rebound or fn.id in _local_names.get(id(node), ())):
                # The file binds this name itself (`def eval(...)`, `from py_compile import compile`).
                # Which one a given call reaches depends on scope, which is not resolved here.
                out.append(Finding(rel, node.lineno, "method-named-exec",
                                   f"{fn.id}(...): this file also binds the name {fn.id} (a function, an import, a parameter or a variable), "
                                   "so whether this call is the builtin is NOT resolved"))
            elif bare_builtin or (
                    builtin_attr and name in {"exec", "eval", "compile", "__import__"}) or (
                    isinstance(fn, ast.Attribute) and name == "__import__"):
                out.append(Finding(rel, node.lineno, "dynamic-exec", f"{name}(...): dynamic code execution"))
            elif isinstance(fn, ast.Attribute) and name in {"exec", "eval"}:
                # A METHOD named exec or eval is not the builtin: a container command, an SQL query, a model's
                # inference mode, a debugger. Reported under its own kind so a reader can tell it apart.
                out.append(Finding(rel, node.lineno, "method-named-exec",
                                   f".{name}(...): a method named {name}, not the builtin; whether it executes "
                                   "code is NOT resolved"))
            if name == "import_module":
                out.append(Finding(rel, node.lineno, "dynamic-exec", "importlib.import_module(...)"))
            # `getattr(importlib, "import_" + "module")`, `getattr(builtins, name)`: a function of the import
            # machinery or the builtins, chosen by a name the line does not spell out (or by one that loads code)
            if isinstance(fn, ast.Name) and fn.id == "getattr" and "getattr" not in rebound and "getattr" not in _local_names.get(id(node), ()) and len(node.args) >= 2 \
                    and isinstance(node.args[0], ast.Name):
                owner = node.args[0].id if node.args[0].id in ("__builtins__",) else (
                    _imported_as(node.args[0].id) or "")
                attr = node.args[1]
                spelled = attr.value if isinstance(attr, ast.Constant) and isinstance(attr.value, str) else None
                if owner in ("importlib", "builtins", "__builtins__") and (
                        spelled is None or spelled in {"import_module", "__import__", "exec", "eval", "compile"}):
                    out.append(Finding(rel, node.lineno, "dynamic-exec",
                                       f"getattr({node.args[0].id}, ...): a function of {owner} chosen at run time; "
                                       "what it loads or runs is NOT resolved"))
            loader = LOADER_CALLS.get((recv_top, name)) or (
                LOADER_CALLS.get((None, name)) if (recv_root or from_import_call) else None)
            if loader:
                shown = f"{recv_top}.{name}" if recv_top else name
                out.append(Finding(rel, node.lineno, "dynamic-exec", f"{shown}(...): {loader}; what runs is NOT resolved"))
            # native libraries: ctypes loaders, `ctypes.windll.<lib>.<fn>(...)` chains, cffi's dlopen
            chain_attrs = _attr_chain(fn)
            if (recv_top, name) in FFI_CALLS or (recv_root in FFI_ATTR_ROOTS) or (
                    recv_top == "ctypes" and chain_attrs & FFI_ATTR_ROOTS) or (
                    name == "dlopen" and isinstance(fn, ast.Attribute)):
                # (the whole chain, so the library is named: `ctypes.windll.urlmon.URLDownloadToFileW`)
                shown = _dotted_name(fn) if (chain_attrs & FFI_ATTR_ROOTS or recv_root in FFI_ATTR_ROOTS) \
                    and _dotted_name(fn) else (
                    f"{recv_top}.{name}" if recv_top else name)
                out.append(Finding(rel, node.lineno, "native-call",
                                   f"{shown}(...): calls into a native library; what it does is outside static analysis"))
            # logging handlers that send every record over the network
            if name in NETWORK_LOG_HANDLERS and (module_imports_logging_handlers or recv_top == "logging"):
                # SysLogHandler is judged by its address: a path (`/dev/log`) is a Unix socket on this machine,
                # and with none at all it sends to ('localhost', 514). A host written elsewhere is the network.
                address = next((kw.value for kw in node.keywords if kw.arg == "address"),
                               node.args[0] if node.args else None)
                syslog_here = name == "SysLogHandler" and (
                    address is None
                    or (isinstance(address, ast.Constant) and isinstance(address.value, str))
                    or (isinstance(address, (ast.Tuple, ast.List)) and address.elts
                        and isinstance(address.elts[0], ast.Constant) and isinstance(address.elts[0].value, str)
                        and _THIS_MACHINE_HOST_RE.fullmatch(address.elts[0].value) is not None))
                if syslog_here:
                    out.append(Finding(rel, node.lineno, "loopback-call",
                                       "logging.handlers.SysLogHandler(...): sends log records to the syslog daemon on "
                                       "this machine (a Unix socket path, or localhost); nothing leaves it at this line"))
                else:
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"logging.handlers.{name}(...): sends every log record over the network"))
            # hub and dataset downloaders
            if name in {"download"} and recv_top in {"nltk", "spacy"}:
                out.append(Finding(rel, node.lineno, "network-call", f"{recv_top}.download(...): fetches a resource"))
            if recv_top == "torch" and isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Attribute) \
                    and fn.value.attr == "hub":
                out.append(Finding(rel, node.lineno, "network-call", f"torch.hub.{name}(...): fetches from a remote hub"))
            # a UNC path (`\\fs01\builds\x`) opened, copied or listed: a file on another machine, reached over SMB
            unc_host = _python_unc_host(node, name, assigned, path_bound)
            smb_library = (_dotted_name(node.func) or "").split(".")[0] in ("smbclient", "smbprotocol")
            if unc_host is not None and unc_host.startswith("/") and smb_library:
                # `smbclient.copyfile(a, "//host/share/x")`: the SMB library reads it as a share on every system
                if not _UNC_THIS_MACHINE_RE.fullmatch(unc_host[1:]):
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"{name}(...): reads or writes a path on another machine (a UNC path, reached "
                                       "over SMB)"))
            elif unc_host is not None and unc_host.startswith("/"):
                # `//fs01/share/x`: a UNC path where Windows runs the code, a local path elsewhere
                if not _UNC_THIS_MACHINE_RE.fullmatch(unc_host[1:]):
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"{name}(...): reads or writes //{unc_host[1:]}/..., which on Windows is a path on "
                                       "another machine reached over SMB (on Linux and macOS it is a local path)"))
            elif unc_host is not None:
                if _UNC_THIS_MACHINE_RE.fullmatch(unc_host):
                    out.append(Finding(rel, node.lineno, "loopback-call",
                                       f"{name}(...): reads or writes a UNC path on this machine; nothing leaves it at "
                                       "this line"))
                else:
                    out.append(Finding(rel, node.lineno, "network-call",
                                       f"{name}(...): reads or writes a path on another machine (a UNC path, reached "
                                       "over SMB)"))
            # a URL literal handed to something that fetches, or a connection string handed to a client
            if name in URL_SINK_NAMES:
                # A URL written in the call. A name bound once in the file to a URL literal counts
                # only where the callee is unmistakably a fetcher: `q.put(base_url)` is a queue.
                given = _string_args(node)
                # the address given by keyword: `get_file('m.h5', origin='https://...')`, `read_csv(filepath_or_buffer=...)`
                given += [kw.value.value for kw in node.keywords
                          if (kw.arg in _ADDRESS_KEYWORDS or kw.arg in _ADDRESS_KEYWORDS_BY_CALL.get(name, ()))
                          and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)]
                if name in UNAMBIGUOUS_FETCHERS or recv_top in FORBIDDEN_IMPORT_MODULES or (
                        recv_mod in FORBIDDEN_IMPORT_MODULES):
                    given = given + [assigned[a.id].value for a in node.args
                                     if isinstance(a, ast.Name) and isinstance(assigned.get(a.id), ast.Constant)]
                # `responses`, `requests_mock` and `httpretty` describe a canned reply with the same
                # verbs a client uses. The reply's description (`status=`, `body=`, `text=`) marks one,
                # unless the call is made on a network client: `httplib2.Http().request(url, 'POST',
                # body=...)` and urllib3's `request(..., body=...)` send that body.
                on_client = (isinstance(fn, ast.Attribute) and _receiver_is_network(fn.value)) or (
                    from_import_call and _names_network_package(fn.id))
                mock = (any(kw.arg in MOCK_REPLY_KEYWORDS for kw in node.keywords) and not on_client) or (
                    recv_root is not None and (_TEST_DOUBLE_NAME_RE.search(recv_root) is not None
                                               or recv_root in mock_names))
                # `os.environ.get("REPO", "https://...")` reads a mapping; the URL is its default.
                recv_tail = (_dotted_name(fn.value) or "").rsplit(".", 1)[-1] if isinstance(fn, ast.Attribute) else ""
                if name == "get" and (recv_tail in MAPPING_RECEIVERS or (
                        isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id in cache_names)):
                    given = []
                # `schema.get("$id", "http://localhost/schema.json")`: a key that is not an address,
                # then a default. A client's `get` takes its address first. A receiver that is a
                # network module keeps its finding whatever it is handed.
                if (name == "get" and isinstance(fn, ast.Attribute) and len(node.args) == 2 and not node.keywords
                        and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                        and not URL_RE.search(node.args[0].value)
                        and not node.args[0].value.lstrip().startswith(("/", "?"))
                        and recv_top not in FORBIDDEN_IMPORT_MODULES and recv_mod not in FORBIDDEN_IMPORT_MODULES):
                    given = []
                storage = None if name not in _STORAGE_READERS or any(URL_RE.search(s) for s in given) else next(
                    (_STORAGE_URL_RE.match(s) for s in given if _STORAGE_URL_RE.match(s)), None)
                if storage:
                    # `pd.read_csv('s3://bucket/x.csv')`, `cv2.VideoCapture('rtsp://cam/live')`: an object store, a
                    # hub or a stream, read over the network unless its host is this machine
                    scheme, host = storage.group(1).lower(), storage.group(2)
                    traced = name in UNAMBIGUOUS_FETCHERS or name == "VideoCapture" or (
                        isinstance(fn, ast.Attribute) and _receiver_is_network(fn.value)) or (
                        from_import_call and _names_network_package(fn.id))
                    if mock:
                        out.append(Finding(rel, node.lineno, "network-target",
                                           f"{name}(...) describes a canned reply for an address with the scheme {scheme}://; nothing is "
                                           "sent at this line"))
                    elif host and _THIS_MACHINE_HOST_RE.fullmatch(host):
                        out.append(Finding(rel, node.lineno, "loopback-call",
                                           f"{name}(...) is given an address with the scheme {scheme}:// on this machine; nothing "
                                           "leaves it at this line"))
                    elif name == "open" and isinstance(fn, ast.Name) and not traced:
                        pass                    # the built-in `open` reads files on this machine only
                    elif traced:
                        out.append(Finding(rel, node.lineno, "network-call",
                                           f"{name}(...) is given an address with the scheme {scheme}:// written in the file (an object "
                                           "store, a hub, a remote file system or a stream), "
                                           + ("written over the network" if name.startswith("to_") else "read over the network")))
                    else:
                        on = (_dotted_name(fn.value) or "an object") if isinstance(fn, ast.Attribute) else name
                        out.append(Finding(rel, node.lineno, "unresolved-call",
                                           f"{name}(...) is given an address with the scheme {scheme}://; what {on!s} is was NOT "
                                           "resolved, so whether this reaches the network is not shown"))
                    given = []
                for s in given:
                    # `{http://www.w3.org/XML/1998/namespace}base` is a qualified name in an XML tree
                    # (the namespace in braces, then the local name). So is a bare W3C namespace name.
                    if _XML_QNAME_RE.match(s) or (URL_RE.search(s) and not _has_external_url(s)
                                                  and _NAMESPACE_NAME_RE.search(s)):
                        continue
                    if s.lstrip().startswith(("/", "?")):
                        continue        # `client.post('/login?next=http://example.com')`: a path on the app under test
                    if URL_RE.search(s):
                        if name in TARGET_BUILDERS and id(node) in sent_on_build and (
                                sent_on_build[id(node)] is None or _receiver_is_network(sent_on_build[id(node)])):
                            # `urlopen(Request("https://..."))`: the request is built and sent in one expression
                            out.append(Finding(rel, node.lineno, "network-call",
                                               f"{name}(...) builds a request for a URL literal and the same expression "
                                               "sends it"))
                        elif name in TARGET_BUILDERS or (recv_root is not None and _REQUEST_FACTORY_NAME_RE.search(recv_root)):
                            # `Request(url, body=...)`, `factory.get(url)`: an object is built; nothing is sent
                            out.append(Finding(rel, node.lineno, "network-target",
                                               f"{name}(...) builds a request for a URL literal; nothing is sent "
                                               "at this line"))
                        elif mock:
                            out.append(Finding(rel, node.lineno, "network-target",
                                               f"{name}(...) describes a canned reply for a URL literal (a test "
                                               "double's registration); nothing is sent at this line"))
                        elif _URL_NO_HOST_RE.search(s) and not _URL_HOST_RE.search(s):
                            # `ftp:///archive.zip` with `host=` passed beside it: the address names no host,
                            # so it is neither this machine nor another one.
                            out.append(Finding(rel, node.lineno, "unresolved-call",
                                               f"{name}(...) is given a URL that names no host; where it connects "
                                               "is NOT shown by this line"))
                        elif not _has_external_url(_one_url(s)) and _names_outside_proxy(node):
                            # `get("http://localhost:1", proxies={"http": "proxy.example"})`: the request goes to the
                            # proxy named on the line, not to this machine
                            out.append(Finding(rel, node.lineno, "unresolved-call",
                                               f"{name}(...) is given an address on this machine and a proxy that is "
                                               "not; whether the request leaves it is NOT shown by this line"))
                        elif not _has_external_url(_one_url(s)):
                            out.append(Finding(rel, node.lineno, "loopback-call",
                                               f"{name}(...) is given an address on this machine; "
                                               "nothing leaves it at this line"))
                        elif (name in UNAMBIGUOUS_FETCHERS or (
                                isinstance(fn, ast.Attribute) and _receiver_is_network(fn.value)) or (
                                from_import_call and _names_network_package(fn.id))) and (
                                _transport_patch_covers(node.lineno, fn)
                                or (isinstance(fn, ast.Attribute) and _stub_transport(fn.value, node.lineno))):
                            stub = _stub_transport(fn.value, node.lineno) if isinstance(fn, ast.Attribute) else None
                            how = (f"built over {stub}, a stand-in class this file defines, as its transport" if stub
                                   else "while the test replaces the client's transport method")
                            out.append(Finding(rel, node.lineno, "network-target",
                                               f"{name}(...) is given a URL literal on a client {how}; nothing "
                                               "reaches the network at this line"))
                        elif (name in UNAMBIGUOUS_FETCHERS or (
                                isinstance(fn, ast.Attribute) and _receiver_is_network(fn.value)) or (
                                from_import_call and _names_network_package(fn.id))) and (
                                node.lineno in patched_lines or doubled.get(node.lineno, ("", False))[1]):
                            lib = doubled[node.lineno][0] if node.lineno in doubled else "a test double"
                            out.append(Finding(rel, node.lineno, "network-target",
                                               f"{name}(...) is given a URL literal while {lib} replaces the socket "
                                               "and refuses real connections; nothing reaches the network at this line"))
                        elif name in UNAMBIGUOUS_FETCHERS or (
                                isinstance(fn, ast.Attribute) and _receiver_is_network(fn.value)) or (
                                from_import_call and _names_network_package(fn.id)):
                            through = (f"; called while {doubled[node.lineno][0]} replaces the socket, which answers "
                                       "the addresses registered with it and passes others to the network"
                                       ) if node.lineno in doubled else ""
                            out.append(Finding(rel, node.lineno, "network-call",
                                               f"{name}(...) is given a URL literal{through}"))
                        else:
                            # The method's NAME matched; what it is called on was not traced to a
                            # network package. The claim is scoped to what the line shows.
                            on = (_dotted_name(fn.value) or "an object") if isinstance(fn, ast.Attribute) else name
                            out.append(Finding(rel, node.lineno, "unresolved-call",
                                               f"{name}(...) is given a URL literal; what {on!s} is was NOT "
                                               "resolved, so whether this reaches the network is not shown"))
                        break
            if name in DSN_SINK_NAMES or name in _DSN_RUNNERS:
                # a connection string written in the call, or held in a name bound once to one (`DB = "postgresql://..."`)
                given_values = list(node.args) + [kw.value for kw in node.keywords]
                bound_strings = [assigned[v.id].value for v in given_values
                                 if isinstance(v, ast.Name) and isinstance(assigned.get(v.id), ast.Constant)
                                 and isinstance(assigned[v.id].value, str)]
                for s in _string_args(node) + [kw.value.value for kw in node.keywords
                                               if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)] \
                        + bound_strings:
                    if DSN_RE.search(s):
                        if _dsn_is_loopback(s) and (
                                any(_sets_dsn_host(kw, s) for kw in node.keywords)
                                # a string that names no host takes it from a service or options file, or from the
                                # client's environment variable (an explicit host in the string wins over both)
                                or (_dsn_hosts(s) == [] and (
                                    re.search(r"(?i)[?&](?:service|read_default_file|read_default_group)=", s)
                                    or dsn_env_named()))):
                            # `create_engine("postgresql:///x", connect_args={"host": h})`, `os.environ["PGHOST"] = h`:
                            # the host is set somewhere other than the string
                            out.append(Finding(rel, node.lineno, "unresolved-call",
                                               f"{name}(...) is given a connection string for this machine and "
                                               "settings that may name another host (a keyword, a service file or the "
                                               "environment); where it connects is NOT shown by this line"))
                        elif name in _DSN_RUNNERS:
                            # `pd.read_sql(q, "postgresql://host/db")`, `df.to_sql("t", "mysql://...")`: connects and runs
                            # the query, reading or writing over that connection
                            out.append(Finding(rel, node.lineno, "loopback-call" if _dsn_is_loopback(s) else "network-call",
                                               f"{name}(...) is given a connection string naming "
                                               + ("this machine; nothing leaves it at this line" if _dsn_is_loopback(s)
                                                  else "a host, and connects to it")))
                        elif name == "connect" and _dsn_is_loopback(s):
                            out.append(Finding(rel, node.lineno, "loopback-call",
                                               f"{name}(...) is given a connection string naming this machine; "
                                               "nothing leaves it at this line"))
                        elif name == "connect":
                            out.append(Finding(rel, node.lineno, "network-call",
                                               f"{name}(...) is given a connection string naming a host"))
                        elif _dsn_is_loopback(s):
                            # `create_engine("postgresql://localhost/db")`, `Connection("redis+socket:///tmp/r.sock")`
                            out.append(Finding(rel, node.lineno, "loopback-call",
                                               f"{name}(...) builds a client for a connection string naming this "
                                               "machine; nothing leaves it at this line"))
                        else:
                            out.append(Finding(rel, node.lineno, "network-target",
                                               f"{name}(...) builds a client for a connection string naming a host; "
                                               "nothing is sent at this line"))
                        break
    out += _task_runner_findings(tree, rel, module_alias, from_alias, assigned)
    out += _compat_attribute_findings(tree, rel, module_alias, from_alias)
    out += _bound_native_library_findings(tree, rel)
    return out


def _compat_attribute_findings(tree: ast.AST, rel: str, module_alias: dict, from_alias: dict) -> list[Finding]:
    """`import six` then `six.moves.urllib.request.urlopen(...)`, or `from six import moves` then
    `moves.http_client.HTTPSConnection(...)`: a standard-library module reached through a compatibility layer by
    attribute, judged as an import of that module, once per line and module."""
    layers = {}                                  # local name -> the layer's dotted name it stands for
    for local, mod in module_alias.items():
        if mod in ("six", "future") or mod.startswith(_COMPAT_PREFIXES):
            layers[local] = mod
    for local, (mod, name) in from_alias.items():
        # `from six import moves`, `from six.moves import urllib`: a module of the layer, bound to a name (a class
        # taken from one of its modules is an import, judged where it is imported)
        full = f"{mod}.{name}"
        if full in _COMPAT_PREFIXES or (mod in _COMPAT_PREFIXES and (name in _COMPAT_NAMES or name in (
                "urllib", "http_client", "socketserver", "xmlrpc_client", "xmlrpc_server"))):
            layers[local] = full
    if not layers:
        return []
    out: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    inner = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}    # parts of a longer chain
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or id(node) in inner:
            continue
        dotted = _dotted_name(node)
        if not dotted or dotted.split(".")[0] not in layers:
            continue
        full = layers[dotted.split(".")[0]] + dotted[len(dotted.split(".")[0]):]
        if not full.startswith(_COMPAT_PREFIXES):
            continue
        target = _compat_module(full)
        parts = target.split(".")
        for k in range(len(parts), 0, -1):          # the longest module the chain names that this tool judges
            if ".".join(parts[:k]) in NON_NETWORK_SUBMODULES or (k == 1 and parts[0] in _EMPTY_PACKAGES):
                break                               # `six.moves.urllib.parse.quote`: a pure module, or an empty package
            cls = _classify_module(".".join(parts[:k]))
            if cls in ("network", "inbound"):
                key = (node.lineno, ".".join(parts[:k]))
                if key not in seen:
                    seen.add(key)
                    kind = "network-import" if cls == "network" else "inbound-listener"
                    out.append(Finding(rel, node.lineno, kind, f"uses {dotted} ({key[1]}), reached through a "
                                                               "compatibility layer"))
                break
    return out


# Task runners whose task functions are handed an object that runs commands: nox's `session.run('git', ...)` takes
# an argv; invoke's and fabric's `c.run('curl ...')` take a shell string
_TASK_DECORATORS = {"nox": ("session",), "invoke": ("task",), "fabric": ("task",)}
_TASK_RUN_METHODS = {"nox": ("run", "run_always", "run_install", "install", "conda_install"),
                     "invoke": ("run", "sudo", "local"),
                     "fabric": ("run", "sudo", "local")}


def _task_runner_findings(tree: ast.AST, rel: str, module_alias: dict, from_alias: dict,
                          assigned: dict) -> list[Finding]:
    roots = {m.split(".")[0] for m in module_alias.values()} | {m.split(".")[0] for m, _ in from_alias.values()}
    out: list[Finding] = []
    for runner in (r for r in _TASK_DECORATORS if r in roots):
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or not fn.args.args:
                continue
            if not any((_dotted_name(d.func if isinstance(d, ast.Call) else d) or "").rsplit(".", 1)[-1]
                       in _TASK_DECORATORS[runner] for d in fn.decorator_list):
                continue
            param = fn.args.args[0].arg
            for node in ast.walk(fn):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name) and node.func.value.id == param
                        and node.func.attr in _TASK_RUN_METHODS[runner] and node.args):
                    continue
                caller = f"{param}.{node.func.attr}"
                if runner == "nox":
                    # each argument is one word of the argv (`session.run("python", "-c", "import x\nprint(x)")`);
                    # `session.install("pytest")` runs `pip install pytest` (`conda_install`, `conda install`)
                    argv = [s for a in node.args for s in (_literal_argv(a, assigned, split=False) or [_ARGV_HOLE])]
                    if node.func.attr in ("install", "conda_install"):
                        argv = (["pip", "install"] if node.func.attr == "install" else ["conda", "install"]) + argv
                    out += _argv_findings(rel, node.lineno, caller, argv)
                else:
                    arg = node.args[0]
                    if isinstance(arg, ast.JoinedStr):
                        # `c.run(f'git pull origin v{version}')`: the written parts, each value a word held open
                        command = ["".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str)
                                           else "X" for v in arg.values)]
                    else:
                        command = _literal_argv(arg, assigned, split=False)
                    if command and command[0] != _ARGV_HOLE:
                        out += [Finding(rel, node.lineno, f.kind, f"{caller}(...) runs a shell command: {f.detail}")
                                for f in _check_script(Path("task.sh"), rel, text=command[0] + "\n")]
    return out


def _literal_loopback_host(node: ast.Call) -> bool:
    """`create_connection(("127.0.0.1", port))`: the host is a literal, and it is this machine.

    asyncio's event loop takes a protocol factory first and the host second
    (`loop.create_connection(factory, "127.0.0.1", 9000)`), or `remote_addr=` for a datagram endpoint."""
    hosts = [kw.value for kw in node.keywords if kw.arg == "host"]
    hosts += [kw.value.elts[0] for kw in node.keywords
              if kw.arg == "remote_addr" and isinstance(kw.value, (ast.Tuple, ast.List)) and kw.value.elts]
    for arg in node.args[:2]:
        if isinstance(arg, (ast.Tuple, ast.List)) and arg.elts:
            hosts.append(arg.elts[0])
        elif isinstance(arg, (ast.Constant, ast.JoinedStr)):
            hosts.append(arg)
    for host in hosts:
        if isinstance(host, ast.Constant) and isinstance(host.value, str):
            return _LOOPBACK_HOST_RE.fullmatch(host.value) is not None or _url_host_is_loopback(host.value, True)
        if isinstance(host, ast.JoinedStr) and host.values and isinstance(host.values[0], ast.Constant) \
                and isinstance(host.values[0].value, str):
            # f"ws://127.0.0.1:{port}": the host is written out; only what follows it is filled in
            return _url_host_is_loopback(host.values[0].value, len(host.values) == 1)
    return False


# A browser or Node network call whose first argument is a written-out address.
_JS_LITERAL_CALL_RE = re.compile(
    r"""(?:\b(?:fetch|WebSocket|EventSource|navigator\.sendBeacon|axios(?:\.\w+)?|jQuery\.(?:ajax|get|post|getJSON|getScript))"""
    r"""|\$\.(?:ajax|get|post|getJSON|getScript))\s*\(\s*(['"`])([^'"`]*)\1""")
_JS_ANY_CALL_RE = re.compile(
    r"""(?:\b(?:fetch|WebSocket|EventSource|navigator\.sendBeacon|axios(?:\.\w+)?|jQuery\.(?:ajax|get|post|getJSON|getScript))"""
    r"""|\$\.(?:ajax|get|post|getJSON|getScript))\s*\(""")


# This machine only. (`_LOOPBACK_HOST_RE` also accepts the page's own host, which is no outside address but is
# not this machine either: a page served from a server talks to that server.)
_THIS_MACHINE_HOST_RE = re.compile(r"""localhost\.?|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1?\]|::1?|(?:0{1,4}:){7}0{0,3}1"""
                                   r"""|[\w-]+\.localhost\.?""",
                                   re.IGNORECASE)


def _names_outside_proxy(call: ast.Call) -> bool:
    """`proxies={"http": "non-resolvable-address"}` or `proxy="http://proxy.example:3128"`: the call is routed through
    a proxy that is not this machine (or one that is not written out)."""
    for kw in call.keywords:
        if kw.arg not in ("proxies", "proxy", "proxy_url"):
            continue
        v = kw.value
        values = [x for x in v.values] if isinstance(v, ast.Dict) else [v]
        for x in values:
            if not (isinstance(x, ast.Constant) and isinstance(x.value, str)):
                if isinstance(x, ast.Constant) and x.value is None:
                    continue
                return True
            text = x.value.strip()
            host = _URL_HOST_RE.match(text)
            name = host.group(1) if host else text.split("/")[0].rsplit(":", 1)[0]
            if name and not _THIS_MACHINE_HOST_RE.fullmatch(name):
                return True
    return False


def _js_calls_only_loopback(line: str) -> bool:
    """`new WebSocket("ws://127.0.0.1:9000")`: every network call on the line is given an address on this machine."""
    calls = _JS_ANY_CALL_RE.findall(line)
    literals = _JS_LITERAL_CALL_RE.findall(line)
    if not calls or len(literals) != len(calls):
        return False
    for quote, text in literals:
        m = _URL_HOST_RE.match(text.strip())
        if not m or not _THIS_MACHINE_HOST_RE.fullmatch(m.group(1)):
            return False
        # a browser ends the host at a backslash (`http://a.example.com\@localhost/` goes to a.example.com), where
        # this reading would take the part after `@`
        authority = re.match(r"[A-Za-z][\w+.-]*://([^/?#]*)", text.strip())
        if authority and "\\" in authority.group(1):
            return False
        filled_in = quote == "`" and "${" in text
        if filled_in and text.strip()[m.end():][:1] not in (":", "/", "?", "#"):
            return False
    return True


def _one_url(text: str) -> str:
    """One address written as a string, read as a URL parser reads it: a tab or a line break inside it dropped
    (`"http://localhost<TAB>.evil.example.com"` is `localhost.evil.example.com`)."""
    return text.replace("\t", "").replace("\r", "").replace("\n", "")


def _url_host_is_loopback(text: str, complete: bool) -> bool:
    """The text begins with a URL whose host is this machine. When more text is appended while
    running (`complete` is False), the host must be closed by `:`, `/`, `?` or `#` inside the literal,
    so `f"http://127.0.0.1{suffix}"` is not taken for this machine. A tab or a line break inside it is dropped first,
    as URL parsers drop them (`http://localhost<TAB>.evil.example.com` is `localhost.evil.example.com`)."""
    text = re.sub(r"[\t\r\n]", "", text)
    m = _URL_HOST_RE.match(text.strip())
    if not m or not _LOOPBACK_HOST_RE.fullmatch(m.group(1)):
        return False
    rest = text.strip()[m.end():]
    return complete or rest[:1] in (":", "/", "?", "#")


def _rel(path: Path, target: Path) -> str:
    """A report path is written with forward slashes on every operating system, so the
    same tree gives the same report on Windows, Linux and macOS."""
    return path.relative_to(target).as_posix()


def _read_python_source(path: Path) -> str:
    """Decode a Python file the way the interpreter does: BOM and PEP 263 encoding
    cookie honoured. A file Python cannot decode is a file Python cannot run, and it
    is reported as unparseable rather than read under a different codec."""
    return _reads.read_python_source(path)


def _attr_chain(node: ast.AST) -> set[str]:
    """Every attribute name in a chain: `ctypes.windll.wininet.Open` -> {windll, wininet, Open}."""
    names: set[str] = set()
    while isinstance(node, ast.Attribute):
        names.add(node.attr)
        node = node.value
    return names


def _dotted_name(node: ast.AST) -> str | None:
    """`a.b.c` as the string 'a.b.c'. None unless the chain is names all the way down."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id] + parts[::-1])


# Stands where an argv element is not a literal (a variable, a call): never a program, an option or a subcommand.
_ARGV_HOLE = "\x00"


def _literal_argv(node: ast.AST, assigned: dict, split: bool = True, _depth: int = 0) -> list[str] | None:
    """The literal strings of a command, when the source spells them out.

    A list or tuple literal; a string literal (split on whitespace into an argv when
    `split`, kept whole as a shell string otherwise); `"curl -s x".split()`;
    `shlex.split("curl -s x")`; and a name bound exactly once in the file to one of
    those. Anything built at run time returns None: it is not resolved.
    """
    if isinstance(node, (ast.List, ast.Tuple)):
        return _argv_strings(node, holes=True, assigned=assigned)
    # `["curl", "-s"] + urls`: the program and its first arguments are spelled out; what is
    # added at run time comes after them.
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and _depth < 4:
        # `['git', '-C', repo] + ['push', 'origin']`, `GIT + ['push']`: each side spelled out in the file is read; a
        # side built while running is a hole
        left = _literal_argv(node.left, assigned, split, _depth + 1) \
            if isinstance(node.left, (ast.List, ast.Tuple, ast.BinOp, ast.Name)) else None
        if not left or left[0] == _ARGV_HOLE:
            return None
        right = _literal_argv(node.right, assigned, split, _depth + 1) \
            if isinstance(node.right, (ast.List, ast.Tuple, ast.BinOp, ast.Name)) else None
        return left + (right if right is not None else [_ARGV_HOLE])
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.split() if split else [node.value]
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "split":
            if isinstance(fn.value, ast.Constant) and isinstance(fn.value.value, str) and not node.args:
                return fn.value.value.split() if split else [fn.value.value]
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value.split() if split else [node.args[0].value]   # shlex.split("...")
        return None
    if isinstance(node, ast.Name) and node.id in assigned and _depth < 2:
        return _literal_argv(assigned[node.id], assigned, split, _depth + 1)
    return None


def _attr_root_name(node: ast.AST) -> str | None:
    """Left-most Name of an attribute chain: `a.b.c` -> 'a'. None for anything else."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _resolves_to(func: ast.AST, module_alias: dict, from_alias: dict) -> str:
    """The dotted name a called expression reaches, through the file's import aliases (`ET.parse` after
    `import xml.etree.ElementTree as ET`, `make_parser` after `from xml.sax import make_parser`)."""
    dotted = _dotted_name(func) or ""
    head, dot, tail = dotted.partition(".")
    if head in from_alias:
        mod, attr = from_alias[head]
        return f"{mod}.{attr}{dot}{tail}"
    return f"{module_alias.get(head, head)}{dot}{tail}"


_SAX_FACTORIES = {"xml.sax.make_parser", "xml.sax.expatreader.create_parser"}


def _is_sax_parser(node, module_alias: dict, from_alias: dict, bound: dict, tree: ast.AST | None = None) -> bool:
    """`xml.sax.make_parser()`, or a name or an attribute (`self.p`) the file binds only to it: an object whose
    `.parse` reads a source."""
    def factory(v) -> bool:
        return isinstance(v, ast.Call) and _resolves_to(v.func, module_alias, from_alias) in _SAX_FACTORIES
    if isinstance(node, ast.Call):
        return factory(node)
    if isinstance(node, ast.Name) and node.id in bound:
        values = bound[node.id]
        return bool(values) and all(factory(v) for v in values)
    if isinstance(node, ast.Attribute) and tree is not None:
        target = _dotted_name(node)
        values = [a.value for a in ast.walk(tree) if isinstance(a, (ast.Assign, ast.AnnAssign)) and a.value is not None
                  and any(_dotted_name(t) == target for t in (a.targets if isinstance(a, ast.Assign) else [a.target]))]
        return bool(target) and bool(values) and all(factory(v) for v in values)
    return False


def _local_xml_source(arg: ast.AST, bound: dict | None = None, tree: ast.AST | None = None) -> bool:
    """A source the SAX parser reads from this machine: a literal that is not an address, an open file, bytes or text
    held in memory, or a name the file binds only to an `InputSource()` holding a stream and given no system id
    (`source = InputSource(); source.setByteStream(...)`)."""
    if isinstance(arg, ast.Constant):
        return not (isinstance(arg.value, str) and URL_RE.search(arg.value))
    if isinstance(arg, ast.Call):
        callee = (_dotted_name(arg.func) or "").rsplit(".", 1)[-1]
        return callee in ("open", "BytesIO", "StringIO", "Path")
    if isinstance(arg, ast.Name) and tree is not None:
        # `with open("f.xml") as f: xml.sax.parse(f, h)`: every place the file binds the name is a `with` that opens
        # something local
        stores = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == arg.id and isinstance(n.ctx, ast.Store)]
        opened = [it.context_expr for n in ast.walk(tree) if isinstance(n, (ast.With, ast.AsyncWith)) for it in n.items
                  if isinstance(it.optional_vars, ast.Name) and it.optional_vars.id == arg.id]
        params = any(isinstance(n, ast.arg) and n.arg == arg.id for n in ast.walk(tree))
        if opened and len(opened) == len(stores) and not params \
                and all(isinstance(v, ast.Call) and _local_xml_source(v) for v in opened):
            return True
    if isinstance(arg, ast.Name) and bound and tree is not None:
        values = bound.get(arg.id) or []
        if values and all(isinstance(v, ast.Call) and (_dotted_name(v.func) or "").rsplit(".", 1)[-1] == "InputSource"
                          and not v.args and not v.keywords for v in values):
            calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and isinstance(n.func.value, ast.Name) and n.func.value.id == arg.id}
            return "setSystemId" not in calls and bool(calls & {"setByteStream", "setCharacterStream"})
    return False


# Python calls that open, read, write, copy or list the path they are given
_PATH_IO_CALLS = {"open", "open_file", "ZipFile", "TarFile", "connect", "listdir", "scandir", "stat", "walk", "remove", "unlink", "rename", "replace", "makedirs",
                  "mkdir", "rmdir", "copy", "copy2", "copyfile", "copytree", "move", "rmtree", "read_text",
                  "read_bytes", "write_text", "write_bytes", "iterdir", "glob", "rglob", "startfile", "chdir",
                  "getsize", "exists", "isfile", "isdir", "loadtxt", "read_csv", "read_excel", "read_parquet", "load"}
_PATH_TYPES = {"Path", "PurePath", "WindowsPath", "PureWindowsPath", "PosixPath", "PurePosixPath"}
_STR_METHOD_NAMES = {"replace"}
_PYTHON_UNC_RE = re.compile(r"""\\\\(?:[?.]\\UNC\\)?(?![?.]\\)([A-Za-z0-9][\w.-]*)(?:@SSL)?(?:@\d+)?(?:\\DavWWWRoot)?\\[\w$.-]+""",
                            re.IGNORECASE)


# `//fs01/share/x`: a UNC path on Windows (on Linux and macOS a local path), the share named after the host
_PYTHON_SLASHED_UNC_RE = re.compile(r"""//(?![?.]/)([A-Za-z0-9][\w.-]*)(?:@SSL)?(?:@\d+)?/[\w$.-]+""", re.IGNORECASE)


def _path_root(node: ast.AST, bound: dict | None, _depth: int = 0) -> ast.AST:
    r"""What a path is built from: `Path(r"\\fs01\share") / "x"` gives `Path(r"\\fs01\share")`, as do
    `os.path.join(r"\\fs01\share", "x")`, `r"\\fs01\share" + "\\x"` and `f"\\\\fs01\\share\\{name}"` (their first
    part), and a name bound once to such an expression gives what it is bound to."""
    while _depth < 8:
        _depth += 1
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            node = node.left
        elif isinstance(node, ast.Call) and node.args and (_dotted_name(node.func) or "").rsplit(".", 2)[-2:] in (
                ["path", "join"], ["ntpath", "join"], ["posixpath", "join"]):
            node = node.args[0]
        elif isinstance(node, ast.JoinedStr) and node.values and all(
                isinstance(v, ast.Constant) or (isinstance(v, ast.FormattedValue) and v.format_spec is None
                                               and isinstance(v.value, ast.Name) and bound is not None
                                               and len(bound.get(v.value.id, ())) == 1
                                               and isinstance(bound[v.value.id][0], ast.Constant)
                                               and isinstance(bound[v.value.id][0].value, str))
                for v in node.values):
            # `f"\\\\{SERVER}\\share\\x"` with `SERVER` bound once to a literal: the string it makes
            node = ast.Constant("".join(v.value if isinstance(v, ast.Constant) else bound[v.value.id][0].value
                                        for v in node.values))
        elif isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
            node = node.values[0]
        elif isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.FormattedValue) \
                and node.values[0].format_spec is None and node.values[0].conversion == -1:
            node = node.values[0].value     # `f"{SHARE}\\x.csv"`: what the path starts with is the name's value
        elif isinstance(node, ast.Name) and bound is not None and len(bound.get(node.id, ())) == 1 \
                and isinstance(bound[node.id][0], (ast.BinOp, ast.Call)):
            node = bound[node.id][0]
        else:
            break
    return node


def _python_unc_host(call: ast.Call, name: str, assigned: dict, bound: dict | None = None) -> str | None:
    r"""The host of a UNC path a file call is given (`open(r"\\fs01\x\y")`, `shutil.copy(SHARE, ...)` with `SHARE`
    bound once to one, `Path(r"\\fs01\x").read_text()`, `(Path(r"\\fs01\x") / "y").read_text()`); None when it is
    given none. A host written with forward slashes (`//fs01/x`) is returned with a leading "/"."""
    if name not in _PATH_IO_CALLS:
        return None
    values = list(call.args) + [kw.value for kw in call.keywords]
    fn = call.func
    receiver = _path_root(fn.value, bound) if isinstance(fn, ast.Attribute) else None
    if isinstance(receiver, ast.Call) and (_dotted_name(receiver.func) or "").rsplit(".", 1)[-1] in _PATH_TYPES:
        values += list(receiver.args)               # `Path(r"\\fs01\x").read_text()`: the path it is called on
    elif name in _STR_METHOD_NAMES and not (isinstance(fn, ast.Attribute) and (
            _dotted_name(fn.value) or "").split(".")[0] in ("os", "shutil", "pathlib")):
        return None                                 # `text.replace(...)`: a string's method, not a file's
    for v in values:
        v = _path_root(v, bound)
        if isinstance(v, ast.Call) and (_dotted_name(v.func) or "").rsplit(".", 1)[-1] in _PATH_TYPES and v.args:
            v = _path_root(v.args[0], bound)
        if isinstance(v, ast.Name) and isinstance(assigned.get(v.id), ast.Constant):
            v = assigned[v.id]
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            m = _PYTHON_UNC_RE.match(v.value)
            if m:
                return m.group(1)
            m = _PYTHON_SLASHED_UNC_RE.match(v.value)
            if m:
                return "/" + m.group(1)
    return None


def _string_args(call: ast.Call) -> list[str]:
    """String constants among a call's positional arguments, lists and tuples flattened."""
    return _argv_strings(call)


def _which_program(node: ast.AST) -> str | None:
    """`shutil.which('git')` or `which('git')`: the program it looks up, which is what runs when its path is used."""
    if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
            and isinstance(node.args[0].value, str) and (_dotted_name(node.func) or "").rsplit(".", 1)[-1] == "which":
        return node.args[0].value
    return None


def _argv_strings(node: ast.AST, holes: bool = False, assigned: dict | None = None, _depth: int = 0) -> list[str]:
    """String constants of an argv-shaped expression, in order. `sys.executable` is kept
    as the word 'python' so a child interpreter can be recognised. With `holes`, an element
    that is not a literal leaves `_ARGV_HOLE` in its place, so positions still line up:
    in `["docker", "compose", "-f", path, "down"]` the value of `-f` is `path`, not `down`."""
    out: list[str] = []
    items = node.args if isinstance(node, ast.Call) else getattr(node, "elts", [])
    for e in items:
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            out.append(e.value)
        elif isinstance(e, (ast.List, ast.Tuple)):
            out += _argv_strings(e, holes)
        elif isinstance(e, ast.Attribute) and e.attr == "executable" and _attr_root_name(e) == "sys":
            out.append("python")
        elif _which_program(e) or (assigned and isinstance(e, ast.Name) and e.id in assigned
                                   and _which_program(assigned[e.id])):
            # `[shutil.which('git'), 'clone', url]`, or a name bound once to that call
            out.append(_which_program(e) or _which_program(assigned[e.id]))
        elif assigned and isinstance(e, ast.Name) and isinstance(assigned.get(e.id), ast.Constant) \
                and isinstance(assigned[e.id].value, str):
            out.append(assigned[e.id].value)        # `GIT = 'git'` then `[GIT, 'pull']`
        elif (assigned and _depth < 2 and isinstance(e, ast.Starred) and isinstance(e.value, ast.Name)
              and isinstance(assigned.get(e.value.id), (ast.List, ast.Tuple))):
            # `CURL = ['curl', '-fsSL']` then `[*CURL, url]`: the list's words, in place
            out += _argv_strings(assigned[e.value.id], holes, assigned, _depth + 1)
        elif holes:
            out.append(_ARGV_HOLE)
    return out


# programs that open what they are given in the default browser (or are the browser)
_BROWSER_OPENERS = {"xdg-open", "open", "start", "explorer", "sensible-browser", "x-www-browser", "gnome-open",
                    "kde-open", "wslview", "firefox", "chrome", "google-chrome", "chromium", "chromium-browser",
                    "msedge", "rundll32"}


def _argv_findings(rel: str, lineno: int, caller: str, elts: list[str],
                   local_modules: frozenset[str] = frozenset()) -> list[Finding]:
    """Findings for a literal argv: a network binary, a git remote subcommand, a shell
    interpreter handed a command string, or a child interpreter handed a module or code."""
    out: list[Finding] = []
    # `holed` keeps a placeholder where an element was not a literal; the checks below read the literals,
    # and a check that depends on position or on there being nothing else reads `holed`.
    holed = list(elts)
    elts = [a for a in elts if a != _ARGV_HOLE]
    if not elts:
        return out
    # `env curl ...`, `sudo wget ...`, `timeout 5 curl ...`: the program that runs is the
    # one after the wrapper, its options, any number and any VAR=value setting.
    for _ in range(4):
        if _argv_basename(elts[0]) not in ARGV_WRAPPERS:
            break
        rest = list(elts[1:])
        while rest and (rest[0].startswith("-") or "=" in rest[0] or re.fullmatch(r"[\d.]+[smhd]?", rest[0])):
            rest = rest[1:]
        if not rest:
            return out
        elts = rest
    exe = _argv_basename(elts[0])
    if exe in _BROWSER_OPENERS and any(re.match(r"(?i)(?:https?|ftp)://", a) and _has_external_url(a)
                                       for a in elts[1:]):
        # `['xdg-open', 'https://...']`: the default browser fetches the address
        return [Finding(rel, lineno, "subprocess-net-binary",
                        f"{caller}([{exe!r}, ...]): opens an address on another machine in the default browser, "
                        "which fetches it")]
    if exe == "git":
        # git's subcommand is its first word that is not one of git's own options (`git -C dir -c k=v pull`);
        # words after it are that subcommand's arguments (`git commit -m pull` commits)
        k = 1
        while k < len(elts) and elts[k].startswith("-"):
            k += 2 if elts[k] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                                  "--config-env") else 1
        sub = elts[k] if k < len(elts) else ""
        rest = [a for a in elts[k + 1:] if not a.startswith("-")]
        if sub == "remote":
            # `git remote` lists remotes and `git remote add|remove|rename|set-url|get-url` edit local
            # configuration; only `update`, `prune`, `show` and `set-head` ask the remote anything.
            if rest[:1] and rest[0] in GIT_REMOTE_CONTACTING:
                out.append(Finding(rel, lineno, "git-remote", f"git remote {rest[0]}"))
        elif sub == "submodule":
            # `git submodule status|init|sync|foreach` act on this machine; `update` and `add` fetch
            if rest[:1] and rest[0] in ("update", "add"):
                out.append(Finding(rel, lineno, "git-remote", f"git submodule {rest[0]}"))
        elif sub == "clone" and rest[:1] and re.match(r"""(?:\.|/|~|file://|[A-Za-z]:[\\/])""", rest[0]):
            pass                    # `git clone ./local dir`: a repository on this machine
        elif sub in FORBIDDEN_GIT_SUBCOMMANDS:
            out.append(Finding(rel, lineno, "git-remote", f"git {sub}"))
        elif sub in ("daemon", "instaweb"):
            out.append(Finding(rel, lineno, "inbound-listener", f"git {sub} serves repositories (INBOUND, not egress)"))
        elif sub == "archive" and any(a == "--remote" or a.startswith("--remote=") for a in elts[k + 1:]):
            out.append(Finding(rel, lineno, "git-remote", "git archive --remote"))   # made by the remote, sent here
    elif exe in SHELL_INTERPRETERS:
        # `pwsh --version`, `bash --login`: only the shell's own flags and none of them takes a command
        if all(a.startswith(("-", "/")) for a in elts[1:]) and not any(a.lower() in SHELL_COMMAND_FLAGS for a in elts[1:]):
            return out
        command = " ".join(elts[1:])
        hit = _SHELL_NET_WORD_RE.search(command)
        extra = f"; the command string invokes {hit.group(1)!r}" if hit else ""
        out.append(Finding(rel, lineno, "subprocess-shell",
                           f"{caller}([{exe!r}, ...]): a shell interpreter is handed a command string{extra}"))
    elif _PYTHON_EXE_RE.match(exe):
        rest = elts[1:]
        if "-m" in rest:
            at = rest.index("-m") + 1
            module = rest[at] if at < len(rest) else ""
            # `python -m pip cache purge`, `python -m pip --version`: the module asked about itself
            local_only = _asks_about_itself(rest[at + 1:])
            if not local_only and (module in _PYTHON_NET_MODULES_FOR_M or _classify_module(module) == "network"):
                out.append(Finding(rel, lineno, "subprocess-net-binary",
                                   f"{caller}([python, '-m', {module!r}, ...]): a child interpreter runs a "
                                   "network-capable module"))
        if "-c" in rest and rest.index("-c") + 1 < len(rest):
            code = rest[rest.index("-c") + 1]
            for f in _check_python(Path(rel), rel, local_modules, None, source=code):
                out.append(Finding(rel, lineno, f.kind,
                                   f"in a -c string handed to a child interpreter: {f.detail}"))
    elif exe in _ARGV_SCRIPT_JUDGED:
        # package managers and probes are judged by the rules their command line is judged by on a script line, so
        # `['npm', 'install']` and `['ping', '127.0.0.1']` say what `npm install` and `ping 127.0.0.1` say; a
        # subcommand that acts on this machine (`npm run build`, `pip uninstall x`) or an offline or version request
        # is silent, and one that is not spelled out or not known keeps the claim a network program gets
        start = len(holed) - len(elts) + 1 if holed[-len(elts):] == elts else holed.index(elts[0]) + 1
        args = holed[start:] if _ARGV_HOLE in holed else elts[1:]
        words = ["X" if a == _ARGV_HOLE or not a or re.search(r"\s|['\"`$;&|<>()]", a) else a for a in args]
        command = " ".join([exe] + words)
        found = [f for f in _check_script(Path("argv.sh"), rel, text=command + "\n") if f.kind != "external-url"]
        # `os.execvp("brew", ["brew", x])` repeats the program as its argv[0]: that word is not a subcommand
        named = args[1:] if args and args[0] != _ARGV_HOLE and _argv_basename(args[0]) == exe else args
        sub = next((a for a in named if a == _ARGV_HOLE or not a.startswith("-")), None)
        local = _ARGV_LOCAL_SUBCOMMANDS.get(exe, ())
        first = named[0] if named else None
        # the subcommand is shown when the first argument is a word written out (`yarn application -kill x` is
        # Hadoop's yarn, judged by the script rules); after an option (`pnpm -q out`) or in a variable it is not
        shown = first is not None and first != _ARGV_HOLE and not first.startswith("-")
        for f in found:
            kind = "subprocess-net-binary" if f.kind == "script-network-command" else f.kind
            out.append(Finding(rel, lineno, kind, f"{caller}([{exe!r}, ...]): {f.detail}"))
        if not found and not _install_stays_here(command) and not shown and first not in local \
                and not _asks_about_itself(named) and not (sub is not None and sub != _ARGV_HOLE and sub in local):
            out.append(Finding(rel, lineno, "subprocess-net-binary",
                               f"{caller}([{exe!r}, ...]): network binary via argv list, no shell=True so it "
                               "evades the shell check"))
    elif exe in PY_NET_BINARIES:
        if exe == "openssl" and not _openssl_connects(elts[1:]):
            if any(s in ("s_server", "ocsp") for s in elts[1:]) and any(
                    a in ("-port", "-accept") or a.startswith(("-port=", "-accept=")) for a in elts[1:]):
                # `openssl ocsp -index x -port 8888` answers on a port, `s_server -accept`: inbound, not egress
                out.append(Finding(rel, lineno, "inbound-listener",
                                   f"{caller}([{exe!r}, ...]): serves on a port (INBOUND, not egress)"))
            return out
        # `kubectl version` asks the cluster for its version too, unless told `--client`
        asks_server = _kubectl_asks_the_server(exe, elts[1:])
        # `brew --prefix`, `pip --version`, `npm config ...`: the tool asks the program about
        # itself or its local settings. Only when the first argument is spelled out and is one of these.
        # (For a client whose `-h` names the host, `redis-cli -h cache.example.com ping`, `-h` is not help.)
        # A cloud or cluster client lists and shows what is on the service (`gsutil ls`, `helm list`): only asking it
        # about itself or its settings stays here.
        local_first = _SERVICE_CLIENT_LOCAL_ARGS if exe in _SERVICE_CLIENTS else LOCAL_ONLY_FIRST_ARGS
        # a placeholder is an argument too (`['wget', '-v', url]`): `-v` there is not alone
        if _asks_about_itself(elts[1:] + ([_ARGV_HOLE] if _ARGV_HOLE in holed else []), local_first) and not (elts[1] == "-h" and exe in HOST_H_TOOLS) and not asks_server:
            return out
        if exe in _SERVICE_CLIENTS and _ARGV_HOLE not in holed and not asks_server:
            # global options may come first (`aws --profile p configure get x`): the subcommand is the first word that
            # is neither an option nor an option's value
            words = _subcommand_words(elts[1:])
            if words and (words[0] in _SERVICE_CLIENT_LOCAL_ARGS or tuple(words[:2]) in _SERVICE_CLIENT_LOCAL_PAIRS
                          or words[0] in _SERVICE_LOCAL_SUBCOMMANDS.get(exe, ())):
                return out
            if exe == "kubectl" and words[:1] == ["create"] and len(words) > 1 and "--dry-run=client" in elts and not any(
                    a in ("-f", "--filename", "-k", "--kustomize") or a.startswith(("--filename=", "-f=", "--kustomize="))
                    for a in elts):
                return out      # `kubectl create deployment x --image=y --dry-run=client -o yaml` prints a manifest
            if words and words[0] in _SERVICE_LOCAL_WITH_PATH.get(exe, ()) and (words[0] != "dependency"
                                                                               or words[1:2] == ["list"]):
                # `helm template rel ./chart`, `kubectl kustomize ./overlay`: files here, unless an argument names a
                # repository chart (`bitnami/nginx`) or an address (`--repo https://...`, `oci://...`)
                if not any("://" in w or ("/" in w and not w.startswith((".", "/", "~"))) for w in words[1:]):
                    return out
        # a database client given no host talks to this machine; given one, it is judged by it
        if exe in _DB_CLIENT_HOST_FLAGS:
            # read with the placeholders kept, from the program on (wrappers such as `timeout 30` set aside)
            at = next((k for k, a in enumerate(holed) if a == elts[0]), None)
            host = _db_client_host(exe, holed[at + 1:] if at is not None else elts[1:])
            if host == "" or (host is not None and _THIS_MACHINE_HOST_RE.fullmatch(host)):
                said = "no host is given" if host == "" else "the host given is this machine"
                out.append(Finding(rel, lineno, "loopback-call",
                                   f"{caller}([{exe!r}, ...]): {said}, so {exe} talks to this machine; nothing leaves "
                                   "it at this line"))
                return out
        if exe == "openssl":
            connect = next((elts[k + 1] for k, a in enumerate(elts[:-1]) if a == "-connect"), None)
            if connect and _THIS_MACHINE_HOST_RE.fullmatch(connect.rsplit(":", 1)[0].strip("[]")):
                out.append(Finding(rel, lineno, "loopback-call",
                                   f"{caller}([{exe!r}, ...]): connects to an address on this machine; nothing leaves "
                                   "it at this line"))
                return out
        # `docker-compose` (compose's first, separate program) acts as `docker compose` does
        if exe in ("docker-compose", "podman-compose") and (
                _compose_subcommand(list(holed[1:])) in DOCKER_LOCAL_SUBCOMMANDS
                or (_compose_subcommand(list(holed[1:])) in ("run", "create", "up") and _pulls_never(elts))):
            return out
        # `docker logs x`, `docker compose down`: these act on containers already on this machine
        if exe in ("docker", "podman") and len(elts) > 1:
            # docker's own options come before the subcommand (`docker --debug run ...`); one naming a daemon or a
            # context (`-H ssh://host`, `--context prod`) may send every subcommand to another machine
            at, remote = 1, False
            while at < len(elts) and elts[at].startswith("-"):
                flag, _, value = elts[at].partition("=")
                if flag in _DOCKER_GLOBAL_VALUE_FLAGS:
                    value = value or (elts[at + 1] if at + 1 < len(elts) else "")
                    if flag in ("-H", "--host"):
                        remote = remote or not value.startswith(("unix://", "npipe://"))
                    elif flag in ("-c", "--context"):
                        remote = remote or value != "default"
                    at += 1 if "=" in elts[at] else 2
                elif flag in _DOCKER_GLOBAL_SWITCHES:
                    at += 1
                else:
                    break
            sub = "" if remote or at >= len(elts) else elts[at]
            if sub == "compose":
                # the subcommand comes after compose's own flags: `docker compose -f c.yml down`. Read with the
                # placeholders kept, so `-f <variable>` does not take the subcommand as its value.
                sub = _compose_subcommand(holed[holed.index("compose") + 1:] if "compose" in holed else elts[2:])
            # (compose takes its flags anywhere; `docker run`'s end at the image)
            if (sub == "up" and _pulls_never(elts)) or (
                    sub in ("run", "create") and elts[at] == sub and _pulls_never(elts, at + 1)) or (
                    sub in ("run", "create") and elts[at] == "compose" and _pulls_never(elts)):
                return out                  # `docker run --pull never img`: an image already here, or nothing
            if sub in DOCKER_LOCAL_SUBCOMMANDS:
                return out
            if sub == "import" and _ARGV_HOLE not in holed and not any("://" in a for a in elts):
                return out                  # `docker import a.tar`: a file here (an address would be fetched)
            if sub in DOCKER_MANAGEMENT_NETWORK and sub in holed:
                # `docker volume rm "$1"`, `docker network create`, `docker buildx use`: a management command acts here
                # unless its subcommand pulls, pushes or builds (a subcommand held in a variable is not known)
                inner = next((a for a in holed[holed.index(sub) + 1:] if a == _ARGV_HOLE or not a.startswith("-")), "")
                if inner != _ARGV_HOLE and inner not in DOCKER_MANAGEMENT_NETWORK[sub]:
                    return out
        # `npm run-script` with nothing after it lists the package's scripts
        if exe in SCRIPT_RUNNERS and len(elts) == 2 and elts[1] in ("run", "run-script") and _ARGV_HOLE not in holed:
            return out
        # rsync and scp reach the network only when an argument names a host (`host:path`, `rsync://`, or a
        # variable that could hold one); `Popen('/bin/rsync *')` copies on this machine
        if exe in _COPY_TOOLS and _ARGV_HOLE not in holed and not any(_REMOTE_SPEC_RE.search(" " + a) for a in elts[1:]):
            return out
        # `redis-cli -p 6360 ping`: no host given, and redis-cli's default is this machine
        if exe in DEFAULT_LOCAL_HOST_TOOLS and _ARGV_HOLE not in holed and not any(
                a.split("=", 1)[0] in DEFAULT_LOCAL_HOST_TOOLS[exe] or a.startswith(DEFAULT_LOCAL_HOST_TOOLS[exe][0])
                for a in elts[1:]):
            out.append(Finding(rel, lineno, "loopback-call",
                               f"{caller}([{exe!r}, ...]): no host is given, so {exe} talks to this machine; nothing "
                               "leaves it at this line"))
            return out
        # `yarn application -kill ...` is Hadoop's resource manager, not the JavaScript package manager
        if exe == "yarn" and len(elts) > 1 and elts[1] in HADOOP_YARN_SUBCOMMANDS:
            return out
        # Mercurial, like git, works on the repository on this machine except for a few subcommands.
        # Judged the way git is: by the subcommand that reaches a remote, when it is spelled out.
        if exe == "hg" and len(elts) > 1:
            # the first word that is not an option and not the program again (`os.execvp` repeats it as argv[0])
            sub = next((a for a in elts[1:] if not a.startswith("-") and _argv_basename(a) != "hg"), "")
            if re.fullmatch(r"[a-z][a-z-]*", sub) and sub not in HG_REMOTE_SUBCOMMANDS:
                return out
        # Two programs are called certutil. Windows' downloads with `-urlcache` and its relatives; Mozilla NSS's
        # (`certutil -d <db> -A ...`) edits a certificate database on this machine. Judged by the verb, when written.
        if exe == "certutil" and len(elts) > 1 and _ARGV_HOLE not in holed \
                and not any(a.lower().lstrip("-/") in CERTUTIL_NETWORK_VERBS for a in elts[1:]):
            return out
        # `svn status`, `svn add`: the working copy on this machine; judged by the subcommand, when written, and a
        # repository named by a path here (`svn export . /tmp/x`, `file:///srv/repo`) is here too
        if exe == "svn" and len(elts) > 1:
            positional = [a for a in elts[1:] if not a.startswith("-")]
            sub = positional[0] if positional else ""
            # any subcommand given a repository address (`svn info https://...`, `svn diff ^/trunk`) reads it there
            names_repo = any(_svn_repository_address(a) for a in positional[1:])
            if re.fullmatch(r"[a-z]+", sub) and sub not in SVN_REMOTE_SUBCOMMANDS and not names_repo:
                return out
            if _ARGV_HOLE not in holed and len(positional) > 1 and positional[1].startswith((".", "/", "~", "file://")):
                return out
        # socat relays between two addresses; it reaches the network only when one of them is a network address that
        # it connects to elsewhere. One that only listens (`TCP-LISTEN:8080`) is inbound.
        if exe == "socat" and _ARGV_HOLE not in holed:
            nets = [a for a in elts[1:] if _SOCAT_NET_ADDRESS_RE.match(a)]
            if not nets:
                return out
            listens = [a for a in nets if re.match(r"[\w]+-(?:LISTEN|RECV|RECVFROM)\b", a, re.I)]
            connects = [a for a in nets if a not in listens]
            if all(_THIS_MACHINE_HOST_RE.fullmatch((a.split(":") + ["", ""])[1].strip("[]")) for a in connects):
                if listens:
                    out.append(Finding(rel, lineno, "inbound-listener",
                                       f"{caller}([{exe!r}, ...]): listens for connections (INBOUND, not egress)"
                                       + ("" if not connects else "; it relays to this machine only")))
                else:
                    out.append(Finding(rel, lineno, "loopback-call",
                                       f"{caller}([{exe!r}, ...]): connects to an address on this machine; nothing "
                                       "leaves it at this line"))
                return out
        # `nc -l 8080`: listens (INBOUND), it does not connect out
        if exe in ("nc", "ncat", "netcat") and _ARGV_HOLE not in holed and any(
                a == "--listen" or (re.fullmatch(r"-[A-Za-z]+", a) and "l" in a) for a in elts[1:]):
            out.append(Finding(rel, lineno, "inbound-listener",
                               f"{caller}([{exe!r}, ...]): listens for connections (INBOUND, not egress)"))
            return out
        out.append(Finding(rel, lineno, "subprocess-net-binary",
                           f"{caller}([{exe!r}, ...]): network binary via argv list, no shell=True so it "
                           "evades the shell check"))
    elif _ARGV_HOLE not in holed[:2]:
        # `['go', 'get', ...]`, `['cargo', 'install', ...]`, `['gem', 'install', ...]`: a package manager or build tool
        # of another ecosystem, judged by the same rules as on a script line
        command = " ".join([exe] + [a if a and not re.search(r"\s", a) else "X" for a in elts[1:]])
        m = _SCRIPT_INSTALL_RE.match(command) or _ARGV_OTHER_INSTALL_RE.match(command)
        if m and not _install_stays_here(command):
            tool = m.group(1).split()[0].lower()
            if tool in _ALWAYS_REMOTE_TOOLS and _HOST_TOOL_LOOPBACK_RE.search(command[len(m.group(1)):]):
                out.append(Finding(rel, lineno, "loopback-call",
                                   f"{caller}([{exe!r}, ...]): runs {tool!r} against an address on this machine; "
                                   "nothing leaves it at this line"))
            elif tool in _ALWAYS_REMOTE_TOOLS or _SENDS_RE.search(m.group(1)):
                shown = " ".join([w for w in m.group(1).split() if not w.startswith("-")][:2])
                out.append(Finding(rel, lineno, "subprocess-net-binary",
                                   f"{caller}([{exe!r}, ...]): runs {shown!r}, a program that reaches the network"))
            else:
                shown = " ".join([w for w in m.group(1).split() if not w.startswith("-")][:2])
                out.append(Finding(rel, lineno, "subprocess-net-binary",
                                   f"{caller}([{exe!r}, ...]): runs {shown!r}, which reaches the network to download "
                                   "packages or other content it needs when they are not already on this machine"))
    return out


# Installers a script line meets through another rule, in their argv form (`['go', 'get', ...]`, `['gem', 'install']`)
_ARGV_OTHER_INSTALL_RE = re.compile(
    r"""((?:go\s+(?:get|install|mod\s+download)|gem\s+install|cargo\s+install|choco\s+install|winget\s+install"""
    r"""|scoop\s+install|nuget\s+install|cpanm?\s+\S+|bower\s+install|jspm\s+install|nix-channel\s+--update"""
    r"""|apk\s+add|zypper\s+in|port\s+install|pkg\s+install|snap\s+install|flatpak\s+install))(?!\S)""",
    re.IGNORECASE)


def _shebang(path: Path) -> bytes:
    """The first line of a file when it is a `#!` line, else empty. A file that cannot be opened raises `OSError`:
    what kind of file it is cannot be told, so it is not taken for a file of no kind."""
    head = _reads.read_head(path, _SHEBANG_SNIFF_BYTES)
    first = head.split(b"\n", 1)[0]
    return first if first.startswith(b"#!") else b""


def _is_python_script(path: Path) -> bool:
    """A file with no extension whose first line is a Python shebang (python, pypy, or `uv run`)."""
    first = _shebang(path)
    return b"python" in first or b"pypy" in first or re.search(rb"\buv\s+run\b", first) is not None


# Python by its name (SCons build files, a WSGI entry point, a Twisted application file), and the extensions a
# server runs as a script when its shebang names Python (`app.cgi`, `app.fcgi`)
_PYTHON_FILE_NAMES = {"sconstruct", "sconscript"}
_PYTHON_FILE_EXTS = {".wsgi", ".tac", ".rpy"}
_SHEBANG_SCRIPT_EXTS = {"", ".cgi", ".fcgi"}


def _is_python_file(path: Path, suffix: str) -> bool:
    """Python by its extension (`.py`, `.pyw`), by a name or an extension that is Python by convention, or with no
    extension or a CGI one and a Python shebang."""
    if suffix in TEXT_EXTS or suffix in _PYTHON_FILE_EXTS or path.name.lower() in _PYTHON_FILE_NAMES:
        return True
    return suffix in _SHEBANG_SCRIPT_EXTS and _is_python_script(path)


# pipeline files whose names vary (`azure-pipelines.yaml`, `azure-pipelines-pr.yml`, `cloudbuild-release.yaml`)
_PIPELINE_NAME_RE = re.compile(r"(?:azure-pipelines|cloudbuild)[^/]*\.ya?ml")


def _is_recipe_name(rel: str) -> bool:
    """A script, a build recipe or a pipeline definition by its path alone (`Dockerfile.prod`,
    `.github/workflows/ci.yml`, `ci.mk`)."""
    low = rel.lower().replace("\\", "/")
    name = low.rsplit("/", 1)[-1]
    suffix = "." + name.rsplit(".", 1)[1] if "." in name.lstrip(".") else ""
    if suffix in SCRIPT_EXTS or name in SCRIPT_NAMES or name.startswith(("dockerfile.", "containerfile.", "jenkinsfile.")) \
            or name.endswith((".dockerfile", ".mk", ".gitlab-ci.yml", ".gitlab-ci.yaml", ".just", ".jenkinsfile")) \
            or name == ".justfile" or _PIPELINE_NAME_RE.fullmatch(name):
        return True
    return suffix in (".yml", ".yaml") and (any(d in "/" + low for d in ("/" + p for p in _PIPELINE_DIRS))
                                            or name.startswith(("docker-compose", "compose.")))


def _is_script(path: Path, rel: str) -> bool:
    """A shell, PowerShell or batch script, a build recipe, or a pipeline definition."""
    suffix = _reads.suffix_of(path).lower()
    if _is_recipe_name(rel):
        return True
    if not suffix:
        first = _shebang(path)
        return bool(first) and any(sh in first for sh in (b"sh", b"bash", b"zsh", b"ksh", b"fish", b"pwsh"))
    return False


_HOST_TOOLS = {"nc", "ncat", "netcat", "telnet", "ssh", "sftp", "ftp", "test-connection", "test-netconnection"}
# Tools that copy files: they reach the network only when an argument names a host.
_COPY_TOOLS = {"rsync", "scp"}
# `host:path`, `user@host:path`, `rsync://host/...` (not `C:\...`), or a variable that could hold one.
_REMOTE_SPEC_RE = re.compile(r"""(?:^|\s|['"])(?:[^\s@'"]+@)?(?:[\w.-]{2,}|\[[0-9A-Fa-f:.%\w]+\])::?(?!\\)[^\s]*"""
                             r"""|\w+://|\$""")
# the host of each `host:path` a copy names (`deploy@[2001:db8::5]:/srv/`, `localhost:/p`)
_REMOTE_SPEC_HOST_RE = re.compile(r"""(?:^|\s|['"])(?:[^\s@'"]+@)?([\w.-]{2,}|\[[0-9A-Fa-f:.%\w]+\])::?(?!\\)""")
# `NAME = value`, `NAME := value`, `NAME ?= value` at the start of a Makefile line (a recipe line starts with a tab).
_MAKE_VARIABLE_RE = re.compile(r"""^(?:export\s+|override\s+)?[A-Za-z_][\w.-]*\s*(?::{1,3}|\+|\?|!)?=""")
_MAKE_CONDITIONAL_RE = re.compile(r"^\s*(?:ifeq|ifneq|ifdef|ifndef|else|endif)\b")
_MAKE_DEFINE_RE = re.compile(r"^\s*(?:export\s+|override\s+)?define\s")
_MAKE_RULE_RE = re.compile(r"^[^\s#=][^=]*?(?<!:):(?![=:])")


# Words that mark a key whose block value is a script in a pipeline, compose or CI file: `run`, `script`,
# `before_script`, `install` (run-on-arch), `CIBW_BEFORE_ALL_LINUX`, `pre-build-command`, `inlineScript`. A key with
# none of them (`SYSTEM_PROMPT`, `body`, `description`, `notes`) holds text that something reads.
_YAML_COMMAND_WORDS = {"run", "runs", "script", "scripts", "inlinescript", "command", "commands", "cmd", "entrypoint",
                       "exec", "shell", "bash", "sh", "pwsh", "powershell", "install", "setup", "build", "before",
                       "after", "pre", "post", "test", "tests", "steps", "all", "hook", "hooks", "do", "task", "tasks"}
_YAML_BLOCK_OPENER_RE = re.compile(r"""^(\s*(?:-\s+)?)([\w.-]+)\s*:\s*[|>][-+0-9]*\s*(?:#.*)?$""")


# Words that mark a key whose value is text for a person or a program to read.
_YAML_TEXT_WORDS = {"prompt", "prompts", "message", "messages", "body", "description", "desc", "notes", "note", "summary",
                    "text", "comment", "comments", "title", "template", "changelog", "readme", "markdown", "content",
                    "instructions", "help", "usage", "explanation", "reason", "announcement", "greeting", "footer",
                    "header", "caption", "label", "labels"}


def _yaml_key_holds_script(key: str) -> bool:
    """A block value is a script unless its key says it is text and says nothing about running.

    `SYSTEM_PROMPT: |-` and `body: |` hold text; `run: |`, `install: |` and an action's `prepare: |` hold scripts,
    and so does any key whose name says neither (the default keeps the stronger claim it had)."""
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key).lower().replace("_", " ").replace("-", " ").replace(".", " ").split()
    return any(w in _YAML_COMMAND_WORDS for w in words) or not any(w in _YAML_TEXT_WORDS for w in words)


def _github_script_step(lines: list[str], n: int) -> bool:
    """The block opened at line index `n` is the `script:` of an `actions/github-script` step: JavaScript, not a
    shell script. A shell command written inside it is text the script builds (a comment's code block)."""
    m = _YAML_BLOCK_OPENER_RE.match(lines[n])
    if not m or m.group(2).lower() != "script":
        return False
    indent = len(m.group(1))
    for k in range(n - 1, max(-1, n - 40), -1):
        line = lines[k]
        if "actions/github-script" in line:
            return True
        stripped = line.lstrip()
        # the start of this step (`- uses: ...`, `- name: ...`) sits left of `with:`, which sits left of `script:`
        if stripped.startswith("- ") and len(line) - len(stripped) < indent - 2:
            return "actions/github-script" in line
    return False


def _yaml_text_lines(lines: list[str]) -> set[int]:
    """Line numbers (1-based) inside a YAML block scalar whose key does not hold a script."""
    held: set[int] = set()
    n = 0
    while n < len(lines):
        m = _YAML_BLOCK_OPENER_RE.match(lines[n])
        if not m or (_yaml_key_holds_script(m.group(2)) and not _github_script_step(lines, n)):
            n += 1
            continue
        indent = len(m.group(1))
        k = n + 1
        while k < len(lines) and (not lines[k].strip() or len(lines[k]) - len(lines[k].lstrip()) > indent):
            held.add(k + 1)
            k += 1
        n = k
    return held


# `CMD="curl -v -x $PROXY_URL ..."`: a whole line that only assigns a quoted string to a shell variable.
_SHELL_ASSIGN_ONLY_RE = re.compile(r"""^(?:(?:export|local|readonly|declare)\s+)?[A-Za-z_]\w*=(["'])(.*)\1\s*;?$""")


# `missing_deps+=("wget or curl")`, `deps=(curl jq)`: a shell array of words or strings.
_SHELL_ARRAY_ASSIGN_RE = re.compile(r"""^(?:(?:local|readonly|declare(?:\s+-a)?)\s+)?[A-Za-z_]\w*\+?=\((.*)\)\s*;?$""")


def _holds_command_text(stripped: str) -> bool:
    """The line stores a command in a variable (or words in an array); it runs where `$NAME` is used, if at all.
    A substitution inside it (`$(curl ...)`, a backtick) still runs here."""
    m = _SHELL_ASSIGN_ONLY_RE.match(stripped) or _SHELL_ARRAY_ASSIGN_RE.match(stripped)
    value = m.group(m.lastindex) if m else ""
    return bool(m) and "$(" not in value and "`" not in value


def _make_variable_lines(lines: list[str]) -> set[int]:
    """Line numbers (1-based) of a Makefile that hold a variable's value, not a recipe.

    A recipe line starts with a tab, but only after a rule's target line: a tab-indented
    `NAME = value` inside an `ifeq` block before any rule is an assignment, and every line of a
    `define NAME ... endef` block is the variable's text. Either holds a command that runs where
    `$(NAME)` is used.
    """
    held: set[int] = set()
    in_rule = in_define = False
    for n, line in enumerate(lines, 1):
        if in_define:
            held.add(n)
            if line.strip() == "endef":
                in_define = False
            continue
        if _MAKE_DEFINE_RE.match(line):
            held.add(n)
            in_define = True
            continue
        if line.startswith("\t"):
            if not in_rule and _MAKE_VARIABLE_RE.match(line.lstrip()):
                held.add(n)
            continue
        if not line.strip() or line.lstrip().startswith("#") or _MAKE_CONDITIONAL_RE.match(line):
            continue
        if _MAKE_VARIABLE_RE.match(line):
            held.add(n)
            in_rule = False
        elif _MAKE_RULE_RE.match(line):
            in_rule = True
        else:
            in_rule = False
    return held
# The host argument of such a tool, when it is this machine: `localhost`, `user@127.0.0.1`.
_SCRIPT_LOOPBACK_ARG_RE = re.compile(r"""(?:^|\s)(?:[\w.-]+@)?(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)(?=\s|$|['"])""")
# A regular expression that begins like an address: `https://github.com/([^/?#]+)/...`, `https://github\.com/`.
# It matches addresses; it is not one. Recognised by pattern syntax inside the same run of characters.
# A URL whose host is a glob (`https://*)` in a `case` arm, `allowed_urls=http://snapshot.test*`): a pattern
# that addresses are matched against, not an address.
_GLOB_URL_RE = re.compile(r"""(?:https?|wss?|ftps?)://[^\s"'/]*\*[^\s"']*""", re.IGNORECASE)
_PATTERN_URL_RE = re.compile(r"""(?:https?|wss?|ftps?|ssh)://[^\s"']*?(?:\\\.|\(\[\^|\[\^|\(\.[+*]\)|\)\?|\[\[:)[^\s"']*""",
                             re.IGNORECASE)
# A here-document opener (`<<EOF`, `<<-'EOF'`), not a here-string (`<<<`).
# a here-document opener and its delimiter word, in any shell quoting (`<<EOF`, `<<'EOF'`, `<<\EOF`, `<<"E"OF`, `<<1`,
# `<<'!PY'`); not a here-string (`<<<`) or a shift inside arithmetic (`$((1<<2))`)
_HEREDOC_RE = re.compile(r"""(?<![<\d])<<-?[ \t]*((?:\\.|'[^'\n]*'|"[^"\n]*"|[^\s;&|<>()'"\\`$])+)""")


_HEREDOCS_PER_LINE = 64      # here-documents read on one line; a line opening more is reported as not analysed


def _split_commands(line: str) -> list[str]:
    """The commands of one line, in order: split at `&&`, `||`, `;` and a background `&` that stand outside quotes,
    parentheses, braces and backquotes. A pipeline stays one command (`curl ... | sh`). Each is judged on its own, so
    a first command that reaches nothing (`curl --version && curl ... | sh`) does not speak for the rest."""
    masked = list(line)
    for qs, qe in _quote_regions(line):
        masked[qs + 1:qe] = " " * (min(qe, len(line)) - qs - 1)
    # an escaped join (`\;` in a POSIX shell, `^&` in cmd, a backquote before `;` in PowerShell) joins nothing
    text = _ESCAPED_PAIR_RE[_ESCAPE_STYLE.get()].sub("  ", "".join(masked))
    pieces, start, depth, i, n, backquoted = [], 0, 0, 0, len(text), False
    while i < n:
        c = text[i]
        if c == "`":
            backquoted = not backquoted
        elif backquoted:
            pass
        elif c in "({":
            depth += 1
        elif c in ")}":
            depth = max(0, depth - 1)
        elif text.startswith(";;", i):
            i += 2                          # a `case` branch's end, inside one command
            continue
        elif depth == 0 and (text.startswith("&&", i) or text.startswith("||", i)):
            pieces.append(line[start:i])
            start = i = i + 2
            continue
        elif depth == 0 and (c == ";" and not text.startswith(";;", i) or (
                c == "&" and text[i - 1:i] not in ("<", ">", "&", "|") and text[i + 1:i + 2] not in (">", "&"))):
            pieces.append(line[start:i])
            start = i + 1
        i += 1
    pieces.append(line[start:])
    return [p for p in pieces if p.strip()] or [line]


def _yaml_block_ends(lines: list[str]) -> list[int]:
    """For each line of a YAML file, the index of the first later line its block does not hold: the first non-blank
    line indented less than it, or no more than it when the line is a key or a list item (`- run: cat <<EOF` ends at the
    next step). A here-document opened on a line ends inside that line's block or not at all."""
    n = len(lines)
    out = [n] * n
    stack: list[tuple[int, int, bool]] = []         # (index, indent, key-or-item) of lines still waiting for their end
    for k, ln in enumerate(lines):
        if not ln.strip():
            continue
        ind = _yaml_indent(ln)
        while stack and (ind < stack[-1][1] or (ind == stack[-1][1] and stack[-1][2])):
            out[stack.pop()[0]] = k
        stack.append((k, ind, bool(re.match(r"\s*(?:-\s|[\w.-]+\s*:(?:\s|$))", ln))))
    return out


# shells and command runners beyond the named readers: any `*sh` with a version (`bash5`, `mksh`, `tcsh`), `xonsh`,
# and programs that run each line they read (`at`, `batch`, `parallel`)
# readers whose name is also an ordinary argument (`jq . <<EOF`, `git log --format=source`): readers only as the program
_READERS_AS_PROGRAM_ONLY = {".", "source", "eval", "RUN"}
_HEREDOC_SHELL_NAME_RE = re.compile(r"(?:ba|z|k|da|mk|tc|c|a|yash|posh)?sh[\d.]*|xonsh|at|batch|parallel")


_SCRIPT_TARGET_SUFFIXES = ("", ".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".pl",
                           ".rb", ".js", ".mjs", ".cjs", ".php", ".py", ".pyw", ".command")


# files with no extension that hold text and are never run (a name with no extension is otherwise taken for a script)
_TEXT_FILE_NAMES = {"motd", "issue", "issue.net", "hosts", "hostname", "fstab", "sudoers", "passwd", "group", "shells",
                    "timezone", "mailname", "machine-id", "license", "readme", "notice", "authors", "changelog",
                    "copying", "codeowners", "version"}


def _writes_text_file(target) -> bool:
    """A here-document written to a file that is not a script (`cat > NOTES.txt <<EOF`): its body is text, read for
    addresses. One written to a script, a name with no extension or one held in a variable may be run: read as lines."""
    if target is None:
        return False
    name = target.group(target.lastindex).strip("'\"")
    if "$" in name or "`" in name:
        return False
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if base.lower() in _TEXT_FILE_NAMES:
        return True                     # `sudo tee /etc/motd <<EOF`: a file with no extension that nothing runs
    if _is_recipe_name(name):
        # a build recipe or pipeline file (`cat <<EOF >> tox.ini`, `> Dockerfile.prod`, `> .github/workflows/ci.yml`):
        # what is written there is run
        return False
    suffix = "." + base.rsplit(".", 1)[1].lower() if "." in base.lstrip(".") else ""
    return suffix not in _SCRIPT_TARGET_SUFFIXES


def _heredoc_runs_as_code(line: str, seg_s: int, segment: str, at: int) -> bool:
    """Is the program a here-document is handed to one that runs it as code: a shell or an interpreter in its command
    (`ssh host bash <<EOF`, `${SH:-/bin/sh} <<EOF`), a brace group's commands (`{ sh; } <<EOF`), or the shell itself
    running what `$(cat <<EOF ...)` prints, where that stands as a command."""
    text = segment
    if segment.lstrip().startswith("}"):
        # the input of `{ ...; }` goes to the commands inside it
        brace = line.rfind("{", 0, seg_s)
        text = line[brace:at] if brace >= 0 else segment
    # a quoted string is one word with its quotes taken off (`"$BASH"` names a shell); one holding a space is a phrase
    # (`'meet at noon'`), not a program
    protect = {"|": "\x01", ";": "\x02", "&": "\x03", "(": "\x04", ")": "\x05", "{": "\x06", "}": "\x07"}
    masked = list(text)
    for qs, qe in _quote_regions(text):
        for k in range(qs + 1, min(qe, len(text))):
            masked[k] = "\x00" if masked[k] in " \t" else protect.get(masked[k], masked[k])
    restore = str.maketrans({v: k for k, v in protect.items()})
    words = [w.translate(restore).replace('"', "").replace("'", "")
             for w in re.split(r"[\s|;&(){}]+", "".join(masked)) if w and "\x00" not in w]
    for k, w in enumerate(words):
        b = _argv_basename(w)
        if b in _READERS_AS_PROGRAM_ONLY and not (k == 0 or words[k - 1] in ("sudo", "doas", "env", "exec", "command")):
            continue        # `jq . <<EOF`: `.` is an argument there, not the shell's `.`
        if b in ("sudo", "doas") and any(not x.startswith(("-", "<", ">")) for x in words[k + 1:]):
            continue        # `| sudo tee /etc/x`: the program sudo runs reads the body, and is judged itself
        # (Python with a script reads the body as data; one reading it as code is judged as Python first)
        if (w in _HEREDOC_CODE_READERS or b in _HEREDOC_CODE_READERS
                or _VARIABLE_SHELL_RE.fullmatch(w) or re.fullmatch(r"\$\{\w+:-[^}]*\}", w)
                # a shell by name anywhere (`ssh host mksh`); `at`, `batch` and `parallel` only as the program
                or (_HEREDOC_SHELL_NAME_RE.fullmatch(b) and (k == 0 or b not in ("at", "batch", "parallel")))):
            return True
    # `$(cat <<EOF ...)` or a backquoted `cat` at a command's start: the shell runs what it prints
    return re.search(r"(?:^|[;&|({]\s*|\b(?:then|do|else|eval|exec)\s+)(?:\$\(|`)\s*cat\s+$", line[:at]) is not None


def _shell_quote_scan(text: str, carried: tuple | None = None) -> tuple[list[tuple[int, int]], tuple | None, int]:
    """How the shell quotes one line: (the quoted spans, the quote still open at its end, where a quote open at its
    start closes, -1 if it does not). `'...'` takes everything literally, `"..."` and `$'...'` honour a backslash,
    and outside quotes a backslash escapes the next character and `#` at a word's start comments out the rest. A span
    is (start, end) of its quote characters; one still open at the end of the line runs to the line's end. What is
    still open at the end (a quote, a `$(` inside double quotes) is returned to be carried into the next line."""
    state, resume, paren = carried if carried else (None, [], 0)
    resume = list(resume)       # inside `"... $( ... ) ..."`: the depth at which the double-quoted string resumes
    spans: list[tuple[int, int]] = []
    first_close = -1 if state else 0
    opened = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if state is None:
            if c == "\\":
                i += 2
                continue
            if c == "#" and (i == 0 or text[i - 1] in " \t;&|()"):
                break
            if c == "$" and text[i + 1:i + 2] == "'":
                state, opened = "$'", i
                i += 2
                continue
            if c in "'\"":
                state, opened = c, i
            elif c == "(":
                paren += 1
            elif c == ")":
                if resume and paren == resume[-1]:
                    resume.pop()
                    state, opened = '"', i              # back inside the double-quoted string around `$(...)`
                else:
                    paren = max(0, paren - 1)
        elif state == '"' and text.startswith("$(", i):
            # a command substitution inside double quotes quotes afresh: `"$(cat <<'EOF'` opens a here-document
            spans.append((opened, i))
            resume.append(paren)
            state = None
            i += 2
            continue
        elif state == "'":
            if c == "'":
                spans.append((opened, i))
                state = None
                first_close = i if first_close == -1 else first_close
        else:                                       # `"` or `$'`: a backslash escapes the next character
            if c == "\\":
                i += 2
                continue
            if c == state[-1]:
                spans.append((opened, i))
                state = None
                first_close = i if first_close == -1 else first_close
        i += 1
    if state is not None:
        spans.append((opened, n))
    return spans, ((state, tuple(resume), paren) if state is not None or resume else None), first_close


def _heredoc_word(doc: re.Match) -> tuple[str, bool]:
    """(the terminator line, whether the body is quoted): the delimiter with its quoting removed, and quoted when any
    part of it is quoted or escaped, as the shell decides whether the body is expanded."""
    word = doc.group(1)
    term = re.sub(r"""\\(.)|'([^']*)'|"([^"]*)\"""", lambda m: m.group(1) or m.group(2) or m.group(3) or "", word)
    return term, bool(re.search(r"""['"\\]""", word))


def _shell_lines(text: str) -> list[str]:
    """The lines of a script as the shell reads them: ended by a line feed (a carriage return before it is the line
    ending, too), never by a form feed, a vertical tab, a file separator or a Unicode line or paragraph separator."""
    if text.endswith("\n"):
        text = text[:-1]
    return [ln[:-1] if ln.endswith("\r") else ln for ln in text.split("\n")] if text else []
# Its body written to a file (`cat <<EOF > run.sh`), which may run later.
_HEREDOC_TO_FILE_RE = re.compile(r"""(?<![0-9&>])>{1,2}\s*(?!&)[^\s|;&]""")
# The file a here-document's body is written to: after `>`, `tee`, or a Dockerfile `COPY <<EOF <dest>`
_HEREDOC_TARGET_RE = re.compile(
    r"""(?<![0-9&>])>{1,2}\s*(?!&)([^\s|;&]+)|\btee\s+(?:-a\s+)?([^\s|;&<>]+)"""
    r"""|^(?:COPY|ADD)\b(?:\s+--\S+)*\s+(?:<<-?\s*['"]?[\w.-]+['"]?\s+)+([^\s<]+)\s*$""", re.IGNORECASE)
# Programs that run what they read on standard input as code.
_HEREDOC_CODE_READERS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "node", "perl", "ruby",
                         "php", "ssh", "docker", "podman", "kubectl", "sudo", "eval", "source", ".",
                         "su", "doas", "chroot", "arch-chroot", "schroot", "nsenter", "unshare", "fakeroot",
                         "firejail", "lxc-attach", "machinectl", "adb", "busybox",
                         "RUN"}     # a Dockerfile `RUN <<EOF` runs its body as a shell script
# a shell named by a variable: `$SHELL <<EOF`, `"${SHELL}" <<EOF`
_VARIABLE_SHELL_RE = re.compile(
    r"""["']?\$(?:\{(?:\w*SHELL\w*|BASH|0)(?::?[-=+?][^}]*)?\}|\w*SHELL\w*|BASH|0)["']?""")
_YAML_BARE_KEY_RE = re.compile(r"""^[\w.-]+:\s*$""")
# A line that only prints: `echo "git fetch origin"`. Anything that hands the text on (a pipe, `&&`,
# `;`, a substitution, a redirect into a file) means it may run, so such a line does not match.
_PRINTED_RE = re.compile(r"""^\s*(?:-\s+)?(?:run:\s*)?@?(?:echo|printf|Write-Host|Write-Output)\b(?:(?!\$\()[^|;&`<>])*$""",
                         re.IGNORECASE)
_COMMAND_JOIN_RE = re.compile(r"&&|\|\||;|(?<![&>|])&(?![&>])")
# A character escaped by a backslash (POSIX shells) or a caret (cmd) is text, not a separator. Each escaped pair is
# blanked before separators are looked for, so `\\;` (an escaped backslash, then `;`) still separates.
_ESCAPED_PAIR_RE = {"posix": re.compile(r"\\.", re.S), "batch": re.compile(r"\^.", re.S),
                    "powershell": re.compile(r"`.", re.S)}
# Which character escapes the next one in the file being read: `\` in a POSIX shell (and a Dockerfile's RUN),
# `^` in cmd, a backquote in PowerShell.
_ESCAPE_STYLE: contextvars.ContextVar = contextvars.ContextVar("entrovouch_escape_style", default="posix")


def _mask_escapes(s: str) -> str:
    """`s` with every escaped pair replaced by two spaces: same length, so positions hold."""
    return _ESCAPED_PAIR_RE[_ESCAPE_STYLE.get()].sub("  ", s)
# Where one command ends and the next may start inside a line: joins, pipes, substitutions, `sh -c "`.
_COMMAND_START_SPLIT_RE = re.compile(
    # an escaped backtick or `\$(` is text, not a command substitution; `{}` (xargs' and find's placeholder) and
    # `{name}` are words, not a block
    r"""&&|\|\||;|(?<![&>|])&(?![&>])|(?<!\\)\||(?<!\\)`|(?<![${\\])\(|(?<![${])\{(?!\w*\})|(?<!\\)\$\((?![A-Za-z_]\w*\))|-\w*c\s+["']"""
    r"""|\[\s*["']?CMD(?:-SHELL)?["']?\s*,""")
# What may stand in front of a program at the start of a command: a key (`run:`, `commands =`, a tox
# factor, a CI variable), a Dockerfile instruction and its flags, a recipe's silencing prefix, a prompt,
# PowerShell's call operator, a wrapper (`sudo`, `env`, `timeout 10`), a variable assignment, a condition,
# an argv list's opening bracket and quote.
_COMMAND_PREFIX_RE = re.compile(
    r"""^\s*(?:-\s+)?"""
    r"""(?:[\w.,{}-]+\s*[:=]\s*[|>]?[-+]?\s*)?"""
    r"""(?:\[\s*)?["']?"""
    r"""(?:(?-i:RUN|CMD|ENTRYPOINT|SHELL)(?:\s+--\S+)*\s+(?:\[\s*["']?)?)?"""
    r"""(?:[\w.*|-]+\)\s*)?"""
    r"""(?:[@+-]\s*)?(?:\$\s+|>\s+|PS\S*>\s*|&\s*)?"""
    # cmd's `if exist x`, `if not defined X`, `if errorlevel 1`, `if %A%==b`, and `start "" ` with its window title
    r"""(?:if\s+(?:/i\s+)?(?:not\s+)?(?:exist\s+\S+|defined\s+\S+|errorlevel\s+\d+|\S+==\S+)\s+"""
    r"""|start\s+"[^"]*"(?:\s+/\w+)*\s+"""
    # PowerShell's launcher, with the program named directly or by `-FilePath`: `Start-Process curl.exe -ArgumentList`
    r"""|(?:start-process|saps)(?:\s+-(?:wait|nonewwindow|passthru|windowstyle\s+\w+))*(?:\s+-f\w*)?\s+"""
    # PowerShell's `Invoke-Expression "git pull"` (`iex`) runs the string it is given
    r"""|(?:invoke-expression|iex)(?:\s+-command)?\s+["']?"""
    # PowerShell runs the command an assignment takes its value from: `$r = Invoke-RestMethod ...`
    r"""|\$[\w:]+\s*\+?=\s*"""
    # a redirection may stand before the program: `>/dev/null curl ...`, `2> err.log curl ...`
    r"""|\d*(?:[<>]{1,2}|&>>?)&?[^\s<>|;&]+\s+|\d*(?:[<>]{1,2}|&>>?)\s+[^\s<>|;&]+\s+"""
    # a wrapper may be written as a path (`/usr/bin/env python3 -c ...`, `/usr/bin/sudo -u app curl ...`)
    r"""|(?:(?:/usr)?/s?bin/)?(?:sudo|doas|exec|time|nohup|command|builtin|env|xargs|watch|timeout|nice|ionice|chrt|setsid|unbuffer|chronic|caffeinate|parallel|stdbuf|retry|travis_retry|travis_wait|busybox|shell|coproc|!|if|elif|while"""
    r"""|until|call|start|then|do|else|strace|ltrace|torsocks|tsocks|proxychains4?|firejail"""
    r"""|git\s+submodule\s+(?:--quiet\s+)?foreach(?:\s+--recursive)?)"""
    # (an option's value may be quoted or substituted: `sudo -u "$APP_USER"`, `xargs -a "$LIST"`, `nice -n "$(n)"`)
    r"""(?:\s+(?:-{1,2}|/)[\w-]+(?:\{\}|=\S+|\s+(?![-/])(?:"[^"]*"|'[^']*'|\$\([^()]*\)|[^\s"'`|;&]+))?)*\s+"""
    r"""|[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S*)\s+|\d+[smh]?\s+"""
    # a positional a wrapper takes, held in a variable or a substitution: `timeout "$TIMEOUT"`, `env $(cat prod.env)`
    r"""|\$\([^()]*\)\s+|"\$\([^()"]*\)"\s+|\$\{[A-Za-z_]\w*\}\s+|\$[A-Za-z_]\w*\s+"""
    r"""|"\$(?:[@*]|\{?[A-Za-z_]\w*(?:\[[@*\w]+\])?\}?)"\s+"""
    # `find . -name '*.tgz' -exec aws s3 cp {} s3://b/ \;`: find runs the program after `-exec`
    r"""|find\s[^;&|]*?\s-(?:exec|execdir|ok|okdir)\s+"""
    # `runuser -u app -- git pull`: runuser's options take a value, and `--` ends them
    r"""|runuser(?:\s+-{1,2}[\w-]+(?:=\S+|\s+(?!-)[^\s;&|]+)?)*\s+--\s+"""
    # `flock /tmp/lock aws s3 sync ...`: flock takes the lock file, then runs the program
    # (its options that take a number: `-w 10`, `--timeout 30`, `-E 3`)
    r"""|flock(?:\s+(?:-[wE]\s*\d+|--(?:timeout|wait|conflict-exit-code)(?:=|\s+)\d+|-{1,2}[\w-]+(?:=\S+)?))*"""
    r"""\s+(?!-)[^\s;&|]+\s+"""
    # a `case` and its first arm on one line: `case $1 in deploy) aws s3 sync . s3://b ;; esac`
    r"""|case\s+(?:"[^"]*"|'[^']*'|\S+)\s+in\s+\(?[\w.*|"'$-]+\)\s*)*"""
    r"""(?:\S*\\)?$""",
    re.IGNORECASE)
# Wrappers that may stand between a launcher and the program: `-- sudo snap install`.
_WRAPPERS_TAIL_RE = re.compile(
    r"""(?:\b(?:sudo|doas|exec|time|nohup|env|timeout|nice|busybox)\b"""
    r"""(?:\s+-{1,2}[\w-]+(?:=\S+|\s+(?!-)(?:"[^"]*"|'[^']*'|[^\s"'`|;&]+))?)*\s+|\b[A-Za-z_]\w*=\S*\s+)+$""")
# A launcher between the start of a command and the program it runs: an interpreter's `-m`
# (`python -m pip`, `$(PYTHON) -m pip`, `${{ matrix.python }} -I -m pip`), a container or an environment
# runner (`docker exec box apt-get`, `hatch env run -e test -- pip`, `poetry run pip`, `tox -e x -- pip`).
_LAUNCHER_TAIL_RE = re.compile(
    r"""(?:(?:\$\{\{[^}]*\}\}|\$\{[^}]*\}|\$\([^)]*\)|\{env\w*\}"""
    r"""|\S*?(?<![\w.-])(?:python|pypy|py)(?:[\d.]|\$\{[^}]*\})*(?:\.exe)?)"""
    r"""(?:\s+-(?![A-Za-z]*m\b)[A-Za-z0-9][\w.:]*(?:\s+(?!-)[^\s-]\S*)?)*\s+-[A-Za-z]*m"""
    r"""|\b(?:docker|podman|kubectl)\s+(?:compose\s+)?(?:exec|run)\b.*?"""
    r"""|\b(?:hatch|pdm|poetry|uv|pipenv|rye|pixi|conda|mamba)\b(?:\s+-\S+(?:\s+(?!-)\S+)?)*\s+(?:env\s+)?run\b.*?"""
    r"""|\b(?:tox|nox|multipass)\b.*?\s--"""
    # a settings-file runner: `dotenv -f prod.env run -- psql`, `dotenv -e .env -- node x.js`, `dotenvx run -- curl`
    r"""|\bdotenvx?\b(?:\s+-\S+(?:\s+(?!-)\S+)?)*(?:\s+run(?:\s+-(?!-\s)\S+(?:\s+(?!-)\S+)?)*)?(?:\s+--)?"""
    # a shell given its command as arguments: `powershell -Command Invoke-WebRequest ...`, `cmd /c curl ...`
    r"""|\b(?:powershell|pwsh)(?:\.exe)?(?:\s+-(?!c\b|command\b)\w+(?:\s+(?!-)\S+)?)*\s+-(?:c|command)"""
    r"""|\bcmd(?:\.exe)?(?:\s+/[a-z](?::\w+)?)*?\s+/[ck])\s+$""",
    re.IGNORECASE)


def _quote_regions(s: str) -> list:
    """(open, close) offsets of each top-level quoted string, read the way a shell reads quotes."""
    regions, k, n = [], 0, len(s)
    while k < n:
        ch = s[k]
        if ch == "\\":
            k += 2
            continue
        if ch in "'\"":
            j = k + 1
            while j < n and s[j] != ch:
                j += 2 if (s[j] == "\\" and ch == '"') else 1
            if j >= n:
                # never closed on this line: the line closes a string opened on an earlier one (`}' | gh api`),
                # or holds an apostrophe. Either way it marks no quoted region here.
                k += 1
                continue
            regions.append((k, j))
            k = j + 1
            continue
        k += 1
    return regions


_LOOKUP_ONLY_RE = re.compile(r"""(?:\bcommand\s+-[vV]|\bwhich|\btype(?:\s+-[a-zA-Z]+)?|\bhash|\bwhereis|\bwhere"""
                             r"""|\bGet-Command)\s+$""", re.IGNORECASE)
# A quote that opens code: after a shell's command flag (`sh -c '...'`, `pwsh -Command "..."`).
_CODE_QUOTE_FLAG_RE = re.compile(r"""(?:-\w*c|-command|-encodedcommand|/c|/k)\s*$""", re.IGNORECASE)


# A command prefix longer than this is not one: no wrapper, key or launcher chain runs to thousands of characters.
# Bounding it keeps one long line linear rather than quadratic.
_PREFIX_LIMIT = 2000
_LONG_PREFIX_RE = re.compile(
    r"""^\s*(?:(?:env|sudo|doas|exec|command|nohup|time|nice|timeout|stdbuf)(?:\s+-{1,2}[\w-]+(?:=\S*)?)*\s+"""
    r"""|[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S*)\s+|\d+(?:\.\d+)?[smhd]?\s+)+""")


@functools.lru_cache(maxsize=256)
def _line_layout(line: str, style: str) -> tuple:
    """For one line, computed once: its quote regions, and the ends of the places where a new command may start
    outside quotes (with the escape style of the file being read)."""
    regions = tuple(_quote_regions(line))
    masked = list(line)
    for qs, qe in regions:
        for k in range(qs + 1, min(qe, len(line))):
            if masked[k] != "\n":
                masked[k] = " "
    masked = _ESCAPED_PAIR_RE[style].sub("  ", "".join(masked))
    splits = tuple(m.end() for m in _COMMAND_START_SPLIT_RE.finditer(masked))
    joins = tuple((m.start(), m.end()) for m in _COMMAND_JOIN_RE.finditer(_ESCAPED_PAIR_RE[style].sub("  ", line)))
    return regions, splits, joins, tuple(s for s, _ in joins)


def _at_command_start(line: str, at: int, _depth: int = 0) -> bool:
    """True when the program matched at `at` stands where a command starts, so the line runs it.

    Inside quotes, only a quoted string that itself opens where a command starts (`run: "pip ..."`, the
    string handed to `sh -c`, an element of an argv list) is code, and it is judged as a command line of
    its own. Any other quoted string is an argument: a `|` in a `grep` pattern starts nothing.
    """
    # `command -v curl`, `which curl`, `type curl`, `hash curl`: the name is looked up, not run
    if _LOOKUP_ONLY_RE.search(line[max(0, at - 80):at]):
        return False
    regions, splits, _, _ = _line_layout(line, _ESCAPE_STYLE.get())
    # regions do not overlap and are in order: only the last one opening before `at` can hold it
    k = bisect.bisect_left(regions, (at, -1)) - 1
    for qs, qe in regions[k:k + 1] if k >= 0 else ():
        if qs < at < qe + (qe == len(line)):
            if _depth >= 4:
                return False
            if line[qs] == '"':
                # inside double quotes a command substitution still runs: `echo "$(curl -s https://...)"`
                subs = [m.start() for m in re.finditer(r"(?<!\\)(?:\$\(|`)", line[:at]) if m.start() > qs]
                sub = subs[-1] if subs else -1
                if sub > qs and not re.search(r"(?<!\\)" + (r"\)" if line[sub] == "$" else "`"), line[sub + 1:at]):
                    inner = sub + (2 if line[sub] == "$" else 1)
                    return _at_command_start(line[inner:qe], at - inner, _depth + 1)
            before = line[:qs]
            code = (_CODE_QUOTE_FLAG_RE.search(before) or re.search(r"""[\[,]\s*$""", before)
                    or _at_command_start(line[:qs] + "X", qs, _depth + 1))
            return bool(code) and _at_command_start(line[qs + 1:qe], at - qs - 1, _depth + 1)
    # outside quotes: what is inside a quoted string separates no commands
    idx = bisect.bisect_right(splits, at) - 1 if splits and splits[0] <= at else -1
    start = splits[idx] if idx >= 0 else 0
    # a command substitution that has closed before `at` (`env $(cat prod.env) gcloud ...`) belongs to the command it
    # stands in: that command starts where it started
    for _ in range(4):
        if start >= 2 and line[start - 2:start] == "$(" and ")" in line[start:at] \
                and line[start:at].count(")") > line[start:at].count("("):
            idx -= 1
            start = splits[idx] if idx >= 0 else 0
        else:
            break
    before = line[start:at]
    if len(before) > _PREFIX_LIMIT:
        # a long `VAR=value` prefix (a PYTHONPATH of many entries) is still a prefix, after `env` or `sudo` too: the
        # wrappers and assignments are set aside
        before = _LONG_PREFIX_RE.sub("", before)
        if len(before) > _PREFIX_LIMIT:
            return False
    if _COMMAND_PREFIX_RE.match(before):
        return True
    # a launcher's own words may look like a wrapper (`docker exec -i "$C" aws ...`: docker's `exec`, not the shell's),
    # so a launcher is looked for before the wrappers are set aside
    launcher = _LAUNCHER_TAIL_RE.search(before) if _depth < 3 else None
    wrappers = _WRAPPERS_TAIL_RE.search(before)
    if not launcher and wrappers:
        before = before[:wrappers.start()]
        launcher = _LAUNCHER_TAIL_RE.search(before) if _depth < 3 else None
    return bool(launcher) and _at_command_start(line, start + launcher.start(), _depth + 1)


def _first_command(s: str) -> str:
    """`s` up to its first separator that is not escaped."""
    m = _COMMAND_JOIN_RE.search(_mask_escapes(s))
    return s[:m.start()] if m else s


def _in_printed_part(line: str, at: int) -> bool:
    """True when position `at` lies in a part of a joined command line that only prints:
    `echo "Cisco SSH tests" && pytest ...` names SSH in text that is shown."""
    _, _, joins, join_starts = _line_layout(line, _ESCAPE_STYLE.get())
    k = bisect.bisect_left(join_starts, at)
    if k < len(joins):
        start = joins[k - 1][1] if k else 0
        return bool(_PRINTED_RE.match(line[start:joins[k][0]]))
    start = joins[-1][1] if joins else 0
    return start > 0 and bool(_PRINTED_RE.match(line[start:]))


# A Dockerfile instruction that runs or fetches, in any case, with any ONBUILD in front of it
_DOCKER_INSTR_RE = re.compile(
    r"(?i)^(?:onbuild\s+)?(?:healthcheck(?:\s+--\S+)*\s+(?=cmd\b))?(run|cmd|entrypoint|shell|add)(?=[\s\[])")
# A Dockerfile `ADD` whose source is an address (`ADD --chmod=644 https://host/f /dst`, `ADD ["https://h/f", "/d"]`)
_DOCKER_ADD_URL_RE = re.compile(r"""^ADD(?:\s+--\S+)*\s+(?:\[\s*)?["']?((?:https?|ftp|git)://\S+|git@\S+)""")
# `FROM [--platform=...] image [AS name]` and `COPY --from=image ...`
_DOCKER_FROM_RE = re.compile(r"""^(?:onbuild\s+)?FROM(?:\s+--\S+)*\s+(\S+)(?:\s+AS\s+(\S+))?\s*$""", re.IGNORECASE)
_DOCKER_COPY_FROM_RE = re.compile(r"""^(?:onbuild\s+)?COPY\b(?:\s+--(?!from=)\S+)*\s+--from=(\S+)""", re.IGNORECASE)
_DOCKER_MOUNT_FROM_RE = re.compile(r"""^(?:onbuild\s+)?RUN\b[^\n]*?\s--mount=\S*?\bfrom=([^,\s]+)""", re.IGNORECASE)
_DOCKER_EXEC_FORM_RE = re.compile(r"""^(?:onbuild\s+)?(?:RUN|CMD|ENTRYPOINT)\s+(\[.*\])\s*$""", re.IGNORECASE)


# `python -c '<code>'` on a script line: the quoted string is Python. Options may stand before `-c`
# (`python3 -W ignore -c`), but not `-m`, whose next word is a module and whose own `-c` is something else.
# an interpreter named by a variable: `$PYTHON`, `"${PYTHON:-python3}"`, make's `$(PYTHON)`, `$PY`
_VARIABLE_PYTHON = (r"""["']?\$(?:\{(?i:\w*python\w*|py[0-9]?|pyexe)(?:[:=?+-][^}"'\s]*)?\}"""
                   r"""|\((?i:\w*python\w*|py[0-9]?|pyexe)\)|(?i:\w*python\w*|py[0-9]?|pyexe)(?![\w(]))["']?""")
_VARIABLE_PYTHON_RE = re.compile(_VARIABLE_PYTHON)
_INLINE_PYTHON_RE = re.compile(
    r"""(?:^|(?<=[\s;&|(`]))(?:(?:[\w.~${}()/\\:-]{0,256}[\\/])?(?:python[0-9.]*w?|ipython[0-9]*|py|pypy[0-9]*)(?:\.exe)?"""
    # an interpreter in a quoted path (`"C:\Program Files\Python312\python.exe"`) or named by a variable
    r"""|(["'])[^"'\n]{0,256}[\\/](?:python[0-9.]*w?|pypy[0-9]*)(?:\.exe)?\1|""" + _VARIABLE_PYTHON + r""")"""
    # options before `-c`: letters (`-W ignore`, `-I`) or the Windows launcher's version (`py -3`, `py -3.12`, `-V:3.12`)
    r"""(?:\s+-(?![A-Za-z]*[mc](?![\w.:]))[A-Za-z0-9][\w.:]*(?:\s+(?![-"'])\S+)?)*\s+-[A-Za-z]*c(?:\s+|(?=["'$]))"""
    r"""(?=\S)""",
    re.IGNORECASE)
# `python3 <<< 'code'`: a here-string is the program's standard input
_HERESTRING_RE = re.compile(r"(?<!<)<<<[ \t]*")


# In a Makefile recipe `$(...)` is make's own (a variable or `$(shell pwd)`, expanded before the shell sees the line);
# the shell's command substitution is written `$$(...)`.
_MAKE_COMMAND_SUBSTITUTION_RE = re.compile(r"\$\$\(|`|\$\(shell\s")


_PYTHON_WRAPPERS = {"sudo", "doas", "env", "nice", "nohup", "time", "timeout", "stdbuf", "exec", "command", "builtin",
                    "uv", "poetry", "pipenv", "hatch", "pdm", "rye", "run"}
# options of the interpreter that take a value (`-W ignore`, `-X utf8`)
_PYTHON_VALUE_OPTIONS = {"-W", "-X", "-Q"}


_PYTHON_LAUNCHERS = {"uv", "poetry", "pipenv", "hatch", "pdm", "rye", "pixi", "conda", "mamba"}
# Options of `docker run`/`docker exec` (and their relatives) that take the next word as their value.
_CONTAINER_VALUE_FLAGS = {"-e", "--env", "-w", "--workdir", "-u", "--user", "--name", "-v", "--volume", "--network",
                          "--net", "--entrypoint", "-p", "--publish", "--env-file", "--platform", "--mount", "-l",
                          "--label", "-c", "--container", "-n", "--namespace", "--cpus", "-m", "--memory",
                          "--hostname", "-h", "--add-host", "--gpus", "--device", "--pull", "--restart", "--ulimit",
                          "--shm-size", "--ipc", "--pid", "--security-opt", "--cap-add", "--cap-drop", "--tmpfs",
                          "--log-driver", "--dns", "--runtime", "--cidfile", "--group-add", "--detach-keys",
                          "--context", "--kubeconfig", "-f", "--filename"}
_REDIRECTION_RE = re.compile(r"\d*(?:[<>]{1,2}|&>>?|>\|)&?")


def _drop_redirections(words: list[str]) -> list[str]:
    """The words of a command with its redirections taken out (`>/dev/null`, `2>&1`, `< in.txt`): they may stand
    anywhere, before the program included."""
    out, k = [], 0
    while k < len(words):
        w = words[k]
        m = _REDIRECTION_RE.match(w)
        if m and not w.startswith("<<"):
            k += 1 if m.end() < len(w) else 2       # `>file` holds its target; `> file` takes the next word
            continue
        out.append(w)
        k += 1
    return out


def _python_takes_stdin(words: list[str]) -> bool:
    """The command is an interpreter that runs what it reads on standard input: given no script, or `-` or
    `/dev/stdin` as its script (`python3 - "$URL"`: what follows is the program's own argv). `python3 tool.py`
    reads its input as data, and `docker run -i python bash`, `sh -s python` and `bash ./python` run another
    program. Wrappers (`sudo -u app`, `env`, `timeout 10`) and launchers (`uv run --with httpx`) may stand first."""
    words = _drop_redirections(words)
    if len(words) > 2 and _argv_basename(words[0]) in ("docker", "podman", "kubectl", "oc") and words[1] in ("exec", "run"):
        # `docker exec -i app python -`, `kubectl exec -i pod -- python -`: the command after the container runs
        if "--" in words:
            return _python_takes_stdin(words[words.index("--") + 1:])
        k = 2
        while k < len(words) and words[k].startswith("-"):
            k += 2 if words[k] in _CONTAINER_VALUE_FLAGS else 1
        return _python_takes_stdin(words[k + 1:])
    k = 0
    launcher = bool(words) and words[0] in _PYTHON_LAUNCHERS
    while k < len(words) and not (_PYTHON_EXE_RE.match(_argv_basename(words[k].strip("'\"")))
                                  or _VARIABLE_PYTHON_RE.fullmatch(words[k])):
        w = words[k]
        if not (launcher or w in _PYTHON_WRAPPERS or w.startswith("-") or re.fullmatch(r"[A-Za-z_]\w*=\S*|\d+[smh]?", w)
                or (k and words[k - 1] in ("-u", "-g", "-n", "-s", "-k", "-C"))):
            return False                # a program other than a wrapper stands before the interpreter
        k += 1
    if k == len(words):
        return False
    rest = words[k + 1:]
    j = 0
    while j < len(rest):
        w = rest[j].strip("'\"")
        if w in ("-", "/dev/stdin", "/dev/fd/0"):
            return True                 # the script is standard input; what follows is its argv
        if w in _PYTHON_VALUE_OPTIONS:
            j += 2
        elif w == "--" or (w.startswith("-") and not w.startswith(("-c", "-m"))):
            j += 1
        else:
            return False                # a script, `-c` code or `-m` module: standard input is its data
    return True


def _python_reads_heredoc(line: str, doc: re.Match) -> bool:
    """The interpreter is the program the here-document is handed to: the command that holds `<<`
    (`python3 - <<EOF`, `sudo python3 <<EOF`), or the first program of the pipe after it (`cat <<EOF | python3`).
    `bash <<EOF && python3 -V` hands it to bash; `docker run -i python bash <<EOF` hands it to bash."""
    before = _mask_escapes(line[:doc.start()])
    if re.search(r"""(?:^|[\s;&|(`])\S*?(?:python[0-9.]*|pypy[0-9]*)(?:\.exe)?(?:\s+-\S+)*?\s+-[A-Za-z]*c\s*"?\$\(\s*cat\s*$""",
                 before):
        return True                     # `python3 -c "$(cat <<'EOF' ... EOF)"`: the here-document is the code
    # the command the here-document belongs to starts after a join, a pipe, `$(`, a backquote or `(`; a shell keyword
    # (`until`, `while !`, `if`) or a path to a wrapper may stand in front of it
    receiver = re.split(r"&&|\|\||;|\||&|\$\(|`|\(", before)[-1]
    receiver = re.sub(r"^\s*(?:(?:until|while|if|elif|then|do|else|!|time|exec|\{)\s+)+", "", receiver)
    receiver = re.sub(r"^\s*(?:/usr)?/s?bin/(?=env\b|sudo\b)", "", receiver)
    # a Dockerfile's `RUN python3 <<EOF` (or a test helper's `run python3 <<EOF`): RUN and its flags run the rest
    receiver = re.sub(r"(?i)^\s*(?:onbuild\s+)?run(?:\s+--\S+)*\s+", "", receiver)
    # a redirection may come first: `<<EOF python3` hands the body to the program named after it
    rest_of_command = re.match(r"[^|;&]*", line[doc.end():]).group(0)
    if _python_takes_stdin(receiver.split() + [w for w in rest_of_command.split() if not w.startswith("<<")]):
        return True
    after = re.match(r"[^|;&]*\|(?!\|)([^|;&]*)", line[doc.end():])
    return bool(after) and _python_takes_stdin(after.group(1).split())


def _has_substitution(text: str, makefile: bool = False) -> bool:
    """The shell runs a command inside `text` (a double-quoted string, a line of an unquoted here-document) before
    the program sees it: `$(...)` or a backquote not escaped. An escaped backslash (`\\\\$(`) escapes only itself.
    In a Makefile recipe `$(...)` is make's own; the shell's is `$$(...)`."""
    masked = re.sub(r"\\.", "  ", text, flags=re.S)
    return bool((_MAKE_COMMAND_SUBSTITUTION_RE if makefile else _PLAIN_SUBSTITUTION_RE).search(masked))


_PLAIN_SUBSTITUTION_RE = re.compile(r"\$\(|`")


_ANSI_C_ESCAPE_RE = re.compile(r"\\(?:x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|.)", re.S)
_ANSI_C_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b",
                  "E": "\x1b", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c_char(escape: str) -> str:
    """One `$'...'` escape as the character bash makes of it."""
    body = escape[1:]
    try:
        if body[:1] in "xuU" and len(body) > 1:
            return chr(int(body[1:], 16))
        if body.isdigit():
            return chr(int(body, 8))
    except ValueError:
        return ""                           # beyond Unicode: bash writes nothing for it
    return _ANSI_C_SIMPLE.get(body, escape)


def _shell_word(line: str, i: int, makefile: bool = False) -> tuple[int, str, bool] | None:
    """The shell word starting at `i`, the way the shell hands it to a program: quotes removed, escapes undone,
    adjacent pieces joined (`'a'\\''b'` is `a'b`). Returns (end, text, expands): `expands` when the shell runs a
    command inside it first. None when a quote is not closed on this line."""
    out: list[str] = []
    expands, n = False, len(line)
    # a backquote ends the word: outside quotes it opens or closes a command substitution around it
    while i < n and not line[i].isspace() and line[i] not in ";|&<>()`":
        c = line[i]
        if c == "$" and line.startswith('$"', i):
            i += 1                              # bash's locale quoting: `$"..."` is a double-quoted string
            continue
        if c == "$" and line.startswith("$'", i):
            # ANSI-C quoting: `$'import os\nos.system(...)'`, backslash escapes decoded
            j, buf = i + 2, []
            while j < n and line[j] != "'":
                if line[j] == "\\" and j + 1 < n:
                    m = _ANSI_C_ESCAPE_RE.match(line, j)
                    if m:
                        buf.append(_ansi_c_char(m.group(0)))
                        j = m.end()
                        continue
                buf.append(line[j])
                j += 1
            if j >= n:
                return None
            out.append("".join(buf))
            i = j + 1
            continue
        if c == "'":
            j = line.find("'", i + 1)
            if j < 0:
                return None
            out.append(line[i + 1:j])
            i = j + 1
        elif c == '"':
            j, buf = i + 1, []
            while j < n and line[j] != '"':
                if line[j] == "\\" and j + 1 < n:
                    if line[j + 1] in '\\"$`':
                        buf.append(line[j + 1])
                        j += 2
                        continue
                    buf.append("\\")
                    j += 1
                    continue
                buf.append(line[j])
                j += 1
            if j >= n:
                return None
            expands = expands or _has_substitution(line[i + 1:j], makefile)
            out.append("".join(buf))
            i = j + 1
        elif c == "\\" and i + 1 < n:
            out.append(line[i + 1])
            i += 2
        else:
            if line.startswith("$(", i):
                expands = True
            out.append(c)
            i += 1
    return i, "".join(out), expands


def _inline_python(line: str, makefile: bool = False) -> list[tuple[int, int, str]]:
    """(first character, last character, code) of each `python -c` word on a script line, the code as the shell hands
    it to Python. A word in which the shell runs a command first is left to the script rules."""
    out = []
    for m in _INLINE_PYTHON_RE.finditer(line):
        # only where a command starts and the line does not just print it (`echo python -c "..."`)
        if not _at_command_start(line, m.start()) or _PRINTED_RE.match(line) or _in_printed_part(line, m.start()):
            continue
        word = _shell_word(line, m.end(), makefile)
        if word is None:
            continue
        out.append((m.end(), word[0] - 1, word[1], word[2]))
    # `echo 'import socket' | python3`, `printf '%s\n' 'import x' 'x.f()' | python3 -`: the printed text is the program
    for m in _PRINT_INTO_RE.finditer(line) if "|" in line else ():
        if not _at_command_start(line, m.start()):
            continue
        words, end = _command_words_to(line, m.end())
        rest = line[end:].lstrip()
        if not rest.startswith("|") or rest.startswith("||"):
            continue
        receiver = re.split(r"[;&|)]", rest[1:], maxsplit=1)[0]
        if not _python_takes_stdin(receiver.split()) or _ARGV_HOLE in words:
            continue
        code = _printed_text(m.group(1), words)
        if code is not None:
            out.append((m.end(), end - 1, code, False, f"piped into Python by `{m.group(1)}`"))
    seps = [s.end() for s in re.finditer(r"[|&;(`]", line)] if "<<<" in line else []
    for m in _HERESTRING_RE.finditer(line):
        # the command the here-string is given to: from the join or pipe before it
        k = bisect.bisect_right(seps, m.start()) - 1
        start = seps[k] if k >= 0 else 0
        if m.start() - start > _PREFIX_LIMIT:
            continue
        receiver = line[start:m.start()]
        lead = len(receiver) - len(receiver.lstrip())
        if not (receiver.strip() and _python_takes_stdin(receiver.split())
                and _at_command_start(line, start + lead) and not _in_printed_part(line, m.start())):
            continue
        word = _shell_word(line, m.end(), makefile)
        if word is not None:
            out.append((m.end(), word[0] - 1, word[1], word[2], "given by a here-string (`<<<`)"))
    return out


# `node -e <code>`, `node --print <code>`, `bun -e <code>`, `deno eval <code>`: JavaScript handed over on the line
_INLINE_JS_RE = re.compile(
    r"""(?:^|(?<=[\s;&|(`]))(?:(?:[\w.~${}()/\\:-]{0,256}[\\/])?(?:(node(?:js)?|bun)(?:\.exe)?"""
    r"""(?:\s+--?(?!e\b|eval\b|p\b|print\b)[\w-]+(?:=\S+)?)*\s+(?:-e|--eval|-p|--print)(?:\s+|=(?=\S))"""
    r"""|(deno)(?:\.exe)?\s+eval(?:\s+--?[\w-]+(?:=\S+)?)*\s+))(?=\S)""")


def _inline_javascript(line: str, makefile: bool = False) -> list[tuple[int, int, str, str]]:
    """(first character, last character, code, program) of each `node -e` / `bun -e` / `deno eval` word on a script
    line, where a command starts and the line does not just print it. A word the shell runs a command inside first is
    left to the script rules."""
    out = []
    if "node" not in line and "bun" not in line and "deno" not in line:
        return out
    for m in _INLINE_JS_RE.finditer(line):
        if not _at_command_start(line, m.start()) or _PRINTED_RE.match(line) or _in_printed_part(line, m.start()):
            continue
        word = _shell_word(line, m.end(), makefile)
        if word is None or word[2]:
            continue
        program = f"{m.group(1)} -e" if m.group(1) else "deno eval"
        out.append((m.end(), word[0] - 1, word[1], program))
    return out


# how many lines a quoted `python -c` program may run to
_MULTILINE_PYTHON_LIMIT = 400


def _multiline_inline_python(lines: list[str], i: int, makefile: bool = False
                             ) -> tuple[int, str, str, bool] | None:
    """A `python -c` whose quoted program opens on line `i` and closes on a later line:
    (index of the closing line, the program as Python reads it, line `i` with the program replaced by an empty word
    and the rest of the closing line after it, whether the shell runs a command inside it first). None otherwise."""
    raw = lines[i]
    if "-" not in raw:
        return None
    line = raw.strip()
    for m in _INLINE_PYTHON_RE.finditer(line):
        if not _at_command_start(line, m.start()) or _PRINTED_RE.match(line) or _in_printed_part(line, m.start()):
            continue
        if _shell_word(line, m.end(), makefile) is not None:
            continue                            # the program closes on this line: read with the line
        text = "\n".join([line] + lines[i + 1:i + _MULTILINE_PYTHON_LIMIT])
        word = _shell_word(text, m.end(), makefile)
        if word is None or word[0] <= len(line):
            continue
        end = i + text.count("\n", 0, word[0])
        tail = text[word[0]:text.find("\n", word[0]) if "\n" in text[word[0]:] else len(text)]
        return end, textwrap.dedent(word[1]), line[:m.end()] + "''" + tail, word[2]
    return None


_TRAILING_PUNCT_RE = re.compile(r"""[ \t"'`;|&)]*""")


def _terminator_after(line_at: dict, end: str, i: int) -> bool:
    """Is there a line reading exactly `end` at index `i` or later? (One lookup, not a scan of the rest of the file.)"""
    at = line_at.get(end)
    return bool(at) and at[-1] >= i


# A program written in quotes where a command starts (`& "C:\Program Files\Git\bin\git.exe" pull`, `& 'pip' install`,
# `"C:\tools\curl.exe" -s ...`), and a Windows program suffix (`git.exe`, `npm.cmd`) outside quotes.
_QUOTED_PROGRAM_RE = re.compile(
    r"""(?:^|(?<=[;|(&])|(?<=\bcall)|(?<=\bstart))(\s*(?:&\s*)?)(["'])((?:[^"'\n]*[\\/])?)([\w+-][\w.+-]*?)"""
    r"""((?:\.(?:exe|cmd|bat|com))?)\2(?=\s|$)""", re.IGNORECASE)
_PROGRAM_SUFFIX_RE = re.compile(r"""(?<=[\w+-])\.(?:exe|cmd|bat|com)(?=\s|$)""", re.IGNORECASE)


# a program named by a variable with a default: `${CURL:-curl}`, `"${GIT:=git}"` (the default is group 4)
_DEFAULT_PROGRAM_RE = re.compile(
    r"""(^|[;&|(]\s*|\s)(["']?)(\$\{[A-Za-z_]\w*:?[-=])((?:[\w.~+-]*/)*[A-Za-z][\w.+-]*)(\})(\2)(?=[\s;&|)]|$)""")


# PowerShell's `Start-Process` (and its alias `saps`): its program and its arguments are found by the parameters'
# names, as PowerShell binds them (`-FilePath` or the first positional, `-ArgumentList` or the second). Its own
# parameters and the common ones, each a switch or one that takes a value, by full name and alias; a name is also
# any prefix that only one of them starts with.
_START_PROCESS_RE = re.compile(r"(?<![\w-])(?:start-process|saps)(?![\w-])", re.IGNORECASE)
_START_PROCESS_PARAMS = {
    "filepath": "value", "argumentlist": "value", "credential": "value", "workingdirectory": "value",
    "loaduserprofile": "switch", "nonewwindow": "switch", "passthru": "switch", "redirectstandarderror": "value",
    "redirectstandardinput": "value", "redirectstandardoutput": "value", "verb": "value", "windowstyle": "value",
    "wait": "switch", "usenewenvironment": "switch", "environment": "value",
    "verbose": "switch", "debug": "switch", "erroraction": "value", "warningaction": "value",
    "informationaction": "value", "progressaction": "value", "errorvariable": "value", "warningvariable": "value",
    "informationvariable": "value", "outvariable": "value", "outbuffer": "value", "pipelinevariable": "value",
    "whatif": "switch", "confirm": "switch"}
_START_PROCESS_ALIASES = {
    "pspath": "filepath", "path": "filepath", "args": "argumentlist", "runas": "credential", "lup": "loaduserprofile",
    "nnw": "nonewwindow", "rse": "redirectstandarderror", "rsi": "redirectstandardinput",
    "rso": "redirectstandardoutput", "vb": "verbose", "db": "debug", "ea": "erroraction", "wa": "warningaction",
    "infa": "informationaction", "proga": "progressaction", "ev": "errorvariable", "wv": "warningvariable",
    "iv": "informationvariable", "ov": "outvariable", "ob": "outbuffer", "pv": "pipelinevariable", "wi": "whatif",
    "cf": "confirm"}
_PS_TOKEN_RE = re.compile(r"""@?\((?:[^()'"]|'[^']*'|"[^"]*")*\)|@\{(?:[^{}'"]|'[^']*'|"[^"]*")*\}|'[^']*'|"[^"]*"|,"""
                          r"""|[^\s,'"(){}]+""")


def _start_process_param(name: str) -> str | None:
    """The `Start-Process` parameter a name binds to (`-F` is `-FilePath`, `-Args` is `-ArgumentList`); None when no
    parameter, or more than one, has that name."""
    if name in _START_PROCESS_PARAMS:
        return name
    if name in _START_PROCESS_ALIASES:
        return _START_PROCESS_ALIASES[name]
    hits = [p for p in _START_PROCESS_PARAMS if p.startswith(name)]
    return hits[0] if len(hits) == 1 else None


def _start_process_view(line: str) -> str:
    """`line` with each `Start-Process` command read as the command it starts (`Start-Process -FilePath "git.exe"
    -Wait -ArgumentList 'pull'` as `git pull`), padded to its length so that positions in the line still hold. A
    command this cannot take apart is left as it is."""
    out, pos = [], 0
    for m in _START_PROCESS_RE.finditer(line):
        if m.start() < pos:
            continue
        end = len(line)
        quote, depth = None, 0
        for k in range(m.end(), len(line)):
            c = line[k]
            if quote:
                quote = None if c == quote else quote
            elif c in "'\"":
                quote = c
            elif c in "({":
                depth += 1
            elif c in ")}":
                depth -= 1
            elif c in ";|" and depth <= 0:
                end = k
                break
        tokens = [t for t in _PS_TOKEN_RE.findall(line[m.end():end])]
        program, args, positional, k = None, [], [], 0

        def value_list(k: int) -> tuple[list, int]:
            # one value, or several joined by commas: `"install","requests"`, `@('a', 'b')`, `("pull")`
            items = []
            while k < len(tokens):
                items.append(tokens[k])
                if k + 1 < len(tokens) and tokens[k + 1] == ",":
                    k += 2
                    continue
                return items, k + 1
            return items, k
        unread = False
        while k < len(tokens):
            t = tokens[k]
            if t.startswith("-") and len(t) > 1 and t[1:].split(":", 1)[0].replace("_", "").isalpha():
                # `-Name value`, or `-Name:value` with the value in the same word
                name, colon, inline = t[1:].partition(":")
                param = _start_process_param(name.lower())
                if param is None:
                    unread = True       # a parameter Start-Process does not have, or a name more than one starts
                    break
                if _START_PROCESS_PARAMS[param] == "switch":
                    k += 1              # `-Wait`, `-Verbose:$true`
                    continue
                if colon:
                    tokens[k] = inline
                else:
                    k += 1
                if param == "filepath":
                    program, k = (tokens[k] if k < len(tokens) else None), k + 1
                elif param == "argumentlist":
                    args, k = value_list(k)
                else:
                    k += 1              # a parameter with a value (`-WorkingDirectory C:\repo`, `-Environment @{...}`)
                continue
            if t == ",":
                k += 1
                continue
            items, k = value_list(k)
            positional.append(items)
        if unread:
            continue
        if program is None and positional:
            program = positional.pop(0)[0]
        if not args and positional:
            args = positional.pop(0)
        if program is None or program.startswith("$") or "://" in program:
            continue            # (`Start-Process "https://..."` opens an address: the line is read as written)
        name = program.strip("'\"").replace("\\", "/").rsplit("/", 1)[-1]
        name = re.sub(r"(?i)\.(?:exe|cmd|bat|com)$", "", name)
        words = []
        for item in args:
            item = item.strip()
            if item.startswith(("@(", "(")):
                item = item[item.index("(") + 1:-1]
            words += [w.strip("'\"") for w in re.findall(r"""'[^']*'|"[^"]*"|[^\s,'"]+""", item)]
        words = [w for part in words for w in part.split()]
        text = " ".join([name] + words)
        span = end - m.start()
        if len(text) > span or not name:
            continue
        out.append(line[pos:m.start()] + text + " " * (span - len(text)))
        pos = end
    out.append(line[pos:])
    return "".join(out)


# Programs whose own options may stand before their subcommand (`npm --prefix web ci`, `terraform -chdir=infra init`,
# `apt-get -o Acquire::Retries=3 update`, `pip --trusted-host h install x`)
_OPTION_FIRST_PROGRAMS = {
    "npm", "yarn", "pnpm", "bun", "uv", "pip", "pip3", "pipx", "gem", "go", "bundle", "bundler", "composer", "dotnet",
    "brew", "terraform", "tofu", "apt", "apt-get", "aptitude", "yum", "dnf", "microdnf", "tdnf", "apk", "zypper",
    "conda", "mamba", "micromamba", "poetry", "pdm", "pipenv", "hatch", "pixi", "cargo", "deno", "corepack", "helm",
    "mvn", "mvnw", "gradle", "gradlew", "nuget", "flutter", "dart", "pod", "swift", "mix", "bazel", "bazelisk", "cabal",
    "stack", "opam", "luarocks", "vcpkg", "conan", "rustup", "nix", "flatpak", "snap", "git", "hg", "svn", "docker",
    "podman", "kubectl", "aws", "gcloud", "az", "gsutil", "rclone",
}
# of those, the ones judged by rules that read their own options (`docker -H tcp://h ps` names a daemon elsewhere,
# `git -C dir pull`): only a variable between the program and its subcommand is set aside for them
_OPTION_READING_PROGRAMS = {"git", "hg", "svn", "docker", "podman", "kubectl", "helm", "aws", "gcloud", "az", "gsutil",
                            "rclone"}
# Words that are a subcommand where they follow such an option, never its value
_SUBCOMMAND_WORDS = {
    "install", "i", "ci", "add", "update", "up", "upgrade", "sync", "lock", "fetch", "init", "restore", "build", "test",
    "run", "get", "download", "pull", "push", "clone", "plan", "apply", "destroy", "import", "refresh", "exec", "x",
    "dlx", "create", "mod", "cache", "outdated", "view", "audit", "info", "search", "require", "source", "build-dep",
    "dist-upgrade", "full-upgrade", "makecache", "check-update", "reinstall", "remote", "submodule", "lfs", "ls-remote",
    "env", "self", "global", "compose", "login", "s3", "storage", "cp", "copy", "deps", "vendor", "pack", "publish",
    "provision", "providers", "workload", "tool", "new", "upload", "send", "packages", "bundle", "repo", "toolchain",
    "target", "component", "profile", "develop", "shell", "flake", "image", "container", "pod", "deploy", "pip",
    "python", "tool", "venv",
}
# one-letter options of these programs that take a value (`go -C dir`, `hatch -e env`, `apt-get -o opt`, `pnpm -C dir`,
# `cargo -Z unstable-options`)
_VALUE_LETTERS = set("CEHZcdefopruw")
# Options that keep a command on this machine, kept so the rules that read them still do
_LOCAL_OPTION_RE = re.compile(r"(?i)offline|no-index|no-deps|find-links|index|no-build-isolation|frozen|locked|no-sync"
                              r"|no-network|no-download|cache-only|no-install")
_OPTION_PROGRAM_RE = re.compile(r"(?<![\w.\-$])(?:[\w.~${}()-]{0,256}/)?([\w.+-]+?)(?:\.exe)?(?=[ \t]+(?:-|\$|\"\$))")
_OPTION_TOKEN_RE = re.compile(
    r"""[ \t]+(\$\{\{[^}\n]*\}\}|"\$\{?\w+\}?"|\$\((?:[^()\n]|\([^()\n]*\))*\)|\$\{\w+\}|\$\w+|[^\s;&|]+)""")


def _blank_leading_options(line: str) -> str:
    """`line` with the options and variables written between a program and its subcommand set to spaces (`npm --prefix
    web ci` read as `npm ... ci`, `pip $PIPFLAGS install x` as `pip ... install x`), the length unchanged. An option
    without `=` takes the next word as its value unless that word is a subcommand; an option that keeps the command
    on this machine (`--offline`, `--no-index`) is kept."""
    out = list(line)
    changed = False
    for m in _OPTION_PROGRAM_RE.finditer(line):
        if m.group(1).lower() not in _OPTION_FIRST_PROGRAMS:
            continue
        variables_only = m.group(1).lower() in _OPTION_READING_PROGRAMS
        pos, blank, steps = m.end(), [], 0
        while steps < 24:
            steps += 1
            t = _OPTION_TOKEN_RE.match(line, pos)
            if not t:
                break
            word = t.group(1)
            if word.startswith(("$", '"$')):
                blank.append((t.start(1), t.end(1)))
            elif word.startswith("-") and len(word) > 1 and word != "--":
                if _LOCAL_OPTION_RE.search(word) or variables_only:
                    break
                blank.append((t.start(1), t.end(1)))
                if "=" not in word:
                    nxt = _OPTION_TOKEN_RE.match(line, t.end())
                    # a one-letter option takes a value when it is one of the letters that conventionally do
                    # (`-C dir`, `-e env`, `-o opt`; `-q` and `-v` are switches), a long one unless a subcommand follows
                    short = re.fullmatch(r"-[A-Za-z]", word)
                    takes = (word[1] in _VALUE_LETTERS) if short else (
                        nxt is not None and nxt.group(1).lower() not in _SUBCOMMAND_WORDS)
                    if nxt and takes and not nxt.group(1).startswith(("-", "$", '"$')):
                        blank.append((nxt.start(1), nxt.end(1)))
                        pos = nxt.end()
                        continue
            else:
                break
            pos = t.end()
        if blank and _OPTION_TOKEN_RE.match(line, pos):
            for a, b in blank:
                out[a:b] = " " * (b - a)
            changed = True
    return "".join(out) if changed else line


def _normalize_programs(line: str) -> str:
    """`line` with each program written as a quoted path, or with a Windows suffix, written as its bare name; every
    other character kept and the length unchanged, so positions in the line still hold. A program named by a variable
    with a default (`${CURL:-curl} -fsSL ...`) is read as that default, which is what runs when the variable is unset,
    and PowerShell's `Start-Process git -ArgumentList 'pull'` as the command it starts, `git pull`."""
    if _START_PROCESS_RE.search(line):
        line = _start_process_view(line)
    if " -" in line or "$" in line or "\t-" in line:
        line = _blank_leading_options(line)
    style = _ESCAPE_STYLE.get()
    if style == "batch" and re.match(r"(?i)\s*for\s", line):
        # `for %%f in (a b) do git -C %%f pull`: the body after `do` is a command
        line = re.sub(r"""(?i)^(\s*for\s+(?:/\w(?:\s+"[^"]*")?\s+)*%%?\w\s+in\s+\([^)]*\)\s+do\s+)""",
                      lambda f: " " * len(f.group(1)), line)
    elif style == "powershell" and "param" in line.lower():
        # `function Up { param($d) git -C $d pull }`: a parameter block is not a command
        line = re.sub(r"(?i)(?<=\{)(\s*param\s*\([^()]*\))", lambda f: " " * len(f.group(1)), line)
    if "${" in line:
        def default(m: re.Match) -> str:
            before = line[:m.start(2)].rstrip()
            if before and before[-1] not in ";&|(" and not re.search(
                    r"(?:^|[\s;&|(])(?:sudo|env|exec|time|nohup|command|xargs|timeout\s+\S+)$", before):
                return m.group(0)
            return m.group(1) + " " * (len(m.group(2)) + len(m.group(3))) + m.group(4) + " " * (len(m.group(5)) + len(m.group(6)))
        line = _DEFAULT_PROGRAM_RE.sub(default, line)
    if "." not in line and '"' not in line and "'" not in line:
        return line

    def quoted(m: re.Match) -> str:
        return m.group(1) + " " * (1 + len(m.group(3))) + m.group(4) + " " * (len(m.group(5)) + 1)
    line = _QUOTED_PROGRAM_RE.sub(quoted, line)
    regions = _quote_regions(line)

    def suffix(m: re.Match) -> str:
        # only the program's own name (`git.exe pull`, `cmd /c npm.cmd ci`): `ping example.com` names a host
        word_start = max(line.rfind(c, 0, m.start()) for c in " \t;&|(") + 1
        before = line[:word_start].rstrip()
        program = not before or before[-1] in ";&|(" or re.search(r"(?:^|[\s;&|(])(?:call|start|cmd\s+/[ck]|sudo|"
                                                                   r"env|exec|time|nohup|&)$", before, re.I)
        if any(qs < m.start() < qe for qs, qe in regions) or not program or "://" in line[word_start:m.start()]:
            return m.group(0)           # (`start https://example.com`: the end of an address, not a suffix)
        return " " * len(m.group(0))
    return _PROGRAM_SUFFIX_RE.sub(suffix, line)


def _command_around(line: str, at: int) -> tuple[int, int]:
    """(start, end) of the command holding position `at`: from the join before it (`&&`, `||`, `;`, `&`) to the
    join after it. A pipe joins programs into one command, so a pipeline is one piece."""
    _, _, joins, join_starts = _line_layout(line, _ESCAPE_STYLE.get())
    k = bisect.bisect_left(join_starts, at)
    start = joins[k - 1][1] if k else 0
    end = joins[k][0] if k < len(joins) else len(line)
    return start, end


# A Dockerfile `RUN` with nothing but its flags before a here-document: the body is the program run
_DOCKER_RUN_ONLY_RE = re.compile(r"\s*(?:onbuild\s+)?run(?:\s+--\S+)*\s*", re.IGNORECASE)
_PYTHON_SHEBANG_RE = re.compile(r"#!\s*(?:\S*/)?(?:env\s+(?:-\S+\s+)*)?(?:python|pypy)[\d.]*\b")
# a pipeline's `shell:` setting, and whether it names Python (`python`, `python3 -u {0}`)
_YAML_SHELL_RE = re.compile(r"""^\s*(?:-\s+)?shell\s*:\s*['"]?([^'"#\n]*?)['"]?\s*(?:#.*)?$""")
_YAML_SHELL_IS_PYTHON_RE = re.compile(r"(?:\S*/)?(?:python|pypy)[\d.]*(?:\s+-\S+)*(?:\s+\{0\})?")
# a `run:` key with a block (`run: |`) or a value on the same line
_YAML_RUN_LINE_RE = re.compile(r"""^(\s*(?:-\s+)?)run\s*:\s*(?:([|>][-+0-9]*)\s*(?:#.*)?|(\S.*?))\s*$""")


_JENKINS_DOCKER_IMAGE_RE = re.compile(r"""\bdocker\.image\(\s*['"]([^'"\s]+)['"]\s*\)\.(?:inside|pull|withRun|run)\b""")
# A Jenkins pipeline step that runs its one-line string: `sh 'curl ...'`, `bat "..."`, `powershell(script: '...')`
_JENKINS_STEP_RE = re.compile(r"""^(\s*)(?:sh|bat|powershell|pwsh)\s*\(?\s*(?:script\s*:\s*)?(['"])(?!\2\2)(.*?)(?<!\\)\2"""
                              r"""\s*\)?\s*(?=$|//)""")
# A step anywhere on a line (`steps { sh 'make' }`, `sh label: 'build', script: 'curl ...'`): its string is the command
_JENKINS_STEP_ANY_RE = re.compile(
    r"""(?:^|[{;(]|\s)(?:sh|bat|powershell|pwsh)\s*\(?\s*"""
    r"""(?:(?:label|encoding|returnStdout|returnStatus)\s*:\s*(?:(['"])[^'"\n]*\1|\w+)\s*,\s*)*"""
    r"""(?:script\s*:\s*)?(['"])(?!\2\2)(.*?)(?<!\\)\2""")


# Groovy in a Jenkinsfile that sends a request: the HTTP Request plugin's step (group 1), or an address read
# (`new URL(u).text`, `u.toURL().openStream()`)
_JENKINS_GROOVY_NET_RE = re.compile(
    r"""(?:^|[\s{;(=])(httpRequest)\b\s*[(\s'"]"""
    # (group 2) a checkout from the job's repository: `checkout scm`, `checkout([...])`, `git url: '...'`, `git '...'`
    r"""|(?:^|[\s{;(=])((?:checkout)\s*(?:\(|\[|scm\b)|git\s*(?:\(|\s)\s*(?:url\s*:|branch\s*:|credentialsId\s*:|['"]))"""
    r"""|(?:\bnew\s+URL\s*\([^()\n]*(?:\([^()\n]*\)[^()\n]*)*\)|\.toURL\s*\(\s*\))\s*\.\s*"""
    r"""(?:text|getText|bytes|getBytes|openConnection|openStream|newReader|withReader|newInputStream|withInputStream|eachLine)\b""")


# a flow map's keys before its `run:` or `script:` (group 1 ends where the key starts; group 2 is the key and `:`)
_FLOW_MAP_RUN_RE = re.compile(r"""\{((?:[^{}'"]|'[^'\n]*'|"[^"\n]*")*?,\s*)((?:run|script)\s*:)""")
# CircleCI's `- run: { name: fetch, command: "curl ..." }`: the step's command, inside the map a `run:` key takes
_RUN_MAP_COMMAND_RE = re.compile(r"""(\brun\s*:\s*)(\{(?:[^{}'"]|'[^'\n]*'|"[^"\n]*")*?(?:,\s*|(?<=\{)\s*))(command\s*:)""")
# a list of commands written as a flow sequence on one line (`script: [npm ci, git fetch origin]`)
_FLOW_COMMANDS_RE = re.compile(
    r"""^(\s*(?:-\s+)?(?:script|before_script|after_script|commands|cmds|install|before_install|after_success)\s*:\s*)"""
    r"""\[((?:[^\[\]'"]|'[^'\n]*'|"[^"\n]*")*)\]\s*$""")


def _flow_commands_line(line: str) -> str:
    """A flow sequence of commands written as the commands one after another (`script: [a, b]` as `script:  a; b `),
    the length kept: brackets and the quotes around a whole item become spaces, the commas between items `;`."""
    m = _FLOW_COMMANDS_RE.match(line)
    if not m:
        return line
    body = list(m.group(2))
    quote, item = None, 0
    for k, c in enumerate(body + [","]):
        if quote:
            quote = None if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c == ",":
            text = "".join(body[item:k])
            a = len(text) - len(text.lstrip())
            b = len(text.rstrip())
            if b - a >= 2 and text[a] in "'\"" and text[b - 1] == text[a]:
                body[item + a] = body[item + b - 1] = " "
            if k < len(body):
                body[k] = ";"
            item = k + 1
    return m.group(1) + " " + "".join(body) + " " + line[m.end(2) + 1:]


def _jenkins_step_line(line: str) -> str:
    """A Jenkinsfile line as the commands its steps run: the line's indentation and each step's string, joined as one
    command line (`sh 'a'; sh 'b'` runs both). A line with no step is left as it is."""
    m = _JENKINS_STEP_RE.match(line)
    if m:
        return m.group(1) + m.group(3)
    steps = [s.group(3) for s in _JENKINS_STEP_ANY_RE.finditer(line)]
    if not steps:
        return line
    return line[:len(line) - len(line.lstrip())] + "; ".join(steps)


# A command key whose value is folded (`run: >-` then its lines) or a plain scalar continued on the next lines
# (`run: pip` then `install requests`): YAML joins the lines with spaces into one command
_YAML_FOLDED_KEY_RE = re.compile(r"""^(\s*(?:-\s+)?)([\w.-]+)\s*:\s*>[-+0-9]*\s*(?:#.*)?$""")
_YAML_PLAIN_KEY_RE = re.compile(r"""^(\s*(?:-\s+)?)([\w.-]+)\s*:\s*([^\s|>'"#&*!%@`{\[][^#]*?)\s*$""")
# a list item of a command list (`script:` then `- >` and its lines, or `- python -m pip` continued below)
_YAML_FOLDED_ITEM_RE = re.compile(r"""^(\s*)-\s+>[-+0-9]*\s*(?:#.*)?$""")
_YAML_PLAIN_ITEM_RE = re.compile(r"""^(\s*)-\s+(?![\w.-]+\s*:(?:\s|$))([^\s|>'"#&*!%@`{\[-][^#]*?)\s*$""")
_YAML_KEY_LINE_RE = re.compile(r"""^(\s*)(?:-\s+)?([\w.-]+)\s*:\s*(?:#.*)?$""")
# a command key whose quoted value is not closed on its line (`run: "pip`)
_YAML_QUOTED_OPEN_RE = re.compile(r"""^(\s*(?:-\s+)?)([\w.-]+)\s*:\s*(["'])([^"'\n]*)$""")


def _yaml_command_key(key: str) -> bool:
    """A key whose value is a command or a list of commands (`run`, `script`, `before_script`, `commands`)."""
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key).lower().replace("_", " ").replace("-", " ").split()
    return any(w in ("run", "script", "scripts", "command", "commands", "cmd") for w in words)


def _blank_action_inputs(lines: list[str]) -> list[str]:
    """A step's `with:` mapping holds inputs of the action it uses (`packages: curl git`), not commands: the value of a
    key that is not a command key (`run`, `script`, `command`) is set to spaces, the length kept. The lines of a block
    scalar (`other_names: |`) and an address stay as they are."""
    out = list(lines)
    with_indent: int | None = None
    block_indent: int | None = None
    for n, ln in enumerate(out):
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = _yaml_indent(ln)
        if block_indent is not None:
            if indent > block_indent:
                continue
            block_indent = None
        if with_indent is not None and indent <= with_indent:
            with_indent = None
        if with_indent is None:
            if re.match(r"\s*(?:-\s+)?with\s*:\s*(?:#.*)?$", ln):
                with_indent = indent if not ln.lstrip().startswith("-") else indent + 2
            continue
        if re.search(r":\s*[|>][-+0-9]*\s*(?:#.*)?$", ln):
            block_indent = indent
            continue
        m = re.match(r"(\s*)([\w.-]+)(\s*:\s+)(\S.*)$", ln)
        if m and not _yaml_command_key(m.group(2)) and "://" not in m.group(4):   # (an address stays: it is a finding)
            out[n] = m.group(1) + m.group(2) + m.group(3) + " " * len(m.group(4))
    return out


def _fold_yaml_commands(lines: list[str]) -> list[str]:
    """`lines` with each folded or continued plain command scalar joined onto its first line, as YAML reads it; the
    other lines of it are left empty, so every line keeps its number. A command key's own value, and each item of a
    command key's list, is read this way."""
    out = list(lines)
    parents: list[tuple[int, str]] = []         # (indent, key) of the block keys above the current line
    n = 0
    while n < len(out):
        if out[n].strip() and not out[n].lstrip().startswith("#"):
            ind = _yaml_indent(out[n])
            is_item = out[n].lstrip().startswith("- ")
            while parents and (parents[-1][0] > ind or (parents[-1][0] == ind and not is_item)):
                parents.pop()
            key_line = _YAML_KEY_LINE_RE.match(out[n])
            if key_line:
                parents.append((len(key_line.group(1)), key_line.group(2)))
        quoted = _YAML_QUOTED_OPEN_RE.match(out[n])
        if quoted and _yaml_command_key(quoted.group(2)):
            # `run: "pip` then `install requests"`: a quoted scalar over several lines, joined with spaces
            q, k = quoted.group(3), n + 1
            while k < len(out) and k - n < 200 and q not in out[k]:
                k += 1
            if k < len(out) and k - n < 200:
                tail = out[k].split(q, 1)[0]
                out[n] = (quoted.group(1) + quoted.group(2) + ": " + quoted.group(4) + " "
                          + " ".join(out[j].strip() for j in range(n + 1, k)) + " " + tail.strip())
                for j in range(n + 1, k + 1):
                    out[j] = ""
                n = k + 1
                continue
        folded = _YAML_FOLDED_KEY_RE.match(out[n])
        folded = folded if folded and _yaml_command_key(folded.group(2)) else None
        plain = None if folded else _YAML_PLAIN_KEY_RE.match(out[n])
        plain = plain if plain and _yaml_command_key(plain.group(2)) else None
        if not (folded or plain) and parents and _yaml_command_key(parents[-1][1]):
            folded = _YAML_FOLDED_ITEM_RE.match(out[n])
            plain = None if folded else _YAML_PLAIN_ITEM_RE.match(out[n])
        if not (folded or plain):
            n += 1
            continue
        key_indent = len((folded or plain).group(1))
        k, parts = n + 1, []
        while k < len(out) and (not out[k].strip() or _yaml_indent(out[k]) > key_indent):
            if out[k].strip() and plain and re.match(r"\s*(?:-\s|[\w.-]+\s*:(?:\s|$))", out[k]):
                break                               # a key or a list item: the plain scalar ended before it
            parts.append(k)
            k += 1
        while parts and not out[parts[-1]].strip():
            parts.pop()
        if folded and parts and not any(out[j].strip() == "" for j in parts) and \
                len({_yaml_indent(out[j]) for j in parts}) == 1:
            # a folded block with no blank line and no more-indented line: one line, joined with spaces
            first = parts[0]
            out[first] = out[first].rstrip() + " " + " ".join(out[j].strip() for j in parts[1:])
            for j in parts[1:]:
                out[j] = ""
        elif plain and parts and all(out[j].strip() for j in parts):
            out[n] = out[n].rstrip() + " " + " ".join(out[j].strip() for j in parts)
            for j in parts:
                out[j] = ""
        n = k if parts else n + 1
    return out


def _yaml_indent(s: str) -> int:
    return len(s) - len(s.lstrip())


_COMPOSE_IMAGE_RE = re.compile(r"""^(\s*)image\s*:\s*['"]?([^\s'"#]+)""")


# Pipeline files whose jobs run in containers they name: GitLab CI, GitHub Actions, CircleCI, Bitbucket, Drone,
# Woodpecker, Azure Pipelines
_CI_FILE_RE = re.compile(r"(?:^|/)(?:\.gitlab-ci\.ya?ml|\.github/workflows/[^/]+|\.circleci/config\.ya?ml"
                         r"|bitbucket-pipelines\.ya?ml|\.drone\.ya?ml|\.woodpecker(?:\.ya?ml|/[^/]+)|azure-pipelines[^/]*\.ya?ml"
                         r"|\.gitlab/ci/[^/]+\.ya?ml|[^/]*\.gitlab-ci\.ya?ml|action\.ya?ml|cloudbuild[^/]*\.ya?ml)$",
                         re.IGNORECASE)
# Google Cloud Build: each step runs in the image its `name:` names (`- name: gcr.io/cloud-builders/curl`)
_CLOUDBUILD_FILE_RE = re.compile(r"(?:^|/)cloudbuild[^/]*\.ya?ml$", re.IGNORECASE)
_CLOUDBUILD_STEP_RE = re.compile(r"""^\s*-\s+name\s*:\s*['"]?([^\s'"#]+)['"]?\s*(?:#.*)?$""")


def _cloudbuild_images(lines: list[str]) -> dict[int, str]:
    """{line index: image} for each step of a Cloud Build file: the `name:` of an item under `steps:`."""
    out: dict[int, str] = {}
    steps_indent = None
    for n, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = _yaml_indent(line)
        if re.match(r"\s*steps\s*:\s*(?:#.*)?$", line):
            steps_indent = indent
            continue
        if steps_indent is not None and indent < steps_indent or (indent == steps_indent and not line.lstrip().startswith("-")):
            steps_indent = None
        m = _CLOUDBUILD_STEP_RE.match(line) if steps_indent is not None else None
        if m and "$" not in m.group(1):
            out[n] = m.group(1)
    return out
# `image: python:3.12`, `- image: cimg/base`, `container: node:20`, `uses: docker://alpine:3.19`
_CI_IMAGE_RE = re.compile(r"""^\s*(?:-\s+)?(?:image|container)\s*:\s*(?![|>]\s*$)(\S.*?)\s*(?:\s#.*)?$""")
# keys under which `image:` is a value handed on (an action's input, a matrix entry naming a runner), not a container
_CI_NOT_A_CONTAINER_KEYS = {"with", "env", "variables", "inputs", "outputs", "args", "parameters", "matrix", "strategy",
                            "include", "exclude", "vars", "secrets"}


def _ci_image_value(value: str) -> str:
    """An image as written after `image:`, without quotes or a YAML anchor (`&py cimg/python:3.12`); "" for a YAML alias
    (`*py`, reported where the anchor is written), a mapping in braces, or nothing."""
    value = value.strip()
    value = re.sub(r"^&\S+\s*", "", value)
    if not value or value[0] in "*{[" or value.startswith("<<:"):
        return ""
    if re.search(r"(?:^|/)Dockerfile[\w.-]*['\"]?$", value):
        return ""               # an action's `image: Dockerfile` is built here from the file named
    if value[0] in "'\"" and value[-1:] == value[0]:
        value = value[1:-1].strip()
    return value
_CI_DOCKER_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses\s*:\s*['"]?docker://([^\s'"#]+)""")
# under `image:` or a services list with no value on the key's line: `name: postgres:16`
_CI_NAME_RE = re.compile(r"""^\s*(?:-\s+)?name\s*:\s*['"]?([^\s'"#]+)""")
# a GitLab services list entry written as a string: `- postgres:16`
_CI_LIST_ITEM_RE = re.compile(r"""^\s*-\s+['"]?([\w.-]+(?:/[\w.-]+)*(?::[\w.-]+)?(?:@sha256:[0-9a-f]+)?)['"]?\s*(?:#.*)?$""")


def _ci_pulled_images(lines: list[str]) -> dict[int, str]:
    """{line index: image} for each container image a CI pipeline's jobs run in or beside: `image:`, `container:`,
    `uses: docker://`, and GitLab's `services:` entries."""
    out: dict[int, str] = {}
    parent: list[tuple[int, str]] = []          # (indent, key) of the keys above the current line
    # Azure Pipelines names a container resource in a list (`resources: containers: - container: py`, with its
    # `image:` beside it) and a job refers to it by that name (`container: py`): neither is an image
    aliases = {m.group(1) for m in (re.match(r"\s*-\s+container\s*:\s*['\"]?([\w.-]+)['\"]?\s*(?:#.*)?$", ln)
                                    for ln in lines) if m}
    for n, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        ref = re.match(r"\s*(-\s+)?container\s*:\s*['\"]?([\w.-]+)['\"]?\s*(?:#.*)?$", line)
        if ref and (ref.group(1) or ref.group(2) in aliases):
            continue
        indent = _yaml_indent(line)
        while parent and parent[-1][0] >= indent and not (parent[-1][0] == indent and line.lstrip().startswith("-")
                                                          and parent[-1][1] == "services"):
            parent.pop()
        key = re.match(r"\s*(?:-\s+)?([\w.-]+)\s*:\s*(?:#.*)?$", line)
        m = _CI_IMAGE_RE.match(line) or _CI_DOCKER_USES_RE.match(line)
        if any(k in _CI_NOT_A_CONTAINER_KEYS for _, k in parent):
            m = None            # an action's input, a variable or a matrix entry named `image`: a value handed on
        if m:
            image = _ci_image_value(m.group(1))
            if image:
                out[n] = image
        elif parent and parent[-1][1] in ("image", "container") and _CI_NAME_RE.match(line):
            out[n] = _ci_image_value(_CI_NAME_RE.match(line).group(1)) or _CI_NAME_RE.match(line).group(1)
        elif parent and parent[-1][1] == "services" and not key:
            item = _CI_NAME_RE.match(line) or _CI_LIST_ITEM_RE.match(line)
            if item and (":" in item.group(1) or "/" in item.group(1) or _CI_NAME_RE.match(line)):
                out[n] = item.group(1)
        if key:
            parent.append((indent, key.group(1)))
    return out


def _compose_pulled_images(lines: list[str]) -> dict[int, str]:
    """{line index: image} for each `image:` of a Compose service that does not also have a `build:` key (a service
    that builds its image here names the image it builds). A service written in flow style
    (`web: {image: nginx, ports: ["80:80"]}`) names its image inside braces."""
    out: dict[int, str] = {}
    # one pass: each line's parent (the nearest line above it with less indent), and the parents with a `build:` child
    parent: dict[int, int] = {}
    stack: list[tuple[int, int]] = []            # (indent, line index) of the open blocks
    builds: set[tuple[int, int]] = set()         # (parent, indent) of each `build:` key
    images: list[tuple[int, int, str]] = []      # (line, indent, image)
    for n, line in enumerate(lines):
        if not line.strip():
            continue
        ind = _yaml_indent(line)
        while stack and stack[-1][0] >= ind:
            stack.pop()
        parent[n] = stack[-1][1] if stack else -1
        stack.append((ind, n))
        m = _COMPOSE_IMAGE_RE.match(line)
        if m:
            images.append((n, ind, m.group(2)))
        elif re.match(r"\s*build\s*:", line):
            builds.add((parent[n], ind))
        else:
            flow = re.search(r"""[{,]\s*image\s*:\s*['"]?([^\s'",}#]+)""", line)
            if flow and not re.search(r"""[{,]\s*build\s*:""", line):
                out[n] = flow.group(1)
    for n, ind, image in images:
        if (parent[n], ind) not in builds:
            out[n] = image
    return dict(sorted(out.items()))


def _python_default_ranges(lines: list[str]) -> list[tuple[int, int]]:
    """Line ranges where `defaults: run: shell: python` makes Python every step's shell: the whole file for a
    workflow-level default, the job's lines for a job-level one."""
    out = []
    for n, line in enumerate(lines):
        if not re.match(r"\s*defaults\s*:\s*(?:#.*)?$", line):
            continue
        c, k, python = _yaml_indent(line), n + 1, False
        while k < len(lines) and (not lines[k].strip() or _yaml_indent(lines[k]) > c):
            sm = _YAML_SHELL_RE.match(lines[k])
            python = python or bool(sm and _YAML_SHELL_IS_PYTHON_RE.fullmatch(sm.group(1).strip()))
            k += 1
        if not python:
            continue
        if c == 0:
            out.append((0, len(lines)))
            continue
        p = n - 1
        while p >= 0 and (not lines[p].strip() or _yaml_indent(lines[p]) >= c):
            p -= 1
        p_ind = _yaml_indent(lines[p]) if p >= 0 else -1
        e = n + 1
        while e < len(lines) and (not lines[e].strip() or _yaml_indent(lines[e]) > p_ind):
            e += 1
        out.append((max(p, 0), e))
    return out


_JUST_RECIPE_RE = re.compile(r"^@?[A-Za-z_][\w-]*(?:\s[^:=#]*)?:(?![=:])")


def _just_python_recipes(lines: list[str]) -> dict[int, tuple[int, str]]:
    """{first body line: (end, body)} for each justfile recipe whose body starts with a Python shebang
    (`#!/usr/bin/env python3`): just writes such a body to a file and runs it with that interpreter."""
    out: dict[int, tuple[int, str]] = {}
    for n, line in enumerate(lines):
        if not _JUST_RECIPE_RE.match(line):
            continue
        start = n + 1
        while start < len(lines) and not lines[start].strip():
            start += 1
        if start >= len(lines) or not lines[start][:1].isspace() or not _PYTHON_SHEBANG_RE.match(lines[start].strip()):
            continue
        k = start + 1
        while k < len(lines) and (not lines[k].strip() or lines[k][:1].isspace()):
            k += 1
        out[start] = (k, textwrap.dedent("\n".join(lines[start:k])) + "\n")
    return out


def _python_run_blocks(lines: list[str]) -> dict[int, tuple[int, str]]:
    """A pipeline step whose shell is Python (its own `shell: python`, or a `defaults:` one) runs its `run:` with
    Python. For each such step: {index of the first line of its code: (index after its last line, the code)}."""
    out: dict[int, tuple[int, str]] = {}
    defaults = _python_default_ranges(lines) if any("defaults" in ln for ln in lines) else []
    for n, line in enumerate(lines):
        m = _YAML_RUN_LINE_RE.match(line)
        if not m:
            continue
        indent = len(m.group(1))
        # the step: from the `- ` that opens it (left of `run:`) to the next line at or left of that dash
        s = n
        while s >= 0 and not (lines[s].lstrip().startswith("- ") and len(lines[s]) - len(lines[s].lstrip()) < indent):
            if s < n and lines[s].strip() and len(lines[s]) - len(lines[s].lstrip()) < indent:
                s = -1                  # left the step's mapping without finding its dash
                break
            s -= 1
        if s < 0:
            continue
        dash = len(lines[s]) - len(lines[s].lstrip())
        e = s + 1
        while e < len(lines) and (not lines[e].strip() or len(lines[e]) - len(lines[e].lstrip()) > dash):
            e += 1
        own = next((sm.group(1).strip() for sm in map(_YAML_SHELL_RE.match, lines[s:e]) if sm), None)
        python = (_YAML_SHELL_IS_PYTHON_RE.fullmatch(own) is not None if own is not None
                  else any(a <= n < b for a, b in defaults))
        if not python:
            continue
        if m.group(3) is not None:
            # `run: import socket; ...` on one line: the value is the code
            out[n] = (n + 1, m.group(3).strip().strip("'\"") + "\n")
            continue
        k = n + 1
        while k < len(lines) and (not lines[k].strip() or len(lines[k]) - len(lines[k].lstrip()) > indent):
            k += 1
        if k > n + 1:
            out[n + 1] = (k, textwrap.dedent("\n".join(lines[n + 1:k])) + "\n")
    return out


_DEV_TCP_RE = re.compile(r"(?<![\w.])/dev/(?:tcp|udp)/([^/\s'\"]*)")
# `\\server\share`, not `\\?\C:\...` or `\\.\pipe\...` (this machine's long-path and device prefixes)
# a daemon address given to docker or podman in front of the command (`DOCKER_HOST=ssh://host docker ps`)
_DOCKER_HOST_RE = re.compile(r"""\b(?:DOCKER_HOST|CONTAINER_HOST)=['"]?([^\s'"]+)['"]?\s+(?:\S+=\S*\s+)*$""")
# A Windows remote administration command and the machine it is given as `\\server`
# (psexec's options may stand before the machine, which may be a list file, `@computers.txt`; the query tools take
# the machine after `/s`, with or without `\\`)
_REMOTE_ADMIN_RE = re.compile(
    r"""(?i)\b(psexec(?:64)?(?:\.exe)?|paexec(?:\.exe)?)(?:\s+-\w+(?:\s+(?![\\@-])[^\s\\@]\S*)?)*"""
    r"""\s+(?:\\\\([A-Za-z0-9][\w.-]*)(?![\w.-])|@(\S+))"""
    r"""|\b(net(?:\.exe)?\s+(?:view|use|time|session|file|share)|sc(?:\.exe)?"""
    r"""|reg(?:\.exe)?\s+(?:query|add|delete|copy|save|load|export|compare)|shutdown(?:\.exe)?(?:\s+/\w+)*\s+/m)"""
    r"""\s+\\\\([A-Za-z0-9][\w.-]*)(?![\w.-])"""
    r"""|\b((?:tasklist|taskkill|schtasks|systeminfo|getmac|driverquery|openfiles|eventcreate)(?:\.exe)?)"""
    r"""(?:\s+/\w+(?:\s+(?![/\\])\S+)?)*?\s+/s\s+(?:\\\\)?([A-Za-z0-9][\w.-]*)(?![\w.-])""")
_UNC_RE = re.compile(r"""(?<![\w\\])\\\\(?:[?.]\\UNC\\)?(?![?.]\\)([A-Za-z0-9][\w.-]*)(?:@SSL)?(?:@\d+)?\\[\w$.-]+""",
                     re.IGNORECASE)
# UNC hosts that are this machine: itself by name or address, and the WSL file systems it serves (`\\wsl.localhost\`)
_UNC_THIS_MACHINE_RE = re.compile(r"localhost|127(?:\.\d{1,3}){3}|wsl\.localhost", re.IGNORECASE)
# `powershell -EncodedCommand <base64>` (any prefix of the option PowerShell accepts: `-e`, `-ec`, `-enc`, ...)
_ENCODED_COMMAND_RE = re.compile(r"""\b(?:powershell|pwsh)(?:\.exe)?\b""", re.IGNORECASE)
# each option of that command with a value that could be base64 (`-ExecutionPolicy Bypass`, `-enc:<b64>`)
_ENCODED_ARG_RE = re.compile(r"""(?<!\S)[-/]([A-Za-z]+)(?::|\s+)['"]?([A-Za-z0-9+/]{4,}={0,2})(?![\w+/=])""")
_ENCODED_FLAG_RE = re.compile(r"ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?", re.IGNORECASE)
# Package managers, build tools and fetchers of other ecosystems, in the forms that resolve or download (a bare `yarn`
# installs). Counted only where a command starts: the same word in a list of packages is a package's name.
_SCRIPT_INSTALL_RE = re.compile(  # (`uv run --with x` fetches x; `--with-editable .` is a path here)
    r"""(?<![\w./-])(?:[\w.~${}()-]{0,256}/){0,8}("""
    r"""yarn(?:\s+-{1,2}[\w=.-]+)*(?=\s*(?:$|[;&|)]))|yarn(?:\s+-{1,2}[\w=.-]+)*\s+(?:install|add|upgrade|up|dlx|create|global\s+add|set\s+version|import)"""
    r"""|bunx|pnpx|bun\s+(?:install|i|add|update|upgrade|x|create|pm\s+(?:pack|publish))|pnpm\s+(?:dlx|update|up|upgrade|create|fetch|exec\s+-y)"""
    r"""|npm(?:\s+-{1,2}[\w=.-]+)*\s+(?:update|up|upgrade|audit|exec|x|create|outdated|view|show|v|info|search|s|find|dist-tag|deprecate|login|adduser|whoami|ping|unpublish|owner|access|token|cit|doctor|star|unstar|team|org|hook|profile|docs|home|repo|bugs|cache\s+add)(?![\w-])|npm(?:\s+-{1,2}[\w=.-]+)*\s+init(?=\s+(?!-)[@\w])"""
    r"""|corepack\s+(?:prepare|install|up|use)|deno\s+(?:install|cache|add|upgrade|compile|outdated|run)|bower\s+(?:install|i|update|info|search)"""
    r"""|mc\s+(?:cp|mirror|mv|cat|ls|rm|stat|alias\s+set)(?=\s)|mailx?(?=(?:\s+-\S+(?:\s+(?!-)\S+)?)*\s+[\w.+-]+@[\w-]+(?:\.[\w-]+)+)|buck2?\s+(?:build|test|run|fetch)"""
    r"""|poetry(?:\s+(?:(?:-C|-P|--directory|--project)(?:=\S+|\s+\S+)|-{1,2}[\w=.-]+))*\s+(?:install|add|update|lock|sync|publish|self\s+(?:update|add|install))|pipenv\s+(?:install|update|lock|sync|upgrade)"""
    r"""|pdm\s+(?:install|add|update|lock|sync|publish|self\s+update)|pip-sync|easy_install|uv\s+(?:lock|python\s+install|self\s+update|build|publish)"""
    # `uv run`, `hatch run`, `pixi run` make the environment first (`uv run` syncs the project and its `--with` packages)
    # (`--no-sync` or `--offline` counts among `uv run`'s own options, before the program it runs: after it, it is
    # that program's)
    r"""|uv\s+run\b(?!(?:[ \t]+-\S+)*[ \t]+--(?:no-sync|offline)(?![\w-]))|(?:hatch|pixi)\s+run\b|uvx(?=\s)"""
    r"""|(?:python[\d.]*\s+)?setup\.py(?:\s+[\w-]+)*?\s+(?:install|develop|easy_install|upload|register)"""
    # programs that deploy or publish to a service, run a playbook on hosts, or download browsers or packages
    r"""|vercel(?!\s+(?:dev|build|--version|-v|--help|-h|help)\b)|netlify\s+(?:deploy|sites:\S*|api|link|login|env:\S*|init)"""
    r"""|firebase\s+(?:deploy|login|use|hosting:\S*|functions:\S*)|(?:fly|flyctl)\s+(?:deploy|launch|ssh|apps|secrets|scale|logs|status|machine)"""
    r"""|sam\s+(?:deploy|sync|publish|logs|delete)|cdk\s+(?:deploy|destroy|diff|bootstrap|import)|(?:serverless|sls)\s+(?:deploy|remove|invoke|logs)"""
    r"""|heroku(?!\s+(?:local|--version|-v|--help|help|version)\b)(?=\s)|(?:hatch|flit)\s+publish|playwright\s+install"""
    r"""|ansible-playbook|ansible(?=\s+\S+\s+-m\b)|(?:Rscript|R)(?:\s+--?[\w-]+)*\s+-e\s+['"][^'"]*install\.packages|julia\s+-e\s+['"][^'"]*Pkg\.add"""
    r"""|(?:conda|mamba|micromamba)(?:\s+-{1,2}[\w=.-]+)*\s+(?:create|update|upgrade|env\s+(?:create|update))|micromamba\s+install|pixi\s+(?:install|add|update|upgrade|global\s+install)"""
    r"""|bundle\s+(?:install|update|add|lock)|bundler\s+install|composer\s+(?:install|update|require|create-project|global\s+require)"""
    r"""|go\s+(?:mod\s+(?:download|tidy)|run\s+\S+@|work\s+sync)|cargo(?:\s+(?:\+\S+|(?:-C|-Z|--manifest-path|--config|--color|--lockfile-path)(?:=\S+|\s+\S+)|-{1,2}[\w=.-]+))*\s+(?:build|fetch|update|add|publish|vendor|generate-lockfile|test|run|check|doc|clippy|bench|b|c|t|r|d)(?![\w-])"""
    r"""|(?:mvn|mvnw|gradle|gradlew)(?=\s+\S)(?!\s+(?:-v|--version|-h|--help)(?!\S))"""
    r"""|dotnet\s+(?:restore|build|publish|test|add\s+\S+\s+package|tool\s+(?:install|update|restore)|nuget\s+push|new\s+install|workload\s+(?:install|update|restore))"""
    r"""|nuget\s+(?:restore|install|update|push)|terraform\s+(?:init|plan|apply|destroy|import|refresh|providers\s+mirror|get)"""
    r"""|tofu\s+(?:init|plan|apply)|ansible-galaxy\s+(?:install|collection\s+install|role\s+install)"""
    r"""|apk(?:\s+-{1,2}[\w=.-]+)*\s+(?:update|upgrade)|zypper(?:\s+-{1,2}[\w=.-]+)*\s+(?:in|install|refresh|ref|update|up|dup)"""
    r"""|nix-shell\s+(?:-p|--packages)|nix\s+(?:build|develop|shell|run|profile\s+install|flake\s+update)|nix-env\s+-i"""
    r"""|flatpak\s+(?:install|update)|rustup\s+(?:toolchain\s+install|install|update|target\s+add|component\s+add|default)"""
    r"""|nvm\s+install|pyenv\s+install|asdf\s+(?:install|plugin\s+add)|sdk\s+install|mise\s+install|volta\s+install"""
    r"""|rclone\s+(?:copy|sync|move|copyto|moveto|lsd|ls|lsf|mount|serve|check)|s3cmd|skopeo\s+(?:login|logout)|skopeo\s+(?:copy|inspect|sync|list-tags|delete)(?=[^\n;&|]*\bdocker://)"""
    r"""|cargo(?:\s+(?:\+\S+|(?:-C|-Z|--manifest-path|--config|--color|--lockfile-path)(?:=\S+|\s+\S+)|-{1,2}[\w=.-]+))*\s+(?:search|login|owner|yank|install)"""
    r"""|go\s+(?:build|test|vet|run|generate|list\s+-m)|(?:flutter|dart)\s+pub\s+(?:get|upgrade|add|outdated|downgrade|global\s+activate)"""
    r"""|flutter\s+(?:precache|upgrade|create)|pod\s+(?:install|update|repo\s+update|outdated|trunk\s+push)|carthage\s+(?:update|bootstrap|checkout)"""
    r"""|swift\s+(?:package\s+(?:resolve|update)|build|test|run)|mix\s+(?:deps\.get|deps\.update|local\.hex|local\.rebar|hex\.publish|archive\.install)"""
    r"""|(?:bazel|bazelisk)\s+(?:build|test|run|fetch|sync|query|coverage)|sbt(?=\s+\S)(?!\s+(?:-v|--version|-h|--help)(?!\S))"""
    r"""|lein\s+(?:deps|install|uberjar|jar|test|run|compile|check|deploy)|(?:clojure|clj)\s+-P|conan\s+(?:install|create|download|upload|remote\s+login)"""
    r"""|vcpkg\s+(?:install|upgrade|update|x-update-baseline)|cabal\s+(?:update|install|build|test|run|get|fetch)|stack\s+(?:build|install|setup|update|test|run|upgrade)"""
    r"""|opam\s+(?:install|update|upgrade|init|switch\s+create)|luarocks\s+(?:install|download|upload)|cpanm?(?=\s+(?:-\S+\s+)*[\w:]+(?:\s|$))"""
    r"""|rebar3\s+(?:get-deps|upgrade|compile|hex\s+publish)|elm\s+(?:install|make|publish)|wasm-pack\s+(?:build|test|publish)"""
    r"""|(?:apt-get|apt|aptitude)(?:\s+-{1,2}[\w=.-]+)*\s+(?:update|upgrade|dist-upgrade|full-upgrade|source|download|build-dep)"""
    r"""|(?:yum|dnf|microdnf|tdnf)(?:\s+-{1,2}[\w=.-]+)*\s+(?:update|upgrade|makecache|check-update|download|reinstall|distro-sync|groupinstall)|(?:microdnf|tdnf)(?:\s+-{1,2}[\w=.-]+)*\s+install"""
    r"""|brew\s+(?:update|upgrade|tap|fetch|bundle|reinstall)|gem\s+(?:update|push|fetch|sources\s+-a|yank)|snap\s+(?:refresh|download)"""
    r"""|pip[\d.]*\s+(?:wheel|index)|pip-compile|tox(?=\s|$)|nox(?=\s|$)|pre-commit\s+(?:run|autoupdate|install-hooks|try-repo|install\s+(?:.*\s)?--install-hooks)"""
    r"""|git-lfs\s+(?:fetch|pull|push|clone)|(?:huggingface-cli|hf)\s+(?:download|upload|login)|kaggle\s+(?:competitions|datasets|kernels|models)"""
    r"""|dvc\s+(?:pull|push|fetch|import|import-url|get|get-url|update)|ollama\s+(?:pull|push|run)"""
    r"""|dotnet\s+(?:run|pack|add\s+(?:\S+\s+)?package)|pulumi\s+(?:up|preview|destroy|refresh|import|login|plugin\s+install|new)"""
    r"""|vagrant\s+(?:up|box\s+(?:add|update)|provision|reload|ssh|cloud)|packer\s+(?:build|init)"""
    r"""|lftp|whois|nmap|mosh|ping|traceroute|tracert|mtr|host(?=\s+[\w.-]+\.[a-z]{2,}\b)|sshpass|autossh|wsl\s+--update"""
    r"""|ssh-keyscan|ntpdate|sendmail"""
    # `python -m build` installs the build requirements into an isolated environment first (not with `-n`)
    r"""|(?:python[\d.]*|py)\s+(?:-\S+\s+)*-m\s+build(?![\w.-])(?![^\n;&|]*\s(?:--no-isolation|-n)(?!\S))"""
    r""")(?:\.(?:exe|cmd|bat))?(?![\w.-]|://|=|/|\\|:\S)""",
    re.IGNORECASE)
# The host a ping-like tool is pointed at, when it is this machine
_HOST_TOOL_LOOPBACK_RE = re.compile(r"""(?:^|\s)(?:localhost|127(?:\.\d{1,3}){3}|::1|0\.0\.0\.0)(?=\s|$)""")
# Programs judged, on a script line, by the same argument rules as an argv list Python hands them.
_SCRIPT_ARGV_PROGRAM_RE = re.compile(
    r"""(?<![\w./-])(?:[\w.~${}()-]{0,256}/)?(aws|gcloud|gsutil|az|kubectl|helm|docker|podman|psql|mysql|redis-cli|mongosh"""
    r"""|pg_dump|pg_dumpall|pg_restore|mysqldump|mongodump|mongorestore"""
    r"""|openssl|hg|svn|socat|smbclient|mosquitto_pub|mosquitto_sub|docker-compose|podman-compose)(?:\.exe)?(?=[ \t]|$)""")


def _make_runs_now(line: str, at: int) -> bool:
    """In a Makefile, the program at `at` runs when make reads the file: inside `$(shell ...)` or `${shell ...}`,
    or as the value of a `!=` assignment."""
    before = line[max(0, at - 400):at]
    # the first program of the function's text, wrappers aside (`$(shell sudo docker run ...)`)
    if re.search(r"\$[({]shell\s+(?:(?:sudo|doas|env|nice|nohup|command|exec|timeout\s+\S+)(?:\s+-\S+)*\s+"
                 r"|[A-Za-z_]\w*=\S*\s+)*$", before) \
            or re.match(r"^(?:export\s+|override\s+)?[A-Za-z_][\w.-]*\s*!=\s*$", line[:at]):
        return True
    # a later command of the function's text (`$(shell cd x && git pull)`), inside a `$(shell` still open here
    opened = max(before.rfind("$(shell"), before.rfind("${shell"))
    return opened >= 0 and before[opened:].count("(") + before[opened:].count("{") > \
        before[opened:].count(")") + before[opened:].count("}") \
        and bool(re.search(r"(?:&&|\|\||;|\|)\s*$", before))


_PRINT_INTO_RE = re.compile(r"(?<![\w./-])(echo|printf)(?=[ \t])")


def _command_words_to(line: str, at: int, limit: int = 256) -> tuple[list[str], int]:
    """The words from `at` up to the first separator or redirection, as the shell hands them over (a word in which the
    shell expands something is `_ARGV_HOLE`), and where they end."""
    words, i, n = [], at, len(line)
    while i < n and len(words) < limit:
        j = i
        while j < n and line[j] in " \t":
            j += 1
        if j >= n or line[j] in ";|&<>()`":
            return words, j
        w = _shell_word(line, j)
        if w is None or w[0] == j:
            return words, j
        words.append(_ARGV_HOLE if w[2] or "$" in line[j:w[0]] and line[j] != "'" else w[1])
        i = w[0]
    return words, i


def _printed_text(program: str, words: list[str]) -> str | None:
    """What `echo` or `printf` writes, given its arguments: echo's words joined by spaces (with `-e`, its escapes
    undone), printf's format applied to its arguments in turn. None for a form not followed here."""
    def unescape(s: str) -> str:
        return s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
    if program == "echo":
        flags = set()
        while words and re.fullmatch(r"-[neE]+", words[0]):
            flags |= set(words.pop(0)[1:])
        text = " ".join(words)
        return (unescape(text) if "e" in flags else text) + "\n"
    if not words:
        return None
    fmt, args = unescape(words[0]), words[1:]
    slots = len(re.findall(r"%[sb]", fmt))
    if "%" in fmt.replace("%s", "").replace("%b", "").replace("%%", ""):
        return None                     # a numeric or padded format: not followed
    if not slots or not args:
        return fmt.replace("%%", "%")
    out = []
    for k in range(0, len(args), slots):
        chunk = args[k:k + slots] + [""] * (slots - len(args[k:k + slots]))
        piece = fmt
        for a in chunk:
            piece = re.sub(r"%[sb]", lambda _m, a=a: a, piece, count=1)
        out.append(piece.replace("%%", "%"))
    return "".join(out)


def _command_words(line: str, at: int, limit: int = 64) -> list[str]:
    """The words of the command starting at `at`, as the shell hands them over, up to the first separator or
    redirection. A word holding a variable is a hole (`_ARGV_HOLE`): its value is not known here."""
    words, i, n = [], at, len(line)
    while i < n and len(words) < limit:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n or line[i] in ";|&<>()`":
            break
        w = _shell_word(line, i)
        if w is None or w[0] == i:
            break
        # an option keeps its name even when its value is a variable (`-u$USER`); any other word holding one is a hole
        words.append(w[1] if w[1].startswith("-") else _ARGV_HOLE if w[2] or "$" in line[i:w[0]] else w[1])
        i = w[0]
    return words


def _script_argv_findings(rel: str, lineno: int, line: str, parsed: list, held: bool, makefile: bool) -> list[Finding]:
    """A program such as `aws`, `kubectl`, `docker` or `psql` on a script line, judged with its arguments by the
    rules `_argv_findings` applies to an argv list (`docker logs` and `kubectl config` act on this machine)."""
    out: list[Finding] = []
    for m in _SCRIPT_ARGV_PROGRAM_RE.finditer(line):
        if any(qs < m.start() < qe for qs, qe in parsed) or _in_printed_part(line, m.start()):
            continue
        # a value (`DB=mysql`, `--group aws`), a key (`mysql = ...`, `docker:`), or text inside `${VAR:-...}`
        before = line[:m.start()]
        prev_word = before.split()[-1] if before.split() else ""
        if before[-1:] in ("=", ",") or re.match(r"[ \t]*[=:]", line[m.end():]) \
                or (prev_word.startswith("--") and prev_word != "--" and "=" not in prev_word) \
                or (before.rfind("${") > before.rfind("}")):
            continue
        if not (_at_command_start(line, m.start()) or (makefile and _make_runs_now(line, m.start()))):
            continue
        words = _command_words(line, m.start())
        if len(words) < 2 and not (_argv_basename(words[0] if words else "") in _DB_CLIENT_HOST_FLAGS and (
                re.search(r"(?:^|\s)--\s*$", line[:m.start()]) or line.strip() == m.group(0).strip())):
            # a program named with nothing after it is a word in a list; a database client alone on its line or
            # after a launcher's `--` (`dotenv run -- psql`) connects, as it does run bare
            continue
        word_only = held and not (makefile and _make_runs_now(line, m.start()))
        exe0 = _argv_basename(words[0])
        daemon = _DOCKER_HOST_RE.search(line[max(0, m.start() - 600):m.start()]) if exe0 in ("docker", "podman") else None
        daemon_host = _host_of(daemon.group(1)) if daemon else None
        if daemon and not word_only and not daemon.group(1).startswith(("unix://", "npipe://", "$")) \
                and not (daemon_host and _THIS_MACHINE_HOST_RE.fullmatch(daemon_host)):
            # `DOCKER_HOST=ssh://deploy@prod docker ps`: every docker command talks to that daemon
            out.append(Finding(rel, lineno, "script-network-command",
                               f"runs {exe0!r} against the daemon DOCKER_HOST names on another machine, a command "
                               "that reaches the network"))
            break
        for f in _argv_findings(rel, lineno, "script", words):
            exe = _argv_basename(words[0])
            if f.kind == "loopback-call":
                # the argv rule's own reason (no host given, or the host given is this machine), said of the line
                out.append(Finding(rel, lineno, "loopback-call", f"runs {exe!r}: {f.detail.split('): ', 1)[-1]}"))
            elif f.kind == "inbound-listener":
                out.append(Finding(rel, lineno, "inbound-listener", f"runs {exe!r}: {f.detail.split('): ', 1)[-1]}"))
            elif f.kind in ("subprocess-net-binary", "git-remote"):
                sub = next((w for w in words[1:] if w != _ARGV_HOLE and not w.startswith("-")), "")
                if word_only:
                    detail = (f"names {exe!r}, a program that reaches the network, in a place this line is NOT "
                              "shown to run it from")
                elif (exe in ("docker-compose", "podman-compose") and _compose_subcommand(list(words[1:])) == "push") or (
                        exe in ("docker", "podman") and sub == "compose"
                        and _compose_subcommand(list(words[words.index("compose") + 1:])) == "push"):
                    # `docker compose push`: it sends images to a registry
                    detail = f"runs {(exe + ' compose') if sub == 'compose' else exe!r}, a command that reaches the network"
                elif exe in ("docker-compose", "podman-compose"):
                    detail = f"runs {exe!r}, which pulls an image from a registry when it is not already on this machine"
                elif exe in ("docker", "podman") and sub in _CONTAINER_PULLING_SUBCOMMANDS:
                    # it reaches a registry for what is not on this machine; an image built here a line earlier is
                    detail = (f"runs '{exe} {sub}', which pulls an image from a registry when it is not already on "
                              "this machine")
                else:
                    detail = f"runs {exe!r}, a command that reaches the network"
                out.append(Finding(rel, lineno, "script-network-word" if word_only else "script-network-command",
                                   detail))
        if out:
            break
    return out


# Tools that reach the network whenever they run; the others on `_SCRIPT_INSTALL_RE` resolve or download what is not
# already on the machine.
_ALWAYS_REMOTE_TOOLS = {"lftp", "whois", "nmap", "mosh", "ping", "traceroute", "tracert", "mtr", "host", "sshpass",
                        "autossh", "s3cmd", "rclone", "skopeo", "vercel", "netlify", "firebase", "fly", "flyctl", "sam",
                        "cdk", "serverless", "sls", "heroku", "ansible-playbook", "ansible", "ssh-keyscan", "ntpdate",
                        "sendmail", "mail", "mailx"}
# subcommands that send to a service rather than fetch what is missing (`hatch publish`, `gem push`)
_SENDS_RE = re.compile(r"\b(?:publish|upload|register|deploy|push)\b")


def _script_install_findings(rel: str, lineno: int, line: str, parsed: list, held: bool,
                             makefile: bool) -> list[Finding]:
    """A package manager, build tool or fetcher of another ecosystem where a command starts (`yarn`, `poetry
    install`, `cargo build`, `ping host`)."""
    for m in _SCRIPT_INSTALL_RE.finditer(line):
        if any(qs < m.start() < qe for qs, qe in parsed) or _in_printed_part(line, m.start()):
            continue
        before = line[:m.start()]
        prev_word = before.split()[-1] if before.split() else ""
        if before[-1:] in ("=", ",") or re.match(r"[ \t]*[=:]", line[m.end():]) \
                or (prev_word.startswith("--") and prev_word != "--" and "=" not in prev_word) \
                or before.rfind("${") > before.rfind("}"):
            continue
        if not (_at_command_start(line, m.start()) or (makefile and _make_runs_now(line, m.start()))):
            continue
        command = _first_command(line[m.start():])
        if _install_stays_here(command, line[max(0, m.start() - 256):m.start()]):
            return []
        tool = m.group(1).split()[0].lower().rsplit("/", 1)[-1]
        word_only = held and not (makefile and _make_runs_now(line, m.start()))
        if tool in _ALWAYS_REMOTE_TOOLS and not word_only and _HOST_TOOL_LOOPBACK_RE.search(command[len(m.group(1)):]):
            return [Finding(rel, lineno, "loopback-call",
                            f"runs {tool!r} against an address on this machine; nothing leaves it at this line")]
        shown = " ".join([w for w in m.group(1).split() if not w.startswith("-")][:2]) if tool not in _ALWAYS_REMOTE_TOOLS else tool
        if tool in ("rscript", "r", "julia"):
            shown = f"{m.group(1).split()[0]} -e install.packages(...)" if tool != "julia" else "julia -e Pkg.add(...)"
        elif re.search(r"\s-m\s+build\b", m.group(1)):
            shown = "python -m build"
        if word_only:
            return [Finding(rel, lineno, "script-network-word",
                            f"names {shown!r}, a program that reaches the network, in a place this line is NOT shown "
                            "to run it from")]
        if tool in _ALWAYS_REMOTE_TOOLS or _SENDS_RE.search(m.group(1)):
            return [Finding(rel, lineno, "script-network-command", f"runs {shown!r}, a command that reaches the network")]
        if tool == "mc":
            # the MinIO client: a path that starts with an alias (`myminio/bucket/`) is on the server the alias names
            return [Finding(rel, lineno, "script-network-command",
                            f"runs {shown!r}, the MinIO client, which reaches the storage server an alias in its "
                            "arguments names (a plain local path stays on this machine)")]
        return [Finding(rel, lineno, "script-network-command",
                        f"runs {shown!r}, which downloads packages or other content it needs from the network when "
                        "they are not already on this machine")]
    return []


# the program asked only about itself (`yarn --version`, `sbt -h`, `tox --help`)
_ABOUT_ITSELF_RE = re.compile(r"\S+(?:\s+(?:-v|-V|--version|-h|--help|help|version|--info|-version))+\s*", re.IGNORECASE)


# launchers that fetch a program or make its environment and then run it, handing it the words after its name:
# (the program, the subcommand that launches, or "" when the program itself launches)
_LAUNCH_VERBS = {"npx": "", "bunx": "", "pnpx": "", "uvx": "", "yarn": "dlx", "pnpm": "dlx", "npm": "exec|x",
                 "bun": "x", "uv": "run|tool run", "pipx": "run", "go": "run", "deno": "run", "cargo": "run",
                 "dotnet": "run", "poetry": "run", "pdm": "run", "hatch": "run", "rye": "run", "pixi": "run"}


def _outer_quote_close(command: str) -> int:
    """Where a quote closes a string opened before `command` began (`yarn install' --offline`): a quote straight after
    a word, with no string of the command's own open. The length of `command` when there is none."""
    open_quote = None
    for k, c in enumerate(command):
        if c not in "'\"":
            continue
        if open_quote == c:
            open_quote = None
        elif open_quote is None:
            before = command[k - 1] if k else " "
            if before.isspace() or before in "=(:,[{$":
                open_quote = c
            else:
                return k
    return len(command)


def _launcher_own_part(command: str) -> str:
    """The words of a command that belong to the program written first, not to a program it launches: everything
    before a standalone `--`, and for a launcher (`npx some-cli --offline`, `go run ./cmd/x -mod=vendor`,
    `uv run python app.py --offline`) the words before the program it runs. An option with a value may be taken for
    that program, which only shortens what is read. A command written inside quotes (`bash -c 'yarn install'
    --offline`) ends at the quote that closes them: what follows is the outer program's."""
    command = command[:_outer_quote_close(command)]
    words = command.split()
    if "--" in words:
        words = words[:words.index("--")]
    if not words:
        return ""
    tool = words[0].lower().rsplit("/", 1)[-1]
    verbs = _LAUNCH_VERBS.get(tool)
    if verbs is None:
        return " ".join(words)
    k = 1
    if verbs:
        for verb in sorted(verbs.split("|"), key=len, reverse=True):
            parts = verb.split()
            at = next((j for j in range(1, len(words) - len(parts) + 1)
                       if words[j:j + len(parts)] == parts and not any(not w.startswith("-") for w in words[1:j])), None)
            if at is not None:
                k = at + len(parts)
                break
        else:
            return " ".join(words)
    while k < len(words) and words[k].startswith("-"):
        k += 1
    return " ".join(words[:k])


def _install_stays_here(command: str, before: str = "") -> bool:
    """A package manager or build tool told not to reach the network, or asked only about itself: `--offline`, `-o`
    to Maven and Gradle, `--frozen` to Cargo, `--no-restore` to dotnet, `-mod=vendor` or `GOPROXY=off` to Go, and
    `--version` or `--help`. `before` is the text in front of the command on its line (`GOFLAGS=-mod=vendor go build`).
    Only the words that belong to the program written first count: a flag after `--` or after the program a launcher
    runs is that program's."""
    command = _launcher_own_part(command)
    if _offline_install(command) or _ABOUT_ITSELF_RE.fullmatch(command.strip()):
        return True
    program = re.match(r"(?:\S*/)?([\w.-]+)", command)
    tool = program.group(1).lower() if program else ""
    if tool in ("mvn", "mvnw", "gradle", "gradlew") and re.search(r"(?<!\S)(?:-o|--offline)(?!\S)", command):
        return True
    if tool == "cargo" and (re.search(r"(?<!\S)(?:--frozen|--offline)(?!\S)", command)
                            or re.search(r"--config[=\s]+['\"]?net\.offline\s*=\s*true", command)
                            or re.search(r"\bCARGO_NET_OFFLINE=['\"]?true\b", before)):
        return True
    if tool == "npx" and re.search(r"(?<!\S)--(?:no-install|no)(?![\w=-])", command):
        return True             # `npx --no-install tool` runs a package already installed and fetches nothing
    if tool == "dotnet":
        if re.search(r"(?<!\S)--no-restore(?!\S)", command) and not re.match(r"\S+\s+restore\b", command):
            return True
        # `dotnet test --no-build`, `dotnet publish --no-build`: no build, so no restore (it implies `--no-restore`)
        if re.search(r"(?<!\S)--no-build(?!\S)", command) and re.match(r"\S+\s+(?:test|publish|pack|run)\b", command):
            return True
        # `--source ./packages`: the restore reads only the folders named, in place of every configured feed
        sources = re.findall(r"(?<!\S)(?:--source|-s)(?:=|\s+)(\S+)", command)
        if sources and not any("://" in s or s.startswith("$") for s in sources):
            return True
    if tool == "go":
        env = before.rsplit(";", 1)[-1].rsplit("&&", 1)[-1]
        if re.search(r"(?<!\S)-mod=vendor(?!\S)", command) or re.search(
                r"\b(?:GOFLAGS=['\"]?[^'\"\s]*-mod=vendor|GOPROXY=['\"]?off\b)", env):
            return True
    return False


def _offline_install(command: str) -> bool:
    """A package install that reads only this machine: `--no-index` / `--offline`, or `--no-deps` with every package
    named a local file (a wheel, or a path with build isolation off). With the index off pip still fetches what the
    command names by address (`--find-links https://...`, `git+https://...`, a wheel's URL), so a command naming one is
    not offline."""
    command = _launcher_own_part(command)
    if re.search(r"(?<!\S)--(?:no-index|offline)(?![\w-])", command):
        return not (re.search(r"(?i)(?:git|hg|svn|bzr)\+", command) or any(
            m.group(1).lower() != "file" for m in re.finditer(r"(?i)([a-z][a-z0-9+.-]*)://", command)))
    if not re.search(r"(?<!\S)--no-deps(?![\w-])", command):
        return False
    words = command.split()
    verb = next((k for k, w in enumerate(words) if w in ("install", "add", "i")), None)
    if verb is None:
        return False
    named, k = [], verb + 1
    while k < len(words):
        w = words[k]
        if w in ("-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url"):
            return False                # a requirements file or an index: packages come from elsewhere
        if w.startswith("-"):
            # an option whose value is not a package (`-t dir`, `--find-links ./wheels`); `-e path` names one
            k += 2 if w in ("-t", "--target", "--prefix", "--root", "-f", "--find-links", "--python", "--platform") else 1
            continue
        named.append(w)
        k += 1
    local = all(not w.startswith("@") and (w.startswith((".", "/", "~")) or re.match(r"[A-Za-z]:[\\/]", w) or "/" in w
                                           or w.lower().endswith(".whl"))      # (`nettacker-*.whl` in the working folder)
                for w in named)
    wheels = all(w.endswith(".whl") for w in named)
    return bool(named) and local and "://" not in command and (
        wheels or re.search(r"(?<!\S)--no-build-isolation(?![\w-])", command) is not None)


def _check_script(path: Path, rel: str, text: str | None = None) -> list[Finding]:
    """Commands in a script, build recipe or pipeline file that reach the network, and URLs
    outside comments. Line-based: no shell is parsed, variables are not expanded. `text`, when given, is read
    in place of the file (a decoded `-EncodedCommand` script)."""
    suffix = _reads.suffix_of(path).lower()
    style = "batch" if suffix in (".bat", ".cmd") else "powershell" if suffix in (".ps1", ".psm1", ".psd1") else "posix"
    if text is None:
        try:
            text = _reads.read_text(path)
        except OSError:
            return []
    token = _ESCAPE_STYLE.set(style)
    db_token = _DB_HOST_ELSEWHERE.set(_DB_HOST_ELSEWHERE.get() or _db_host_elsewhere(text))
    try:
        return _check_script_lines(path, rel, text)
    finally:
        _DB_HOST_ELSEWHERE.reset(db_token)
        _ESCAPE_STYLE.reset(token)


# `NAME = value`, `NAME := value`, `NAME ?= value` (a value of words, variables and paths, with no shell syntax in it)
_MAKE_SIMPLE_VARIABLE_RE = re.compile(
    r"^(?:export\s+|override\s+)?([A-Za-z_][\w-]*)\s*(?::{1,3}|\?)?=\s*([\w./+@:=,$(){}-]+(?:[ \t]+[\w./+@:=,$(){}-]+)*)\s*$")
_MAKE_REFERENCE_RE = re.compile(r"\$\(([A-Za-z_][\w-]*)\)|\$\{([A-Za-z_][\w-]*)\}")
_MAKE_FUNCTION_RE = re.compile(r"[$][({][a-z-]+[ \t]")
# a recipe line whose command starts with a variable (`\t@$(PIP) install -r requirements.txt`)
_MAKE_RECIPE_VARIABLE_RE = re.compile(r"^(\t[ \t@+-]*)\$(?:\(([A-Za-z_][\w-]*)\)|\{([A-Za-z_][\w-]*)\})((?:[ \t].*)?)$")


def _make_programs_named(lines: list[str]) -> list[str]:
    """A Makefile's lines with `$(NAME)` and `${NAME}` written as the value of a variable the file sets to plain words
    (`PIP = pip`, `PIP := $(VENV)/bin/pip`, `PIP = $(PYTHON) -m pip`, `KUBECTL ?= kubectl --context prod`), read
    through the variables it names, so `$(PIP) install requests` is read as the command it runs. A variable set more
    than once is read when every value starts with the same program (`pip` in one branch, `pip3` in another); one set
    another way (`+=`, `!=`, `$(shell ...)`) is left as written, as is a name the file does not set (`$(HOME)`).
    One set to different programs in different conditional branches is read once per value (`py -m pip install ...`
    and `pip3 install ...` on the same line); a later plain assignment replaces what came before it."""
    # each assignment with whether it stands inside a conditional (`ifeq ... else ... endif`)
    assignments: dict[str, list[tuple[str | None, bool]]] = {}
    depth = 0
    defining: list = []         # inside `define NAME` ... `endef`: [name, inside a conditional, body lines]
    for ln in lines:
        if defining:
            if re.match(r"^\s*endef\b", ln):
                body = [x.strip() for x in defining[2] if x.strip()]
                assignments.setdefault(defining[0], []).append(
                    (body[0] if len(body) == 1 and not _MAKE_FUNCTION_RE.search(body[0]) else None, defining[1]))
                defining = []
            else:
                defining[2].append(ln)
            continue
        if re.match(r"^\s*(?:ifeq|ifneq|ifdef|ifndef)\b", ln):
            depth += 1
        elif re.match(r"^\s*endif\b", ln):
            depth = max(0, depth - 1)
        d = re.match(r"^\s*(?:(?:export|override|private)\s+)*define\s+([A-Za-z_][\w-]*)", ln)
        if d:
            defining = [d.group(1), depth > 0, []]
            continue
        # `NAME op value`, with `export`, `override` or `private` before it and a comment after it set aside
        a = re.match(r"^(?:(?:export|override|private)\s+)*([A-Za-z_][\w-]*)\s*(::?=|:::=|\?=|\+=|!=|=)\s*(.*?)\s*$",
                     re.sub(r"(?<!\\)\s+#.*$", "", ln))
        if not a or ln[:1] == "\t":
            continue
        name, op, rhs = a.groups()
        rhs = re.sub(r"\$[({]strip\s+([^(){}]*)[)}]", r"\1", rhs).strip()        # `$(strip git)` is `git`
        before = assignments.get(name, [])
        prior = before[-1][0] if before else None
        # a reference to the name's own value (`FETCH := $(FETCH) -C repo`), read as the value it had
        if prior is not None and re.search(r"\$[({]" + re.escape(name) + r"[)}]", rhs):
            rhs = re.sub(r"\$[({]" + re.escape(name) + r"[)}]", lambda _r: prior, rhs)
        elif re.search(r"\$[({]" + re.escape(name) + r"[)}]", rhs):
            rhs = None
        if op == "?=" and before:
            continue                            # set only when it has no value, and it has one
        if op == "!=" or rhs is None or _MAKE_FUNCTION_RE.search(rhs) \
                or not re.fullmatch(r"[\w./+@:=,$(){}~ \t-]*", rhs):
            value = None                        # set by a command or a function: not read
        elif op == "+=":
            value = (prior + " " + rhs).strip() if prior is not None and before else (rhs if not before else None)
        else:
            value = rhs
        assignments.setdefault(name, []).append((value, depth > 0))
    # the values a name may hold where its recipes run: an assignment outside any conditional replaces what came
    # before it (`TOOL = pip` then `TOOL = echo` is `echo`); those after it, inside branches, are alternatives
    values: dict[str, list[str | None]] = {}
    for k, v in assignments.items():
        last_plain = max((i for i, (_, inside) in enumerate(v) if not inside), default=0)
        values[k] = [x for x, _ in v[last_plain:]]

    def expand(text: str, depth: int = 0) -> str:
        if depth > 6:
            return text
        return _MAKE_REFERENCE_RE.sub(
            lambda r: expand(chosen[r.group(1) or r.group(2)], depth + 1)
            if (r.group(1) or r.group(2)) in chosen else r.group(0), text)

    def program(text: str) -> str:
        first = text.split()[0] if text.split() else ""
        return re.sub(r"[\d.]+$", "", first.rsplit("/", 1)[-1])

    chosen: dict[str, str] = {}
    for k, v in values.items():
        if v and None not in v:
            chosen[k] = v[0]
    # a name with more than one value is read only when each, read through the others, runs the same program
    branches: dict[str, list[str]] = {}
    for k, v in list(values.items()):
        if k in chosen and len(v) > 1 and len({program(expand(x)) for x in v}) != 1:
            del chosen[k]
            branches[k] = list(dict.fromkeys(v))
    out = []
    for ln in lines:
        q = re.match(r"^(\t[ \t@+-]*)\$[({]([A-Za-z_][\w-]*)[)}](?=[\w./$])", ln)
        if q and q.group(2) not in branches and (
                q.group(2) not in chosen or expand(chosen[q.group(2)]).strip() in ("", "@", "-", "+", "@-", "-@")):
            # `$(AT)git pull` with `AT = @` or unset: a prefix that silences the recipe line, not a program
            ln = q.group(1) + " " * (q.end() - len(q.group(1))) + ln[q.end():]
        m = _MAKE_RECIPE_VARIABLE_RE.match(ln)
        name = (m.group(2) or m.group(3)) if m else None
        if name and name in branches and not ln.rstrip().endswith("\\"):
            # set to different programs in different branches: each is a command this line may run
            ln = m.group(1) + " ; ".join(expand(v) + m.group(4) for v in branches[name])
        if "$" in ln and chosen and not _MAKE_SIMPLE_VARIABLE_RE.match(ln):
            ln = _MAKE_REFERENCE_RE.sub(lambda r: expand(chosen[r.group(1) or r.group(2)])
                                        if (r.group(1) or r.group(2)) in chosen else r.group(0), ln)
        out.append(ln)
    return out


# `NAME=value` alone on a line (`PIP="$VENV/bin/pip"`, `export AWS=aws`), a value of one word
_SHELL_ASSIGNMENT_RE = re.compile(r"""^\s*(?:export\s+|readonly\s+|local\s+|declare\s+)?([A-Za-z_]\w*)="""
                                  r"""(?:"([^"\s`]*)"|'([^'\s]*)'|([^\s"'`;&|()<>]*))\s*(?:#.*)?$""")
# a variable standing where a line's command starts, quoted or not (`"$PIP" install`, `sudo ${AWS} s3 ls`)
_SHELL_PROGRAM_VARIABLE_RE = re.compile(
    r"""^(\s*(?:(?:sudo|exec|nohup|time|command|env)\s+)*)("?)\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))\2(?=\s|$)""")


def _dockerfile_programs_named(lines: list[str]) -> list[str]:
    """A Dockerfile's lines with a variable that starts a `RUN` command written as its value, when an `ENV` or `ARG`
    sets it once to one word (`ENV PIP_CMD=pip` then `RUN ${PIP_CMD} install requests`)."""
    counts: dict[str, int] = {}
    values: dict[str, str] = {}
    for ln in lines:
        d = re.match(r"(?i)^\s*(?:ENV|ARG)\s+(.*)$", ln)
        if not d:
            continue
        pairs = re.findall(r"""([A-Za-z_]\w*)(?:=(?:"([^"\s$]*)"|([^\s"'$]*)))?""", d.group(1))
        legacy = re.fullmatch(r"([A-Za-z_]\w*)\s+([^\s=\"'$]+)\s*", d.group(1))     # `ENV NAME value`
        if legacy:
            pairs = [(legacy.group(1), "", legacy.group(2))]
        for name, quoted, plain in pairs:
            counts[name] = counts.get(name, 0) + 1
            if quoted or plain:
                values[name] = quoted or plain
    once = {k: v for k, v in values.items() if counts.get(k) == 1}
    if not once:
        return lines
    out = []
    for ln in lines:
        m = re.match(r"(?i)^(\s*RUN\s+(?:--\S+\s+)*)\$\{?([A-Za-z_]\w*)\}?(?=\s)", ln)
        if m and m.group(2) in once:
            ln = m.group(1) + once[m.group(2)] + ln[m.end():]
        out.append(ln)
    return out


def _windows_programs_named(lines: list[str], batch: bool) -> list[str]:
    """A batch or PowerShell script's lines with a variable that starts a command written as its value, when the
    script sets it once, alone on a line, to one word: `set VCS=git` then `%VCS% pull`, `$vcs = "git"` then `& $vcs
    pull`. A variable set more than once, or not by the script, is left as written."""
    if batch:
        set_re = re.compile(r"""(?i)^\s*@?set\s+"?([A-Za-z_][\w]*)=([^"\s&|<>%]+)"?\s*$""")
        any_set = re.compile(r"(?i)^\s*@?set\s+(?:/[ap]\s+)?\"?([A-Za-z_][\w]*)=")
        use = r"""^(\s*@?)%{}%(?=\s|$)"""
    else:
        set_re = re.compile(r"""^\s*\$([A-Za-z_]\w*)\s*=\s*(?:"([^"\s$`]+)"|'([^'\s]+)')\s*;?\s*$""")
        any_set = re.compile(r"\$([A-Za-z_]\w*)\s*[+\-]?=")
        use = r"""^(\s*&\s*)(?:\$\{{{0}\}}|"\${0}"|\${0})(?=\s|$)"""
    counts: dict[str, int] = {}
    values: dict[str, str] = {}
    for ln in lines:
        m = set_re.match(ln)
        for a in any_set.finditer(ln):
            counts[a.group(1).lower()] = counts.get(a.group(1).lower(), 0) + 1
        if m:
            values[m.group(1).lower()] = next(g for g in m.groups()[1:] if g)
    once = {k: v for k, v in values.items() if counts.get(k) == 1}
    if not once:
        return lines
    out = []
    for ln in lines:
        for name, value in once.items():
            r = re.match(use.format(re.escape(name)), ln, re.IGNORECASE)
            if r:
                ln = r.group(1) + value + ln[r.end():]
                break
        out.append(ln)
    return out


def _shell_programs_named(lines: list[str]) -> list[str]:
    """A shell script's lines with a variable that starts a line's command written as its value, when the script sets
    it once, alone on a line, to one word (`PIP="$VENV/bin/pip"` then `"$PIP" install requests`). A variable set more
    than once, or not by the script, is left as written."""
    # each assignment with whether it stands inside a conditional or a loop (`if ... fi`, `case ... esac`, `for ...
    # done`): a later one outside them replaces what came before (`T=ls` then `T=cat` runs `cat`)
    sets: dict[str, list[tuple[str, bool]]] = {}
    depth = 0
    for ln in lines:
        words = re.findall(r"(?:^|[\s;&|(])(if|case|for|while|until|fi|esac|done)(?=[\s;&|)]|$)", ln)
        m = _SHELL_ASSIGNMENT_RE.match(ln)
        if m:
            sets.setdefault(m.group(1), []).append((next(g for g in m.group(2, 3, 4) if g is not None), depth > 0))
        else:
            for a in re.finditer(r"(?:^|[\s;&|(])([A-Za-z_]\w*)\+?=", ln):
                sets.setdefault(a.group(1), []).append(("", True))      # set some other way: not read
            for a in re.finditer(r"\bread\s+(?:-\w+\s+)*([A-Za-z_]\w*)", ln):
                sets.setdefault(a.group(1), []).append(("", True))
        for w in words:
            depth = depth + 1 if w in ("if", "case", "for", "while", "until") else max(0, depth - 1)
    values: dict[str, list[str]] = {}
    for k, v in sets.items():
        last_plain = max((i for i, (_, inside) in enumerate(v) if not inside), default=0)
        values[k] = list(dict.fromkeys(x for x, _ in v[last_plain:]))

    def program(value: str) -> str:
        return re.sub(r"(?i)[\d.]*(?:\.exe)?$", "", value.rsplit("/", 1)[-1])
    # one value, or values in branches that all run the same program (`PIP="$VENV/bin/pip"` or `PIP="pip"`)
    once = {k: v[0] for k, v in values.items()
            if v and all(v) and len({program(x) for x in v}) == 1}
    # `PYTHON=${1:-python}`: the default is the program, as `${CURL:-curl}` written in place is
    once = {k: (d.group(1) if (d := re.fullmatch(r"\$\{\w+:?-([^${}]+)\}", v)) else v) for k, v in once.items()}
    if not once:
        return lines
    out = []
    for ln in lines:
        m = _SHELL_PROGRAM_VARIABLE_RE.match(ln)
        name = (m.group(3) or m.group(4)) if m else None
        if name in once and not _SHELL_ASSIGNMENT_RE.match(ln):
            ln = m.group(1) + once[name] + ln[m.end():]
        out.append(ln)
    return out


# variables make itself sets to its own programs: `$(MAKE) install` runs make's install target
_MAKE_BUILTIN_PROGRAMS = {"MAKE", "CC", "CXX", "CPP", "LD", "AR", "AS", "RM", "INSTALL", "MKDIR", "LN", "SHELL",
                          "ECHO", "FC", "LEX", "YACC", "TAR", "CP", "MV"}
# a program given by a variable (`$VCS`, `"${PIP}"`, `$(INSTALLER)`, `$(firstword $(TOOLS))`, cmd's `%VCS%`) and the
# subcommand after it, where that subcommand fetches for the programs that have it
_UNRESOLVED_PROGRAM_RE = re.compile(
    r"""("?\$(?:\{\w+\}|\w+|\((?:[^()\n]|\([^()\n]*\))*\))"?|%\w+%)"""
    r"""[ \t]+(install|update|upgrade|pull|push|clone|fetch|sync|download|ci|add|restore|get|i)(?![\w.-])""")


def _exec_form_as_words(line: str) -> str:
    """A Dockerfile instruction in exec form (`RUN ["pip", "install", "requests"]`) with the separators between its
    words set to spaces, so the words read as the command they are (`RUN ["pip   install   requests"]`); the length
    is unchanged. Any other line is returned as it is."""
    m = re.match(r"""(?i)^\s*(?:ONBUILD\s+)?(?:RUN|CMD|ENTRYPOINT|HEALTHCHECK(?:\s+--\S+)*\s+CMD)(?:\s+--\S+)*\s+\[""", line)
    if not m:
        return line
    end = line.rfind("]")
    if end < m.end():
        return line
    inner = line[m.end():end]
    if "\\" in inner or not re.fullmatch(r'\s*"[^"]*"(?:\s*,\s*"[^"]*")*\s*', inner):
        return line                     # an element with an escape in it, or not a plain list of strings
    # each element's quotes and the commas between them set to spaces; the element a shell runs (after `-c`, `/c`,
    # `-Command`) keeps its quotes, as the shell's own command string does: `sh -c "pip install x"`
    chars = list(re.sub(",", " ", inner))
    elements = list(re.finditer(r'"([^"]*)"', inner))
    for k, e in enumerate(elements):
        if k and elements[k - 1].group(1).lower() in ("-c", "/c", "-command"):
            continue
        chars[e.start()] = chars[e.end() - 1] = " "
    return line[:m.end() - 1] + " " + "".join(chars) + " " + line[end + 1:]


def _check_script_lines(path: Path, rel: str, text: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    if text is None:
        try:
            text = _reads.read_text(path)
        except OSError:
            return out
    batch = _reads.suffix_of(path).lower() in (".bat", ".cmd")
    pipeline = _reads.suffix_of(path).lower() in (".yml", ".yaml")
    ini = _reads.suffix_of(path).lower() in (".ini", ".cfg")
    # in a Makefile a line that defines a variable holds the command; it runs where `$(NAME)` is used
    makefile = path.name.lower() in ("makefile", "gnumakefile") or _reads.suffix_of(path).lower() == ".mk"
    low = path.name.lower()
    dockerfile = low in ("dockerfile", "containerfile") or low.startswith(("dockerfile.", "containerfile.")) \
        or _reads.suffix_of(path).lower() in (".dockerfile", ".containerfile")
    comment = ("rem ", "::", "@rem ") if batch else ("#", ";") if ini else ("#",)
    if _reads.suffix_of(path).lower() in (".ps1", ".psm1", ".psd1"):
        # `<# ... #>` is a block comment (comment-based help lives in one); line count kept
        text = _blank_spans(text, _delimited_spans(text, (("<#", "#>"),)), lambda s: "\n" * s.count("\n"))
    # lines end where the shell ends them, at a line feed: a form feed, a vertical tab or a Unicode line separator is a
    # character inside a line (`str.splitlines` would end lines there that the shell does not)
    lines = _shell_lines(text)
    if dockerfile:
        # `# syntax=docker/dockerfile:1`, a parser directive above the first instruction: the build runs with that
        # frontend image, pulled from a registry when it is not already on this machine
        for k, ln in enumerate(lines, 1):
            directive = re.match(r"\s*#\s*([A-Za-z]+)\s*=\s*(\S+)", ln)
            if not directive:
                break
            if directive.group(1).lower() == "syntax":
                out.append(Finding(rel, k, "declared-remote-source",
                                   f"# syntax={directive.group(2)[:120]} names the build frontend image, pulled from a "
                                   "registry when it is not already present"))
    if makefile:
        lines = _make_programs_named(lines)
    elif not (pipeline or dockerfile or batch or ini) and _ESCAPE_STYLE.get() == "posix":
        lines = _shell_programs_named(lines)
    elif batch or _ESCAPE_STYLE.get() == "powershell":
        lines = _windows_programs_named(lines, batch)
    elif dockerfile:
        lines = _dockerfile_programs_named(lines)
    if pipeline:
        lines = _fold_yaml_commands(lines)
        lines = _blank_action_inputs(lines)
        # a step written as a flow map (`- {name: x, run: "pip install requests"}`): its `run:` value is a command, as
        # it is written on a line of its own; the keys before it are blanked, the length kept
        lines = [_FLOW_MAP_RUN_RE.sub(lambda m: " " * (m.end(1) - m.start()) + m.group(2), ln) if "{" in ln else ln
                 for ln in lines]
        lines = [_RUN_MAP_COMMAND_RE.sub(lambda m: m.group(1) + " " * (len(m.group(2)) + len(m.group(3))), ln)
                 if "command" in ln else ln for ln in lines]
        lines = [_flow_commands_line(ln) if "[" in ln else ln for ln in lines]
    agent_images: dict[int, str] = {}
    if low == "jenkinsfile" or low.endswith(".jenkinsfile") or low.startswith("jenkinsfile."):
        # a Jenkins step runs its string: `sh 'curl ...'`, `bat "..."`, `powershell(script: '...')`
        lines = [_jenkins_step_line(ln) for ln in lines]
        # `agent { docker { image 'python:3' } }`, on one line or several: the job runs in that image, pulled from a
        # registry; `docker {` there is a block of the pipeline, not a command
        for n, ln in enumerate(lines):
            for d in re.finditer(r"\bdocker\s*\{", ln):
                depth, k, at = 0, n, d.end() - 1
                while k < len(lines) and k < n + 50:
                    text = lines[k][at:] if k == n else lines[k]
                    img = re.search(r"""\bimage\s*\(?\s*['"]([^'"\s]+)['"]""", text)
                    if img and depth >= 0:
                        agent_images[k] = img.group(1)
                        break
                    depth += text.count("{") - text.count("}")
                    if depth <= 0 and k > n:
                        break
                    k += 1
        lines = [re.sub(r"\bdocker(?=\s*\{)", "      ", ln) for ln in lines]
    # the character that continues a line: `\` in a POSIX shell and a Dockerfile, `^` in cmd, a backquote in PowerShell,
    # and in a Dockerfile whatever its `# escape=` directive names (a Windows image's paths end in `\`)
    cont_char = "^" if batch else "`" if _reads.suffix_of(path).lower() in (".ps1", ".psm1", ".psd1") else "\\"
    if dockerfile:
        for ln in lines:
            directive = re.match(r"\s*#\s*escape\s*=\s*(\S)\s*$", ln, re.I)
            if directive:
                cont_char = directive.group(1)
                if cont_char == "`":
                    _ESCAPE_STYLE.set("batch")      # a Windows image: RUN goes to cmd
                break
            if not re.match(r"\s*#\s*[A-Za-z]+\s*=", ln):
                break                               # parser directives come first or not at all
    make_held = _make_variable_lines(lines) if makefile else set()
    # Each line -> the indices it stands at, for here-document ends. The shell ends a body only at a line that is the
    # terminator exactly (`<<-` strips leading tabs first); a pipeline's block, a recipe and a Jenkins string carry
    # indentation their own format strips before the shell sees the lines, so there the terminator is compared stripped.
    # (a Makefile, a justfile, a Jenkinsfile or a Procfile has no extension and is not one: its recipes and steps are
    # lines its own program hands to a shell)
    shell_file = dockerfile or low in (".envrc",) or _reads.suffix_of(path).lower() in (
        ".sh", ".bash", ".zsh", ".ksh", ".dash", ".command") or (
        not _reads.suffix_of(path) and low not in SCRIPT_NAMES and low != ".justfile")
    line_at: dict[str, list[int]] = {}
    tabs_at: dict[str, list[int]] = {}
    for k, ln in enumerate(lines):
        line_at.setdefault(ln if shell_file else ln.strip(), []).append(k)
        tabs_at.setdefault(ln.lstrip("\t") if shell_file else ln.strip(), []).append(k)
    # a prompt, a note or any other text value of a pipeline file: a program named there is not run there
    make_held |= _yaml_text_lines(lines) if pipeline else set()
    # A pipeline step with `shell: python` runs its `run:` block with Python: the block is read as Python
    # in a pipeline file a here-document ends inside the block of the line that opens it, or not at all
    block_end = _yaml_block_ends(lines) if pipeline else None
    py_steps = _python_run_blocks(lines) if pipeline else _just_python_recipes(lines) if low in (
        "justfile", ".justfile") or low.endswith(".just") else {}
    # a Compose file's `image:` is pulled from a registry, unless its service builds that image here (`build:`)
    compose = pipeline and path.name.lower().startswith(("docker-compose", "compose."))
    compose_pulls = _compose_pulled_images(lines) if compose else _ci_pulled_images(lines) if (
        pipeline and (_CI_FILE_RE.search(rel) or rel in _CI_INCLUDED.get())) else {}
    step_images = _cloudbuild_images(lines) if pipeline and _CLOUDBUILD_FILE_RE.search(rel) else {}
    compose_pulls = {**compose_pulls, **step_images}
    pulled_when = "the service starts" if compose else "the job runs"
    if low == "jenkinsfile" or low.endswith(".jenkinsfile") or low.startswith("jenkinsfile."):
        # `docker.image('node:20').inside { ... }`, `docker.image('x').pull()`: the pipeline runs in a pulled image
        compose_pulls = {n: m.group(1) for n, m in
                         ((n, _JENKINS_DOCKER_IMAGE_RE.search(ln)) for n, ln in enumerate(lines)) if m}
        compose_pulls.update({n: image for n, image in agent_images.items() if n not in compose_pulls})
        # Groovy in the pipeline that reaches the network itself: the HTTP Request plugin's step, a URL read
        for n, ln in enumerate(lines):
            if ln.lstrip().startswith(("//", "*", "/*")):
                continue
            g = _JENKINS_GROOVY_NET_RE.search(ln)
            before = ln[:g.start()] if g else ""
            if g and (before.count('"') - before.count('\\"')) % 2 == 0 and before.count("'") % 2 == 0:
                # (not inside a string the line quotes: `echo "use httpRequest"`)
                out.append(Finding(rel, n + 1, "script-network-command",
                                   "runs Jenkins' httpRequest step, which sends an HTTP request" if g.group(1)
                                   else "checks out the job's source from its repository, a fetch from the Jenkins node"
                                   if g.group(2) else
                                   "reads an address in the pipeline's Groovy (`URL.text`, `openStream`, ...), "
                                   "a request from the Jenkins node"))
    docker_stages: set[str] = set()     # the names a Dockerfile gives its stages (`FROM ... AS build`)
    i = 0
    skip: set[int] = set()      # lines of a here-document or step body already read, as text or as Python
    shell_ends: list[int] = []  # terminators of the bodies a shell reads that are open, innermost last
    text_until = -1             # the last line of a body Python reads that is read as lines
    unterminated_checked = -1   # the end of the last body with no terminator already checked as Python
    open_quote = None           # in a script, the quote a string left open at the end of the line before
    while i < len(lines):
        if i in skip:
            i += 1
            continue
        if i in compose_pulls:
            out.append(Finding(rel, i + 1, "declared-remote-source",
                               (f"name: {compose_pulls[i]}: the step runs in this image, pulled from a registry when "
                                if i in step_images else f"image: {compose_pulls[i]}: the image is pulled from a registry when ")
                               + f"{pulled_when} and it is not already present"))
        if i in py_steps:
            end, body = py_steps[i]
            found = _check_python(path, rel, source=body)
            if not any(f.kind == "unparseable-source" for f in found):
                how = "Python run by a `shell: python` step" if pipeline else "Python a recipe runs by its shebang"
                out += [Finding(rel, i + f.line, f.kind, f"{how}: {f.detail}")
                        for f in found]
                judged = {i + f.line for f in found}
                for k in range(i, end):
                    text_k = _GLOB_URL_RE.sub(" ", _PATTERN_URL_RE.sub(" ", lines[k]))
                    if k + 1 not in judged and _has_external_url(text_k):
                        out.append(_script_url_finding(rel, k + 1, text_k))
                skip.update(range(i, end))
                continue
        first = i + 1
        # `python -c "` with its program on the lines that follow, up to the closing quote: the program is Python,
        # checked at its own lines; the command around it is read as one line
        multi = None if batch or makefile or dockerfile else _multiline_inline_python(lines, i)
        if multi:
            end, code, opening, expands = multi
            found = _check_python(path, rel, source=code + "\n")
            if not any(f.kind == "unparseable-source" for f in found):
                out += [Finding(rel, i + f.line, f.kind, f"Python passed inline (`python -c`): {f.detail}")
                        for f in found]
                if not expands:
                    judged = {i + f.line for f in found}
                    for k in range(i + 1, end):
                        text_k = _GLOB_URL_RE.sub(" ", _PATTERN_URL_RE.sub(" ", lines[k]))
                        if k + 1 not in judged and _has_external_url(text_k):
                            out.append(_script_url_finding(rel, k + 1, text_k))
                    # the command is read from the closing line on (it may go on with a trailing backslash), reported
                    # at the line it opened on
                    lines[end] = opening
                    i = end
        # a command continued with a trailing backslash is one command: what follows an
        # install verb on later lines is its list of packages, not commands being run
        parts = []
        start_indent = _yaml_indent(lines[i])
        while True:
            piece = lines[i]
            if not batch:
                piece = _TRAILING_COMMENT_RE.sub("", piece)
            # an odd run of the continuation character continues the line; an even one ends with that character
            # escaped (`echo C:\\`, `^^` in cmd, a doubled backquote in PowerShell)
            trail = len(piece.rstrip()) - len(piece.rstrip().rstrip(cont_char))
            cont = trail % 2 == 1
            parts.append(piece.rstrip()[:-1] if cont else piece)
            i += 1
            if not cont or i >= len(lines):
                break
            if dockerfile:
                # a comment line inside a continued instruction is dropped and the instruction goes on
                while i < len(lines) and lines[i].lstrip().startswith("#"):
                    i += 1
                if i >= len(lines):
                    break
            # in a pipeline file a step, a list item or a key at the command's own margin or left of it is not part
            # of the command: YAML ended the value before it (`- run: echo C:\` then `- run: npm ci`)
            if pipeline and lines[i].strip() and (_yaml_indent(lines[i]) < start_indent or (
                    _yaml_indent(lines[i]) == start_indent and re.match(r"\s*(?:-\s|-$|[\w.-]+\s*:(?:\s|$))", lines[i]))):
                break
        stripped = " ".join(x.strip() for x in parts).strip()
        if not stripped or stripped.lower().startswith(comment):
            continue
        if makefile and parts and parts[0][:1] == "\t":
            stripped = re.sub(r"^[@+-]+\s*", "", stripped)
        if dockerfile:
            stripped = _exec_form_as_words(stripped)
        # `git.exe pull`, `& "C:\Program Files\Git\bin\git.exe" pull`: the program by its bare name
        stripped = _normalize_programs(stripped)
        # Every here-document opened on this line, in order: the first body starts on the next line, each later one
        # where the one before it ended (`cat <<A; python3 - <<B`). An opener inside quotes is text
        # (`echo 'PROMPT<<PROMPT_EOF'` is a CI output's delimiter), and one with no terminator line after where its
        # body would start is not a here-document at all.
        body_start = i
        # A line inside a body that is still open: in a body Python reads (one that did not parse, read as lines
        # here) an opener is Python text, not a here-document; in a body a shell reads, an opener is one only if its
        # terminator comes before the enclosing body's, since the shell ends that body at its own terminator first.
        while shell_ends and shell_ends[-1] < first - 1:
            shell_ends.pop()
        in_text = first - 1 <= text_until
        opened: list[int] = []
        # In a script the shell reads as written, quoting is followed across lines (a string may span them), so an
        # opener inside a string that opened on an earlier line is text; elsewhere each line is quoted on its own.
        if shell_file and not batch:
            quoted, quote_after, _ = _shell_quote_scan(stripped, open_quote)
        else:
            quoted, quote_after = (_quote_regions(stripped) if not batch and "<<" in stripped else []), None
        masked_line = None
        read = 0
        for doc in (_HEREDOC_RE.finditer(stripped) if not batch and not in_text else ()):
            if any(qs <= doc.start() <= qe for qs, qe in quoted):
                continue
            before = stripped[:doc.start()]
            if (len(before) - len(before.rstrip("\\"))) % 2:
                continue                    # `\<<EOF`: an escaped `<` is a character, not an opener
            if before.rfind("${") > before.rfind("}"):
                continue                    # inside a parameter expansion (`${x:-<<EOF}`)
            if masked_line is None:
                masked_line = list(stripped)
                for qs, qe in quoted:
                    masked_line[qs:qe + 1] = " " * (min(qe + 1, len(stripped)) - qs)
                masked_line = "".join(masked_line)
            unquoted_before = masked_line[:doc.start()]
            if unquoted_before.count("((") > unquoted_before.count("))"):
                continue                    # a shift inside arithmetic (`$((1 << 2))`, `(( x << 3 ))`)
            read += 1
            if read > _HEREDOCS_PER_LINE:
                # each opener is judged against its whole command, so a line of thousands would take time in
                # proportion to their square; the rest are reported as not read rather than passed over
                out.append(Finding(rel, first, "unparseable-source",
                                   f"more than {_HEREDOCS_PER_LINE} here-documents open on this line; the rest were NOT "
                                   "analysed, and absence of findings in their bodies is not evidence of absence"))
                break
            term, body_quoted = _heredoc_word(doc)
            ends = (tabs_at if stripped[doc.start():doc.start() + 3] == "<<-" else line_at).get(term, ())
            k_end = bisect.bisect_left(ends, body_start)
            j = ends[k_end] if k_end < len(ends) else None
            if j is not None and shell_ends and j >= shell_ends[-1]:
                j = None                    # the enclosing body ends first: this one has no terminator inside it
            if j is not None and block_end is not None and j >= block_end[first - 1]:
                j = None                    # a line `EOF` in a later step or value is not this step's terminator
            unterminated = j is None
            if unterminated:
                # With no terminator the shell reads the body to the end of its input: the end of the file, or of the
                # enclosing body a shell reads. Only in a script the shell reads as written; elsewhere (a pipeline
                # block, a recipe line) an opener with no terminator is left as a line. Either way nothing is hidden:
                # the lines stay command lines, and a body Python reads is also checked as Python, so text taken for
                # an opener by mistake cannot swallow what follows it.
                if not shell_file:
                    continue
                j = shell_ends[-1] if shell_ends else len(lines)
                if j <= unterminated_checked:
                    break                   # a body already checked to that end holds this one
            seg_s, seg_e = _command_around(stripped, doc.start())
            segment = stripped[seg_s:seg_e]
            to_file = _HEREDOC_TO_FILE_RE.search(segment) or re.search(r"(?:^|[\s|])tee\s+(?:-a\s+)?[^\s|;&<>-]", segment)
            # a body written to a `.py` file (`cat > x.py <<EOF`, `tee x.py <<EOF`, a Dockerfile's `COPY <<EOF x.py`)
            # is Python that runs when that file does
            target = _HEREDOC_TARGET_RE.search(segment)
            # (a Dockerfile's `COPY <<EOF /entry.sh` writes its body to that file, as `cat > /entry.sh <<EOF` does)
            to_file = to_file or (target is not None and dockerfile)
            written_py = target is not None and target.group(target.lastindex).strip("'\"").endswith((".py", ".pyw"))
            # an interpreter that reads the body is handed it whatever its own output is sent to
            # (`python3 - <<EOF > out.json`); `>` decides only for a program that writes the body out (`cat > x <<EOF`)
            is_python = written_py or _python_reads_heredoc(stripped, doc) or not to_file and (
                # a Dockerfile `RUN <<EOF` whose body starts with a Python shebang runs that body with Python
                dockerfile and body_start < j and _DOCKER_RUN_ONLY_RE.fullmatch(stripped[seg_s:doc.start()]) is not None
                and _PYTHON_SHEBANG_RE.match(lines[body_start].strip()) is not None)
            if unterminated:
                if is_python:
                    unterminated_checked = j
                    body = lines[body_start:j]
                    found = _check_python(path, rel, source=textwrap.dedent("\n".join(body)) + "\n")
                    if not any(f.kind == "unparseable-source" for f in found):
                        out += [Finding(rel, body_start + f.line, f.kind,
                                        f"Python read from a here-document with no terminator: {f.detail}")
                                for f in found]
                break                       # its body runs to the end of what the shell reads: no opener follows it
            if is_python:
                # `python - <<EOF ... EOF`: the body is Python, checked as Python at its own lines. A body that does
                # not parse, or an unquoted one in which the shell runs a command first (`$(curl ...)`), is read as
                # lines.
                body = lines[body_start:j]
                if stripped[doc.start():doc.start() + 3] == "<<-":
                    body = [ln.lstrip("\t") for ln in body]
                expands = not body_quoted and any(_has_substitution(ln, makefile) for ln in body)
                # inside a pipeline's block (`run: |`) or a recipe the body carries the block's indentation, which the
                # shell hands over too; Python reads it at the margin the YAML or recipe strips
                found = _check_python(path, rel, source=textwrap.dedent("\n".join(body)) + "\n")
                if expands or any(f.kind == "unparseable-source" for f in found):
                    text_until = max(text_until, j)
                if not any(f.kind == "unparseable-source" for f in found):
                    how = (f"Python a here-document writes to {target.group(target.lastindex)}" if written_py
                           else "Python read from a here-document")
                    out += [Finding(rel, body_start + f.line, f.kind, f"{how}: {f.detail}") for f in found]
                    if not expands:
                        # Python, with no command the shell runs inside it first: its lines are not shell lines
                        judged = {body_start + f.line for f in found}
                        for k, body_line in enumerate(lines[body_start:j]):
                            # an address on a line the Python check said nothing about is still an address here
                            text_k = _GLOB_URL_RE.sub(" ", _PATTERN_URL_RE.sub(" ", body_line))
                            if body_start + k + 1 not in judged and _has_external_url(text_k):
                                out.append(_script_url_finding(rel, body_start + k + 1, text_k))
                        skip.update(range(body_start, j + 1))
            elif (not to_file or _writes_text_file(target)) and not _heredoc_runs_as_code(stripped, seg_s, segment,
                                                                                           doc.start()):
                # A here-document handed to a program that is not a shell or an interpreter is text it reads:
                # `cat <<EOF` prints it, `cat <<EOF | gh release create --notes-file=-` makes it release notes.
                # Its lines are read for addresses, not for commands. The opening line itself is a command line.
                for k in range(body_start, j):
                    text = _GLOB_URL_RE.sub(" ", _PATTERN_URL_RE.sub(" ", lines[k]))
                    if _has_external_url(text):
                        out.append(_script_url_finding(rel, k + 1, text))
                skip.update(range(body_start, j + 1))
            else:
                opened.append(j)                    # a body a shell or another program reads, read as lines here
            body_start = j + 1
        shell_ends.extend(sorted(opened, reverse=True))
        if shell_file and not batch and not in_text:
            open_quote = quote_after
        if dockerfile:
            km = _DOCKER_INSTR_RE.match(stripped)
            if km:
                stripped = km.group(1).upper() + stripped[km.end(1):]
        base = _DOCKER_FROM_RE.match(stripped) if dockerfile else None
        if base:
            # `FROM python:3.12 AS build`: the builder pulls the base image from a registry unless it is already
            # present; `FROM scratch` and an earlier stage's name pull nothing
            image = base.group(1)
            if image.lower() != "scratch" and image.lower() not in docker_stages:
                out.append(Finding(rel, first, "declared-remote-source",
                                   f"FROM {image}: the base image is pulled from a registry when the image is built and "
                                   "is not already present"))
            if base.group(2):
                docker_stages.add(base.group(2).lower())
            continue
        mount_from = _DOCKER_MOUNT_FROM_RE.search(stripped) if dockerfile else None
        if mount_from and mount_from.group(1).lower() not in docker_stages and not mount_from.group(1).isdigit():
            # `RUN --mount=type=bind,from=nginx:latest ...` mounts an image, pulled when it is not already present
            out.append(Finding(rel, first, "declared-remote-source",
                               f"RUN --mount from={mount_from.group(1)} mounts an image, pulled from a registry when it "
                               "is not already present"))
        exec_form = _DOCKER_EXEC_FORM_RE.match(stripped) if dockerfile else None
        if exec_form:
            # `RUN ["python", "-c", "import socket"]`: the exec form hands its array to the program as argv
            try:
                argv = json.loads(exec_form.group(1))
            except (ValueError, RecursionError):
                argv = None
            if isinstance(argv, list) and all(isinstance(a, str) for a in argv) and len(argv) > 2 \
                    and _PYTHON_EXE_RE.match(_argv_basename(argv[0])) and "-c" in argv[1:-1]:
                code = argv[argv.index("-c", 1) + 1]
                found = _check_python(path, rel, source=code + "\n")
                if not any(f.kind == "unparseable-source" for f in found):
                    out += [Finding(rel, first, f.kind, f"Python given by the exec form `{exec_form.group(0)[:3]}`: "
                                    f"{f.detail}") for f in found]
                    continue
        copy_from = _DOCKER_COPY_FROM_RE.match(stripped) if dockerfile else None
        if copy_from and copy_from.group(1).lower() not in docker_stages and not copy_from.group(1).isdigit():
            out.append(Finding(rel, first, "declared-remote-source",
                               f"COPY --from={copy_from.group(1)} copies from an image, pulled from a registry when it "
                               "is not already present"))
            continue
        add = _DOCKER_ADD_URL_RE.match(stripped) if dockerfile else None
        if add:
            # `ADD https://host/file /dst`: the builder downloads the address when the image is built
            if add.group(1).startswith("git@") or _has_external_url(add.group(1)):
                out.append(Finding(rel, first, "script-network-command",
                                   "ADD fetches an address when the image is built, a command that reaches the network"))
            else:
                out.append(Finding(rel, first, "loopback-call",
                                   "ADD fetches an address on this machine when the image is built; nothing leaves it"))
            continue
        if pipeline and _YAML_LABEL_RE.match(stripped):
            continue        # a step's `name:` is a label that is shown, not a command that runs
        if pipeline and _YAML_BARE_KEY_RE.match(stripped):
            continue        # `ssh:` on its own line names a service or a section
        # Each command of the line is judged on its own (`curl --version && curl ... | sh`, `nc -l 9000 & git pull`):
        # one that reaches nothing, or only this machine, does not speak for the rest. Once a command has been
        # reported as reaching further, the line has said what it does.
        line_start = len(out)
        for stripped in _split_commands(stripped):
            # an address only mentioned (`echo "see https://..." && curl ... | sh`), or a program only named (`hash curl
            # && curl ... | sh`, `mytool curl x; curl ... | sh`), does not end the judging either
            if any(f.kind not in ("loopback-call", "inbound-listener", "external-url", "script-network-word")
                   for f in out[line_start:]):
                break
            parsed: list[tuple[int, int]] = []        # `python -c` strings that parse: read as Python
            reported: list[tuple[int, int]] = []      # ... and that the Python check reported on
            for item in _inline_python(stripped, makefile):
                qs, qe, code, expands = item[:4]
                how = item[4] if len(item) > 4 else "passed inline (`python -c`)"
                found = _check_python(path, rel, source=code + "\n")
                if any(f.kind == "unparseable-source" for f in found):
                    continue                              # shell expansions inside: read as a script line
                if not expands:
                    # a word the shell runs a command inside is also left to the script rules, which see that command
                    parsed.append((qs, qe))
                    if found:
                        reported.append((qs, qe))
                out += [Finding(rel, first, f.kind, f"Python {how}: {f.detail}") for f in found]
            for qs, qe, code, program in _inline_javascript(stripped, makefile):
                # `node -e "fetch('https://...')"`, `bun -e ...`, `deno eval ...`: the code is JavaScript, read by the
                # JavaScript rules
                src = _strip_js_comments(code)
                found = [f for f in _js_import_findings(src, rel, None) + _js_expression_findings(code, src, rel)
                         if f.kind != "unparseable-source"]
                parsed.append((qs, qe))
                if found:
                    reported.append((qs, qe))
                out += [Finding(rel, first, f.kind, f"JavaScript passed inline (`{program}`): {f.detail}") for f in found]
            # an address inside inline Python the Python check said nothing about (a client it does not know) is still
            # an address written on this line
            if reported:
                masked_line = list(stripped)
                for qs, qe in reported:
                    masked_line[qs + 1:qe] = " " * (qe - qs - 1)
                plain = "".join(masked_line)
            else:
                plain = stripped
            # A download tool named with nothing after it is a word in a list (a package to
            # install, an entry in a variable), not a command being run.
            printed_line = _PRINTED_RE.match(stripped)
            held = first in make_held or _holds_command_text(stripped)
            # PowerShell's .NET clients: `(New-Object System.Net.WebClient).DownloadFile(...)` runs where it is written
            dotnet = None if printed_line else next(
                (m for m in _DOTNET_NET_RE.finditer(stripped)
                 if not any(qs < m.start() < qe for qs, qe in parsed) and not _in_printed_part(stripped, m.start())), None)
            if dotnet:
                out.append(Finding(rel, first, "script-network-word" if held else "script-network-command",
                                   "uses a .NET network client (WebClient, HttpClient, a socket)"
                                   + (", in a place this line is NOT shown to run it from" if held
                                      else ", a command that reaches the network")))
                continue
            # bash opens a connection when a path under /dev/tcp or /dev/udp is redirected to or read
            # a UNC path (`\\server\share\x.exe`) in a PowerShell or batch command is a file on another machine (SMB)
            uncs = [] if printed_line or held or _ESCAPE_STYLE.get() == "posix" else list(_UNC_RE.finditer(stripped))
            unc = next((u for u in uncs if not _UNC_THIS_MACHINE_RE.fullmatch(u.group(1))), None)
            if uncs and not unc:
                out.append(Finding(rel, first, "loopback-call",
                                   "reads or writes a UNC path on this machine (`\\\\localhost\\...`, a WSL file system); "
                                   "nothing leaves it at this line"))
                continue
            if unc:
                out.append(Finding(rel, first, "script-network-command",
                                   "reads or writes a path on another machine (a UNC path, reached over SMB), a command "
                                   "that reaches the network"))
                continue
            # Windows' remote administration tools given a machine as `\\server` (`psexec \\srv`, `net view \\srv`,
            # `sc \\srv query`, `reg query \\srv\HKLM\...`)
            admin = None if printed_line or held or _ESCAPE_STYLE.get() == "posix" else _REMOTE_ADMIN_RE.search(stripped)
            at = next((k for k in (1, 4, 6) if admin and admin.group(k)), None)
            if admin and _at_command_start(stripped, admin.start(at)):
                tool = admin.group(at).split()[0]
                host = admin.group(2) or admin.group(5) or admin.group(7)
                if host is None:
                    out.append(Finding(rel, first, "script-network-command",
                                       f"runs {tool!r} against the machines listed in {admin.group(3)}, a command that "
                                       "reaches the network"))
                elif _UNC_THIS_MACHINE_RE.fullmatch(host):
                    out.append(Finding(rel, first, "loopback-call",
                                       f"runs {tool!r} against this machine; nothing leaves it at this line"))
                else:
                    out.append(Finding(rel, first, "script-network-command",
                                       f"runs {tool!r} against another machine (\\\\{host}), a command that reaches the "
                                       "network"))
                continue
            dev_tcp = None if printed_line or held else _DEV_TCP_RE.search(stripped)
            if dev_tcp and _THIS_MACHINE_HOST_RE.fullmatch(dev_tcp.group(1).strip("[]")):
                out.append(Finding(rel, first, "loopback-call",
                                   "opens a connection through the shell's /dev/tcp or /dev/udp to an address on this "
                                   "machine; nothing leaves it at this line"))
                continue
            if dev_tcp:
                out.append(Finding(rel, first, "script-network-command",
                                   "opens a connection through the shell's /dev/tcp or /dev/udp, a command that reaches "
                                   "the network"))
                continue
            # `powershell -EncodedCommand <base64>`: the command is the decoded text, read as a PowerShell script
            for shell in (() if printed_line else _ENCODED_COMMAND_RE.finditer(stripped)):
                # `Start-Process powershell -ArgumentList '-enc','<base64>'` starts it with its arguments as a list
                lo = max(0, shell.start() - 200)        # the look-back is bounded: a line of launchers stays linear
                started = re.search(r"\bStart-Process\s+(?:-FilePath\s+)?['\"]?$", stripped[lo:shell.start()], re.IGNORECASE)
                if not _at_command_start(stripped, shell.start()) and not (
                        started and _at_command_start(stripped, lo + started.start())):
                    continue
                args = _first_command(stripped[shell.end():])
                if started:
                    args = re.sub(r"""['",@()]""", " ", args)
                # the first option that is a prefix of -EncodedCommand, whatever options come before it
                enc = next((a for a in _ENCODED_ARG_RE.finditer(args)
                            if _ENCODED_FLAG_RE.fullmatch(a.group(1))), None)
                if enc is None:
                    continue
                try:
                    decoded = base64.b64decode(enc.group(2), validate=True).decode("utf-16-le")
                except (ValueError, UnicodeDecodeError):
                    out.append(Finding(rel, first, "dynamic-exec",
                                       "powershell -EncodedCommand with text that does not decode as UTF-16; the command "
                                       "it runs is NOT read"))
                    continue
                out += [Finding(rel, first, f.kind, f"in a -EncodedCommand script: {f.detail}")
                        for f in _check_script(Path("encoded.ps1"), rel, text=decoded)]
            hit = None if printed_line else next(
                (m for m in _SCRIPT_NET_COMMAND_RE.finditer(stripped)
                 if not any(qs < m.start() < qe for qs, qe in parsed)
                 and ((m.start() == m.start(1) and not stripped[m.end(1):m.end()]) or _at_command_start(stripped, m.start())
                      or (makefile and _make_runs_now(stripped, m.start())))
                 and (m.group(1).lower() not in _BARE_TOOLS
                      # the program xargs runs takes its arguments from what xargs reads (`cat urls | xargs -n1 wget`)
                      or _XARGS_RUNS_RE.search(stripped, max(0, m.start() - 200), m.start()) is not None or (
                     # something follows the name (looked at in place, not by copying the rest of a long line)
                     _TRAILING_PUNCT_RE.match(stripped, m.end()).end() < len(stripped)
                     # `--run-optional-tests=ssh,sudo`: a value handed to an option, or an item in a list
                     and stripped[m.start() - 1:m.start()] not in ("=", ",")
                     and stripped[m.end():m.end() + 1] != ","))
                 and not _in_printed_part(stripped, m.start())), None)
            # In a Makefile, `X := $(shell curl ...)` and `X != curl ...` run the command when make reads the file
            make_now = bool(hit) and makefile and _make_runs_now(stripped, hit.start())
            held = held and not make_now
            at_start = bool(hit) and (make_now or _at_command_start(stripped, hit.start()))
            if not hit and not printed_line:
                # programs judged by their arguments, by the same rules as the argv lists Python hands them
                argv_found = _script_argv_findings(rel, first, stripped, parsed, held, makefile)
                out += argv_found
                if not argv_found:
                    out += _script_install_findings(rel, first, stripped, parsed, held, makefile)
                serves = re.search(r"(?<![\w./-])git\s+(?:-\S+\s+)*(daemon|instaweb)\b", stripped)
                if serves and not held and _at_command_start(stripped, serves.start()):
                    out.append(Finding(rel, first, "inbound-listener",
                                       f"runs 'git {serves.group(1)}', which serves repositories (INBOUND, not egress)"))
                # `python3 -m http.server 8000`: a web server for the folder (INBOUND)
                web = _PYTHON_WEB_SERVER_RE.search(stripped)
                if web and not held and _at_command_start(stripped, web.start()) \
                        and not any(qs < web.start() < qe for qs, qe in parsed) \
                        and not any(qs < web.start() < qe for qs, qe in _quote_regions(stripped)):
                    out.append(Finding(rel, first, "inbound-listener",
                                       f"runs 'python -m {web.group(1)}', a web server for this folder (INBOUND, not "
                                       "egress)"))
            if hit and at_start and not held and _offline_install(_first_command(stripped[hit.start():])) and not \
                    re.search(r"(?i)\bPIP_(?:FIND_LINKS|INDEX_URL|EXTRA_INDEX_URL)\s*=\s*['\"]?(?!file:)[a-z][a-z0-9+.-]*://",
                              stripped[:hit.start()]):
                continue        # `pip install --no-index --find-links ./wheels ...`: installs from this machine only
            if hit and at_start and not held:
                command = _first_command(stripped[hit.start():])
                words = command.split()
                tool = hit.group(1).lower().split()[0]
                if tool in _BARE_TOOLS and len(words) > 1 and (words[1] in ("--version", "-V", "--help") or (
                        tool in ("curl", "wget", "dig", "nc", "ncat") and words[1] in ("-h", "--manual", "-M")
                        and len(words) == 2)):
                    continue    # `curl --version`, `curl -h`: the program reports on itself
                if tool == "npx" and _install_stays_here(command):
                    continue    # `npx --no-install tool`: runs a package already installed and fetches nothing
                if tool == "curl" and "file://" in command and not URL_RE.search(command) and all(
                        w.startswith(("-", "file://", "'file://", '"file://')) or (k > 1 and words[k - 1] in (
                            "-o", "--output", "-H", "--header", "-A", "--user-agent", "-w", "--write-out"))
                        for k, w in enumerate(words[1:], 1)):
                    continue    # `curl file:///etc/hosts`: reads a file on this machine
                if tool == "dig" and re.search(r"(?<!\S)@(?:localhost|127(?:\.\d{1,3}){3}|::1)(?!\S)", command):
                    out.append(Finding(rel, first, "loopback-call",
                                       "runs 'dig' against a name server on this machine; nothing leaves it at this line"))
                    continue
                positional = [w for w in words[1:] if not w.startswith("-")]
                if tool == "nslookup" and len(positional) >= 2 and re.fullmatch(
                        r"localhost|127(?:\.\d{1,3}){3}|::1", positional[1]):
                    # `nslookup name 127.0.0.1`: the server asked is this machine (`nslookup localhost` asks the configured
                    # server, which may be elsewhere)
                    out.append(Finding(rel, first, "loopback-call",
                                       "runs 'nslookup' against a name server on this machine; nothing leaves it at this "
                                       "line"))
                    continue
                clone = re.search(r"\bclone\b((?:\s+-{1,2}[\w=-]+(?:\s+(?=-))?)*)\s+(\S+)", command) if tool == "git" else None
                if clone and re.match(r"""['"]?(?:\.|/|~|file://|[A-Za-z]:[\\/])""", clone.group(2)):
                    continue    # `git clone ./local /tmp/x`: a repository on this machine
                if tool in ("nc", "ncat", "netcat") and re.search(r"(?<!\S)(?:--listen|-[A-Za-z]*l[A-Za-z]*)(?!\S)", command):
                    out.append(Finding(rel, first, "inbound-listener",
                                       f"runs {tool!r} listening for connections (INBOUND, not egress)"))
                    continue
            if hit and (not at_start or held):
                # named where no command starts (an argument, text inside `echo '...'`): reported, smaller claim
                out.append(Finding(rel, first, "script-network-word",
                                   f"names {' '.join(hit.group(1).split())!r}, a program that reaches the network, "
                                   "in a place this line is NOT shown to run it from"))
                continue
            if hit and hit.group(1).lower() in ("curl", "wget") and URL_RE.search(stripped) and not _has_external_url(stripped):
                # `curl http://localhost:8086/ping`: every address on the line is this machine
                out.append(Finding(rel, first, "loopback-call",
                                   f"runs {hit.group(1)!r} against an address on this machine; nothing leaves it at this line"))
            elif hit and hit.group(1).lower() in _HOST_TOOLS and _SCRIPT_LOOPBACK_ARG_RE.search(stripped[hit.end():]) \
                    and not _has_external_url(stripped) and not _ssh_routed(hit.group(1), stripped[hit.end():]):
                # `nc -z localhost 4100`, `ssh user@127.0.0.1`: the host named is this machine
                out.append(Finding(rel, first, "loopback-call",
                                   f"runs {hit.group(1)!r} against an address on this machine; nothing leaves it at this line"))
            elif hit and hit.group(1).lower() in _COPY_TOOLS and at_start and not held \
                    and (hosts := _REMOTE_SPEC_HOST_RE.findall(_first_command(stripped[hit.end():]))) \
                    and all(_THIS_MACHINE_HOST_RE.fullmatch(h) for h in hosts) \
                    and not re.search(r"\$|\w+://", _first_command(stripped[hit.end():])) \
                    and not _ssh_routed(hit.group(1), stripped[hit.end():]):
                # `scp dist.tgz localhost:/srv/`: every host it names is this machine
                out.append(Finding(rel, first, "loopback-call",
                                   f"runs {hit.group(1)!r} against an address on this machine; nothing leaves it at this line"))
            elif hit and hit.group(1).lower() in _COPY_TOOLS and at_start \
                    and not _REMOTE_SPEC_RE.search(_first_command(stripped[hit.end():])):
                # `rsync -a docs/_build/html/ docs/gh-pages/current/`: every place named is on this machine (an
                # argument held in a variable could be a host, so a line with one is still reported)
                continue
            elif hit and not held and at_start:
                out.append(Finding(rel, first, "script-network-command",
                                   f"runs {' '.join(hit.group(1).split())!r}, a command that reaches the network"))
            elif hit:
                # The program's name is on the line, but not where a command starts: an argument, a value,
                # a word in text. Reported, with a claim that stops at the name.
                out.append(Finding(rel, first, "script-network-word",
                                   f"names {' '.join(hit.group(1).split())!r}, a program that reaches the network, "
                                   "in a place this line is NOT shown to run it from"))
            elif _has_external_url(_GLOB_URL_RE.sub(" ", _PATTERN_URL_RE.sub(" ", plain))):
                out.append(_script_url_finding(rel, first, _GLOB_URL_RE.sub(" ", _PATTERN_URL_RE.sub(" ", plain))))
        # a line with a command that reaches further says so once; an address an earlier command only mentions is
        # then part of that claim, as it was when the line was judged whole
        if any(f.kind not in ("loopback-call", "inbound-listener", "external-url") for f in out[line_start:]):
            out[line_start:] = [f for f in out[line_start:] if f.kind != "external-url"]
        # a line that runs a network command does run one: that it also names a program elsewhere is not reported as
        # "NOT shown to run it". A line that only names programs is reported once, for the first it names.
        if any(f.kind == "script-network-command" for f in out[line_start:]):
            out[line_start:] = [f for f in out[line_start:] if f.kind != "script-network-word"]
        else:
            words = [k for k, f in enumerate(out[line_start:]) if f.kind == "script-network-word"]
            out[line_start:] = [f for k, f in enumerate(out[line_start:]) if k not in words[1:]]
        # a command whose program is a variable this file does not resolve, run with a subcommand that fetches
        # (`$(INSTALLER) install requests`, `"$VCS" pull`): what runs is not shown, and that it may fetch is
        unresolved = None if len(out) > line_start else _UNRESOLVED_PROGRAM_RE.search(stripped)
        if unresolved and re.sub(r"[\"$%(){}]", "", unresolved.group(1)) in _MAKE_BUILTIN_PROGRAMS:
            unresolved = None       # `$(MAKE) install`: make's own variable for make, running a target here
        if unresolved and _at_command_start(stripped, unresolved.start(1)) \
                and not any(qs < unresolved.start(1) < qe for qs, qe in _quote_regions(stripped)):
            out.append(Finding(rel, first, "unresolved-call",
                               f"runs the program {' '.join(unresolved.group(1).split())} names, with "
                               f"{unresolved.group(2)!r}, a subcommand that fetches for the package managers and "
                               "version control tools that have it; which program runs is NOT shown"))
    return out


# Line magics that run Python: the statement after `%time`, `%timeit`, `%prun` or `%debug` (with the options of each
# that take a value), and the modules `%aimport`, `%load_ext`, `%reload_ext` and `%run -m` import.
_PYTHON_LINE_MAGICS = {"time": "", "timeit": "nrp", "prun": "DTls", "debug": "b"}
_LONG_VALUE_OPTIONS = {"breakpoint"}
_IMPORT_LINE_MAGICS = {"aimport", "load_ext", "reload_ext", "run"}
# IPython's own extensions, which `%load_ext` finds inside IPython
_IPYTHON_EXTENSIONS = {"autoreload", "storemagic"}
_LINE_MAGIC_RE = re.compile(r"([ \t]*)%([A-Za-z_]\w*)(?![\w.%])[ \t]*(.*)$")
# Cell magics whose body is Python (run, timed, profiled, debugged, captured, or written to a file).
_PYTHON_CELL_MAGICS = {"writefile", "file", "python", "python3", "pypy", "time", "timeit", "capture", "prun", "debug"}
_PYTHON_CELL_MAGIC_RE = re.compile(r"%%(?:" + "|".join(sorted(_PYTHON_CELL_MAGICS)) + r")\b")
# Cell magics whose body is markup the notebook displays, not code the kernel runs.
_DISPLAY_CELL_MAGICS = {"html", "HTML", "markdown", "latex", "svg", "javascript", "js"}   # `HTML` is IPython's alias
_MODULE_NAME_RE = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*")


def magic_python(magic: str, text: str) -> str:
    """The Python a line magic runs: `%timeit -n 10 f()` runs `f()`. `%time` takes no options."""
    words = text.strip()
    takes = _PYTHON_LINE_MAGICS.get(magic)
    if not takes:
        return words
    while words.startswith("-"):
        m = re.match(r"-(-[\w-]+|[A-Za-z])(\S*)\s*", words)
        if not m:
            break
        words = words[m.end():]
        opt = m.group(1)
        takes_value = opt[1:] in _LONG_VALUE_OPTIONS if opt.startswith("-") else opt in takes
        if takes_value and not m.group(2):
            words = re.sub(r"^\S+\s*", "", words, count=1)
    return words


def line_magic_python(magic: str, text: str) -> str | None:
    """The Python a line magic runs, "" for one that runs none, None for a magic that is not one of these."""
    if magic in _PYTHON_LINE_MAGICS:
        return magic_python(magic, text)
    if magic not in _IMPORT_LINE_MAGICS:
        return None
    words = [w for w in re.split(r"[\s,]+", text.strip()) if w]
    if magic == "run":
        # `%run -m module`: the module is imported and run; `%run script.py` runs a file the scan reads on its own
        mods = [words[words.index("-m") + 1]] if "-m" in words and words.index("-m") + 1 < len(words) else []
    elif magic == "aimport":
        mods = [w for w in words if not w.startswith("-")]          # `%aimport -x` excludes x
    else:
        mods = [w for w in words[:1] if w not in _IPYTHON_EXTENSIONS]
    mods = [w for w in mods if _MODULE_NAME_RE.fullmatch(w)]
    return "import " + ", ".join(mods) if mods else ""


# `files = !ls`, `out = %sx curl ...`, `a, b = %time f()`: IPython assigns what a shell escape or a line magic returns
_ASSIGN_MAGIC_RE = re.compile(r"(\s*)(?:[A-Za-z_]\w*(?:\.\w+)*\s*,\s*)*[A-Za-z_]\w*(?:\.\w+)*\s*,?\s*=\s*(?=[!%])")


def _unassigned(line: str) -> str:
    """A notebook line that assigns a shell escape's or a magic's result, as the escape or magic itself (its indent
    kept); any other line unchanged."""
    m = _ASSIGN_MAGIC_RE.match(line)
    return m.group(1) + line[m.end():] if m else line


# IPython's help request: `requests.get?`, `obj??`, `?np.load`, `np.*load*?`; it shows documentation and runs nothing
_IPYTHON_HELP_RE = re.compile(r"\s*(?:\?{1,2}\s*[\w.*]+|[\w.*]+(?:\(\))?\?{1,2})\s*(?:#.*)?")


def _magic_lines(text: str) -> list[bool]:
    """For each line of a cell: is it a magic or a shell escape? Only a line that starts a statement can be one; inside
    brackets, a string or a continued line, `%` and `!` are Python (`!= x`, `% n` on Black's continuation lines)."""
    out: list[bool] = []
    depth, quote, cont = 0, None, False
    for ln in text.splitlines():
        if depth == 0 and quote is None and not cont and (_unassigned(ln).lstrip().startswith(("%", "!"))
                                                          or _IPYTHON_HELP_RE.fullmatch(ln)):
            out.append(True)
            continue
        out.append(False)
        i, n = 0, len(ln)
        while i < n:
            c = ln[i]
            if quote:
                if c == "\\":
                    i += 2
                    continue
                if ln.startswith(quote, i):
                    i += len(quote)
                    quote = None
                    continue
                i += 1
                continue
            if c == "#":
                break
            if c in "\"'":
                quote = ln[i:i + 3] if ln[i:i + 3] in ('"""', "\'\'\'") else c
                i += len(quote)
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth = max(0, depth - 1)
            i += 1
        cont = ln.rstrip().endswith("\\") and quote is None
        if quote in ('"', "'") and not ln.rstrip().endswith("\\"):
            quote = None            # a one-line string ends with its line
    return out


def notebook_line_python(line: str) -> str | None:
    """A notebook line that is a Python line magic, as the Python it runs at the same indent; None otherwise."""
    m = _LINE_MAGIC_RE.match(line)
    if not m:
        return None
    code = line_magic_python(m.group(2), m.group(3))
    return None if code is None else m.group(1) + code


def notebook_code_cells(data) -> list[tuple[int, str]] | None:
    """The code cells of a notebook as (number, text), numbered from 1 over all cells. nbformat 4 keeps cells in
    `cells` with the code in `source`; nbformat 3 keeps them in `worksheets[].cells` with the code in `input`. None for
    any other layout: a notebook this tool cannot read is not a notebook with no code."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("cells"), list):
        cells, field_name = data["cells"], "source"
    elif isinstance(data.get("worksheets"), list):
        cells = [c for w in data["worksheets"] if isinstance(w, dict) and isinstance(w.get("cells"), list)
                 for c in w["cells"]]
        field_name = "input"
    else:
        return None
    out: list[tuple[int, str]] = []
    for number, cell in enumerate(cells, start=1):
        if not isinstance(cell, dict):
            return None         # a cell that is not an object: not a layout Jupyter opens
        if cell.get("cell_type") == "code":
            source = cell.get(field_name, "")
            if not (isinstance(source, str) or (isinstance(source, list) and all(isinstance(s, str) for s in source))):
                return None     # code that is not text (`"source": 5`)
            out.append((number, "".join(source) if isinstance(source, list) else source))
    return out


def _cell_python(text: str) -> str:
    """A code cell as the Python it runs: shell escapes and other magics blanked (line numbers hold), magics that run
    Python kept as their code, and a `%%timeit` line's setup statement kept."""
    lines = text.splitlines()
    magic = _magic_lines(text)
    first = next((k for k, ln in enumerate(lines) if ln.strip()), -1)
    kept: list[str] = []
    for k, ln in enumerate(lines):
        if not magic[k]:
            kept.append(ln)
        elif k == first and re.match(r"\s*%%timeit\b", ln):
            kept.append(magic_python("timeit", re.sub(r"^\s*%%timeit", "", ln)))
        else:
            # an indented escape or magic (`    !curl ...` in a function) is a statement where it stands
            indent = ln[:len(ln) - len(ln.lstrip())]
            kept.append(notebook_line_python(_unassigned(ln)) or (indent + "pass" if indent else ""))
    return "\n".join(kept) + "\n"


def _exported_magic_code(node: ast.AST) -> tuple[str, str, str] | None:
    """`get_ipython().run_cell_magic('time', '', body)` or `get_ipython().run_line_magic('timeit', code)`, as nbconvert
    writes a Python magic: (method, magic, the code it runs). None for any other call."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("run_cell_magic", "run_line_magic") and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name) and node.func.value.func.id == "get_ipython"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        return None
    texts = [a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else None for a in node.args[1:3]]
    method, magic = node.func.attr, node.args[0].value
    if method == "run_line_magic" and texts and texts[0] is not None:
        code = line_magic_python(magic, texts[0])
        return (method, magic, code) if code else None
    if method == "run_cell_magic" and magic in _PYTHON_CELL_MAGICS and len(texts) == 2 and texts[1] is not None:
        setup = magic_python("timeit", texts[0] or "") if magic == "timeit" else ""
        return method, magic, (setup + "\n" if setup else "") + texts[1]
    return None


def exported_magic_units(src: str) -> list[tuple[str, int]]:
    """The Python inside the magic calls of a notebook exported as a script, each at the line of its call."""
    if "get_ipython" not in src:
        return []
    try:
        tree = _parse_quietly(src)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    return [(_cell_python(hit[2]), node.lineno) for node in ast.walk(tree)
            for hit in [_exported_magic_code(node)] if hit]


def python_units(path: Path) -> list[tuple[str, int | None]] | None:
    """The Python a file holds, the way the auditor reads it, as (source, cell) pairs: a `.py` or `.pyw` file, a file
    with no extension and a Python shebang, the start-up lines of a text `.pth` file (other lines blanked, so line
    numbers hold), and the code cells of a notebook (nbformat 3 or 4), numbered from 1 (shell escapes and magics
    blanked, Python line magics kept as their code; a cell handed to another program by a cell magic left out). In a
    notebook exported as a script, the Python inside a `get_ipython().run_cell_magic('time', ...)` call is a unit of
    its own at the call's line. None when the file holds no Python. A notebook that is not JSON, or not a layout this
    tool reads, raises ValueError."""
    suffix = _reads.suffix_of(path).lower()
    if _is_python_file(path, suffix):
        try:
            src = _read_python_source(path)
        except (SyntaxError, LookupError, UnicodeDecodeError):
            return [(_reads.read_text(path), None)]
        return [(src, None)] + exported_magic_units(src)
    if suffix in PTH_EXTS and _is_text_pth(path):
        lines = _reads.read_text(path).splitlines()
        return [("\n".join(ln if re.match(r"import[ \t]", ln) else "" for ln in lines) + "\n", None)]
    if suffix in NOTEBOOK_EXTS:
        try:
            data = json.loads(_reads.read_text(path))
        except RecursionError:
            raise ValueError("a notebook nested too deeply to read") from None
        cells = notebook_code_cells(data)
        if cells is None:
            raise ValueError("not a notebook layout this tool reads")
        language = notebook_language(data)
        if language is not None and language not in _PYTHON_KERNEL_LANGUAGES:
            raise NotPythonNotebook(f"a notebook for a {language!r} kernel, whose cells are not Python")
        out: list[tuple[str, int | None]] = []
        for number, text in cells:
            first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
            m = re.match(r"%%(\w+|!)", first)
            if m and m.group(1) in _PROGRAM_CELL_MAGICS | _DISPLAY_CELL_MAGICS | {"!"}:
                continue        # handed to another program, or markup the notebook displays
            out.append((_cell_python(text), number))
        return out
    return None


def _check_notebook(path: Path, rel: str, local_modules: frozenset[str] = frozenset(),
                    shadowed: set[str] | None = None, unlisted: set[str] | None = None,
                    own_names: frozenset[str] = frozenset(),
                    importable: frozenset[str] | None = None) -> list[Finding]:
    """Code cells of a Jupyter notebook (nbformat 3 or 4), checked as Python. `!command` lines are shell
    escapes, as are `%system` and `%sx` lines and cells under a magic that hands them to another program
    (`%%bash`, `%%script`), and `%pip` / `%conda` lines install packages; all are reported. `%time`, `%timeit` and
    `%prun` lines run their text as Python and are checked as Python. Line numbers are cell numbers, counted from 1
    over all cells."""
    try:
        data = json.loads(_reads.read_text(path))
        cells = notebook_code_cells(data)
    except (ValueError, AttributeError, RecursionError):
        data, cells = None, None
    if cells is None:
        return [Finding(rel, 0, "unparseable-source",
                        "could not parse this notebook, so it was NOT analysed; absence of findings here is "
                        "not evidence of absence")]
    language = notebook_language(data)
    if language is not None and language not in _PYTHON_KERNEL_LANGUAGES:
        return [Finding(rel, 0, "unparseable-source",
                        f"a notebook for a {language!r} kernel, whose cells this tool does not read; it was NOT "
                        "analysed, and absence of findings here is not evidence of absence")]
    out: list[Finding] = []
    for number, text in cells:
        out += _check_cell_text(path, rel, number, text, f"cell {number}", local_modules, shadowed, unlisted,
                                own_names, importable)
    # What the notebook shows when it is opened: a markdown cell's images and markup, and the HTML or JavaScript a
    # cell saved as its output, which a trusted notebook renders and runs.
    for number, cell in _notebook_all_cells(data):
        if cell.get("cell_type") == "markdown":
            source = cell.get("source", "")
            text = "".join(x for x in source if isinstance(x, str)) if isinstance(source, list) else str(source)
            out += [Finding(rel, number, f.kind, f"cell {number} (markdown): {f.detail}")
                    for f in _display_cell_findings("markdown", text, rel)]
        outputs = cell.get("outputs")
        for output in outputs if isinstance(outputs, list) else []:
            shown = output.get("data") if isinstance(output, dict) and isinstance(output.get("data"), dict) else {}
            for mime, magic in (("text/html", "html"), ("application/javascript", "javascript"),
                                ("image/svg+xml", "svg"), ("text/markdown", "markdown")):
                value = shown.get(mime)
                # a list holding something other than text (`["fetch(1)", null]`): its text, not a crash
                text = ("".join(x for x in value if isinstance(x, str)) if isinstance(value, list)
                        else value if isinstance(value, str) else "")
                if text:
                    out += [Finding(rel, number, f.kind, f"cell {number}'s saved {mime} output: {f.detail}")
                            for f in _display_cell_findings(magic, text, rel)]
    return out


class NotPythonNotebook(ValueError):
    """A notebook whose kernel speaks another language: it holds no Python, and what it holds was not read as code."""


# Kernel languages whose cells are Python
_PYTHON_KERNEL_LANGUAGES = {"python", "python2", "python3", "ipython", "ipython3", "pypy", "pypy3", "xpython"}


def notebook_language(data) -> str | None:
    """The language a notebook's kernel speaks, from its metadata (`kernelspec.language`, `language_info.name`),
    lower case; None when the notebook does not say."""
    meta = data.get("metadata") if isinstance(data, dict) and isinstance(data.get("metadata"), dict) else {}
    for key, field_name in (("kernelspec", "language"), ("language_info", "name")):
        block = meta.get(key)
        if isinstance(block, dict) and isinstance(block.get(field_name), str) and block[field_name].strip():
            return block[field_name].strip().lower()
    return None


def _notebook_all_cells(data) -> list[tuple[int, dict]]:
    """Every cell of a notebook (nbformat 3 or 4) as (number, cell), numbered from 1, as `notebook_code_cells` numbers."""
    if isinstance(data.get("cells"), list):
        cells = data["cells"]
    else:
        cells = [c for w in data.get("worksheets") or [] if isinstance(w, dict) and isinstance(w.get("cells"), list)
                 for c in w["cells"]]
    return [(n, c) for n, c in enumerate(cells, start=1) if isinstance(c, dict)]


def _check_cell_text(path: Path, rel: str, line: int, text: str, label: str,
                     local_modules: frozenset[str] = frozenset(), shadowed: set[str] | None = None,
                     unlisted: set[str] | None = None, own_names: frozenset[str] = frozenset(),
                     importable: frozenset[str] | None = None, written: bool = False) -> list[Finding]:
    """One notebook cell, or the text of a magic call in an exported script, reported at `line` and named by
    `label`."""
    out: list[Finding] = []
    # IPython runs a cell whose first line (after any blank ones) is indented with that indentation taken off every
    # line that starts with it
    lead = re.match(r"[ \t]+", next((ln for ln in text.split("\n") if ln.strip()), ""))
    if lead:
        text = "\n".join(ln[len(lead.group(0)):] if ln.startswith(lead.group(0)) else ln for ln in text.split("\n"))
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if re.match(r"%%(?:" + "|".join(sorted(_PROGRAM_CELL_MAGICS)) + r")\b|%%!", first):
        # a cell magic hands the whole cell to another program (`%%!` to the shell): it is a script, not Python
        body = text.split("\n", 1)[1] if "\n" in text else ""
        hit = _SHELL_NET_WORD_RE.search(body)
        extra = f"; invokes {hit.group(1)!r}" if hit else ""
        return [Finding(rel, line, "subprocess-shell",
                        f"{label}: `{first[:40]}` runs the cell's text as a program{extra}")]
    cell_magic = re.match(r"%%([A-Za-z_]\w*)", first)
    if cell_magic and cell_magic.group(1) in _DISPLAY_CELL_MAGICS:
        # markup or JavaScript the notebook displays or runs in the browser: read with that reader
        body = text.split("\n", 1)[1] if "\n" in text else ""
        return [Finding(rel, line, f.kind, f"{label} (`{first[:40]}`): {f.detail}")
                for f in _display_cell_findings(cell_magic.group(1), body, rel)]
    if cell_magic and cell_magic.group(1).lower() in _OTHER_LANGUAGE_CELL_MAGICS:
        found = []
        dsn = DSN_RE.search(first)
        if cell_magic.group(1).lower() == "sql" and dsn:
            found = [_dsn_finding(rel, line, label, first)]
        return found + [Finding(rel, line, "unparseable-source",
                                f"{label}: `{first[:40]}` hands the cell to another language, which this tool does "
                                "not read; it was NOT analysed, and absence of findings here is not evidence of "
                                "absence")]
    for ln, is_magic in zip(text.splitlines(), _magic_lines(text)):
        ln = _unassigned(ln)
        stripped = ln.lstrip()
        if not is_magic or notebook_line_python(ln) is not None:
            continue
        if stripped.startswith("!") or re.match(r"%(?:system|sx)\b", stripped):
            hit = _SHELL_NET_WORD_RE.search(stripped)
            extra = f"; invokes {hit.group(1)!r}" if hit else ""
            web = None if hit else _PYTHON_WEB_SERVER_RE.search(stripped)
            if web:
                # `!python -m http.server 8000`: a web server for the folder (INBOUND, not egress)
                extra = f"; runs 'python -m {web.group(1)}', a web server for this folder (INBOUND)"
            out.append(Finding(rel, line, "subprocess-shell",
                               f"{label}: notebook shell escape `{stripped[:80]}`{extra}"))
        elif re.match(r"%alias\s+\S+\s+\S", stripped):
            hit = _SHELL_NET_WORD_RE.search(stripped)
            extra = f"; invokes {hit.group(1)!r}" if hit else ""
            out.append(Finding(rel, line, "subprocess-shell",
                               f"{label}: `{stripped[:80]}` makes a shell command the notebook can run{extra}"))
        elif stripped.startswith("%"):
            loader = re.match(r"%(?:load|loadpy|pycat)\s+(\S+)", stripped)
            if loader and _has_external_url(stripped):
                out.append(Finding(rel, line, "network-call",
                                   f"{label}: `{stripped[:80]}` fetches the URL into the notebook"))
            elif loader and "$" in loader.group(1):
                out.append(Finding(rel, line, "unresolved-call",
                                   f"{label}: `{stripped[:80]}` loads a file or URL named by a variable; what it "
                                   "fetches is NOT resolved"))
            if re.match(r"%+(pip|conda|mamba|uv)\b", stripped):
                out.append(Finding(rel, line, "subprocess-net-binary",
                                   f"{label}: `{stripped[:80]}` installs packages from a remote index"))
            if re.match(r"%+sql\b", stripped) and DSN_RE.search(stripped):
                out.append(_dsn_finding(rel, line, label, stripped))
    if written or re.match(r"%%(?:writefile|file)\b", first):
        where = (f"{label} (its text is written to a file"
                 + (f" by `{first[:40]}`" if not written else "") + ", not run in the notebook)")
        target = re.match(r"%%(?:writefile|file)\s+(?:-a\s+)?(\S+)", first)
        name = target.group(1).strip("'\"") if target else ""
        if name and not name.lower().endswith((".py", ".pyw", ".ipy")):
            # `%%writefile setup.sh`: the text is the file it writes, read as a script when the file is one (as
            # `cat > x.sh <<EOF` is), and otherwise as text nothing in the notebook runs
            if _is_recipe_name(name):
                body = text.split("\n", 1)[1] if "\n" in text else ""
                out += [Finding(rel, line, f.kind, f"{where}: {f.detail}")
                        for f in _check_script(Path(name), rel, text=body)]
            return out
    else:
        where = label
    for f in _check_python(path, rel, local_modules, shadowed, source=_cell_python(text),
                           unlisted=unlisted, own_names=own_names, importable=importable):
        out.append(Finding(rel, line, f.kind, f"{where}: {f.detail}"))
    return out


# Cell magics that hand the cell's text to another program.
_PROGRAM_CELL_MAGICS = {"bash", "sh", "zsh", "script", "system", "sx", "perl", "ruby"}
# Cell magics whose body is another language this tool does not read (compared in lower case).
_OTHER_LANGUAGE_CELL_MAGICS = {"r", "julia", "sql", "cython", "octave", "matlab", "scala", "spark", "sparksql",
                               "bigquery", "kql", "fortran", "cpp", "c", "rust", "go", "java", "kotlin", "node",
                               "typescript", "groovy", "lua", "haskell", "swift", "wolfram", "stata", "sas",
                               "gnuplot", "powershell", "pwsh", "cmd", "dot", "mermaid"}


def _dsn_finding(rel: str, line: int, label: str, text: str) -> Finding:
    """`%sql postgresql://user@db/x`: the magic connects to the database its connection string names."""
    m = DSN_RE.search(text)
    tail = text[m.start():].split()[0] if m else ""
    if _dsn_is_loopback(tail):
        return Finding(rel, line, "loopback-call",
                       f"{label}: `{text[:80]}` connects to a database on this machine; nothing leaves it here")
    return Finding(rel, line, "network-call", f"{label}: `{text[:80]}` connects to the database it names")


def _display_cell_findings(magic: str, body: str, rel: str) -> list[Finding]:
    """A `%%html`, `%%svg`, `%%markdown`, `%%latex` or `%%javascript` cell: markup is read as a page, a markdown
    image as an address the notebook loads when it shows the cell, JavaScript as JavaScript. LaTeX loads nothing."""
    magic = "html" if magic == "HTML" else magic
    if magic in ("javascript", "js"):
        src = _strip_js_comments(body)
        return _js_import_findings(src, rel, None) + _js_expression_findings(body, src, rel)
    if magic == "latex":
        return []
    out = _check_markup(Path("cell.svg" if magic == "svg" else "cell.html"), rel, text=body)
    if magic == "markdown":
        body_starts = _line_starts(body)
        for m in re.finditer(r"!\[[^\]\n]*\]\(\s*<?([^)\s>]+)", body):
            if _has_external_url(m.group(1)) or m.group(1).startswith("//"):
                out.append(Finding(rel, bisect.bisect_right(body_starts, m.start()), "html-external",
                                   "markdown image: the address is loaded when the cell is shown"))
    return out


# Cython source is text by nature and is not read; every other artifact type is binary or a pickle.
_SOURCE_ARTIFACT_EXTS = {".pyx", ".pxd"}
_PICKLE_ARTIFACT_EXTS = {".pkl", ".pickle", ".joblib", ".pt", ".ckpt"}
_ARTIFACT_TEXT_LIMIT = 1 << 20


def _artifact_name_on_text(path: Path, suffix: str) -> bool:
    """A file whose extension names an artifact type but whose content is plain text and not a pickle.

    Extensions are shared: whois samples are named for domains (`sapo.pt`, `google.so`). Compiled,
    archived and serialised content is binary, or (for the serialised types) a pickle, which may be
    text in protocol 0 and is parsed here without being run. Anything uncertain stays an artifact:
    an empty file, a file over 1 MiB, an `ar` or zip header, a NUL byte, bytes that are not UTF-8.
    The size is counted with CRLF line endings as LF, so a checkout that converts them reads the file the same way.
    """
    if suffix in _SOURCE_ARTIFACT_EXTS:
        return False
    try:
        data = _reads.read_head(path, 2 * _ARTIFACT_TEXT_LIMIT + 2)
    except OSError:
        return False
    data = data.replace(b"\r\n", b"\n")
    if not data or len(data) > _ARTIFACT_TEXT_LIMIT or b"\x00" in data or data.startswith((b"!<arch>", b"PK")):
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if suffix in _PICKLE_ARTIFACT_EXTS:
        import pickletools
        try:
            for _ in pickletools.genops(data):
                pass
            return False            # parses as a pickle: it would run what it names when loaded
        except Exception:
            pass
    return True


# git's text test (`text=auto`): control bytes other than backspace, tab, form feed and escape, and DEL, are
# non-printable; bytes from 0x80 up are printable
_GIT_NONPRINTABLE = bytes(b for b in range(32) if b not in (8, 9, 10, 12, 13, 27)) + b"\x7f"
_GIT_NOT_PRINTABLE = _GIT_NONPRINTABLE + b"\n\r"


class _GitTextStats:
    """The counts git keeps to decide whether a file is text it may convert line endings in: a NUL byte or a lone
    CR makes it binary, and so does more than one non-printable byte per 128 printable ones. The decision is the same
    for an LF and a CRLF checkout of one file. Fed in chunks."""

    def __init__(self) -> None:
        self.printable = self.nonprintable = self.cr = self.crlf = 0
        self.nul = self._last_cr = False

    def update(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.nul = self.nul or b"\x00" in chunk
        n = len(chunk)
        self.nonprintable += n - len(chunk.translate(None, _GIT_NONPRINTABLE))
        self.printable += len(chunk.translate(None, _GIT_NOT_PRINTABLE))
        self.cr += chunk.count(b"\r")
        self.crlf += chunk.count(b"\r\n") + (self._last_cr and chunk[:1] == b"\n")
        self._last_cr = chunk.endswith(b"\r")

    def text(self) -> bool:
        return not self.nul and self.cr == self.crlf and (self.printable >> 7) >= self.nonprintable


def _git_text(data: bytes) -> bool:
    s = _GitTextStats()
    s.update(data)
    return s.text()


def _is_text_artifact(path: Path, suffix: str) -> bool:
    """An artifact whose bytes git takes for text, so it converts their line endings: Cython source, a protocol-0
    pickle. Its digest folds CRLF as a text file's does. One git takes for binary (a NUL byte, a lone CR, many control
    bytes: a binary pickle) or one over the reader's limit is hashed byte for byte."""
    try:
        if os.path.getsize(path) > _reads._HOLD_LIMIT:
            return False
        data = _reads.read_bytes(path)
    except OSError:
        return False
    if b"\x00" in data:
        return False
    return suffix in _SOURCE_ARTIFACT_EXTS or _git_text(data)


def _is_text_pth(path: Path) -> bool:
    """A path-configuration file is short text. The same extension is also used for
    binary model checkpoints, which are not read by `site` and are not scanned here."""
    try:
        head = _reads.read_head(path, _PTH_SNIFF_BYTES)
    except OSError:
        return False
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # a multi-byte character cut by the sniff window is still text
        return exc.start >= len(head) - 4
    return True


def _check_pth(path: Path, rel: str, local_modules: frozenset[str] = frozenset(),
               shadowed: set[str] | None = None, unlisted: set[str] | None = None,
               own_names: frozenset[str] = frozenset(),
               importable: frozenset[str] | None = None) -> list[Finding]:
    """Lines of a `.pth` file that `site` executes, analysed as the Python they are.

    `site.addpackage` runs `exec(line)` for every line starting with `import`
    followed by a space or a tab; every other non-comment line is a directory to
    add to `sys.path`. Each executed line is reported as `startup-exec`, which says
    only that the line runs at interpreter start when the file sits in a site
    directory. What the line does is then checked exactly like a `.py` file.
    """
    out: list[Finding] = []
    text = _reads.read_text(path)
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.startswith(("import ", "import\t")):
            continue
        shown = line if len(line) <= 120 else line[:117] + "..."
        out.append(Finding(rel, number, "startup-exec",
                           f"{shown}: a .pth line beginning with `import` is executed by "
                           "Python's site module at every interpreter start when this file "
                           "is in a site directory; modules it imports from outside this "
                           "tree were NOT analysed"))
        for finding in _check_python(path, rel, local_modules, shadowed, source=line,
                                     unlisted=unlisted, own_names=own_names, importable=importable):
            finding.line = number
            out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Markup / JS checks (regex: external refs and network calls)
# ---------------------------------------------------------------------------
# an attribute's quoted value may hold `<` and `>` (`generic="T extends Record<string, unknown>"`); bounded, so
# unclosed quotes keep it linear
_BLOCK_OPEN_RE = re.compile(r"""<(script|style)\b(?:[^<>"']|"[^"\n]{0,512}"|'[^'\n]{0,512}')*>""", re.I)
_BLOCK_CLOSE_RE = {"script": re.compile(r"</script\s*>", re.I), "style": re.compile(r"</style\s*>", re.I)}
_BLOCK_WHOLE_RE = re.compile(r"""(<(script|style)\b(?:[^<>"']|"[^"\n]{0,512}"|'[^'\n]{0,512}')*>)(.*)(</\2\s*>)""",
                             re.S | re.I)


def _tag_blocks(text: str, names: tuple = ("script", "style")) -> list[re.Match]:
    """Each `<script>`/`<style>` block with its closing tag, as a match with groups (opener, name, body, closer).
    Found in one pass: once no closing tag of a kind follows, no later opener of that kind is a block."""
    out, pos, closed_out = [], 0, set()
    while True:
        m = _BLOCK_OPEN_RE.search(text, pos)
        if not m:
            return out
        name = m.group(1).lower()
        if name not in names or name in closed_out:
            pos = m.end()
            continue
        close = _BLOCK_CLOSE_RE[name].search(text, m.end())
        if not close:
            closed_out.add(name)
            pos = m.end()
            continue
        out.append(_BLOCK_WHOLE_RE.fullmatch(text, m.start(), close.end()))
        pos = close.end()


def _markup_script_view(text: str, suffix: str) -> str:
    """The parts of a page or component that are JavaScript, everything else blanked (newlines kept): `<script>`
    blocks that hold code, an Astro component's front matter (server code between its `---` lines), and an MDX
    file's top-level `import`/`export` paragraphs outside fenced code."""
    keep = [False] * len(text)

    def mark(a: int, b: int) -> None:
        keep[a:b] = [True] * (b - a)

    for m in _tag_blocks(text, ("script",)):
        if not _DATA_SCRIPT_TYPE_RE.search(m.group(1)):
            mark(m.start(3), m.end(3))
    if suffix == ".astro":
        fm = re.match(r"\A\ufeff?(?:[ \t]*\r?\n)*---[ \t]*\r?\n(.*?)^---[ \t]*$", text, re.S | re.M)
        if fm:
            mark(fm.start(1), fm.end(1))
    elif suffix == ".mdx":
        fence, pos, k = None, 0, 0
        lines = text.splitlines(keepends=True)
        while k < len(lines):
            line = lines[k]
            f = re.match(r"\s*(```+|~~~+)", line)
            if f and (fence is None or f.group(1)[0] == fence[0]):
                fence = None if fence else f.group(1)
            elif fence is None and re.match(r"(?:import|export)\b", line):
                start = pos
                while k < len(lines) and lines[k].strip():
                    pos += len(lines[k])
                    k += 1
                mark(start, pos)
                continue
            pos += len(line)
            k += 1
    return "".join(c if keep[k] or c == "\n" else " " for k, c in enumerate(text))


# an attribute whose value a browser loads or follows, with the value in quotes
_URL_ATTR_VALUE_RE = re.compile(
    r"""(\b(?:src|href|action|formaction|data|poster|background|srcset|xlink:href|manifest|ping|cite|longdesc|code"""
    r"""|codebase|archive|icon|lowsrc|dynsrc)\s*=\s*)(["'])(.{0,4000}?)\2""", re.IGNORECASE | re.DOTALL)


def _browser_url_view(text: str) -> str:
    """Attribute values that hold an address, as a browser reads them: it drops tabs and line breaks inside a URL
    (`https://ev<tab>il.example.com`) and reads a backslash as a slash (`https:\\\\host\\p.png`). The line breaks
    taken out are written after the value, so every line number still points at the original line."""
    def fix(m: re.Match) -> str:
        value = m.group(3)
        clean = re.sub(r"[\t\r\n]", "", value)
        if re.match(r"(?i)\s*(?:https?|wss?|ftps?)?:?[\\/]{2}", clean) or re.match(r"(?i)\s*(?:https?|wss?|ftps?):", clean):
            clean = clean.replace("\\", "/")
        if clean == value:
            return m.group(0)
        return m.group(1) + m.group(2) + clean + m.group(2) + "\n" * value.count("\n")
    return _URL_ATTR_VALUE_RE.sub(fix, text) if ("\\" in text or "\t" in text or "\n" in text) else text


def _check_markup(path: Path, rel: str, unlisted: set[str] | None = None, text: str | None = None) -> list[Finding]:
    """Markup, a stylesheet or a template, read from `path` (or `text`, read as a file named like `path`)."""
    out: list[Finding] = []
    if text is None:
        try:
            text = _reads.read_text(path)
        except OSError:
            return out
    if _reads.suffix_of(path).lower() != ".css":
        text = _decode_punctuation_entities(_browser_url_view(text))
        # an import in a component's script or front matter is the same import it is in a .js file
        out += _js_import_findings(_strip_js_comments(_markup_script_view(text, _reads.suffix_of(path).lower())), rel, unlisted)
    # A URL inside a comment loads nothing. Comments are blanked with their newlines kept, so every
    # reported line number still points at the original file. Each comment syntax is honoured only
    # where it IS a comment: `/* */` inside <script> and <style> (and in a stylesheet), `<!-- -->`
    # and Jinja `{# #}` outside them. A `<!--` inside a script string, or a `/*` in body text, is
    # not a comment and blanks nothing.
    anchor_lines: set[int] = set()

    def _blank(m: re.Match) -> str:
        return "\n" * m.group(0).count("\n")

    data_only_call_lines: set[int] = set()
    fetching_block_lines: set[int] = set()

    def _spaces(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    def _in_block(m: re.Match) -> str:
        body = m.group(3)
        if m.group(2).lower() != "script":
            return m.group(1) + _CSS_SELECTOR_URL_RE.sub(
                _spaces, _blank_spans(body, _delimited_spans(body, (("/*", "*/"),)), _newlines_only)) + m.group(4)
        if _DATA_SCRIPT_TYPE_RE.search(m.group(1)):
            # `<script type="application/ld+json">` holds data the browser does not execute
            return m.group(1) + re.sub(r"[^\n]", " ", body) + m.group(4)
        # a template comment (`{# ... #}`) is removed by the template engine before any browser sees the script
        body = _blank_spans(body, _delimited_spans(body, (("{#", "#}"),)), _spaces_keep_newlines)
        stripped = _strip_js_comments(body)
        # a call name that only occurs inside a string (embedded data, a message) calls nothing
        first = bisect.bisect_right(block_starts, m.start(3))
        # A script that builds a script or image element, or fetches, loads the addresses it holds: the
        # analytics snippet hands its URL to a function that sets `src` on another line.
        code_only = _js_code_only(stripped)
        if len(code_only) == len(stripped) and any(code_only[s.start()] == stripped[s.start()]
                                                   for s in _SCRIPT_BLOCK_LOADS_RE.finditer(stripped)):
            fetching_block_lines.update(range(first, first + body.count("\n") + 1))
        for k, (with_strings, code) in enumerate(zip(stripped.split("\n"), _js_code_only(body).split("\n"))):
            if NET_CALL_RE.search(with_strings) and not NET_CALL_RE.search(code):
                data_only_call_lines.add(first + k)
        return m.group(1) + _blank_prose_urls(stripped) + m.group(4)

    if _reads.suffix_of(path).lower() == ".css":
        text = _blank_spans(text, _delimited_spans(text, (("/*", "*/"),)), _newlines_only)
        text = _CSS_SELECTOR_URL_RE.sub(_spaces, text)
    else:
        pieces, last = [], 0
        block_starts = _line_starts(text)
        for m in _tag_blocks(text):
            outside = text[last:m.start()]
            pieces.append(_blank_spans(outside, _delimited_spans(outside, _MARKUP_COMMENT_PAIRS), _newlines_only))
            pieces.append(_in_block(m))
            last = m.end()
        tail = text[last:]
        pieces.append(_blank_spans(tail, _delimited_spans(tail, _MARKUP_COMMENT_PAIRS), _newlines_only))
        text = "".join(pieces)
    # Component files keep script outside <script> tags (Astro front matter): `//` line comments
    # there are blanked too. `//` right after `:` or a quote is a URL, not a comment.
    if _reads.suffix_of(path).lower() in {".vue", ".svelte", ".astro"}:
        text = re.sub(r"""(?<![:'"`\\=(])//[^\n]*""", "", text)
    elif _reads.suffix_of(path).lower() in _PAGE_EXTS:
        # In a page, a browser acts on tags, on <script> and <style> blocks and on what a template
        # engine substitutes. Text between tags is displayed: a URL in a paragraph, in a <pre>
        # sample or in entity-escaped markup loads nothing. It is blanked, newlines kept.
        kept, last = [], 0
        for start, end in _page_active_spans(text):
            kept.append(re.sub(r"[^\n]", " ", text[last:start]))
            kept.append(text[start:end])
            last = end
        kept.append(re.sub(r"[^\n]", " ", text[last:]))
        text = "".join(kept)
        # A document type declaration, a metadata tag and a link that only names a relation
        # (canonical, alternate, author) carry identifiers nobody fetches.
        def _inert(m: re.Match) -> str:
            tag = m.group(0)
            if tag[:5].lower() == "<meta" and re.search(r"""http-equiv\s*=\s*['"]?refresh""", tag, re.I):
                return tag                      # a refresh sends the browser somewhere
            return re.sub(r"[^\n]", " ", tag)
        text = _PAGE_INERT_TAG_RE.sub(_inert, text)
    if _reads.suffix_of(path).lower() in _PAGE_EXTS or _reads.suffix_of(path).lower() in {".vue", ".svelte", ".astro"}:
        # An anchor is a link the user must follow. Found per tag, so one written over several
        # lines or carrying other attributes is still an anchor: reported once, at its first line.
        anchor_starts = _line_starts(text)

        def _anchor(m: re.Match) -> str:
            tag = m.group(0)
            # `<a itemtype='https://schema.org/WebPage' href='%s'>`: a vocabulary identifier is not where it points
            target = _VOCAB_ATTR_RE.sub("", _XMLNS_ATTR_RE.sub("", tag))
            if _has_external_url(target) or PROTO_REL_RE.search(target):
                anchor_lines.add(bisect.bisect_right(anchor_starts, m.start()))
            return re.sub(r"[^\n]", " ", tag)
        # (an attribute's quoted value may hold `>`: `<a v-if="n > 1" href=...>`)
        attrs = r"""(?>[^<>"']+|"[^"<]*"|'[^'<]*'|["'])*"""
        text = re.sub(rf"<(?:a|form|area)\b{attrs}>|<(?:button|input)\b(?=[^<>]*\bformaction\b){attrs}>", _anchor, text,
                      flags=re.I)
    # Where the page LOADS from: an attribute that fetches (`src`, `srcset`, `poster`, an object's `data`,
    # `href` on a stylesheet link or an SVG `use`/`image`/`script`, a refresh's `content`). Found per tag,
    # so an attribute on a continuation line is still placed. A URL anywhere else in markup is reported
    # with a claim that stops at what the line shows.
    load_lines: set[int] = set()
    starts = _line_starts(text)
    for m in _MARKUP_TAG_RE.finditer(text):
        tag = m.group(1).lower().rsplit(":", 1)[-1]
        refresh = tag == "meta" and re.search(r"""http-equiv\s*=\s*['"]?refresh""", m.group(2), re.I)
        for a in _MARKUP_ATTR_RE.finditer(m.group(2)):
            attr = a.group(1).lower().rsplit(":", 1)[-1].lstrip("@")
            value = a.group(2)
            if not (_has_external_url(value) or PROTO_REL_RE.search("=" + value)):
                continue
            if (attr in _LOAD_ATTRS or (attr == "data" and tag == "object")
                    or (attr == "href" and tag in _HREF_LOAD_TAGS) or (attr == "style" and CSS_URL_RE.search(value))
                    or (attr == "content" and refresh)
                    # `<base href>` is where every relative `src` and `href` on the page loads from
                    or (attr == "href" and tag == "base" and _page_has_relative_load(text))):
                load_lines.add(bisect.bisect_right(starts, m.start(2) + a.start(2)))
    # A template name bound to an address and used where the page loads from: `{% set u = "https://..." %}`
    # or `{% macro mathjax(url="https://...") %}`, then `<script src="{{ url }}">`. Traced within the file.
    used_for_loading: set[str] = set()
    for m in _MARKUP_TAG_RE.finditer(text):
        tag = m.group(1).lower().rsplit(":", 1)[-1]
        for a in _MARKUP_ATTR_RE.finditer(m.group(2)):
            attr = a.group(1).lower().rsplit(":", 1)[-1].lstrip("@")
            if attr in _LOAD_ATTRS or (attr == "href" and tag in _HREF_LOAD_TAGS) or (attr == "data" and tag == "object"):
                used_for_loading.update(re.findall(r"\{\{-?\s*(\w+)", a.group(2)))
    for k, line in enumerate(text.splitlines(), 1):
        if k in fetching_block_lines or _MARKUP_FETCH_RE.search(line):
            used_for_loading.update(re.findall(r"\{\{-?\s*(\w+)", line))
    if used_for_loading:
        for start, end in _delimited_spans(text, (("{%", "%}"),)):
            for b in re.finditer(r"(?:\bset\s+|[(,]\s*)(\w+)\s*=([^=,)][^,)]*)", text[start:end]):
                if b.group(1) in used_for_loading and (_has_external_url(b.group(2)) or PROTO_REL_RE.search(b.group(2))):
                    load_lines.add(bisect.bisect_right(starts, start + b.start(2)))
    load_lines |= fetching_block_lines
    for i, line in enumerate(text.splitlines(), 1):
        # A namespace declaration or a vocabulary attribute names an identifier; nothing ever fetches it.
        line = _XMLNS_ATTR_RE.sub("", line)
        line = _VOCAB_ATTR_RE.sub("", line)
        line = _SHOWN_TEXT_ATTR_RE.sub("", line)
        stripped = _strip_origin_only_urls(line)
        # An anchor is a link the user must click: reported, and told apart from a load.
        without_anchors = ANCHOR_RE.sub("", stripped)
        loads = _has_external_url(without_anchors) or PROTO_REL_RE.search(without_anchors)
        if not loads and (i in anchor_lines or without_anchors != stripped):
            out.append(Finding(rel, i, "external-link", "link to an external URL; nothing is fetched by loading the page"))
        elif loads and (i in load_lines or CSS_URL_RE.search(without_anchors)
                        or _MARKUP_FETCH_RE.search(without_anchors) or _JS_BRACKET_CALL_RE.search(without_anchors)):
            out.append(Finding(rel, i, "html-external", "external URL / src / href"))
        elif loads:
            out.append(Finding(rel, i, "external-url",
                               "external URL in markup or an inline script, not in a position the page loads from; "
                               "whether anything fetches it is NOT shown"))
        elif stripped != line and not ((NET_CALL_RE.search(line) and i not in data_only_call_lines)
                                       or _JS_BRACKET_CALL_RE.search(line)):
            # (a line that also calls fetch, a WebSocket or sendBeacon is judged by that call, below)
            out.append(Finding(rel, i, "external-url",
                               "URL string used only as a postMessage target origin or an origin comparison: "
                               "no request from this line"))
        elif _DATA_URI_CODE_RE.search(line) or _DATA_URI_SVG_RUNS_RE.search(line):
            # a `data:` URI fetches nothing; one that holds script or a page runs code this tool does not read
            out.append(Finding(rel, i, "dynamic-exec",
                               "a data: URI holding script or a page; the code it holds is NOT read"))
        elif ENTITY_SCHEME_RE.search(line):
            out.append(Finding(rel, i, "html-external", "entity-encoded http scheme"))
        elif (NET_CALL_RE.search(line) and i not in data_only_call_lines and not _JS_BRACKET_CALL_RE.search(line)
              and _js_calls_only_loopback(line)):
            out.append(Finding(rel, i, "loopback-call",
                               "fetch/XHR/WebSocket call given an address on this machine; nothing leaves it at this line"))
        elif (NET_CALL_RE.search(line) and i not in data_only_call_lines) or _JS_BRACKET_CALL_RE.search(line):
            out.append(Finding(rel, i, "network-call", "fetch/XHR/WebSocket/sendBeacon call; the target may be same-origin"))
    return out


# ---------------------------------------------------------------------------
# Content hash. Origin is MerkleSigner (--key): a MAC keyed by published text proves nothing about origin.
# ---------------------------------------------------------------------------


# Fields excluded from the SIGNED body. This set is deliberately minimal: it
# holds ONLY the three fields that cannot be inside the thing they describe.
#
# `signature_algorithm` and `public_root` are INSIDE the signed body, not merely
# displayed beside it. A field a reader relies on to judge a signature has to be
# covered by that signature, or it is decoration: editing either one yields
# TAMPERED rather than a quietly different claim. The displayed algorithm is
# exactly what a counterparty reads to satisfy a cryptography clause, so an
# unauthenticated one would be worse than none at all.
_SIG_FIELDS = {"signature", "content_hash", "integrity_tag"}

# Fields that are properties of THIS ISSUANCE rather than of the audit result.
# Excluding them is what makes `findings_digest` reproducible.
#
# `signature_algorithm` and `public_root` are named here EXPLICITLY rather than
# inherited from `_SIG_FIELDS`. They are now signed, but they must still not
# reach `findings_digest`, or the same audit of the same tree would reproduce
# differently depending on who signed it -- which is the one property
# `findings_digest` exists to provide.
_ISSUANCE_FIELDS = _SIG_FIELDS | {"signature_algorithm", "public_root",
                                  "scanned_at_utc", "findings_digest",
                                  "subject", "parser_python"}

_FILE_TAG = bytes([0])   # domain separation, same discipline as signer.py
_TREE_TAG = bytes([1])
# stands in the subject digest for a file that could not be opened: no content hashes to all zeros
_UNREAD_DIGEST = "00" * 32


def _subject_name(target: Path) -> str:
    """The final path component, resolving relative forms to a real name.

    `Path(".").name` is the empty string, and `.` is the most natural way anyone
    runs this. Resolving gives the report a real `target` and the in-toto Statement
    a real `subject.name`, and only the final component is ever returned, never the
    absolute path.
    """
    target = Path(target)   # callers pass str or Path; a redundant guard at a boundary is cheap
    try:
        on_disk = target.resolve().name
    except OSError:
        on_disk = ""
    name = target.name
    # `.`, `..`, or the same name typed in another case on a file system that ignores case: the name as it is
    # stored, so one folder gives one report however its path was typed. A link's own name is kept.
    short = re.fullmatch(r"[^.~]{1,6}~\d+(?:\.[^.]{0,3})?", name or "") is not None
    if name in ("", ".", "..") or (on_disk and (on_disk.lower() == name.lower() or short)):
        name = on_disk
    # A drive root ("D:\\") resolves to an empty name too. Say so rather than
    # emitting an empty string that reads as a missing field.
    # one name in one form, as the paths inside the report are: `café` typed with a combining accent is `café`
    return unicodedata.normalize("NFC", name) if name else "<filesystem-root>"


def _file_digest(path: Path, text: bool = True) -> str:
    """SHA3-256 of a file's content. Content, never path metadata.

    For a file read as text, CRLF line endings are folded to LF before hashing. Git
    converts line endings on checkout on some systems and not on others, and the two
    checkouts are the same source: they give the same digest. A file with a NUL byte in
    it, and anything passed with `text=False`, is hashed byte for byte.
    """
    h = hashlib.sha3_256()
    # A file read as text is parsed too, so its digest comes from the one read the parsers share. An artifact is only
    # hashed: it is read here and not kept.
    if not text:
        _reads.digest_into(path, h)    # byte for byte, never held whole; checked against the run's version
        return h.hexdigest()
    raw = _reads.read_bytes(path)      # the version every other read of this file in the run must match
    data = raw.replace(b"\r\n", b"\n") if b"\x00" not in raw else raw
    h.update(data)
    return h.hexdigest()


class _FoldingDigest:
    """SHA3-256 of a file's bytes with CRLF folded to LF, fed in chunks (a CR at the end of one chunk is held until
    the next is seen); byte for byte instead when a NUL byte turns up. The same value `_file_digest` gives a file
    held whole, for a file of any size."""

    def __init__(self) -> None:
        self.raw, self.folded = hashlib.sha3_256(), hashlib.sha3_256()
        self.nul = self.cr = False

    def update(self, chunk: bytes) -> None:
        self.raw.update(chunk)
        if self.nul:
            return
        if b"\x00" in chunk:
            self.nul = True
            return
        if self.cr:
            chunk, self.cr = b"\r" + chunk, False
        if chunk.endswith(b"\r"):
            chunk, self.cr = chunk[:-1], True
        self.folded.update(chunk.replace(b"\r\n", b"\n"))

    def hexdigest(self) -> str:
        if self.nul:
            return self.raw.hexdigest()
        if self.cr:
            self.folded.update(b"\r")
            self.cr = False
        return self.folded.hexdigest()


class _ArtifactDigest(_FoldingDigest):
    """`_FoldingDigest` with the text-artifact rule of `_is_text_artifact`, decided as the bytes stream past: folded
    when git takes the bytes for text (or the file is Cython source with no NUL byte), byte for byte otherwise."""

    def __init__(self, source: bool) -> None:
        super().__init__()
        self.source, self.stats = source, _GitTextStats()

    def update(self, chunk: bytes) -> None:
        super().update(chunk)
        if not self.source:
            self.stats.update(chunk)

    def hexdigest(self) -> str:
        if self.nul or not (self.source or self.stats.text()):
            return self.raw.hexdigest()
        return super().hexdigest()


_EXECUTABLE_MAGIC = ((b"\x7fELF", "an ELF executable or shared library"),
                     (b"\xfe\xed\xfa\xce", "a Mach-O executable"), (b"\xfe\xed\xfa\xcf", "a Mach-O executable"),
                     (b"\xce\xfa\xed\xfe", "a Mach-O executable"), (b"\xcf\xfa\xed\xfe", "a Mach-O executable"),
                     (b"\xca\xfe\xba\xbe", "a Mach-O universal binary or a Java class file"),
                     (b"\xca\xfe\xba\xbf", "a Mach-O universal binary"),
                     (b"MZ", "a Windows executable"))


def _executable_kind(path: Path) -> str:
    """What compiled code a file is, by its first bytes, or "" when it is none of these."""
    head = _reads.read_head(path, 64)
    if head.startswith(b"MZ") and b"\x00" not in head:
        return ""                           # text that begins with the letters `MZ`; a DOS header holds zero bytes
    return next((what for magic, what in _EXECUTABLE_MAGIC if head.startswith(magic)), "")


def _artifact_digest(path: Path, suffix: str) -> str:
    """An artifact's digest: folded as text when its bytes are text, at any size (a large one is streamed)."""
    if os.path.getsize(path) <= _reads._HOLD_LIMIT:
        return _file_digest(path, text=_is_text_artifact(path, suffix))
    d = _ArtifactDigest(source=suffix in _SOURCE_ARTIFACT_EXTS)
    _reads.digest_into(path, d)
    return d.hexdigest()


def tree_listing_digest(files) -> str:
    """Every file the walk found, by name and by content (CRLF folded to LF in a file with no NUL byte, as in the
    subject digest, at any size: a large file is folded as it is streamed). Two reports with the same value were
    made from the same files; a converter that joins two reports checks it."""
    h = hashlib.sha3_256(b"entrovouch-tree-listing-v2\x00")
    for rel, path in sorted(files, key=lambda e: e[0].encode("utf-8", "backslashreplace")):
        try:
            if os.path.getsize(path) <= _reads._HOLD_LIMIT:
                dig = _file_digest(path)
            else:
                folding = _FoldingDigest()
                _reads.digest_into(path, folding)
                dig = folding.hexdigest()
        except OSError:
            dig = "unreadable"
        h.update(rel.encode("utf-8", "backslashreplace") + b"\x00" + dig.encode("ascii") + b"\n")
    return h.hexdigest()


def _tree_digest(entries: list[tuple[str, str]]) -> str:
    """Order-independent digest over (relative_path, file_digest) pairs.

    Sorted before hashing, so filesystem iteration order cannot change the
    result. Covers exactly the files the audit READ -- a digest over files the
    tool never opened would assert coverage the report does not have.
    """
    h = hashlib.sha3_256()
    h.update(_TREE_TAG)
    for rel, dig in sorted(entries,
                           key=lambda e: (e[0].encode("utf-8", "backslashreplace"), e[1])):
        h.update(_FILE_TAG)
        h.update(rel.encode("utf-8", "backslashreplace"))
        h.update(bytes.fromhex(dig))
    return h.hexdigest()


def reproducible_body(report_dict: dict) -> bytes:
    """The bytes behind `findings_digest` -- stable across runs and machines.

    What sits inside a skipped directory is not part of the tree that was read: `.git/` differs between a full and a
    shallow clone, caches (`.hypothesis/`, `__pycache__/`) and `node_modules/` appear when the code is run or
    installed. The report keeps those directories and their file counts; the reproducible body leaves them out, so
    a fresh checkout of the same commit gives the same digest."""
    clean = {k: v for k, v in report_dict.items() if k not in _ISSUANCE_FIELDS}
    ns = clean.get("not_scanned")
    if isinstance(ns, dict) and "skipped_directories" in ns:
        skipped = ns.get("skipped_directories")
        clean["not_scanned"] = {k: v for k, v in ns.items() if k != "skipped_directories"}
        if isinstance(skipped, dict) and isinstance(clean.get("files_not_read"), int):
            clean["files_not_read"] -= sum(v for v in skipped.values() if isinstance(v, int))
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_body(report_dict: dict) -> bytes:
    """The exact bytes that are hashed and signed. Stable across processes."""
    clean = {k: v for k, v in report_dict.items() if k not in _SIG_FIELDS}
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sign(report_dict: dict) -> tuple[str, str]:
    """Compute the unkeyed content hash. The second element is always "".

    An HMAC keyed by published text detects exactly what the unkeyed hash beside it detects, and this package's own
    `key_provenance` detector would report it as `derived-from-parameter`.

    Origin attestation is `signer.MerkleSigner`, via `audit(..., signer=...)`.
    """
    ch = hashlib.sha3_256(canonical_body(report_dict)).hexdigest()
    return ch, ""


def report_is_intact(report_dict: dict) -> bool | None:
    """Does the body still hash to its own `content_hash`?

    True or False for a report that carries one; None for a document with no
    `content_hash` to check against. A converter that reformats a report whose body
    was edited after issue would carry the edit into a new format with nothing to
    show for it, so the adapters refuse on False.
    """
    if not isinstance(report_dict, dict) or not report_dict.get("content_hash"):
        return None
    return _hash_matches(report_dict)


def _hash_matches(report_dict: dict) -> bool:
    """The body hashes to the `content_hash` it carries. Any document that cannot be hashed, or a claimed hash
    that is not a string, does not match: it is never an exception."""
    claimed = report_dict.get("content_hash")
    if not isinstance(claimed, str):
        return False
    try:
        ch = hashlib.sha3_256(canonical_body(report_dict)).hexdigest()
    except (TypeError, ValueError):
        return False
    # bytes, not str: `compare_digest` refuses a str with any non-ASCII character
    return hmac.compare_digest(ch.encode("ascii"), claimed.encode("utf-8", "surrogatepass"))


def _reject_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"the key {k!r} appears twice in one object; readers would disagree on its value")
        out[k] = v
    return out


def _reject_constant(name):
    raise ValueError(f"{name} is not a JSON number")


def strict_json_loads(text: str):
    """`json.loads` that refuses a key given twice in one object (one parser reads the first value, another the
    last, so one file would say two things) and NaN or Infinity (not JSON)."""
    return json.loads(text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant,
                      parse_float=_finite_float)


def _finite_float(text: str) -> float:
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{text} is too large to be a JSON number this tool reads")
    return value


def _claims_signed(report_dict: dict) -> bool:
    """The body names a signer: a public root, or an algorithm other than the unsigned marker."""
    return bool(report_dict.get("public_root")) or report_dict.get("signature_algorithm", UNSIGNED) not in (UNSIGNED, "")


def _identity_matches(report_dict: dict, sig: dict) -> bool:
    """The signer the body names is the signer the signature names."""
    return (report_dict.get("public_root") == sig.get("public_root")
            and report_dict.get("signature_algorithm") == sig.get("algorithm"))


def subject_matches(report_dict: dict) -> bool:
    """The in-toto subject a report carries names what the report's own body names: its target and its subject
    digest, which `findings_digest` covers. A subject naming another artifact would be signed, verify, and match a
    re-run's digest while pointing an in-toto consumer elsewhere. True for a report that carries no subject."""
    if not isinstance(report_dict, dict) or "subject" not in report_dict or "subject_digest" not in report_dict:
        return True
    return report_dict.get("subject") == [{"name": report_dict.get("target"),
                                           "digest": {"sha3-256": report_dict.get("subject_digest")}}]


def findings_digest_matches(report_dict: dict) -> bool:
    """A report that carries `findings_digest` carries the digest of its own reproducible body: the value a reader
    compares with a re-run must describe the findings and verdict the report shows, not another run's. True for a
    report that carries none (a key-provenance report)."""
    if not isinstance(report_dict, dict) or "findings_digest" not in report_dict:
        return True
    try:
        return report_dict.get("findings_digest") == hashlib.sha3_256(reproducible_body(report_dict)).hexdigest()
    except (TypeError, ValueError):
        return False


def report_problem(report_dict) -> str | None:
    """Why a document cannot be used as the report it claims to be, or None. Checks what can be checked without a
    pinned root: the body against its hash, and a signature against the body it signs."""
    if not isinstance(report_dict, dict):
        return "the JSON's top level is not an object; a report is one object"
    if report_is_intact(report_dict) is False:
        return ("this report's body does not match its own content hash: it was changed after it was issued. "
                "Not converted.")
    if not findings_digest_matches(report_dict):
        return ("this report's findings_digest does not describe the findings it shows, so re-running the tool and "
                "comparing that value would check nothing about them. Not converted.")
    if not subject_matches(report_dict):
        return ("this report's in-toto subject does not name the tree its body names (target and subject_digest). "
                "Not converted.")
    sig = report_dict.get("signature")
    if sig:
        # the same test `verify_report` makes: a signed report's `integrity_tag` is absent or the empty string, never null
        if not isinstance(sig, dict) or not _identity_matches(report_dict, sig) or report_dict.get("integrity_tag", "") != "":
            return "this report's signature does not belong to its body (the signer it names differs). Not converted."
        try:
            body = canonical_body(report_dict)
        except (TypeError, ValueError):
            return "this report cannot be put in canonical form. Not converted."
        if not verify_any(body, sig):
            return "this report's signature does not verify against its body: it was changed after signing. Not converted."
    elif _claims_signed(report_dict):
        return "this report names a signer and carries no signature: the signature was removed. Not converted."
    return None


class ReportError(ValueError):
    """A file given as a report cannot be used as one. Its message is the sentence to print."""


NO_EGRESS_TOOL = "ENTROVOUCH no-egress auditor"
CBOM_TOOL = "ENTROVOUCH CBOM generator"
SBOM_TOOL = "ENTROVOUCH SBOM"
KEY_PROVENANCE_TOOL = "ENTROVOUCH key-provenance detector"


def _kind_problem(data: dict, kind: str) -> str | None:
    """Why `data` is not a report of `kind` (the `tool` that writes it), or None."""
    tool = data.get("tool")
    if tool is None and kind == KEY_PROVENANCE_TOOL:
        return ("this key-provenance report names no tool, so an earlier version wrote it: run key_provenance again. "
                "Not converted.")
    if tool != kind:
        what = f"a report from {tool}" if isinstance(tool, str) and tool else "not a report that names its tool"
        return f"this is {what}, not a report from {kind}. Not converted."
    if not data.get("content_hash"):
        return "this report carries no content hash, so an edit to it cannot be seen. Not converted."
    return None


def load_report(path: Path | str, check: bool = True, kind: str | None = None) -> dict:
    """Read a report a command was handed. Every way it can be unusable is a ReportError, never a traceback.
    `kind` names the tool whose reports the command accepts. With `check=False` only the JSON is checked, for a
    verifier that reports TAMPERED as a status."""
    path = Path(path)
    if path.is_dir():
        raise ReportError(f"{path} is a folder, not a report")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ReportError(f"{path} is not UTF-8 text, so it is not a report") from None
    except OSError as exc:
        raise ReportError(f"could not read {path}: {exc.strerror or exc}") from None
    if text.startswith("﻿"):
        # an editor saved it with a byte-order mark: the report was written without one, so these are not its bytes
        raise ReportError(f"{path} starts with a byte-order mark the report was written without (an editor added it); "
                          "a report is checked as the bytes the tool wrote, so save it as UTF-8 without one") from None
    try:
        data = strict_json_loads(text)
    except RecursionError:
        raise ReportError(f"{path} nests deeper than this reader follows, so it is not a report") from None
    except ValueError as exc:
        raise ReportError(f"{path} is not usable JSON ({exc})") from None
    if not isinstance(data, dict):
        raise ReportError(f"{path} holds JSON whose top level is not an object; a report is one object")
    problem = (kind and _kind_problem(data, kind)) or (report_problem(data) if check else None)
    if problem:
        raise ReportError(problem)
    return data


def verify_any(message: bytes, sig: dict,
               expected_root: str | None = None) -> bool:
    """Verify a signature under whichever scheme produced it.

    Dispatch is on the signature's own `algorithm` field, and an ALGORITHM THIS
    BUILD DOES NOT KNOW RETURNS FALSE rather than raising or, worse, falling
    through to a default verifier. A verifier that quietly picks a scheme when
    it does not recognise the one it was handed is how a downgrade happens.

    One scheme ships: Lamport-Merkle SHA3-256. It is hash-based, so it rests on
    no lattice or discrete-log assumption, and it claims conformance to no
    published standard - there is nothing here to fail a conformance test
    against.
    """
    if not isinstance(sig, dict):
        return False
    algorithm = sig.get("algorithm")
    if algorithm == ALGORITHM:
        return verify_signature(message, sig, expected_root=expected_root)
    return False


def verify_report(report_dict: dict, expected_root: str | None = None,
                  expected_tool: str | None = "ENTROVOUCH no-egress auditor") -> tuple[bool, str]:
    """Verify a report. Returns `(ok, status)` -- never a bare bool.

    A bare `True` could not tell "cryptographically attested by a pinned identity"
    from "the bytes hash to what they say they hash to", so the status travels with it.

    `ok` IS TRUE FOR EXACTLY ONE STATUS: `ATTESTED`. It answers *"may I rely
    on this as third-party evidence?"*, and only a signature checked against an
    identity the caller pinned can answer yes. Everything else is False.

    FAIL-CLOSED by design: an unsigned report is not evidence of origin and cannot
    be mistaken for it by a caller who checks the boolean and ignores the status.

    status is one of:
      ATTESTED  - signed by `expected_root`; origin and integrity both proven.
                  THE ONLY STATUS FOR WHICH `ok` IS TRUE.
      UNVERIFIED- signature is internally valid but the caller pinned no
                  identity, so anyone could have produced it. Not evidence.
      UNSIGNED  - well-formed, self-consistent, and carries NO origin claim.
      TAMPERED  - body does not match its own hash, the signature is invalid, or
                  the document is not a well-formed report at all.
    """
    if not isinstance(report_dict, dict) or not _hash_matches(report_dict) or not findings_digest_matches(report_dict) \
            or not subject_matches(report_dict):
        return False, "TAMPERED"
    # A report of another kind (a CBOM handed to the no-egress verifier, or any signed dictionary) is not this one.
    if expected_tool is not None and report_dict.get("tool") != expected_tool:
        return False, "TAMPERED"

    sig = report_dict.get("signature")
    if not sig and _claims_signed(report_dict):
        return False, "TAMPERED"          # the body names a signer: its signature was removed
    if not sig:
        # `integrity_tag` is DELIBERATELY NOT CONSULTED. It is an HMAC keyed by
        # public material, so it is computable by anyone and detects exactly
        # what the unkeyed `content_hash` above already detects -- it was never
        # weak evidence, it was REDUNDANT evidence wearing a cryptographic name.
        return False, "UNSIGNED"

    # `integrity_tag` sits outside the signed body and a signed report is issued with it empty. Anything else in
    # it would travel unsigned inside a report that verifies, where a reader could take it for part of the claim.
    # (An unsigned report from an earlier version may carry one; it is UNSIGNED either way.)
    if report_dict.get("integrity_tag", "") != "":
        return False, "TAMPERED"
    # the signer the body names (shown as "Signed by", copied into attestations) is the signer that signed
    if not isinstance(sig, dict) or not _identity_matches(report_dict, sig):
        return False, "TAMPERED"
    body = canonical_body(report_dict)
    if isinstance(expected_root, str):
        expected_root = expected_root.strip().lower()
    if not verify_any(body, sig, expected_root=expected_root):
        return False, "TAMPERED"
    return (True, "ATTESTED") if expected_root else (False, "UNVERIFIED")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def audit(target: Path | str, label: str | None = None, signer: "MerkleSigner | None" = None) -> AuditReport:
    """Audit `target`. `label` names the subject in the signed report.

    The report is handed to the audited party, so `target` never carries the
    auditor's absolute local path: an OS user name, a directory layout or a
    session identifier mean nothing to the recipient and are pure downside.

    Pass `label` as the checkable identity of what was audited
    (`org/repo@commit`). With no label, only the final path component is
    recorded: never the absolute path. There is no way to get the full local
    path into a report, which is the point.
    """
    target = Path(target)   # a public entry point takes what its users type
    # the digest and the analysis are computed from one read of each file
    with _reads.one_read_per_file():
        return _audit(target, label, signer)


_GITLAB_LOCAL_RE = re.compile(r"""^\s*(?:-\s+)?(?:local\s*:\s*)?(?:['"]/?([^'"\n]+\.ya?ml)['"]|/?([\w./*-]+\.ya?ml))\s*(?:#.*)?$""")


def _tree_module_names(rels) -> frozenset:
    """Dotted names of the Python modules and packages (a folder with `__init__.py`) a tree holds, as imported from the
    tree's root or from its `src/` folder (`google/cloud/storage/blob.py` gives `google.cloud.storage.blob`;
    `google/cloud/storage/__init__.py` gives `google.cloud.storage`). A namespace folder with no `__init__.py`
    (`google/cloud/`) is shared with other distributions and is not the tree's own.

    Only where Python would import it from the tree: under a top-level name the tree holds as an ordinary package, or
    under a namespace other distributions also install into (`google`, `azure`, `opentelemetry`, or a top-level
    `__init__.py` that extends its path). A namespace folder beside an installed ordinary package of that name
    (`src/boto3/s3/transfer.py` with no `__init__.py`) is never imported: the installed package wins."""
    out: set[str] = set()
    rels = frozenset(rels)
    # folders that are a project of their own (`pyproject.toml`, `setup.py`, `setup.cfg`), the tree's root included:
    # what such a project holds at its top or under its source folder is what it installs
    projects = {r.rpartition("/")[0] for r in rels if r.rpartition("/")[2] in ("pyproject.toml", "setup.py", "setup.cfg")}

    def init(base: str, names) -> bool:
        return ("/".join(([base] if base else []) + list(names)) + "/__init__.py") in rels

    def owned_from(base: str, dotted: list[str]) -> int | None:
        """How many leading names of `dotted` are a namespace the module is reached through and is not the tree's
        (0: the whole name is the tree's), or None when Python would not import it from the tree. An ordinary top-level
        package is the tree's, and so is one whose `__init__.py` extends its path (the tree's folder comes first on that
        path); so is everything under a namespace other distributions share. Under a namespace folder a project here
        installs, the tree's own code starts at its first ordinary package (`nats/client/`, `paho/mqtt/`): a module
        lying loose in namespace folders (`twisted/plugins/x.py`) is reached through the installed package of that
        name when it is an ordinary one, which the tree cannot tell."""
        if dotted[0] in _SHARED_NAMESPACES or init(base, dotted[:1]):
            return 0
        parent = base.rpartition("/")[0] if base.rpartition("/")[2].lower() in _SOURCE_ROOTS else None
        if not (base in projects or (parent is not None and parent in projects)):
            return None
        return next((j for j in range(2, len(dotted) + 1) if init(base, dotted[:j])), None)

    for rel in rels:
        if not rel.lower().endswith((".py", ".pyw")):
            continue
        parts = rel.rsplit(".", 1)[0].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        # where the module may be imported from: the tree's root, a source folder (`src/`, `nats-core/src/`), or a
        # folder that is a project of its own
        for k in range(len(parts) - 1):
            base = "/".join(parts[:k])
            if k and parts[k - 1].lower() not in _SOURCE_ROOTS and base not in projects:
                continue
            dotted = parts[k:]
            start = owned_from(base, dotted) if all(p.isidentifier() for p in dotted) else None
            if start is None:
                continue
            out.add(".".join(dotted))
            # the folders between are the tree's too (`discord/ext/` holding `commands/`), from where the tree's own
            # code starts; in a namespace several distributions share, `google.cloud` is every distribution's
            if dotted[0] not in _SHARED_NAMESPACES:
                out.update(".".join(dotted[:j]) for j in range(max(2, start), len(dotted)))
    return frozenset(out)


# the top-level names several distributions install modules into (`google-cloud-storage` and `google-cloud-pubsub`
# both under `google`)
_SHARED_NAMESPACES = frozenset(v.split(".")[0] for v in _DISTRIBUTION_FAMILIES.values())


def _gitlab_glob(pattern: str) -> re.Pattern:
    """GitLab's include wildcard: `*` within one folder, `**` across folders."""
    out = ""
    for part in re.split(r"(\*\*/?|\*)", pattern):
        out += ".*" if part.startswith("**") else "[^/]*" if part == "*" else re.escape(part)
    return re.compile(out + r"\Z")


def _gitlab_local_includes(files, walked: frozenset) -> frozenset:
    """The files of the tree a GitLab pipeline includes by path: `include: 'ci/x.yml'`, `include: - local: ci/x.yml`,
    and the files those include in turn. A path is taken from the repository root, as GitLab takes it."""
    pending = [p for rel, p in files if rel.rsplit("/", 1)[-1].lower() in (".gitlab-ci.yml", ".gitlab-ci.yaml")]
    seen: set[str] = set()
    while pending:
        p = pending.pop()
        try:
            lines = _reads.read_text(p).splitlines()
        except OSError:
            continue
        inside, indent = False, 0
        for ln in lines:
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            head = re.match(r"(\s*)include\s*:\s*(.*)$", ln)
            if head:
                inside, indent = True, len(head.group(1))
                if not head.group(2).strip():
                    continue
                ln = head.group(2)
            elif inside and _yaml_indent(ln) <= indent and not ln.lstrip().startswith("-"):
                inside = False
            if not inside or "://" in ln or re.match(r"\s*(?:-\s+)?(?:remote|template|project|file)\s*:", ln):
                continue
            # a flow list (`include: [ci/a.yml, ci/b.yml]`) holds several paths on one line, and a flow map
            # (`- { local: ci/build.yml, rules: ... }`) holds its keys on one line
            text = re.sub(r"^\s*-\s+", "", ln).strip()
            items = text[1:-1].split(",") if text[:1] + text[-1:] in ("[]", "{}") else [ln]
            for item in items:
                # an item of a flow list may itself be a flow map (`include: [{local: ci/build.yml}]`)
                m = _GITLAB_LOCAL_RE.match(item.strip().strip("{}").strip())
                if not m:
                    continue
                path = m.group(1) or m.group(2)      # quoted, a path may hold a space
                while path.startswith("./"):
                    path = path[2:]                 # `./.ci/build.yml` is `.ci/build.yml`
                # a wildcard (`ci/*.yml`, `ci/**.yml`) names every file of the tree it matches
                names = ([r for r in sorted(walked) if _gitlab_glob(path).match(r)] if "*" in path
                         else [path] if path in walked else [])
                for rel in names:
                    if rel not in seen:
                        seen.add(rel)
                        pending += [q for r, q in files if r == rel]
    return frozenset(seen)


# `- template: templates/build.yml`, `template: /ci/steps.yml@self`, under `extends:` as well; `@other` names a
# template in another repository, which is not in the tree
_AZURE_TEMPLATE_RE = re.compile(r"""^\s*(?:-\s+)?\{?\s*template\s*:\s*['"]?([^'"\s#@,}]+\.ya?ml)(?:@([^\s,}'"]+))?['"]?\s*[,}]?.*$""")


def _azure_templates(files, walked: frozenset) -> frozenset:
    """The files of the tree an Azure Pipelines definition uses as templates, and the templates those use in turn. A
    path is taken from the folder of the file that names it, or from the repository root when it starts with `/`."""
    pending = [(rel, p) for rel, p in files
               if re.search(r"(?:^|/)azure-pipelines[^/]*\.ya?ml$|(?:^|/)\.?azure-pipelines/[^/]+\.ya?ml$", rel, re.IGNORECASE)]
    seen: set[str] = set()
    while pending:
        rel0, p = pending.pop()
        try:
            lines = _reads.read_text(p).splitlines()
        except OSError:
            continue
        for ln in lines:
            m = _AZURE_TEMPLATE_RE.match(ln)
            if not m or (m.group(2) and m.group(2).lower() != "self"):
                continue
            path = m.group(1)
            path = path[1:] if path.startswith("/") else posixpath.join(rel0.rpartition("/")[0], path)
            path = posixpath.normpath(path)
            if path in walked and path not in seen:
                seen.add(path)
                pending += [(r, q) for r, q in files if r == path]
    return frozenset(seen)


def _audit(target: Path, label: str | None, signer: "MerkleSigner | None") -> AuditReport:
    rep = AuditReport(target=label or _subject_name(target),
                      scanned_at_utc=datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = []
    scanned = 0
    tree: list[tuple[str, str]] = []
    # Names the tree provides itself shadow installed packages (Python's own
    # resolution order), so they are not third-party network imports.
    shadowed: set[str] = set()
    unlisted: set[str] = set()
    unlisted_js: set[str] = set()
    unscanned: dict[str, int] = {}
    walk = tree_files(target)
    skipped = walk.skipped
    extended: set[str] = set()
    local_modules = frozenset(_local_top_level_modules(target, frozenset(rel for rel, _ in walk.files), extended))
    # every directory and module name the tree itself holds: an import of one is the tree's own code
    own_names = frozenset(part[:-3] if part.lower().endswith(".py") else part
                          for rel, _ in walk.files if rel.lower().endswith((".py", ".pyw"))
                          for part in rel.split("/")) | local_modules
    walked_rels = frozenset(rel for rel, _ in walk.files)
    # pipeline files a `.gitlab-ci.yml` pulls in by path (`include: local: ci/build.yml`): read as pipeline files
    ci_included = _gitlab_local_includes(walk.files, walked_rels) | _azure_templates(walk.files, walked_rels)
    beside: dict[str, set[str]] = {}         # directory -> module and package names Python finds there
    for rel, _ in walk.files:
        if rel.lower().endswith((".py", ".pyw")):
            folder, _, name = rel.rpartition("/")
            beside.setdefault(folder, set()).add(name.rsplit(".", 1)[0])
            while folder:                        # a folder holding Python is a (namespace) package of its parent
                parent, _, sub = folder.rpartition("/")
                beside.setdefault(parent, set()).add(sub)
                folder = parent
    # Python found inside another file (a script's `python -c`) adds its unknown imports to the same list
    sink_token = _UNLISTED_SINK.set((unlisted, own_names))
    ci_token = _CI_INCLUDED.set(ci_included)
    modules_token = _TREE_MODULES.set(_tree_module_names(walked_rels))
    extended_token = _EXTENDED_ROOTS.set(frozenset(extended))
    try:
        for rel, p in walk.files:
            suffix = _reads.suffix_of(p).lower()
            folder = rel.rpartition("/")[0]
            # beside a file in a package, `import x` is NOT the module beside it (Python 3 has no implicit relative
            # import); beside a script or a test that is not in a package, it is
            in_package = (folder + "/__init__.py" if folder else "__init__.py") in walked_rels
            importable = local_modules | (frozenset() if in_package else frozenset(beside.get(folder, ())))
            # a file that cannot be opened (permissions, a lock held by another program) is listed as not
            # analysed, and stands in the subject digest as unread: no run reports a clean result over it
            try:
                if _is_python_file(p, suffix):
                    scanned += 1
                    findings += _check_python(p, rel, local_modules, shadowed, unlisted=unlisted, own_names=own_names,
                                              importable=importable)
                    tree.append((rel, _file_digest(p)))
                elif suffix in PTH_EXTS and _is_text_pth(p):
                    scanned += 1
                    findings += _check_pth(p, rel, local_modules, shadowed, unlisted, own_names, importable)
                    tree.append((rel, _file_digest(p)))
                elif suffix in NOTEBOOK_EXTS:
                    scanned += 1
                    findings += _check_notebook(p, rel, local_modules, shadowed, unlisted, own_names, importable)
                    tree.append((rel, _file_digest(p)))
                elif (suffix in TS_EXTS or suffix in JS_EXTS or suffix in MARKUP_EXTS) and _executable_kind(p):
                    # an executable under a source file's name (`app.js` holding an ELF binary): compiled code
                    tree.append((rel, _artifact_digest(p, suffix)))
                    findings.append(Finding(rel, 0, "unanalysed-artifact",
                                            f"{_executable_kind(p)}: compiled code this tool does not read; absence of "
                                            "findings in it is not evidence of absence"))
                elif suffix in TS_EXTS or suffix in JS_EXTS:
                    scanned += 1
                    findings += _check_ecmascript(p, rel, unlisted_js)
                    tree.append((rel, _file_digest(p)))
                elif suffix in MARKUP_EXTS:
                    scanned += 1
                    findings += _check_markup(p, rel, unlisted_js)
                    tree.append((rel, _file_digest(p)))
                elif (suffix in ARTIFACT_EXTS and not _artifact_name_on_text(p, suffix)) or (
                        suffix in PTH_EXTS and not _is_text_pth(p)):
                    # git converts line endings in any file without a NUL byte (Cython source, a protocol-0 pickle): such a file
                    # is folded as text is, at any size (a large one as it is streamed)
                    tree.append((rel, _artifact_digest(p, suffix)))
                    what = ("Cython source, which this tool does not read" if suffix in _SOURCE_ARTIFACT_EXTS
                            else "compiled, archived or serialised content this tool does not read")
                    findings.append(Finding(rel, 0, "unanalysed-artifact",
                                            f"{suffix} file: {what}; absence of findings in it is not evidence of absence"))
                elif is_manifest_path(rel):
                    continue  # read by the manifest pass below
                elif (not suffix or re.fullmatch(r"\.\d+", suffix) or _is_script(p, rel)) and _executable_kind(p):
                    # an executable or a shared library named without a listed extension (`bin/tool`, `libx.so.1`), or
                    # named as a script (`tool.sh` holding an ELF binary): compiled code, never script lines
                    tree.append((rel, _artifact_digest(p, suffix)))
                    findings.append(Finding(rel, 0, "unanalysed-artifact",
                                            f"{_executable_kind(p)}: compiled code this tool does not read; absence of "
                                            "findings in it is not evidence of absence"))
                elif _is_script(p, rel) or rel in ci_included:
                    scanned += 1
                    findings += _check_script(p, rel)
                    tree.append((rel, _file_digest(p)))
                else:
                    key = suffix or "(no extension)"
                    unscanned[key] = unscanned.get(key, 0) + 1
            except OSError as exc:
                findings.append(Finding(rel, 0, "unparseable-source",
                                        f"could not be opened ({type(exc).__name__}), so it was NOT analysed; "
                                        "absence of findings here is not evidence of absence"))
                tree[:] = [e for e in tree if e[0] != rel] + [(rel, _UNREAD_DIGEST)]
    finally:
        _UNLISTED_SINK.reset(sink_token)
        _CI_INCLUDED.reset(ci_token)
        _TREE_MODULES.reset(modules_token)
        _EXTENDED_ROOTS.reset(extended_token)
    man_findings, man_tree = _check_manifests(target)
    # `setup.py` is both Python source and a manifest: one entry in the subject digest.
    already = {r for r, _ in tree}
    for r, _ in man_tree:
        if r not in already and not is_manifest_path(r):      # a manifest by name was never counted as unread
            ext = _reads.suffix_of(Path(r)).lower() or "(no extension)"
            if unscanned.get(ext):
                unscanned[ext] -= 1
                if not unscanned[ext]:
                    del unscanned[ext]
    findings += man_findings
    scanned += sum(1 for r, _ in man_tree if r not in already)
    tree.extend(e for e in man_tree if e[0] not in already)
    rep.not_scanned = {
        "skipped_directories": dict(sorted(skipped.items())),
        "files_by_extension": dict(sorted(unscanned.items())),
        "symbolic_links": walk.symlinks,
    }
    rep.files_not_read = sum(unscanned.values()) + sum(skipped.values()) + walk.symlinks
    rep.shadowed_imports = sorted(shadowed)
    rep.unlisted_imports = sorted(unlisted)
    rep.unlisted_js_imports = sorted(unlisted_js)
    rep.parser_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    rep.files_scanned = scanned
    rep.findings = [asdict(f) for f in findings]
    if findings:
        rep.verdict = "FINDINGS"
    elif scanned == 0:
        rep.verdict = "NOT-ANALYSED"   # nothing was read, so nothing can be said
    else:
        rep.verdict = "CLEAN"
    rep.subject_digest = _tree_digest(tree)
    rep.subject = [{"name": rep.target, "digest": {"sha3-256": rep.subject_digest}}]
    rep.findings_digest = hashlib.sha3_256(
        reproducible_body(asdict(rep))).hexdigest()
    # ORDER IS LOAD-BEARING. Identity fields are written BEFORE the body is
    # hashed and signed, so they are covered by both. Read from the signer's
    # own `algorithm` property, never hard-coded, so a report cannot name a
    # scheme other than the one that signed it.
    if signer is not None:
        rep.signature_algorithm = signer.algorithm
        rep.public_root = signer.public_root
    ch, tag = _sign(asdict(rep))
    rep.content_hash = ch
    rep.integrity_tag = tag
    if signer is not None:
        rep.signature = signer.sign(canonical_body(asdict(rep)))
        # Belt and braces: the signature reports its own algorithm, and it must
        # agree with what we just signed. A mismatch means the signer lied
        # about itself, which is a bug, not a report to hand anyone.
        if rep.signature.get("algorithm", rep.signature_algorithm) != rep.signature_algorithm:
            raise SignerError(
                "signer.algorithm disagrees with the algorithm in its own "
                "signature; refusing to issue a report that misnames its scheme")
    return rep


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")
# What a GitHub-flavoured renderer turns into a link on its own: a scheme URL, a `www.` name, an e-mail address.
_MD_AUTOLINK = re.compile(r"(?i)[a-z][a-z0-9+.-]*://\S+|\bwww\.\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def markdown_cell(text, in_table: bool = True) -> str:
    """Text from the audited tree as plain markdown: every character markdown or HTML would act on is escaped, and
    anything a renderer would turn into a link on its own is set as code, so a file cannot put an image, a link or a
    tag into a report, and a bar or a line break cannot end a table cell."""
    t = str(text).replace("\r", " ").replace("\n", " ")
    out, at = [], 0
    for m in _MD_AUTOLINK.finditer(t):
        link = m.group(0).rstrip(".,:;!?*_~'\")]")      # trailing punctuation is not part of a link
        if not link:
            continue
        out.append(_MD_SPECIAL.sub(r"\\\1", t[at:m.start()]))
        out.append(markdown_code(link, in_table=in_table))
        at = m.start() + len(link)
    out.append(_MD_SPECIAL.sub(r"\\\1", t[at:]))
    return "".join(out) + _decomposed_note(t, in_table)


def _decomposed_note(t: str, in_table: bool) -> str:
    """For text not in composed form (NFC), its spelling with escapes: two files named `é.py`, one composed and one
    decomposed, look the same on screen and are told apart by this."""
    if unicodedata.normalize("NFC", t) == t:
        return ""
    return " (written " + markdown_code(t.encode("ascii", "backslashreplace").decode("ascii"), in_table=in_table, note=False) + ")"


def markdown_code(text, in_table: bool = True, note: bool = True) -> str:
    """Text from the audited tree as a code span, fenced with more backticks than any run inside it, so a backtick
    in a name cannot close the span. In a table a bar is escaped, which the table reads and removes. A control
    character (a line break in a file name) is written as its escape, `\\x0a`, so the name shown is the name."""
    # (and a character that reorders the text around it, `‮`, so a name cannot be shown as another)
    t = re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\x{ord(m.group(0)):02x}", str(text))
    t = re.sub(r"[؜‎‏‪-‮⁦-⁩]", lambda m: f"\\u{ord(m.group(0)):04x}", t)
    shown = t.replace("|", "\\|") if in_table else t
    run = max((len(r) for r in re.findall(r"`+", shown)), default=0)
    pad = " " if run else ""
    return "`" * (run + 1) + pad + shown + pad + "`" * (run + 1) + (_decomposed_note(t, in_table) if note else "")


def render_markdown(rep: AuditReport) -> str:
    lines = [
        f"# ENTROVOUCH No-Egress Audit: {rep.verdict}",
        "",
        f"- **Target:** {markdown_code(rep.target, in_table=False)}",
        f"- **Scanned:** {rep.scanned_at_utc}",
        f"- **Files scanned:** {rep.files_scanned}"
        + (f" ({rep.files_not_read} more were not read: skipped directories, types this tool has no reader "
           f"for, and links, listed below)"
           if rep.files_not_read else ""),
        *([f"- **Resolved locally, NOT counted as network imports:** "
           f"{', '.join(markdown_code(n, in_table=False) for n in rep.shadowed_imports)}: this tree supplies a top-level "
           f"module of each name, which shadows any installed package. Check these "
           f"if the tree vendors dependencies."]
          if rep.shadowed_imports else []),
        *([f"- **Imported, and not known to this tool ({len(rep.unlisted_imports)}):** "
           f"{', '.join(markdown_code(n, in_table=False) for n in rep.unlisted_imports[:40])}"
           + (f", and {len(rep.unlisted_imports) - 40} more" if len(rep.unlisted_imports) > 40 else "")
           + ". These third-party modules are on none of this tool's lists, so it says nothing "
             "about what they do. Check them against what you know they are."]
          if rep.unlisted_imports else []),
        *([f"- **JavaScript packages imported, and not known to this tool ({len(rep.unlisted_js_imports)}):** "
           f"{', '.join(markdown_code(n, in_table=False) for n in rep.unlisted_js_imports[:40])}"
           + (f", and {len(rep.unlisted_js_imports) - 40} more" if len(rep.unlisted_js_imports) > 40 else "")
           + ". This tool says nothing about what they do."]
          if rep.unlisted_js_imports else []),
        *_not_scanned_lines(rep),
        f"- **Parsed with:** Python {rep.parser_python}",
        f"- **Findings:** {len(rep.findings)}",
        # Order and labels are deliberate: the reproducible digest first, and the
        # content hash labelled as the one value that never reproduces, because a
        # reader holding only the markdown would otherwise compare it, see a
        # mismatch, and conclude the report was forged.
        f"- **Findings digest (reproduces):** `{rep.findings_digest}`",
        f"- **Subject digest (binds the files this audit read):** `{rep.subject_digest}`",
        f"- **Content hash (this issuance only, does NOT reproduce):** "
        f"`{rep.content_hash[:32]}…`",
    ]
    if rep.signature:
        lines += [
            f"- **Signed by:** `{rep.public_root}` ({rep.signature_algorithm})",
        ]
        # Only a stateful scheme has a one-time index; print it only when present.
        leaf = rep.signature.get("leaf_index")
        if leaf is not None:
            lines.append(f"- **One-time key index:** {leaf}  "
                         f"(stateful scheme; this leaf is now spent)")
        lines += [
            "",
            "> **How to verify origin:** pin the publisher's root out of band, then "
            "`verify_report(json.load(f), expected_root=<root>)`. A status of "
            "`ATTESTED` means this report came from the holder of that root; "
            "`UNVERIFIED` means you did not pin one and origin is unproven.",
        ]
    else:
        lines += [
            f"- **Signature:** {UNSIGNED}",
            "",
            "> ⚠️ **This report is NOT attested.** The content hash proves the body "
            "matches its own digest; it proves nothing about who produced it, "
            "because anyone can recompute it. Do not rely on this document as "
            "evidence of source.",
        ]
    lines += [
        "",
        "> **How to reproduce this report:** re-run the same tool version "
        "against the same tree with the same label and compare **`findings digest`**: it is "
        "bit-identical across runs, processes and machines. Do NOT compare the "
        "content hash: it covers the issuance timestamp and is *expected* to "
        "differ on every run. A different content hash with an identical "
        "findings digest is the same result, issued twice.",
        "",
        f"> **Scope:** {rep.scope_statement}",
        "",
    ]
    if rep.findings:
        lines += ["## Findings", "", "| File | Line | Kind | Detail |", "|---|---|---|---|"]
        for f in rep.findings:
            lines.append(f"| {markdown_code(f['file'])} | {f['line']} | {f['kind']} | {markdown_cell(f['detail'])} |")
    elif rep.verdict == "NOT-ANALYSED":
        lines.append("**Nothing was scanned.** No file of a type this tool reads was found outside the skipped "
                     "directories, so this report says nothing about the tree. See `not_scanned` above.")
    else:
        lines.append("**Nothing came to this tool's attention in the files it read.** That is limited assurance: "
                     "see the scope statement, `not_scanned` for what it did not read, and the imports listed "
                     "above as not known to this tool.")
    lines += ["", "*ENTROVOUCH. For the People.*"]
    return "\n".join(lines)


def _not_scanned_lines(rep: AuditReport) -> list[str]:
    ns = rep.not_scanned or {}
    skipped = ns.get("skipped_directories") or {}
    by_ext = ns.get("files_by_extension") or {}
    out: list[str] = []
    if skipped:
        shown = ", ".join(f"{markdown_code(k, in_table=False)} ({v})" for k, v in list(skipped.items())[:12])
        more = f", and {len(skipped) - 12} more" if len(skipped) > 12 else ""
        out.append(f"- **Skipped directories (not read, not in the subject digest):** {shown}{more}")
    if by_ext:
        total = sum(by_ext.values())
        top = sorted(by_ext.items(), key=lambda kv: -kv[1])[:12]
        shown = ", ".join(f"{markdown_code(k, in_table=False)} ({v})" for k, v in top)
        more = f", and {len(by_ext) - 12} more types" if len(by_ext) > 12 else ""
        out.append(f"- **Files of types this tool does not read:** {total} ({shown}{more})")
    if ns.get("symbolic_links"):
        out.append(f"- **Symbolic links (not followed, not read):** {ns['symbolic_links']}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ENTROVOUCH no-egress auditor")
    ap.add_argument("target", type=Path, nargs="?", help="directory to audit")
    ap.add_argument("--json", type=Path, default=None, help="write JSON report")
    ap.add_argument("--md", type=Path, default=None, help="write markdown report")
    ap.add_argument("--key", type=Path, default=None,
                    help="signing identity (see --init-key). WITHOUT THIS THE REPORT IS "
                         "UNSIGNED and attests nothing about its origin.")
    ap.add_argument("--hash-based", action="store_true",
                    help="(the only signer; flag kept for compatibility) Lamport-Merkle. "
                         "Signatures are ~16 KB and the key is STATEFUL "
                         "(one-time leaves that must never be reused).")
    ap.add_argument("--init-key", type=Path, default=None, metavar="PATH",
                    help="create a new signing identity at PATH, print its public root, exit. "
                         "Keep PATH secret; publish only the root.")
    ap.add_argument("--advance-key", type=int, default=None, metavar="N",
                    help="with --key: mark the next N one-time leaves as spent without signing, then exit. "
                         "Run this after restoring the key file from a backup, or before a second copy signs "
                         "anywhere, with N at least the number of signatures the lost copy could have made.")
    ap.add_argument("--label", default=None,
                    help="identity of the audited subject in the report, e.g. 'org/repo@commit'. "
                         "Defaults to the directory name. The auditor's absolute local path is "
                         "never recorded.")
    args = ap.parse_args(argv)
    try:  # non-ASCII in the markdown must not crash a cp1252 console
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    try:
        return _main(args)
    except (SignerError, OSError, ValueError) as exc:
        # Exit 2 is "could not run". It is never 1, which a pipeline reads as findings,
        # and never 0, which it reads as clean.
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _main(args: argparse.Namespace) -> int:
    if args.init_key and args.advance_key is not None:
        print("error: --advance-key moves an existing key on; it cannot be used with --init-key", file=sys.stderr)
        return 2
    if args.init_key:
        parent = Path(args.init_key).resolve().parent
        if not parent.is_dir():
            why = "is a file, not a folder" if parent.exists() else "does not exist; create it first"
            print(f"error: the folder for {args.init_key} {why}", file=sys.stderr)
            return 2
        signer = MerkleSigner.create(args.init_key)
        print(f"signing identity written to {args.init_key} (KEEP SECRET)")
        print(f"algorithm: {ALGORITHM}")
        print(f"public root (publish this): {signer.public_root}")
        print("")
        print("Keep one copy of this file. It cannot be regenerated: anyone holding it")
        print("can sign as you, and losing it means every reader who pinned the root")
        print("above must re-pin. The key is STATEFUL: each leaf signs once. A copy that")
        print("falls behind (a restored backup, a second machine) will reuse leaves, and")
        print("nothing in a signature reveals that. Before a restored or copied key signs")
        print("again, run --key PATH --advance-key N with N at least the number of")
        print("signatures the other copy could have made.")
        return 0
    if args.advance_key is not None:
        if not args.key:
            print("error: --advance-key needs --key PATH", file=sys.stderr)
            return 2
        if not args.key.is_file():
            print(f"error: signing key {args.key} does not exist", file=sys.stderr)
            return 2
        signer = MerkleSigner.load(args.key)
        new_index = signer.advance(args.advance_key)
        print(f"advanced: the next unused one-time leaf is now {new_index} of {signer.leaf_count}")
        return 0

    if args.target is None:
        print("error: target directory required (or use --init-key)", file=sys.stderr)
        return 2
    if not args.target.is_dir():
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        return 2
    if args.key and not args.key.is_file():
        what = "is a folder, not a key file" if args.key.is_dir() else "does not exist (create one with --init-key)"
        print(f"error: signing key {args.key} {what}", file=sys.stderr)
        return 2
    problem = missing_folder(args.json, args.md, key=args.key, tree=args.target)
    if problem:
        print(problem, file=sys.stderr)
        return 2
    signer = MerkleSigner.load(args.key) if args.key else None
    if signer is None:
        print("warning: no --key given; report will be UNSIGNED", file=sys.stderr)
    rep = audit(args.target, label=args.label, signer=signer)
    if args.json:
        write_text(args.json, json.dumps(asdict(rep), indent=2))
    if args.md:
        write_text(args.md, render_markdown(rep))
    print(render_markdown(rep))
    if rep.verdict == "NOT-ANALYSED":
        return 2
    return 0 if rep.verdict == "CLEAN" else 1


if __name__ == "__main__":
    raise SystemExit(run(main))

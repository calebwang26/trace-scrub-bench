"""Carriers: the realistic places where sensitive items show up in a trace.

A carrier builds one or two steps (e.g. `cat .env` & its output) & plants an
item inside them through the registry, which records exactly where it landed.

Three groups:
  * plain carriers   - the item appears as-is in a natural spot
  * hard carriers    - the same secret, but split over two lines, base64-encoded
                       or sitting inside an escaped JSON string
  * decoy carriers   - look-alikes that are NOT sensitive
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass

from tracegen import decoys, sensitive
from tracegen.content import Vocab, bash, call, python_module, result, timestamp, user
from tracegen.marks import Registry
from tracegen.sensitive import B64, HEX, MARK, b64, rand

S = "sensitive"
D = "decoy"
MODULE_TEAMS = ["payments", "platform", "search", "growth", "infra"]


# --- a secret plus the text that surrounds it --------------------------------

@dataclass
class Secret:
    type: str
    name: str  # the environment-variable style name it usually goes by
    value: str  # the secret itself: this is what must be removed
    before: str = ""  # non-secret text glued in front (e.g. "postgres://app:")
    after: str = ""  # non-secret text glued behind (e.g. "@host:5432/db")

    @property
    def full(self) -> str:
        return self.before + self.value + self.after


SECRET_TYPES = ["aws_key", "github_token", "openai_key", "jwt", "db_password", "env_secret", "private_key"]


def make_secret(rng: random.Random, type: str, special: bool = False) -> Secret:
    if type == "aws_key":
        return Secret(type, "AWS_ACCESS_KEY_ID", sensitive.aws_key(rng))
    if type == "github_token":
        return Secret(type, rng.choice(["GITHUB_TOKEN", "GH_TOKEN", "GH_PAT"]), sensitive.github_token(rng))
    if type == "openai_key":
        return Secret(type, rng.choice(["OPENAI_API_KEY", "LLM_API_KEY"]), sensitive.openai_key(rng))
    if type == "jwt":
        return Secret(type, rng.choice(["SERVICE_JWT", "AUTH_TOKEN", "ACCESS_TOKEN"]), sensitive.jwt(rng))
    if type == "db_password":
        before, pw, after = sensitive.db_url_parts(rng)
        return Secret(type, rng.choice(["DATABASE_URL", "DB_URL", "REPLICA_URL"]), pw, before, after)
    if type == "env_secret":
        name, value = sensitive.env_secret(rng, special=special)
        return Secret(type, name, value)
    if type == "private_key":
        name = rng.choice(["TLS_PRIVATE_KEY", "DEPLOY_KEY", "SIGNING_PRIVATE_KEY"])
        header, body, footer = sensitive.private_key_parts(rng)
        return Secret(type, name, body, header + "\n", "\n" + footer)  # the secret is the body, not the header lines
    raise ValueError(type)


def planted(reg: Registry, s: Secret, carrier: str, variant: str = "plain") -> str:
    """The secret with its surroundings, with the secret part marked."""
    return s.before + reg.plant(S, s.type, s.value, variant, carrier) + s.after


_ENV_FILLER = ["DEBUG=false", "PORT=8000", "LOG_LEVEL=info", "APP_ENV=production", "WORKERS=4", "CACHE_TTL=300", "TZ=UTC", "FEATURE_NEW_CHECKOUT=1", "SENTRY_ENVIRONMENT=prod"]


def _with_filler(rng: random.Random, line: str, filler: list[str], lo: int = 2, hi: int = 5) -> list[str]:
    lines = rng.sample(filler, rng.randint(lo, hi))
    lines.insert(rng.randint(0, len(lines)), line)
    return lines


# --- plain carriers for secrets ----------------------------------------------

def dotenv(rng, reg, v, s):
    lines = _with_filler(rng, f"{s.name}={planted(reg, s, 'dotenv')}", _ENV_FILLER)
    return [bash(rng.choice(["cat .env", "cat .env.production", "head -20 .env"])), result("\n".join(lines))]


def env_dump(rng, reg, v, s):
    filler = ["HOME=/root", "LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin", "PYTHONUNBUFFERED=1", f"VIRTUAL_ENV=/workspace/{v.project}/.venv", "SHELL=/bin/bash", "PWD=/workspace/" + v.project]
    lines = sorted(_with_filler(rng, f"{s.name}={planted(reg, s, 'env_dump')}", filler, 3, 6))
    return [bash(rng.choice(["env | sort", "printenv"])), result("\n".join(lines))]


def python_settings(rng, reg, v, s):
    line = f'{s.name} = "{planted(reg, s, "python_settings")}"'
    return [call("read_file", path=f"src/{v.project}/settings.py"), result(python_module(rng, v, extra_lines=[line], n_funcs=1), python=True)]


_HEADERS = {
    "github_token": "Authorization: token ",
    "openai_key": "Authorization: Bearer ",
    "jwt": "Authorization: Bearer ",
    "aws_key": "X-Aws-Access-Key: ",
    "env_secret": "X-Internal-Secret: ",
}


def curl(rng, reg, v, s):
    cmd = f"curl -s -H '{_HEADERS[s.type]}{planted(reg, s, 'curl')}' https://api.internal.example/v1/{v.module}/status"
    return [bash(cmd), result(json.dumps({"status": "ok", "module": v.module, "latency_ms": rng.randint(4, 900)}))]


def app_log(rng, reg, v, s):
    t = timestamp(rng)
    lines = [
        f"{t} INFO {v.project}.boot: starting worker {rng.randint(1, 16)}",
        f"{t} DEBUG {v.project}.config: loaded {s.name}={planted(reg, s, 'app_log')}",
        f"{t} INFO {v.project}.{v.module}: ready",
    ]
    return [bash("tail -n 20 logs/app.log"), result("\n".join(lines))]


def compose(rng, reg, v, s):
    text = (
        f"services:\n  web:\n    image: {v.project}:latest\n    environment:\n      - APP_ENV=production\n"
        f"      - {s.name}={planted(reg, s, 'compose')}\n      - WORKERS={rng.randint(1, 8)}\n    ports:\n      - \"8000:8000\""
    )
    return [bash("cat docker-compose.yml"), result(text)]


def aws_credentials(rng, reg, v, s):
    """An AWS credentials file: the key id plus the secret access key next to it."""
    secret_access_key = MARK + rand(rng, B64, 36)  # 40 characters, no fixed prefix
    text = (
        f"[default]\naws_access_key_id = {planted(reg, s, 'aws_credentials')}\n"
        f"aws_secret_access_key = {reg.plant(S, 'aws_key', secret_access_key, 'plain', 'aws_credentials_secret')}\nregion = us-east-1"
    )
    return [bash("cat ~/.aws/credentials"), result(text)]


def git_remote(rng, reg, v, s):
    url = f"https://x-access-token:{planted(reg, s, 'git_remote')}@github.com/example-org/{v.project}.git"
    return [bash("git remote get-url origin"), result(url)]


def npmrc(rng, reg, v, s):
    text = f"@example-org:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken={planted(reg, s, 'npmrc')}\nalways-auth=true"
    return [bash("cat .npmrc"), result(text)]


def pem_file(rng, reg, v, s):
    path = rng.choice(["deploy_key.pem", "~/.ssh/id_rsa", "certs/server.key", "secrets/signing.pem"])
    return [bash(f"cat {path}"), result(planted(reg, s, "pem_file"))]


def yaml_key_block(rng, reg, v, s):
    """A private key in a YAML block scalar: every line is indented."""
    indent = lambda t: t.replace("\n", "\n    ")
    body = reg.plant(S, s.type, s.value, "plain", "yaml_key_block", text=indent(s.value))
    text = f"tls:\n  cert_path: /etc/{v.project}/tls.crt\n  key: |\n    {indent(s.before)}{body}{indent(s.after)}\n  min_version: \"1.2\""
    return [bash("cat config/tls.yaml"), result(text)]


def sqlalchemy_error(rng, reg, v, s):
    text = (
        "Traceback (most recent call last):\n"
        f'  File "/workspace/{v.project}/src/{v.project}/db.py", line {rng.randint(10, 90)}, in connect\n'
        "    engine.connect()\n"
        'sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) connection to server failed: timeout expired\n'
        f"(Background on this error at: https://sqlalche.me/e/20/e3q8)\n[engine url: {planted(reg, s, 'sqlalchemy_error')}]"
    )
    return [bash(f"python -m {v.project}.migrate"), result(text)]


def token_response(rng, reg, v, s):
    body = '{"access_token": "' + planted(reg, s, "token_response") + '", "token_type": "bearer", "expires_in": 3600}'
    return [bash("curl -s -X POST https://auth.internal.example/oauth/token -d grant_type=client_credentials"), result(body)]


# --- hard carriers ------------------------------------------------------------

def _halves(rng: random.Random, value: str) -> tuple[str, str]:
    cut = rng.randint(int(len(value) * 0.3), int(len(value) * 0.7))
    return value[:cut], value[cut:]


def split_shell(rng, reg, v, s):
    """A shell script where the secret continues on the next line after a backslash."""
    a, b = _halves(rng, s.value)
    i = reg.new(S, s.type, s.value, "split", "split_shell")
    text = f'#!/bin/sh\nset -eu\ncurl -s https://api.internal.example/v1/{v.module}/sync \\\n  -H "{_HEADERS.get(s.type, "X-Api-Key: ")}{reg.wrap(i, a)}\\\n{reg.wrap(i, b)}" \\\n  -d @payload.json'
    return [bash("cat scripts/sync.sh"), result(text)]


def split_python(rng, reg, v, s):
    """Python source where the secret is written as two adjacent string literals."""
    a, b = _halves(rng, s.value)
    i = reg.new(S, s.type, s.value, "split", "split_python")
    line = f'{s.name} = (\n    "{reg.wrap(i, a)}"\n    "{reg.wrap(i, b)}"\n)'
    return [call("read_file", path=f"src/{v.project}/settings.py"), result(python_module(rng, v, extra_lines=[line], n_funcs=1), python=True)]


def split_wrap(rng, reg, v, s):
    """Terminal output hard-wrapped by a narrow terminal, cutting the secret in two."""
    a, b = _halves(rng, s.value)
    i = reg.new(S, s.type, s.value, "split", "split_wrap")
    t = timestamp(rng)
    text = f"{t} INFO deploy: syncing config for {v.project}\n{t} DEBUG deploy: {s.name}={reg.wrap(i, a)}\n{reg.wrap(i, b)}\n{t} INFO deploy: done"
    return [bash("tmux capture-pane -p -t deploy"), result(text)]


def base64_k8s(rng, reg, v, s):
    """A Kubernetes Secret: values are base64-encoded, which hides every prefix."""
    key = "tls.key" if s.type == "private_key" else s.name
    blob = reg.plant(S, s.type, s.value, "base64", "base64_k8s", text=b64(s.full))
    text = f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: {v.project}-secrets\n  namespace: prod\ntype: Opaque\ndata:\n  APP_ENV: {b64('production')}\n  {key}: {blob}"
    return [bash(f"kubectl get secret {v.project}-secrets -o yaml"), result(text)]


def base64_echo(rng, reg, v, s):
    blob = reg.plant(S, s.type, s.value, "base64", "base64_echo", text=b64(s.full))
    return [bash(f"echo {blob} | base64 -d > /tmp/{s.name.lower()}"), result("")]


def json_write_env(rng, reg, v, s):
    """A write_file tool call: the .env content is one JSON string, newlines escaped."""
    quote = '"' if s.type == "private_key" else ""
    lines = _with_filler(rng, f"{s.name}={quote}{planted(reg, s, 'json_write_env', 'json_escaped')}{quote}", _ENV_FILLER, 2, 4)
    return [call("write_file", path=".env", content="\n".join(lines) + "\n"), result("Wrote .env")]


def json_curl(rng, reg, v, s):
    """A bash tool call whose command uses double quotes, so JSON escapes them."""
    cmd = f'curl -s -H "{_HEADERS.get(s.type, "X-Api-Key: ")}{planted(reg, s, "json_curl", "json_escaped")}" "https://api.internal.example/v1/{v.module}?limit=5"'
    return [bash(cmd), result(json.dumps({"items": [], "next": None}))]


def json_nested(rng, reg, v, s):
    """A tool result that is JSON, containing program output that is itself JSON."""
    inner = json.dumps({"env": "production", s.name.lower(): planted(reg, s, "json_nested", "json_escaped"), "region": "us-east-1"}, ensure_ascii=False)
    outer = json.dumps({"exit_code": 0, "stdout": inner, "stderr": ""}, ensure_ascii=False)
    return [bash(f"python -m {v.project}.config --dump"), result(outer)]


PLAIN = {
    "aws_key": [dotenv, env_dump, python_settings, app_log, compose, aws_credentials, aws_credentials, curl],
    "github_token": [dotenv, env_dump, curl, git_remote, npmrc, app_log],
    "openai_key": [dotenv, env_dump, python_settings, curl, app_log, compose],
    "jwt": [curl, app_log, python_settings, token_response, dotenv],
    "db_password": [dotenv, env_dump, python_settings, compose, sqlalchemy_error, app_log],
    "env_secret": [dotenv, dotenv, env_dump, compose, app_log, python_settings],
    "private_key": [pem_file, pem_file, yaml_key_block],
}
HARD = {
    "aws_key": [split_shell, split_python, split_wrap, base64_k8s, base64_echo, json_write_env, json_curl, json_nested],
    "github_token": [split_shell, split_python, split_wrap, base64_k8s, base64_echo, json_write_env, json_curl, json_nested],
    "openai_key": [split_shell, split_python, split_wrap, base64_k8s, base64_echo, json_write_env, json_curl, json_nested],
    "jwt": [split_shell, split_python, split_wrap, base64_k8s, json_curl, json_nested],
    "db_password": [base64_k8s, base64_echo, json_write_env, json_nested],
    "env_secret": [split_python, split_wrap, base64_k8s, base64_echo, json_write_env, json_curl, json_nested],
    "private_key": [base64_k8s, json_write_env, json_nested],
}
NEEDS_REPO = {git_remote}
HARD_RATE = 0.3  # share of planted secrets that use a hard carrier


def secret_event(rng: random.Random, reg: Registry, v: Vocab, type: str, has_repo: bool) -> list[dict]:
    hard = rng.random() < HARD_RATE
    options = [c for c in (HARD if hard else PLAIN)[type] if has_repo or c not in NEEDS_REPO]
    carrier = rng.choice(options)
    special = type == "env_secret" and carrier in (json_write_env, json_curl, json_nested) and rng.random() < 0.5
    return carrier(rng, reg, v, make_secret(rng, type, special=special))


# --- personal data carriers ---------------------------------------------------

def _name(reg, name, carrier):
    return reg.plant(S, "person_name", name, "plain", carrier)


def _email(reg, addr, carrier):
    return reg.plant(S, "email", addr, "plain", carrier)


def git_log_full(rng, reg, v):
    entries = []
    for _ in range(rng.randint(1, 3)):
        name = sensitive.person_name(rng)
        entries.append(
            f"commit {rand(rng, HEX, 40)}\nAuthor: {_name(reg, name, 'git_log')} <{_email(reg, sensitive.email(rng, name), 'git_log')}>\n"
            f"Date:   {timestamp(rng)} +0000\n\n    {rng.choice(['Fix', 'Refactor', 'Add tests for', 'Speed up'])} {v.fn}"
        )
    return [bash(f"git log -n {len(entries)} -- {v.path}"), result("\n\n".join(entries))]


def git_blame(rng, reg, v):
    lines = []
    for n in range(rng.randint(2, 4)):
        lines.append(f"{rand(rng, HEX, 8)} ({_name(reg, sensitive.person_name(rng), 'git_blame')} {timestamp(rng)} +0000 {40 + n})     total += item.{v.attr} * factor")
    return [bash(f"git blame -L 40,{40 + len(lines) - 1} {v.path}"), result("\n".join(lines))]


def fixture_customers(rng, reg, v):
    """A test fixture file with customer records: name, email & phone together."""
    rows = []
    for i in range(rng.randint(1, 3)):
        name = sensitive.person_name(rng)
        rows.append(
            f'  {{"id": {1000 + i}, "name": "{_name(reg, name, "fixture")}", "email": "{_email(reg, sensitive.email(rng, name), "fixture")}", '
            f'"phone": "{reg.plant(S, "phone", sensitive.phone(rng), "plain", "fixture")}", "plan": "{rng.choice(["free", "pro", "team"])}"}}'
        )
    return [bash("cat tests/fixtures/customers.json"), result("[\n" + ",\n".join(rows) + "\n]")]


def user_contact(rng, reg, v):
    kind = rng.choice(["email", "phone", "name", "name_email"])
    name = sensitive.person_name(rng)
    if kind == "email":
        text = f"If you get stuck, email me at {_email(reg, sensitive.email(rng), 'user_message')} & I'll take a look."
    elif kind == "phone":
        text = f"This one is urgent. If the deploy breaks, call the on-call number: {reg.plant(S, 'phone', sensitive.phone(rng), 'plain', 'user_message')}."
    elif kind == "name":
        text = f"For context, {_name(reg, name, 'user_message')} wrote the original version of `{v.fn}`, so keep the style consistent."
    else:
        text = f"When you're done, summarize the change for {_name(reg, name, 'user_message')} ({_email(reg, sensitive.email(rng, name), 'user_message')})."
    return [user(text)]


def code_comment(rng, reg, v):
    name = sensitive.person_name(rng)
    kind = rng.choice(["maintainer", "questions", "reviewed"])
    if kind == "maintainer":
        line = f"# Maintainer: {_name(reg, name, 'code_comment')} <{_email(reg, sensitive.email(rng, name), 'code_comment')}>"
    elif kind == "questions":
        line = f"# Questions about this module: {_email(reg, sensitive.email(rng), 'code_comment')}"
    else:
        line = f"# Reviewed by {_name(reg, name, 'code_comment')} before the last release."
    return [call("read_file", path=v.path), result(python_module(rng, v, extra_lines=[line]), python=True)]


def mail_log(rng, reg, v):
    t = timestamp(rng)
    lines = [f"{t} INFO mailer: queue depth {rng.randint(0, 40)}"]
    for _ in range(rng.randint(1, 3)):
        lines.append(f"{t} INFO mailer: sent receipt to {_email(reg, sensitive.email(rng), 'mail_log')} (order {rng.randint(1000, 99999)})")
    return [bash("tail -n 10 logs/mailer.log"), result("\n".join(lines))]


def pyproject_authors(rng, reg, v):
    name = sensitive.person_name(rng)
    text = f'[project]\nname = "{v.project}"\nauthors = [{{name = "{_name(reg, name, "pyproject")}", email = "{_email(reg, sensitive.email(rng, name), "pyproject")}"}}]\nrequires-python = ">=3.10"'
    return [bash("head -5 pyproject.toml"), result(text)]


def sms_log(rng, reg, v):
    t = timestamp(rng)
    lines = [f"{t} INFO sms: sending login code to {reg.plant(S, 'phone', sensitive.phone(rng), 'plain', 'sms_log')}" for _ in range(rng.randint(1, 2))]
    return [bash("grep sms logs/app.log | tail -n 5"), result("\n".join(lines + [f"{t} INFO sms: provider responded 202"]))]


def contacts_csv(rng, reg, v):
    rows = ["id,team,oncall_phone"]
    for i in range(rng.randint(1, 3)):
        rows.append(f"{i + 1},{rng.choice(MODULE_TEAMS)},{reg.plant(S, 'phone', sensitive.phone(rng), 'plain', 'contacts_csv')}")
    return [bash("cat ops/oncall.csv"), result("\n".join(rows))]


def _ip(rng, reg, carrier):
    return reg.plant(S, "ipv4", sensitive.ipv4(rng), "plain", carrier)


def access_log(rng, reg, v):
    lines = []
    for _ in range(rng.randint(1, 4)):
        lines.append(f'{_ip(rng, reg, "access_log")} - - [{timestamp(rng)}] "GET /api/{v.module}/{rng.randint(1, 999)} HTTP/1.1" {rng.choice([200, 200, 404, 500])} {rng.randint(100, 9000)}')
    return [bash("tail -n 5 /var/log/nginx/access.log"), result("\n".join(lines))]


def ssh_command(rng, reg, v):
    return [bash(f"ssh deploy@{_ip(rng, reg, 'ssh_command')} 'systemctl status {v.project}'"), result(f"● {v.project}.service - {v.project} web\n   Active: active (running)")]


def connection_error(rng, reg, v):
    text = f"psycopg2.OperationalError: connection to server at \"{_ip(rng, reg, 'connection_error')}\", port 5432 failed: Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?"
    return [bash(f"python -m {v.project}.healthcheck"), result(text)]


def hosts_yaml(rng, reg, v):
    text = f"upstreams:\n  primary:\n    host: {_ip(rng, reg, 'hosts_yaml')}\n    port: 8080\n  replica:\n    host: {_ip(rng, reg, 'hosts_yaml')}\n    port: 8080\ntimeout_s: {rng.randint(2, 30)}"
    return [bash("cat config/upstreams.yaml"), result(text)]


def kubectl_pods(rng, reg, v):
    rows = ["NAME                     READY   STATUS    RESTARTS   AGE   IP"]
    for _ in range(rng.randint(1, 3)):
        rows.append(f"{v.project}-{rand(rng, HEX, 9)}-{rand(rng, 'bcdfghjklmnpqrstvwxz', 5)}   1/1     Running   0          {rng.randint(1, 30)}d   {_ip(rng, reg, 'kubectl_pods')}")
    return [bash("kubectl get pods -o wide"), result("\n".join(rows))]


PII = {
    "email": [git_log_full, fixture_customers, user_contact, code_comment, mail_log, pyproject_authors],
    "phone": [fixture_customers, user_contact, sms_log, contacts_csv],
    "person_name": [git_log_full, git_blame, user_contact, code_comment, fixture_customers],
    "ipv4": [access_log, ssh_command, connection_error, hosts_yaml, kubectl_pods],
}
NEEDS_REPO |= {git_log_full, git_blame}


def pii_event(rng: random.Random, reg: Registry, v: Vocab, type: str, has_repo: bool) -> list[dict]:
    options = [c for c in PII[type] if has_repo or c not in NEEDS_REPO]
    return rng.choice(options)(rng, reg, v)


# Relative frequency of each type among planting events.
EVENT_WEIGHTS = {
    "email": 11, "phone": 8, "person_name": 8, "ipv4": 10,
    "aws_key": 9, "github_token": 9, "openai_key": 10, "jwt": 8, "db_password": 9, "env_secret": 12, "private_key": 6,
}


def sensitive_event(rng: random.Random, reg: Registry, v: Vocab, has_repo: bool) -> list[dict]:
    type = rng.choices(list(EVENT_WEIGHTS), weights=list(EVENT_WEIGHTS.values()))[0]
    if type in PII:
        return pii_event(rng, reg, v, type, has_repo)
    return secret_event(rng, reg, v, type, has_repo)


# --- decoy carriers -----------------------------------------------------------

def _decoy(reg, type, value):
    return reg.plant(D, type, value)


def readme_docs(rng, reg, v):
    text = (
        f"# {v.project}\n\n## Configuration\n\nCopy `.env.example` to `.env` & set your keys:\n\n"
        f"    export OPENAI_API_KEY={_decoy(reg, 'doc_example_key', decoys.doc_example_key(rng))}\n"
        f"    export AWS_ACCESS_KEY_ID={_decoy(reg, 'doc_example_key', decoys.doc_example_key(rng))}\n\n"
        f"Questions? Open an issue or write to {_decoy(reg, 'example_email', decoys.example_email(rng))}."
    )
    return [bash("cat README.md"), result(text)]


def env_example(rng, reg, v):
    lines = ["# Copy to .env & fill in real values", "APP_ENV=development"]
    for _ in range(rng.randint(1, 3)):
        name, value = decoys.env_placeholder(rng)
        lines.append(f"{name}={_decoy(reg, 'env_placeholder', value)}")
    lines.append(f"OPENAI_API_KEY={_decoy(reg, 'doc_example_key', decoys.doc_example_key(rng))}")
    return [bash("cat .env.example"), result("\n".join(lines))]


def request_log(rng, reg, v):
    t = timestamp(rng)
    lines = [f"{t} INFO uvicorn: Uvicorn running on http://{_decoy(reg, 'safe_ip', rng.choice(['127.0.0.1', '0.0.0.0']))}:8000"]
    for _ in range(rng.randint(1, 3)):
        lines.append(f"{t} INFO {v.project}.api: request_id={_decoy(reg, 'uuid', decoys.uuid(rng))} GET /api/{v.module} 200 {rng.randint(2, 400)}ms")
    return [bash("tail -n 6 logs/server.log"), result("\n".join(lines))]


def git_log_oneline(rng, reg, v):
    lines = [f"{_decoy(reg, 'git_sha', decoys.git_sha(rng, short=True))} {rng.choice(['Fix', 'Refactor', 'Test', 'Bump', 'Document'])} {rng.choice(['pagination', v.fn, v.module + ' tests', 'dependencies', 'retry logic'])}" for _ in range(rng.randint(3, 6))]
    return [bash("git log --oneline -n 6"), result("\n".join(lines))]


def git_rev_parse(rng, reg, v):
    return [bash("git rev-parse HEAD"), result(_decoy(reg, "git_sha", decoys.git_sha(rng, short=False)))]


def pip_hashes(rng, reg, v):
    pkg = rng.choice(["requests", "urllib3", "certifi", "idna", "attrs"])
    lines = [f"{pkg}=={rng.randint(1, 3)}.{rng.randint(0, 30)}.{rng.randint(0, 9)} \\"]
    lines += [f"    --hash=sha256:{_decoy(reg, 'sha256', decoys.sha256(rng))}" + (" \\" if i == 0 else "") for i in range(2)]
    return [bash(f"grep -A2 '^{pkg}' requirements.lock"), result("\n".join(lines))]


def docker_pull(rng, reg, v):
    text = f"3.11-slim: Pulling from library/python\nDigest: sha256:{_decoy(reg, 'sha256', decoys.sha256(rng))}\nStatus: Image is up to date for python:3.11-slim"
    return [bash("docker pull python:3.11-slim"), result(text)]


def package_lock(rng, reg, v):
    pkg = rng.choice(["lodash", "left-pad", "chalk", "semver"])
    text = (
        f'    "node_modules/{pkg}": {{\n      "version": "{rng.randint(1, 5)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}",\n'
        f'      "resolved": "https://registry.npmjs.org/{pkg}/-/{pkg}.tgz",\n      "integrity": "sha512-{_decoy(reg, "b64_blob", decoys.b64_blob(rng))}"\n    }}'
    )
    return [bash(f"grep -A4 'node_modules/{pkg}\"' package-lock.json"), result(text)]


def fixture_payload(rng, reg, v):
    text = f'PNG_1X1 = "{_decoy(reg, "b64_blob", decoys.b64_blob(rng))}"\nEXPECTED_WIDTH = 1\nEXPECTED_HEIGHT = 1'
    return [call("read_file", path="tests/fixtures/images.py"), result(text, python=True)]


def git_remote_ssh(rng, reg, v):
    url = f"{_decoy(reg, 'example_email', 'git@github.com')}:example-org/{v.project}.git"
    return [bash("git remote get-url origin"), result(url)]


def versions(rng, reg, v):
    lines = [f"{name} {_decoy(reg, 'safe_ip', f'{rng.randint(1, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 40)}.{rng.randint(0, 9)}')}" for name in rng.sample(["libssl", "grpcio-tools", "chromedriver", "protoc-gen", "tzdata"], rng.randint(1, 3))]
    return [bash("./scripts/print-versions.sh"), result("\n".join(lines))]


DECOYS = [readme_docs, env_example, request_log, git_log_oneline, git_rev_parse, pip_hashes, docker_pull, package_lock, fixture_payload, git_remote_ssh, versions]
NEEDS_REPO |= {git_log_oneline, git_rev_parse, git_remote_ssh}


def decoy_event(rng: random.Random, reg: Registry, v: Vocab, has_repo: bool) -> list[dict]:
    options = [c for c in DECOYS if has_repo or c not in NEEDS_REPO]
    return rng.choice(options)(rng, reg, v)

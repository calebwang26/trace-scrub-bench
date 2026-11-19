"""Hand-written adversarial traces for the held-out test split.

The generator has a fixed set of templates. A scrubber could score well just
by learning those templates. These traces use formats the generator never
produces, so they test whether a scrubber generalizes.

They were written before any scrubber in this repo existed & are never used
for tuning. Each case is short: a command & its output.

Safety: as everywhere in this project, every secret carries FAKE & is glued
together from parts at runtime, so no key-shaped literal sits in this file.
The long random-looking bodies come from a fixed-seed random generator.
"""
from __future__ import annotations

import base64
import json
import random
from pathlib import Path

from tracegen.content import bash, result, say, user
from tracegen.generate import finish_trace, write_dataset
from tracegen.marks import Registry
from tracegen.sensitive import ALNUM, B64, MARK, b64url_json, rand

S, D, ADV = "sensitive", "decoy", "adversarial"
_rng = random.Random("adversarial-v1")  # only for filler characters


def _fill(alphabet: str, n: int) -> str:
    return rand(_rng, alphabet, n)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class Case:
    """One adversarial trace under construction."""

    def __init__(self, name: str, task: str):
        self.name, self.task = name, task
        self.reg = Registry()
        self.steps = [user(task)]

    def secret(self, type: str, value: str, text: str | None = None) -> str:
        return self.reg.plant(S, type, value, ADV, self.name, text=text)

    def fragments(self, type: str, value: str, pieces: list[str]) -> list[str]:
        i = self.reg.new(S, type, value, ADV, self.name)
        return [self.reg.wrap(i, p) for p in pieces]

    def decoy(self, value: str) -> str:
        return self.reg.plant(D, ADV, value)

    def run(self, command: str, output: str, python: bool = False) -> None:
        self.steps += [bash(command), result(output, python)]


def query_param(c: Case) -> None:
    """A key passed as a URL query parameter instead of a header."""
    key = "sk" + "-" + MARK + _fill(ALNUM, 44)
    c.run(f'curl -s "https://api.internal.example/v1/export?format=csv&api_key={c.secret("openai_key", key)}&limit=100"', '{"rows": 100}')


def hex_dump(c: Case) -> None:
    """A secret shown as plain hex (xxd -p), which hides every recognizable prefix."""
    token = "gh" + "p_" + MARK + _fill(ALNUM, 32)
    c.run("xxd -p -c 256 .token", c.secret("github_token", token, text=token.encode().hex()))


def new_github_formats(c: Case) -> None:
    """Token formats other than the classic `ghp_` one."""
    fine_grained = "github" + "_pat_" + MARK + _fill(ALNUM, 18) + "_" + _fill(ALNUM, 59)
    oauth = "gh" + "o_" + MARK + _fill(ALNUM, 32)
    c.run("gh auth status --show-token", f"github.com\n  ✓ Logged in to github.com account build-bot (keyring)\n  - Token: {c.secret('github_token', oauth)}")
    c.run("cat ~/.config/deploy/token", c.secret("github_token", fine_grained))


def aws_temporary_credentials(c: Case) -> None:
    """Temporary AWS credentials: a different key prefix & a long session token."""
    key_id = "AS" + "IA" + MARK + _fill("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12)
    session = "FwoGZXIvYXdzE" + MARK + _fill(B64, 180)
    body = json.dumps({"Credentials": {"AccessKeyId": c.secret("aws_key", key_id), "SessionToken": c.secret("aws_key", session), "Expiration": "2026-11-20T10:00:00Z"}}, indent=2, ensure_ascii=False)
    c.run("aws sts get-session-token --duration-seconds 3600", body)


def other_key_headers(c: Case) -> None:
    """Private keys whose header is not the usual `BEGIN ... PRIVATE KEY`-on-its-own-line shape."""
    dashes = "-" * 5
    openssh_body = "\n".join(["b3BlbnNzaC1rZXktdjEA" + MARK + _fill(B64, 46)] + [_fill(B64, 70) for _ in range(5)])
    openssh = f"{dashes}BEGIN OPENSSH PRIVATE" + f" KEY{dashes}\n{openssh_body}\n{dashes}END OPENSSH PRIVATE" + f" KEY{dashes}"
    c.run("cat ~/.ssh/id_ed25519", openssh.replace(openssh_body, c.secret("private_key", openssh_body)))
    pgp_body = "\n".join(["lQOYBG" + MARK + _fill(B64, 54)] + [_fill(B64, 64) for _ in range(4)] + ["=" + _fill(B64, 4)])
    pgp = f"{dashes}BEGIN PGP PRIVATE KEY" + f" BLOCK{dashes}\n\n{pgp_body}\n{dashes}END PGP PRIVATE KEY" + f" BLOCK{dashes}"
    script = f"#!/bin/sh\ngpg --batch --import <<'EOF'\n{pgp.replace(pgp_body, c.secret('private_key', pgp_body))}\nEOF\ngpg --list-secret-keys"
    c.run("cat scripts/import-signing-key.sh", script)


def wrapped_jwt(c: Case) -> None:
    """A JWT folded over three lines at a fixed width, as mail clients & some loggers do."""
    header = b64url_json({"alg": "HS256", "typ": "JWT"})
    payload = b64url_json({"sub": "svc_deploy", "role": "admin", "iat": 1760000000})
    token = f"{header}.{payload}." + MARK + _fill(ALNUM + "-_", 39)
    pieces = [token[i : i + 56] for i in range(0, len(token), 56)]
    a = c.fragments("jwt", token, pieces)
    c.run("grep -A3 'X-Service-Token' logs/proxy-debug.log", "X-Service-Token:\n " + "\n ".join(a) + "\nX-Request-Start: t=1760000000")


def database_credentials_without_a_url(c: Case) -> None:
    """Database passwords that are not inside a `scheme://user:pass@host` URL."""
    pw1, pw2, pw3 = MARK + "-orders-7731", MARK + _fill(ALNUM, 14), MARK + "%40pw%21" + _fill(ALNUM, 6)
    c.run("cat config/database.ini", f"[primary]\ndsn = host=db.internal.example port=5432 dbname=orders user=app password={c.secret('db_password', pw1)} sslmode=require")
    c.run(f"mysql -u root -p{c.secret('db_password', pw2)} -h mysql.internal.example -e 'show tables'", "Tables_in_app\norders\nusers")
    c.run("grep jdbc application.properties", f"spring.datasource.url=jdbc:postgresql://db.internal.example:5432/app?user=svc&password={c.secret('db_password', pw3)}&ssl=true")


def unusual_secret_names(c: Case) -> None:
    """Secrets under names that are not UPPER_CASE environment variables."""
    a, b, d = MARK + _fill(ALNUM, 24), MARK + "-winter-2291", MARK + _fill(ALNUM + "-_", 30)
    c.run("cat config/app.toml", f'[mailer]\nhost = "smtp.internal.example"\nuser = "notify"\npasswd = "{c.secret("env_secret", b)}"\n\n[search]\napi-key = "{c.secret("env_secret", a)}"')
    c.run("cat config/client.json", '{\n  "endpoint": "https://api.internal.example",\n  "clientSecret": "' + c.secret("env_secret", d) + '",\n  "timeoutMs": 3000\n}')


def python_repr(c: Case) -> None:
    """A secret inside a Python dict printed in a traceback: single quotes, no `=`."""
    pw = MARK + _fill(ALNUM, 16)
    text = (
        "Traceback (most recent call last):\n"
        '  File "/workspace/app/src/app/mailer.py", line 41, in send\n'
        "    smtp.login(**creds)\n"
        "smtplib.SMTPAuthenticationError: (535, b'Authentication failed')\n"
        f"locals: creds={{'user': 'notify', 'password': '{c.secret('env_secret', pw)}', 'port': 587}}"
    )
    c.run("python -m app.mailer --test", text)


def double_base64(c: Case) -> None:
    """A token base64-encoded twice."""
    token = "gh" + "p_" + MARK + _fill(ALNUM, 32)
    c.run("kubectl get configmap ci-bootstrap -o jsonpath='{.data.token_b64}'", c.secret("github_token", token, text=_b64(_b64(token))))


def obfuscated_emails(c: Case) -> None:
    """Emails written so that a simple pattern won't see them."""
    c.run("head -3 MAINTAINERS", f"# Security contact: {c.secret('email', 'ingrid.berg@fakecorp.example', text='ingrid.berg [at] fakecorp [dot] example')}\n# Please do not open public issues for vulnerabilities.")
    c.run("grep mailto docs/index.html", f'<a href="mailto:{c.secret("email", "rahul.kapoor@fakemail.test", text="rahul.kapoor%40fakemail.test")}?subject=Support">Contact support</a>')


def phone_formats(c: Case) -> None:
    """Phone numbers outside the US dash-&-parenthesis formats."""
    c.run(
        "cat ops/escalation.md",
        f"## Escalation\n\n1. London office: {c.secret('phone', '+44 20 7946 0958')}\n2. Pager (digits only): {c.secret('phone', '4155550142')}\n"
        f"3. Click to call: tel:{c.secret('phone', '+12125550187')}",
    )


def ip_shapes(c: Case) -> None:
    """IPv4 addresses that are not four dotted numbers standing alone."""
    c.run(
        "kubectl get nodes -o wide | head -3",
        f"NAME                          STATUS   ROLES    AGE\nip-{c.secret('ipv4', '10.0.12.7', text='10-0-12-7')}.ec2.internal    Ready    worker   41d",
    )
    c.run(f"curl -s http://{c.secret('ipv4', '192.168.4.20')}:9200/_cat/health", "1760000000 10:00:00 es-prod green 3 3")
    c.run("grep 'accepted' logs/gateway.log | tail -1", f"2026-11-02 08:14:09 INFO gateway: accepted connection from ::ffff:{c.secret('ipv4', '203.0.113.77')} port 51544")


def names_in_prose(c: Case) -> None:
    """Personal names without a helpful `Author:` label in front."""
    c.run(
        "git show -s --format=%B HEAD~2",
        f"Fix rounding in refund totals\n\nThanks to {c.secret('person_name', 'Ana María de la Cruz')} for the report & the failing test.\n\n"
        f"Co-authored-by: {c.secret('person_name', 'Kwame Mensah-Boateng')} <{c.secret('email', 'kwame@corp-fake.example')}>",
    )
    c.steps.append(say(f"The original author seems to be {c.secret('person_name', 'Yuki Tanaka')}; I'll keep their naming conventions."))


def harmless_lookalikes(c: Case) -> None:
    """Things that look sensitive & are not. A good scrubber leaves all of them alone."""
    c.run(
        "cat .env.defaults",
        f"SECRET_KEY_PATH={c.decoy('/etc/app/keys/current.pem')}\nPASSWORD_MIN_LENGTH={c.decoy('12')}\nTOKEN_EXPIRY_SECONDS={c.decoy('3600')}\nAPI_KEY_HEADER={c.decoy('X-Api-Key')}",
    )
    c.run("npm install", f"added 2 packages: {c.decoy('react@18.2.0')}, {c.decoy('lodash@4.17.21')}")
    c.run("openssl x509 -in certs/server.crt -noout -text | grep -A1 'Subject Alternative'", f"X509v3 extension {c.decoy('2.5.29.17')}:\n    DNS:app.internal.example")
    png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    c.run("grep -o 'data:image[^\"]*' static/pixel.html", f"data:image/png;base64,{c.decoy(png)}")
    c.run("cat docs/references.md", f"- Style guide, ISBN {c.decoy('978-3-16-148410-0')}\n- Build cache key: {c.decoy('sha1:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b')}")


CASES = [
    (query_param, "Check why the CSV export endpoint returns only 100 rows."),
    (hex_dump, "The deploy token file looks corrupted. Inspect its raw bytes."),
    (new_github_formats, "Find out which GitHub identity the build machine is using."),
    (aws_temporary_credentials, "Get temporary AWS credentials for the upload script."),
    (other_key_headers, "The signing step fails in CI. Check how the signing key is imported."),
    (wrapped_jwt, "The proxy rejects our service token. Look at what is actually sent."),
    (database_credentials_without_a_url, "List every place the app's database connection is configured."),
    (unusual_secret_names, "Move the mailer & search settings into environment variables."),
    (python_repr, "The mailer test fails with an authentication error. Reproduce it."),
    (double_base64, "CI bootstrap can't read its token from the config map. Show the stored value."),
    (obfuscated_emails, "Update the security contact in the docs."),
    (phone_formats, "Reformat the escalation runbook as a table."),
    (ip_shapes, "Elasticsearch looks unhealthy. Check the cluster from the gateway host."),
    (names_in_prose, "Summarize the last three commits that touched refund totals."),
    (harmless_lookalikes, "Document the default settings & the front-end dependencies."),
]


def build() -> list[tuple[dict, list[dict], list[dict], list[dict]]]:
    """Build every adversarial trace in the generator's row format."""
    global _rng
    _rng = random.Random("adversarial-v1")  # reset, so every call builds identical traces
    built = []
    for number, (fn, task) in enumerate(CASES, start=1):
        case = Case(fn.__name__, task)
        fn(case)
        case.steps.append(say("Done. See the output above."))
        meta = {"trace_id": f"adv-{number:02d}-{fn.__name__.replace('_', '-')}", "model": "hand-written", "harness": "hand-written", "task": task, "outcome": "success", "has_repo": False}
        built.append(finish_trace(meta, case.steps, case.reg))
    return built


def write(out_dir: str | Path) -> dict:
    return write_dataset(build(), out_dir, {"source": "hand-written adversarial traces, v1"})


if __name__ == "__main__":
    print(json.dumps(write("bench/data/adversarial"), indent=2))

"""Factories for the sensitive values that get planted in traces.

Everything here is synthetic. Two safety rules shape the code:

1. Every secret contains the marker FAKE where its format allows, so it is
   obvious to a human, to this repo's secret scanner & to GitHub's scanner.
2. No complete key-shaped string is written in this file. Each value is
   assembled at runtime from parts (prefix + FAKE + random characters).

Formats that can't carry the marker use reserved ranges instead: phone numbers
use the fictional 555-01xx block, IP addresses use private & documentation
ranges, & email domains end in the reserved .example / .test.
"""
from __future__ import annotations

import base64
import json
import random
import string

MARK = "FA" + "KE"

ALNUM = string.ascii_letters + string.digits
UPPER_B32 = string.ascii_uppercase + "234567"  # the alphabet of AWS key ids
B64 = ALNUM + "+/"
B64URL = ALNUM + "-_"
HEX = "0123456789abcdef"

# Severity tiers live in bench/score.py. This is just the list of types.
TYPES = [
    "private_key",
    "aws_key",
    "github_token",
    "openai_key",
    "jwt",
    "db_password",
    "env_secret",
    "email",
    "phone",
    "person_name",
    "ipv4",
]


def rand(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _b64url_json(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# --- secrets -----------------------------------------------------------------

def aws_key(rng: random.Random) -> str:
    """AWS access key id: 'AKIA' + 16 base32 characters (20 total)."""
    return "AK" + "IA" + MARK + rand(rng, UPPER_B32, 12)


def github_token(rng: random.Random) -> str:
    """Classic GitHub personal access token: 'ghp_' + 36 characters."""
    return "gh" + "p_" + MARK + rand(rng, ALNUM, 32)


def openai_key(rng: random.Random) -> str:
    """OpenAI-style API key, in one of three shapes seen in the wild."""
    style = rng.choices(["classic", "project", "generic"], weights=[4, 3, 3])[0]
    if style == "classic":  # sk- + 20 + a fixed middle marker + 20
        return "sk" + "-" + MARK + rand(rng, ALNUM, 16) + "T3Blbk" + "FJ" + rand(rng, ALNUM, 20)
    if style == "project":  # newer keys: longer, with - & _ inside
        return "sk" + "-proj-" + MARK + rand(rng, B64URL, 60)
    return "sk" + "-" + MARK + rand(rng, ALNUM, 44)


def jwt(rng: random.Random) -> str:
    """JSON Web Token: header.payload.signature, each base64url."""
    header = _b64url_json({"alg": "HS256", "typ": "JWT"})
    payload = _b64url_json(
        {
            "sub": f"user_{rng.randrange(10**6):06d}",
            "role": rng.choice(["admin", "service", "member", "billing"]),
            "iat": 1760000000 + rng.randrange(10**6),
        }
    )
    signature = MARK + rand(rng, B64URL, 39)
    return f"{header}.{payload}.{signature}"


def private_key(rng: random.Random) -> str:
    """A PEM private-key block (header line, base64 body, footer line)."""
    label = rng.choice(["RSA ", "EC ", ""]) + "PRIVATE" + " KEY"
    n_lines = rng.randint(5, 12)
    lines = ["MIIE" + MARK + rand(rng, B64, 56)]
    lines += [rand(rng, B64, 64) for _ in range(n_lines - 1)]
    lines.append(rand(rng, B64, rng.randint(20, 60)) + "==")
    dashes = "-" * 5
    return f"{dashes}BEGIN {label}{dashes}\n" + "\n".join(lines) + f"\n{dashes}END {label}{dashes}"


_PW_WORDS = ["summer", "dragon", "orders", "prod", "falcon", "billing", "winter", "admin", "tiger", "staging"]


def password(rng: random.Random, special: bool = False) -> str:
    """A password. Some are random, some are the human kind (low randomness)."""
    style = rng.choices(["random", "human"], weights=[6, 4])[0]
    if style == "random":
        pw = MARK + rand(rng, ALNUM, rng.randint(10, 18))
    else:
        pw = MARK + "-" + rng.choice(_PW_WORDS) + "-" + str(rng.randint(10, 9999))
    if special:  # characters that must be escaped inside JSON
        i = rng.randint(len(MARK) + 1, len(pw) - 1)
        pw = pw[:i] + rng.choice(['"', "\\", '"$', '\\"']) + pw[i:]
    return pw


_DB_SCHEMES = ["postgres", "postgresql", "mysql", "mongodb", "redis", "postgresql+psycopg2"]
_DB_USERS = ["app", "app_user", "admin", "svc_orders", "postgres", "root", "readonly", "etl"]
_DB_HOSTS = ["db-prod.internal.example", "pg-primary.corp.example", "db.staging.example", "localhost", "mysql-01.internal.example"]
_DB_NAMES = ["orders", "app", "billing", "analytics", "users", "inventory", "main"]


def db_url_parts(rng: random.Random) -> tuple[str, str, str]:
    """A database URL as (before, password, after). Only the password is the secret."""
    scheme = rng.choice(_DB_SCHEMES)
    port = {"postgres": 5432, "postgresql": 5432, "postgresql+psycopg2": 5432, "mysql": 3306, "mongodb": 27017, "redis": 6379}[scheme]
    before = f"{scheme}://{rng.choice(_DB_USERS)}:"
    after = f"@{rng.choice(_DB_HOSTS)}:{port}/{rng.choice(_DB_NAMES)}"
    return before, password(rng), after


_ENV_NAMES = [
    "SESSION_SECRET", "JWT_SECRET", "DJANGO_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "APP_SECRET",
    "CLIENT_SECRET", "SECRET_KEY_BASE", "FLASK_SECRET_KEY", "OAUTH_CLIENT_SECRET", "COOKIE_SECRET",
    "ADMIN_PASSWORD", "SMTP_PASSWORD", "REDIS_PASSWORD", "ENCRYPTION_KEY", "SIGNING_KEY",
    "SENTRY_AUTH_TOKEN", "DEPLOY_TOKEN", "INTERNAL_API_TOKEN",
]


def env_secret(rng: random.Random, special: bool = False) -> tuple[str, str]:
    """A .env-style line as (NAME, value). Only the value is the secret."""
    name = rng.choice(_ENV_NAMES)
    style = rng.choices(["hex", "b64", "password"], weights=[3, 4, 3])[0]
    if special or style == "password":
        return name, password(rng, special=special)
    if style == "hex":
        return name, MARK.lower() + rand(rng, HEX, rng.choice([28, 36, 60]))
    return name, MARK + rand(rng, B64URL, rng.choice([28, 40, 44]))


# --- personal data -----------------------------------------------------------

_FIRST = [
    "Dana", "Priya", "Marcus", "Elena", "Tomás", "Aiko", "Kwame", "Sofia", "Liam", "Noor", "Hannah", "Diego",
    "Mei", "Olu", "Ingrid", "Rahul", "Zoe", "Mateo", "Fatima", "Jonas", "Chloe", "Arjun", "Nadia", "Victor",
    "Yuki", "Amara", "Peter", "Leila", "Oscar", "Greta",
]
_LAST = [
    "Reyes", "Nair", "Okafor", "Petrova", "Lindqvist", "Tanaka", "Mensah", "Costa", "Murphy", "Haddad", "Schmidt",
    "Alvarez", "Chen", "Adeyemi", "Berg", "Kapoor", "Novak", "Silva", "Rahman", "Keller", "Dubois", "Iyer",
    "Kowalski", "Marin", "Sato", "Eze", "Hughes", "Farouk", "Lund", "Weiss",
]
_EMAIL_DOMAINS = ["fakecorp.example", "fakemail.test", "corp-fake.example", "fake-startup.example", "team.fakelabs.example"]


def person_name(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"


def _ascii(s: str) -> str:
    return s.replace("á", "a")


def email(rng: random.Random, name: str | None = None) -> str:
    """An email address at a reserved domain, optionally matching a person's name."""
    first, last = (name or person_name(rng)).lower().split(" ", 1)
    first, last = _ascii(first), _ascii(last)
    local = rng.choice([f"{first}.{last}", f"{first[0]}{last}", f"{first}", f"{first}_{last}{rng.randint(1, 99)}", f"{first}.{last}+dev"])
    return f"{local}@{rng.choice(_EMAIL_DOMAINS)}"


def phone(rng: random.Random) -> str:
    """A US phone number in the fictional 555-0100..0199 block."""
    area = rng.choice(["415", "212", "646", "510", "312", "206", "617", "303"])
    last = f"01{rng.randrange(100):02d}"
    fmt = rng.choice(["({a}) 555-{l}", "{a}-555-{l}", "+1 {a} 555 {l}", "{a}.555.{l}", "+1-{a}-555-{l}", "1 ({a}) 555-{l}"])
    return fmt.format(a=area, l=last)


def ipv4(rng: random.Random) -> str:
    """An IPv4 address from a private or documentation range."""
    kind = rng.choice(["10", "172", "192.168", "doc"])
    if kind == "10":
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    if kind == "172":
        return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    if kind == "192.168":
        return f"192.168.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
    return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(2, 254)}"

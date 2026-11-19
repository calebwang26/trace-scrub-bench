"""Decoys: strings that look sensitive but are not.

A good scrubber leaves these alone. The benchmark tracks them to measure how
much harmless content a scrubber destroys. Like the secrets, key-shaped decoys
are assembled from parts so no key-shaped literal sits in this file.
"""
from __future__ import annotations

import base64
import random
import uuid as _uuid

from tracegen.sensitive import HEX, rand

DECOY_TYPES = ["doc_example_key", "env_placeholder", "uuid", "git_sha", "sha256", "b64_blob", "safe_ip", "example_email"]


def doc_example_key(rng: random.Random) -> str:
    """Placeholder keys of the kind found in READMEs & API docs."""
    return rng.choice(
        [
            "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",  # the example key id from the AWS docs
            "sk" + "-" + "x" * 32,
            "gh" + "p_" + "x" * 36,
            "sk" + "-your-api-key-here",
            "<YOUR_API_KEY>",
            "sk" + "-" + "0" * 24,
            "gh" + "p_" + "EXAMPLE" + "0" * 29,
        ]
    )


def env_placeholder(rng: random.Random) -> tuple[str, str]:
    """A (NAME, value) pair from an .env.example file: the value is a placeholder."""
    name = rng.choice(["SESSION_SECRET", "JWT_SECRET", "API_TOKEN", "ADMIN_PASSWORD", "SECRET_KEY", "CLIENT_SECRET"])
    value = rng.choice(["changeme", "your-secret-here", "<set-me>", "xxxxxxxx", "replace-with-real-value", "TODO"])
    return name, value


def uuid(rng: random.Random) -> str:
    return str(_uuid.UUID(int=rng.getrandbits(128), version=4))


def git_sha(rng: random.Random, short: bool | None = None) -> str:
    if short is None:
        short = rng.random() < 0.4
    return rand(rng, HEX, rng.choice([7, 8, 10]) if short else 40)


def sha256(rng: random.Random) -> str:
    return rand(rng, HEX, 64)


def b64_blob(rng: random.Random) -> str:
    """Random-looking base64 that is public: an npm integrity hash or a test payload."""
    raw = bytes(rng.getrandbits(8) for _ in range(rng.choice([24, 48, 64])))
    return base64.b64encode(raw).decode()


def safe_ip(rng: random.Random) -> str:
    """Looks like an IPv4 address but is harmless: loopback, wildcard or a version number."""
    return rng.choice(["127.0.0.1", "0.0.0.0", "127.0.0.1", f"{rng.randint(1, 4)}.{rng.randint(0, 20)}.{rng.randint(0, 30)}.{rng.randint(0, 9)}"])


def example_email(rng: random.Random) -> str:
    """Email-shaped strings that identify nobody."""
    return rng.choice(["user@example.com", "you@example.com", "noreply@github.com", "git@github.com", "name@example.org", "test@test.com"])

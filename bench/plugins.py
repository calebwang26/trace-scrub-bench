"""Plug-in interface: how the benchmark finds & calls a scrubber.

A scrubber is anything that turns a text into a scrubbed text:

    scrub(text: str) -> str

Entries are listed in scrubbers.yaml, in one of two forms:

    - name: my-scrubber
      entry: some.module:function        # a Python function scrub(text) -> str

    - name: my-cli-tool
      command: ["my-tool", "--redact"]   # reads text on stdin, writes it on stdout

The benchmark loads every entry by name & calls them all the same way. It
never imports a scrubber directly, so it can't depend on one's internals.

A Python entry may also point at an object with a `scrub_many(texts)` method
(one call per trace). That exists for tools with a high start-up cost, such as
a command-line scanner that would otherwise be launched once per step.
"""
from __future__ import annotations

import importlib
import subprocess
from pathlib import Path
from typing import Callable

import yaml

REGISTRY = Path(__file__).resolve().parent / "scrubbers.yaml"


class Unavailable(Exception):
    """An optional scrubber whose dependencies are not installed."""


def load_registry(path: str | Path = REGISTRY) -> list[dict]:
    entries = yaml.safe_load(Path(path).read_text(encoding="utf-8"))["scrubbers"]
    names = [e["name"] for e in entries]
    if len(names) != len(set(names)):
        raise ValueError("scrubber names must be unique")
    for e in entries:
        if ("entry" in e) == ("command" in e):
            raise ValueError(f"{e['name']}: give exactly one of 'entry' or 'command'")
    return entries


def _from_command(command: list[str]) -> Callable[[str], str]:
    def scrub(text: str) -> str:
        done = subprocess.run(command, input=text, capture_output=True, text=True, check=True)
        return done.stdout

    return scrub


def load(entry: dict) -> Callable[[list[str]], list[str]]:
    """Return the entry as `scrub_many(texts) -> texts`, the form the scorer calls."""
    if "command" in entry:
        scrub = _from_command(entry["command"])
        return lambda texts: [scrub(t) for t in texts]
    module_name, _, attr = entry["entry"].partition(":")
    try:
        target = getattr(importlib.import_module(module_name), attr)
    except ImportError as error:
        if entry.get("optional"):
            raise Unavailable(f"{entry['name']}: {error}") from error
        raise
    if hasattr(target, "available") and not target.available():
        raise Unavailable(f"{entry['name']}: {target.why_unavailable()}")
    if hasattr(target, "scrub_many"):
        return target.scrub_many
    scrub = target.scrub if hasattr(target, "scrub") else target
    return lambda texts: [scrub(t) for t in texts]

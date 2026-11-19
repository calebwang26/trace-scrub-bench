"""Ordinary coding-agent work: the non-sensitive bulk of every trace.

Each function here returns a list of steps (usually a tool call plus its
result). Nothing in this file is sensitive: no emails, no names, no IP
addresses, no keys. Sensitive items & decoys are added by carriers.py, so the
ground truth stays complete.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass

from tracegen.sensitive import HEX, rand

PROJECTS = ["orderflow", "ledgerly", "pixelgrid", "routewise", "tasklane", "stockroom", "mailmerge", "quotekit", "farebox", "shiftplan"]
MODULES = ["orders", "billing", "auth", "inventory", "search", "notifications", "reports", "payments", "users", "shipping", "pricing", "exports"]
NOUNS = ["refund", "invoice", "discount", "total", "tax", "quota", "window", "batch", "retry", "cursor", "slug", "rate"]
VERBS = ["compute", "apply", "parse", "normalize", "validate", "merge", "resolve", "format", "split", "round"]
ATTRS = ["amount", "quantity", "price", "weight", "score", "count"]
BUGS = [
    "rounds half-cents the wrong way",
    "crashes on an empty list",
    "is off by one at the page boundary",
    "ignores the timezone when comparing dates",
    "double-counts items after a retry",
    "returns None instead of raising for bad input",
    "mutates its input list",
    "treats 0 as missing",
]


@dataclass
class Vocab:
    """The names used consistently throughout one trace."""

    project: str
    module: str
    fn: str
    noun: str
    attr: str
    bug: str

    @property
    def path(self) -> str:
        return f"src/{self.project}/{self.module}.py"

    @property
    def test_path(self) -> str:
        return f"tests/test_{self.module}.py"

    @property
    def test_name(self) -> str:
        return f"test_{self.fn}_{self.noun}"


def make_vocab(rng: random.Random) -> Vocab:
    noun = rng.choice(NOUNS)
    return Vocab(rng.choice(PROJECTS), rng.choice(MODULES), f"{rng.choice(VERBS)}_{noun}", noun, rng.choice(ATTRS), rng.choice(BUGS))


# --- step helpers ------------------------------------------------------------

def step(role: str, type: str, content: str, python: bool = False) -> dict:
    return {"role": role, "type": type, "content": content, "python": python}


def call(tool: str, **args) -> dict:
    """An assistant tool call. Its content is one line of JSON, as harnesses log it."""
    return step("assistant", "tool_call", json.dumps({"tool": tool, "args": args}, ensure_ascii=False))


def bash(command: str) -> dict:
    return call("bash", command=command)


def result(text: str, python: bool = False) -> dict:
    return step("tool", "tool_result", text, python)


def say(text: str) -> dict:
    return step("assistant", "message", text)


def user(text: str) -> dict:
    return step("user", "message", text)


def timestamp(rng: random.Random) -> str:
    return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"


def fill(template: str, **values) -> str:
    """Replace {name} tokens. Unlike str.format, other braces are left alone."""
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    return template


# --- Python source -----------------------------------------------------------

_FUNCS = [
    '''def {fn}(items, factor={n}):
    """Return the {noun} total for items, scaled by factor."""
    if items is None:
        raise ValueError("items is required")
    total = 0
    for item in items:
        total += item.{attr} * factor
    return round(total, 2)
''',
    '''def {fn}(value, default=None):
    """Normalize a raw {noun} value read from the request."""
    if value is None or value == "":
        return default
    text = str(value).strip().lower()
    if text in ("none", "null"):
        return default
    return text
''',
    '''def {fn}(records, page=1, per_page={n}):
    """Return one page of {noun} records, newest first."""
    start = (page - 1) * per_page
    ordered = sorted(records, key=lambda r: r.created_at, reverse=True)
    return ordered[start:start + per_page]
''',
    '''class {cls}:
    """Tracks the running {noun} for one account."""

    def __init__(self, limit={n}):
        self.limit = limit
        self.entries = []

    def add(self, {attr}):
        if {attr} < 0:
            raise ValueError("{attr} must be >= 0")
        self.entries.append({attr})
        return sum(self.entries) <= self.limit
''',
    '''def {fn}(start, end, step={n}):
    """Yield {noun} windows between start & end."""
    current = start
    while current < end:
        upper = min(current + step, end)
        yield current, upper
        current = upper
''',
    '''def {fn}(payload):
    """Validate a {noun} payload & return the cleaned fields."""
    errors = {}
    for field in ("id", "{attr}", "currency"):
        if field not in payload:
            errors[field] = "missing"
    if errors:
        raise ValidationError(errors)
    return {"id": int(payload["id"]), "{attr}": float(payload["{attr}"])}
''',
    '''def {fn}(left, right):
    """Merge two {noun} mappings; values from right win."""
    merged = dict(left)
    for key, value in right.items():
        if value is not None:
            merged[key] = value
    return merged
''',
    '''def {fn}(attempt, base={n}, cap=60):
    """Seconds to wait before retry number attempt."""
    delay = base * (2 ** attempt)
    logger.debug("{noun} retry %s waits %ss", attempt, delay)
    return min(delay, cap)
''',
]

_IMPORTS = ["import logging", "import os", "from dataclasses import dataclass", "from decimal import Decimal", "import json", "from datetime import datetime, timezone"]


def python_module(rng: random.Random, v: Vocab, extra_lines: list[str] | None = None, n_funcs: int | None = None) -> str:
    """Source of a small Python module. `extra_lines` go into the constants section."""
    imports = sorted(rng.sample(_IMPORTS, rng.randint(2, 4)), key=lambda s: s.split()[1])
    constants = [f"MAX_{v.noun.upper()}S = {rng.randint(2, 500)}", f"DEFAULT_{v.attr.upper()} = {rng.randint(0, 20)}"]
    lines = constants + list(extra_lines or [])
    rng.shuffle(lines)
    funcs = []
    templates = rng.sample(_FUNCS, n_funcs or rng.randint(1, 3))
    for i, template in enumerate(templates):
        name = v.fn if i == 0 else f"{rng.choice(VERBS)}_{rng.choice(NOUNS)}"
        funcs.append(fill(template, fn=name, cls=v.noun.title() + "Tracker", noun=v.noun, attr=v.attr, n=rng.randint(2, 50)))
    head = f'"""{v.module.title()} helpers for {v.project}."""\n' + "\n".join(imports) + "\n\nlogger = logging.getLogger(__name__)\n\n"
    return head + "\n".join(lines) + "\n\n\n" + "\n\n".join(funcs)


def python_test_file(rng: random.Random, v: Vocab) -> str:
    cases = "\n\n".join(
        f"def {v.test_name}_{name}():\n    assert {v.fn}({args}) == {expected}"
        for name, args, expected in rng.sample(
            [("empty", "[]", "0"), ("single", "[Item(2)]", "4"), ("negative", "[Item(-1)]", "-2"), ("many", "[Item(1), Item(2)]", "6"), ("zero", "[Item(0)]", "0")],
            rng.randint(2, 4),
        )
    )
    return f"import pytest\n\nfrom {v.project}.{v.module} import {v.fn}\nfrom tests.factories import Item\n\n\n{cases}\n"


# --- background actions ------------------------------------------------------

def read_source(rng, v):
    return [call("read_file", path=v.path), result(python_module(rng, v), python=True)]


def read_tests(rng, v):
    return [call("read_file", path=v.test_path), result(python_test_file(rng, v), python=True)]


def pytest_output(rng: random.Random, v: Vocab, passed: bool) -> str:
    n = rng.randint(3, 24)
    secs = f"{rng.uniform(0.05, 4):.2f}"
    head = (
        "============================= test session starts ==============================\n"
        f"platform linux -- Python 3.11.{rng.randint(4, 11)}, pytest-8.{rng.randint(0, 3)}.{rng.randint(0, 4)}, pluggy-1.5.0\n"
        f"rootdir: /workspace/{v.project}\ncollected {n} items\n\n"
    )
    if passed:
        return head + f"{v.test_path} {'.' * n}{' ' * 20}[100%]\n\n============================== {n} passed in {secs}s ==============================="
    got, want = rng.randint(1, 90), rng.randint(91, 180)
    k = rng.randrange(n)
    return head + (
        f"{v.test_path} {'.' * k}F{'.' * (n - k - 1)}{' ' * 20}[100%]\n\n"
        "=================================== FAILURES ===================================\n"
        f"___________________________ {v.test_name} ___________________________\n\n"
        f"    def {v.test_name}():\n>       assert {v.fn}(items) == {want}\nE       assert {got} == {want}\n\n"
        f"{v.test_path}:{rng.randint(8, 140)}: AssertionError\n"
        "=========================== short test summary info ============================\n"
        f"FAILED {v.test_path}::{v.test_name} - assert {got} == {want}\n"
        f"========================= 1 failed, {n - 1} passed in {secs}s ========================="
    )


def run_pytest(rng, v, passed=None):
    if passed is None:
        passed = rng.random() < 0.4
    flags = rng.choice(["-x", "-q", "-x -q", "", "--maxfail=1"])
    return [bash(f"pytest {flags} {v.test_path}".replace("  ", " ")), result(pytest_output(rng, v, passed))]


def edit_source(rng, v):
    old = f"        total += item.{v.attr} * factor"
    new = rng.choice([f"        total += Decimal(str(item.{v.attr})) * factor", f"        if item.{v.attr} is None:\n            continue\n        total += item.{v.attr} * factor"])
    return [call("edit_file", path=v.path, old=old, new=new), result(f"Applied 1 edit to {v.path}")]


def grep(rng, v):
    hits = [f"{v.path}:{rng.randint(5, 200)}:def {v.fn}(items, factor=2):"]
    hits += [f"src/{v.project}/{m}.py:{rng.randint(5, 300)}:    value = {v.fn}(batch)" for m in rng.sample(MODULES, rng.randint(1, 3))]
    hits.append(f"{v.test_path}:{rng.randint(3, 60)}:from {v.project}.{v.module} import {v.fn}")
    return [bash(f"grep -rn '{v.fn}' src tests"), result("\n".join(hits))]


def list_files(rng, v):
    names = sorted(rng.sample(MODULES, rng.randint(4, 8)) + ["__init__"])
    return [bash(f"ls src/{v.project}"), result("\n".join(f"{n}.py" for n in names))]


def git_status(rng, v):
    return [bash("git status --short"), result(rng.choice([f" M {v.path}", f" M {v.path}\n M {v.test_path}", f" M {v.path}\n?? scratch.py"]))]


def git_diff(rng, v):
    a, b = rand(rng, HEX, 7), rand(rng, HEX, 7)
    line = rng.randint(10, 120)
    text = (
        f"diff --git a/{v.path} b/{v.path}\nindex {a}..{b} 100644\n--- a/{v.path}\n+++ b/{v.path}\n"
        f"@@ -{line},7 +{line},7 @@ def {v.fn}(items, factor=2):\n     total = 0\n     for item in items:\n"
        f"-        total += item.{v.attr} * factor\n+        total += Decimal(str(item.{v.attr})) * factor\n     return round(total, 2)"
    )
    return [bash("git diff"), result(text)]


def cat_config(rng, v):
    kind = rng.choice(["toml", "yaml", "json"])
    if kind == "toml":
        text = f'[project]\nname = "{v.project}"\nversion = "{rng.randint(0, 3)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"\nrequires-python = ">=3.10"\n\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\naddopts = "-ra"'
        return [bash("cat pyproject.toml"), result(text)]
    if kind == "yaml":
        text = f"app:\n  name: {v.project}\n  workers: {rng.randint(1, 8)}\n  log_level: {rng.choice(['info', 'debug', 'warning'])}\n{v.module}:\n  page_size: {rng.randint(10, 200)}\n  retry_limit: {rng.randint(1, 6)}"
        return [bash("cat config/settings.yaml"), result(text)]
    text = json.dumps({"name": v.project, "features": {v.module: True, "beta_" + v.noun: False}, "page_size": rng.randint(10, 200)}, indent=2)
    return [bash("cat config/app.json"), result(text)]


def pip_install(rng, v):
    pkgs = rng.sample(["requests", "pydantic", "sqlalchemy", "httpx", "click", "rich", "attrs", "tenacity"], rng.randint(1, 3))
    lines = [f"Collecting {p}" for p in pkgs] + ["Installing collected packages: " + ", ".join(pkgs)]
    lines.append("Successfully installed " + " ".join(f"{p}-{rng.randint(0, 3)}.{rng.randint(0, 30)}.{rng.randint(0, 9)}" for p in pkgs))
    return [bash("pip install " + " ".join(pkgs)), result("\n".join(lines))]


def run_script(rng, v):
    t = timestamp(rng)
    lines = [
        f"{t} INFO {v.project}.{v.module}: starting {v.noun} job",
        f"{t} INFO {v.project}.{v.module}: loaded {rng.randint(10, 9000)} rows",
        f"{t} {rng.choice(['INFO', 'WARNING'])} {v.project}.{v.module}: {v.fn} finished in {rng.randint(3, 900)}ms",
    ]
    return [bash(f"python -m {v.project}.{v.module} --dry-run"), result("\n".join(lines))]


BACKGROUND = [(read_source, 5), (read_tests, 3), (run_pytest, 6), (edit_source, 4), (grep, 3), (list_files, 2), (cat_config, 2), (pip_install, 1), (run_script, 2)]
BACKGROUND_REPO = [(git_status, 2), (git_diff, 2)]

THOUGHTS = [
    "Let me look at the failing test first.",
    "I'll read `{path}` to see how `{fn}` is implemented.",
    "The bug is in `{fn}`: it {bug}. I'll fix that.",
    "Running the tests to see where things stand.",
    "That change didn't fix it. Looking closer at the {noun} handling.",
    "I need to check where `{fn}` is called from.",
    "The test expects a different {noun}. Let me compare with the implementation.",
    "Applying a smaller fix that keeps the public signature the same.",
    "Checking the configuration before I change anything else.",
    "Let me re-run only the {module} tests.",
]

TASKS = [
    "The test `{test_name}` in `{test_path}` is failing. `{fn}` {bug}. Please fix it without changing the public API.",
    "In {project}, `{fn}` in `{path}` {bug}. Find the cause, fix it & make sure the {module} tests pass.",
    "Users report a problem in the {module} module of {project}: `{fn}` {bug}. Add a regression test & fix the bug.",
    "Please investigate why `{fn}` {bug}. The relevant code is in `{path}`.",
]


def thought(rng: random.Random, v: Vocab) -> dict:
    return say(fill(rng.choice(THOUGHTS), path=v.path, fn=v.fn, bug=v.bug, noun=v.noun, module=v.module))


def task(rng: random.Random, v: Vocab) -> str:
    return fill(rng.choice(TASKS), test_name=v.test_name, test_path=v.test_path, fn=v.fn, bug=v.bug, project=v.project, path=v.path, module=v.module)


def weighted(rng: random.Random, options: list[tuple]):
    return rng.choices([o[0] for o in options], weights=[o[1] for o in options])[0]

"""Score a scrubber against a dataset whose sensitive items are known.

The scorer never looks at how a scrubber works. It only sees the text before
& after, lines them up (align.py) & asks, character by character, what
disappeared. From that it computes:

  recall          share of planted items that were removed
  severity score  the same, but each item weighted by how bad a leak would be
  precision       of the characters removed, the share that was sensitive
  utility kept    share of non-sensitive characters that survived
  decoys kept     share of harmless look-alikes left fully intact
  Python kept     share of Python files that still parse after scrubbing
  speed           traces per second
"""
from __future__ import annotations

import ast
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from bench.align import surviving

# How bad is a leak of each type? Private keys & cloud keys give direct access
# to infrastructure. API tokens & passwords give access to one service.
# Emails, phones & names identify a person. An internal IP reveals little alone.
SEVERITY = {
    "private_key": 10, "aws_key": 10,
    "github_token": 7, "openai_key": 7, "jwt": 7, "db_password": 7, "env_secret": 7,
    "email": 3, "phone": 3, "person_name": 3,
    "ipv4": 1,
}


def allowed_survivors(length: int) -> int:
    """How many characters of an item may survive while it still counts as removed.

    At most 4, & never more than a quarter of the item. That lets a scrubber
    keep a public prefix such as `ghp_` or `AKIA`, & nothing more: half a key
    is still a leaked key.
    """
    return min(4, length // 4)


@dataclass
class Dataset:
    traces: list[dict]
    truth: dict[tuple[str, int], list[dict]] = field(default_factory=dict)  # (trace_id, step) -> planted items
    decoys: dict[tuple[str, int], list[dict]] = field(default_factory=dict)  # (trace_id, step) -> decoys
    python_steps: set[tuple[str, int]] = field(default_factory=set)


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_dataset(*folders: str | Path) -> Dataset:
    """Load one or more folders written by the generator & join them."""
    data = Dataset(traces=[])
    for folder in map(Path, folders):
        data.traces += _jsonl(folder / "traces.jsonl")
        for name, target in (("ground_truth.jsonl", data.truth), ("decoys.jsonl", data.decoys)):
            for row in _jsonl(folder / name):
                target.setdefault((row["trace_id"], row["step"]), []).append(row)
        data.python_steps |= {(r["trace_id"], r["step"]) for r in _jsonl(folder / "python_steps.jsonl")}
    return data


def per_text(scrub: Callable[[str], str]) -> Callable[[list[str]], list[str]]:
    """Turn a one-text scrubber into the per-trace form the scorer calls."""
    return lambda texts: [scrub(t) for t in texts]


def _parses(source: str) -> bool:
    try:
        ast.parse(source)
        return True
    except (SyntaxError, ValueError):
        return False


def _ratio(a: float, b: float) -> float | None:
    return a / b if b else None


def score(data: Dataset, scrub_many: Callable[[list[str]], list[str]], name: str = "scrubber", keep_misses: bool = False) -> dict:
    """Run a scrubber over every step of every trace & return its scores.

    `scrub_many` takes the list of step texts of one trace & returns the
    scrubbed texts in the same order.
    """
    seconds = 0.0
    chars = Counter()  # total, sensitive, removed, removed_sensitive
    items, removed_items = Counter(), Counter()  # by type
    variants, removed_variants = Counter(), Counter()
    weight_total = weight_removed = 0
    decoys, decoys_kept = Counter(), Counter()
    python_total = python_ok = 0
    misses: list[dict] = []
    false_positives: list[dict] = []

    for trace in data.traces:
        texts = [s["content"] for s in trace["steps"]]
        start = time.perf_counter()
        outputs = scrub_many(texts)
        seconds += time.perf_counter() - start
        if len(outputs) != len(texts) or not all(isinstance(o, str) for o in outputs):
            raise TypeError(f"{name}: a scrubber must return one string per input text")

        for step, (original, scrubbed) in enumerate(zip(texts, outputs)):
            key = (trace["trace_id"], step)
            keep = surviving(original, scrubbed)
            chars["total"] += len(original)
            chars["removed"] += len(original) - keep.count(1)

            for item in data.truth.get(key, ()):
                length = sum(b - a for a, b in item["spans"])
                survivors = sum(keep[a:b].count(1) for a, b in item["spans"])
                chars["sensitive"] += length
                chars["removed_sensitive"] += length - survivors
                gone = survivors <= allowed_survivors(length)
                weight = SEVERITY[item["type"]]
                items[item["type"]] += 1
                variants[item["variant"]] += 1
                weight_total += weight
                if gone:
                    removed_items[item["type"]] += 1
                    removed_variants[item["variant"]] += 1
                    weight_removed += weight
                elif keep_misses:
                    misses.append({**item, "survivors": survivors, "scrubbed": scrubbed})

            for decoy in data.decoys.get(key, ()):
                decoys[decoy["type"]] += 1
                intact = all(keep[a:b].count(0) == 0 for a, b in decoy["spans"])
                decoys_kept[decoy["type"]] += intact
                if keep_misses and not intact:
                    false_positives.append({**decoy, "scrubbed": scrubbed})

            if key in data.python_steps:
                python_total += 1
                python_ok += scrubbed == original or _parses(scrubbed)

    n_items = sum(items.values())
    non_sensitive = chars["total"] - chars["sensitive"]
    destroyed = chars["removed"] - chars["removed_sensitive"]
    result = {
        "name": name,
        "n_traces": len(data.traces),
        "n_items": n_items,
        "recall": _ratio(sum(removed_items.values()), n_items),
        "severity_score": _ratio(weight_removed, weight_total),
        "precision": _ratio(chars["removed_sensitive"], chars["removed"]),
        "utility_kept": _ratio(non_sensitive - destroyed, non_sensitive),
        "decoys_kept": _ratio(sum(decoys_kept.values()), sum(decoys.values())),
        "python_kept": _ratio(python_ok, python_total),
        "traces_per_sec": _ratio(len(data.traces), seconds),
        "recall_by_type": {t: removed_items[t] / n for t, n in sorted(items.items())},
        "recall_by_variant": {v: removed_variants[v] / n for v, n in sorted(variants.items())},
        "decoys_kept_by_type": {t: decoys_kept[t] / n for t, n in sorted(decoys.items())},
        "counts": {"chars": dict(chars), "items": dict(sorted(items.items())), "variants": dict(sorted(variants.items())), "decoys": sum(decoys.values()), "python_steps": python_total},
    }
    if keep_misses:
        result["misses"], result["false_positives"] = misses, false_positives
    return result

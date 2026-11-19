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
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from bench.align import GONE, SOLID, surviving

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


def bootstrap_ci(pairs: list[tuple[float, float]], resamples: int = 2000, seed: int = 0) -> list[float] | None:
    """95% confidence interval for sum(numerators) / sum(denominators).

    `pairs` holds one (numerator, denominator) per trace, e.g. (items removed,
    items planted). The bootstrap asks: if this split had been a different
    random draw of traces, how much would the score move? It redraws the
    traces with replacement many times, recomputes the score each time, &
    reports the range that holds the middle 95% of those scores.

    Whole traces are redrawn, not single items, because items in one trace
    are not independent (they come from the same carriers).
    """
    pairs = [p for p in pairs if p[1]]
    if not pairs:
        return None
    rng = random.Random(seed)
    scores = []
    for _ in range(resamples):
        draw = rng.choices(pairs, k=len(pairs))
        scores.append(sum(p[0] for p in draw) / sum(p[1] for p in draw))
    scores.sort()
    return [scores[int(0.025 * (resamples - 1))], scores[int(0.975 * (resamples - 1))]]


def score(data: Dataset, scrub_many: Callable[[list[str]], list[str]], name: str = "scrubber", keep_misses: bool = False, by_trace: bool = False) -> dict:
    """Run a scrubber over every step of every trace & return its scores.

    `scrub_many` takes the list of step texts of one trace & returns the
    scrubbed texts in the same order.
    """
    seconds = 0.0
    chars = Counter()  # total, sensitive, removed_sensitive, destroyed (non-sensitive characters lost)
    items, removed_items = Counter(), Counter()  # by type
    variants, removed_variants = Counter(), Counter()
    weight_total = weight_removed = 0
    decoys, decoys_kept = Counter(), Counter()
    python_total = python_ok = 0
    misses: list[dict] = []
    false_positives: list[dict] = []
    collateral: Counter = Counter()  # harmless snippets that were destroyed
    per_trace: dict[str, Counter] = defaultdict(Counter)  # only filled when by_trace is set

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
            unmatched = keep.count(GONE)  # harmless text: any match counts as kept

            for item in data.truth.get(key, ()):
                length = sum(b - a for a, b in item["spans"])
                # planted items: only solid matches count as leaked (see align.py)
                survivors = sum(keep[a:b].count(SOLID) for a, b in item["spans"])
                unmatched -= sum(keep[a:b].count(GONE) for a, b in item["spans"])
                chars["sensitive"] += length
                chars["removed_sensitive"] += length - survivors
                gone = survivors <= allowed_survivors(length)
                weight = SEVERITY[item["type"]]
                items[item["type"]] += 1
                variants[item["variant"]] += 1
                weight_total += weight
                tally = per_trace[trace["trace_id"]]
                tally["items"] += 1
                tally["removed"] += gone
                tally["weight"] += weight
                tally["weight_removed"] += weight * gone
                if item["variant"] == "adversarial":
                    tally["adversarial"] += 1
                    tally["adversarial_removed"] += gone
                if gone:
                    removed_items[item["type"]] += 1
                    removed_variants[item["variant"]] += 1
                    weight_removed += weight
                elif keep_misses:
                    misses.append({**item, "survivors": survivors, "scrubbed": scrubbed})

            chars["destroyed"] += unmatched  # non-sensitive characters that are gone
            if keep_misses and unmatched:
                sensitive = bytearray(len(original))
                for item in data.truth.get(key, ()):
                    for a, b in item["spans"]:
                        sensitive[a:b] = b"\x01" * (b - a)
                i = 0
                while i < len(original):
                    if keep[i] == GONE and not sensitive[i]:
                        j = i
                        while j < len(original) and keep[j] == GONE and not sensitive[j]:
                            j += 1
                        collateral[original[i:j]] += 1
                        i = j
                    else:
                        i += 1

            for decoy in data.decoys.get(key, ()):
                decoys[decoy["type"]] += 1
                intact = all(keep[a:b].count(GONE) == 0 for a, b in decoy["spans"])
                decoys_kept[decoy["type"]] += intact
                per_trace[trace["trace_id"]]["decoys"] += 1
                per_trace[trace["trace_id"]]["decoys_kept"] += intact
                if keep_misses and not intact:
                    false_positives.append({**decoy, "scrubbed": scrubbed})

            if key in data.python_steps:
                python_total += 1
                python_ok += scrubbed == original or _parses(scrubbed)

    n_items = sum(items.values())
    non_sensitive = chars["total"] - chars["sensitive"]
    destroyed = chars["destroyed"]
    chars["removed"] = chars["removed_sensitive"] + destroyed
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
        # 95% bootstrap intervals over traces (see bootstrap_ci)
        "recall_ci": bootstrap_ci([(t["removed"], t["items"]) for t in per_trace.values()]),
        "severity_ci": bootstrap_ci([(t["weight_removed"], t["weight"]) for t in per_trace.values()]),
        "adversarial_ci": bootstrap_ci([(t["adversarial_removed"], t["adversarial"]) for t in per_trace.values()]),
        "recall_by_type": {t: removed_items[t] / n for t, n in sorted(items.items())},
        "recall_by_variant": {v: removed_variants[v] / n for v, n in sorted(variants.items())},
        "decoys_kept_by_type": {t: decoys_kept[t] / n for t, n in sorted(decoys.items())},
        "counts": {"chars": dict(chars), "items": dict(sorted(items.items())), "variants": dict(sorted(variants.items())), "decoys": sum(decoys.values()), "python_steps": python_total},
    }
    if by_trace:
        result["by_trace"] = {trace_id: dict(c) for trace_id, c in per_trace.items()}
    if keep_misses:
        result["misses"], result["false_positives"], result["collateral"] = misses, false_positives, collateral
    return result

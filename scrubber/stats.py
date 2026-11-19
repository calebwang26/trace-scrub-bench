"""Dataset statistics for a file of traces.

    python -m scrubber.stats data/traces.jsonl

Answers the first questions a buyer asks about a dataset: how many traces,
how long are they, how often did the agent succeed, how many come with a repo
& what is the mix of models & harnesses.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


def load_traces(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def p90(values: list[int]) -> int:
    """90th percentile, nearest-rank method: the value 90% of traces are at or below."""
    ordered = sorted(values)
    return ordered[math.ceil(0.9 * len(ordered)) - 1]


def _spread(values: list[int]) -> dict:
    return {"mean": round(statistics.mean(values), 2), "median": statistics.median(values), "p90": p90(values)}


def _breakdown(traces: list[dict], key: str) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for t in traces:
        groups[t[key]].append(t)
    return {
        name: {
            "n": len(group),
            "share": round(len(group) / len(traces), 4),
            "success_rate": round(sum(t["outcome"] == "success" for t in group) / len(group), 4),
            "repo_share": round(sum(t["has_repo"] for t in group) / len(group), 4),
        }
        for name, group in sorted(groups.items())
    }


def compute(traces: list[dict]) -> dict:
    steps = [len(t["steps"]) for t in traces]
    kinds = [Counter(s["type"] for s in t["steps"]) for t in traces]
    return {
        "n_traces": len(traces),
        "steps_per_trace": _spread(steps),
        "tool_calls_per_trace": _spread([k["tool_call"] for k in kinds]),
        "messages_per_trace": _spread([k["message"] for k in kinds]),
        "success_rate": round(sum(t["outcome"] == "success" for t in traces) / len(traces), 4),
        "repo_share": round(sum(t["has_repo"] for t in traces) / len(traces), 4),
        "by_model": _breakdown(traces, "model"),
        "by_harness": _breakdown(traces, "harness"),
    }


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def to_markdown(stats: dict) -> str:
    lines = [
        "| metric | value |", "|---|---|",
        f"| traces | {stats['n_traces']:,} |",
        f"| success rate | {pct(stats['success_rate'])} |",
        f"| share with a repo | {pct(stats['repo_share'])} |",
    ]
    for key, label in [("steps_per_trace", "steps per trace"), ("tool_calls_per_trace", "tool calls per trace"), ("messages_per_trace", "messages per trace")]:
        s = stats[key]
        lines.append(f"| {label} (mean / median / p90) | {s['mean']} / {s['median']} / {s['p90']} |")
    for key, label in [("by_model", "model"), ("by_harness", "harness")]:
        lines += ["", f"| {label} | traces | share | success rate | with repo |", "|---|---|---|---|---|"]
        for name, g in stats[key].items():
            lines.append(f"| {name} | {g['n']:,} | {pct(g['share'])} | {pct(g['success_rate'])} | {pct(g['repo_share'])} |")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Print dataset statistics for a traces.jsonl file.")
    parser.add_argument("path")
    parser.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    args = parser.parse_args()
    stats = compute(load_traces(args.path))
    print(json.dumps(stats, indent=2) if args.json else to_markdown(stats))


if __name__ == "__main__":
    main()

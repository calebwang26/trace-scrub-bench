"""Score every registered scrubber & write the leaderboard.

    python -m bench.run                 # held-out test split -> LEADERBOARD.md + plots
    python -m bench.run --split dev     # dev split, for tuning: prints a table only
    python -m bench.run --only regex-v1 --limit 200

Use the dev split while building a scrubber. Look at the test split only when
the scrubber is finished, or the test numbers stop meaning anything.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from bench import build_splits, charts, plugins
from bench.score import SEVERITY, load_dataset, score

HERE = Path(__file__).resolve().parent
BASELINES = ("do-nothing", "redact-everything")


def balance(result: dict) -> float:
    """Harmonic mean of risk removed & utility kept. Both baselines score 0."""
    a, b = result["severity_score"], result["utility_kept"]
    return 2 * a * b / (a + b) if a + b else 0.0


def run(split: str, only: list[str] | None = None, limit: int | None = None, registry: str | Path = plugins.REGISTRY) -> tuple[list[dict], list[str]]:
    """Score the registered scrubbers on a split. Returns (results, skipped notes)."""
    build_splits.ensure()
    data = load_dataset(*build_splits.folders(split))
    if limit:
        data.traces = data.traces[:limit]
    results, skipped = [], []
    for entry in plugins.load_registry(registry):
        if only and entry["name"] not in only:
            continue
        try:
            scrub_many = plugins.load(entry)
        except plugins.Unavailable as reason:
            skipped.append(str(reason))
            continue
        result = score(data, scrub_many, entry["name"])
        result["description"] = entry.get("description", "")
        result["balance"] = balance(result)
        results.append(result)
        print(f"scored {entry['name']}")
    results.sort(key=lambda r: (-r["balance"], r["name"]))
    return results, skipped


def pct(x: float | None, digits: int = 1) -> str:
    return "n/a" if x is None else f"{100 * x:.{digits}f}%"


def speed(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{float(f'{x:.2g}'):,.0f}" if x >= 10 else f"{x:.1f}"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(r) + " |" for r in rows]


def main_table(results: list[dict]) -> list[str]:
    header = ["scrubber", "balance", "severity-weighted score", "recall", "precision", "utility kept", "decoys kept", "Python still parses", "adversarial recall", "traces/sec"]
    rows = [
        [r["name"], pct(r["balance"]), pct(r["severity_score"]), pct(r["recall"]), pct(r["precision"]), pct(r["utility_kept"], 2), pct(r["decoys_kept"]),
         pct(r["python_kept"]), pct(r["recall_by_variant"].get("adversarial")), speed(r["traces_per_sec"])]
        for r in results
    ]
    return _table(header, rows)


def breakdown_table(results: list[dict], key: str) -> list[str]:
    columns = sorted({c for r in results for c in r[key]})
    return _table(["scrubber"] + [c.replace("_", " ") for c in columns], [[r["name"]] + [pct(r[key].get(c), 0) for c in columns] for r in results])


def leaderboard(results: list[dict], skipped: list[str], split: str) -> str:
    first = results[0]
    counts = first["counts"]
    lines = [
        "# ScrubBench leaderboard",
        "",
        f"Split: **{split}** (held out, plus hand-written adversarial traces). {first['n_traces']:,} traces, {first['n_items']:,} planted sensitive items, "
        f"{counts['decoys']:,} decoys, {counts['python_steps']:,} Python files. All data is synthetic.",
        "",
        "Regenerate with `python -m bench.run`. Every number except traces/sec is deterministic; speed depends on the machine.",
        "",
        *main_table(results),
        "",
        "## How to read the columns",
        "",
        "- **balance:** harmonic mean of the severity-weighted score & utility kept. It is high only when a scrubber removes the risk **and** keeps the content, so both baselines score 0. The table is sorted by it.",
        "- **severity-weighted score:** share of risk removed, where each planted item counts by how bad its leak would be ("
        + ", ".join(f"{t.replace('_', ' ')} {w}" for t, w in SEVERITY.items()) + ").",
        "- **recall:** share of planted items removed. An item counts as removed only if at most 4 of its characters (& at most a quarter of it) survive: half a key is still a leaked key.",
        "- **precision:** of all characters the scrubber removed, the share that was sensitive.",
        "- **utility kept:** share of non-sensitive characters that survived.",
        "- **decoys kept:** share of harmless look-alikes (UUIDs, commit hashes, documentation example keys, ...) left fully intact.",
        "- **Python still parses:** share of Python files that are still valid Python after scrubbing.",
        "- **adversarial recall:** recall on the hand-written traces only, in formats the generator never produces.",
        "- **traces/sec:** scrubbing speed on one CPU core, scoring time excluded.",
        "",
        "## Recall by type",
        "",
        *breakdown_table(results, "recall_by_type"),
        "",
        "## Recall by how the item was hidden",
        "",
        *breakdown_table(results, "recall_by_variant"),
        "",
        "## Decoys kept, by kind",
        "",
        *breakdown_table(results, "decoys_kept_by_type"),
        "",
        "![Recall by type & variant](plots/recall_heatmap.png)",
        "",
        "![Risk removed vs utility kept](plots/recall_vs_utility.png)",
    ]
    if skipped:
        lines += ["", "## Skipped entries", ""] + [f"- {note}" for note in skipped]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Score every registered scrubber.")
    parser.add_argument("--split", choices=["test", "dev"], default="test")
    parser.add_argument("--only", nargs="*", help="score only these entries")
    parser.add_argument("--limit", type=int, help="score only the first N traces (quick checks)")
    args = parser.parse_args()
    results, skipped = run(args.split, args.only, args.limit)
    print()
    print("\n".join(main_table(results)))
    for note in skipped:
        print("skipped:", note)
    partial = bool(args.only or args.limit)
    if partial:
        print("\n(partial run: nothing written)")
        return
    (HERE / f"results_{args.split}.json").write_text(json.dumps({"split": args.split, "skipped": skipped, "results": results}, indent=2) + "\n", encoding="utf-8")
    if args.split == "test":
        (HERE / "plots").mkdir(exist_ok=True)
        charts.recall_heatmap(results, HERE / "plots" / "recall_heatmap.png")
        charts.recall_vs_utility(results, HERE / "plots" / "recall_vs_utility.png")
        (HERE / "LEADERBOARD.md").write_text(leaderboard(results, skipped, args.split), encoding="utf-8")
        print("\nwrote bench/LEADERBOARD.md, bench/results_test.json & bench/plots/")


if __name__ == "__main__":
    main()

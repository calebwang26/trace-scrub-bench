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
import sys
from pathlib import Path

if __package__ in (None, ""):  # also allow `python bench/run.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench import build_splits, charts, plugins
from bench.score import SEVERITY, load_dataset, score

HERE = Path(__file__).resolve().parent
BASELINES = ("do-nothing", "redact-everything")


def balance(result: dict) -> float:
    """Harmonic mean of risk removed & utility kept. Both baselines score 0."""
    a, b = result["severity_score"], result["utility_kept"]
    return 2 * a * b / (a + b) if a + b else 0.0


def run(split: str, only: list[str] | None = None, limit: int | None = None, registry: str | Path = plugins.REGISTRY, skip_optional: bool = False) -> tuple[list[dict], list[str]]:
    """Score the registered scrubbers on a split. Returns (results, skipped notes)."""
    build_splits.ensure()
    data = load_dataset(*build_splits.folders(split))
    if limit:
        data.traces = data.traces[:limit]
    results, skipped = [], []
    saved = _saved_results(split) if not limit else {}
    for entry in plugins.load_registry(registry):
        if only and entry["name"] not in only:
            continue
        if skip_optional and entry.get("optional"):
            skipped.append(f"{entry['name']}: skipped on request (--skip-optional)")
            continue
        try:
            scrub_many = plugins.load(entry)
        except plugins.Unavailable as reason:
            # The tool isn't installed here. If a saved result for the same data exists, show it.
            old = saved.get(entry["name"])
            if old and old["n_traces"] == len(data.traces) and old["counts"]["chars"]["total"] == sum(len(s["content"]) for t in data.traces for s in t["steps"]):
                results.append({**old, "reused": True})
                skipped.append(f"{reason}. Its row shows the saved result from the last run that had it installed.")
            else:
                skipped.append(str(reason))
            continue
        result = score(data, scrub_many, entry["name"])
        result["description"] = entry.get("description", "")
        result["note"] = " ".join(entry.get("note", "").split())
        result["balance"] = balance(result)
        results.append(result)
        print(f"scored {entry['name']}")
    results.sort(key=lambda r: (-r["balance"], r["name"]))
    return results, skipped


def adversarial_cases(names: list[str], registry: str | Path = plugins.REGISTRY) -> dict[str, dict]:
    """Score the hand-written traces alone, case by case: {scrubber: {trace_id: counts}}."""
    data = load_dataset(build_splits.DATA_ROOT / "adversarial")
    entries = {e["name"]: e for e in plugins.load_registry(registry)}
    return {name: score(data, plugins.load(entries[name]), name, by_trace=True)["by_trace"] for name in names}


def adversarial_table(cases: dict[str, dict]) -> list[str]:
    names = list(cases)
    trace_ids = sorted(next(iter(cases.values())))
    rows = []
    for trace_id in trace_ids:
        cells = []
        for name in names:
            c = cases[name][trace_id]
            cells.append(f"{c.get('removed', 0)} of {c['items']}" if c.get("items") else f"{c.get('decoys_kept', 0)} of {c['decoys']} kept")
        rows.append([trace_id.split("-", 2)[2].replace("-", " ")] + cells)
    return _table(["hand-written case"] + names, rows)


def _saved_results(split: str) -> dict[str, dict]:
    path = HERE / f"results_{split}.json"
    if not path.exists():
        return {}
    return {r["name"]: r for r in json.loads(path.read_text(encoding="utf-8"))["results"]}


def pct(x: float | None, digits: int = 1) -> str:
    return "n/a" if x is None else f"{100 * x:.{digits}f}%"


def with_ci(x: float | None, ci: list[float] | None) -> str:
    """A percentage followed by its 95% interval, e.g. `98.1% (97.5 to 98.6)`."""
    if x is None:
        return "n/a"
    if not ci or ci[0] == ci[1]:
        return pct(x)
    return f"{100 * x:.1f}% ({100 * ci[0]:.1f} to {100 * ci[1]:.1f})"


def speed(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{float(f'{x:.2g}'):,.0f}" if x >= 10 else f"{x:.1f}"


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(r) + " |" for r in rows]


def main_table(results: list[dict]) -> list[str]:
    header = ["scrubber", "balance", "severity-weighted score", "recall", "precision", "utility kept", "decoys kept", "Python still parses", "adversarial recall", "traces/sec"]
    rows = [
        [r["name"], pct(r["balance"]), with_ci(r["severity_score"], r.get("severity_ci")), with_ci(r["recall"], r.get("recall_ci")), pct(r["precision"]),
         pct(r["utility_kept"], 2), pct(r["decoys_kept"]), pct(r["python_kept"]),
         with_ci(r["recall_by_variant"].get("adversarial"), r.get("adversarial_ci")), speed(r["traces_per_sec"])]
        for r in results
    ]
    return _table(header, rows)


def breakdown_table(results: list[dict], key: str) -> list[str]:
    columns = sorted({c for r in results for c in r[key]})
    return _table(["scrubber"] + [c.replace("_", " ") for c in columns], [[r["name"]] + [pct(r[key].get(c), 0) for c in columns] for r in results])


def leaderboard(results: list[dict], skipped: list[str], split: str, cases: dict[str, dict] | None = None) -> str:
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
        "- **the ranges in brackets** are 95% confidence intervals from a bootstrap over traces: redraw the traces with replacement 2,000 times, rescore, & take the middle 95%. "
        "They say how much a score would move on a different random draw of traces from the same generator. They do not cover the bigger uncertainty: how different real traces are from generated ones.",
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
        *(
            ["## The hand-written adversarial traces, case by case", "",
             "Items removed out of items planted. The last row holds only harmless look-alikes, so it shows how many were left intact.", "",
             *adversarial_table(cases), ""]
            if cases else []
        ),
        "![Recall by type & variant](plots/recall_heatmap.png)",
        "",
        "![Risk removed vs utility kept](plots/recall_vs_utility.png)",
    ]
    notes = [f"- **{r['name']}:** {r['note']}" for r in results if r.get("note")]
    if notes:
        lines += ["", "## Notes on individual entries", ""] + notes
    lines += ["", "## Entries", ""] + [f"- **{r['name']}:** {r['description']}" for r in results]
    if skipped:
        lines += ["", "## Skipped entries", ""] + [f"- {note}" for note in skipped]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Score every registered scrubber.")
    parser.add_argument("--split", choices=["test", "dev"], default="test")
    parser.add_argument("--only", nargs="*", help="score only these entries")
    parser.add_argument("--limit", type=int, help="score only the first N traces (quick checks)")
    parser.add_argument("--skip-optional", action="store_true", help="leave out the optional third-party entries")
    parser.add_argument("--merge", action="store_true", help="with --only: keep the other entries' saved results & rewrite the leaderboard")
    args = parser.parse_args()
    results, skipped = run(args.split, args.only, args.limit, skip_optional=args.skip_optional)
    print()
    print("\n".join(main_table(results)))
    for note in skipped:
        print("skipped:", note)
    results_path = HERE / f"results_{args.split}.json"
    if args.merge and args.only and not args.limit and results_path.exists():
        saved = json.loads(results_path.read_text(encoding="utf-8"))
        order = [e["name"] for e in plugins.load_registry()]
        fresh = {r["name"] for r in results}
        results += [r for r in saved["results"] if r["name"] not in fresh and r["name"] in order]
        results.sort(key=lambda r: (-r["balance"], r["name"]))
        skipped = saved["skipped"]
    elif args.only or args.limit:
        print("\n(partial run: nothing written)")
        return
    results_path.write_text(json.dumps({"split": args.split, "skipped": skipped, "results": results}, indent=2) + "\n", encoding="utf-8")
    if args.split == "test":
        (HERE / "plots").mkdir(exist_ok=True)
        charts.recall_heatmap(results, HERE / "plots" / "recall_heatmap.png")
        charts.recall_vs_utility(results, HERE / "plots" / "recall_vs_utility.png")
        cases = adversarial_cases([r["name"] for r in results if r["name"] not in BASELINES and not r.get("reused")])
        (HERE / "LEADERBOARD.md").write_text(leaderboard(results, skipped, args.split, cases), encoding="utf-8")
        print("\nwrote bench/LEADERBOARD.md, bench/results_test.json & bench/plots/")


if __name__ == "__main__":
    main()

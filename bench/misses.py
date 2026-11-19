"""Error analysis for building a scrubber: what did it miss, & what did it break?

    python -m bench.misses --scrubber regex-v1

Works on the **dev split only**, on purpose. Looking at individual misses on
the test split & then fixing them would turn the test split into a second dev
split, & its scores would stop being an honest estimate.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict

from bench import build_splits, plugins
from bench.score import load_dataset, score


def _clip(text: str, width: int = 110) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= width else text[: width - 3] + "..."


def report(name: str, examples: int = 2) -> str:
    entry = next(e for e in plugins.load_registry() if e["name"] == name)
    build_splits.ensure()
    data = load_dataset(*build_splits.folders("dev"))
    result = score(data, plugins.load(entry), name, keep_misses=True)
    lines = [f"{name} on dev: recall {100 * result['recall']:.1f}%, {len(result['misses'])} misses, {len(result['false_positives'])} damaged decoys", ""]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for miss in result["misses"]:
        groups[(miss["type"], miss["variant"], miss["carrier"])].append(miss)
    totals = Counter((r["type"], r["variant"], r["carrier"]) for rows in data.truth.values() for r in rows)
    lines.append("MISSED ITEMS (type / variant / carrier: missed of planted)")
    for key, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"  {' / '.join(key)}: {len(rows)} of {totals[key]}")
        for row in rows[:examples]:
            a, b = row["spans"][0][0], row["spans"][-1][1]
            lines.append(f"      planted: {_clip(row['text'])}")
            lines.append(f"      after:   {_clip(row['scrubbed'][max(0, a - 30) : b + 30])}")

    damaged: dict[str, list[dict]] = defaultdict(list)
    for fp in result["false_positives"]:
        damaged[fp["type"]].append(fp)
    lines += ["", "DAMAGED DECOYS (kind: damaged of planted)"]
    for kind, rows in sorted(damaged.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"  {kind}: {len(rows)} of {result['counts']['decoys'] and sum(1 for ds in data.decoys.values() for d in ds if d['type'] == kind)}")
        for row in rows[:examples]:
            a, b = row["spans"][0]
            lines.append(f"      decoy:  {_clip(row['text'])}")
            lines.append(f"      after:  {_clip(row['scrubbed'][max(0, a - 30) : b + 30])}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Show what a scrubber misses & breaks on the dev split.")
    parser.add_argument("--scrubber", required=True)
    parser.add_argument("--examples", type=int, default=2)
    args = parser.parse_args()
    print(report(args.scrubber, args.examples))


if __name__ == "__main__":
    main()

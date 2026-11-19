"""Stratified sampler: pick N traces that keep the mix of the full dataset.

    python -m scrubber.sample --in data/traces.jsonl --n 200 --out outputs/sample

A stratum is one combination of (model, outcome, has_repo). The sampler takes
the same share from every stratum, so the sample has the same mix of models,
success/fail & repo/no-repo as the full set. It writes the sampled traces plus
a sample card: the one-page summary a buyer reads before deciding to buy.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path

from scrubber.stats import compute, load_traces, pct

Stratum = tuple[str, str, bool]


def stratum(trace: dict) -> Stratum:
    return (trace["model"], trace["outcome"], trace["has_repo"])


def allocate(counts: dict[Stratum, int], n: int) -> dict[Stratum, int]:
    """How many traces to take from each stratum (largest-remainder method).

    Each stratum's exact share is n * count / total, usually not a whole
    number. Round every share down, then hand the leftover seats to the strata
    with the largest fractional parts. The result sums to exactly n & every
    stratum is within one trace of its exact share.
    """
    total = sum(counts.values())
    if not 0 < n <= total:
        raise ValueError(f"n must be between 1 and {total}")
    exact = {s: n * c / total for s, c in counts.items()}
    take = {s: math.floor(x) for s, x in exact.items()}
    leftover = n - sum(take.values())
    by_remainder = sorted(counts, key=lambda s: (-(exact[s] - take[s]), s))  # ties broken by name
    for s in by_remainder[:leftover]:
        take[s] += 1
    return take


def stratified_sample(traces: list[dict], n: int, seed: int = 0) -> list[dict]:
    """Return n traces, in their original order, with the full set's mix."""
    groups: dict[Stratum, list[int]] = defaultdict(list)
    for i, t in enumerate(traces):
        groups[stratum(t)].append(i)
    take = allocate({s: len(idx) for s, idx in groups.items()}, n)
    rng = random.Random(seed)
    chosen: list[int] = []
    for s in sorted(groups):  # fixed order, so the same seed gives the same sample
        chosen += rng.sample(groups[s], take[s])
    return [traces[i] for i in sorted(chosen)]


def _shares(traces: list[dict], key) -> dict:
    counts = Counter(key(t) for t in traces)
    return {k: c / len(traces) for k, c in counts.items()}


def max_deviation(full: list[dict], sample: list[dict]) -> float:
    """Largest gap, over all strata, between the full-set share & the sample share."""
    a, b = _shares(full, stratum), _shares(sample, stratum)
    return max(abs(a[s] - b.get(s, 0.0)) for s in a)


def sample_card(full: list[dict], sample: list[dict], seed: int, source: str, scrubbed_with: str | None = None) -> str:
    """Markdown summary of the sample next to the full set."""
    fs, ss = compute(full), compute(sample)
    lines = [
        "# Sample card",
        "",
        f"- **Source:** `{source}` ({len(full):,} traces)",
        f"- **Sample:** {len(sample):,} traces ({pct(len(sample) / len(full))} of the source), seed {seed}",
        "- **Method:** stratified by model × outcome × has_repo, proportional allocation (largest remainder)",
        f"- **Scrubbing:** {scrubbed_with or 'not scrubbed'}",
        "- **Note:** all traces, secrets & personal data in this project are synthetic.",
        "",
        "## Key numbers",
        "",
        "| metric | full set | sample |", "|---|---|---|",
        f"| traces | {fs['n_traces']:,} | {ss['n_traces']:,} |",
        f"| success rate | {pct(fs['success_rate'])} | {pct(ss['success_rate'])} |",
        f"| share with a repo | {pct(fs['repo_share'])} | {pct(ss['repo_share'])} |",
    ]
    for key, label in [("steps_per_trace", "steps per trace"), ("tool_calls_per_trace", "tool calls per trace")]:
        f, s = fs[key], ss[key]
        lines.append(f"| {label} (mean / median / p90) | {f['mean']} / {f['median']} / {f['p90']} | {s['mean']} / {s['median']} / {s['p90']} |")
    for key, label in [("by_model", "model"), ("by_harness", "harness")]:
        lines += ["", f"## Mix by {label}", "", f"| {label} | full set | sample | sample success rate |", "|---|---|---|---|"]
        for name, g in fs[key].items():
            s = ss[key].get(name, {"share": 0.0, "success_rate": 0.0})
            lines.append(f"| {name} | {pct(g['share'])} | {pct(s['share'])} | {pct(s['success_rate'])} |")
    lines += [
        "",
        "## How close is the sample to the full set?",
        "",
        f"Across all {len(_shares(full, stratum))} strata (model × outcome × has_repo), the largest gap between a stratum's share "
        f"in the full set & in the sample is **{100 * max_deviation(full, sample):.2f} percentage points**. "
        "Harness is not a stratum, so its mix is only approximately preserved.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Draw a stratified sample of traces & write a sample card.")
    parser.add_argument("--in", dest="src", default="data/traces.jsonl")
    parser.add_argument("--n", type=int, default=200)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="outputs/sample")
    parser.add_argument("--scrubbed-with", default=None, help="label of the scrubber already applied to the input")
    args = parser.parse_args()
    full = load_traces(args.src)
    sample = stratified_sample(full, args.n, args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "sample.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for t in sample:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")
    card = sample_card(full, sample, args.seed, args.src, args.scrubbed_with)
    (out / "SAMPLE_CARD.md").write_text(card, encoding="utf-8")
    print(card)


if __name__ == "__main__":
    main()

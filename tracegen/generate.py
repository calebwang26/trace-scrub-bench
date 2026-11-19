"""Seeded generator of synthetic coding-agent traces with planted sensitive items.

    python -m tracegen.generate --seed 20261118 --n 2000 --out data

Writes into the output folder:
    traces.jsonl        one trace per line (the data a scrubber sees)
    ground_truth.jsonl  one planted sensitive item per line, with exact positions
    decoys.jsonl        one harmless look-alike per line, with exact positions
    python_steps.jsonl  which steps are whole Python files (for the parse check)
    manifest.json       seed, sizes & how many items of each kind were planted

The same seed always produces byte-identical files. Model & harness names are
invented, & so are their success rates: they say nothing about real systems.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path

from tracegen import carriers, content
from tracegen.marks import Registry, resolve

# (name, weight in the dataset, probability a task succeeds). All invented.
MODELS = [
    ("atlas-4", 22, 0.68),  # closed
    ("orion-pro-2", 18, 0.61),  # closed
    ("nimbus-large", 14, 0.55),  # closed
    ("openllama-70b", 18, 0.42),  # open-weight
    ("codeqwin-32b", 16, 0.47),  # open-weight
    ("deepcoder-v2-16b", 12, 0.33),  # open-weight
]
# (name, weight, probability the trace comes with a repo snapshot). All invented.
HARNESSES = [("cli-agent", 35, 0.85), ("ide-agent", 30, 0.7), ("swe-harness", 20, 0.95), ("ci-bot", 10, 0.6), ("notebook-agent", 5, 0.15)]

# How many planting events a trace gets: {count: weight}. Mean is about 2.1.
SENSITIVE_EVENTS = {0: 25, 1: 20, 2: 18, 3: 14, 4: 10, 5: 7, 6: 4, 8: 2}
DECOY_EVENTS = {0: 30, 1: 30, 2: 20, 3: 12, 4: 8}


def _pick(rng: random.Random, table: dict[int, int]) -> int:
    return rng.choices(list(table), weights=list(table.values()))[0]


def generate_trace(seed: int, index: int) -> tuple[dict, list[dict], list[dict], list[dict]]:
    """Build trace number `index`. Returns (trace, ground_truth, decoys, python_steps)."""
    rng = random.Random(f"{seed}:{index}")  # each trace has its own random stream
    reg = Registry()
    v = content.make_vocab(rng)

    model, _, p_success = content.weighted(rng, [(m, m[1]) for m in MODELS])
    harness, _, p_repo = content.weighted(rng, [(h, h[1]) for h in HARNESSES])
    outcome = "success" if rng.random() < p_success else "fail"
    has_repo = rng.random() < p_repo
    task = content.task(rng, v)

    # Decide which turns carry a planted item or a decoy.
    n_turns = max(4, min(40, round(rng.gauss(19, 6))))
    events: dict[int, list[str]] = {}
    for kind, table in (("sensitive", SENSITIVE_EVENTS), ("decoy", DECOY_EVENTS)):
        for _ in range(_pick(rng, table)):
            events.setdefault(rng.randrange(n_turns), []).append(kind)

    background = content.BACKGROUND + (content.BACKGROUND_REPO if has_repo else [])
    steps = [content.user(task)]
    for turn in range(n_turns):
        if rng.random() < 0.6:
            steps.append(content.thought(rng, v))
        for kind in events.get(turn, []):
            if kind == "sensitive":
                steps += carriers.sensitive_event(rng, reg, v, has_repo)
            else:
                steps += carriers.decoy_event(rng, reg, v, has_repo)
        n_actions = (rng.random() < 0.85) + (rng.random() < 0.35)
        for _ in range(n_actions):
            steps += content.weighted(rng, background)(rng, v)

    # The trace ends with a final test run that matches the outcome.
    steps += content.run_pytest(rng, v, passed=(outcome == "success"))
    steps.append(content.say("All tests pass now. The fix is in place." if outcome == "success" else f"I could not get `{v.test_name}` to pass. Stopping here with the failure above."))

    # Strip the markers & turn them into exact positions.
    trace_id = f"trace-{rng.getrandbits(48):012x}"
    ground_truth, decoy_rows, python_steps, clean_steps = [], [], [], []
    seen: set[int] = set()
    for i, s in enumerate(steps):
        text, spans = resolve(s["content"])
        clean_steps.append({"role": s["role"], "type": s["type"], "content": text})
        if s["python"]:
            python_steps.append({"trace_id": trace_id, "step": i})
        for item_id, item_spans in sorted(spans.items()):
            assert item_id not in seen, "an item must sit inside a single step"
            seen.add(item_id)
            item = reg.items[item_id]
            row = {"trace_id": trace_id, "step": i, "type": item.type}
            if item.kind == "sensitive":
                row.update(variant=item.variant, carrier=item.carrier, value=item.value)
            row.update(spans=[list(sp) for sp in item_spans], text=text[item_spans[0][0] : item_spans[-1][1]])
            (ground_truth if item.kind == "sensitive" else decoy_rows).append(row)
    assert len(seen) == len(reg.items), "a planted item got lost"

    trace = {"trace_id": trace_id, "model": model, "harness": harness, "task": task, "steps": clean_steps, "outcome": outcome, "has_repo": has_repo}
    return trace, ground_truth, decoy_rows, python_steps


def dumps(row: dict) -> str:
    return json.dumps(row, ensure_ascii=False)


FILES = ["traces.jsonl", "ground_truth.jsonl", "decoys.jsonl", "python_steps.jsonl", "manifest.json"]


def generate(seed: int, n_traces: int, out_dir: str | Path) -> dict:
    """Generate a dataset into out_dir & return its manifest."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    counts = {"sensitive_by_type": Counter(), "sensitive_by_variant": Counter(), "decoys_by_type": Counter()}
    n_steps = n_python = 0
    names = ["traces.jsonl", "ground_truth.jsonl", "decoys.jsonl", "python_steps.jsonl"]
    handles = [open(out / name, "w", encoding="utf-8", newline="\n") for name in names]
    try:
        for index in range(n_traces):
            trace, truth, decoy_rows, py = generate_trace(seed, index)
            for handle, rows in zip(handles, ([trace], truth, decoy_rows, py)):
                for row in rows:
                    handle.write(dumps(row) + "\n")
            n_steps += len(trace["steps"])
            n_python += len(py)
            for row in truth:
                counts["sensitive_by_type"][row["type"]] += 1
                counts["sensitive_by_variant"][row["variant"]] += 1
            for row in decoy_rows:
                counts["decoys_by_type"][row["type"]] += 1
    finally:
        for handle in handles:
            handle.close()
    manifest = {
        "seed": seed,
        "n_traces": n_traces,
        "n_steps": n_steps,
        "n_python_steps": n_python,
        "n_sensitive": sum(counts["sensitive_by_type"].values()),
        "n_decoys": sum(counts["decoys_by_type"].values()),
        **{key: dict(sorted(c.items())) for key, c in counts.items()},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--seed", type=int, default=20261118)
    parser.add_argument("--n", type=int, default=2000, help="number of traces")
    parser.add_argument("--out", default="data")
    args = parser.parse_args()
    manifest = generate(args.seed, args.n, args.out)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

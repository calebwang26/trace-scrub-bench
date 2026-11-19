"""Side check: is Presidio blind to this benchmark's emails only because of their domains?

    python -m bench.adapters.presidio_tld_check

Every synthetic email here ends in a reserved top-level domain (`.example` or
`.test`) so it can never belong to a real person. Presidio validates the
top-level domain against the public list, so it may reject exactly these.
This script re-runs Presidio on the same test-split emails with the ending
swapped for a real one (`.com` / `.org`) & reports both recalls. It is a
footnote to the leaderboard, not part of it.
"""
from __future__ import annotations

from bench import build_splits
from bench.adapters.presidio_adapter import scrubber
from bench.score import load_dataset


def main() -> None:
    if not scrubber.available():
        raise SystemExit(f"Presidio is not available: {scrubber.why_unavailable()}")
    build_splits.ensure()
    data = load_dataset(*build_splits.folders("test"))
    steps = {(t["trace_id"], i): s["content"] for t in data.traces for i, s in enumerate(t["steps"])}
    total = caught_reserved = caught_real = 0
    for key, items in data.truth.items():
        for item in items:
            if item["type"] != "email" or item["variant"] != "plain":
                continue
            email = item["value"]
            swapped = email.replace(".example", ".com").replace(".test", ".org")
            total += 1
            caught_reserved += email not in scrubber.scrub(steps[key])
            caught_real += swapped not in scrubber.scrub(steps[key].replace(email, swapped))
    print(f"emails checked:                      {total}")
    print(f"removed with reserved endings:       {caught_reserved} ({100 * caught_reserved / total:.1f}%)")
    print(f"removed with .com / .org endings:    {caught_real} ({100 * caught_real / total:.1f}%)")


if __name__ == "__main__":
    main()

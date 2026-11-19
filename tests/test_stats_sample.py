import random

import pytest

from scrubber.sample import allocate, max_deviation, sample_card, scrubbing_line, stratified_sample, stratum
from scrubber.stats import compute, p90, to_markdown
from tracegen.generate import generate_trace


@pytest.fixture(scope="module")
def traces():
    return [generate_trace(11, i)[0] for i in range(600)]


def test_p90_nearest_rank():
    assert p90(list(range(1, 11))) == 9
    assert p90([5]) == 5


def test_stats_on_a_tiny_hand_made_dataset():
    def trace(model, outcome, has_repo, n_calls):
        steps = [{"role": "user", "type": "message", "content": "x"}] + [{"role": "assistant", "type": "tool_call", "content": "{}"}] * n_calls
        return {"model": model, "harness": "h", "outcome": outcome, "has_repo": has_repo, "steps": steps}

    stats = compute([trace("a", "success", True, 1), trace("a", "fail", False, 3), trace("b", "success", True, 5), trace("b", "success", False, 7)])
    assert stats["n_traces"] == 4
    assert stats["success_rate"] == 0.75 and stats["repo_share"] == 0.5
    assert stats["tool_calls_per_trace"] == {"mean": 4, "median": 4.0, "p90": 7}
    assert stats["steps_per_trace"]["mean"] == 5
    assert stats["by_model"]["a"] == {"n": 2, "share": 0.5, "success_rate": 0.5, "repo_share": 0.5}
    assert "| traces | 4 |" in to_markdown(stats)


def test_allocate_sums_to_n_and_stays_within_one_of_the_exact_share():
    rng = random.Random(0)
    for _ in range(200):
        counts = {("m%d" % i, "success", True): rng.randint(1, 400) for i in range(rng.randint(1, 30))}
        total = sum(counts.values())
        n = rng.randint(1, total)
        take = allocate(counts, n)
        assert sum(take.values()) == n
        for s, c in counts.items():
            assert abs(take[s] - n * c / total) < 1
            assert 0 <= take[s] <= c


def test_allocate_rejects_impossible_sizes():
    with pytest.raises(ValueError):
        allocate({("m", "fail", False): 3}, 4)


def test_sample_keeps_the_mix_of_every_stratum(traces):
    n = 150
    sample = stratified_sample(traces, n, seed=1)
    assert len(sample) == n == len({t["trace_id"] for t in sample})
    full_counts, sample_counts = {}, {}
    for group, counts in ((traces, full_counts), (sample, sample_counts)):
        for t in group:
            counts[stratum(t)] = counts.get(stratum(t), 0) + 1
    for s, c in full_counts.items():
        assert abs(sample_counts.get(s, 0) - n * c / len(traces)) < 1
    assert max_deviation(traces, sample) < 1 / n


def test_stratified_beats_simple_random_on_average(traces):
    """Stratifying is the point: its worst-stratum gap is smaller than plain random sampling's."""
    n, rng = 150, random.Random(5)
    random_gaps = [max_deviation(traces, rng.sample(traces, n)) for _ in range(30)]
    assert max_deviation(traces, stratified_sample(traces, n, seed=1)) < sum(random_gaps) / len(random_gaps)


def test_sample_is_deterministic_and_seed_dependent(traces):
    ids = lambda seed: [t["trace_id"] for t in stratified_sample(traces, 100, seed)]
    assert ids(3) == ids(3)
    assert ids(3) != ids(4)


def test_sample_card_states_the_scrubbers_measured_miss_rate():
    scores = {"recall": 0.981, "severity_score": 0.984, "recall_by_variant": {"adversarial": 0.586}}
    line = scrubbing_line("scrubber v2", scores)
    assert "removed 98.1%" in line and "about 1.9% of sensitive items to remain" in line and "58.6%" in line
    assert "not guaranteed clean" in line
    assert scrubbing_line(None, None) == "not scrubbed"
    assert "not measured" in scrubbing_line("some tool", None)


def test_sample_card_reports_both_columns(traces):
    card = sample_card(traces, stratified_sample(traces, 100, 0), seed=0, source="traces.jsonl", scrubbed_with="v2")
    assert "| traces | 600 | 100 |" in card
    assert "**Scrubbing:** v2" in card and "synthetic" in card

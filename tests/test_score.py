"""The scorer must give exactly the expected numbers on cases with a known answer."""
import pytest

from bench.align import SOLID, WEAK, surviving
from bench.baselines import do_nothing, redact_everything
from bench.score import SEVERITY, Dataset, allowed_survivors, bootstrap_ci, load_dataset, per_text, score
from tracegen.generate import generate

KEY = "AKIAFAKE7Q2MXP4RTZ1L"  # 20 characters
EMAIL = "dana@fakecorp.example"  # 21 characters


def _item(step, type, text, content, variant="plain"):
    start = content.index(text)
    return {"trace_id": "t1", "step": step, "type": type, "variant": variant, "value": text, "spans": [[start, start + len(text)]], "text": text}


def tiny():
    """One trace, two steps, three planted items, one decoy, one Python step."""
    step0 = f"email {EMAIL} now"
    step1 = f"key={KEY}\nip 10.0.0.5 ok"
    step2 = 'SHA = "3feff92"\nprint(SHA)\n'
    data = Dataset(traces=[{"trace_id": "t1", "steps": [{"content": step0}, {"content": step1}, {"content": step2}]}])
    data.truth = {("t1", 0): [_item(0, "email", EMAIL, step0)], ("t1", 1): [_item(1, "aws_key", KEY, step1), _item(1, "ipv4", "10.0.0.5", step1)]}
    data.decoys = {("t1", 2): [{"trace_id": "t1", "step": 2, "type": "git_sha", "spans": [[7, 14]], "text": "3feff92"}]}
    data.python_steps = {("t1", 2)}
    return data, (step0, step1, step2)


# --- the two baselines ---------------------------------------------------------

def test_do_nothing_scores_zero_recall_and_perfect_utility():
    data, _ = tiny()
    r = score(data, per_text(do_nothing))
    assert r["recall"] == 0 and r["severity_score"] == 0
    assert r["utility_kept"] == 1 and r["decoys_kept"] == 1 and r["python_kept"] == 1
    assert r["precision"] is None  # it removed nothing, so precision is undefined


def test_redact_everything_scores_full_recall_and_zero_utility():
    data, steps = tiny()
    r = score(data, per_text(redact_everything))
    assert r["recall"] == 1 and r["severity_score"] == 1
    assert r["utility_kept"] == 0 and r["decoys_kept"] == 0 and r["python_kept"] == 0
    assert r["precision"] == (21 + 20 + 8) / sum(map(len, steps))  # sensitive chars / all chars


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    folder = tmp_path_factory.mktemp("score")
    generate(seed=3, n_traces=60, out_dir=folder)
    return load_dataset(folder)


def test_baselines_on_generated_data(generated):
    nothing = score(generated, per_text(do_nothing))
    everything = score(generated, per_text(redact_everything))
    assert nothing["n_items"] > 100
    assert (nothing["recall"], nothing["severity_score"], nothing["utility_kept"], nothing["decoys_kept"], nothing["python_kept"]) == (0, 0, 1, 1, 1)
    assert (everything["recall"], everything["severity_score"], everything["utility_kept"], everything["decoys_kept"], everything["python_kept"]) == (1, 1, 0, 0, 0)
    assert set(everything["recall_by_type"].values()) == {1.0}
    chars = everything["counts"]["chars"]
    assert everything["precision"] == chars["sensitive"] / chars["total"]


def test_an_oracle_scrubber_scores_perfectly(generated):
    """A scrubber that redacts exactly the planted spans must get 100% everywhere.

    This is the end-to-end check on generator + scorer together: if the ground
    truth or the alignment were off, the perfect scrubber would lose points.
    """
    truth_by_trace = iter([[generated.truth.get((t["trace_id"], i), []) for i in range(len(t["steps"]))] for t in generated.traces])

    def oracle(texts):
        out = []
        for text, items in zip(texts, next(truth_by_trace)):
            spans = sorted((a, b, item["type"]) for item in items for a, b in item["spans"])
            for a, b, type in reversed(spans):
                text = text[:a] + f"[REDACTED_{type.upper()}]" + text[b:]
            out.append(text)
        return out

    r = score(generated, oracle, keep_misses=True)
    assert [(m["type"], m["carrier"]) for m in r["misses"]] == []
    assert (r["recall"], r["severity_score"], r["precision"], r["utility_kept"], r["decoys_kept"]) == (1, 1, 1, 1, 1)
    assert r["python_kept"] > 0.95  # a few secrets are split across two string literals


# --- a hand-made example with a known answer -----------------------------------

def test_hand_made_example_gives_exactly_the_expected_numbers():
    """A scrubber that removes the email (& 4 harmless characters), half the key & not the IP."""
    data, (step0, step1, step2) = tiny()
    outputs = {step0: "email [E]", step1: "key=XXXXXXXXXX2MXP4RTZ1L\nip 10.0.0.5 ok", step2: step2}
    r = score(data, per_text(outputs.__getitem__), keep_misses=True)

    assert r["recall"] == 1 / 3  # only the email counts: half a key is still a leak
    assert r["recall_by_type"] == {"aws_key": 0, "email": 1, "ipv4": 0}
    assert r["severity_score"] == SEVERITY["email"] / (SEVERITY["email"] + SEVERITY["aws_key"] + SEVERITY["ipv4"]) == 3 / 14
    # removed: 21 (email) + 4 (" now") + 10 (half the key) = 35 characters, 31 of them sensitive
    assert r["precision"] == 31 / 35
    # non-sensitive characters: 10 + 11 + 27 = 48, of which 4 (" now") were destroyed
    assert r["utility_kept"] == 44 / 48
    assert r["decoys_kept"] == 1 and r["python_kept"] == 1
    assert {m["type"] for m in r["misses"]} == {"aws_key", "ipv4"}


# --- the "partial redaction is a miss" rule -------------------------------------

def test_allowed_survivors():
    assert allowed_survivors(40) == 4  # a kept `ghp_` prefix is fine
    assert allowed_survivors(20) == 4
    assert allowed_survivors(8) == 2  # short items: at most a quarter
    assert allowed_survivors(3) == 0


@pytest.mark.parametrize(
    "scrubbed_key, removed",
    [
        ("[REDACTED_AWS_KEY]", True),  # shares letters with the key by coincidence: still removed
        ("AKIA****************", True),  # keeps the public 4-character prefix
        ("AKIAF***************", False),  # keeps 5 characters
        ("**********2MXP4RTZ1L", False),  # keeps the second half
        ("", True),
    ],
)
def test_partial_redaction_counts_as_a_miss(scrubbed_key, removed):
    data, (step0, step1, step2) = tiny()
    outputs = {step0: step0, step1: step1.replace(KEY, scrubbed_key), step2: step2}
    r = score(data, per_text(outputs.__getitem__))
    assert r["recall_by_type"]["aws_key"] == (1 if removed else 0)
    assert r["utility_kept"] == 1  # nothing harmless was touched


def test_split_item_needs_both_fragments_removed():
    content = "TOKEN=abcdefghij\\\nklmnopqrst end"
    item = {"trace_id": "t", "step": 0, "type": "env_secret", "variant": "split", "value": "abcdefghijklmnopqrst", "spans": [[6, 16], [18, 28]], "text": ""}
    data = Dataset(traces=[{"trace_id": "t", "steps": [{"content": content}]}], truth={("t", 0): [item]})
    half = score(data, per_text(lambda t: t.replace("abcdefghij", "[X]")))
    both = score(data, per_text(lambda t: t.replace("abcdefghij", "[X]").replace("klmnopqrst", "[X]")))
    assert half["recall"] == 0 and both["recall"] == 1
    assert both["utility_kept"] == 1  # the backslash & newline between the halves are untouched


def test_a_damaged_decoy_and_broken_python_are_counted():
    data, (step0, step1, step2) = tiny()
    outputs = {step0: step0, step1: step1, step2: 'SHA = [REDACTED]\nprint(SHA)\n'}  # eats the quotes too
    r = score(data, per_text(outputs.__getitem__))
    assert r["decoys_kept"] == 0
    assert r["python_kept"] == 1  # `SHA = [REDACTED]` is still valid Python (a list)
    outputs[step2] = 'SHA = "[REDACTED]\nprint(SHA)\n'  # unbalanced quote
    assert score(data, per_text(outputs.__getitem__))["python_kept"] == 0


# --- confidence intervals ---------------------------------------------------------

def test_bootstrap_interval_collapses_when_every_trace_agrees():
    assert bootstrap_ci([(2, 2)] * 50) == [1.0, 1.0]
    assert bootstrap_ci([(0, 3)] * 50) == [0.0, 0.0]
    assert bootstrap_ci([]) is None and bootstrap_ci([(0, 0)]) is None  # nothing to estimate from


def test_bootstrap_interval_brackets_the_score_and_is_repeatable():
    pairs = [(1, 1)] * 80 + [(0, 1)] * 20  # true score 0.80
    low, high = bootstrap_ci(pairs)
    assert low < 0.80 < high and 0.70 < low and high < 0.89  # roughly 0.80 +/- 2 * sqrt(0.8 * 0.2 / 100)
    assert bootstrap_ci(pairs) == [low, high]  # fixed seed: same interval every time


def test_fewer_traces_give_a_wider_interval():
    few, many = bootstrap_ci([(1, 1)] * 8 + [(0, 1)] * 2), bootstrap_ci([(1, 1)] * 800 + [(0, 1)] * 200)
    assert few[1] - few[0] > 5 * (many[1] - many[0])


def test_score_reports_intervals(generated):
    r = score(generated, per_text(lambda t: t.replace("@", "[at]")))  # catches emails only
    assert r["recall_ci"][0] <= r["recall"] <= r["recall_ci"][1]
    assert r["severity_ci"][0] <= r["severity_score"] <= r["severity_ci"][1]
    assert r["adversarial_ci"] is None  # this small generated set has no adversarial traces


# --- alignment ------------------------------------------------------------------

def test_unchanged_text_survives_completely():
    assert surviving("abc\ndef", "abc\ndef") == bytearray([SOLID]) * 7


def test_only_the_replaced_span_is_marked_removed():
    original = "line one\nuser=alice pw=hunter2secret ok\nline three\n"
    keep = surviving(original, original.replace("hunter2secret", "[REDACTED]"))
    start = original.index("hunter2secret")
    assert keep[start : start + 13] == bytearray(13)
    assert keep.count(0) == 13


def test_multi_line_block_replaced_by_one_placeholder():
    block = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----"
    original = f"before\n{block}\nafter\n"
    keep = surviving(original, "before\n[REDACTED_PRIVATE_KEY]\nafter\n")
    start = original.index(block)
    assert keep[start : start + len(block)].count(SOLID) == 0
    assert keep[: start].count(SOLID) == start


def test_short_matches_are_weak_and_long_ones_solid():
    """` <` between two redactions really survived; `KE` inside a redacted key is a coincidence."""
    original = "Author: Greta Dubois <greta@fakecorp.example> key AKIAFAKE7Q2MXP4RTZ1L"
    scrubbed = "Author: [REDACTED_PERSON_NAME] <[REDACTED_EMAIL]> key [REDACTED_AWS_KEY]"
    keep = surviving(original, scrubbed)
    gap = original.index(" <")
    assert keep[gap : gap + 2] == bytearray([WEAK, WEAK])
    key = original.index("AKIA")
    assert keep[key:].count(SOLID) == 0  # nothing of the key counts as leaked
    assert keep[original.index("> key ") : key] == bytearray([SOLID]) * 6


def test_a_scrubber_must_return_one_string_per_text():
    data, _ = tiny()
    with pytest.raises(TypeError):
        score(data, lambda texts: texts[:1])

"""The frozen splits must rebuild to exactly the checksummed bytes."""
import json
import re

import pytest

from bench import adversarial, build_splits


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("splits")
    return root, build_splits.build(root)


def _rows(root, part, name):
    return [json.loads(line) for line in open(root / part / name, encoding="utf-8")]


def test_rebuilt_data_matches_the_frozen_checksums(built):
    _, found = built
    assert build_splits.verify(found) == []


def test_a_changed_file_is_detected(built):
    _, found = built
    tampered = {**found, "test": {**found["test"], "traces.jsonl": "0" * 64}}
    assert len(build_splits.verify(tampered)) == 1


def test_spec_shape():
    spec = build_splits.load_spec()
    assert spec["parts"]["dev"]["seed"] != spec["parts"]["test"]["seed"]
    for part in spec["parts"].values():
        assert set(part["sha256"]) == set(build_splits.CHECKED_FILES)


def test_dev_and_test_share_no_traces(built):
    root, _ = built
    dev = {t["trace_id"] for t in _rows(root, "dev", "traces.jsonl")}
    test = {t["trace_id"] for t in _rows(root, "test", "traces.jsonl")}
    assert len(dev) == 2000 and len(test) == 1000 and not dev & test


def test_planted_values_do_not_repeat_between_dev_and_test(built):
    """A scrubber can't pass the test split by memorizing dev's secrets."""
    root, _ = built
    secret_types = {"aws_key", "github_token", "openai_key", "jwt", "private_key"}
    dev = {r["value"] for r in _rows(root, "dev", "ground_truth.jsonl") if r["type"] in secret_types}
    test = {r["value"] for r in _rows(root, "test", "ground_truth.jsonl") if r["type"] in secret_types}
    assert not dev & test


def test_test_split_includes_the_adversarial_traces():
    assert [p.name for p in build_splits.folders("test")] == ["test", "adversarial"]
    assert [p.name for p in build_splits.folders("dev")] == ["dev"]


def test_adversarial_ground_truth_is_exact(built):
    root, _ = built
    traces = {t["trace_id"]: t for t in _rows(root, "adversarial", "traces.jsonl")}
    rows = _rows(root, "adversarial", "ground_truth.jsonl")
    assert len(traces) == len(adversarial.CASES) and len(rows) >= 25
    for r in rows:
        assert r["variant"] == "adversarial"
        content = traces[r["trace_id"]]["steps"][r["step"]]["content"]
        assert content[r["spans"][0][0] : r["spans"][-1][1]] == r["text"]


def test_adversarial_build_is_repeatable():
    assert adversarial.build() == adversarial.build()


def test_no_key_shaped_literal_in_adversarial_source():
    src = open(adversarial.__file__, encoding="utf-8").read()
    for p in [r"AKIA[A-Z0-9]{16}", r"ASIA[A-Z0-9]{16}", r"gh[po]_[A-Za-z0-9]{36}", r"sk-[A-Za-z0-9]{20,}", r"-----BEGIN [A-Z ]*PRIVATE KEY", r"eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+"]:
        assert not re.search(p, src), p

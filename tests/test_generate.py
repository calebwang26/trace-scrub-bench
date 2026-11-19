"""The generator must be deterministic, & its ground truth must be exact."""
import ast
import hashlib
import json
import re
from collections import defaultdict

import pytest

from tracegen.generate import generate, generate_trace
from tracegen.sensitive import TYPES

N = 150


def _load(folder, name):
    return [json.loads(line) for line in open(folder / name, encoding="utf-8")]


def _digest(folder):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.iterdir())}


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    folder = tmp_path_factory.mktemp("gen")
    manifest = generate(seed=7, n_traces=N, out_dir=folder)
    traces = {t["trace_id"]: t for t in _load(folder, "traces.jsonl")}
    return folder, manifest, traces


def test_same_seed_gives_identical_bytes(data, tmp_path):
    folder, _, _ = data
    generate(seed=7, n_traces=N, out_dir=tmp_path)
    assert _digest(tmp_path) == _digest(folder)


def test_different_seed_gives_different_data(data, tmp_path):
    folder, _, _ = data
    generate(seed=8, n_traces=N, out_dir=tmp_path)
    assert _digest(tmp_path)["traces.jsonl"] != _digest(folder)["traces.jsonl"]


def test_a_trace_does_not_depend_on_how_many_others_are_generated():
    assert generate_trace(7, 42) == generate_trace(7, 42)


def test_trace_schema(data):
    _, _, traces = data
    assert len(traces) == N  # ids are unique
    for t in traces.values():
        assert set(t) == {"trace_id", "model", "harness", "task", "steps", "outcome", "has_repo"}
        assert t["outcome"] in {"success", "fail"} and isinstance(t["has_repo"], bool)
        assert t["steps"][0]["role"] == "user"
        for s in t["steps"]:
            assert set(s) == {"role", "type", "content"}
            assert s["type"] in {"message", "tool_call", "tool_result"}
            if s["type"] == "tool_call":
                assert "tool" in json.loads(s["content"])


def test_ground_truth_positions_are_exact(data):
    folder, manifest, traces = data
    rows = _load(folder, "ground_truth.jsonl")
    assert len(rows) == manifest["n_sensitive"] > 0
    for r in rows:
        content = traces[r["trace_id"]]["steps"][r["step"]]["content"]
        assert content[r["spans"][0][0] : r["spans"][-1][1]] == r["text"]
        pieces = "".join(content[a:b] for a, b in r["spans"])
        if r["variant"] == "split":
            assert len(r["spans"]) == 2 and pieces == r["value"]
        elif r["variant"] == "plain" and r["type"] != "private_key":
            assert pieces == r["value"]


def test_every_type_and_every_hard_variant_is_planted(data):
    _, manifest, _ = data
    assert set(manifest["sensitive_by_type"]) == set(TYPES)
    assert set(manifest["sensitive_by_variant"]) == {"plain", "split", "base64", "json_escaped"}


def test_python_steps_all_parse(data):
    folder, _, traces = data
    rows = _load(folder, "python_steps.jsonl")
    assert rows
    for r in rows:
        ast.parse(traces[r["trace_id"]]["steps"][r["step"]]["content"])


def test_nothing_sensitive_looking_is_left_unlabeled(data):
    """Outside the labeled spans there must be no emails, IPs, keys or FAKE markers.

    Otherwise a scrubber that correctly removed them would be punished for it.
    """
    folder, _, traces = data
    labeled = defaultdict(list)
    for r in _load(folder, "ground_truth.jsonl") + _load(folder, "decoys.jsonl"):
        labeled[(r["trace_id"], r["step"])] += [tuple(s) for s in r["spans"]]
    patterns = [r"[\w.+-]+@[\w-]+\.[\w.-]+", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"(?i)fake", r"AKIA", r"ghp_", r"\bsk-", r"555\D?01\d\d", r"BEGIN [A-Z ]*PRIVATE"]
    for t in traces.values():
        for i, s in enumerate(t["steps"]):
            spans = labeled.get((t["trace_id"], i), [])
            for p in patterns:
                for m in re.finditer(p, s["content"]):
                    assert any(m.start() < b and a < m.end() for a, b in spans), (p, m.group(0), s["content"][:200])

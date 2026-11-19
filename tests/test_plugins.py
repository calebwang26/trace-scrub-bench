import re
import subprocess
import sys
from pathlib import Path

import pytest

from bench import plugins
from bench.run import balance, leaderboard, run

ROOT = Path(__file__).resolve().parent.parent


class _Object:
    def scrub_many(self, texts):
        return [t.upper() for t in texts]


OBJECT = _Object()


def shout(text: str) -> str:
    return text + "!"


def test_python_function_entry():
    assert plugins.load({"name": "x", "entry": "tests.test_plugins:shout"})(["a", "b"]) == ["a!", "b!"]


def test_python_object_entry_with_scrub_many():
    assert plugins.load({"name": "x", "entry": "tests.test_plugins:OBJECT"})(["a", "b"]) == ["A", "B"]


def test_command_entry_reads_stdin_and_writes_stdout():
    code = "import sys; sys.stdout.write(sys.stdin.read().replace('hunter2', '[X]'))"
    scrub_many = plugins.load({"name": "cli", "command": [sys.executable, "-c", code]})
    assert scrub_many(["pw=hunter2\nline two"]) == ["pw=[X]\nline two"]


def test_missing_optional_dependency_is_skipped_not_fatal():
    with pytest.raises(plugins.Unavailable):
        plugins.load({"name": "x", "entry": "no_such_module_xyz:scrub", "optional": True})
    with pytest.raises(ImportError):
        plugins.load({"name": "x", "entry": "no_such_module_xyz:scrub"})


def test_registry_is_valid_and_every_required_entry_loads():
    entries = plugins.load_registry()
    assert {"do-nothing", "redact-everything"} <= {e["name"] for e in entries}
    for e in entries:
        if not e.get("optional"):
            plugins.load(e)


def test_registry_rejects_bad_entries(tmp_path):
    bad = tmp_path / "s.yaml"
    bad.write_text("scrubbers:\n  - name: a\n    entry: m:f\n  - name: a\n    entry: m:g\n")
    with pytest.raises(ValueError):
        plugins.load_registry(bad)
    bad.write_text("scrubbers:\n  - name: a\n")
    with pytest.raises(ValueError):
        plugins.load_registry(bad)


def test_benchmark_never_imports_the_scrubber_package():
    """bench/ must reach scrubbers only through scrubbers.yaml, never by importing them."""
    for path in (ROOT / "bench").rglob("*.py"):
        assert not re.search(r"^\s*(import|from)\s+scrubber\b", path.read_text(encoding="utf-8"), re.MULTILINE), path


def test_the_runner_also_starts_as_a_plain_script():
    """`python bench/run.py` must work, not only `python -m bench.run`."""
    done = subprocess.run([sys.executable, "bench/run.py", "--only", "do-nothing", "--limit", "5"], cwd=ROOT, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert "| do-nothing |" in done.stdout


def test_balance_is_zero_for_both_baselines():
    assert balance({"severity_score": 0.0, "utility_kept": 1.0}) == 0
    assert balance({"severity_score": 1.0, "utility_kept": 0.0}) == 0
    assert balance({"severity_score": 0.5, "utility_kept": 0.5}) == 0.5


def test_run_and_leaderboard_on_a_small_slice():
    results, skipped = run("test", only=["do-nothing", "redact-everything"], limit=25)
    by_name = {r["name"]: r for r in results}
    assert by_name["do-nothing"]["recall"] == 0 and by_name["redact-everything"]["recall"] == 1
    text = leaderboard(results, skipped, "test")
    assert "| do-nothing |" in text and "## Recall by type" in text

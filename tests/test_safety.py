"""Checks on the repo's own safety files."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_gitignore_blocks_env_and_generated_data():
    lines = (ROOT / ".gitignore").read_text().splitlines()
    for needed in [".env", "data/", "bench/data/", "outputs/", "*.jsonl", "*.zip"]:
        assert needed in lines, f"{needed} missing from .gitignore"


def test_gitleaks_allowlist_is_only_the_fake_marker():
    text = (ROOT / ".gitleaks.toml").read_text()
    assert "useDefault = true" in text
    assert "regexes = ['''FAKE''']" in text


def test_pre_commit_hook_runs_gitleaks_on_staged_changes():
    hook = ROOT / "hooks" / "pre-commit"
    assert "gitleaks protect --staged" in hook.read_text()

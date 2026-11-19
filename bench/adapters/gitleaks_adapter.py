"""Gitleaks (github.com/gitleaks/gitleaks) as a scrubber entry.

Gitleaks is a secret *scanner*: it reports findings, it doesn't rewrite text.
This adapter turns it into a scrubber: scan, then replace every reported
secret with a placeholder. It uses gitleaks' default rules, NOT this repo's
`.gitleaks.toml` (which allows FAKE-marked values & would hide everything).

One process is started per trace (all of its steps at once), because starting
one per step would mean tens of thousands of process launches.
"""
from __future__ import annotations

import base64
import binascii
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

PLACEHOLDER = "[REDACTED_GITLEAKS]"


def _slice_for(line: str, finding: dict) -> str | None:
    """The encoded text behind a decoded finding (gitleaks reports its column range).

    Gitleaks' columns are off by one on every line but the first, so both
    offsets are tried & the one that really decodes to the secret is kept.
    """
    for shift in (2, 1):
        piece = line[max(finding["StartColumn"] - shift, 0) : finding["EndColumn"] - shift + 1]
        text = piece
        for _ in range(5):  # gitleaks decodes nested base64 up to depth 5
            try:
                text = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                break
            if finding["Secret"] in text:
                return piece
    return None


def _apply(text: str, findings: list[dict]) -> str:
    """Replace every reported secret. All targets are located on the original text
    first & then replaced longest-first, so the result does not depend on the order
    in which gitleaks happens to list its findings (it scans in parallel).
    """
    lines = text.split("\n")
    targets: set[str] = set()
    for f in findings:
        if any(tag.startswith("decoded:") for tag in f.get("Tags") or []):
            # found inside base64: the reported secret is the decoded form, so locate the encoded text
            if f["StartLine"] == f["EndLine"] and f["StartLine"] <= len(lines):
                piece = _slice_for(lines[f["StartLine"] - 1], f)
                if piece:
                    targets.add(piece)
        elif f["Secret"] and f["Secret"] in text:
            targets.add(f["Secret"])
    for target in sorted(targets, key=lambda t: (-len(t), t)):
        text = text.replace(target, PLACEHOLDER)
    return text


class GitleaksScrubber:
    def available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def why_unavailable(self) -> str:
        return "the gitleaks command is not installed (brew install gitleaks)"

    def scrub_many(self, texts: list[str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "steps"
            source.mkdir()
            for i, text in enumerate(texts):
                (source / f"{i:05d}.txt").write_text(text, encoding="utf-8")
            report = Path(tmp) / "report.json"
            subprocess.run(
                ["gitleaks", "dir", str(source), "--report-format", "json", "--report-path", str(report), "--no-banner", "--exit-code", "0", "--log-level", "error"],
                check=True, capture_output=True,
            )
            findings = json.loads(report.read_text(encoding="utf-8") or "[]") if report.exists() else []
        by_step: dict[int, list[dict]] = {}
        for f in findings:
            by_step.setdefault(int(Path(f["File"]).stem), []).append(f)
        return [_apply(text, by_step.get(i, [])) for i, text in enumerate(texts)]

    def scrub(self, text: str) -> str:
        return self.scrub_many([text])[0]


scrubber = GitleaksScrubber()

"""The scrubber: find sensitive spans in a text & replace them with typed placeholders.

    scrub_v1(text) -> str     regex rules only
    python -m scrubber.scrub --version v1 --in data/traces.jsonl --out outputs/traces.scrubbed.jsonl
    echo "some text" | python -m scrubber.scrub --stdin

How it works: every detector looks at the original text & proposes spans
(start, end, label). Overlapping proposals are settled by priority (earlier
detectors win), then each surviving span is replaced by `[REDACTED_<LABEL>]`.
Detecting on the original text, rather than replacing rule by rule, means one
rule can never trip over another rule's placeholder.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Callable, Iterable

Span = tuple[int, int, str]  # (start, end, label)
Detector = Callable[[str], Iterable[Span]]


@dataclass(frozen=True)
class Rule:
    """A regex detector. `group` picks which part of the match gets redacted."""

    label: str
    pattern: re.Pattern
    group: int = 0

    def __call__(self, text: str) -> Iterable[Span]:
        for m in self.pattern.finditer(text):
            if m.end(self.group) > m.start(self.group):
                yield (m.start(self.group), m.end(self.group), self.label)


def rule(label: str, pattern: str, group: int = 0, flags: int = 0) -> Rule:
    return Rule(label, re.compile(pattern, flags), group)


# --- v1: one obvious regex per type -------------------------------------------

RULES_V1: list[Detector] = [
    rule("PRIVATE_KEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    rule("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
    rule("GITHUB_TOKEN", r"\bghp_[A-Za-z0-9]{36}\b"),
    rule("OPENAI_KEY", r"\bsk-[A-Za-z0-9]{20,}\b"),
    rule("JWT", r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    rule("DB_PASSWORD", r"\b[a-z][a-z0-9+]*://[^:/\s]+:([^@\s]+)@", group=1),
    rule("ENV_SECRET", r"^\w*(?:SECRET|PASSWORD|TOKEN)\w*=(.+)$", group=1, flags=re.MULTILINE),
    rule("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    rule("PHONE", r"(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
    rule("IPV4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
]


def find_spans(text: str, detectors: list[Detector]) -> list[Span]:
    """Collect spans from all detectors; on overlap the earlier detector wins."""
    accepted: list[Span] = []
    for detector in detectors:
        for start, end, label in detector(text):
            if all(end <= a or b <= start for a, b, _ in accepted):
                accepted.append((start, end, label))
    return sorted(accepted)


def redact(text: str, spans: list[Span]) -> str:
    """Replace each span with its placeholder."""
    if not spans:
        return text
    out, pos = [], 0
    for start, end, label in spans:
        out += [text[pos:start], f"[REDACTED_{label}]"]
        pos = end
    out.append(text[pos:])
    return "".join(out)


def scrub_v1(text: str) -> str:
    """Version 1: regex rules only."""
    return redact(text, find_spans(text, RULES_V1))


VERSIONS = {"v1": scrub_v1}


def scrub_trace(trace: dict, scrub: Callable[[str], str]) -> dict:
    """Scrub every step of a trace, & its task text."""
    steps = [{**s, "content": scrub(s["content"])} for s in trace["steps"]]
    return {**trace, "task": scrub(trace["task"]), "steps": steps}


def main() -> None:
    parser = argparse.ArgumentParser(description="Scrub a traces.jsonl file, or stdin.")
    parser.add_argument("--version", choices=sorted(VERSIONS), default=sorted(VERSIONS)[-1])
    parser.add_argument("--stdin", action="store_true", help="read text on stdin, write scrubbed text on stdout")
    parser.add_argument("--in", dest="src", default="data/traces.jsonl")
    parser.add_argument("--out", default="outputs/traces.scrubbed.jsonl")
    args = parser.parse_args()
    scrub = VERSIONS[args.version]
    if args.stdin:
        sys.stdout.write(scrub(sys.stdin.read()))
        return
    from pathlib import Path

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.src, encoding="utf-8") as src, open(args.out, "w", encoding="utf-8", newline="\n") as out:
        for line in src:
            out.write(json.dumps(scrub_trace(json.loads(line), scrub), ensure_ascii=False) + "\n")
            n += 1
    print(f"scrubbed {n} traces with {args.version} -> {args.out}")


if __name__ == "__main__":
    main()

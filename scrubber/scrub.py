"""The scrubber: find sensitive spans in a text & replace them with typed placeholders.

    scrub_v1(text) -> str     regex rules only
    scrub_v2(text) -> str     regex + entropy + fixes for what v1 missed on the dev split

    python -m scrubber.scrub --version v2 --in data/traces.jsonl --out outputs/traces.scrubbed.jsonl
    echo "some text" | python -m scrubber.scrub --stdin

How it works: every detector looks at the original text & proposes spans
(start, end, label). Overlapping proposals are settled by priority (earlier
detectors win), then each surviving span is replaced by `[REDACTED_<LABEL>]`.
Detecting on the original text, rather than replacing rule by rule, means one
rule can never trip over another rule's placeholder.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import dataclass
from typing import Callable, Iterable

from scrubber.entropy import high_entropy_spans

Span = tuple[int, int, str]  # (start, end, label)
Detector = Callable[[str], Iterable[Span]]


@dataclass(frozen=True)
class Rule:
    """A regex detector. `group` picks which part of the match gets redacted.

    `keep`, if given, is asked about every match; returning False drops it
    (used for allowlists such as documentation example keys).
    """

    label: str
    pattern: re.Pattern
    group: int = 0
    keep: Callable[[re.Match], bool] | None = None

    def __call__(self, text: str) -> Iterable[Span]:
        for m in self.pattern.finditer(text):
            if m.end(self.group) > m.start(self.group) and (self.keep is None or self.keep(m)):
                yield (m.start(self.group), m.end(self.group), self.label)


def rule(label: str, pattern: str, group: int = 0, flags: int = 0, keep: Callable[[re.Match], bool] | None = None) -> Rule:
    return Rule(label, re.compile(pattern, flags), group, keep)


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


# =============================================================================
# v1: one obvious regex per type
# =============================================================================

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


def scrub_v1(text: str) -> str:
    """Version 1: regex rules only."""
    return redact(text, find_spans(text, RULES_V1))


# =============================================================================
# v2: regex + entropy + fixes for what v1 missed on the dev split
# Each block below names the dev-split finding that motivated it.
# =============================================================================

# --- placeholders & allowlists (v1 damaged 44% of the harmless decoys) --------

_PLACEHOLDER_WORDS = ("your", "replace", "change", "example", "todo", "dummy", "placeholder", "insert", "set-me", "xxx", "redacted")


def is_placeholder(value: str) -> bool:
    """True for values like `changeme`, `<YOUR_API_KEY>`, `xxxxxxxx` or `...EXAMPLE`."""
    v = value.strip("\"'").lower()
    if not v or (v[0] in "<$" and v[-1] in ">}") or "example" in v:
        return True
    if v.startswith(_PLACEHOLDER_WORDS):
        return True
    body = re.sub(r"^[a-z]{2,6}[-_]", "", v)  # drop a prefix such as sk- or ghp_
    return len(body) >= 6 and len(set(body)) <= 2  # one or two characters repeated


def _real_token(m: re.Match) -> bool:
    return not is_placeholder(m.group(0))


_EXAMPLE_DOMAINS = {"example.com", "example.org", "example.net", "test.com"}
_ROLE_LOCAL_PARTS = {"user", "you", "name", "test", "noreply", "no-reply", "git", "example"}


def _real_email(m: re.Match) -> bool:
    local, _, domain = m.group(0).lower().partition("@")
    return domain not in _EXAMPLE_DOMAINS and local not in _ROLE_LOCAL_PARTS


def _real_ip(m: re.Match) -> bool:
    octets = [int(x) for x in m.group(0).split(".")]
    if any(o > 255 for o in octets) or octets[0] in (0, 127):
        return False  # not an address, or loopback / wildcard
    line_start = m.string.rfind("\n", 0, m.start()) + 1
    line_end = m.string.find("\n", m.end())
    line = m.string[line_start : len(m.string) if line_end < 0 else line_end]
    # "libssl 3.27.5.5" on a line of its own is a version number, not a host
    return not re.fullmatch(r"[A-Za-z][\w.+-]* v?\d+(?:\.\d+){3}", line.strip())


# --- secrets named by their variable (v1 only knew `^NAME=value`) -------------

_SECRET_NAME = r"[A-Za-z0-9_.-]*(?:secret|passw(?:or)?d|token|credential|(?<![a-z])(?:api|private|encryption|signing|access)[_-]?key)[A-Za-z0-9_.-]*|[A-Za-z0-9_.-]*[_-]key"


def looks_secret(value: str) -> bool:
    """A value worth redacting: not a placeholder, no spaces or brackets, & random-looking.

    Random-looking means 8+ characters with a digit, or 12+ characters mixing
    upper & lower case. `changeme` & `info` fail; `FAKE-tiger-1725` passes.
    """
    if len(value) < 8 or re.search(r"[\s()\[\]{}]", value) or is_placeholder(value):
        return False
    mixed_case = len(value) >= 12 and any(c.isupper() for c in value) and any(c.islower() for c in value)
    return any(c.isdigit() for c in value) or mixed_case


def _assignment_value(m: re.Match) -> bool:
    return looks_secret(m.group("value"))


# `NAME=value` taking the rest of the line: .env files, compose lists, YAML, Python constants.
ASSIGNMENT_LINE = rule(
    "ENV_SECRET",
    rf"^[ \t]*(?:export[ \t]+|-[ \t]+)?[\"']?(?:{_SECRET_NAME})[\"']?[ \t]*[=:][ \t]*[\"']?(?P<value>.+?)[\"']?,?[ \t]*$",
    group="value", flags=re.MULTILINE | re.IGNORECASE, keep=_assignment_value,
)
# The same in the middle of a line (log lines, headers): the value ends at a space or quote.
ASSIGNMENT_INLINE = rule(
    "ENV_SECRET",
    rf"(?<![\w.-])(?:{_SECRET_NAME})[\"']?[ \t]*[=:][ \t]*[\"']?(?P<value>[^\s\"',;]+)",
    group="value", flags=re.IGNORECASE, keep=_assignment_value,
)

# --- personal names: only findable through their context ---------------------

_NAME = r"[A-Z][\w'’-]+(?: [A-Z][\w'’-]+){1,3}"
_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
NAME_RULES: list[Detector] = [
    rule("PERSON_NAME", rf"(?:Author|Maintainer|Committer|Reviewed by|Signed-off-by|Co-authored-by):? +({_NAME})", group=1),
    rule("PERSON_NAME", rf"({_NAME}) [<(]{_EMAIL}[>)]", group=1),
    rule("PERSON_NAME", rf"^\^?[0-9a-f]{{7,40}} \(({_NAME}) +\d{{4}}-\d\d-\d\d", group=1, flags=re.MULTILINE),  # git blame
    rule("PERSON_NAME", rf"[\"']?\bname[\"']? *[=:] *[\"']({_NAME})[\"']", group=1),
]

# --- base64: decode it & look inside ------------------------------------------

_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")


def base64_secrets(text: str) -> Iterable[Span]:
    """A base64 blob is sensitive if what it decodes to contains something sensitive."""
    for m in _B64.finditer(text):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded.isprintable() or "\n" in decoded:
            if find_spans(decoded, DECODED_RULES):
                yield (m.start(), m.end(), "BASE64_SECRET")


# `echo <blob> | base64 -d`: someone is unpacking a credential, whatever it decodes to.
BASE64_PIPE = rule("BASE64_SECRET", r"\becho +[\"']?([A-Za-z0-9+/]{12,}={0,2})[\"']? *\| *base64 +(?:-d|-D|--decode)\b", group=1)


_ENTROPY_ON = True  # switched off only by scrub_v2_no_entropy, the ablation


def entropy_detector(text: str) -> Iterable[Span]:
    if not _ENTROPY_ON:
        return
    for start, end in high_entropy_spans(text):
        if not is_placeholder(text[start:end]):
            yield (start, end, "HIGH_ENTROPY")


TOKEN_RULES: list[Detector] = [
    rule("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b", keep=_real_token),
    rule("GITHUB_TOKEN", r"\bghp_[A-Za-z0-9]{36}\b", keep=_real_token),
    rule("OPENAI_KEY", r"\bsk-[A-Za-z0-9_-]{20,}", keep=_real_token),  # v1 stopped at the `-` in `sk-proj-...`
    rule("JWT", r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]
# Only the key body: the BEGIN/END lines are public & say what kind of key was there.
PRIVATE_KEY = rule("PRIVATE_KEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)*([\s\S]*?)(?:\\n|\s)*-----END [A-Z ]*PRIVATE KEY-----", group=1)
DB_PASSWORD = rule("DB_PASSWORD", r"\b[a-z][a-z0-9+]*://[^:/\s]+:([^@\s]+)@", group=1)

# What counts as "something sensitive" inside a decoded base64 blob.
DECODED_RULES: list[Detector] = [PRIVATE_KEY, *TOKEN_RULES, DB_PASSWORD, ASSIGNMENT_LINE, entropy_detector]

RULES_V2: list[Detector] = [
    PRIVATE_KEY,
    *TOKEN_RULES,
    DB_PASSWORD,
    ASSIGNMENT_LINE,
    ASSIGNMENT_INLINE,
    *NAME_RULES,
    rule("EMAIL", _EMAIL, keep=_real_email),
    rule("PHONE", r"(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
    rule("IPV4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", keep=_real_ip),
    BASE64_PIPE,
    base64_secrets,
    entropy_detector,
]

# --- secrets split over two lines (v1 caught none of them) -------------------

_BLOB_LINE = re.compile(r"[A-Za-z0-9+/_.-]{4,}={0,2}")  # a line that is one unbroken run of token characters
_BLOB_TAIL = re.compile(r"[A-Za-z0-9+/_.-]{4,}$")
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----")
_STRING_JOIN = re.compile(r"([\"'])[ \t]*\n[ \t]*\1")  # "abc"<newline>"def": adjacent string literals


def joined_view(text: str) -> tuple[str, list[int]]:
    """Return the text with line breaks inside a token removed, plus a position map.

    Three kinds of break are undone:
      * a backslash at the end of a line (shell continuation);
      * adjacent string literals on consecutive lines (Python, C, JSON5 ...);
      * a hard terminal wrap: a line that is nothing but token characters,
        right after a line that ends in token characters.
    `positions[i]` is where character i of the view sits in the original text.
    """
    cut = bytearray(len(text))  # 1 = this character is dropped in the view
    for m in re.finditer(r"\\\n", text):
        cut[m.start() : m.end()] = b"\x01\x01"
    for m in _STRING_JOIN.finditer(text):
        cut[m.start() : m.end()] = b"\x01" * (m.end() - m.start())
    pos, previous, chained = 0, None, False
    for line in text.split("\n"):
        wrapped = (
            previous is not None
            and _BLOB_LINE.fullmatch(line) is not None
            and _BLOB_TAIL.search(previous) is not None
            and (chained or _BLOB_LINE.fullmatch(previous) is None)
        )
        if wrapped:
            cut[pos - 1] = 1  # the newline before this line
        previous, chained = line, wrapped
        pos += len(line) + 1
    positions = [i for i in range(len(text)) if not cut[i]]
    return "".join(text[i] for i in positions), positions


SPLIT_RULES: list[Detector] = [*TOKEN_RULES, ASSIGNMENT_LINE, ASSIGNMENT_INLINE, entropy_detector]


def split_secrets(text: str) -> Iterable[Span]:
    """Find tokens that only show up once broken lines are joined back together."""
    if "\n" not in text:
        return
    view, positions = joined_view(text)
    if len(view) == len(text):
        return
    pem = [m.span() for m in _PEM_BLOCK.finditer(text)]  # key & certificate blocks are wrapped by design
    for start, end, label in find_spans(view, SPLIT_RULES):
        if positions[end - 1] - positions[start] == end - 1 - start:
            continue  # not split: the normal rules handle it
        if any(positions[start] < b and a <= positions[end - 1] for a, b in pem):
            continue
        run_start = start
        for i in range(start + 1, end + 1):  # one span per unbroken fragment
            if i == end or positions[i] != positions[i - 1] + 1:
                yield (positions[run_start], positions[i - 1] + 1, label)
                run_start = i


DETECTORS_V2: list[Detector] = [PRIVATE_KEY, split_secrets, *RULES_V2[1:]]

# --- JSON: read it as JSON instead of guessing with regexes -------------------

_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
_SECRET_KEY = re.compile(r"secret|passw(?:or)?d|token|credential|(?:api|private|encryption|signing|access)[_-]?key|[_-]key$", re.IGNORECASE)
_NAME_KEY = re.compile(r"^(?:full_?)?name$|^author$|^maintainer$|^owner$", re.IGNORECASE)


def _scrub_json(text: str, depth: int) -> str:
    """Scrub every string value of a JSON document, leaving its formatting alone.

    Each string literal is decoded (so `\\"` & `\\n` become real characters,
    & JSON nested inside a string can be parsed again), scrubbed, re-encoded.
    """
    out, pos, last_key = [], 0, None
    for m in _JSON_STRING.finditer(text):
        is_key = text[m.end() : m.end() + 8].lstrip().startswith(":")
        try:
            value = json.loads(m.group(0))
        except ValueError:
            continue
        if is_key:
            last_key = value
            continue
        after_colon = text[pos : m.start()].rstrip().endswith(":") or text[: m.start()].rstrip().endswith(":")
        key = last_key if after_colon else None
        scrubbed = scrub_v2(value, depth + 1)
        if scrubbed == value and key is not None:
            if _SECRET_KEY.search(key) and looks_secret(value):
                scrubbed = "[REDACTED_ENV_SECRET]"
            elif _NAME_KEY.search(key) and re.fullmatch(_NAME, value):
                scrubbed = "[REDACTED_PERSON_NAME]"
        if scrubbed != value:
            out += [text[pos : m.start()], json.dumps(scrubbed, ensure_ascii=False)]
            pos = m.end()
    out.append(text[pos:])
    return "".join(out)


def scrub_v2(text: str, depth: int = 0) -> str:
    """Version 2: regex + entropy + the fixes found on the dev split."""
    stripped = text.strip()
    if depth < 3 and stripped[:1] in ("{", "[") and stripped[-1:] in ("}", "]"):
        try:
            json.loads(text)
        except ValueError:
            pass
        else:
            return _scrub_json(text, depth)
    return redact(text, find_spans(text, DETECTORS_V2))


def scrub_v2_no_entropy(text: str) -> str:
    """Ablation: v2 with the entropy detector switched off, to measure what it adds & costs."""
    global _ENTROPY_ON
    _ENTROPY_ON = False
    try:
        return scrub_v2(text)
    finally:
        _ENTROPY_ON = True


VERSIONS = {"v1": scrub_v1, "v2": scrub_v2}


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

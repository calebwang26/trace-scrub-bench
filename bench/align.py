"""Work out which characters of the original text survived scrubbing.

A scrubber only hands back a new string. To score it at the character level,
the benchmark has to line the two strings up & decide, for every character of
the original, whether it is still there.

It does that in two passes, like `git diff --word-diff`:
  1. compare line by line: unchanged lines survive completely;
  2. inside changed lines, compare character by character.

Each original character gets one of three marks:

  SOLID (2)  it sits in an unchanged line, or in a matching run that is at
             least MIN_RUN characters long (or touches the edge of the change)
  WEAK  (1)  it sits in a shorter matching run
  GONE  (0)  nothing matches it

Why two kinds of match? A short match can be real or a coincidence, & the
alignment alone can't tell. In `Author: NAME <EMAIL>` the two characters ` <`
between the redactions really did survive. But the placeholder
`[REDACTED_AWS_KEY]` also shares `K` & `E` with almost any key, & that must
not count as "two characters of the key leaked". So the scorer reads the
marks differently by context: for harmless text any match counts as kept;
for a planted item only SOLID characters count as leaked.
"""
from __future__ import annotations

from difflib import SequenceMatcher

MIN_RUN = 4
GONE, WEAK, SOLID = 0, 1, 2


def surviving(original: str, scrubbed: str) -> bytearray:
    """Return one byte per character of `original`: SOLID, WEAK or GONE."""
    n = len(original)
    if original == scrubbed:
        return bytearray([SOLID]) * n
    keep = bytearray(n)
    old_lines = original.splitlines(keepends=True)
    new_lines = scrubbed.splitlines(keepends=True)
    starts = [0]
    for line in old_lines:
        starts.append(starts[-1] + len(line))
    matcher = SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            _mark(keep, starts[i1], starts[i2], SOLID)
        elif tag == "replace" and i2 - i1 == j2 - j1:
            # Same number of lines before & after: pair them up one to one.
            for k in range(i2 - i1):
                _align_chars(old_lines[i1 + k], new_lines[j1 + k], keep, starts[i1 + k])
        elif tag == "replace":
            _align_chars(original[starts[i1] : starts[i2]], "".join(new_lines[j1:j2]), keep, starts[i1])
        # "delete": the lines are gone, nothing survives. "insert": nothing to mark.
    return keep


def _mark(keep: bytearray, start: int, end: int, value: int) -> None:
    keep[start:end] = bytes([value]) * (end - start)


def _align_chars(old: str, new: str, keep: bytearray, offset: int) -> None:
    """Character pass for one changed region. Marks survivors in `keep`."""
    limit = min(len(old), len(new))
    prefix = 0
    while prefix < limit and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and old[-1 - suffix] == new[-1 - suffix]:
        suffix += 1
    _mark(keep, offset, offset + prefix, SOLID)
    _mark(keep, offset + len(old) - suffix, offset + len(old), SOLID)
    mid_old, mid_new = old[prefix : len(old) - suffix], new[prefix : len(new) - suffix]
    if not mid_old or not mid_new:
        return
    for block in SequenceMatcher(None, mid_old, mid_new, autojunk=False).get_matching_blocks():
        start = offset + prefix + block.a
        _mark(keep, start, start + block.size, SOLID if block.size >= MIN_RUN else WEAK)

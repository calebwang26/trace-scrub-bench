"""Shannon entropy: a measure of how random a string looks.

For a string, count how often each character appears, turn the counts into
probabilities p, & compute  H = -sum(p * log2(p)).  The unit is bits per
character. `aaaaaaaa` scores 0 (no surprise at all). English identifiers score
around 3 to 4. A random base64 secret scores higher, because it uses many
different characters about equally often.

Two facts that shape the detector:
  * a string of n characters can't score above log2(n), so short strings
    can't look very random however random they are;
  * hexadecimal text can't score above 4.0 (only 16 symbols), which is why
    commit hashes & checksums stay below a threshold placed above 4.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# Runs of characters that secrets are made of (base64, base64url, hex).
CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")


def shannon_entropy(text: str) -> float:
    """Bits per character."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


# Chosen on the dev split (see BUILDLOG.md, step 8). At 4.3 bits per character
# & a minimum length of 20, the detector flagged 4 of 96,528 harmless strings
# that were not decoys; at 4.0 it flagged 128, at 3.8 it flagged 6,505.
THRESHOLD = 4.3
_HEX = re.compile(r"[0-9a-fA-F]+")
_PUBLIC_HASH = re.compile(r"sha(?:1|256|384|512)-")  # subresource-integrity hashes are public


def high_entropy_spans(text: str, threshold: float = THRESHOLD):
    """Yield (start, end) for every long, random-looking token in the text."""
    for m in CANDIDATE.finditer(text):
        token = m.group(0)
        if _HEX.fullmatch(token) or _PUBLIC_HASH.match(token):
            continue  # commit hashes, checksums & integrity hashes are not secrets
        if shannon_entropy(token) >= threshold:
            yield m.start(), m.end()

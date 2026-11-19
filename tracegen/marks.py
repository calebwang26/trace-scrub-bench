"""Track where planted items end up in the final text.

The generator writes text from templates. While it does, it wraps every
planted item in invisible marker characters:

    <START>7<SEP>the secret text<END>

When a step's text is finished, `resolve` strips the markers again & returns
the clean text plus the exact character positions of each item. That is how
the ground truth gets exact offsets without anyone counting characters by hand.

The markers are Unicode "private use" characters, which never appear in
normal text, so they can't collide with real content. They also pass through
`json.dumps(..., ensure_ascii=False)` untouched, while the secret between them
gets escaped like any other text. So a secret planted inside a JSON string is
recorded exactly as it appears after escaping.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

START, SEP, END = "", "", ""
_MARK = re.compile(f"{START}(\\d+){SEP}(.*?){END}", re.DOTALL)


@dataclass
class Item:
    """One planted thing: either a sensitive item or a harmless decoy."""

    kind: str  # "sensitive" or "decoy"
    type: str  # e.g. "aws_key", "email", "uuid"
    value: str  # the logical value (before any escaping, encoding or splitting)
    variant: str = "plain"  # "plain", "split", "base64" or "json_escaped"
    carrier: str = ""  # which template planted it


@dataclass
class Registry:
    """Hands out ids for the items planted in one trace."""

    items: list[Item] = field(default_factory=list)

    def new(self, kind: str, type: str, value: str, variant: str = "plain", carrier: str = "") -> int:
        self.items.append(Item(kind, type, value, variant, carrier))
        return len(self.items) - 1

    def wrap(self, item_id: int, text: str) -> str:
        """Mark `text` as (a fragment of) item `item_id`."""
        return f"{START}{item_id}{SEP}{text}{END}"

    def plant(self, kind: str, type: str, value: str, variant: str = "plain", carrier: str = "", text: str | None = None) -> str:
        """Register an item & return it wrapped, ready to drop into a template."""
        return self.wrap(self.new(kind, type, value, variant, carrier), value if text is None else text)


def resolve(marked: str) -> tuple[str, dict[int, list[tuple[int, int]]]]:
    """Strip markers. Return (clean_text, {item_id: [(start, end), ...]}).

    Positions are character offsets into clean_text. An item has more than one
    span when it was split into fragments (e.g. a key wrapped over two lines).
    """
    out: list[str] = []
    spans: dict[int, list[tuple[int, int]]] = {}
    pos = 0  # position in the marked text
    length = 0  # length of the clean text so far
    for m in _MARK.finditer(marked):
        before = marked[pos : m.start()]
        out.append(before)
        length += len(before)
        text = m.group(2)
        spans.setdefault(int(m.group(1)), []).append((length, length + len(text)))
        out.append(text)
        length += len(text)
        pos = m.end()
    out.append(marked[pos:])
    clean = "".join(out)
    assert START not in clean and SEP not in clean and END not in clean, "unbalanced markers"
    return clean, spans

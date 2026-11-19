"""The two anchor scrubbers. Every real scrubber should land between them."""

BLOCK = "█"  # a solid block character that never occurs in a trace


def do_nothing(text: str) -> str:
    """Removes nothing: 0% recall, 100% utility."""
    return text


def redact_everything(text: str) -> str:
    """Removes everything: 100% recall, 0% utility."""
    return BLOCK

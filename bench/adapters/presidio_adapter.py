"""Microsoft Presidio (github.com/microsoft/presidio) as a scrubber entry.

Presidio finds personal data with a mix of patterns & a named-entity model.
It is set up here for the four kinds of personal data in this benchmark:
email addresses, phone numbers, IP addresses & person names. It has no rules
for API keys or passwords, so those are expected misses.

Uses spaCy's small English model (`en_core_web_sm`, about 12 MB) instead of
the large default, to keep the install light. That makes name detection
weaker than Presidio at its best.

    pip install -r requirements-optional.txt
    python -m spacy download en_core_web_sm
"""
from __future__ import annotations

ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "PERSON"]


class PresidioScrubber:
    def __init__(self) -> None:
        self._analyzer = None
        self._error = ""

    def available(self) -> bool:
        try:
            import spacy
            from presidio_analyzer import AnalyzerEngine  # noqa: F401

            if not spacy.util.is_package("en_core_web_sm"):
                self._error = "spaCy model en_core_web_sm is not installed"
                return False
            return True
        except ImportError as error:
            self._error = str(error)
            return False

    def why_unavailable(self) -> str:
        return self._error or "presidio-analyzer is not installed"

    def _load(self):
        if self._analyzer is None:
            import logging

            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)
            provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]})
            self._analyzer = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
        return self._analyzer

    def scrub(self, text: str) -> str:
        if not text.strip():
            return text
        results = self._load().analyze(text=text, entities=ENTITIES, language="en")
        # Replace from the end so earlier positions stay valid; skip overlaps.
        last_start = len(text) + 1
        for r in sorted(results, key=lambda r: (-r.end, r.start)):
            if r.end <= last_start:
                text = text[: r.start] + f"<{r.entity_type}>" + text[r.end :]
                last_start = r.start
        return text


scrubber = PresidioScrubber()

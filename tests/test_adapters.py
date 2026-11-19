"""The optional third-party entries. Each test is skipped when its tool isn't installed."""
import base64
import shutil

import pytest

from bench import plugins

GH = "ghp_FAKEn4Jq8Zr2Lw6Tb0Xc5Vd9Ys3Ku7Pm1Ha4"


def _entry(name):
    return next(e for e in plugins.load_registry() if e["name"] == name)


def test_optional_entries_are_marked_optional():
    assert _entry("gitleaks")["optional"] and _entry("presidio")["optional"]


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks is not installed")
def test_gitleaks_adapter_redacts_plain_and_base64_findings():
    scrub_many = plugins.load(_entry("gitleaks"))
    blob = base64.b64encode(GH.encode()).decode()
    texts = ["nothing to see", f"line one\nexport GITHUB_TOKEN={GH}\nblob: {blob}\nlast line"]
    assert scrub_many(texts) == ["nothing to see", "line one\nexport GITHUB_TOKEN=[REDACTED_GITLEAKS]\nblob: [REDACTED_GITLEAKS]\nlast line"]


def test_presidio_adapter_redacts_a_phone_number_and_an_ip():
    pytest.importorskip("presidio_analyzer")
    try:
        scrub_many = plugins.load(_entry("presidio"))
    except plugins.Unavailable as reason:
        pytest.skip(str(reason))
    assert scrub_many(["call (415) 555-0142 or ssh 10.0.12.7", ""]) == ["call <PHONE_NUMBER> or ssh <IP_ADDRESS>", ""]

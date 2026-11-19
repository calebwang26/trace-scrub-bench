"""A few hand-written cases for the scrubber. All secrets are synthetic & carry FAKE."""
import subprocess
import sys

import pytest

from scrubber.scrub import find_spans, redact, rule, scrub_trace, scrub_v1

AWS = "AKIAFAKE7Q2MXP4RTZ1L"
GH = "ghp_FAKEn4Jq8Zr2Lw6Tb0Xc5Vd9Ys3Ku7Pm1Ha4"  # ghp_ + 36 characters
# Glued from two parts: written as one literal, GitHub's secret scanner reads it as an OpenAI key.
SK = "sk-" + "FAKEa8Jd72kLq0Zx5Vb3Nm9Rt6Yw1Pc4Hg7Ue2Is"
assert len(GH) == 40 and len(AWS) == 20


@pytest.mark.parametrize(
    "text, expected",
    [
        (f"AWS_ACCESS_KEY_ID={AWS}", "AWS_ACCESS_KEY_ID=[REDACTED_AWS_KEY]"),
        (f"curl -H 'Authorization: token {GH}' https://x.example", "curl -H 'Authorization: token [REDACTED_GITHUB_TOKEN]' https://x.example"),
        (f'client = OpenAI(api_key="{SK}")', 'client = OpenAI(api_key="[REDACTED_OPENAI_KEY]")'),
        ("DATABASE_URL=postgres://app:FAKEpw123@db.internal.example:5432/orders", "DATABASE_URL=postgres://app:[REDACTED_DB_PASSWORD]@db.internal.example:5432/orders"),
        ("DEBUG=false\nSESSION_SECRET=FAKE-summer-42\nPORT=8000", "DEBUG=false\nSESSION_SECRET=[REDACTED_ENV_SECRET]\nPORT=8000"),
        ("mail dana.reyes@fakecorp.example today", "mail [REDACTED_EMAIL] today"),
        ("call (415) 555-0142 now", "call [REDACTED_PHONE] now"),
        ("connect to 10.0.12.7 port 5432", "connect to [REDACTED_IPV4] port 5432"),
    ],
)
def test_v1_redacts_each_plain_type(text, expected):
    assert scrub_v1(text) == expected


def test_v1_redacts_a_whole_private_key_block():
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEabc\ndef==\n-----END RSA PRIVATE KEY-----"
    assert scrub_v1(f"before\n{block}\nafter") == "before\n[REDACTED_PRIVATE_KEY]\nafter"


def test_v1_redacts_a_jwt():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.FAKEsignature_abc-123"
    assert scrub_v1(f"Bearer {token}") == "Bearer [REDACTED_JWT]"


def test_ordinary_text_is_left_alone():
    text = "def compute_total(items, factor=2):\n    return round(sum(i.price for i in items) * factor, 2)\n"
    assert scrub_v1(text) == text


def test_overlapping_detections_are_settled_by_priority():
    detectors = [rule("FIRST", r"abcdef"), rule("SECOND", r"cdefgh"), rule("THIRD", r"xyz")]
    assert find_spans("abcdefgh xyz", detectors) == [(0, 6, "FIRST"), (9, 12, "THIRD")]
    assert redact("abcdefgh xyz", [(0, 6, "FIRST"), (9, 12, "THIRD")]) == "[REDACTED_FIRST]gh [REDACTED_THIRD]"


def test_a_token_in_an_env_line_is_redacted_once():
    assert scrub_v1(f"GITHUB_TOKEN={GH}") == "GITHUB_TOKEN=[REDACTED_GITHUB_TOKEN]"


def test_scrub_trace_scrubs_task_and_steps_and_keeps_the_rest():
    trace = {"trace_id": "t", "model": "m", "task": "email dana@fakecorp.example", "steps": [{"role": "tool", "type": "tool_result", "content": f"key {AWS}"}]}
    out = scrub_trace(trace, scrub_v1)
    assert out["task"] == "email [REDACTED_EMAIL]" and out["steps"][0]["content"] == "key [REDACTED_AWS_KEY]"
    assert out["trace_id"] == "t" and out["steps"][0]["role"] == "tool"


def test_command_line_stdin_mode():
    done = subprocess.run([sys.executable, "-m", "scrubber.scrub", "--version", "v1", "--stdin"], input=f"key {AWS}\n", capture_output=True, text=True, check=True)
    assert done.stdout == "key [REDACTED_AWS_KEY]\n"

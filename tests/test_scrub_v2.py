"""Cases for scrubber v2: one or two per fix. All secrets are synthetic & carry FAKE."""
import ast
import base64
import json
import math

import pytest

from scrubber.entropy import THRESHOLD, high_entropy_spans, shannon_entropy
from scrubber.scrub import is_placeholder, joined_view, looks_secret, scrub_v1, scrub_v2

AWS = "AKIAFAKE7Q2MXP4RTZ1L"
GH = "ghp_FAKEn4Jq8Zr2Lw6Tb0Xc5Vd9Ys3Ku7Pm1Ha4"
RANDOM = "FAKEq7Zx2Lm9Vb4Nc8Rt1Yw6Pd3Hg5Ks0Ju"  # 34 random-looking characters


# --- entropy -------------------------------------------------------------------

def test_entropy_of_simple_strings():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("abababab") == 1  # two symbols, equally often: 1 bit
    assert shannon_entropy("abcdefgh") == 3  # eight different symbols: log2(8) bits
    assert shannon_entropy("x" * 5 + "abc") < 3


def test_entropy_cannot_exceed_log2_of_the_length():
    assert shannon_entropy(RANDOM) <= math.log2(len(RANDOM))


def test_entropy_detector_flags_random_tokens_but_not_hashes_or_words():
    assert list(high_entropy_spans(f"value {RANDOM} end")) == [(6, 6 + len(RANDOM))]
    sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert shannon_entropy(sha256) < THRESHOLD  # hex can never exceed 4 bits per character
    for harmless in [sha256, "test_normalize_discount_handles_negative_amounts", "7798afb7-8a4a-43a1-91fd-cf57b69464ab", "src/stockroom/exports/helpers", "sha512-" + RANDOM]:
        assert list(high_entropy_spans(harmless)) == [], harmless


def test_a_false_positive_the_entropy_detector_really_produces():
    """Public base64 (here a test image) is as random as a secret. This is the known cost."""
    blob = base64.b64encode(bytes(range(7, 250, 5))).decode()
    assert scrub_v2(f'PNG_1X1 = "{blob}"') == 'PNG_1X1 = "[REDACTED_HIGH_ENTROPY]"'


# --- what v1 missed --------------------------------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("LLM_API_KEY=sk-proj-FAKEa8Jd_2kLq0-x5Vb3Nm9Rt6Yw1Pc4Hg7Ue2", "LLM_API_KEY=[REDACTED_OPENAI_KEY]"),
        ("aws_secret_access_key = FAKErxWQejLFVqvRNfG0y5XR31bAvHDoVanE39Q/", "aws_secret_access_key = [REDACTED_ENV_SECRET]"),
        ('SMTP_PASSWORD = "FAKE-tiger-1725"', 'SMTP_PASSWORD = "[REDACTED_ENV_SECRET]"'),
        ("      - ADMIN_PASSWORD=FAKE-tiger-1725", "      - ADMIN_PASSWORD=[REDACTED_ENV_SECRET]"),
        ("DEBUG config: loaded JWT_SECRET=fake82bcec61572b27 ok", "DEBUG config: loaded JWT_SECRET=[REDACTED_ENV_SECRET] ok"),
        ("ENCRYPTION_KEY=fake9c84fd23ca1fda527c38623bc017", "ENCRYPTION_KEY=[REDACTED_ENV_SECRET]"),
        ("Author: Greta Dubois <greta.dubois@fakecorp.example>", "Author: [REDACTED_PERSON_NAME] <[REDACTED_EMAIL]>"),
        ("1f81cd09 (Chloe Alvarez 2026-06-15 00:05:07 +0000 40)     total += 1", "1f81cd09 ([REDACTED_PERSON_NAME] 2026-06-15 00:05:07 +0000 40)     total += 1"),
        ("echo RkFLRVhuRERNUDNHeFpYVw== | base64 -d > /tmp/key", "echo [REDACTED_BASE64_SECRET] | base64 -d > /tmp/key"),
    ],
)
def test_v2_catches_what_v1_missed(text, expected):
    assert scrub_v2(text) == expected
    assert scrub_v1(text) != expected


def test_base64_blob_is_redacted_when_it_decodes_to_a_secret():
    blob = base64.b64encode(AWS.encode()).decode()
    harmless = base64.b64encode(b"production").decode()
    # the name `bootstrap` gives nothing away: only decoding the blob reveals the key
    assert scrub_v2(f"data:\n  APP_ENV: {harmless}\n  bootstrap: {blob}") == f"data:\n  APP_ENV: {harmless}\n  bootstrap: [REDACTED_BASE64_SECRET]"


def test_private_key_body_is_removed_and_the_header_kept():
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV\nWXYZ0123456789abcdefghij==\n-----END RSA PRIVATE KEY-----"
    assert scrub_v2(f"$ cat key.pem\n{block}") == "$ cat key.pem\n-----BEGIN RSA PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END RSA PRIVATE KEY-----"


# --- split secrets ------------------------------------------------------------------

def test_joined_view_undoes_three_kinds_of_line_break():
    text = 'a="AKIAFAKE7Q"\n  "2MXP4RTZ1L"\nb: ghp_FAKEn4Jq8Zr2\\\nLw6Tb0Xc5V\nc=sk-FAKEabcdef\nghijklmnop\ndone here'
    view, positions = joined_view(text)
    assert view == 'a="AKIAFAKE7Q2MXP4RTZ1L"\nb: ghp_FAKEn4Jq8Zr2Lw6Tb0Xc5V\nc=sk-FAKEabcdefghijklmnop\ndone here'
    assert all(text[p] == ch for p, ch in zip(positions, view))


def test_split_secrets_are_redacted_in_both_fragments():
    python = f'AWS_ACCESS_KEY_ID = (\n    "{AWS[:9]}"\n    "{AWS[9:]}"\n)\n'
    scrubbed = scrub_v2(python)
    assert AWS[:9] not in scrubbed and AWS[9:] not in scrubbed
    ast.parse(scrubbed)  # still valid Python
    shell = f'curl -H "Authorization: token {GH[:20]}\\\n{GH[20:]}" https://x.example'
    assert scrub_v2(shell) == 'curl -H "Authorization: token [REDACTED_GITHUB_TOKEN]\\\n[REDACTED_GITHUB_TOKEN]" https://x.example'
    wrapped = f"DEBUG deploy: GH_PAT={GH[:18]}\n{GH[18:]}\nINFO deploy: done"
    assert scrub_v2(wrapped) == "DEBUG deploy: GH_PAT=[REDACTED_GITHUB_TOKEN]\n[REDACTED_GITHUB_TOKEN]\nINFO deploy: done"


def test_ordinary_lines_are_not_glued_together():
    listing = "__init__.py\nauth.py\nbilling.py\ninventory.py"
    assert joined_view(listing)[0] == listing
    env = "SESSION_SECRET=FAKE-tiger-1725\nPORT=8000\nWORKERS=4"
    assert scrub_v2(env) == "SESSION_SECRET=[REDACTED_ENV_SECRET]\nPORT=8000\nWORKERS=4"


# --- JSON -------------------------------------------------------------------------

def test_json_strings_are_decoded_before_scrubbing():
    call = json.dumps({"tool": "write_file", "args": {"path": ".env", "content": 'DEBUG=false\nSESSION_SECRET=FAKEp"w9x\nPORT=8000\n'}})
    out = json.loads(scrub_v2(call))
    assert out["args"]["content"] == "DEBUG=false\nSESSION_SECRET=[REDACTED_ENV_SECRET]\nPORT=8000\n"
    assert out["tool"] == "write_file" and out["args"]["path"] == ".env"


def test_json_nested_inside_json():
    inner = json.dumps({"env": "production", "deploy_token": 'FAKEx"k9WjOlRmbeK', "region": "us-east-1"})
    outer = json.dumps({"exit_code": 0, "stdout": inner, "stderr": ""})
    result = json.loads(json.loads(scrub_v2(outer))["stdout"])
    assert result == {"env": "production", "deploy_token": "[REDACTED_ENV_SECRET]", "region": "us-east-1"}


def test_json_formatting_outside_the_changed_strings_is_untouched():
    text = '[\n  {"id": 1000, "name": "Yuki Alvarez", "plan": "pro"}\n]'
    assert scrub_v2(text) == '[\n  {"id": 1000, "name": "[REDACTED_PERSON_NAME]", "plan": "pro"}\n]'
    config = '{\n  "name": "stockroom",\n  "page_size": 58\n}'
    assert scrub_v2(config) == config


# --- decoys: v1 damaged these, v2 leaves them alone ----------------------------------

@pytest.mark.parametrize(
    "harmless",
    [
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "SESSION_SECRET=changeme",
        "API_TOKEN=<set-me>",
        "Questions? Write to user@example.com.",
        "origin\tgit@github.com:example-org/stockroom.git (fetch)",
        "INFO uvicorn: Uvicorn running on http://127.0.0.1:8000",
        "grpcio-tools 3.27.5.5",
        "request_id=7798afb7-8a4a-43a1-91fd-cf57b69464ab GET /api/orders 200",
        "    --hash=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "    ordered = sorted(records, key=lambda r: r.created_at, reverse=True)",
    ],
)
def test_v2_leaves_harmless_lookalikes_alone(harmless):
    assert scrub_v2(harmless) == harmless


def test_placeholder_and_secret_shape_helpers():
    for value in ["changeme", "<YOUR_API_KEY>", "xxxxxxxx", "your-secret-here", "AKIAIOSFODNN7EXAMPLE", "sk-000000000000000000000000", "${SECRET}"]:
        assert is_placeholder(value), value
    for value in [AWS, "FAKE-tiger-1725", RANDOM]:
        assert not is_placeholder(value) and looks_secret(value), value
    for value in ["info", "lambda", "true", "compute_total(items)", "changeme", "/etc/app/keys"]:
        assert not looks_secret(value), value

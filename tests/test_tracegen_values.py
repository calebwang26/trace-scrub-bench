import base64
import json
import random
import re

from tracegen import decoys, sensitive
from tracegen.marks import Registry, resolve


def test_resolve_returns_clean_text_and_exact_spans():
    reg = Registry()
    marked = "key=" + reg.plant("sensitive", "aws_key", "AKIAFAKE7Q2MXP4RTZ1L") + " id=" + reg.plant("decoy", "uuid", "abc")
    clean, spans = resolve(marked)
    assert clean == "key=AKIAFAKE7Q2MXP4RTZ1L id=abc"
    assert clean[slice(*spans[0][0])] == "AKIAFAKE7Q2MXP4RTZ1L"
    assert clean[slice(*spans[1][0])] == "abc"


def test_split_item_gets_one_span_per_fragment():
    reg = Registry()
    i = reg.new("sensitive", "aws_key", "AKIAFAKE7Q2MXP4RTZ1L", variant="split")
    marked = "x " + reg.wrap(i, "AKIAFAKE7Q") + "\\\n  " + reg.wrap(i, "2MXP4RTZ1L")
    clean, spans = resolve(marked)
    assert "".join(clean[s:e] for s, e in spans[i]) == "AKIAFAKE7Q2MXP4RTZ1L"
    assert len(spans[i]) == 2


def test_markers_survive_json_escaping():
    reg = Registry()
    marked = json.dumps({"cmd": 'echo "' + reg.plant("sensitive", "env_secret", 'FAKEp"w') + '"'}, ensure_ascii=False)
    clean, spans = resolve(marked)
    assert json.loads(clean) == {"cmd": 'echo "FAKEp"w"'}
    assert clean[slice(*spans[0][0])] == 'FAKEp\\"w'  # recorded as it appears: escaped


def test_secret_formats():
    rng = random.Random(0)
    for _ in range(200):
        assert re.fullmatch(r"AKIA[A-Z2-7]{16}", sensitive.aws_key(rng))
        assert re.fullmatch(r"ghp_[A-Za-z0-9]{36}", sensitive.github_token(rng))
        assert re.fullmatch(r"sk-[A-Za-z0-9_-]{48,}", sensitive.openai_key(rng))
        header, payload, _sig = sensitive.jwt(rng).split(".")
        assert json.loads(base64.urlsafe_b64decode(header + "=="))["typ"] == "JWT"
        assert "sub" in json.loads(base64.urlsafe_b64decode(payload + "=="))
        key = sensitive.private_key(rng)
        assert key.startswith("-----BEGIN ") and key.endswith("PRIVATE KEY-----")


def test_every_secret_carries_the_fake_marker():
    rng = random.Random(1)
    for _ in range(200):
        values = [sensitive.aws_key(rng), sensitive.github_token(rng), sensitive.openai_key(rng), sensitive.jwt(rng),
                  sensitive.private_key(rng), sensitive.db_url_parts(rng)[1], sensitive.env_secret(rng)[1],
                  sensitive.env_secret(rng, special=True)[1], sensitive.email(rng)]
        for v in values:
            assert "fake" in v.lower(), v


def test_personal_data_uses_reserved_ranges():
    rng = random.Random(2)
    for _ in range(200):
        assert re.search(r"555\D?01\d\d$", sensitive.phone(rng))
        assert sensitive.email(rng).rsplit(".", 1)[1] in {"example", "test"}
        ip = sensitive.ipv4(rng)
        assert ip.startswith(("10.", "172.", "192.168.", "192.0.2.", "198.51.100.", "203.0.113."))


def test_decoys_never_contain_the_fake_marker():
    rng = random.Random(3)
    for _ in range(200):
        values = [decoys.doc_example_key(rng), decoys.env_placeholder(rng)[1], decoys.uuid(rng), decoys.git_sha(rng),
                  decoys.sha256(rng), decoys.safe_ip(rng), decoys.example_email(rng)]
        for v in values:
            assert "FAKE" not in v


def test_no_key_shaped_literal_in_generator_source():
    """Secrets must be assembled at runtime: the source may not hold a full key."""
    patterns = [r"AKIA[A-Z0-9]{16}", r"ghp_[A-Za-z0-9]{36}", r"sk-[A-Za-z0-9]{20,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"]
    for module in (sensitive, decoys):
        src = open(module.__file__).read()
        for p in patterns:
            assert not re.search(p, src), f"{p} found in {module.__name__}"

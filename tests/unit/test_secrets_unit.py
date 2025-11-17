from __future__ import annotations

from tools.vectorscan import secret_scrubber as secrets_mod


def test_scrub_text_redacts_sensitive_values():
    env = {
        "AWS_SECRET_ACCESS_KEY": "abcd1234secret",
        "NOT_SECRET": "public",
    }
    original = "Token=abcd1234secret; keep"
    scrubbed = secrets_mod.scrub_text(original, env)
    assert "abcd1234secret" not in scrubbed
    assert "[REDACTED:AWS_SECRET_ACCESS_KEY]" in scrubbed


def test_scrub_structure_redacts_nested_values():
    env = {"API_TOKEN": "super-secret-token"}
    payload = {
        "outer": {
            "inner": "super-secret-token",
            "list": ["safe", "super-secret-token"],
        }
    }
    scrubbed = secrets_mod.scrub_structure(payload, env)
    assert scrubbed["outer"]["inner"] == "[REDACTED:API_TOKEN]"
    assert scrubbed["outer"]["list"][1] == "[REDACTED:API_TOKEN]"


def test_contains_secret_detects_in_dict_and_string():
    env = {"SESSION_TOKEN": "session12345"}
    payload = {"data": "session12345"}
    assert secrets_mod.contains_secret(payload, env)
    assert secrets_mod.contains_secret("session12345", env)
    assert not secrets_mod.contains_secret({"data": "safe"}, env)

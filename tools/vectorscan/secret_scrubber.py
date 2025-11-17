from __future__ import annotations

import json
import os
from typing import Any, Mapping

SENSITIVE_KEY_HINTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "API_KEY",
    "SESSION",
    "CREDENTIAL",
)

MIN_SECRET_VALUE_LENGTH = 8


def _gather_sensitive_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    env_map = env or os.environ
    secrets: dict[str, str] = {}
    for key, value in env_map.items():
        if not value:
            continue
        upper = key.upper()
        if any(hint in upper for hint in SENSITIVE_KEY_HINTS):
            if len(value) >= MIN_SECRET_VALUE_LENGTH:
                secrets[key] = value
    return secrets


def _scrub_text(text: str, secrets: Mapping[str, str]) -> str:
    result = text
    for key, value in secrets.items():
        if value and value in result:
            result = result.replace(value, f"[REDACTED:{key}]")
    return result


def scrub_text(text: str, env: Mapping[str, str] | None = None) -> str:
    secrets = _gather_sensitive_env(env)
    return _scrub_text(text, secrets)


def _scrub(value: Any, secrets: Mapping[str, str]) -> Any:
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(item, secrets) for item in value]
    if isinstance(value, str):
        return _scrub_text(value, secrets)
    return value


def scrub_structure(value: Any, env: Mapping[str, str] | None = None) -> Any:
    secrets = _gather_sensitive_env(env)
    return _scrub(value, secrets)


def contains_secret(value: Any, env: Mapping[str, str] | None = None) -> bool:
    secrets = _gather_sensitive_env(env)
    if not secrets:
        return False
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return any(secret and secret in payload for secret in secrets.values())


__all__ = [
    "scrub_text",
    "scrub_structure",
    "contains_secret",
]

from __future__ import annotations

from pathlib import Path
from typing import Union

PathLike = Union[str, Path]

STRICT_MODE_PREFIX = "[Strict Mode] "
NO_NETWORK_MESSAGE = "Lead capture disabled (no-network mode)"


def _stringify(value: PathLike | None) -> str:
    if value is None:
        return "-"
    return str(value)


def strict_mode(detail: str) -> str:
    message = detail.strip() or "Strict mode violation"
    return f"{STRICT_MODE_PREFIX}{message}"


def file_not_found(path: PathLike) -> str:
    return f"Error: file not found: {_stringify(path)}"


def invalid_json(path: PathLike) -> str:
    return f"Error: invalid JSON: {_stringify(path)}"


def permission_denied(path: PathLike) -> str:
    return f"Error: permission denied: {_stringify(path)}"


def schema_error() -> str:
    return "Error: invalid plan structure"


def stdin_json_error() -> str:
    return "Error: invalid JSON from stdin"

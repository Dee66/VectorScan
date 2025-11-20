"""Minimal fixpack loader for VectorScan fixpack hints and metadata."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

_FIXPACK_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "fixpack", "vectorscan")
)


def load_fixpack(issue_id: str) -> Optional[Dict[str, Any]]:
    """Return parsed fixpack metadata for the given issue id, if available."""

    path = _resolve_fixpack_path(issue_id)
    if path is None:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            contents = handle.read()
    except OSError:
        return None

    parsed = _parse_fixpack(contents)
    if parsed is None:
        return None
    parsed.setdefault("fixpack_id", issue_id)
    return parsed


def get_fixpack_hint(rule_id: str) -> Optional[str]:
    """Placeholder lookup for rule-to-fixpack hint resolution."""

    path = _resolve_fixpack_path(rule_id)
    if path is None:
        return None
    return f"fixpack:{rule_id}"


def get_fixpack_metadata(rule_id: str) -> Optional[Dict[str, Any]]:
    """Return structured metadata for the provided rule, if available."""

    return load_fixpack(rule_id)


def _resolve_fixpack_path(issue_id: str) -> Optional[str]:
    filename = f"{issue_id}.hcl"
    candidate = os.path.join(_FIXPACK_DIR, filename)
    if os.path.exists(candidate):
        return candidate
    return None


def _parse_fixpack(contents: str) -> Optional[Dict[str, Any]]:
    fixpack_id = _extract_string("fixpack_id", contents)
    description = _extract_string("description", contents)
    terraform_patch = _extract_heredoc("terraform_patch", contents)

    if not terraform_patch:
        return None

    if not fixpack_id or not description:
        return None

    return {
        "fixpack_id": fixpack_id,
        "description": description,
        "terraform_patch": terraform_patch,
    }


def _extract_string(key: str, contents: str) -> Optional[str]:
    pattern = rf"{key}\s*=\s*\"([^\"]*)\""
    match = re.search(pattern, contents)
    if match:
        return match.group(1).strip()
    return None


def _extract_heredoc(key: str, contents: str) -> Optional[str]:
    pattern = rf"{key}\s*=\s*<<EOT\s*\r?\n(.*?)\r?\nEOT"
    match = re.search(pattern, contents, re.DOTALL)
    if match:
        return match.group(1).strip("\n")
    return None

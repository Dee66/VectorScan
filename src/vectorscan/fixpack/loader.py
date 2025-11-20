"""Stub fixpack loader to keep canonical imports working."""

from __future__ import annotations

from typing import Any, Dict, Optional

_FIXPACK_HINTS: Dict[str, str] = {}


def load_fixpack(issue_id: str) -> Optional[Dict[str, Any]]:
    """Return fixpack metadata for the given issue id, if available."""

    _ = issue_id
    return None


def get_fixpack_hint(rule_id: str) -> Optional[str]:
    """Placeholder lookup for rule-to-fixpack hint resolution."""

    return _FIXPACK_HINTS.get(rule_id)

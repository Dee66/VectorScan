"""Minimal fixpack loader for VectorScan fixpack hints."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

_FIXPACK_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "fixpack", "vectorscan")
)


def load_fixpack(issue_id: str) -> Optional[Dict[str, Any]]:
    """Return fixpack metadata for the given issue id, if available."""

    path = _resolve_fixpack_path(issue_id)
    if path is None:
        return None
    return {
        "id": issue_id,
        "path": path,
        "manifest": json.dumps({"file": os.path.basename(path)}),
    }


def get_fixpack_hint(rule_id: str) -> Optional[str]:
    """Placeholder lookup for rule-to-fixpack hint resolution."""

    path = _resolve_fixpack_path(rule_id)
    if path is None:
        return None
    return f"fixpack:{rule_id}"


def _resolve_fixpack_path(issue_id: str) -> Optional[str]:
    filename = f"{issue_id}.hcl"
    candidate = os.path.join(_FIXPACK_DIR, filename)
    if os.path.exists(candidate):
        return candidate
    return None

"""Remediation helpers."""

from __future__ import annotations

from typing import Dict, Any


def build_fixpack(issue_id: str) -> Dict[str, Any]:
    return {"remediation_hint": f"fixpack/{issue_id}.hcl", "remediation_difficulty": "medium"}

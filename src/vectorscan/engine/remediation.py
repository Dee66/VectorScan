"""Remediation helpers."""

from __future__ import annotations

from typing import Dict, Any


_DEFAULT_HINT = "Upgrade to VectorGuard for comprehensive remediation guidance."


def build_fixpack(_: str) -> Dict[str, Any]:
    """Return placeholder remediation data for free scanner builds."""

    return {"remediation_hint": _DEFAULT_HINT, "remediation_difficulty": "medium"}

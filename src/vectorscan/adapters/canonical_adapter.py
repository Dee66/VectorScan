"""Canonical adapter placeholder."""

from __future__ import annotations

from typing import Dict, Any


def adapt_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize plan structure for evaluators."""
    plan.setdefault("resource_changes", [])
    return plan

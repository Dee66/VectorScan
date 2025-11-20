"""Deterministic placeholder rule for the VectorScan pipeline."""

from __future__ import annotations

from . import register
from .base import Rule, build_issue


@register
class PlaceholderRule(Rule):
    id = "P-VEC-000"
    severity = "low"

    @classmethod
    def evaluate(cls, plan):
        _ = plan
        _ = build_issue  # Placeholder hook for rule authors.
        # Still returns no issues — placeholder only.
        return []

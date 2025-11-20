"""Deterministic placeholder rule for the VectorScan pipeline."""

from __future__ import annotations

from . import register
from .base import Rule


@register
class PlaceholderRule(Rule):
    id = "P-VEC-000"
    severity = "low"

    @classmethod
    def evaluate(cls, plan):
        return []

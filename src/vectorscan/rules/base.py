"""Rule base class for VectorScan."""

from __future__ import annotations

from typing import Any, Dict, List


class Rule:
    """Minimal rule abstraction loaded by the evaluator."""

    id = "UNSET"
    severity = "low"

    @classmethod
    def evaluate(cls, plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

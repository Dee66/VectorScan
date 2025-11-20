"""Template evaluator wiring."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from ..canonical_utils import canonicalize_output, Issue
from ..constants import PILLAR_NAME
from .loader import PlanLoader


class PillarEvaluator:
    """Evaluates a plan using template rules."""

    def __init__(self, loader: PlanLoader) -> None:
        self.loader = loader

    def evaluate(self, path: Optional[Path], stdin_payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        plan = self.loader.load(path=path, stdin_payload=stdin_payload)
        issues: list[Issue] = []
        result = {
            "pillar": PILLAR_NAME,
            "issues": issues,
            "pillar_score_inputs": {"resource_count": len(plan.get("resource_changes", []))},
            "guardscore_badge": {"status": "template"},
            "playground_summary": {"message": "Template output"},
        }
        result["issues"] = issues
        result.setdefault("severity_counts", {})
        return canonicalize_output(result)

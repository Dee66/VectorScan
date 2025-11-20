"""Template evaluator wiring."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from ..evaluator import run_scan
from .loader import PlanLoader


class PillarEvaluator:
    """Evaluates a plan using template rules."""

    def __init__(self, loader: PlanLoader) -> None:
        self.loader = loader

    def evaluate(
        self,
        path: Optional[Path],
        stdin_payload: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        plan = self.loader.load(path=path, stdin_payload=stdin_payload)
        raw_size = None
        if path and path.exists():
            raw_size = path.stat().st_size
        return run_scan(plan=plan, source_path=path, raw_size=raw_size)

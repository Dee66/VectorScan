"""Utilities to normalize pillar output into the canonical schema."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List

from .constants import (
    PILLAR_NAME,
    SCAN_VERSION,
    GUARDSCORE_RULES_VERSION,
    CANONICAL_SCHEMA_VERSION,
    ENVIRONMENT_DEFAULT,
)


@dataclass
class Issue:
    id: str
    severity: str
    title: str
    description: str
    resource_address: str
    attributes: Dict[str, Any]
    remediation_hint: str
    remediation_difficulty: str


def base_output() -> Dict[str, Any]:
    return {
        "pillar": PILLAR_NAME,
        "scan_version": SCAN_VERSION,
        "guardscore_rules_version": GUARDSCORE_RULES_VERSION,
        "canonical_schema_version": CANONICAL_SCHEMA_VERSION,
        "latency_ms": 0,
        "quick_score_mode": False,
        "environment": ENVIRONMENT_DEFAULT,
        "issues": [],
        "pillar_score_inputs": {},
        "percentile_placeholder": True,
        "guardscore_badge": {},
        "playground_summary": {},
        "upgrade_hint": "",
    }


def canonicalize_output(data: Dict[str, Any]) -> Dict[str, Any]:
    base = base_output()
    base.update(data)
    base["issues"] = [
        issue if isinstance(issue, dict) else asdict(issue) for issue in base.get("issues", [])
    ]
    return base


def severity_counts(issues: List[Issue]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for issue in issues:
        counts[issue.severity] = counts.get(issue.severity, 0) + 1
    return counts

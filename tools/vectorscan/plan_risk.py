"""Plan risk profile heuristics for VectorScan outputs."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

RISK_LEVELS: Tuple[str, ...] = ("low", "medium", "high", "critical")
_RISK_RANK = {name: idx for idx, name in enumerate(RISK_LEVELS)}


def _normalize_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _promote(current: str, candidate: str) -> str:
    if candidate not in _RISK_RANK:
        return current
    if current not in _RISK_RANK:
        return candidate
    if _RISK_RANK[candidate] > _RISK_RANK[current]:
        return candidate
    return current


def compute_plan_risk_profile(
    *,
    severity_summary: Dict[str, int] | None,
    metrics: Dict[str, Any] | None,
    suspicious_defaults: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Derive a coarse risk profile from policy severity + exposure heuristics."""

    severity_summary = severity_summary or {}
    metrics = metrics or {}
    suspicious_defaults = list(suspicious_defaults or [])

    current = "low"
    factors: List[str] = []

    def escalate(level: str, reason: str) -> None:
        nonlocal current
        current = _promote(current, level)
        if reason:
            factors.append(reason)

    if severity_summary.get("critical", 0):
        escalate("critical", "Critical policy violations detected")
    elif severity_summary.get("high", 0):
        escalate("high", "High-severity policy violations detected")
    elif severity_summary.get("medium", 0):
        escalate("medium", "Policy violations detected")

    open_sg = _normalize_int(metrics.get("open_sg_count"))
    if open_sg >= 3:
        escalate("high", "Multiple security groups expose 0.0.0.0/0 ingress")
    elif open_sg > 0:
        escalate("medium", "Security group exposes 0.0.0.0/0 ingress")

    iam_risky = _normalize_int(metrics.get("iam_risky_actions"))
    if iam_risky >= 2:
        escalate("high", "Multiple IAM policies include wildcard or risky actions")
    elif iam_risky == 1:
        escalate("medium", "An IAM policy includes wildcard or risky actions")

    try:
        compliance_score = int(metrics.get("compliance_score", 0))
    except (TypeError, ValueError):
        compliance_score = 0
    if compliance_score < 60:
        escalate("high", "Compliance score below 60")
    elif compliance_score < 80:
        escalate("medium", "Compliance score below 80")

    iam_drift_status = (metrics.get("iam_drift") or {}).get("status", "PASS")
    if isinstance(iam_drift_status, str) and iam_drift_status.upper() == "FAIL":
        escalate("high", "IAM drift detected risky changes")

    if suspicious_defaults:
        if len(suspicious_defaults) > 2:
            escalate("high", "Multiple suspicious defaults detected")
        else:
            escalate("medium", "Suspicious defaults detected")

    return {
        "profile": current,
        "factors": factors,
    }


__all__ = ["compute_plan_risk_profile", "RISK_LEVELS"]

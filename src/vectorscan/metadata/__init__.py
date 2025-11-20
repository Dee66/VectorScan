"""Metadata helpers for the canonical VectorScan pipeline."""

from __future__ import annotations

from typing import Any, Dict


def build_environment(plan: Dict[str, Any]) -> Dict[str, Any]:
    inferred = plan.get("inferred_stage") or "dev"
    count = int(plan.get("resource_count") or 0)
    providers = sorted(plan.get("providers") or [])
    return {
        "inferred_stage": inferred,
        "resource_count": count,
        "providers": providers,
    }

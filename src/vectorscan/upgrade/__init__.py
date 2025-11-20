"""Upgrade funnel helpers."""

from __future__ import annotations

from typing import Dict, Any


def build_upgrade_hint(result: Dict[str, Any]) -> str:
    if result.get("issues"):
        return "Upgrade to unlock full remediation."
    return "Upgrade to access premium insights."

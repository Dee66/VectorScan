"""Stub rule registry for the canonical VectorScan pipeline."""

from __future__ import annotations

from typing import List, Type

from .base import Rule

_registry: List[Type[Rule]] = []


def register(rule_cls: Type[Rule]) -> Type[Rule]:
    _registry.append(rule_cls)
    return rule_cls


def get_all_rules() -> List[Type[Rule]]:
    """Return the ordered list of rule classes registered with the pillar."""

    return list(_registry)


# Ensure placeholder rule registers with the decorator at import time.
from . import placeholder_rule as _placeholder_rule  # noqa: F401,E402
from . import rule_public_access as _rule_public_access  # noqa: F401,E402

"""Rule registry and manifest helpers for the canonical VectorScan pipeline."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Dict, List, Type

from vectorscan.fixpack import loader as fixpack_loader

from .base import Rule

_registry: List[Type[Rule]] = []


def register(rule_cls: Type[Rule]) -> Type[Rule]:
    _registry.append(rule_cls)
    return rule_cls


def get_all_rules() -> List[Type[Rule]]:
    """Return the ordered list of rule classes registered with the pillar."""

    return list(_registry)


def build_rule_manifest() -> List[Dict[str, Any]]:
    """Return deterministic manifest entries for every registered rule."""

    manifest: List[Dict[str, Any]] = []
    repo_root = _repo_root()
    for rule_cls in sorted(get_all_rules(), key=lambda rule: rule.id):
        python_class = f"{rule_cls.__module__}.{rule_cls.__name__}"
        file_path = _resolve_rule_path(rule_cls, repo_root)
        manifest.append(
            {
                "id": rule_cls.id,
                "severity": rule_cls.severity,
                "python_class": python_class,
                "file_path": file_path,
                "fixpack": fixpack_loader.get_fixpack_hint(rule_cls.id),
                "description": (rule_cls.__doc__ or "").strip(),
            }
        )
    return manifest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_rule_path(rule_cls: Type[Rule], repo_root: Path) -> str:
    try:
        file_path = Path(inspect.getfile(rule_cls)).resolve()
    except (TypeError, OSError):
        return ""
    try:
        relative = file_path.relative_to(repo_root)
        return str(relative)
    except ValueError:
        return str(file_path)


# Ensure placeholder rule registers with the decorator at import time.
from . import placeholder_rule as _placeholder_rule  # noqa: F401,E402
from . import rule_public_access as _rule_public_access  # noqa: F401,E402
from . import rule_missing_encryption as _rule_missing_encryption  # noqa: F401,E402
from . import rule_unrestricted_network as _rule_unrestricted_network  # noqa: F401,E402
from . import rule_low_dimension as _rule_low_dimension  # noqa: F401,E402

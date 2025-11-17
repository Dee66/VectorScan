"""Base classes and registry for VectorScan policy plugins."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence


@dataclass(frozen=True)
class PolicyMetadata:
    policy_id: str
    name: str
    severity: str = "medium"
    category: str = "general"
    description: str | None = None


class BasePolicy:
    """Minimal interface all policy plugins must satisfy."""

    # Subclasses should override these attributes
    metadata: PolicyMetadata

    def evaluate(self, resources: Sequence[dict]) -> List[str]:  # pragma: no cover - abstract
        raise NotImplementedError


class PolicyRegistry:
    """In-memory registry tracking available policies."""

    def __init__(self) -> None:
        self._policies: Dict[str, BasePolicy] = {}

    def register(self, policy: BasePolicy) -> None:
        if policy.metadata.policy_id in self._policies:
            raise ValueError(f"Duplicate policy id registered: {policy.metadata.policy_id}")
        self._policies[policy.metadata.policy_id] = policy

    def all(self) -> List[BasePolicy]:
        return list(self._policies.values())

    def metadata_map(self) -> Dict[str, PolicyMetadata]:
        return {pid: policy.metadata for pid, policy in self._policies.items()}

    def get(self, policy_id: str) -> BasePolicy:
        return self._policies[policy_id]


_registry = PolicyRegistry()


def register_policy(cls: type[BasePolicy]) -> type[BasePolicy]:
    """Class decorator to register built-in policies when modules import."""

    policy = cls()
    if not isinstance(policy.metadata, PolicyMetadata):
        raise TypeError(f"Policy {cls.__name__} must define PolicyMetadata")
    _registry.register(policy)
    return cls


def get_policies() -> List[BasePolicy]:
    return _registry.all()


def get_policy_metadata() -> Dict[str, PolicyMetadata]:
    return _registry.metadata_map()


def get_policy(policy_id: str) -> BasePolicy:
    return _registry.get(policy_id)

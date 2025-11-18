"""VectorScan policy plugin registry and built-in policies."""

from __future__ import annotations

from .base_policy import (
    BasePolicy,
    PolicyMetadata,
    get_policies,
    get_policy,
    get_policy_metadata,
    register_policy,
)
from .fin.tagging import TaggingPolicy as _TaggingPolicy  # noqa: F401

# Import built-in policies so they register with the global registry on package import.
from .sec.encryption import EncryptionPolicy as _EncryptionPolicy  # noqa: F401

__all__ = [
    "BasePolicy",
    "PolicyMetadata",
    "get_policy",
    "get_policies",
    "get_policy_metadata",
    "register_policy",
]

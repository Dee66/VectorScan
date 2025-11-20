"""Stub fixpack loader to keep canonical imports working."""

from __future__ import annotations

from typing import Any, Dict, Optional

# TODO Phase 2: wire real evaluator
# TODO Phase 3: integrate rule registry
# TODO Phase 4: attach fixpack lookup


def load_fixpack(issue_id: str) -> Optional[Dict[str, Any]]:
    """Return fixpack metadata for the given issue id, if available."""

    return None


def get_fixpack_hint(rule_id: str) -> Optional[str]:
    """Placeholder lookup for rule-to-fixpack hint resolution."""

    _ = rule_id
    return None

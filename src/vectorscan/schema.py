"""Schema helpers for pillar output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class PillarOutput:
    data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return self.data

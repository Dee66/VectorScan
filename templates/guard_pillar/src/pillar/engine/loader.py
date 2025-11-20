"""Plan loader abstraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


class PlanLoader:
    """Loads Terraform JSON plans from disk or stdin payloads."""

    def load(self, path: Optional[Path], stdin_payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if stdin_payload is not None:
            return stdin_payload
        if path is None:
            return {}
        if not path.exists():
            return {}
        return json.loads(path.read_text())

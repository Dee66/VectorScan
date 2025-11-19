"""Stub Terraform adapter for Copilot-generated flows."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class TerraformAdapter:
    """Provides deterministic terraform test results without running terraform."""

    binary: str = "terraform"
    version: str = "default"

    def run_tests(self, working_dir: str) -> dict[str, Any]:
        return {
            "status": "SKIP",
            "working_dir": working_dir,
            "version": self.version,
            "binary": self.binary,
            "stdout": "terraform tests skipped in stub",
            "stderr": "",
        }

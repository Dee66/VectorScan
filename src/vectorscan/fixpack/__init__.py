"""Stubbed fixpack interface for free-scanner builds.

VectorScan no longer ships fixpack content locally, so this module exposes
no-op helpers that keep downstream imports stable without performing any
filesystem access.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def get_fixpack_hint(_: str) -> str:
	"""Return an empty string to indicate no fixpack hint is available."""

	return ""


def get_fixpack_metadata(_: str) -> Optional[Dict[str, Any]]:
	"""VectorScan free_scanner builds never expose fixpack metadata."""

	return None


__all__ = [
	"get_fixpack_hint",
	"get_fixpack_metadata",
]

"""Stubbed fixpack helpers for VectorScan free_scanner distributions."""

from __future__ import annotations

from typing import Any, Dict


def exists(_: str) -> bool:
	"""Fixpacks are not shipped locally, so nothing exists on disk."""

	return False


def get_hint(_: str) -> str:
	"""Return an empty remediation hint placeholder."""

	return ""


def load(_: str) -> Dict[str, Any]:
	"""Return an empty metadata dictionary for compatibility."""

	return {}


def load_metadata(issue_id: str) -> Dict[str, Any]:
	"""Alias maintained for legacy imports until fixpacks are restored."""

	return load(issue_id)


__all__ = ["exists", "get_hint", "load", "load_metadata"]

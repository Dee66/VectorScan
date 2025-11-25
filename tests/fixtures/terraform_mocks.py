"""Deterministic Terraform test reports for offline testing."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

STUB_VERSION = "1.6.0"
STUB_BINARY = "terraform-stub"
_BASE_REPORT: Dict[str, Any] = {
    "status": "PASS",
    "returncode": 0,
    "stdout": "[terraform-stub] tests not executed in offline mode",
    "stderr": "",
    "message": "Terraform tests stubbed",
    "version": STUB_VERSION,
    "binary": STUB_BINARY,
    "source": "stub",
    "strategy": "stub",
    "plan_output": "mock-plan-output",
}


def make_report(status: str = "PASS", **overrides: Any) -> Dict[str, Any]:
    """Return a canonical Terraform report for the requested status."""

    normalized = status.upper()
    report = deepcopy(_BASE_REPORT)
    report["status"] = normalized
    default_return = 0
    if normalized == "FAIL":
        default_return = 1
    elif normalized == "ERROR":
        default_return = 2
    report["returncode"] = overrides.pop("returncode", default_return)
    report.update(overrides)
    return report


def pass_report(**overrides: Any) -> Dict[str, Any]:
    return make_report("PASS", **overrides)


def fail_report(**overrides: Any) -> Dict[str, Any]:
    return make_report("FAIL", **overrides)


def skip_report(**overrides: Any) -> Dict[str, Any]:
    return make_report("SKIP", **overrides)


def error_report(**overrides: Any) -> Dict[str, Any]:
    return make_report("ERROR", **overrides)


__all__ = [
    "STUB_VERSION",
    "STUB_BINARY",
    "make_report",
    "pass_report",
    "fail_report",
    "skip_report",
    "error_report",
]

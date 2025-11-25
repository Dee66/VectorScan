from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from tools.vectorscan import entrypoint_shim
from tools.vectorscan import vectorscan as legacy
from tools.vectorscan.env_flags import env_truthy
from tools.vectorscan.terraform import (
    TerraformDownloadError,
    TerraformManagerError,
)
from tools.vectorscan.constants import (
    DEFAULT_TERRAFORM_CACHE,
    REQUIRED_TERRAFORM_VERSION,
)


_DEFAULT_TERRAFORM_BIN = Path(DEFAULT_TERRAFORM_CACHE) / REQUIRED_TERRAFORM_VERSION / "terraform"
if (
    not os.getenv("VSCAN_TERRAFORM_BIN")
    and _DEFAULT_TERRAFORM_BIN.exists()
    and not env_truthy(os.getenv("VSCAN_TERRAFORM_STUB"))
):
    os.environ["VSCAN_TERRAFORM_BIN"] = str(_DEFAULT_TERRAFORM_BIN)


def tests_requested(options: Any) -> bool:
    """Return True when terraform tests should execute for the current invocation."""

    flag_value = getattr(options, "terraform_tests", False)
    if flag_value:
        return True
    return env_truthy(os.getenv("VSCAN_TERRAFORM_TESTS"))


def _normalize_outcome(token: str) -> str:
    upper = token.upper()
    if upper not in {"PASS", "FAIL", "SKIP"}:
        return "FAIL"
    return upper


def execute(
    options: Any,
    *,
    auto_download: bool,
) -> Tuple[Optional[Dict[str, Any]], str, bool]:
    """Execute terraform tests via the legacy runner and return (report, outcome, flag)."""

    enabled = tests_requested(options)
    if not enabled:
        return None, "SKIP", bool(auto_download)

    override_bin = getattr(options, "terraform_bin", None)
    effective_auto_download = bool(auto_download)
    if getattr(options, "no_terraform_download", False):
        effective_auto_download = False
    if env_truthy(os.getenv("VSCAN_OFFLINE")) or env_truthy(os.getenv("VSCAN_TERRAFORM_STUB")):
        effective_auto_download = False

    legacy._safe_print(
        "[VectorScan] Ensuring Terraform CLI for module tests...",
        stream=sys.stderr,
    )
    try:
        report = entrypoint_shim.run_terraform_tests(override_bin, effective_auto_download)
    except (TerraformManagerError, TerraformDownloadError) as exc:
        return (
            {
                "status": "ERROR",
                "message": str(exc),
                "stdout": "",
                "stderr": str(exc),
            },
            "FAIL",
            effective_auto_download,
        )
    except Exception as exc:  # pragma: no cover - defensive guard
        return (
            {
                "status": "ERROR",
                "message": str(exc),
                "stdout": "",
                "stderr": str(exc),
            },
            "FAIL",
            effective_auto_download,
        )

    status_token = "SKIP"
    version = "?"
    source = "?"
    if isinstance(report, dict):
        status_token = str(report.get("status", "SKIP"))
        version = report.get("version", "?")
        source = report.get("source", "?")
    legacy._safe_print(
        f"[VectorScan] Terraform test status: {status_token.upper()} (CLI {version}, source={source})",
        stream=sys.stderr,
    )

    if not isinstance(report, dict):
        return (
            {
                "status": "SKIP",
                "message": "Terraform tests returned no details",
                "stdout": "",
                "stderr": "",
            },
            "SKIP",
            effective_auto_download,
        )

    if "auto_download" in report:
        effective_auto_download = bool(report["auto_download"])
    else:
        report["auto_download"] = effective_auto_download

    return report, _normalize_outcome(status_token), effective_auto_download


def _bundled_terraform_binary() -> Optional[str]:  # Legacy helper retained for completeness
    if _DEFAULT_TERRAFORM_BIN.exists():
        return str(_DEFAULT_TERRAFORM_BIN)
    return None

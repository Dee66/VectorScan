"""Preview manifest loader and verifier."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class PreviewManifestError(Exception):
    """Raised when the preview manifest cannot be loaded or verified."""


def _default_manifest_path() -> Path:
    root = Path(__file__).resolve().parent
    return root / "preview_manifest.json"


def _canonicalize(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _determine_manifest_path(path: Optional[os.PathLike[str] | str]) -> Path:
    if path is not None:
        return Path(path)
    override = os.getenv("VSCAN_PREVIEW_MANIFEST")
    if override:
        return Path(override)
    return _default_manifest_path()


def load_preview_manifest(path: Optional[os.PathLike[str] | str] = None) -> Dict[str, Any]:
    """Load and validate the preview manifest file."""

    manifest_path = _determine_manifest_path(path)
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:  # pragma: no cover - exercised via CLI tests
        raise PreviewManifestError(f"Preview manifest not found: {manifest_path}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PreviewManifestError(f"Preview manifest is invalid JSON: {manifest_path}: {exc}") from exc

    policies = data.get("policies")
    if not isinstance(policies, list) or not policies:
        raise PreviewManifestError("Preview manifest must include a non-empty 'policies' array.")
    normalized_policies = []
    for idx, policy in enumerate(policies):
        if not isinstance(policy, dict):
            raise PreviewManifestError(f"Preview manifest policy #{idx + 1} must be an object.")
        policy_id = policy.get("id")
        summary = policy.get("summary")
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise PreviewManifestError(f"Preview manifest policy #{idx + 1} missing 'id'.")
        if not isinstance(summary, str) or not summary.strip():
            raise PreviewManifestError(f"Preview manifest policy #{idx + 1} missing 'summary'.")
        normalized_policies.append({"id": policy_id.strip(), "summary": summary.strip()})

    signature = data.get("signature")
    skip_verify = os.getenv("VSCAN_PREVIEW_SKIP_VERIFY")
    canonical = _canonicalize(normalized_policies)
    expected_signature = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    if not isinstance(signature, str) or not signature:
        raise PreviewManifestError("Preview manifest missing signature field.")
    verified = signature == expected_signature
    if not verified and not skip_verify:
        raise PreviewManifestError(
            "Preview manifest signature mismatch. Set VSCAN_PREVIEW_SKIP_VERIFY=1 to bypass in dev."
        )

    return {
        "path": str(manifest_path),
        "version": data.get("version", "unknown"),
        "generated_at": data.get("generated_at"),
        "policies": normalized_policies,
        "signature": signature,
        "verified": bool(verified or skip_verify),
    }


__all__ = ["load_preview_manifest", "PreviewManifestError"]

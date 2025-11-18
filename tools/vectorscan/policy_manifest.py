"""Policy manifest helpers for VectorScan."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Sequence

from tools.vectorscan.policies.base_policy import PolicyMetadata
from tools.vectorscan.versioning import POLICY_VERSION

_DEFAULT_POLICY_SOURCE_URL = os.getenv(
    "VSCAN_POLICY_SOURCE_URL",
    "https://github.com/Dee66/VectorScan/tree/main/tools/vectorscan/policies",
)


class PolicyManifestError(RuntimeError):
    """Raised when policy manifest metadata cannot be loaded or verified."""


def _canonicalize(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _normalize_policies(entries: Sequence[PolicyMetadata]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for meta in entries:
        item: dict[str, Any] = {
            "id": meta.policy_id,
            "name": meta.name,
            "severity": meta.severity,
            "category": meta.category,
        }
        if meta.description:
            item["description"] = meta.description
        normalized.append(item)
    normalized.sort(key=lambda entry: entry["id"])  # deterministic ordering
    return normalized


def _canonical_payload(
    *,
    policy_pack_hash_value: str,
    policy_source_url: str,
    metadata: Sequence[PolicyMetadata],
) -> dict[str, Any]:
    entries = _normalize_policies(metadata)
    payload = {
        "policy_version": POLICY_VERSION,
        "policy_pack_hash": policy_pack_hash_value,
        "policy_source_url": policy_source_url,
        "policy_count": len(entries),
        "policies": entries,
    }
    return payload


def build_policy_manifest(
    metadata: Sequence[PolicyMetadata],
    *,
    policy_pack_hash_value: str,
    source_url: str | None = None,
    path: str | None = None,
) -> Dict[str, Any]:
    """Build a deterministic manifest describing the active policy pack."""

    policy_source_url = source_url or _DEFAULT_POLICY_SOURCE_URL
    payload = _canonical_payload(
        policy_pack_hash_value=policy_pack_hash_value,
        policy_source_url=policy_source_url,
        metadata=metadata,
    )
    signature = hashlib.sha256(_canonicalize(payload)).hexdigest()
    manifest = dict(payload)
    manifest["signature"] = f"sha256:{signature}"
    manifest["signed"] = True
    manifest["verified"] = True
    manifest["path"] = path or "embedded"
    return manifest


def _validate_policies_block(policies_value: Any) -> list[dict[str, Any]]:
    if policies_value is None:
        return []
    if not isinstance(policies_value, list):
        raise PolicyManifestError("Policy manifest 'policies' field must be a list when provided.")
    policies: list[dict[str, Any]] = []
    for idx, raw in enumerate(policies_value):
        if not isinstance(raw, dict):
            raise PolicyManifestError(f"Policy manifest policy #{idx + 1} must be an object.")
        policy_id = raw.get("id")
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise PolicyManifestError(f"Policy manifest policy #{idx + 1} missing 'id'.")
        entry = dict(raw)
        entry["id"] = policy_id.strip()
        policies.append(entry)
    policies.sort(key=lambda entry: entry["id"])
    return policies


def _canonicalize_loaded_payload(data: dict[str, Any]) -> dict[str, Any]:
    policies = _validate_policies_block(data.get("policies"))
    payload = {
        "policy_version": data.get("policy_version"),
        "policy_pack_hash": data.get("policy_pack_hash"),
        "policy_source_url": data.get("policy_source_url"),
        "policy_count": data.get("policy_count", len(policies)),
        "policies": policies,
    }
    return payload


def load_policy_manifest(path: os.PathLike[str] | str) -> Dict[str, Any]:
    """Load a JSON policy manifest from disk and perform basic validation."""

    manifest_path = Path(path)
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:  # pragma: no cover - exercised via CLI tests
        raise PolicyManifestError(f"Policy manifest not found: {manifest_path}") from exc
    except OSError as exc:  # pragma: no cover - unexpected I/O errors
        raise PolicyManifestError(
            f"Unable to read policy manifest: {manifest_path}: {exc}"
        ) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyManifestError(
            f"Policy manifest is invalid JSON: {manifest_path}: {exc}"
        ) from exc

    required_fields = ("policy_version", "policy_pack_hash", "policy_source_url", "signature")
    for field in required_fields:
        value = data.get(field)
        if not isinstance(value, str) or not value.strip():
            raise PolicyManifestError(f"Policy manifest missing required field '{field}'.")

    payload = dict(data)
    policies = _validate_policies_block(payload.get("policies"))
    payload["policies"] = policies
    payload.setdefault("policy_count", len(policies))

    canonical = _canonicalize_loaded_payload(payload)
    computed_signature = f"sha256:{hashlib.sha256(_canonicalize(canonical)).hexdigest()}"
    payload["verified"] = payload.get("signature") == computed_signature
    payload["signed"] = bool(payload.get("signature"))
    payload["path"] = str(manifest_path)
    return payload


__all__ = [
    "PolicyManifestError",
    "build_policy_manifest",
    "load_policy_manifest",
]

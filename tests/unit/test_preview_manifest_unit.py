import hashlib
import json
from pathlib import Path

import pytest

from tools.vectorscan.preview import PreviewManifestError, load_preview_manifest


def _write_manifest(tmp_path: Path, *, signature: str | None = None) -> Path:
    policies = [{"id": "P-SEC-002", "summary": "Zero Trust policy"}]
    canonical = json.dumps(policies, sort_keys=True, separators=(",", ":")).encode()
    sig = signature or f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    payload = {
        "version": "test",
        "generated_at": "2025-11-17T00:00:00Z",
        "policies": policies,
        "signature": sig,
    }
    manifest_path = tmp_path / "preview.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    return manifest_path


def test_load_preview_manifest_success(tmp_path, monkeypatch):
    manifest = _write_manifest(tmp_path)
    monkeypatch.setenv("VSCAN_PREVIEW_MANIFEST", str(manifest))
    data = load_preview_manifest()
    assert data["verified"] is True
    assert data["policies"][0]["id"] == "P-SEC-002"


def test_load_preview_manifest_signature_mismatch(tmp_path, monkeypatch):
    manifest = _write_manifest(tmp_path, signature="sha256:deadbeef")
    monkeypatch.setenv("VSCAN_PREVIEW_MANIFEST", str(manifest))
    with pytest.raises(PreviewManifestError):
        load_preview_manifest()


def test_skip_verify_allows_custom_manifest(tmp_path, monkeypatch):
    manifest = _write_manifest(tmp_path, signature="sha256:deadbeef")
    monkeypatch.setenv("VSCAN_PREVIEW_MANIFEST", str(manifest))
    monkeypatch.setenv("VSCAN_PREVIEW_SKIP_VERIFY", "1")
    data = load_preview_manifest()
    assert data["verified"] is True

#!/usr/bin/env python3
"""
Build vectorscan-free.zip containing the VectorScan CLI and free policies.

Contents:
- tools/vectorscan/vectorscan.py
- tools/vectorscan/README.md
- tools/vectorscan/free_policies.rego
- LICENSE_FREE.txt (snippet referencing main license)

Usage:
  python3 tools/vectorscan/build_vectorscan_package.py
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List

from tools.vectorscan.policies import get_policies
from tools.vectorscan.policy_manifest import build_policy_manifest
from tools.vectorscan.policy_pack import policy_pack_hash
from tools.vectorscan.preview import PreviewManifestError, load_preview_manifest
from tools.vectorscan.time_utils import deterministic_epoch
from tools.vectorscan.versioning import (
    OUTPUT_SCHEMA_VERSION,
    POLICY_VERSION,
    VECTORSCAN_VERSION,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "tools" / "vectorscan"
DIST = REPO_ROOT / "dist"
REQUIREMENT_FILES = [REPO_ROOT / "requirements.txt", REPO_ROOT / "requirements-dev.txt"]

PACKAGE_EXCLUDE_DIRS = {
    "captures",
    "__pycache__",
    ".terraform",
    ".terraform-bin",
    ".venv",
    ".cache",
}
PACKAGE_EXCLUDE_FILES = {"build_vectorscan_package.py"}

PROHIBITED_ARCNAME_PARTS = {"__MACOSX"}
PROHIBITED_FILENAMES = {".DS_Store"}
SENSITIVE_DIR_NAMES = {"__pycache__", ".terraform", ".venv", ".cache"}
SENSITIVE_FILENAMES = {".env", ".envrc", "id_rsa", "id_dsa"}
SENSITIVE_SUFFIXES = {".env", ".pem", ".key", ".crt", ".pfx", ".p12"}
TEXT_FILE_EXTENSIONS = {
    ".py",
    ".md",
    ".rego",
    ".txt",
    ".json",
    ".sh",
    ".yaml",
    ".yml",
    ".cfg",
    ".ini",
    ".tf",
    ".tfvars",
}


def _collect_cli_package_files() -> List[Path]:
    candidates: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(SRC):
        rel_dir = Path(dirpath).relative_to(SRC)
        if any(part in PACKAGE_EXCLUDE_DIRS for part in rel_dir.parts):
            continue
        dirnames[:] = sorted(d for d in dirnames if d not in PACKAGE_EXCLUDE_DIRS)
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            try:
                rel_parts = path.relative_to(SRC).parts
            except ValueError:
                continue
            if any(part in PACKAGE_EXCLUDE_DIRS for part in rel_parts[:-1]):
                continue
            if filename in PACKAGE_EXCLUDE_FILES:
                continue
            suffix = path.suffix.lower()
            if not suffix or suffix not in TEXT_FILE_EXTENSIONS:
                continue
            candidates.append(path)
    candidates.sort(key=lambda p: p.relative_to(REPO_ROOT).as_posix())
    return candidates


FILES = _collect_cli_package_files()

LICENSE_TEXT = (
    "VectorScan Free Utility\n\n"
    "This archive includes the VectorScan CLI and minimal policies for two checks.\n"
    "See the main LICENSE in the repository root for full terms.\n"
)

SIGNER_DOCUMENTATION_URL = "docs/release-distribution.md#verifying-downloads"


def _signer_metadata(bundle_name: str) -> List[Dict[str, str]]:
    base = f"{bundle_name}.zip"
    return [
        {
            "tool": "cosign",
            "oidc_issuer": "https://token.actions.githubusercontent.com",
            "identity": "GitHub Actions (Dee66/VectorScan workflows)",
            "identity_regexp": ".*",
            "signature": f"{base}.sig",
            "certificate": f"{base}.crt",
            "verification_hint": (
                "cosign verify-blob --certificate {cert} --signature {sig} "
                "--certificate-identity-regexp '.*' --certificate-oidc-issuer "
                "https://token.actions.githubusercontent.com {bundle}"
            ).format(cert=f"{base}.crt", sig=f"{base}.sig", bundle=base),
            "documentation": SIGNER_DOCUMENTATION_URL,
        }
    ]


DEFAULT_BUNDLE_VERSION = os.getenv("VSCAN_BUNDLE_VERSION", "dev")
SPECIFIERS = ["==", "!=", ">=", "<=", "~=", ">", "<"]
MIN_DOS_TIME = datetime(1980, 1, 1, tzinfo=timezone.utc)
MIN_DOS_TIMESTAMP = int(MIN_DOS_TIME.timestamp())

if "SOURCE_DATE_EPOCH" not in os.environ:
    os.environ["SOURCE_DATE_EPOCH"] = "0"


def write_sha256(p: Path) -> None:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    out = p.with_suffix(p.suffix + ".sha256")
    out.write_text(f"{h.hexdigest()}  {p.name}\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the VectorScan free bundle with bundled Terraform binary"
    )
    parser.add_argument(
        "--bundle-name",
        default="vectorscan-free",
        help="Base file name (without extension) for the generated zip",
    )
    parser.add_argument(
        "--bundle-version",
        default=DEFAULT_BUNDLE_VERSION,
        help="Version string to record in manifest metadata",
    )
    # Use parse_known_args so pytest runner flags (e.g., -q) don't cause failures when tests import and call main().
    if argv is None:
        argv = sys.argv[1:]
    args, _extra = parser.parse_known_args(argv)
    return args


def load_vectorscan_module():
    target = SRC / "vectorscan.py"
    if not target.exists():
        return None
    spec = importlib.util.spec_from_file_location("vectorscan_packaging", target)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load vectorscan module for packaging")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def ensure_terraform_binary(module, bundle_name: str) -> Path:
    # Determine required version based on bundle naming convention
    required_version = module.REQUIRED_TERRAFORM_VERSION
    if bundle_name.lower().endswith("-legacy"):
        required_version = "1.6.0"

    manager = module.TerraformManager(
        required_version=required_version,
        download_dir=module.DEFAULT_TERRAFORM_CACHE,
        auto_download=True,
    )

    resolution = manager.ensure()
    if resolution.source != "download":
        downloaded = manager._download()
        resolution = manager._resolution_for(downloaded, source="download")
        if resolution is None:
            raise RuntimeError("Failed to resolve downloaded Terraform binary")

    return resolution.path


def ensure_safe_arcname(src: Path) -> str:
    try:
        relative = src.relative_to(REPO_ROOT)
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise RuntimeError(f"File {src} must live inside the repository root") from exc

    posix = PurePosixPath(relative.as_posix())
    for part in posix.parts:
        if part in PROHIBITED_ARCNAME_PARTS or part in PROHIBITED_FILENAMES:
            raise RuntimeError(f"Refusing to package hidden artifact '{posix}'")
        if part in SENSITIVE_DIR_NAMES:
            raise RuntimeError(f"Refusing to package sensitive directory '{posix}'")
    filename = posix.name
    if filename in PROHIBITED_FILENAMES or filename.startswith("._"):
        raise RuntimeError(f"Refusing to package hidden artifact '{filename}'")
    if filename in SENSITIVE_FILENAMES or filename.lower().startswith(".env"):
        raise RuntimeError(f"Refusing to package sensitive file '{filename}'")
    if posix.suffix.lower() in SENSITIVE_SUFFIXES:
        raise RuntimeError(f"Refusing to package sensitive file '{filename}' (suffix disallowed)")
    return posix.as_posix()


def _file_entry_for_path(src: Path, arcname: str) -> Dict[str, Any]:
    h = hashlib.sha256()
    size = 0
    with src.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            if not chunk:
                break
            size += len(chunk)
            h.update(chunk)
    return {"path": arcname, "size": size, "sha256": h.hexdigest()}


def _file_entry_for_bytes(name: str, data: bytes) -> Dict[str, Any]:
    return {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _deterministic_timestamp() -> str:
    epoch = max(deterministic_epoch(), MIN_DOS_TIMESTAMP)
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _zip_date_time() -> tuple[int, int, int, int, int, int]:
    return (
        MIN_DOS_TIME.year,
        MIN_DOS_TIME.month,
        MIN_DOS_TIME.day,
        0,
        0,
        0,
    )


def _policy_manifest_summary() -> Dict[str, Any]:
    policies = get_policies()
    metadata_entries = [policy.metadata for policy in policies]
    if not metadata_entries:
        raise RuntimeError("No policies registered for manifest generation")
    return build_policy_manifest(
        metadata_entries, policy_pack_hash_value=policy_pack_hash(), path="embedded"
    )


def _preview_manifest_summary() -> Dict[str, Any]:
    manifest_path = SRC / "preview_manifest.json"
    if not manifest_path.exists():
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        placeholder: Dict[str, Any] = {
            "version": "dev",
            "generated_at": "1970-01-01T00:00:00Z",
            "policies": [
                {"id": "P-PLACEHOLDER", "summary": "Placeholder preview manifest"},
            ],
        }
        canonical = json.dumps(
            placeholder["policies"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        placeholder["signature"] = f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        placeholder["verified"] = True
        manifest_path.write_text(
            json.dumps(placeholder, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    try:
        manifest = load_preview_manifest(manifest_path)
    except PreviewManifestError as exc:  # pragma: no cover - validation should always succeed
        raise RuntimeError(f"Failed to validate preview manifest: {exc}") from exc
    sha_value = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return {
        "path": ensure_safe_arcname(manifest_path),
        "sha256": sha_value,
        "signature": manifest.get("signature"),
        "version": manifest.get("version"),
        "generated_at": manifest.get("generated_at"),
        "policy_count": len(manifest.get("policies") or []),
        "verified": manifest.get("verified", False),
        "policies": manifest.get("policies", []),
    }


def _build_manifest(
    bundle_name: str,
    bundle_version: str,
    files: List[Dict[str, Any]],
    *,
    policy_manifest: Dict[str, Any],
    preview_manifest: Dict[str, Any],
    signers: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "bundle_name": bundle_name,
        "bundle_version": bundle_version,
        "generated_at": _deterministic_timestamp(),
        "vectorscan_version": VECTORSCAN_VERSION,
        "policy_version": POLICY_VERSION,
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "policy_pack_hash": policy_pack_hash(),
        "file_count": len(files),
        "files": files,
        "policy_manifest": policy_manifest,
        "preview_manifest": preview_manifest,
        "signers": signers,
    }


def _normalize_newlines(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_FILE_EXTENSIONS


def _parse_requirement_line(line: str) -> Dict[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("-") and not stripped.lower().startswith("-r"):
        return None
    base = stripped.split("#", 1)[0].strip()
    if not base:
        return None
    for token in SPECIFIERS:
        if token in base:
            name, remainder = base.split(token, 1)
            return {
                "name": name.strip(),
                "version": remainder.strip(),
                "constraint": f"{token}{remainder.strip()}",
                "specifier": token,
                "raw": base,
            }
    return {
        "name": base.strip(),
        "version": "unspecified",
        "constraint": "",
        "specifier": "",
        "raw": base,
    }


def _resolve_include_path(line: str, current_file: Path) -> Path | None:
    if not line.lower().startswith("-r"):
        return None
    remainder = line[2:].strip()
    if not remainder:
        parts = line.split(None, 1)
        if len(parts) == 2:
            remainder = parts[1].strip()
    if not remainder:
        return None
    return (current_file.parent / remainder).resolve()


def _collect_requirement_entries(files: Iterable[Path]) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    visited: set[Path] = set()
    dedup: set[tuple[str, str]] = set()

    def _parse_file(path: Path) -> None:
        real = path.resolve()
        if real in visited or not real.exists():
            return
        visited.add(real)
        try:
            rel_source = str(real.relative_to(REPO_ROOT))
        except ValueError:
            rel_source = str(real)
        for raw_line in real.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            include = _resolve_include_path(line, real)
            if include is not None:
                _parse_file(include)
                continue
            parsed = _parse_requirement_line(line)
            if not parsed:
                continue
            key = (parsed["name"], parsed.get("constraint", ""))
            if key in dedup:
                continue
            parsed["source"] = rel_source
            entries.append(parsed)
            dedup.add(key)

    for candidate in files:
        if candidate.exists():
            _parse_file(candidate)

    return entries


def _build_sbom(
    bundle_name: str, bundle_version: str, components: List[Dict[str, str]]
) -> Dict[str, Any]:
    timestamp = _deterministic_timestamp()
    sbom_components: List[Dict[str, Any]] = []
    for comp in components:
        version_value = comp.get("version") or "unspecified"
        entry: Dict[str, Any] = {
            "type": "library",
            "name": comp["name"],
            "version": version_value,
        }
        props = [
            {"name": "cdx:lockfile", "value": comp.get("source", "requirements.txt")},
            {"name": "cdx:requirement", "value": comp.get("raw", comp["name"])},
        ]
        constraint = comp.get("constraint")
        if constraint:
            props.append({"name": "cdx:constraint", "value": constraint})
        specifier = comp.get("specifier")
        if specifier:
            props.append({"name": "cdx:specifier", "value": specifier})
        entry["properties"] = props
        version = comp.get("version")
        if version and version.lower() != "unspecified":
            entry["purl"] = f"pkg:pypi/{comp['name']}@{version}"
        sbom_components.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "name": bundle_name,
                "version": bundle_version,
            },
        },
        "components": sbom_components,
    }


def _zipinfo_for_arcname(arcname: str, mode: int | None = None) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(arcname)
    zi.date_time = _zip_date_time()
    zi.compress_type = zipfile.ZIP_DEFLATED
    perms = mode if mode is not None else 0o644
    zi.external_attr = (perms & 0o777) << 16
    return zi


def _write_path_with_fixed_metadata(z: zipfile.ZipFile, src: Path, arcname: str) -> None:
    zi = _zipinfo_for_arcname(arcname, src.stat().st_mode)
    with src.open("rb") as reader, z.open(zi, "w") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 64)


def _write_bytes_with_fixed_metadata(
    z: zipfile.ZipFile, arcname: str, data: bytes, mode: int | None = 0o644
) -> None:
    zi = _zipinfo_for_arcname(arcname, mode)
    z.writestr(zi, data)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    bundle_name = args.bundle_name
    bundle_version = args.bundle_version
    policy_manifest_data = _policy_manifest_summary()
    preview_manifest_data = _preview_manifest_summary()
    signer_data = _signer_metadata(bundle_name)

    module = load_vectorscan_module()
    terraform_path: Path | None = None
    if module is not None:
        try:
            terraform_path = ensure_terraform_binary(module, bundle_name)
        except Exception as exc:
            print(f"Warning: skipping Terraform bundling ({exc})")

    dependencies = _collect_requirement_entries(REQUIREMENT_FILES)
    sbom_payload = (
        json.dumps(_build_sbom(bundle_name, bundle_version, dependencies), indent=2, sort_keys=True)
        + "\n"
    )
    sbom_bytes = sbom_payload.encode("utf-8")

    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / f"{bundle_name}.zip"
    manifest_entries: List[Dict[str, Any]] = []
    manifest_payload = ""
    try:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
            bundled_files: List[Path] = list(FILES)
            if terraform_path is not None:
                bundled_files.append(terraform_path)
            for f in bundled_files:
                if not f.exists():
                    print(f"Warning: missing file {f}")
                    continue
                arcname = ensure_safe_arcname(f)
                if _is_text_file(f):
                    normalized = _normalize_newlines(f.read_bytes())
                    manifest_entries.append(_file_entry_for_bytes(arcname, normalized))
                    _write_bytes_with_fixed_metadata(z, arcname, normalized, mode=f.stat().st_mode)
                else:
                    manifest_entries.append(_file_entry_for_path(f, arcname))
                    _write_path_with_fixed_metadata(z, f, arcname)
            license_bytes = LICENSE_TEXT.encode("utf-8")
            _write_bytes_with_fixed_metadata(z, "LICENSE_FREE.txt", license_bytes)
            manifest_entries.append(_file_entry_for_bytes("LICENSE_FREE.txt", license_bytes))
            _write_bytes_with_fixed_metadata(z, "sbom.json", sbom_bytes)
            manifest_entries.append(_file_entry_for_bytes("sbom.json", sbom_bytes))
            manifest = _build_manifest(
                bundle_name,
                bundle_version,
                manifest_entries,
                policy_manifest=policy_manifest_data,
                preview_manifest=preview_manifest_data,
                signers=signer_data,
            )
            manifest_payload = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            manifest_bytes = manifest_payload.encode("utf-8")
            _write_bytes_with_fixed_metadata(z, "manifest.json", manifest_bytes)
    except RuntimeError as exc:
        if out.exists():
            out.unlink(missing_ok=True)
        print(f"Error: {exc}")
        return 2

    manifest_path = DIST / f"{bundle_name}.manifest.json"
    manifest_path.write_text(manifest_payload, encoding="utf-8")
    sbom_path = DIST / f"{bundle_name}.sbom.json"
    sbom_path.write_text(sbom_payload, encoding="utf-8")

    write_sha256(out)
    write_sha256(manifest_path)
    write_sha256(sbom_path)
    print(f"Wrote {out} and checksum")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

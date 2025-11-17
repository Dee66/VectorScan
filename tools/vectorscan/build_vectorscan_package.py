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
import json
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import hashlib
import importlib.util
import sys
from typing import List, Dict, Any, Iterable

from tools.vectorscan.time_utils import deterministic_epoch
from tools.vectorscan.versioning import (
    VECTORSCAN_VERSION,
    POLICY_VERSION,
    OUTPUT_SCHEMA_VERSION,
)
from tools.vectorscan.policy_pack import policy_pack_hash

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "tools" / "vectorscan"
DIST = REPO_ROOT / "dist"
REQUIREMENT_FILES = [REPO_ROOT / "requirements.txt", REPO_ROOT / "requirements-dev.txt"]

FILES = [
    SRC / "vectorscan.py",
    SRC / "time_utils.py",
    SRC / "README.md",
    SRC / "free_policies.rego",
]

LICENSE_TEXT = (
    "VectorScan Free Utility\n\n"
    "This archive includes the VectorScan CLI and minimal policies for two checks.\n"
    "See the main LICENSE in the repository root for full terms.\n"
)

PROHIBITED_ARCNAME_PARTS = {"__MACOSX"}
PROHIBITED_FILENAMES = {".DS_Store"}
SENSITIVE_DIR_NAMES = {"__pycache__", ".terraform", ".venv", ".cache"}
SENSITIVE_FILENAMES = {".env", ".envrc", "id_rsa", "id_dsa"}
SENSITIVE_SUFFIXES = {".env", ".pem", ".key", ".crt", ".pfx", ".p12"}
TEXT_FILE_EXTENSIONS = {".py", ".md", ".rego", ".txt", ".json", ".sh", ".yaml", ".yml", ".cfg", ".ini", ".tf", ".tfvars"}
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
    parser = argparse.ArgumentParser(description="Build the VectorScan free bundle with bundled Terraform binary")
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
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
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
    dt = datetime.fromtimestamp(max(deterministic_epoch(), MIN_DOS_TIMESTAMP), tz=timezone.utc)
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def _build_manifest(bundle_name: str, bundle_version: str, files: List[Dict[str, Any]]) -> Dict[str, Any]:
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


def _build_sbom(bundle_name: str, bundle_version: str, components: List[Dict[str, str]]) -> Dict[str, Any]:
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
            {"name": "cdx:requirement", "value": comp.get("raw", comp["name"])}
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


def _write_bytes_with_fixed_metadata(z: zipfile.ZipFile, arcname: str, data: bytes, mode: int | None = 0o644) -> None:
    zi = _zipinfo_for_arcname(arcname, mode)
    z.writestr(zi, data)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    bundle_name = args.bundle_name
    bundle_version = args.bundle_version

    module = load_vectorscan_module()
    terraform_path: Path | None = None
    if module is not None:
        try:
            terraform_path = ensure_terraform_binary(module, bundle_name)
        except Exception as exc:
            print(f"Warning: skipping Terraform bundling ({exc})")

    dependencies = _collect_requirement_entries(REQUIREMENT_FILES)
    sbom_payload = json.dumps(_build_sbom(bundle_name, bundle_version, dependencies), indent=2, sort_keys=True) + "\n"
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
            manifest = _build_manifest(bundle_name, bundle_version, manifest_entries)
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

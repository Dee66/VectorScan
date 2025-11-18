#!/usr/bin/env python3
"""Validate VectorScan release bundles against their manifest metadata."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, Tuple

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_MANIFEST_ERROR = 3
EXIT_MISMATCH = 4
MANIFEST_NAME = "manifest.json"

Manifest = Dict[str, Any]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate VectorScan bundles using the embedded manifest"
    )
    parser.add_argument(
        "--bundle", required=True, type=Path, help="Path to the VectorScan bundle zip"
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Optional path to a trusted manifest copy; will be compared to the embedded manifest",
    )
    parser.add_argument(
        "--strict-file-count",
        action="store_true",
        help="Fail when manifest file_count differs from the number of manifest entries",
    )
    return parser.parse_args(argv)


def _read_manifest_from_zip(bundle: Path) -> tuple[str, Manifest]:
    try:
        with zipfile.ZipFile(bundle) as zf:
            try:
                manifest_bytes = zf.read(MANIFEST_NAME)
            except KeyError as exc:
                raise FileNotFoundError(
                    f"bundle integrity: missing {MANIFEST_NAME} in {bundle}"
                ) from exc
    except zipfile.BadZipFile as exc:
        raise ValueError(f"bundle integrity: not a valid zip archive: {bundle}") from exc

    try:
        data = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("bundle integrity: manifest is not valid UTF-8") from exc

    try:
        manifest = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"bundle integrity: manifest JSON is invalid: {exc}") from exc
    return data, manifest


def _load_manifest(bundle: Path, override: Path | None) -> Manifest:
    embedded_text, embedded_manifest = _read_manifest_from_zip(bundle)
    if override is None:
        return embedded_manifest

    if not override.exists():
        raise FileNotFoundError(f"bundle integrity: external manifest not found: {override}")

    override_text = override.read_text(encoding="utf-8")
    if override_text != embedded_text:
        raise ValueError("bundle integrity: embedded manifest does not match provided manifest")

    try:
        return json.loads(override_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"bundle integrity: external manifest JSON invalid: {exc}") from exc


def _validate_manifest_structure(manifest: Manifest, strict_file_count: bool) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("bundle integrity: manifest is not an object")
    for key in ("bundle_name", "file_count", "files"):
        if key not in manifest:
            raise ValueError(f"bundle integrity: manifest missing '{key}'")
    if not isinstance(manifest.get("file_count"), int):
        raise ValueError("bundle integrity: manifest 'file_count' must be an integer")
    files = manifest["files"]
    if not isinstance(files, list):
        raise ValueError("bundle integrity: manifest 'files' must be a list")
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("bundle integrity: manifest file entry is not an object")
        for field in ("path", "sha256", "size"):
            if field not in entry:
                raise ValueError(f"bundle integrity: manifest entry missing '{field}'")
        if not isinstance(entry.get("path"), str):
            raise ValueError("bundle integrity: manifest entry 'path' must be a string")
        if not isinstance(entry.get("sha256"), str):
            raise ValueError("bundle integrity: manifest entry 'sha256' must be a string")
        if not isinstance(entry.get("size"), int):
            raise ValueError("bundle integrity: manifest entry 'size' must be an integer")
    if strict_file_count and manifest.get("file_count") != len(files):
        raise ValueError(
            f"bundle integrity: manifest file_count ({manifest.get('file_count')}) does not match number of entries ({len(files)})"
        )


def _validate_metadata_consistency(manifest: Manifest) -> None:
    preview_meta = manifest.get("preview_manifest")
    if not isinstance(preview_meta, dict):
        raise ValueError("bundle integrity: preview_manifest metadata missing")
    preview_path = preview_meta.get("path")
    preview_sha = preview_meta.get("sha256")
    if not preview_path or not preview_sha:
        raise ValueError("bundle integrity: preview_manifest metadata missing path/sha256")
    file_lookup = {entry["path"]: entry for entry in manifest["files"]}
    preview_entry = file_lookup.get(preview_path)
    if preview_entry is None:
        raise ValueError("bundle integrity: preview_manifest path not listed in files block")
    if preview_entry.get("sha256") != preview_sha:
        raise ValueError("bundle integrity: preview_manifest sha256 mismatch with files block")

    policy_meta = manifest.get("policy_manifest")
    if not isinstance(policy_meta, dict):
        raise ValueError("bundle integrity: policy_manifest metadata missing")
    if policy_meta.get("policy_pack_hash") != manifest.get("policy_pack_hash"):
        raise ValueError("bundle integrity: policy_manifest policy_pack_hash mismatch")
    if not isinstance(policy_meta.get("signature"), str):
        raise ValueError("bundle integrity: policy_manifest signature missing")

    signers = manifest.get("signers")
    if not isinstance(signers, list) or not signers:
        raise ValueError("bundle integrity: signers metadata missing")


def _hash_bytes(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def _verify_entry(zf: zipfile.ZipFile, entry: Dict[str, Any]) -> Tuple[bool, str]:
    target = entry["path"]
    try:
        data = zf.read(target)
    except KeyError:
        return False, f"bundle integrity: missing file '{target}'"

    actual_sha = _hash_bytes(data)
    if actual_sha != entry["sha256"]:
        return False, (
            "bundle integrity: sha256 mismatch for '{target}'\n"
            f" expected: {entry['sha256']}\n"
            f"   actual: {actual_sha}"
        )

    actual_size = len(data)
    if actual_size != entry["size"]:
        return False, (
            f"bundle integrity: size mismatch for '{target}'\n"
            f" expected: {entry['size']} bytes\n"
            f"   actual: {actual_size} bytes"
        )

    return True, ""


def _verify_bundle(bundle: Path, manifest: Manifest) -> Tuple[bool, str]:
    try:
        zf = zipfile.ZipFile(bundle)
    except zipfile.BadZipFile as exc:
        return False, f"bundle integrity: invalid zip archive: {bundle} ({exc})"

    with zf:
        seen_manifest_paths: set[str] = set()
        for entry in manifest["files"]:
            target = entry["path"]
            if target in seen_manifest_paths:
                return False, f"bundle integrity: duplicate manifest entry for '{target}'"
            seen_manifest_paths.add(target)
            ok, message = _verify_entry(zf, entry)
            if not ok:
                return False, message

        actual_files = {
            info.filename
            for info in zf.infolist()
            if not info.is_dir() and info.filename != MANIFEST_NAME
        }
        missing_from_manifest = actual_files.difference(seen_manifest_paths)
        if missing_from_manifest:
            extras = ", ".join(sorted(missing_from_manifest)[:5])
            return False, f"bundle integrity: files not listed in manifest: {extras}"

        expected_count = manifest.get("file_count")
        if isinstance(expected_count, int) and expected_count != len(seen_manifest_paths):
            return False, (
                f"bundle integrity: manifest file_count ({expected_count}) does not match actual entries ({len(seen_manifest_paths)})"
            )
    return True, "bundle integrity: manifest matches all bundle entries"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    bundle = args.bundle.resolve()
    if not bundle.exists():
        print(f"bundle integrity: bundle not found: {bundle}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    manifest_override = args.manifest.resolve() if args.manifest else None

    try:
        manifest = _load_manifest(bundle, manifest_override)
        _validate_manifest_structure(manifest, args.strict_file_count)
        _validate_metadata_consistency(manifest)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_MANIFEST_ERROR
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_INPUT

    ok, message = _verify_bundle(bundle, manifest)
    if ok:
        print(message)
        return EXIT_OK

    print(message, file=sys.stderr)
    return EXIT_MISMATCH


if __name__ == "__main__":
    raise SystemExit(main())

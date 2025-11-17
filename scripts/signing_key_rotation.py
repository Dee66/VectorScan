#!/usr/bin/env python3
"""Assist with rotating VectorScan cosign signing keys.

This utility verifies that both the retiring and the newly promoted cosign keys can
successfully validate the current release bundle. Once both signatures verify, the
script appends a JSON entry to the rotation log so we have an auditable history of
key lineage.

The script intentionally depends only on the Python stdlib so it can run anywhere
VectorScan does.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_COSIGN_FAILURE = 3
EXIT_LOG_ERROR = 4

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify old/new cosign keys during rotation and append to the rotation log"
    )
    parser.add_argument("--bundle", required=True, type=Path, help="Path to the signed release bundle")
    parser.add_argument("--bundle-version", required=True, help="Semantic version for the bundle")
    parser.add_argument(
        "--new-key",
        required=True,
        type=Path,
        help="Path to the new (promoted) cosign public key",
    )
    parser.add_argument(
        "--new-signature",
        required=True,
        type=Path,
        help="Path to the signature generated with the new key",
    )
    parser.add_argument(
        "--old-key",
        type=Path,
        help="Path to the previous cosign public key (optional for first-time setup)",
    )
    parser.add_argument(
        "--old-signature",
        type=Path,
        help="Signature generated with the previous key to prove overlap (required if --old-key provided)",
    )
    parser.add_argument(
        "--rotation-log",
        type=Path,
        default=Path("docs") / "signing_key_rotation_log.json",
        help="JSON file recording rotation history (default: docs/signing_key_rotation_log.json)",
    )
    parser.add_argument(
        "--cosign-path",
        type=Path,
        help="Explicit path to the cosign binary (defaults to PATH lookup)",
    )
    parser.add_argument(
        "--note",
        help="Optional free-form note (e.g., ticket ID, operator name) stored in the rotation log",
    )
    return parser.parse_args(argv)


def _require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} not found: {path}")


def _resolve_cosign(explicit: Optional[Path]) -> Path:
    if explicit:
        if explicit.is_file():
            return explicit
        raise FileNotFoundError(f"cosign binary not found: {explicit}")
    discovered = shutil.which("cosign")
    if not discovered:
        raise FileNotFoundError("cosign binary not found in PATH")
    return Path(discovered)


def _run_cosign(
    cosign_path: Path,
    bundle: Path,
    signature: Path,
    key: Path,
    label: str,
) -> bool:
    cmd = [
        str(cosign_path),
        "verify-blob",
        "--key",
        str(key),
        "--signature",
        str(signature),
        str(bundle),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(f"signing-key-rotation: cosign verification failed for {label}\n")
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return False
    print(f"signing-key-rotation: cosign verification OK for {label}")
    return True


def _fingerprint(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_log(path: Path) -> List[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"rotation log is not valid JSON: {path}") from exc
    if not isinstance(data, list):
        raise ValueError("rotation log must contain a JSON list")
    return data


def _write_log(path: Path, entries: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(entries, indent=2, sort_keys=True)
    path.write_text(serialized + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        _require_file(args.bundle, "bundle")
        _require_file(args.new_key, "new key")
        _require_file(args.new_signature, "new signature")
        if args.old_key and not args.old_signature:
            print("signing-key-rotation: provide --old-signature when --old-key is set", file=sys.stderr)
            return EXIT_INVALID_INPUT
        if args.old_signature and not args.old_key:
            print("signing-key-rotation: provide --old-key when --old-signature is set", file=sys.stderr)
            return EXIT_INVALID_INPUT
        if args.old_key:
            _require_file(args.old_key, "old key")
        if args.old_signature:
            _require_file(args.old_signature, "old signature")
        cosign_path = _resolve_cosign(args.cosign_path)
    except FileNotFoundError as exc:
        print(f"signing-key-rotation: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    bundle_sha256 = _sha256(args.bundle)

    if not _run_cosign(cosign_path, args.bundle, args.new_signature, args.new_key, "new key"):
        return EXIT_COSIGN_FAILURE
    if args.old_key and args.old_signature:
        if not _run_cosign(cosign_path, args.bundle, args.old_signature, args.old_key, "old key"):
            return EXIT_COSIGN_FAILURE

    entry = {
        "bundle": str(args.bundle),
        "bundle_sha256": bundle_sha256,
        "bundle_version": args.bundle_version,
        "new_key_fingerprint": _fingerprint(args.new_key),
        "new_signature": str(args.new_signature),
        "old_key_fingerprint": _fingerprint(args.old_key) if args.old_key else None,
        "old_signature": str(args.old_signature) if args.old_signature else None,
        "rotation_note": args.note,
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

    try:
        log_entries = _load_log(args.rotation_log)
        log_entries.append(entry)
        _write_log(args.rotation_log, log_entries)
    except (OSError, ValueError) as exc:
        print(f"signing-key-rotation: failed to update rotation log: {exc}", file=sys.stderr)
        return EXIT_LOG_ERROR

    print(
        "signing-key-rotation: rotation recorded -- "
        f"bundle={args.bundle_version} sha256={bundle_sha256[:12]} "
        f"new_fpr={entry['new_key_fingerprint'][:12]}"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

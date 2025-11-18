#!/usr/bin/env python3
"""Emergency cosign key revocation helper for VectorScan releases."""
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
        description="Verify replacement cosign keys during an emergency revocation and append to the revocation log",
    )
    parser.add_argument(
        "--bundle", required=True, type=Path, help="Path to the newly re-signed release bundle"
    )
    parser.add_argument(
        "--bundle-version", required=True, help="Version string for the bundle (e.g., v1.5.1"
    )
    parser.add_argument(
        "--revoked-key", required=True, type=Path, help="Path to the compromised cosign public key"
    )
    parser.add_argument(
        "--replacement-key",
        required=True,
        type=Path,
        help="Path to the replacement cosign public key",
    )
    parser.add_argument(
        "--replacement-signature",
        required=True,
        type=Path,
        help="Signature file generated with the replacement key",
    )
    parser.add_argument(
        "--revocation-reason",
        required=True,
        help="Short reason describing why the previous key was revoked (ticket/incident id recommended)",
    )
    parser.add_argument(
        "--revocation-log",
        type=Path,
        default=Path("docs") / "signing_key_revocations.json",
        help="JSON file recording revocation events (default: docs/signing_key_revocations.json)",
    )
    parser.add_argument(
        "--cosign-path", type=Path, help="Explicit path to cosign binary (defaults to PATH lookup)"
    )
    parser.add_argument(
        "--note",
        help="Optional free-form note to include in the revocation log (e.g., operator, link to RCA)",
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


def _run_cosign(cosign_path: Path, bundle: Path, signature: Path, key: Path) -> bool:
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
        sys.stderr.write("signing-key-revocation: cosign verification failed for replacement key\n")
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return False
    print("signing-key-revocation: cosign verification OK for replacement key")
    return True


def _fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        raise ValueError(f"revocation log is not valid JSON: {path}") from exc
    if not isinstance(data, list):
        raise ValueError("revocation log must contain a JSON list")
    return data


def _write_log(path: Path, entries: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        _require_file(args.bundle, "bundle")
        _require_file(args.revoked_key, "revoked key")
        _require_file(args.replacement_key, "replacement key")
        _require_file(args.replacement_signature, "replacement signature")
        cosign_path = _resolve_cosign(args.cosign_path)
    except FileNotFoundError as exc:
        print(f"signing-key-revocation: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    bundle_sha = _sha256(args.bundle)

    if not _run_cosign(cosign_path, args.bundle, args.replacement_signature, args.replacement_key):
        return EXIT_COSIGN_FAILURE

    entry = {
        "bundle": str(args.bundle),
        "bundle_sha256": bundle_sha,
        "bundle_version": args.bundle_version,
        "revoked_key": str(args.revoked_key),
        "revoked_key_fingerprint": _fingerprint(args.revoked_key),
        "replacement_key": str(args.replacement_key),
        "replacement_key_fingerprint": _fingerprint(args.replacement_key),
        "replacement_signature": str(args.replacement_signature),
        "revocation_reason": args.revocation_reason,
        "note": args.note,
        "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

    try:
        log_entries = _load_log(args.revocation_log)
        log_entries.append(entry)
        _write_log(args.revocation_log, log_entries)
    except (OSError, ValueError) as exc:
        print(f"signing-key-revocation: failed to update revocation log: {exc}", file=sys.stderr)
        return EXIT_LOG_ERROR

    print(
        "signing-key-revocation: revocation recorded -- "
        f"bundle={args.bundle_version} revoked={entry['revoked_key_fingerprint'][:12]} "
        f"replacement={entry['replacement_key_fingerprint'][:12]}"
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

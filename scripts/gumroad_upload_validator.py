#!/usr/bin/env python3
"""Compare Gumroad-uploaded bundles against the canonical GitHub release artifact.

This helper ensures the Gumroad bundle matches the release artifact byte-for-byte and
optionally verifies the bundle signature with cosign. It uses only the Python stdlib
so it can run anywhere the VectorScan CLI runs.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_MISMATCH = 3
EXIT_COSIGN_FAILURE = 4


def _compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_digest_from_file(path: Optional[Path]) -> Optional[str]:
    if not path:
        return None
    data = path.read_text().strip().split()
    return data[0] if data else None


def _run_cosign(bundle: Path, signature: Path, public_key: Path, require: bool) -> bool:
    cosign_path = shutil.which("cosign")
    if not cosign_path:
        if require:
            print("gumroad-validator: cosign not found but required", file=sys.stderr)
            return False
        print(
            "gumroad-validator: cosign not found; skipping signature verification", file=sys.stderr
        )
        return True

    cmd = [
        cosign_path,
        "verify-blob",
        "--key",
        str(public_key),
        "--signature",
        str(signature),
        str(bundle),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write("cosign verification failed:\n")
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return False
    print("gumroad-validator: cosign signature OK")
    return True


def _normalize_digest(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return value.strip().lower()


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Gumroad bundle against release artifact")
    parser.add_argument(
        "--release-bundle", required=True, type=Path, help="Path to the GitHub release bundle"
    )
    parser.add_argument(
        "--gumroad-bundle", required=True, type=Path, help="Path to the Gumroad-uploaded bundle"
    )
    parser.add_argument("--release-sha256", help="Expected SHA256 for the release bundle (hex)")
    parser.add_argument(
        "--release-sha256-file",
        type=Path,
        help="File containing expected SHA256 for the release bundle",
    )
    parser.add_argument("--gumroad-sha256", help="Expected SHA256 for the Gumroad bundle (hex)")
    parser.add_argument(
        "--gumroad-sha256-file",
        type=Path,
        help="File containing expected SHA256 for the Gumroad bundle",
    )
    parser.add_argument(
        "--public-key", type=Path, help="Path to cosign public key for signature verification"
    )
    parser.add_argument("--signature", type=Path, help="Path to cosign signature for the bundle")
    parser.add_argument(
        "--require-cosign",
        action="store_true",
        help="Fail if cosign is not available when --public-key/--signature supplied",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    release_bundle = args.release_bundle
    gumroad_bundle = args.gumroad_bundle

    if not release_bundle.is_file():
        print(f"gumroad-validator: release bundle not found: {release_bundle}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    if not gumroad_bundle.is_file():
        print(f"gumroad-validator: Gumroad bundle not found: {gumroad_bundle}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    release_digest = _compute_sha256(release_bundle)
    gumroad_digest = _compute_sha256(gumroad_bundle)

    release_expected = _normalize_digest(args.release_sha256) or _normalize_digest(
        _read_digest_from_file(args.release_sha256_file)
    )
    gumroad_expected = _normalize_digest(args.gumroad_sha256) or _normalize_digest(
        _read_digest_from_file(args.gumroad_sha256_file)
    )

    if release_expected and release_digest != release_expected:
        print(
            "gumroad-validator: release bundle SHA256 mismatch\n"
            f" expected: {release_expected}\n"
            f"   actual: {release_digest}",
            file=sys.stderr,
        )
        return EXIT_MISMATCH

    if gumroad_expected and gumroad_digest != gumroad_expected:
        print(
            "gumroad-validator: Gumroad bundle SHA256 mismatch\n"
            f" expected: {gumroad_expected}\n"
            f"   actual: {gumroad_digest}",
            file=sys.stderr,
        )
        return EXIT_MISMATCH

    if release_digest != gumroad_digest:
        print(
            "gumroad-validator: bundles differ\n"
            f" release: {release_digest}\n"
            f" gumroad: {gumroad_digest}",
            file=sys.stderr,
        )
        return EXIT_MISMATCH

    print("gumroad-validator: bundle digests match")

    if args.public_key and args.signature:
        signature = args.signature
        public_key = args.public_key
        if not signature.is_file():
            print(f"gumroad-validator: signature file not found: {signature}", file=sys.stderr)
            return EXIT_INVALID_INPUT
        if not public_key.is_file():
            print(f"gumroad-validator: public key not found: {public_key}", file=sys.stderr)
            return EXIT_INVALID_INPUT
        if not _run_cosign(release_bundle, signature, public_key, args.require_cosign):
            return EXIT_COSIGN_FAILURE
    elif args.public_key or args.signature:
        print(
            "gumroad-validator: provide both --public-key and --signature or neither",
            file=sys.stderr,
        )
        return EXIT_INVALID_INPUT

    print("gumroad-validator: validation complete")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

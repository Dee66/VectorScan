#!/usr/bin/env python3
"""Download a release artifact and verify SHA256 plus optional cosign signature."""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional
from urllib import request

# ruff: noqa: E402


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.vectorscan.tempfiles import secure_temp_dir, secure_temp_file

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_DOWNLOAD_ERROR = 6
EXIT_MISMATCH = 3
EXIT_COSIGN_FAILURE = 4


def _download(url: str, destination: Path) -> None:
    try:
        with request.urlopen(url) as resp, destination.open("wb") as handle:
            shutil.copyfileobj(resp, handle)
    except Exception as exc:  # pragma: no cover - error path exercised via integration
        raise RuntimeError(f"failed to download {url}: {exc}") from exc


def _compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_expected_sha(args: argparse.Namespace) -> Optional[str]:
    if args.expected_sha256:
        return args.expected_sha256.strip().lower()
    if args.sha256_file:
        try:
            data = Path(args.sha256_file).read_text().strip().split()
            return data[0].lower() if data else None
        except FileNotFoundError:
            raise RuntimeError(f"sha256 file not found: {args.sha256_file}") from None
    return None


def _run_cosign(bundle: Path, signature: Path, public_key: Path, require: bool) -> bool:
    cosign = shutil.which("cosign")
    if not cosign:
        if require:
            print("release-verifier: cosign required but not found", file=sys.stderr)
            return False
        print(
            "release-verifier: cosign not found; skipping signature verification", file=sys.stderr
        )
        return True

    cmd = [
        cosign,
        "verify-blob",
        "--key",
        str(public_key),
        "--signature",
        str(signature),
        str(bundle),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write("cosign verification failed\n")
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return False
    print("release-verifier: cosign signature OK")
    return True


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download GitHub release artifacts and verify integrity"
    )
    parser.add_argument(
        "--artifact-url", required=True, help="URL of the release artifact to download"
    )
    parser.add_argument(
        "--artifact-output", type=Path, help="Optional path to save the downloaded artifact"
    )
    parser.add_argument(
        "--signature-url", help="URL of the signature file (for cosign verification)"
    )
    parser.add_argument(
        "--signature-output", type=Path, help="Optional path to save the downloaded signature"
    )
    parser.add_argument("--expected-sha256", help="Expected SHA256 digest (hex)")
    parser.add_argument("--sha256-file", help="File containing expected SHA256 digest")
    parser.add_argument(
        "--public-key", type=Path, help="Path to cosign public key for verification"
    )
    parser.add_argument(
        "--require-cosign",
        action="store_true",
        help="Fail when cosign is unavailable instead of skipping signature verification",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    tmp_dir = secure_temp_dir(prefix="release-verifier-")
    try:
        if args.artifact_output:
            artifact_path = args.artifact_output
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            artifact_path = secure_temp_file(
                prefix="release-artifact-", suffix=".bin", directory=tmp_dir
            )
        try:
            _download(args.artifact_url, artifact_path)
        except Exception as exc:  # pragma: no cover - network failure path
            print(str(exc), file=sys.stderr)
            return EXIT_DOWNLOAD_ERROR

        digest = _compute_sha256(artifact_path)
        expected = _read_expected_sha(args)
        if expected:
            if digest != expected:
                print(
                    "release-verifier: SHA256 mismatch\n"
                    f" expected: {expected}\n"
                    f"   actual: {digest}",
                    file=sys.stderr,
                )
                return EXIT_MISMATCH
        print(f"release-verifier: artifact SHA256 {digest}")

        if args.public_key or args.signature_url or args.signature_output:
            if not (args.public_key and args.signature_url):
                print(
                    "release-verifier: --public-key and --signature-url must be provided together",
                    file=sys.stderr,
                )
                return EXIT_INVALID_INPUT
            if args.signature_output:
                signature_path = args.signature_output
                signature_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                signature_path = secure_temp_file(
                    prefix="release-signature-", suffix=".sig", directory=tmp_dir
                )
            try:
                _download(args.signature_url, signature_path)
            except Exception as exc:  # pragma: no cover - network failure path
                print(str(exc), file=sys.stderr)
                return EXIT_DOWNLOAD_ERROR

            if not args.public_key.exists():
                print(f"release-verifier: public key not found: {args.public_key}", file=sys.stderr)
                return EXIT_INVALID_INPUT

            if not _run_cosign(artifact_path, signature_path, args.public_key, args.require_cosign):
                return EXIT_COSIGN_FAILURE
        else:
            print("release-verifier: signature verification skipped (no --public-key provided)")

        print("release-verifier: validation complete")
        return EXIT_OK
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Download Gumroad bundles with retry+metrics to guard against transient failures."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
from urllib import error, request

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.vectorscan.time_utils import deterministic_isoformat

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_DOWNLOAD_ERROR = 6

BUFFER_SIZE = 1024 * 1024


@dataclass
class DownloadResult:
    attempts: int
    bytes_downloaded: int
    duration_seconds: float
    errors: List[Dict[str, Any]]
    status: str


def _now_iso() -> str:
    return deterministic_isoformat()


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retry Gumroad downloads and emit failure telemetry")
    parser.add_argument("--download-url", required=True, help="Public Gumroad download URL or signed link")
    parser.add_argument("--output", type=Path, default=Path("dist/gumroad-download.bin"), help="Path to save the downloaded bundle")
    parser.add_argument("--retries", type=int, default=3, help="Number of download attempts before failing")
    parser.add_argument("--delay", type=float, default=2.0, help="Seconds to wait between retries")
    parser.add_argument("--timeout", type=float, default=30.0, help="Per-request timeout in seconds")
    parser.add_argument("--metrics-file", type=Path, default=Path("metrics/gumroad_download_guard.json"), help="Where to write the metrics summary")
    parser.add_argument("--sha256", help="Expected SHA256 digest (hex) for the downloaded file")
    return parser.parse_args(argv)


def _make_parent(path: Path) -> None:
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def _download_once(url: str, destination: Path, timeout: float) -> int:
    _make_parent(destination)
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")
    bytes_written = 0
    try:
        with request.urlopen(url, timeout=timeout) as resp, tmp_path.open("wb") as handle:
            while True:
                chunk = resp.read(BUFFER_SIZE)
                if not chunk:
                    break
                handle.write(chunk)
                bytes_written += len(chunk)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    tmp_path.replace(destination)
    return bytes_written


def _compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(BUFFER_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_metrics(path: Path, payload: Dict[str, Any]) -> None:
    _make_parent(path)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def download_with_retry(url: str, destination: Path, retries: int, delay: float, timeout: float, expected_sha: str | None) -> DownloadResult:
    errors: List[Dict[str, Any]] = []
    attempts = 0
    start_time = time.monotonic()
    bytes_downloaded = 0
    while attempts < retries:
        attempts += 1
        try:
            bytes_downloaded = _download_once(url, destination, timeout)
            if expected_sha:
                actual = _compute_sha256(destination)
                if actual != expected_sha.lower():
                    raise ValueError(
                        f"Checksum mismatch (expected {expected_sha.lower()}, got {actual})"
                    )
            duration = time.monotonic() - start_time
            return DownloadResult(
                attempts=attempts,
                bytes_downloaded=bytes_downloaded,
                duration_seconds=duration,
                errors=errors,
                status="SUCCESS",
            )
        except Exception as exc:
            error_info = {
                "attempt": attempts,
                "timestamp": _now_iso(),
                "message": str(exc),
                "type": exc.__class__.__name__,
            }
            if isinstance(exc, error.HTTPError):
                error_info["status_code"] = exc.code
            errors.append(error_info)
            if attempts < retries:
                time.sleep(delay)
    duration = time.monotonic() - start_time
    return DownloadResult(
        attempts=attempts,
        bytes_downloaded=bytes_downloaded,
        duration_seconds=duration,
        errors=errors,
        status="FAILURE",
    )


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    expected_sha = args.sha256.lower() if args.sha256 else None
    result = download_with_retry(
        url=args.download_url,
        destination=args.output,
        retries=max(1, args.retries),
        delay=max(0.0, args.delay),
        timeout=max(1.0, args.timeout),
        expected_sha=expected_sha,
    )
    payload = {
        "status": result.status,
        "attempts": result.attempts,
        "downloaded_bytes": result.bytes_downloaded,
        "duration_seconds": round(result.duration_seconds, 3),
        "errors": result.errors,
        "url": args.download_url,
        "output": str(args.output),
        "recorded_at": _now_iso(),
    }
    if expected_sha:
        payload["expected_sha256"] = expected_sha
    _write_metrics(args.metrics_file, payload)

    if result.status == "SUCCESS":
        print(
            f"gumroad-download-guard: download OK in {result.attempts} attempt(s), {result.bytes_downloaded} bytes"
        )
        return EXIT_OK

    print(
        f"gumroad-download-guard: failed after {result.attempts} attempts; see {args.metrics_file}",
        file=sys.stderr,
    )
    return EXIT_DOWNLOAD_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Update the progress bar in docs/test-checklist.md."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.update_checklist_progress import update_file

DEFAULT_TEST_CHECKLIST = PROJECT_ROOT / "docs" / "test-checklist.md"
PROGRESS_IDS = ["vs-test-progress"]
LABEL_IDS = ["vs-test-progress-label"]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update docs/test-checklist.md progress indicator based on checkboxes"
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=DEFAULT_TEST_CHECKLIST,
        help="Path to the test checklist markdown file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write changes, only print computed progress",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.file.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2
    done, total, percent = update_file(
        args.file,
        progress_ids=PROGRESS_IDS,
        label_ids=LABEL_IDS,
        dry_run=args.dry_run,
    )
    print(f"Test checklist progress: {percent}% ({done}/{total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

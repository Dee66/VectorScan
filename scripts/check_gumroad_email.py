#!/usr/bin/env python3
"""Ensure the Gumroad delivery email includes mandatory verification instructions."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict

EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_MISSING_SECTION = 3

REQUIRED_SNIPPETS: Dict[str, str] = {
    "bundle_name": "vectorscan-free.zip",
    "github_release": "https://github.com/Dee66/VectorScan/releases/latest",
    "sha256": "sha256sum -c",
    "cosign": "cosign verify-blob",
    "release_doc": "docs/release-distribution.md",
    "blueprint_cta": "https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=blueprint",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Gumroad delivery email copy")
    parser.add_argument(
        "--email-file",
        type=Path,
        default=Path("docs/gumroad_delivery_email.md"),
        help="Path to the Gumroad delivery email Markdown template",
    )
    return parser.parse_args(argv)


def _load_email(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"Email template not found: {path}") from exc


def _find_missing_snippets(text: str) -> list[str]:
    lower_text = text.lower()
    missing: list[str] = []
    for label, snippet in REQUIRED_SNIPPETS.items():
        if snippet.lower() not in lower_text:
            missing.append(label)
    return missing


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        text = _load_email(args.email_file)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_INVALID_INPUT

    missing = _find_missing_snippets(text)
    if missing:
        print(
            "Gumroad email check failed; missing sections: " + ", ".join(missing),
            file=sys.stderr,
        )
        return EXIT_MISSING_SECTION

    print("Gumroad email verification instructions are present")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

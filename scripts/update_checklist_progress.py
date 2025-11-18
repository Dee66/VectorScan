#!/usr/bin/env python3
"""
Update the progress bar in docs/checklist.md based on checkbox status.

Supported checkbox formats:
- Markdown checkboxes: "- [ ] Task" and "- [x] Task"
- HTML inputs: <input type="checkbox"> and <input type="checkbox" checked>

Updates:
- <progress id="vg-progress"|"vs-progress" value="N" max="100">
- <div id="vg-progress-label"|"vs-progress-label">N% Complete (done/total)</div>

Usage:
    scripts/update_checklist_progress.py [-f FILE] [--dry-run]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHECKLIST_PATH = PROJECT_ROOT / "docs" / "checklist.md"


def count_markdown_checkboxes(text: str) -> tuple[int, int]:
    md_matches = re.findall(r"^\s*[-*]\s+\[([ xX])\]", text, flags=re.MULTILINE)
    total = len(md_matches)
    done = sum(1 for m in md_matches if m.lower() == "x")
    return done, total


def count_html_checkboxes(text: str) -> tuple[int, int]:
    inputs = re.findall(r"<input\b[^>]*type=[\"']checkbox[\"'][^>]*>", text, flags=re.IGNORECASE)
    total = len(inputs)
    done = 0
    for tag in inputs:
        if re.search(r"\bchecked\b", tag, flags=re.IGNORECASE):
            done += 1
    return done, total


def compute_progress(text: str) -> tuple[int, int, int]:
    md_done, md_total = count_markdown_checkboxes(text)
    html_done, html_total = count_html_checkboxes(text)
    done = md_done + html_done
    total = md_total + html_total
    percent = 0 if total == 0 else int(round((done / total) * 100))
    return done, total, percent


def update_progress_value(html: str, percent: int, progress_ids: list[str]) -> str:
    """Replace the value attribute on the first matching progress tag."""

    def replace_tag(match: re.Match[str]) -> str:
        tag = match.group(0)
        has_value_attr = re.search(r"\bvalue=", tag) is not None
        if has_value_attr:
            tag = re.sub(
                r"(\bvalue=[\"']?)(\d{1,3})([\"']?)", rf"\g<1>{percent}\g<3>", tag, count=1
            )
        else:
            tag = tag.rstrip(">") + f' value="{percent}">'
        return tag

    updated = html
    for progress_id in progress_ids:
        pattern = rf"<progress\\b[^>]*id=[\"']{re.escape(progress_id)}[\"'][^>]*>"
        candidate = re.sub(pattern, replace_tag, updated, count=1, flags=re.IGNORECASE)
        if candidate != updated:
            return candidate
    return updated


def update_progress_label(
    html: str, done: int, total: int, percent: int, label_ids: list[str]
) -> str:
    new_text = f"{percent}% Complete ({done}/{total})"
    updated = html
    for label_id in label_ids:
        pattern = rf"(<div[^>]*id=[\"']{re.escape(label_id)}[\"'][^>]*>)(.*?)(</div>)"
        candidate = re.sub(
            pattern,
            r"\g<1>" + new_text + r"\g<3>",
            updated,
            count=1,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if candidate != updated:
            return candidate
    return updated


def update_file(
    path: Path,
    *,
    progress_ids: list[str],
    label_ids: list[str],
    dry_run: bool = False,
) -> tuple[int, int, int]:
    text = path.read_text(encoding="utf-8")
    done, total, percent = compute_progress(text)
    updated = update_progress_value(text, percent, progress_ids)
    updated = update_progress_label(updated, done, total, percent, label_ids)

    if not dry_run and updated != text:
        path.write_text(updated, encoding="utf-8")
    return done, total, percent


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Update checklist progress bar based on checkboxes")
    p.add_argument(
        "-f",
        "--file",
        type=Path,
        default=DEFAULT_CHECKLIST_PATH,
        help="Path to checklist markdown file",
    )
    p.add_argument(
        "--progress-id",
        dest="progress_ids",
        action="append",
        help="Progress element id to update (can be provided multiple times)",
    )
    p.add_argument(
        "--label-id",
        dest="label_ids",
        action="append",
        help="Progress label div id to update (can be provided multiple times)",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="Do not write changes, only print computed progress"
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.file.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2
    progress_ids = args.progress_ids or ["vg-progress", "vs-progress"]
    label_ids = args.label_ids or ["vg-progress-label", "vs-progress-label"]
    done, total, percent = update_file(
        args.file,
        progress_ids=progress_ids,
        label_ids=label_ids,
        dry_run=args.dry_run,
    )
    print(f"Progress: {percent}% ({done}/{total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

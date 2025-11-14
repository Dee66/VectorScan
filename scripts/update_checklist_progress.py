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


def update_progress_value(html: str, percent: int) -> str:
    # Replace the first <progress id="vg-progress"|"vs-progress" ...> tag's value
    def replace_tag(match: re.Match) -> str:
        tag = match.group(0)
        if re.search(r"\bvalue=", tag):
            tag = re.sub(r"(\bvalue=[\"']?)(\d{1,3})([\"']?)", rf"\g<1>{percent}\g<3>", tag, count=1)
        else:
            tag = tag.rstrip('>') + f' value="{percent}">'
        return tag

    updated = re.sub(r"<progress\b[^>]*id=[\"']vg-progress[\"'][^>]*>", replace_tag, html, count=1, flags=re.IGNORECASE)
    if updated == html:
        updated = re.sub(r"<progress\b[^>]*id=[\"']vs-progress[\"'][^>]*>", replace_tag, html, count=1, flags=re.IGNORECASE)
    return updated


def update_progress_label(html: str, done: int, total: int, percent: int) -> str:
    new_text = f"{percent}% Complete ({done}/{total})"
    pattern_vg = r"(<div[^>]*id=[\"']vg-progress-label[\"'][^>]*>)(.*?)(</div>)"
    updated = re.sub(pattern_vg, r"\g<1>" + new_text + r"\g<3>", html, count=1, flags=re.IGNORECASE | re.DOTALL)
    if updated == html:
        pattern_vs = r"(<div[^>]*id=[\"']vs-progress-label[\"'][^>]*>)(.*?)(</div>)"
        updated = re.sub(pattern_vs, r"\g<1>" + new_text + r"\g<3>", html, count=1, flags=re.IGNORECASE | re.DOTALL)
    return updated


def update_file(path: Path, dry_run: bool = False) -> tuple[int, int, int]:
    text = path.read_text(encoding="utf-8")
    done, total, percent = compute_progress(text)
    updated = update_progress_value(text, percent)
    updated = update_progress_label(updated, done, total, percent)

    if not dry_run and updated != text:
        path.write_text(updated, encoding="utf-8")
    return done, total, percent


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Update checklist progress bar based on checkboxes")
    p.add_argument("-f", "--file", type=Path, default=DEFAULT_CHECKLIST_PATH, help="Path to checklist markdown file")
    p.add_argument("--dry-run", action="store_true", help="Do not write changes, only print computed progress")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.file.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return 2
    done, total, percent = update_file(args.file, dry_run=args.dry_run)
    print(f"Progress: {percent}% ({done}/{total})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

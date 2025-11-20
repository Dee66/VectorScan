"""Utilities to regenerate VectorScan specification and schema docs."""
from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCS_DIR = REPO_ROOT / "docs"
SCHEMA_PATH = REPO_ROOT / "schemas" / "guardsuite_pillar_schema.json"
SPEC_SOURCE_CANDIDATES: List[Path] = [
    Path("/mnt/data/VectorScan.txt"),
    DOCS_DIR / "VectorScan.txt",
]
SPEC_OUTPUT_PATH = DOCS_DIR / "vectorscan_spec.md"
SCHEMA_OUTPUT_PATH = DOCS_DIR / "output_schema.md"
SECTION_PATTERN = re.compile(r"^(\d+(?:\.\d+)*)(?:\.)?\s+(.*)$")

TOP_LEVEL_DESCRIPTIONS = {
    "pillar": "Name of the pillar emitting the scan (always 'vector').",
    "scan_version": "VectorScan semantic version for traceability.",
    "guardscore_rules_version": "Ruleset version consumed by GuardScore.",
    "canonical_schema_version": "Version of the shared GuardSuite schema.",
    "issues": "List of structured findings emitted by the evaluator.",
    "severity_totals": "Aggregated counts per severity used for reporting.",
    "pillar_score_inputs": "Per-severity counts GuardScore ingests for scoring.",
    "metadata": "Additional evaluator metadata (plan info, renderer hints).",
    "environment": "Detected environment context (stage, providers, counts).",
    "badge_eligible": "Boolean flag used by GuardScore badge pipeline.",
    "quick_score_mode": "Indicates reduced evaluation path for huge plans.",
    "latency_ms": "End-to-end evaluation latency in milliseconds.",
    "schema_validation_error": "Null or populated when canonicalization fails.",
}

ISSUE_FIELD_DESCRIPTIONS = {
    "id": "Stable issue identifier (e.g., P-VEC-001).",
    "severity": "critical / high / medium / low severity classification.",
    "title": "One-line summary of the finding.",
    "description": "Detailed description of the detected risk.",
    "resource_address": "Terraform address pointing to the offending resource.",
    "attributes": "Structured context for remediation (resource metadata).",
    "remediation_hint": "Fixpack reference such as fixpack:P-VEC-001.",
    "remediation_difficulty": "low / medium / high remediation effort guidance.",
}

SEVERITY_DESCRIPTIONS = {
    "critical": "Blocks deployment or introduces severe exposure.",
    "high": "Major governance failure that must be addressed soon.",
    "medium": "Operational or quality issue with moderate impact.",
    "low": "Informational signal that does not block rollout.",
}


def _normalize_ascii(value: str) -> str:
    """Convert Unicode-heavy input to ASCII-only text."""
    normalized = unicodedata.normalize("NFKD", value)
    return normalized.encode("ascii", "ignore").decode("ascii")


def _spec_source_path() -> Path:
    for candidate in SPEC_SOURCE_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("VectorScan.txt source not found in expected locations.")


def _clean_heading_text(text: str) -> str:
    """Replace missing punctuation artifacts inside heading text."""
    return re.sub(r"\s{2,}", " - ", text)


def _convert_spec_text_to_markdown(raw_text: str) -> str:
    output_lines: list[str] = []
    first_heading_written = False
    collecting_exit_codes = False
    exit_rows: list[str] = []

    for line in raw_text.splitlines():
        ascii_line = _normalize_ascii(line.rstrip())
        stripped = ascii_line.strip()

        if collecting_exit_codes:
            if not stripped:
                if exit_rows:
                    output_lines.extend(exit_rows)
                    output_lines.append("")
                    exit_rows = []
                    collecting_exit_codes = False
                continue
            parts = [segment.strip() for segment in re.split(r"\s{2,}|\t", stripped) if segment.strip()]
            if len(parts) >= 2 and parts[0].lower() != "code":
                exit_rows.append(f"- `{parts[0]}` — {parts[1]}")
                continue
            if len(parts) >= 2 and parts[0].lower() == "code":
                continue
            if exit_rows:
                output_lines.extend(exit_rows)
                output_lines.append("")
                exit_rows = []
            collecting_exit_codes = False
            # Fall through so the current line is handled by the standard parser.

        if not stripped:
            if output_lines and output_lines[-1]:
                output_lines.append("")
            continue

        if not first_heading_written:
            output_lines.append(f"# {_clean_heading_text(stripped)}")
            output_lines.append("")
            first_heading_written = True
            continue

        if stripped.lower().startswith("exit codes"):
            output_lines.append("**Exit Codes**")
            output_lines.append("")
            collecting_exit_codes = True
            exit_rows = []
            continue

        section_match = SECTION_PATTERN.match(stripped)
        if section_match:
            depth = min(6, 2 + section_match.group(1).count("."))
            output_lines.append(f"{'#' * depth} {_clean_heading_text(stripped)}")
            output_lines.append("")
            continue

        output_lines.append(stripped)

    if collecting_exit_codes and exit_rows:
        output_lines.extend(exit_rows)
        output_lines.append("")

    return "\n".join(line.rstrip() for line in output_lines).rstrip() + "\n"


def generate_spec_md() -> str:
    """Generate docs/vectorscan_spec.md from the raw specification text."""
    source_text = _spec_source_path().read_text(encoding="utf-8")
    markdown = _convert_spec_text_to_markdown(source_text)
    SPEC_OUTPUT_PATH.write_text(markdown, encoding="utf-8")
    return markdown


def _markdown_table(rows: Iterable[tuple[str, str]]) -> list[str]:
    lines = ["| Key | Description |", "| --- | --- |"]
    for key, description in rows:
        lines.append(f"| `{key}` | {description} |")
    return lines


def generate_schema_md() -> str:
    """Generate docs/output_schema.md from the canonical schema JSON."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    lines: list[str] = ["# VectorScan Output Schema", ""]

    lines.append("## Top-Level Required Keys")
    lines.append("")
    lines.extend(_markdown_table((key, TOP_LEVEL_DESCRIPTIONS.get(key, "See canonical schema.")) for key in schema.get("required", [])))
    lines.append("")

    lines.append("## Issue Object Requirements")
    lines.append("")
    lines.extend(
        _markdown_table(
            (key, ISSUE_FIELD_DESCRIPTIONS.get(key, "Required field on every issue."))
            for key in schema.get("issue_required_fields", [])
        )
    )
    lines.append("")
    lines.append(
        "The `issues` array must contain dictionaries with the fields listed above. Each field is required across the GuardSuite pillars so downstream tooling can present remediation guidance consistently."
    )
    lines.append("")

    lines.append("## Severity Totals")
    lines.append("")
    lines.extend(_markdown_table((key, SEVERITY_DESCRIPTIONS.get(key, "GuardSuite severity bucket.")) for key in schema.get("severity_keys", [])))
    lines.append("")
    lines.append(
        "Severity keys are used by both `severity_totals` and `pillar_score_inputs`. Missing keys are treated as zero counts, but VectorScan should always emit all buckets for determinism."
    )
    lines.append("")

    lines.append("## Nested Structures")
    lines.append("")
    lines.append("- `environment` captures inferred stage, provider list, and resource counts.")
    lines.append("- `metadata` holds evaluator diagnostics, renderer hints, and provenance identifiers.")
    lines.append("- `badge_eligible` indicates GuardScore badge readiness and mirrors `guardscore_badge` in prior specs.")
    lines.append("- `schema_validation_error` is null for valid output and stringified when schema enforcement fails.")
    lines.append("")
    lines.append(
        "Refer to `schemas/guardsuite_pillar_schema.json` for machine-readable enforcement while this document captures the human-readable contract."
    )

    markdown = "\n".join(lines).rstrip() + "\n"
    SCHEMA_OUTPUT_PATH.write_text(markdown, encoding="utf-8")
    return markdown


if __name__ == "__main__":
    generate_spec_md()
    generate_schema_md()

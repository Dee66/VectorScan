"""Human-readable rendering helpers for VectorScan CLI output."""

from __future__ import annotations

from typing import Any, Dict, List

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def render_human_readable(
    output: Dict[str, object], *, include_summary: bool = False
) -> str:
    """Return a deterministic text block describing scan issues."""

    issues = output.get("issues") or []
    lines: List[str] = []

    title = f"Scan completed for {output.get('pillar', 'VectorScan')}"
    lines.append(title)
    lines.append("-")

    if include_summary:
        summary_block = render_severity_summary(output.get("pillar_score_inputs"))
        lines.extend(summary_block.splitlines())
        lines.append("-")

    if not issues:
        lines.append("No issues detected.")
        return "\n".join(lines)

    for issue in issues:
        lines.extend(_render_issue_block(issue))

    return "\n".join(lines)


def _render_issue_block(issue: Dict[str, object]) -> List[str]:
    block: List[str] = []
    issue_id = issue.get("id", "UNKNOWN")
    title = issue.get("title", "")
    severity = issue.get("severity", "unknown")
    block.append(f"[{issue_id}] {title} ({severity})")
    resource = issue.get("resource_address") or "-"
    block.append(f"  Resource: {resource}")
    remediation_hint = issue.get("remediation_hint") or "N/A"
    block.append(f"  Remediation: {remediation_hint}")

    metadata = issue.get("remediation_metadata")
    if isinstance(metadata, dict):
        summary = metadata.get("description") or ""
        if summary:
            block.append(f"  Fix summary: {summary}")
        patch = metadata.get("terraform_patch")
        if patch:
            block.append("  Terraform patch:")
            block.extend(_indent_patch(patch))
    else:
        description = issue.get("description")
        if description:
            block.append(f"  Fix summary: {description}")
    return block


def _indent_patch(patch: object) -> List[str]:
    text = str(patch)
    lines = text.splitlines() or [text]
    return [f"    {line}" for line in lines]


def render_severity_summary(pillar_score_inputs: Dict[str, Any] | None) -> str:
    counts: Dict[str, int] = {}
    source = pillar_score_inputs or {}
    for key in SEVERITY_ORDER:
        value = source.get(key, 0)
        try:
            counts[key] = int(value)
        except (TypeError, ValueError):
            counts[key] = 0

    lines = ["Summary:"]
    for key in SEVERITY_ORDER:
        lines.append(f"  {key}: {counts[key]}")
    return "\n".join(lines)

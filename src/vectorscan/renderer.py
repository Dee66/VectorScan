"""Human-readable rendering helpers for VectorScan CLI output."""

from __future__ import annotations

from typing import Any, Dict, List

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def render_human_readable(output: Dict[str, object]) -> str:
    """Return a deterministic text block describing scan issues."""

    issues = output.get("issues") or []
    lines: List[str] = []

    title = f"Scan completed for {output.get('pillar', 'VectorScan')}"
    lines.append(title)
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


def render_severity_summary(output: Dict[str, Any]) -> str:
    pillar_score_inputs = output.get("pillar_score_inputs")
    counts: Dict[str, int] = {}
    source = pillar_score_inputs or {}
    for key in SEVERITY_ORDER:
        value = source.get(key, 0)
        try:
            counts[key] = int(value)
        except (TypeError, ValueError):
            counts[key] = 0

    total = sum(counts.values())

    lines = ["Summary:"]
    for key in SEVERITY_ORDER:
        count = counts[key]
        percentage = 0
        if total > 0:
            percentage = int(round((count / total) * 100))
        lines.append(f"  {key}: {count} ({percentage}%)")

    badge_info = output.get("guardscore_badge")
    eligible = False
    if isinstance(badge_info, dict):
        eligible = bool(badge_info.get("eligible", False))
    lines.append(f"  badge_eligible: {str(eligible).lower()}")
    return "\n".join(lines)

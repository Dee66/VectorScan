"""Plan evolution diff helpers for VectorScan compare mode."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tools.vectorscan.plan_utils import iter_resources


ChangeSummary = Dict[str, int]
ResourceMap = Dict[str, Dict[str, Any]]


def _classify_actions(actions: Sequence[Any]) -> Optional[str]:
    normalized = [str(action).lower() for action in actions if isinstance(action, str) and action]
    if not normalized:
        return None
    if "update" in normalized:
        return "changes"
    if "create" in normalized and "delete" in normalized:
        return "changes"
    if "create" in normalized:
        return "adds"
    if "delete" in normalized:
        return "destroys"
    return None


def _coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in {"true", "1", "yes", "on"}:
            return True
        if token in {"false", "0", "no", "off"}:
            return False
    return None


def _nonempty_str(value: Any) -> Optional[str]:
    if isinstance(value, str):
        token = value.strip()
        if token:
            return token
    return None


def _resource_index(plan: Dict[str, Any]) -> ResourceMap:
    index: ResourceMap = {}
    for resource in iter_resources(plan):
        address = resource.get("address")
        if isinstance(address, str) and address:
            index[address] = resource
    return index


def _change_summary(plan: Dict[str, Any]) -> ChangeSummary:
    summary: ChangeSummary = {"adds": 0, "changes": 0, "destroys": 0}
    for rc in plan.get("resource_changes") or []:
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        bucket = _classify_actions(actions)
        if not bucket:
            continue
        summary[bucket] = summary.get(bucket, 0) + 1
    return summary


@dataclass
class _EncryptionState:
    storage_encrypted: Optional[bool]
    kms_key_id: Optional[str]
    metadata: Dict[str, Any]


def _collect_encryption_states(resources: Iterable[Dict[str, Any]]) -> Dict[str, _EncryptionState]:
    states: Dict[str, _EncryptionState] = {}
    for resource in resources:
        address = resource.get("address")
        if not isinstance(address, str) or not address:
            continue
        values = resource.get("values") or {}
        if not isinstance(values, dict):
            values = {}
        states[address] = _EncryptionState(
            storage_encrypted=_coerce_bool(values.get("storage_encrypted")),
            kms_key_id=_nonempty_str(values.get("kms_key_id")),
            metadata={
                "type": resource.get("type"),
                "name": resource.get("name"),
            },
        )
    return states


def _detect_encryption_downgrades(
    old_states: Dict[str, _EncryptionState],
    new_states: Dict[str, _EncryptionState],
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for address, old_state in old_states.items():
        new_state = new_states.get(address)
        if new_state is None:
            continue
        reasons: List[str] = []
        if old_state.storage_encrypted is True and not new_state.storage_encrypted:
            reasons.append("storage_encrypted flipped to false")
        if old_state.kms_key_id and not new_state.kms_key_id:
            reasons.append("kms_key_id removed")
        if not reasons:
            continue
        entries.append({
            "address": address,
            "type": new_state.metadata.get("type") or old_state.metadata.get("type"),
            "name": new_state.metadata.get("name") or old_state.metadata.get("name"),
            "previous": {
                "storage_encrypted": old_state.storage_encrypted,
                "kms_key_id": old_state.kms_key_id,
            },
            "current": {
                "storage_encrypted": new_state.storage_encrypted,
                "kms_key_id": new_state.kms_key_id,
            },
            "reasons": reasons,
        })
    entries.sort(key=lambda item: item.get("address") or "")
    return entries


def _format_delta(delta: int, label: str, *, symbol: str, trail: str) -> str:
    if delta > 0:
        prefix = f"{symbol}{delta}"
    elif delta < 0:
        prefix = f"-{abs(delta)}"
    else:
        prefix = f"={0}"
    return f"{prefix} {label} {trail}".rstrip()


def _build_summary_lines(
    *,
    resource_delta: int,
    old_resource_count: int,
    new_resource_count: int,
    old_summary: ChangeSummary,
    new_summary: ChangeSummary,
    downgraded_count: int,
) -> List[str]:
    lines: List[str] = []
    lines.append(
        _format_delta(
            resource_delta,
            "resources",
            symbol="+",
            trail=f"({old_resource_count} → {new_resource_count})",
        )
    )
    adds_delta = new_summary.get("adds", 0) - old_summary.get("adds", 0)
    lines.append(
        _format_delta(
            adds_delta,
            "planned adds",
            symbol="+",
            trail=f"({old_summary.get('adds', 0)} → {new_summary.get('adds', 0)})",
        )
    )
    changes_delta = new_summary.get("changes", 0) - old_summary.get("changes", 0)
    if changes_delta:
        change_trail = f"({old_summary.get('changes', 0)} → {new_summary.get('changes', 0)})"
    else:
        change_trail = "(unchanged)"
    lines.append(
        _format_delta(
            changes_delta,
            "changed resources",
            symbol="~",
            trail=change_trail,
        )
    )
    destroys_delta = new_summary.get("destroys", 0) - old_summary.get("destroys", 0)
    lines.append(
        _format_delta(
            destroys_delta,
            "destroyed resources",
            symbol="-",
            trail=f"({old_summary.get('destroys', 0)} → {new_summary.get('destroys', 0)})",
        )
    )
    prefix = f"!{downgraded_count}" if downgraded_count else "!0"
    suffix = "downgraded encryption settings"
    lines.append(f"{prefix} {suffix}")
    return lines


def compute_plan_evolution(
    *,
    old_plan: Dict[str, Any],
    new_plan: Dict[str, Any],
    old_file: Path | str,
    new_file: Path | str,
    old_resources: Optional[Sequence[Dict[str, Any]]] = None,
    new_resources: Optional[Sequence[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if old_resources is None:
        old_resources = iter_resources(old_plan)
    else:
        old_resources = list(old_resources)
    if new_resources is None:
        new_resources = iter_resources(new_plan)
    else:
        new_resources = list(new_resources)
    old_summary = _change_summary(old_plan)
    new_summary = _change_summary(new_plan)
    old_states = _collect_encryption_states(old_resources)
    new_states = _collect_encryption_states(new_resources)
    downgraded = _detect_encryption_downgrades(old_states, new_states)

    old_resource_count = len(old_resources)
    new_resource_count = len(new_resources)
    resource_delta = new_resource_count - old_resource_count

    summary_lines = _build_summary_lines(
        resource_delta=resource_delta,
        old_resource_count=old_resource_count,
        new_resource_count=new_resource_count,
        old_summary=old_summary,
        new_summary=new_summary,
        downgraded_count=len(downgraded),
    )

    payload = {
        "old_plan": {
            "file": str(old_file),
            "resource_count": old_resource_count,
            "change_summary": old_summary,
        },
        "new_plan": {
            "file": str(new_file),
            "resource_count": new_resource_count,
            "change_summary": new_summary,
        },
        "delta": {
            "resource_count": resource_delta,
            "adds": new_summary.get("adds", 0) - old_summary.get("adds", 0),
            "changes": new_summary.get("changes", 0) - old_summary.get("changes", 0),
            "destroys": new_summary.get("destroys", 0) - old_summary.get("destroys", 0),
        },
        "downgraded_encryption": {
            "count": len(downgraded),
            "resources": downgraded,
        },
        "summary": {
            "lines": summary_lines,
        },
    }
    return payload


__all__ = ["compute_plan_evolution"]

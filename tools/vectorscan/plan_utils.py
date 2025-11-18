"""Plan loading, metadata, and diff helpers for VectorScan."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, cast

from tools.vectorscan.constants import EXIT_INVALID_INPUT
from tools.vectorscan.env_flags import env_falsey
from tools.vectorscan.plan_stream import (
    ModuleStats,
    PlanSchemaError,
    PlanStreamError,
    build_slo_metadata as _build_slo_metadata,
    stream_plan,
)

class PlanLoadError(Exception):
    """Raised when a Terraform plan cannot be parsed or fails schema validation."""


def _schema_error(message: str) -> None:
    print(f"Schema error: {message}", file=sys.stderr)
    raise PlanLoadError(message)


def _validate_plan_schema(plan: Dict[str, Any]) -> None:
    planned_values = plan.get("planned_values")
    if not isinstance(planned_values, dict):
        planned_values = {}
        plan["planned_values"] = planned_values

    root_module_obj = planned_values.get("root_module")
    if root_module_obj is None:
        _schema_error("planned_values.root_module must be present")
    if not isinstance(root_module_obj, dict):
        _schema_error("planned_values.root_module must be an object")
    root_module = cast(Dict[str, Any], root_module_obj)

    resources = root_module.get("resources")
    if resources is None:
        root_module["resources"] = []
    elif not isinstance(resources, list):
        _schema_error("resources must be a list under planned_values/root_module")

    child_modules = root_module.get("child_modules")
    if child_modules is None:
        root_module["child_modules"] = []
    elif not isinstance(child_modules, list):
        _schema_error("child_modules must be a list when present")


def load_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        raise PlanLoadError(f"missing plan: {path}")
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON: {path}: {exc}", file=sys.stderr)
        raise PlanLoadError(f"invalid plan json: {path}")
    if not isinstance(data, dict):
        _schema_error("Top-level plan JSON must be an object")
    _validate_plan_schema(data)
    return data


def load_plan_context(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], Optional[ModuleStats]]:
    """Load a tfplan with streaming parser when enabled."""

    disable_flag = os.getenv("VSCAN_STREAMING_DISABLE")
    streaming_enabled = not (disable_flag and not env_falsey(disable_flag))

    if streaming_enabled:
        try:
            return _load_plan_streaming_context(path)
        except PlanLoadError:
            raise
        except Exception as exc:  # pragma: no cover - fallback path
            print(
                f"[VectorScan] Streaming parser unavailable ({exc}); falling back to legacy parser.",
                file=sys.stderr,
            )

    return _load_plan_eager_context(path)


def _load_plan_streaming_context(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], ModuleStats]:
    try:
        result = stream_plan(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        raise PlanLoadError(f"missing plan: {path}")
    except PlanSchemaError as exc:
        _schema_error(str(exc))
    except PlanStreamError as exc:
        print(f"Error: invalid JSON: {path}: {exc}", file=sys.stderr)
        raise PlanLoadError(f"invalid streaming plan: {path}")

    plan = result.top_level
    plan_limits = _build_plan_limit_block(
        resource_count=len(result.resources),
        parse_duration_ms=result.parse_duration_ms,
        file_size_bytes=result.file_size_bytes,
        parser_mode="streaming",
    )
    return plan, result.resources, plan_limits, result.module_stats


def _load_plan_eager_context(path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], Optional[ModuleStats]]:
    start = time.perf_counter()
    plan = load_json(path)
    duration_ms = int(round((time.perf_counter() - start) * 1000))
    try:
        file_size_bytes = path.stat().st_size
    except FileNotFoundError:
        file_size_bytes = 0
    resources = iter_resources(plan)
    plan_limits = _build_plan_limit_block(
        resource_count=len(resources),
        parse_duration_ms=duration_ms,
        file_size_bytes=file_size_bytes,
        parser_mode="legacy",
    )
    return plan, resources, plan_limits, None


def _build_plan_limit_block(
    *,
    resource_count: int,
    parse_duration_ms: int,
    file_size_bytes: int,
    parser_mode: str,
) -> Dict[str, Any]:
    forced = os.getenv("VSCAN_FORCE_PLAN_PARSE_MS")
    if forced is None:
        forced = os.getenv("VSCAN_FORCE_DURATION_MS")
    if forced is not None:
        try:
            parse_duration_ms = max(0, int(forced))
        except ValueError:
            pass

    exceeds, slo_block = _build_slo_metadata(resource_count, parse_duration_ms, file_size_bytes)
    return {
        "file_size_bytes": file_size_bytes,
        "parse_duration_ms": parse_duration_ms,
        "plan_slo": slo_block,
        "exceeds_threshold": exceeds,
        "parser_mode": parser_mode,
    }


def iter_resources(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    def collect(mod: Dict[str, Any]) -> List[Dict[str, Any]]:
        res = list(mod.get("resources", []) or [])
        for child in mod.get("child_modules", []) or []:
            if isinstance(child, dict):
                res.extend(collect(child))
        return res

    root = plan.get("planned_values", {}).get("root_module", {})
    if not isinstance(root, dict):
        root = {}
    return collect(root)


def _bytes_to_mb(value: Optional[int]) -> Optional[float]:
    if value is None:
        return None
    try:
        return round(float(value) / 1_000_000, 6)
    except Exception:  # pragma: no cover - defensive
        return None


def _classify_change_actions(actions: Sequence[Any]) -> Optional[str]:
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


def compute_plan_metadata(
    plan: Dict[str, Any],
    resources: Optional[List[Dict[str, Any]]] = None,
    *,
    module_stats: Optional[ModuleStats] = None,
    plan_limits: Optional[Dict[str, Any]] = None,
    resource_filter: Optional[Set[str]] = None,
) -> Dict[str, Any]:
    resource_list = resources if resources is not None else iter_resources(plan)
    resource_types: Dict[str, int] = {}
    providers: Set[str] = set()

    for resource in resource_list:
        r_type = resource.get("type")
        if isinstance(r_type, str) and r_type:
            resource_types[r_type] = resource_types.get(r_type, 0) + 1
            provider_guess = r_type.split("_", 1)[0]
            if provider_guess:
                providers.add(provider_guess.lower())
        provider_name = resource.get("provider_name") or resource.get("provider")
        provider_label = _normalize_provider_label(provider_name)
        if provider_label:
            providers.add(provider_label)

    resources_by_type: Dict[str, Dict[str, int]] = {}
    for r_type, count in resource_types.items():
        resources_by_type[r_type] = {
            "planned": count,
            "adds": 0,
            "changes": 0,
            "destroys": 0,
        }

    planned_values = plan.get("planned_values", {}) or {}
    root_module = planned_values.get("root_module")
    if not isinstance(root_module, dict):
        root_module = {}

    def normalize_address(module: Dict[str, Any], fallback: str) -> str:
        addr = module.get("address")
        if isinstance(addr, str) and addr.strip():
            return addr
        return fallback

    if module_stats:
        module_count = module_stats.module_count
        modules_with_resources = module_stats.modules_with_resources
        child_module_count = module_stats.child_module_count
        root_address = module_stats.root_address or "root"
    else:
        root_address = normalize_address(root_module, "root")
        module_stack: List[Tuple[Dict[str, Any], str]] = [(root_module, root_address)]
        module_count = 0
        modules_with_resources = 0
        child_module_count = 0

        while module_stack:
            module, addr = module_stack.pop()
            module_count += 1
            module_resources = module.get("resources")
            if isinstance(module_resources, list) and module_resources:
                modules_with_resources += 1
            children = module.get("child_modules")
            if not isinstance(children, list):
                continue
            for idx, child in enumerate(children):
                if not isinstance(child, dict):
                    continue
                child_addr = normalize_address(child, f"{addr}.child[{idx}]")
                child_module_count += 1
                module_stack.append((child, child_addr))

    resource_filter = {addr for addr in (resource_filter or set()) if addr}
    change_summary = {"adds": 0, "changes": 0, "destroys": 0}
    for rc in plan.get("resource_changes") or []:
        address = rc.get("address")
        if resource_filter and isinstance(address, str) and address not in resource_filter:
            continue
        r_type = rc.get("type")
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        bucket = _classify_change_actions(actions)
        if not bucket:
            continue
        change_summary[bucket] += 1
        entry = resources_by_type.setdefault(
            r_type or "unknown",
            {"planned": 0, "adds": 0, "changes": 0, "destroys": 0},
        )
        entry[bucket] += 1

    parser_mode_value = "legacy"
    if plan_limits:
        parser_mode_raw = plan_limits.get("parser_mode")
        if isinstance(parser_mode_raw, str) and parser_mode_raw.strip():
            parser_mode_value = parser_mode_raw.strip()
    elif module_stats:
        parser_mode_value = "streaming"

    metadata = {
        "resource_count": len(resource_list),
        "resource_types": dict(sorted(resource_types.items())),
        "providers": sorted(providers),
        "module_count": module_count,
        "modules": {
            "root": root_address,
            "with_resources": modules_with_resources,
            "child_module_count": child_module_count,
            "has_child_modules": child_module_count > 0,
        },
        "exceeds_threshold": False,
        "change_summary": change_summary,
        "resources_by_type": resources_by_type,
        "file_size_mb": None,
        "parser_mode": parser_mode_value,
    }

    if plan_limits:
        file_size_bytes = plan_limits.get("file_size_bytes")
        metadata["file_size_bytes"] = file_size_bytes
        metadata["parse_duration_ms"] = plan_limits.get("parse_duration_ms")
        metadata["plan_slo"] = plan_limits.get("plan_slo")
        metadata["exceeds_threshold"] = bool(plan_limits.get("exceeds_threshold"))
        metadata["file_size_mb"] = _bytes_to_mb(file_size_bytes)

    return metadata


def _normalize_provider_label(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    token = value.strip().strip('"')
    if not token:
        return None
    if token.startswith("provider["):
        token = token[len("provider[") :]
        if token.endswith("]"):
            token = token[:-1]
        token = token.strip('"')
    if "/" in token:
        token = token.split("/")[-1]
    token = token.strip()
    if not token:
        return None
    return token.lower()


def _safe_diff_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    try:
        normalized = json.dumps(value, sort_keys=True)
    except Exception:  # pragma: no cover - defensive
        normalized = str(value)
    if len(normalized) > 200:
        return normalized[:197] + "..."
    return normalized


def _format_diff_display(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:  # pragma: no cover - defensive
        return str(value)


def _collect_changed_attributes(before: Any, after: Any) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def walk(b: Any, a: Any, path: str) -> None:
        if b == a:
            return
        if isinstance(b, dict) and isinstance(a, dict):
            keys = sorted(set(b.keys()) | set(a.keys()))
            for key in keys:
                next_path = f"{path}.{key}" if path else key
                walk(b.get(key), a.get(key), next_path)
            return
        if b is None and isinstance(a, dict):
            for key in sorted(a.keys()):
                next_path = f"{path}.{key}" if path else key
                walk(None, a.get(key), next_path)
            return
        if a is None and isinstance(b, dict):
            for key in sorted(b.keys()):
                next_path = f"{path}.{key}" if path else key
                walk(b.get(key), None, next_path)
            return
        if isinstance(b, list) and isinstance(a, list) and b == a:
            return
        entries.append({
            "path": path or ".",
            "before": _safe_diff_value(b),
            "after": _safe_diff_value(a),
        })

    walk(before, after, "")
    entries.sort(key=lambda item: item.get("path") or "")
    return entries


def build_plan_diff(plan: Dict[str, Any], resource_filter: Optional[Set[str]] = None) -> Dict[str, Any]:
    summary = {"adds": 0, "changes": 0, "destroys": 0}
    resource_filter = {addr for addr in (resource_filter or set()) if addr}
    resources: List[Dict[str, Any]] = []
    for rc in plan.get("resource_changes") or []:
        address = rc.get("address")
        if resource_filter and isinstance(address, str) and address not in resource_filter:
            continue
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        change_type = _classify_change_actions(actions) or "changes"
        if change_type in summary:
            summary[change_type] += 1
        else:
            summary["changes"] += 1
        before = change.get("before")
        after = change.get("after")
        attrs = _collect_changed_attributes(before, after)
        if not attrs and change_type not in {"adds", "destroys"}:
            continue
        if not isinstance(address, str) or not address:
            r_type = rc.get("type") or "resource"
            r_name = rc.get("name") or "unnamed"
            address = f"{r_type}.{r_name}"
        resources.append({
            "address": address,
            "type": rc.get("type"),
            "name": rc.get("name"),
            "change_type": change_type,
            "actions": actions,
            "changed_attributes": attrs,
        })
    resources.sort(key=lambda entry: entry.get("address") or "")
    return {
        "summary": summary,
        "resources": resources,
    }


__all__ = [
    "_schema_error",
    "_format_diff_display",
    "build_plan_diff",
    "compute_plan_metadata",
    "iter_resources",
    "load_json",
    "load_plan_context",
]

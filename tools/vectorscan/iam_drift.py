from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.vectorscan.constants import RISKY_ACTION_TERMS

__all__ = ["build_iam_drift_report"]


def _policy_actions_from_json_string(s: str) -> Set[str]:
    acts: Set[str] = set()
    try:
        j = json.loads(s)
    except (json.JSONDecodeError, TypeError, ValueError):
        for term in RISKY_ACTION_TERMS:
            if term in s:
                acts.add(term)
        return acts
    stmts = j.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return acts
    for st in stmts:
        a = st.get("Action")
        if isinstance(a, str):
            acts.add(a)
        elif isinstance(a, list):
            for it in a:
                if isinstance(it, str):
                    acts.add(it)
    return acts


def _is_risky_action(a: str) -> bool:
    if a == "*" or a.endswith(":*"):
        return True
    for term in RISKY_ACTION_TERMS:
        if term == "*":
            continue
        if term in a:
            return True
    return False


def _extract_policy_strings(before: Any, after: Any) -> Tuple[Optional[str], Optional[str]]:
    b = None
    a = None
    if isinstance(before, dict):
        pb = before.get("policy")
        if isinstance(pb, str):
            b = pb
    elif isinstance(before, str):
        b = before
    if isinstance(after, dict):
        pa = after.get("policy")
        if isinstance(pa, str):
            a = pa
    elif isinstance(after, str):
        a = after
    return b, a


def _parse_policy(s: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        j = json.loads(s)
    except (json.JSONDecodeError, TypeError, ValueError):
        return out
    stmts = j.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return out
    for st in stmts:
        eff = st.get("Effect", "Allow")
        act = st.get("Action")
        not_act = st.get("NotAction")
        res = st.get("Resource")
        not_res = st.get("NotResource")

        def norm_list(x):
            if x is None:
                return []
            if isinstance(x, str):
                return [x]
            if isinstance(x, list):
                return [y for y in x if isinstance(y, str)]
            return []

        out.append(
            {
                "Effect": eff,
                "Actions": norm_list(act),
                "NotActions": norm_list(not_act),
                "Resources": norm_list(res),
                "NotResources": norm_list(not_res),
            }
        )
    return out


def _resource_scope(resources: List[str], not_resources: List[str]) -> str:
    has_star = any(r == "*" or r.endswith(":*") for r in resources) if resources else True
    has_not = bool(not_resources)
    return "global" if has_star and not has_not else "scoped"


def build_iam_drift_report(plan: Dict[str, Any]) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    rc_list = plan.get("resource_changes") or []
    iam_types = {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
    risky_count = 0
    for rc in rc_list:
        rtype = rc.get("type")
        if rtype not in iam_types:
            continue
        name = rc.get("name", "<unnamed>")
        change = rc.get("change", {}) or {}
        before = change.get("before")
        after = change.get("after")
        b_policy, a_policy = _extract_policy_strings(before, after)
        if not a_policy:
            continue
        after_stmts = _parse_policy(a_policy)
        after_actions = _policy_actions_from_json_string(a_policy)
        before_actions = _policy_actions_from_json_string(b_policy) if b_policy else set()
        additions = {a for a in after_actions if a not in before_actions}
        risky_additions = []
        severity_by_action: Dict[str, str] = {}
        for a in sorted(additions):
            if not _is_risky_action(a):
                continue
            scope = "global"
            for st in after_stmts:
                if a in st.get("Actions", []):
                    scope = _resource_scope(st.get("Resources", []), st.get("NotResources", []))
                    break
            sev = "high" if scope == "global" else "medium"
            severity_by_action[a] = sev
            risky_additions.append(a)
        notaction_flag = False
        for st in after_stmts:
            if st.get("NotActions") and st.get("Effect", "Allow") == "Allow":
                scope = _resource_scope(st.get("Resources", []), st.get("NotResources", []))
                if scope == "global":
                    notaction_flag = True
                    break
        if not additions and not before_actions:
            for term in RISKY_ACTION_TERMS:
                if a_policy and term in a_policy and (not b_policy or term not in b_policy):
                    risky_additions.append(term)
                    severity_by_action[term] = "high"
        if risky_additions:
            risky_count += 1
            items.append(
                {
                    "resource_type": rtype,
                    "resource_name": name,
                    "change": change.get("actions", []),
                    "risky_additions": risky_additions,
                    "severity_by_action": severity_by_action,
                    "notaction_broad_allow": notaction_flag,
                }
            )
    status = "PASS" if risky_count == 0 else "FAIL"
    return {
        "status": status,
        "counts": {"risky_changes": risky_count},
        "items": items,
        "notes": {
            "limitations": [
                "NotAction not evaluated",
                "Resource scoping not evaluated for drift risk",
            ]
        },
    }

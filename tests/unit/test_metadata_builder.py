from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from src.pillar import constants as pillar_constants
from src.pillar.compat.normalization import (
    ScanOptions,
    build_control_flags,
    flatten_plan,
    metadata_inject,
    resolve_offline_mode,
)
from src.pillar.metadata import build_metadata, snapshot_control_flags

FIXTURE_PATH = Path("tests/fixtures/minimal_plan.json")


def _build_context() -> dict:
    plan_payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    context = flatten_plan(deepcopy(plan_payload))
    context = metadata_inject(context)
    options = ScanOptions()
    offline_mode = resolve_offline_mode(context, options)
    flags = snapshot_control_flags(build_control_flags(context, options, offline_mode))
    environment_block = dict(context.get("environment") or {})
    environment_block.update(flags)
    context["environment"] = environment_block
    context["_control_flags"] = flags
    return context


def test_build_metadata_includes_canonical_fields():
    ctx = _build_context()
    metadata = build_metadata(ctx)

    assert metadata["pillar"] == pillar_constants.PILLAR_NAME
    assert metadata["scan_version"] == pillar_constants.SCAN_VERSION
    assert metadata["canonical_schema_version"] == pillar_constants.CANONICAL_SCHEMA_VERSION

    env_meta = metadata["environment"]
    flags = ctx["_control_flags"]
    assert env_meta["offline_mode"] is flags["offline_mode"]
    assert env_meta["allow_network_capture"] is flags["allow_network_capture"]
    assert env_meta["allow_network"] == (flags.get("allow_network") or flags["allow_network_capture"])
    assert env_meta["auto_download"] is flags["auto_download"]
    assert env_meta["terraform_outcome"] == str(flags.get("terraform_outcome", "SKIP"))

    control_snapshot = metadata["_control_flags"]
    assert control_snapshot == metadata["control"]
    assert control_snapshot["auto_download"] is flags["auto_download"]

    plan_meta = metadata["plan"]
    assert plan_meta.get("resource_count") == ctx["plan_metadata"].get("resource_count")


def test_build_metadata_is_deterministic_and_does_not_mutate_context():
    ctx = _build_context()
    first = build_metadata(ctx)
    second = build_metadata(ctx)

    assert first == second
    assert first is not second

    original_count = ctx["plan_metadata"].get("resource_count")
    first["plan"]["resource_count"] = -1
    assert ctx["plan_metadata"].get("resource_count") == original_count

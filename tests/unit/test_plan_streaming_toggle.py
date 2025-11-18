import json
from pathlib import Path

from tools.vectorscan import plan_utils
from tools.vectorscan.plan_stream import ModuleStats, PlanStreamResult


_DEF_PLAN = {
    "format_version": "1.0",
    "terraform_version": "1.6.0",
    "planned_values": {"root_module": {"resources": [], "child_modules": []}},
    "resource_changes": [],
}


def _write_minimal_plan(path: Path) -> None:
    path.write_text(json.dumps(_DEF_PLAN), encoding="utf-8")


def _make_stream_result() -> PlanStreamResult:
    return PlanStreamResult(
        top_level=_DEF_PLAN,
        resources=[{"address": "aws_rds_cluster.vector_db"}],
        resource_changes=[],
        module_stats=ModuleStats(
            module_count=1,
            modules_with_resources=0,
            child_module_count=0,
            root_address="root",
        ),
        file_size_bytes=957,
        parse_duration_ms=2,
    )


def test_load_plan_context_uses_streaming_by_default(tmp_path, monkeypatch):
    plan_path = tmp_path / "plan.json"
    _write_minimal_plan(plan_path)

    call_counter = {"value": 0}
    expected = _make_stream_result()

    def fake_stream(path: Path) -> PlanStreamResult:
        call_counter["value"] += 1
        assert path == plan_path
        return expected

    monkeypatch.delenv("VSCAN_STREAMING_DISABLE", raising=False)
    monkeypatch.setattr(plan_utils, "stream_plan", fake_stream)

    plan, resources, limits, module_stats = plan_utils.load_plan_context(plan_path)

    assert plan["planned_values"]
    assert call_counter["value"] == 1
    assert module_stats == expected.module_stats
    assert limits["parser_mode"] == "streaming"
    assert resources == expected.resources


def test_load_plan_context_disables_streaming_with_env_flag(tmp_path, monkeypatch):
    plan_path = tmp_path / "plan.json"
    _write_minimal_plan(plan_path)

    def fail_stream(_path: Path) -> PlanStreamResult:  # pragma: no cover - guard
        raise AssertionError("stream_plan should not be called when streaming is disabled")

    monkeypatch.setenv("VSCAN_STREAMING_DISABLE", "1")
    monkeypatch.setattr(plan_utils, "stream_plan", fail_stream)

    _, resources, limits, module_stats = plan_utils.load_plan_context(plan_path)

    assert module_stats is None
    assert isinstance(resources, list)
    assert limits["parser_mode"] == "legacy"


def test_streaming_errors_fall_back_to_legacy_parser(tmp_path, monkeypatch, capsys):
    plan_path = tmp_path / "plan.json"
    _write_minimal_plan(plan_path)

    def boom(_path: Path) -> PlanStreamResult:
        raise RuntimeError("boom")

    monkeypatch.delenv("VSCAN_STREAMING_DISABLE", raising=False)
    monkeypatch.setattr(plan_utils, "stream_plan", boom)

    _, _, limits, module_stats = plan_utils.load_plan_context(plan_path)

    stderr = capsys.readouterr().err.lower()
    assert "falling back to legacy parser" in stderr
    assert module_stats is None
    assert limits["parser_mode"] == "legacy"

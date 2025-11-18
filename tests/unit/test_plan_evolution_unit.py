import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.vectorscan.plan_evolution import compute_plan_evolution

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_compute_plan_evolution_detects_downgrades():
    old_plan = _load("tfplan_compare_old.json")
    new_plan = _load("tfplan_compare_new.json")
    result = compute_plan_evolution(
        old_plan=old_plan,
        new_plan=new_plan,
        old_file=FIXTURES / "tfplan_compare_old.json",
        new_file=FIXTURES / "tfplan_compare_new.json",
    )
    downgraded = result["downgraded_encryption"]
    assert downgraded["count"] == 2
    addresses = [entry["address"] for entry in downgraded["resources"]]
    assert "aws_rds_cluster.vector_db" in addresses
    assert "aws_rds_cluster.analytics" in addresses
    vector_entry = next(
        entry
        for entry in downgraded["resources"]
        if entry["address"] == "aws_rds_cluster.vector_db"
    )
    assert vector_entry["previous"]["storage_encrypted"] is True
    assert vector_entry["current"]["storage_encrypted"] is False
    assert "storage_encrypted flipped to false" in vector_entry["reasons"]


def test_plan_evolution_summary_lines_capture_deltas():
    old_plan = _load("tfplan_compare_old.json")
    new_plan = _load("tfplan_compare_new.json")
    result = compute_plan_evolution(
        old_plan=old_plan,
        new_plan=new_plan,
        old_file="old.json",
        new_file="new.json",
    )
    summary_lines = result["summary"]["lines"]
    assert summary_lines[0].startswith("+1 resources")
    assert any(line.startswith("~") for line in summary_lines)
    assert summary_lines[-1].startswith("!2")

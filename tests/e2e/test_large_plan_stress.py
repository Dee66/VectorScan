import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tools.vectorscan.vectorscan as vectorscan  # noqa: E402

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _write_large_plan(target: Path, *, resource_count: int = 2200, desc_size: int = 4096) -> None:
    resources = []
    base_values = {
        "tags": {"CostCenter": "C", "Project": "P"},
        "description": "X" * desc_size,
        "kms_key_id": "kms",
        "storage_encrypted": True,
    }
    for idx in range(resource_count):
        resources.append(
            {
                "type": "aws_db_instance" if idx % 2 == 0 else "aws_s3_bucket",
                "name": f"resource_{idx}",
                "values": dict(base_values),
            }
        )
    plan = {"planned_values": {"root_module": {"resources": resources}}}
    target.write_text(json.dumps(plan))


@pytest.mark.e2e
def test_large_plan_over_five_mb(tmp_path, capsys):
    plan = tmp_path / "huge-plan.json"
    _write_large_plan(plan)
    assert plan.stat().st_size >= 5 * 1024 * 1024

    capsys.readouterr()
    code_json = vectorscan.main([str(plan), "--json"])  # type: ignore[arg-type]
    out_json = capsys.readouterr().out
    data = json.loads(out_json)
    assert code_json == 0
    assert data["status"] == "PASS"

    capsys.readouterr()
    code_text = vectorscan.main([str(plan)])  # type: ignore[arg-type]
    human = _strip_ansi(capsys.readouterr().out)
    assert code_text == 0
    assert "PASS - tfplan.json - VectorScan checks" in human
    assert "VectorScan" in human

import csv
import json
import tempfile
from pathlib import Path

import importlib.util
from importlib.machinery import ModuleSpec
from typing import cast


def load_module_from_path(name: str, path: Path):
    spec_opt = importlib.util.spec_from_file_location(name, str(path))
    assert spec_opt is not None, "Failed to create spec for module"
    spec = cast(ModuleSpec, spec_opt)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec.loader is not None, "Spec has no loader"
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_telemetry_consumer_idempotent_append():
    # Load the telemetry_consumer module from scripts/
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "telemetry_consumer.py"
    tc = load_module_from_path("telemetry_consumer", mod_path)

    # Create a fake summary structure
    base_summary = {
        "generated_at": "2025-11-14T07:00:00+00:00",
        "entries": 1,
        "status_counts": {"PASS": 1, "FAIL": 0},
        "compliance_score": {"avg": 100.0},
        "network_exposure_score": {"avg": 100.0},
        "drift_failure_rate": 0.0,
    }

    metrics = tc._extract_metrics(base_summary)

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "metrics.csv"

        # First write
        tc.write_csv(csv_path, base_summary, metrics, mode="append")
        assert csv_path.exists()
        rows = list(csv.reader(csv_path.open("r", encoding="utf-8")))
        assert len(rows) == 2  # header + 1 data row

        # Second write with identical generated_at should be a no-op
        tc.write_csv(csv_path, base_summary, metrics, mode="append")
        rows2 = list(csv.reader(csv_path.open("r", encoding="utf-8")))
        assert len(rows2) == 2  # still header + 1 data row

        # Change generated_at and append again -> should add a new row
        updated_summary = dict(base_summary)
        updated_summary["generated_at"] = "2025-11-14T07:05:00+00:00"
        updated_metrics = tc._extract_metrics(updated_summary)
        tc.write_csv(csv_path, updated_summary, updated_metrics, mode="append")
        rows3 = list(csv.reader(csv_path.open("r", encoding="utf-8")))
        assert len(rows3) == 3  # header + 2 data rows


def test_telemetry_consumer_overwrite_mode():
    # Load the telemetry_consumer module from scripts/
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "telemetry_consumer.py"
    tc = load_module_from_path("telemetry_consumer", mod_path)

    summary_a = {
        "generated_at": "2025-11-14T07:10:00+00:00",
        "entries": 2,
        "status_counts": {"PASS": 1, "FAIL": 1},
        "compliance_score": {"avg": 50.0},
        "network_exposure_score": {"avg": 80.0},
        "drift_failure_rate": 0.5,
    }
    metrics_a = tc._extract_metrics(summary_a)

    summary_b = dict(summary_a)
    summary_b["generated_at"] = "2025-11-14T07:15:00+00:00"
    metrics_b = tc._extract_metrics(summary_b)

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = Path(tmpdir) / "metrics.csv"

        tc.write_csv(csv_path, summary_a, metrics_a, mode="append")
        tc.write_csv(csv_path, summary_b, metrics_b, mode="append")
        rows = list(csv.reader(csv_path.open("r", encoding="utf-8")))
        assert len(rows) == 3  # header + 2 data rows

        # Overwrite should replace with a single row (latest snapshot only)
        tc.write_csv(csv_path, summary_b, metrics_b, mode="overwrite")
        rows2 = list(csv.reader(csv_path.open("r", encoding="utf-8")))
        assert len(rows2) == 2  # header + 1 data row
        assert rows2[1][0] == summary_b["generated_at"]

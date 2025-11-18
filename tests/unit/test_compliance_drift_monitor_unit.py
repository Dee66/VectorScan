import importlib.util
import json
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace


def load_module_from_path(name: str, path: Path) -> ModuleType:
    spec_opt = importlib.util.spec_from_file_location(name, str(path))
    assert spec_opt is not None, "Failed to create spec for module"
    spec = spec_opt
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None, "Spec has no loader"
    loader.exec_module(module)
    return module


def test_evaluate_drift_within_threshold():
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "compliance_drift_monitor.py"
    monitor = load_module_from_path("compliance_drift_monitor", mod_path)

    baseline = {"compliance_score": {"avg": 95.0}}
    current = {"compliance_score": {"avg": 97.5}}

    ok, delta, base_score, curr_score = monitor.evaluate_drift(baseline, current, 5.0)
    assert ok is True
    assert abs(delta - 2.5) < 1e-6
    assert base_score == 95.0
    assert curr_score == 97.5


def test_evaluate_drift_flags_large_delta():
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "compliance_drift_monitor.py"
    monitor = load_module_from_path("compliance_drift_monitor", mod_path)

    baseline = {"compliance_score": {"avg": 95.0}}
    current = {"compliance_score": {"avg": 80.0}}

    ok, delta, *_ = monitor.evaluate_drift(baseline, current, 5.0)
    assert ok is False
    assert abs(delta + 15.0) < 1e-6


def test_main_detects_drift(monkeypatch, capsys):
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "compliance_drift_monitor.py"
    monitor = load_module_from_path("compliance_drift_monitor", mod_path)

    baseline_summary = {"compliance_score": {"avg": 96.0}}
    current_summary = {"compliance_score": {"avg": 88.0}}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        baseline_path = tmp / "baseline.json"
        current_path = tmp / "current.json"
        baseline_path.write_text(json.dumps(baseline_summary), encoding="utf-8")
        current_path.write_text(json.dumps(current_summary), encoding="utf-8")

        args = SimpleNamespace(baseline=baseline_path, current=current_path, threshold=5.0)
        monkeypatch.setattr(monitor, "parse_args", lambda: args)

        rc = monitor.main()
        assert rc == 1
        out = capsys.readouterr().out
        assert "Drift detected" in out
        assert "baseline=96.00" in out
        assert "current=88.00" in out

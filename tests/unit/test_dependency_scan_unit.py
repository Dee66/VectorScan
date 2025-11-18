from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.dependency_vulnerability_scan as dep_scan


def _write_requirements(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


def test_dependency_scan_passes_when_no_vulnerabilities(tmp_path, monkeypatch, capsys):
    req = _write_requirements(tmp_path / "requirements.txt", "demo==1.0.0\n")

    def fake_query(payload):
        assert payload["queries"][0]["package"]["name"] == "demo"
        return {"results": [{"vulns": []}]}

    monkeypatch.setattr(dep_scan, "_query_osv", fake_query)

    exit_code = dep_scan.main(["--requirements", str(req), "--format", "text"])
    captured = capsys.readouterr()

    assert exit_code == dep_scan.EXIT_OK
    assert "No known vulnerabilities" in captured.out


def test_dependency_scan_reports_findings(tmp_path, monkeypatch, capsys):
    req = _write_requirements(tmp_path / "requirements.txt", "demo==2.0.0\n")

    def fake_query(payload):
        return {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "OSV-2024-XYZ",
                            "summary": "Demo vulnerability",
                            "severity": [{"score": "HIGH"}],
                        }
                    ]
                }
            ]
        }

    monkeypatch.setattr(dep_scan, "_query_osv", fake_query)

    exit_code = dep_scan.main(["--requirements", str(req), "--format", "text"])
    captured = capsys.readouterr()

    assert exit_code == dep_scan.EXIT_VULNERABILITIES_FOUND
    assert "OSV-2024-XYZ" in captured.out

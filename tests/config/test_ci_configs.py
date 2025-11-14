from pathlib import Path


def test_pyproject_toml_exists_and_has_tools():
    root = Path(__file__).resolve().parents[2]
    pyproject = root / "pyproject.toml"
    assert pyproject.exists(), "pyproject.toml is missing"
    content = pyproject.read_text(encoding="utf-8")
    assert "[tool.black]" in content
    assert "[tool.ruff]" in content


def test_mypy_ini_exists_and_settings():
    root = Path(__file__).resolve().parents[2]
    mypy = root / "mypy.ini"
    assert mypy.exists(), "mypy.ini is missing"
    content = mypy.read_text(encoding="utf-8")
    assert "[mypy]" in content
    assert "ignore_missing_imports = True" in content


def test_workflow_exists():
    root = Path(__file__).resolve().parents[2]
    wf = root / ".github" / "workflows" / "lint.yml"
    assert wf.exists(), "CI lint workflow is missing"
    content = wf.read_text(encoding="utf-8")
    assert "ruff" in content
    assert "black" in content
    assert "mypy" in content

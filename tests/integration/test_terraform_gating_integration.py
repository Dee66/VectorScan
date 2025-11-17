import sys
import json
import subprocess
from pathlib import Path

import pytest


def _extract_first_json(text: str) -> dict:
    """Extract the first top-level JSON object from mixed logs + JSON output.
    Uses brace-depth scanning with basic string handling to find the end of the
    first JSON object that starts at the first '{'.
    """
    s = text.strip()
    start = s.find("{")
    if start == -1:
        raise ValueError("No JSON object found in output")

    depth = 0
    in_string = False
    escape = False
    end = None
    for i in range(start, len(s)):
        ch = s[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        else:
            if ch == '"':
                in_string = True
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
    if end is None:
        raise ValueError("Could not determine end of JSON object")
    candidate = s[start : end + 1]
    return json.loads(candidate)


@pytest.mark.integration
@pytest.mark.parametrize("fixture", ["tfplan-pass.json", "tfplan-fail.json"]) 
def test_terraform_tests_gating_runs(fixture):
    repo_root = Path(__file__).resolve().parents[2]
    cli = repo_root / "tools" / "vectorscan" / "vectorscan.py"
    plan = repo_root / "examples" / "aws-pgvector-rag" / fixture

    cmd = [sys.executable, str(cli), str(plan), "--terraform-tests", "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # CLI returns 0 on PASS, 3 on FAIL; both are acceptable here
    assert result.returncode in (0, 3)

    combined = (result.stdout or "") + (result.stderr or "")
    data = _extract_first_json(combined)

    tf = data.get("terraform_tests", {})
    assert tf.get("status") == "PASS"
    assert tf.get("strategy") in {"modern", "legacy"}
    # Binary path should exist
    b = tf.get("binary")
    assert b and Path(b).exists()
    # Version should look like terraform semantic version
    v = tf.get("version")
    assert isinstance(v, str) and v[0].isdigit()

SECTION 1 — FOUNDATIONS (before writing any tests)

- [ ] Ensure project supports Python 3.9–3.12
- [ ] Confirm CLI entry point: vectorscan.py is importable and executable
- [ ] Ensure output modes: human, JSON, YAML ledger
- [ ] Confirm exit codes match spec (0, 3, 2, 5)
- [ ] Ensure internal functions accept JSON-loaded plans
- [ ] Prepare mechanism for deterministic timestamps (injectable clock)
- [ ] Disable network calls by default
- [ ] Add environment variable toggle for Terraform auto-download

These must be done first so that tests do not break later.

SECTION 2 — TEST DIRECTORY & BOILERPLATE CREATION

 - [ ] Create tests/
 - [ ] Create tests/fixtures/
 - [ ] Create tests/golden/
 - [ ] Add empty placeholder files for all required fixtures and goldens:

Fixtures
- [ ] tfplan_pass.json
- [ ] tfplan_fail.json
- [ ] tfplan_invalid.json
- [ ] tfplan_iam_drift.json
- [ ] tfplan_missing_tags.json
- [ ] tfplan_no_encryption.json

Golden files
 - [ ] pass_output.json
 - [ ] fail_output.json
 - [ ] iam_drift_output.json
 - [ ] audit_ledger.yaml

Test files
 - [ ] test_cli.py
 - [ ] test_end_to_end.py
 - [ ] test_json_output.py
 - [ ] test_iam_drift.py
 - [ ] test_audit_ledger.py
 - [ ] test_error_handling.py
 - [ ] test_lead_capture.py
 - [ ] test_terraform_integration.py

SECTION 3 — CLI ENTRY TESTS

 - [ ] Implement argument parser smoke tests
 - [ ] Test missing file
 - [ ] Test invalid file
 - [ ] Test invalid JSON fixture
 - [ ] Test default mode (human output)
 - [ ] Test JSON mode and YAML ledger output flags
 - [ ] Assert correct exit codes:
 - [ ] Valid plan → 0
 - [ ] Violations → 3
 - [ ] Invalid JSON → 2
 - [ ] Terraform error → 5

SECTION 4 — FUNCTIONAL POLICY TESTS

4.1 Encryption Mandate
 - [ ] Load tfplan_no_encryption.json
 - [ ] Verify violation contains P-SEC-001
 - [ ] Verify explicit human-readable message
 - [ ] Verify compliance score deduction
 - [ ] Verify JSON output contains violation block

4.2 Mandatory Tagging
 - [ ] Load tfplan_missing_tags.json
 - [ ] Missing CostCenter triggers violation
 - [ ] Missing Project triggers violation
 - [ ] JSON output lists resource addresses
 - [ ] JSON output counts affected resources

SECTION 5 — IAM DRIFT TESTS

 - [ ] Load tfplan_iam_drift.json
 - [ ] Generate drift report
 - [ ] Ensure risky actions detected
 - [ ] Ensure severity map present
 - [ ] Penalty applies only when flag set
 - [ ] Validate JSON structure:

{
iam_drift_report: {...},
metrics: {
iam_drift: float,
compliance_score: float
}
}

SECTION 6 — AUDIT LEDGER TESTS

Using same iam drift fixture and golden ledger.

 - [ ] Generate ledger output
 - [ ] Ensure deterministic keys:
environment
scan_timestamp
input_file
violations
iam_drift
evidence
terraform_test_results (optional)

- [ ]  Validate YAML structure
- [ ] Validate file creation and directory auto-creation
- [ ] Compare ledger to golden YAML

SECTION 7 — JSON OUTPUT TESTS

- [ ]  Validate JSON syntax
- [ ] Validate presence of keys:
violations
metrics
timestamp
input_file
compliance_score

- [ ]  Compare pass output to pass_output.json
- [ ] Compare fail output to fail_output.json
- [ ] Compare iam drift output to iam_drift_output.json
- [ ] Enforce schema stability (no extra keys without versioning)

SECTION 8 — ERROR HANDLING TESTS

Fixtures: invalid JSON, nonexistent file.

 Missing file → exit code 2
 Invalid JSON → exit code 2
 Permission denied (monkeypatch open)
 CLI prints safe error message
 No unhandled exceptions

SECTION 9 — LEAD CAPTURE TESTS

Local Capture
- [ ]  Ensure capture directory exists
 - [ ] Write capture file
 - [ ] JSON contains email and results
 - [ ] Timestamp included

Remote Capture (mocked)
 - [ ] Mock endpoint returns 200 → success
 - [ ] Validate POST payload exactly
 - [ ] 400/500 error → graceful degradation
 - [ ] Remote capture only triggers when endpoint provided

SECTION 10 — TERRAFORM INTEGRATION TESTS

Condition: Terraform >= 1.13.5 OR auto-download flag set.

 - [ ] Detect local Terraform binary
 - [ ] Validate auto-download logic
 - [ ] Validate version detection
 - [ ] Validate stdout/stderr truncation
 - [ ] Validate JSON structure under terraform_tests:
status
version
binary_source
stdout
stderr

 - [ ] Handle Terraform errors → exit code 5

SECTION 11 — END-TO-END SCENARIOS

- [ ] Scenario A — PASS
 Run CLI on pass fixture
 Expect exit code 0
 Human output template correct
 JSON output matches golden pass file

- [ ] Scenario B — FAIL
 Run CLI on failing fixture
 Expect exit code 3
 Violations enumerated
 JSON output matches golden fail file

- [ ] Scenario C — IAM Drift + Penalty
 Run CLI with penalty flag
 Score reduced accordingly

- [ ] Scenario D — Audit Ledger
 Run CLI with -o output.yaml
 Output matches golden ledger

SECTION 12 — PERFORMANCE TESTS

- [ ]  Ensure processing time < 200ms for 100 KB plan
- [ ] Ensure no memory leakage (tracemalloc)
- [ ] Validate large plans up to 5 MB
- [ ] Ensure stable performance across Python versions

SECTION 13 — STATIC ANALYSIS & LINTING

- [ ]  Add mypy config
 - [ ] Add flake8 or ruff
 - [ ] Add black formatting
 - [ ] Add isort (optional)
 - [ ] Ensure static checks run in CI pipeline

SECTION 14 — CI/CD PIPELINE CHECKLIST

 - [ ] Run pytest full suite
 - [ ] Run Terraform tests when enabled
 - [ ] Run linting
 - [ ] Run type checks
 - [ ] Compare golden JSON and YAML files
 - [ ] Upload test coverage reports
 - [ ] Fail build if schemas diverge
 - [ ] Validate reproducible outputs (no timestamp drift)

SECTION 15 — COPILOT GENERATION CHECKLIST

When invoking Copilot, ensure it:

 - [ ] Creates missing files automatically
 - [ ] Fills all fixtures with minimal valid JSON
 - [ ] Generates golden files
 - [ ] Writes full pytest tests
 - [ ] Stubs missing internal APIs
 - [ ] Enforces deterministic outputs
 - [ ] Integrates linting/type checks
 - [ ] Produces CI workflow YAML
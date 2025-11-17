SECTION 1 — FOUNDATIONS (before writing any tests)

- [ ] Ensure project supports Python 3.9–3.12
- [ ] Confirm CLI entry point: vectorscan.py is importable and executable
- [ ] Ensure output modes: human, JSON, YAML ledger
- [ ] Confirm exit codes match spec (0, 2, 3, 4, 5, 6)
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
 - [ ] Missing file / invalid JSON → 2
 - [ ] Policy pack load error (corrupted/missing Rego bundle) → 4
 - [ ] Terraform test failure (tests execute but fail) → 5
 - [ ] Terraform automation error (download/execution failure) → 6

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
- [x] Validate `environment_metadata` exists and includes platform, platform_release, python_version, python_implementation, terraform_version, terraform_source, strict_mode, and offline_mode values (override via `VSCAN_ENV_*` for deterministic goldens)

- [ ]  Validate YAML structure
- [ ] Validate file creation and directory auto-creation
- [ ] Compare ledger to golden YAML

SECTION 7 — JSON OUTPUT TESTS

- [ ]  Validate JSON syntax
- [x] Validate presence of keys:
violations
metrics
timestamp
input_file
compliance_score
environment (platform/platform_release/python_version/python_implementation/terraform_version/terraform_source/vectorscan_version/strict_mode/offline_mode)

- [ ]  Compare pass output to pass_output.json
- [ ] Compare fail output to fail_output.json
- [ ] Compare iam drift output to iam_drift_output.json
- [ ] Enforce schema stability (no extra keys without versioning)
- [x] Validate `VSCAN_ENV_*` overrides (platform, release, python, terraform, vectorscan_version) surface in the `environment` block for deterministic CI fixtures

SECTION 8 — ERROR HANDLING TESTS

Fixtures: invalid JSON, nonexistent file.

 Missing file → exit code 2
 Invalid JSON → exit code 2
 Policy pack load failure (tampered bundle) → exit code 4
- Offline mode (VSCAN_OFFLINE=1) → disables telemetry scripts, lead capture, Terraform auto-downloads, and StatsD without changing CLI output
- [x] StatsD toggle validation (`--disable-statsd`, `VSCAN_DISABLE_STATSD`, `VSCAN_ENABLE_STATSD`) → telemetry consumer respects explicit toggles even when a host is configured, emitting rich packets only when enabled
 Permission denied (monkeypatch open)
 CLI prints safe error message
 No unhandled exceptions

- [ ] Strict mode validation
  - [ ] Missing deterministic clock overrides triggers exit code 6 (CONFIG_ERROR)
  - [ ] Any `policy_errors` cause strict failure even when other policies pass
  - [ ] Clean runs under strict mode remain deterministic (no truncation, JSON stable)

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

- [ ] Handle Terraform test failures → exit code 5
- [ ] Handle Terraform automation errors (download/version/exec) → exit code 6

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
  

  SECTION 16 — INVESTIGATION PHASE VALIDATION

[ ] Validate resource traversal logic identifies all resource types, not just the ones in policies
[ ] Test behavior when tfplan.json contains unknown or new Terraform resource types
[ ] Test large, noisy plans with hundreds of resources
[ ] Validate recursive module parsing (child modules, nested modules)
[ ] Validate scanning of resources under "dynamic blocks" or computed fields
[ ] Ensure investigation logic stops early in fatal-plan cases but still prints safe output
[ ] Validate defaults in resources (e.g., missing encryption field that Terraform would fill at apply time)
[ ] Validate normalization logic for plan structures (sometimes Terraform outputs fields in different shapes)

SECTION 17 — POLICY ENGINE ROBUSTNESS TESTS

[ ] Test behavior when the policy returns malformed results
[ ] Test behavior when a policy raises an internal exception
[ ] Ensure scanner gracefully isolates individual policy failures
[ ] Add test for “no policies enabled” edge case
[ ] Add test for multiple policies triggering on same resource
[ ] Validate that violations contain stable, consistent schema for all policies
[ ] Validate corrective hints / remediation text is formatted correctly
[ ] Ensure compliance score cannot go below zero
[ ] Ensure compliance score cannot exceed 100

SECTION 18 — HUMAN OUTPUT QUALITY TESTS

[ ] Validate success message formatting
[ ] Validate alignment and indentation are stable
[ ] Validate that violation summaries never exceed line width unexpectedly
[ ] Ensure color output is disabled when piping into a file
[ ] Test terminal width variations (wide vs narrow terminals)
[ ] Validate that human-readable mode never prints stack traces
[ ] Validate that human output is always consistent (no random ordering)

SECTION 19 — DOCUMENTATION & HELP COMMAND TESTS

[ ] Validate --help displays all flags
[ ] Ensure descriptions for each flag are accurate
[ ] Validate version display (--version)
[ ] Validate no dependency on network for help text
[ ] Validate help output matches README instructions

SECTION 20 — CONFIGURATION & ENVIRONMENT TESTS

[ ] Validate behavior when HOME is unset
[ ] Validate behavior when temp directory is unwritable
[ ] Validate VSCAN_TERRAFORM_BIN override logic
[ ] Validate VSCAN_NO_COLOR disables ANSI codes
[ ] Validate config file loading if you later introduce configuration (reserved for future)

SECTION 21 — CROSS-PLATFORM COMPATIBILITY TESTS

[ ] Run tests on Linux
[ ] Run tests on macOS
[ ] Run Windows-safe subset (path handling, case sensitivity)
[ ] Validate correct handling of CRLF vs LF files
[ ] Validate Unicode paths in input files

SECTION 22 — SECURITY TESTS

[ ] Validate scanner never executes arbitrary code inside plan JSON
[ ] Validate no network calls occur unless explicitly opted in
[ ] Validate Terraform auto-download uses checksum verification
[ ] Validate subprocess calls for Terraform are sanitized and cannot escape directories
[ ] Validate no sensitive environment variables leak into logs
[ ] Validate all temporary files use secure naming (mkstemp)
[ ] Validate audit ledger cannot overwrite arbitrary system paths

SECTION 23 — REPRODUCIBILITY TESTS

[ ] Validate timestamp injection produces identical runs when fixed time is set
[ ] Validate golden file comparisons remain stable over time
[ ] Validate ordering of violations is deterministic
[ ] Validate ordering of resources is stable across runs
[ ] Validate that two identical scans produce identical JSON
[ ] Validate that ledger YAML sorting produces deterministic output

SECTION 24 — ERROR-INJECTION & CHAOS TESTING

[ ] Simulate partial tfplan files
[ ] Simulate truncated JSON
[ ] Simulate random missing fields in deeply nested structures
[ ] Simulate Terraform binary crash
[ ] Simulate Terraform returning unexpected JSON structure
[ ] Simulate disk-full condition when writing ledger
[ ] Simulate slow filesystem to ensure no timeouts or bad assumptions

SECTION 25 — LARGE-SCALE & STRESS TESTS

[ ] Test plan with 10,000+ resources
[ ] Test plan that is 10MB+
[ ] Test repeated runs 1,000 times to validate memory stability
[ ] Benchmark average investigation duration
[ ] Confirm no quadratic or exponential performance patterns

SECTION 26 — INTERNAL UTILITIES TESTS

[ ] Test file loading utility with Unicode, long paths, and odd characters
[ ] Test JSON dump helper (stable formatting)
[ ] Test timestamp helper
[ ] Test compliance score calculator
[ ] Test tagging utility
[ ] Test encryption detection utility
[ ] Test IAM drift score normalization

SECTION 27 — RELEASE VALIDATION TESTS

[ ] Validate release bundles contain required files
[ ] Validate checksum presence
[ ] Validate signature presence
[ ] Validate bundle extraction on Linux
[ ] Validate bundle extraction on macOS
[ ] Validate that bundle works without repo source (true distribution validation)

SECTION 28 — FUTURE-PROOFING TESTS (OPTIONAL BUT RECOMMENDED)

[ ] Add test for new policy addition flow
[ ] Add test ensuring backward compatible JSON schemas
[ ] Add test ensuring new policies cannot modify old policy metrics
[ ] Add test for versioning metadata in output
[ ] Add test for policy toggling logic (enable/disable)



Additional

PART 2 — Improvements to the Test Checklist

Your test checklist is absolutely insane (in a good way).
But here are the final 3 enhancements for true “industry-grade” coverage.

🔥 A. Schema Version Snapshot Tests

Add snapshot tests that fail if the schema changes without bumping schema_version.

🔥 B. Fuzz Testing (Hypothesis) for Unknown Fields

You already test unknown resource types.
Add:

fields with random nesting
random whitespace
random Unicode
unexpected list types
None/null placement


This is what made tfsec and checkov hardened tools.

🔥 C. CLI Argument Fuzz

Use Hypothesis to test random combinations of:

flags

missing flags

flag order

multiple output modes

nonexistent paths

relative/absolute paths

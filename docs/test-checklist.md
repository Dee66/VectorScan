# VectorScan Test Checklist

<style>
.sc-card{border:1px solid #2f2f46;border-radius:10px;margin:1.25em 0;padding:1.15em;background:#121212;}
.sc-hero{margin:1.4em 0;padding:1.4em 1.2em;background:#121212;}
.sc-header{display:flex;justify-content:space-between;flex-wrap:wrap;gap:.75em;margin-bottom:.9em;font-size:.9em;color:#bbb;}
.sc-header a{color:#a5b4fc;font-weight:600;text-decoration:none;}
.sc-title{text-align:center;margin:0;font-size:2em;color:#fff;}
.sc-progress{text-align:center;margin:.8em 0 .9em;}
.sc-legend{font-size:.72em;display:flex;flex-wrap:wrap;gap:1.1em;margin:.9em 0 .2em;color:#bbb;}
.sc-pill{background:#181818;border:1px solid #2a2a2a;padding:.35em .55em;border-radius:6px;}
@media (max-width:760px){.sc-title{font-size:1.6em;} .sc-progress progress{width:100%!important;}}
progress::-webkit-progress-value{background:linear-gradient(90deg,#6ee7b7,#22d3ee);} 
progress::-webkit-progress-bar{background-color:#1f2937;border-radius:6px;} 
progress::-moz-progress-bar{background:linear-gradient(90deg,#6ee7b7,#22d3ee);} 
</style>

<section class="sc-card sc-hero">
   <h1 class="sc-title">VectorScan Test Checklist</h1>
  <div class="sc-progress">
    <progress id="vs-test-progress" value="0" max="100" aria-label="VectorScan test coverage" style="width:60%;height:18px;"></progress>
    <div id="vs-test-progress-label">60% Complete (147/243)</div>
  </div>
   <div class="sc-legend">
      <span class="sc-pill">🟩 Complete</span>
      <span class="sc-pill">🟥 Remaining</span>
   </div>
</section>

This living checklist mirrors the structure of the implementation tracker and keeps every VectorScan test objective visible in one place. Each section below is actionable—mark items complete only when automated tests and documentation conclusively cover the described behavior.

## Section 1 – Foundations (Before Writing Any Tests)
- [x] Ensure project supports Python 3.9–3.12. _(See `docs/python-compatibility.md`, `noxfile.py`, `tests/unit/test_python_compat_unit.py`, `tests/unit/test_python_version_guard.py`.)_
- [x] Confirm CLI entry point (`vectorscan.py`) is importable and executable. _(See `tests/e2e/test_full_user_journey.py`, `tests/test_cli.py`, direct `vectorscan.main` calls.)_
- [x] Ensure human, JSON, and YAML ledger output modes work. _(Covered by `tests/test_end_to_end_scenarios.py`, `tests/test_json_output.py`, `tests/test_audit_ledger.py`.)_
- [x] Validate streaming plan parser feature flag: fast-path iterator is default and automatically falls back to the legacy loader when `VSCAN_STREAMING_DISABLE=1` or parser errors occur. _(See `tests/unit/test_plan_streaming_toggle.py`.)_
- [x] Confirm exit codes match spec (0, 2, 3, 4, 5, 6, 10). _(See `tests/test_cli.py`, `tests/test_error_handling.py`, `tests/test_terraform_cli.py`, `tests/test_json_output.py`.)_
- [x] Ensure internal functions accept JSON-loaded plans. _(Property tests in `tests/unit/test_vectorscan_unit.py` exercise iterators/policies on raw JSON payloads.)_
- [x] Provide an injectable clock for deterministic timestamps. _(All golden comparisons rely on `VSCAN_CLOCK_*` env overrides; see `tests/test_json_output.py` & `tests/test_audit_ledger.py`.)_
- [x] Disable network calls by default. _(Covered by `tests/unit/test_offline_mode_unit.py`, `tests/unit/test_lead_capture_unit.py::test_lead_capture_skipped_in_offline_mode`, and CLI flag coverage in `tests/unit/test_vectorscan.py`.)_
- [x] Add an environment variable toggle for Terraform auto-download. _(Validated via `tests/unit/test_vectorscan_unit.py::test_terraform_auto_download_*` and `tests/unit/test_terraform_chaos_unit.py`.)_

> These foundation items must be completed first so downstream tests stay reliable.

## Section 2 – Test Directory & Boilerplate Creation
- [x] Create `tests/`.
- [x] Create `tests/fixtures/`.
- [x] Create `tests/golden/`.
- [x] Add placeholder files for required fixtures and goldens (populated under `tests/fixtures` & `tests/golden`).

### Fixture Files
- [x] `tfplan_pass.json`
- [x] `tfplan_fail.json`
- [x] `tfplan_invalid.json`
- [x] `tfplan_iam_drift.json`
- [x] `tfplan_missing_tags.json`
- [x] `tfplan_no_encryption.json`
- [x] `tfplan_compare_old.json`
- [x] `tfplan_compare_new.json`

### Golden Files
- [x] `pass_output.json`
- [x] `fail_output.json`
- [x] `iam_drift_output.json`
- [x] `audit_ledger.yaml`
- [x] `plan_compare_output.json` (captures `plan_evolution` snapshot from `vectorscan --compare`).

### Core Test Modules
- [x] `tests/test_cli.py`
- [x] `tests/test_end_to_end_scenarios.py` (supersedes the earlier `test_end_to_end.py` placeholder).
- [x] `tests/test_json_output.py`
- [x] `tests/test_iam_drift.py`
- [x] `tests/test_audit_ledger.py`
- [x] `tests/test_error_handling.py`
- [x] `tests/test_lead_capture_cli.py` (covers CLI + remote/local capture flows).
- [x] `tests/test_terraform_cli.py` (Terraform integration behavior & exit codes).

## Section 3 – CLI Entry Tests
- [x] Implement argument parser smoke tests. _(Implicit throughout `tests/test_cli.py`, `tests/test_json_output.py`, `tests/test_error_handling.py`.)_
- [x] Test missing file handling. _(See `tests/test_error_handling.py::test_missing_file_exit_code`.)_
- [x] Test invalid file path handling. _(Missing/relative path coverage in `tests/test_error_handling.py`.)_
- [x] Test invalid JSON fixture handling. _(See `tests/test_error_handling.py::test_invalid_json_exit_code`.)_
- [x] Test default (human) output mode. _(Validated in `tests/test_end_to_end_scenarios.py` + `tests/e2e/test_full_user_journey.py`.)_
- [x] Test JSON mode and YAML ledger output flags. _(JSON snapshots in `tests/test_json_output.py`; ledger flag via `tests/test_audit_ledger.py`.)_
- [x] Test `--diff` plan diff output. _(Snapshots in `tests/test_json_output.py::test_diff_mode_snapshots`.)_
- [x] Test `--explain` narrative block. _(Snapshots in `tests/test_json_output.py::test_explain_mode_snapshots`.)_
- [x] Test `--resource` scoped execution (exact, suffix, ambiguous cases). _(See `tests/test_json_output.py::test_resource_mode_snapshots` and scope error test.)_
- [x] Test `--preview-vectorguard` banner + exit code 10 even when scan would otherwise PASS/FAIL. _(Covered by `tests/test_json_output.py::test_preview_mode_snapshot` and `tests/test_cli.py::test_cli_preview_manifest_skip_verify`.)_
- [x] Test `--gha` mode (forces JSON, disables color, sorts keys for Actions logs). _(See `tests/test_cli.py::test_cli_github_action_mode_forces_json_sorted_output`.)_
- [x] Test `--compare old.json new.json` and verify `plan_evolution` JSON, human summary, and exit codes (0/2) when encryption downgrades are detected. _(Snapshots in `tests/test_json_output.py::test_compare_mode_snapshot`.)_
- [x] Assert exit codes: valid plan → 0. _(Smoke tests across CLI/e2e suites.)_
- [x] Assert exit codes: violations → 3. _(See `tests/test_cli.py`, `tests/test_end_to_end_scenarios.py`.)_
- [x] Assert exit codes: missing file or invalid JSON → 2. _(See `tests/test_error_handling.py`.)_
- [x] Assert exit codes: policy pack load error (corrupted/missing Rego bundle) → 4. _(See `tests/test_error_handling.py::test_policy_pack_missing_exit_code`.)_
- [x] Assert exit codes: Terraform test failure (tests execute but fail) → 5. _(See `tests/test_terraform_cli.py::test_cli_exit_code_5_when_terraform_tests_fail`.)_
- [x] Assert exit codes: Terraform automation error (download/execution failure) → 6. _(See `tests/test_terraform_cli.py::test_cli_exit_code_6_when_terraform_tests_error`.)_
- [x] Assert exit codes: preview mode (`--preview-vectorguard`) always returns 10 with deterministic banner. _(See `tests/test_json_output.py::test_preview_mode_snapshot` and `tests/test_cli.py::test_cli_preview_manifest_skip_verify`.)_

## Section 4 – Functional Policy Tests
### 4.1 Encryption Mandate (P-SEC-001)
- [x] Load `tfplan_no_encryption.json` fixture. _(Covered by `tests/test_json_output.py::test_tfplan_no_encryption_enforces_p_sec_001`.)_
- [x] Verify violation contains `P-SEC-001`. _(See same test.)_
- [x] Verify explicit human-readable message. _(See same test.)_
- [x] Verify compliance score deduction. _(See same test.)_
- [x] Verify JSON output contains the violation block. _(See same test.)_

### 4.2 Mandatory Tagging (P-FIN-001)
- [x] Load `tfplan_missing_tags.json` fixture. _(Covered by `tests/test_json_output.py::test_tfplan_missing_tags_enforces_p_fin_001`.)_
- [x] Verify missing `CostCenter` triggers a violation. _(See same test.)_
- [x] Verify missing `Project` triggers a violation. _(See same test.)_
- [x] Ensure JSON output lists resource addresses. _(See same test.)_
- [x] Ensure JSON output counts affected resources. _(See same test.)_
- [x] Ensure `violations_struct` includes remediation blocks (summary, docs, HCL examples, completeness score) for both policies. _(See same test.)_

## Section 5 – IAM Drift Tests
- [x] Load `tfplan_iam_drift.json`. _(Used across `tests/test_json_output.py`, `tests/test_end_to_end_scenarios.py`, `tests/test_iam_drift.py`.)_
- [x] Generate drift report. _(Assertions in `tests/test_iam_drift.py`.)_
- [x] Ensure risky IAM actions are detected. _(See `tests/unit/test_iam_drift_unit.py::test_iam_drift_detects_risky_added_action`.)_
- [x] Ensure severity map is present. _(Golden comparisons + `tests/test_end_to_end_scenarios.py` verify `violation_severity_summary`.)_
- [x] Ensure penalty applies only when the IAM drift flag is set. _(Scenario C in `tests/test_end_to_end_scenarios.py`.)_
- [x] Validate JSON structure for the IAM drift report and metrics block:
  ```json
  {
    "iam_drift_report": { ... },
    "metrics": {
      "iam_drift": float,
      "compliance_score": float
    }
  }
  ``` _(Snapshot-enforced via `tests/test_json_output.py::test_iam_drift_matches_golden_and_penalty`.)_

## Section 6 – Audit Ledger Tests
- [x] Generate ledger output via `run_scan.sh -o`. _(All ledger tests invoke the shell wrapper.)_
- [x] Ensure deterministic keys include:
  - [x] `environment`
  - [x] `scan_timestamp`
  - [x] `input_file`
  - [x] `violations`
  - [x] `iam_drift`
  - [x] `evidence`
  - [x] `terraform_test_results` (optional)
- [x] Validate `environment_metadata` includes platform, platform_release, python_version, python_implementation, terraform_version, terraform_source, strict_mode, and offline_mode (override via `VSCAN_ENV_*`).
- [x] Validate YAML structure. _(See `tests/test_audit_ledger.py::test_audit_ledger_yaml_structure`.)_
- [x] Validate file creation and directory auto-creation. _(See `tests/test_audit_ledger.py::test_audit_ledger_creates_missing_subdirectories`.)_
- [x] Compare ledger to golden YAML.
- [x] Assert `smell_report` block exists and mirrors the CLI payload. _(See `tests/test_audit_ledger.py::test_audit_ledger_smell_report_block`.)_
  - [x] Validate YAML structure for smell report.
  - [x] Validate file creation and directory auto-creation for smell report runs.
  - [x] Assert smell report exposes level/summary/finding_count.
- [x] Ensure the ledger mirrors `scan_duration_ms`, `parser_mode`, and `resource_count` exactly as emitted by the CLI metrics block.

## Section 7 – JSON Output Tests
- [x] Validate JSON syntax for every CLI mode. _(CLI exercised via `tests/test_json_output.py`, `tests/test_cli.py`, `tests/test_end_to_end_scenarios.py`.)_
- [x] Validate presence of required keys: `violations`, `metrics`, `timestamp`, `input_file`, `compliance_score`, and `environment` (platform, platform_release, python_version, python_implementation, terraform_version, terraform_source, vectorscan_version, strict_mode, offline_mode).
- [x] Compare PASS output to `pass_output.json` golden.
- [x] Compare FAIL output to `fail_output.json` golden.
- [x] Compare IAM drift output to `iam_drift_output.json` golden.
- [x] Enforce schema stability (no new keys without versioning). _(Snapshot suite in `tests/test_json_output.py`.)_
- [x] Validate `smell_report` presence, stats (module depth, for_each count, KMS gaps, IAM bulk metrics, change totals), and at least one smell entry in FAIL fixtures. _(Unit coverage in `tests/unit/test_plan_smell_unit.py` + ledger assertions.)_
- [x] Validate `plan_evolution` block (old/new summaries, delta math, downgraded encryption evidence, summary lines) via `plan_compare_output.json`. _(See `tests/test_json_output.py::test_compare_mode_snapshot`.)_
- [x] Validate `VSCAN_ENV_*` overrides surface in the `environment` block for deterministic CI fixtures.
- [x] Validate preview snapshots cover `preview_generated`, `preview_policies`, and `preview_manifest.signature/verified` with exit code 10. _(See `tests/test_json_output.py::test_preview_mode_snapshot`.)_
- [x] Validate `--gha` snapshots enforce `gha_mode=true`, disable color, and sort JSON keys. _(See `tests/test_cli.py::test_cli_github_action_mode_forces_json_sorted_output`.)_
- [x] Validate `policy_manifest` block includes `policy_version`, `policy_pack_hash`, `policy_source_url`, `policy_count`, and signed/verified flags across PASS/FAIL fixtures.
- [x] Validate runtime metrics block includes `scan_duration_ms`, `parser_mode`, and `resource_count` (streaming vs legacy observability).

## Section 8 – Error Handling Tests
- [x] Missing file triggers exit code 2. _(See `tests/test_error_handling.py::test_missing_file_exit_code`.)_
- [x] Invalid JSON triggers exit code 2. _(See `tests/test_error_handling.py::test_invalid_json_exit_code`.)_
- [x] Policy pack load failure (tampered bundle) triggers exit code 4. _(See `tests/test_error_handling.py::test_policy_pack_missing_exit_code`.)_
- [x] Default offline enforcement (implicit, `VSCAN_OFFLINE=1`, `VSCAN_ALLOW_NETWORK=0`) disables telemetry scripts, lead capture, Terraform auto-downloads, and StatsD until `VSCAN_ALLOW_NETWORK=1` or `--allow-network` is provided. _(Covered by `tests/unit/test_offline_mode_unit.py` + `tests/unit/test_lead_capture_unit.py::test_lead_capture_skipped_in_offline_mode`.)_
- [x] Offline strict errors (`VSCAN_OFFLINE=1` + missing deterministic clock) return exit code 6 when strict requirements are violated (e.g., Terraform auto-download blocked, strict policy errors). _(See `tests/test_strict_mode_cli.py::test_strict_mode_requires_deterministic_clock`.)_
- [x] Validate StatsD toggle (`--disable-statsd`, `VSCAN_DISABLE_STATSD`, `VSCAN_ENABLE_STATSD`) so telemetry consumer emits packets only when enabled. _(See `tests/unit/test_telemetry_pipeline_unit.py` and `tests/unit/test_telemetry_statsd_unit.py`.)_
- [x] Validate preview manifest overrides: `VSCAN_PREVIEW_MANIFEST` for alternate manifests and `VSCAN_PREVIEW_SKIP_VERIFY=1` for dev/testing (prod must fail on mismatch).
- [x] Permission denied scenarios (monkeypatch `open`) surface safe error messages. _(Covered by `tests/unit/test_vectorscan_unit.py::test_permission_denied_plan_read`.)_
- [x] CLI never throws unhandled exceptions. _(Covered by `tests/unit/test_cli_fuzz_unit.py::test_cli_fuzz_no_crash` running random flag combos.)_
- [x] Strict mode validation – missing deterministic clock overrides trigger exit code 6.
- [x] Strict mode validation – any `policy_errors` cause strict failure even when other policies pass.
- [x] Strict mode validation – clean runs remain deterministic (no truncation, JSON stable). _(All three covered in `tests/test_strict_mode_cli.py`.)_

## Section 9 – Lead Capture Tests
### Local Capture
- [x] Ensure capture directory exists.
- [x] Write capture file.
- [x] Ensure JSON captures email and scan results.
- [x] Ensure timestamps are included.

### Remote Capture (Mocked)
- [x] Mock endpoint returns 200 → success path.
- [x] Validate POST payload exactly.
- [x] 400/500 error produces graceful degradation.
- [x] Remote capture triggers only when endpoint is provided.

## Section 10 – Terraform Integration Tests (Terraform ≥ 1.13.5 or Auto-Download Enabled)
- [x] Detect local Terraform binary.
- [x] Validate auto-download logic now requires `VSCAN_ALLOW_TERRAFORM_DOWNLOAD=1` (or legacy `VSCAN_TERRAFORM_AUTO_DOWNLOAD=1`) plus network opt-in, and defaults to skipping downloads otherwise.
- [x] Validate version detection.
- [x] Validate stdout/stderr truncation.
- [x] Validate JSON structure under `terraform_tests` (status, version, binary_source, stdout, stderr).
- [x] Terraform test failures return exit code 5.
- [x] Terraform automation errors (download/version/exec) return exit code 6.

## Section 11 – End-to-End Scenarios
- [x] Scenario A (PASS): run CLI on pass fixture, expect exit code 0, validated human + JSON outputs.
- [x] Scenario B (FAIL): run CLI on fail fixture, expect exit code 3, ensure violations enumerated and JSON matches golden.
- [x] Scenario C (IAM drift + penalty): run CLI with penalty flag, ensure score reduced appropriately.
- [x] Scenario D (Audit ledger): run CLI with `-o output.yaml`, ensure ledger matches golden.

## Section 12 – Performance Tests
- [x] Ensure processing time < 200ms for 100 KB plan.
- [x] Ensure no memory leakage (tracemalloc).
- [x] Validate large plans up to 5 MB.
- [x] Ensure stable performance across Python versions.

## Section 13 – Static Analysis & Linting
- [x] Add mypy configuration.
- [x] Add Ruff (or flake8) configuration.
- [x] Add Black formatting.
- [x] Add isort (optional but enforced here).
- [x] Ensure static checks run in CI pipeline.

## Section 14 – CI/CD Pipeline Checklist
 - [x] Run full pytest suite in CI.
 - [x] Run Terraform tests when enabled.
 - [x] Run linting.
 - [x] Run type checks. _(CI `lint` job runs `bash scripts/run_static_checks.sh`, which ends with `mypy .`.)_
- [x] Compare golden JSON and YAML files. _(CI `golden` job executes `pytest tests/test_json_output.py tests/test_end_to_end_scenarios.py::test_scenario_d_audit_ledger_matches_golden`.)_
- [x] Upload test coverage reports. _(CI `tests` job now emits `coverage.xml` and uploads per-Python artifacts.)_
- [x] Fail build if schemas diverge. _(CI `schema-guard` job regenerates `docs/output_schema.md` and fails on diffs.)_
- [x] Validate reproducible outputs (no timestamp drift). _(CI `reproducibility` job enforces identical JSON across reruns with fixed clocks.)_

## Section 15 – Copilot Generation Checklist
When invoking Copilot, ensure it:
- [ ] Creates missing files automatically.
- [ ] Fills fixtures with minimal valid JSON.
- [ ] Generates golden files.
- [ ] Writes full pytest suites.
- [ ] Stubs missing internal APIs.
- [ ] Enforces deterministic outputs.
- [ ] Integrates linting/type checks.
- [ ] Produces CI workflow YAML.

## Section 16 – Investigation Phase Validation
- [ ] Validate resource traversal logic covers all resource types, not just policy targets.
- [ ] Test behavior when `tfplan.json` contains unknown or new Terraform resource types.
- [ ] Test large, noisy plans with hundreds of resources.
- [ ] Validate recursive module parsing (child and nested modules).
- [ ] Validate scanning of resources under dynamic blocks or computed fields.
- [ ] Ensure investigation logic stops early in fatal-plan cases but still prints safe output.
- [ ] Validate defaults in resources (e.g., missing encryption fields TerraForm fills at apply time).
- [ ] Validate normalization logic for plan structures (Terraform sometimes changes field shapes).

## Section 17 – Policy Engine Robustness Tests
- [ ] Test behavior when a policy returns malformed results.
- [ ] Test behavior when a policy raises an internal exception.
- [ ] Ensure scanner gracefully isolates individual policy failures.
- [ ] Add test for "no policies enabled" edge case.
- [ ] Add test for multiple policies triggering on the same resource.
- [ ] Validate violations contain stable, consistent schemas for all policies.
- [ ] Validate corrective hints / remediation text formatting.
- [ ] Ensure compliance score never goes below zero.
- [ ] Ensure compliance score never exceeds 100.

## Section 18 – Human Output Quality Tests
- [ ] Validate success message formatting.
- [ ] Validate alignment and indentation stability.
- [ ] Validate violation summaries never exceed line width unexpectedly.
- [ ] Ensure color output is disabled when piping to files.
- [ ] Test terminal width variations (wide vs narrow).
- [ ] Validate human-readable mode never prints stack traces.
- [ ] Validate human output ordering is deterministic.

## Section 19 – Documentation & Help Command Tests
- [ ] Validate `--help` displays all flags.
- [ ] Ensure descriptions for each flag are accurate.
- [ ] Validate version display (`--version`).
- [ ] Validate no network dependency for help text.
- [ ] Validate help output matches README instructions.

## Section 20 – Configuration & Environment Tests
- [ ] Validate behavior when `HOME` is unset.
- [ ] Validate behavior when temp directory is unwritable.
- [ ] Validate `VSCAN_TERRAFORM_BIN` override logic.
- [ ] Validate `VSCAN_NO_COLOR` disables ANSI codes.
- [ ] Validate config file loading if/when configuration support is introduced.

## Section 21 – Cross-Platform Compatibility Tests
- [ ] Run tests on Linux.
- [ ] Run tests on macOS.
- [ ] Run Windows-safe subset (path handling, case sensitivity).
- [ ] Validate correct handling of CRLF vs LF files.
- [ ] Validate Unicode paths in input files.

## Section 22 – Security Tests
- [ ] Validate scanner never executes arbitrary code inside plan JSON.
- [ ] Validate no network calls occur unless explicitly opted in.
- [ ] Validate Terraform auto-download uses checksum verification.
- [ ] Validate Terraform subprocess calls are sanitized and cannot escape working directories.
- [ ] Validate no sensitive environment variables leak into logs.
- [ ] Validate all temporary files use secure naming (`mkstemp`).
- [ ] Validate audit ledger cannot overwrite arbitrary system paths.

## Section 23 – Reproducibility Tests
- [ ] Validate timestamp injection produces identical runs when fixed time is set.
- [ ] Validate golden file comparisons remain stable over time.
- [ ] Validate ordering of violations is deterministic.
- [ ] Validate ordering of resources is stable across runs.
- [ ] Validate two identical scans produce identical JSON.
- [ ] Validate ledger YAML sorting produces deterministic output.

## Section 24 – Error-Injection & Chaos Testing
- [ ] Simulate partial tfplan files.
- [ ] Simulate truncated JSON.
- [ ] Simulate random missing fields in deeply nested structures.
- [ ] Simulate Terraform binary crash.
- [ ] Simulate Terraform returning unexpected JSON structures.
- [ ] Simulate disk-full condition when writing ledger outputs.
- [ ] Simulate slow filesystems to ensure no timeouts or faulty assumptions.

## Section 25 – Large-Scale & Stress Tests
- [ ] Test plans with 10,000+ resources.
- [ ] Test plans that are 10 MB+.
- [ ] Test repeated runs (1,000x) to validate memory stability.
- [ ] Benchmark average investigation duration.
- [ ] Confirm no quadratic or exponential performance patterns.

## Section 26 – Internal Utilities Tests
- [ ] Test file loading utility with Unicode, long paths, and odd characters.
- [ ] Test JSON dump helper for stable formatting.
- [ ] Test timestamp helper.
- [ ] Test compliance score calculator.
- [ ] Test tagging utility.
- [ ] Test encryption detection utility.
- [ ] Test IAM drift score normalization.

## Section 27 – Release Validation Tests
- [ ] Validate release bundles contain required files.
- [ ] Validate checksum presence.
- [ ] Validate signature presence.
- [x] Ensure signed `tools/vectorscan/preview_manifest.json` ships in the bundle and is referenced in `manifest.json`/release docs (see `tests/integration/test_packaging_verification.py`).
- [ ] Validate bundle extraction on Linux.
- [ ] Validate bundle extraction on macOS.
- [ ] Validate bundle works without repo source (true distribution validation).

## Section 28 – Future-Proofing Tests (Optional but Recommended)
- [ ] Add test for new policy addition flow.
- [ ] Add test ensuring backward-compatible JSON schemas.
- [ ] Add test ensuring new policies cannot modify old policy metrics.
- [ ] Add test for versioning metadata in output.
- [ ] Add test for policy toggling logic (enable/disable).

## Part 2 – Improvements to the Test Checklist
Your test checklist is already extensive; these final upgrades push it into "built by a 10-person infosec team" territory.

- [ ] **Schema Version Snapshot Tests** – add snapshots that fail if schema changes without bumping `schema_version`.
- [ ] **Fuzz Testing for Unknown Fields** – extend Hypothesis coverage to random nesting, whitespace, Unicode, list shapes, and `None` placement.
- [ ] **CLI Argument Fuzzing** – fuzz random flag combinations (missing flags, ordering, multiple modes, nonexistent paths, relative vs absolute) to harden the parser.


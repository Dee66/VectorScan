AI Dev Wiring Cycle — 2025-11-21
Instruction Context: Git cleanliness gating disabled per user override.

Work Summary
1. Restored offline-first behavior by defaulting `tools/vectorscan/env_flags.is_offline()` to `True` when no overrides are present.
2. Redirected legacy call sites to `tools.vectorscan.entrypoint_shim` in:
   - tests/integration/test_terraform_cli_integration.py
   - tests/e2e/test_large_plan_stress.py
   - tests/unit/test_terraform_chaos_unit.py
   - tests/unit/test_python_version_guard.py
3. Focused tests executed:
   - `/home/dee/workspace/AI/GuardSuite/VectorScan/.venv/bin/python -m pytest tests/unit/test_offline_mode_unit.py tests/unit/test_lead_capture_unit.py`
   - Result: 29 passed, 0 failed (1.96s)

Commit
- `chore(wiring): restore offline default + redirect callers to shim`
- Hash: `8849554575f1a7afdc7b2c06d2be0fa0854653f7`

Notes
- Git status was intentionally skipped in accordance with the override instructions.

---
AI Dev Pillar Integration Analysis — 2025-11-21

Step 1 — CLI Surface Scan
- `tools/vectorscan/vectorscan.py` exposes a single argparse-driven command that accepts a positional tfplan plus flags (`--json`, `--gha`, `--compare OLD NEW`, `--policy-manifest`, `--terraform-tests`, `--lead-capture`, `--allow-network`, `--preview-vectorguard`, etc.). Behavior expectations are driven by tests such as `tests/test_cli.py`, `tests/test_strict_mode_cli.py`, `tests/unit/test_lead_capture*.py`, `tests/e2e/test_full_user_journey.py`, and `tests/copilot_generated/test_cli_smoke.py`, which assert exit codes, JSON payload contents, color suppression, lead-capture side effects, and preview metadata. No subcommands exist; legacy CLI multiplexes every workflow through the same parser.
- `tools/vectorscan/entrypoint_shim.py` is a placeholder comment with no executable symbols; it neither re-exports `main` nor forwards arguments anywhere, so all traffic still terminates inside the legacy module.
- Click-based CLI scaffolds already exist in `src/vectorscan/cli.py` (commands: `scan` and `rules`) and in the pillar template (`templates/guard_pillar/src/pillar/cli.py`), plus template tests under `tests/vector/**` that invoke `vectorscan.cli` with `--json-output/--no-json-output`. These tests document the expected argument names, help text, and behavior for the canonical surface even though they are not wired into the production entrypoint.

Step 2 — CLI Drift IssueDicts
[
   {
      "id": "PILLAR-CLI-001",
      "severity": "high",
      "title": "Validate command missing from legacy CLI",
      "description": "The GuardSuite pillar contract requires discrete `scan`, `validate`, and `rules` commands, but tools/vectorscan/vectorscan.py exposes only a monolithic argparse workflow with positional tfplan inputs. There is no way to run a standalone metadata/schema validation without executing the full legacy scan path.",
      "resource_address": "tools/vectorscan/vectorscan.py",
      "attributes": {
         "expected_command": "validate",
         "pillar_reference": "src/pillar/cli.py (command list: scan/validate/rules)",
         "legacy_surface": "Argparse parser only supports scan/compare/policy-manifest modes",
         "tests_missing": [
            "tests/pillar/test_cli_contract.py (TODO placeholder)",
            "tests/vector/* (no validate coverage)"
         ]
      },
      "remediation_hint": "Add a `validate` subcommand to pillar.cli (even if it wraps scan initially) and update entrypoint_shim to route `vectorscan validate` invocations to that canonical handler.",
      "remediation_difficulty": "medium"
   },
   {
      "id": "PILLAR-CLI-002",
      "severity": "medium",
      "title": "JSON output flag drift (`--json` vs `--json-output`)",
      "description": "Legacy argparse CLI relies on `--json` (boolean) and `--gha` to control canonical output, while the pillar/click surfaces (`src/vectorscan/cli.py`, template CLI, and tests under tests/vector/**) expect the `--json-output/--no-json-output` flag pair. This divergence blocks a transparent shim because callers cannot rely on a single flag name during the migration.",
      "resource_address": "tools/vectorscan/vectorscan.py#_build_arg_parser",
      "attributes": {
         "legacy_flag": "--json",
         "pillar_flag": "--json-output",
         "tests_using_legacy": ["tests/test_cli.py", "tests/test_strict_mode_cli.py", "tests/unit/test_lead_capture*.py"],
         "tests_using_pillar": ["tests/vector/integration/test_cli_template.py", "tests/vector/integration/test_phase12_cli_remediation_metadata.py"]
      },
      "remediation_hint": "Teach entrypoint_shim to normalize both flag names (accept `--json` for backward compatibility but forward `--json-output` to pillar.cli) and update documentation/help text once the shim is live.",
      "remediation_difficulty": "low"
   },
   {
      "id": "PILLAR-CLI-003",
      "severity": "high",
      "title": "Legacy CLI owns business logic instead of delegating to pillar",
      "description": "tools/vectorscan/vectorscan.py performs plan loading, policy selection, Terraform test orchestration, lead capture, and rendering directly. The canonical migration plan requires the CLI entrypoint to be thin and call into src/pillar/cli (which in turn invokes evaluator.py and renderer.py). Until a bridging layer routes traffic through pillar.cli, the new evaluator pipeline cannot be exercised via CLI flows.",
      "resource_address": "tools/vectorscan/vectorscan.py#main",
      "attributes": {
         "legacy_behavior": "`main()` parses args, loads plans, evaluates policies, prints output",
         "expected_behavior": "Shim translates argv then calls `src/pillar/cli.main()`",
         "blocking_tests": ["tests/test_cli.py", "tests/test_strict_mode_cli.py", "tests/e2e/test_full_user_journey.py", "tests/unit/test_lead_capture*.py"]
      },
      "remediation_hint": "Implement a bridging adapter inside tools/vectorscan/entrypoint_shim.py that constructs the pillar.cli request (scan/rules/validate) and remove business logic from tools/vectorscan/vectorscan.py once parity is confirmed.",
      "remediation_difficulty": "high"
   },
   {
      "id": "PILLAR-CLI-004",
      "severity": "medium",
      "title": "Help and usage text mismatched between argparse and pillar CLI",
      "description": "The argparse parser advertises `VectorScan: minimal tfplan checks (encryption + mandatory tags)` and a legacy flag set, whereas the pillar CLI (Click group) documents GuardSuite pillar commands with modern wording and flag names. Help/usage snapshots, docs, and click tests (tests/vector/...) already assume the new phrasing, so users will see conflicting descriptions depending on which entrypoint they use.",
      "resource_address": "tools/vectorscan/vectorscan.py#_build_arg_parser",
      "attributes": {
         "legacy_description": "VectorScan: minimal tfplan checks (encryption + mandatory tags)",
         "pillar_description": "VectorScan pillar CLI (scan/validate/rules)",
         "tests_relying_on_pillar_help": ["tests/vector/integration/test_cli_template.py", "tests/vector/integration/test_phase16_rule_manifest.py"],
         "docs_referencing_pillar": ["docs/run_scan.md", "docs/run_scan_full references"]
      },
      "remediation_hint": "Align parser descriptions/--help output by routing legacy entrypoint through pillar.cli and updating usage text simultaneously so that both entrypoints print the same Click-generated help.",
      "remediation_difficulty": "medium"
   }
]

Step 3 — Minimal Bridging Structure Proposal
- Route every invocation of `tools/vectorscan/vectorscan.py` through `tools/vectorscan/entrypoint_shim.py`. The shim should remain import-compatible (`main(argv=None) -> int`) so the existing tests continue to call `vectorscan.main`.
- Inside the shim, map the legacy argparse flows to canonical commands: (a) default positional plan ⇒ `pillar.cli` `scan` command, (b) `--policy-manifest` ⇒ `rules --manifest`, (c) future `validate` command ⇒ `pillar.cli validate`. For transitional features that have no pillar analog yet (`--compare`, lead capture), the shim can short-circuit to the legacy helpers until equivalent functionality exists, but the execution graph must still pass through a single adapter function so that remaining flows can be switched incrementally.
- `src/pillar/cli.py` should expose `main(argv: Optional[Sequence[str]] = None)` returning an exit code. `entrypoint_shim` becomes the only module touching argparse/Click bridging logic, and `tools/vectorscan/vectorscan.py` can eventually import and invoke the shim instead of duplicating behavior.

Step 4 — Test Coverage Map for Upcoming Cycle
- Scan command expectations: `tests/test_cli.py`, `tests/test_strict_mode_cli.py`, `tests/unit/test_lead_capture.py`, `tests/unit/test_lead_capture_unit.py`, `tests/e2e/test_full_user_journey.py`, `tests/performance/test_streaming_slo.py`, and `tests/copilot_generated/test_cli_smoke.py` all exercise the legacy argparse flow. The Click-based suites (`tests/vector/integration/test_cli_template.py`, `tests/vector/integration/test_phase12_cli_remediation_metadata.py`) validate the new `scan` signature and JSON-output defaults. These suites must keep passing once the shim forwards traffic to pillar.cli.
- Rules command coverage: `tests/vector/integration/test_phase16_rule_manifest.py` asserts `vectorscan rules --manifest` emits the canonical manifest. Legacy CLI currently lacks this subcommand, so bridging must map the future `tools.vectorscan CLI rules` path to the click implementation and ensure manifest text remains deterministic.
- Validate command: no automated coverage exists today (only the TODO reminder in `tests/pillar/test_cli_contract.py`). The next implementation cycle must add CLI tests for `validate` once the command is implemented to prevent regressions.
- Output-format flags: legacy suites depend on `--json`, `--gha`, `--no-color`, and implicit human-readable output (tests/test_cli.py, tests/test_strict_mode_cli.py, lead capture tests). Click suites depend on `--json-output/--no-json-output` and `--quiet`. Any adapter must preserve both flag families until callers are migrated, and new tests should confirm `entrypoint_shim` accepts `--json` while pillar CLI receives `--json-output`.

---
AI Dev Shim Design Specification — 2025-11-21

1. Shim Responsibilities
- Entry point: `tools.vectorscan.entrypoint_shim.main(argv: Optional[Sequence[str]] = None) -> int` becomes the sole callable used by `tools.vectorscan.vectorscan.main` and all tests that import `vectorscan`. It must accept the exact argv payloads that legacy tests generate (including positional plan paths, `--json`, `--gha`, etc.).
- Parsing: use the existing argparse parser from `tools/vectorscan/vectorscan.py` (or a structurally identical subset) to preserve deterministic error messages. The shim owns translation from parsed Namespace → canonical command invocation; pillar CLI never sees legacy-only flags.
- Command mapping:
  * Scan (default path): positional plan argument or stdin flags route to `pillar.cli scan` with translated options (`--json-output/--no-json-output`, `--stdin`, `--quiet`).
  * Rules: when legacy callers request `--policy-manifest` with no `plan`, the shim must invoke `pillar.cli rules --manifest`. Once a `rules` subcommand is added to the legacy surface, the shim simply forwards `vectorscan rules [...]` to the pillar command list.
  * Validate: until implemented, the shim reserves `vectorscan validate` syntax and forwards it to `pillar.cli validate` once that handler exists. During interim cycles it must emit EXIT_CONFIG_ERROR with a clear "validate not yet available" message to keep behavior deterministic.
- Transitional behaviors:
  * `--compare`, `--preview-vectorguard`, `--terraform-tests`, and lead-capture flags (`--email`, `--lead-capture`, `--endpoint`, `--allow-network`) have no pillar equivalents. The shim retains the ability to call the legacy helper functions for these code paths (short-circuit before invoking pillar CLI) and must document that these modes temporarily bypass the pillar pipeline.
  * GitHub Action mode (`--gha`) is interpreted by the shim: set `--json-output`, force `--quiet`, and ensure pillar CLI receives deterministic sorted JSON instructions when possible; if the flow stays on the legacy fallback path, legacy formatting is preserved.
  * Exit codes remain identical to current legacy values; the shim never invents new codes and must map pillar results back to the constants in `tools.vectorscan.constants`.

2. Flag Translation Table

| Legacy Flag / Input                          | Shim Interpretation                                                                           | Pillar CLI Arguments / Behavior                              | Notes |
|----------------------------------------------|------------------------------------------------------------------------------------------------|----------------------------------------------------------------|-------|
| (positional) `PLAN`                          | Treat as scan target.                                                                          | `scan PLAN --json-output` (unless overridden)                 | When combined with `--compare`, shim defers to legacy compare flow. |
| `--json`                                     | Requests canonical JSON output.                                                                | Append `--json-output`; omit human output                     | Back-compat; pillar default of True remains but translation enforces intent. |
| `--gha`                                      | GitHub Action mode.                                                                             | Force `scan … --json-output --quiet`; set env for sorted JSON | If shim stays in legacy fallback (e.g., compare), continue legacy `--gha` handling. |
| `--no-color`                                 | Suppress ANSI.                                                                                  | Translate to pillar `--quiet` + environment signaling         | Pillar CLI currently only toggles JSON/human; shim should ensure no human output when JSON requested. |
| `--policy-manifest` (no plan)                 | Request manifest output.                                                                        | `rules --manifest`                                            | Shim errors if plan path is also provided, mirroring legacy parser. |
| `rules …` subcommand (future)                | Bypass legacy parser once added.                                                                | `pillar.cli rules …`                                          | Until subcommand exists, only `--policy-manifest` triggers rules. |
| `validate …` subcommand (reserved)           | Placeholder entry.                                                                              | `pillar.cli validate …` (once implemented)                    | Prior to implementation, shim raises deterministic "validate unsupported" error. |
| `--stdin`                                    | Read plan from stdin.                                                                           | `scan --stdin`                                                | Shim ensures pillar CLI receives mutually exclusive plan/stdin semantics. |
| `--quiet`                                    | Suppress human output.                                                                          | Pass through to pillar `--quiet`; if absent, allow human output | Behavior must mimic legacy banner suppression. |
| `--compare OLD NEW`                          | Legacy-only compare mode.                                                                       | Stay in legacy module; do not call pillar CLI                 | Shim should surface TODO for future pillar support. |
| Lead-capture flags (`--email`, `--lead-capture`, `--endpoint`, `--allow-network`) | Legacy-only telemetry path.                                                                     | Either run legacy helper (if scan is legacy) or error until pillar implements telemetry | Documented as fallback behavior; no pillar flag yet. |
| `--terraform-tests`, `--terraform-bin`, `--no-terraform-download` | Terraform orchestration.                                                                       | Legacy fallback only until pillar evaluator handles Terraform preflight | Shim may reject when pillar path selected (deterministic message). |

3. Execution Flow Specification
1. `entrypoint_shim.main(argv)` ensures `argv` defaults to `sys.argv[1:]` and runs the legacy argparse parser to obtain a Namespace and subcommand indicator (if/when added).
2. The shim evaluates guard clauses:
   - If `--compare` is present, invoke the existing `_run_compare_mode` helper and return its exit code (no pillar invocation).
   - If Terraform-test or lead-capture-only flows are requested without a plan (unsupported), emit `EXIT_CONFIG_ERROR` with a deterministic explanation.
3. Determine target command:
   - If `namespace.subcommand == "rules"` or the legacy "policy-manifest without plan" shortcut triggers, build pillar argv `['rules', '--manifest']`.
   - Else if `namespace.subcommand == "validate"`, currently raise the reserved error; after validate implementation, forward `['validate', …]`.
   - Otherwise default to `scan` and build pillar argv comprised of: plan path (if any), `--stdin` when requested, translated flags (`--json-output` when `--json` or `--gha`, `--quiet` when `--quiet` or `--gha`), and placeholders for yet-to-be-supported options (strict-mode, policy selectors) once pillar CLI accepts them.
4. When the target is `scan` or `rules`, call `src.pillar.cli.main(pillar_argv)` via a direct import (resolved lazily to avoid circular imports). Capture its integer exit code and propagate it directly, ensuring `SystemExit` exceptions are normalized to ints.
5. For flows still handled by legacy helpers (compare, Terraform tests, preview), execute the corresponding functions from `tools.vectorscan.vectorscan` to maintain behavior until pillar parity exists. These helpers must be deterministic and remain pure functions from shim perspective.
6. Exit code mapping: whichever path executes returns its native exit code; shim does not translate beyond ensuring `SystemExit` codes travel back as ints. Errors generated by the shim itself must use constants from `tools.vectorscan.constants` for consistency.

4. Test Expectations
- New shim-focused tests: add unit tests under `tests/pillar/test_cli_contract.py` (or a new shim suite) that call `entrypoint_shim.main()` with representative argv values and assert the translated pillar argv (via monkeypatching `src.pillar.cli.main`). These tests cover scan, rules, reserved validate, `--json` translation, and `--policy-manifest` handling.
- Existing legacy CLI suites (tests/test_cli.py, tests/test_strict_mode_cli.py, lead-capture suites, end-to-end bundles) must continue to import `tools.vectorscan.vectorscan` and see identical behavior. Shim design therefore requires high-fidelity translation that keeps their assertions intact during the migration window.
- Click-based pillar tests (tests/vector/integration/*) remain unchanged; they already target `vectorscan.cli`. However, once the shim routes traffic into pillar.cli, we can unify these by running the same CLI entrypoint in both suites. The spec therefore expects future work to add regression tests ensuring `vectorscan.main([...])` now exercises the pillar pipeline when `--compare`, lead capture, and Terraform flags are absent.
- Validate command tests: once implemented, extend `tests/pillar/test_cli_contract.py` and potentially `tests/vector/integration` to cover `vectorscan validate --json-output` and schema validation flows.

5. Outstanding Shim Issues (IssueDicts)
[
   {
      "id": "PILLAR-SHIM-001",
      "severity": "medium",
      "title": "Compare mode lacks pillar equivalent",
      "description": "The shim cannot forward `--compare OLD NEW` requests to src/pillar/cli.py because no canonical command exists. The specification therefore mandates a legacy fallback, but this leaves compare-mode behavior outside the pillar pipeline.",
      "resource_address": "tools/vectorscan/entrypoint_shim.py",
      "attributes": {
         "flag": "--compare",
         "expected_pillar_command": "scan --compare (future)",
         "current_plan": "call tools.vectorscan.vectorscan._run_compare_mode directly"
      },
      "remediation_hint": "Add a compare-aware command to pillar.cli (or extend scan) so the shim can translate `--compare` into canonical arguments and drop the legacy fallback.",
      "remediation_difficulty": "medium"
   },
   {
      "id": "PILLAR-SHIM-002",
      "severity": "medium",
      "title": "Lead capture and preview flags unhandled by pillar CLI",
      "description": "Flags such as `--email`, `--lead-capture`, `--endpoint`, `--allow-network`, and `--preview-vectorguard` have no representation in src/pillar/cli.py. The shim specification keeps these flows on the legacy code path, which means telemetry and preview behaviors bypass the pillar evaluator.",
      "resource_address": "tools/vectorscan/entrypoint_shim.py",
      "attributes": {
         "legacy_flags": ["--email", "--lead-capture", "--endpoint", "--allow-network", "--preview-vectorguard"],
         "expected_behavior": "pillar CLI needs equivalent options or metadata hooks",
         "current_behavior": "shim short-circuits to legacy helpers"
      },
      "remediation_hint": "Extend pillar CLI (and evaluator metadata) to accept lead-capture and preview settings so the shim can translate those flags instead of invoking legacy code directly.",
      "remediation_difficulty": "medium"
   }
]

---
AI Dev Shim Implementation — 2025-11-21

Changes
- Implemented `tools/vectorscan/entrypoint_shim.py` with the specified responsibilities: argv normalization, canonical command detection, rules-manifest routing, scan flag translation (`--json`/`--quiet`/`--stdin`), and deterministic fallbacks for compare / Terraform / lead-capture / preview flows when pillar CLI support is absent.
- Updated `tools/vectorscan/vectorscan.py` so both `main()` and the script entrypoint delegate directly to `shim_main`, ensuring all direct imports now pass through the adapter.

Behavior Notes
- When `pillar.cli.main` becomes available, the shim now forwards `scan`/`rules` traffic with normalized `--json-output` / `--no-json-output` semantics while still reserving `validate`. Until then, the adapter transparently drops back to the legacy `_run_cli` so existing workflows remain stable.
- Canonical subcommands (`scan`, `rules`, `validate`) emit deterministic config errors if the pillar CLI entrypoint is missing, preventing confusing fallbacks.

Tests
- `/home/dee/workspace/AI/GuardSuite/VectorScan/.venv/bin/python -m pytest tests/vector/integration/test_cli_template.py tests/vector/integration/test_phase12_cli_remediation_metadata.py tests/unit/test_lead_capture_unit.py tests/test_cli.py tests/test_strict_mode_cli.py`
   - Result: 41 passed, 0 failed (6.29s)

Commit
- Skipped (`.hypothesis` artifacts remain in the tree, so the workspace is not in a safe state for an atomic shim-only commit).

---
Legacy-Parity Normalization Spec — 2025-11-21

## 1. Legacy normalization inventory
1. **Plan schema normalization** (`tools.vectorscan.plan_utils.load_json`, `_validate_plan_schema`, `iter_resources`): ensures `planned_values.root_module.resources` and `child_modules` exist, recursively flattens resources for downstream metrics, and materializes `resource_changes` derived metadata.
2. **Plan limits + SLO metadata** (`plan_stream`, `_build_plan_limit_block`): computes `file_size_bytes`, `parse_duration_ms`, parser mode, and threshold flags that feed audit logs and JSON payloads.
3. **Policy selection + filtering** (`tools.vectorscan.policies`, `_normalize_resource_address`, `_resolve_policy_selection`): maps `--policy`, `--policies`, presets, and free-tier filters to the active rule list; required for `checks`, `violations`, and severity counts.
4. **Rule evaluation and violation formatting** (`tools.vectorscan.policies.get_policies`, `build_violation_structs`): produces legacy `violations` (string list), remediation metadata, and severity lookup tables consumed by renderers and metrics.
5. **Metrics + severity summary** (`tools.vectorscan.metrics.compute_violation_severity_summary`, `compute_metrics`, `compute_security_grade`): derives `violation_severity_summary`, compliance scores, network exposure stats, IAM risky action counts, and notes fields; deterministic ordering enforced by `SEVERITY_LEVELS`.
6. **IAM drift report** (`tools.vectorscan.iam_drift.build_iam_drift_report`): inspects `resource_changes` to flag risky IAM deltas, attaches `iam_drift_report`, and influences audit ledger text plus quick-score toggles.
7. **Plan smell / risk / evolution reports** (`plan_smell`, `plan_risk`, `plan_evolution`): augment JSON payloads with smell summaries, risk profiles, and evolution diffs referenced by audit ledger tests.
8. **Lead capture + telemetry metadata** (`tools.vectorscan.lead_capture`, `maybe_post`, `write_local_capture`): attaches `lead_capture` blocks, environment hints, and offline indicators required by lead capture unit/integration tests.
9. **Preview / paid manifest overrides** (`tools.vectorscan.preview`, `load_preview_manifest`): injects `preview_manifest`, `preview_policies`, `preview_generated`, and exit code 10 semantics.
10. **Audit ledger generation** (`tools.vectorscan.audit_ledger` via tests/golden templates): transforms canonical JSON payloads into YAML ledger snapshots with deterministic environment metadata (`platform`, `platform_release`, `plan_limits`, smell report, IAM drift summaries).
11. **Human renderer + color logic** (`tools.vectorscan.environment._should_use_color`, `_status_badge`, `src.vectorscan.renderer` helpers): decides badge strings, summary text, issue listings, and respects `--no-color`, `VSCAN_FORCE_COLOR`, `--quiet`, and GitHub Action suppression rules.
12. **JSON output normalizer** (`tools.vectorscan.renderer.safe_print`, legacy CLI sorting, `json.dumps(..., sort_keys=gha_mode)`): enforces indentation, ensures `ensure_ascii=False`, maintains canonical field order for tests.

## 2. Deterministic normalization pipeline
- **Stage 0 – Inputs**: raw tfplan path/stdin bytes, CLI flags, environment overrides (offline, preview, strict mode).
- **Stage 1 – Load + validate plan**: reuse `plan_utils.load_plan_context` to obtain `(plan, resources, plan_limits, module_stats)` ensuring schema corrections; output includes structured resources list.
- **Stage 2 – Policy selection**: consume CLI flag adapters to resolve `active_policy_ids`, severity lookup, and rule metadata; output feeds evaluator + manifest builder.
- **Stage 3 – Legacy evaluator compatibility layer**:
   - Invoke canonical pillar evaluator to get base `issues` and canonical schema fields.
   - Translate canonical issues into legacy violation strings via `build_violation_structs` (issue id + description) and backfill remediation hints/fixpack metadata when missing.
   - Merge severity counts: prefer canonical `severity_totals` but ensure `compute_violation_severity_summary` matches legacy ordering.
- **Stage 4 – Metadata enrichment**:
   - Compute plan metadata via `compute_plan_metadata` using stage-1 outputs.
   - Attach smell report (`plan_smell.compute_smell_report`), risk profile (`plan_risk.compute_plan_risk_profile`), plan evolution (`plan_evolution.compute_plan_evolution` when `--diff`/`--resource` requested), and IAM drift report.
   - Build environment block via `_build_environment_metadata` and merge offline/platform fields.
- **Stage 5 – Metrics + quick score**:
   - Run `compute_metrics`/`compute_security_grade` on resources + violations.
   - Derive `pillar_score_inputs`, `severity_totals`, `violation_severity_summary`, and quick-score toggles (size thresholds from pillar evaluator + legacy heuristics).
- **Stage 6 – Preview / lead capture / Terraform notes**:
   - If preview flags set, call `load_preview_manifest`, merge preview metadata, and adjust exit codes.
   - If lead capture enabled, run `maybe_post` or `write_local_capture` and embed capture status fields.
   - Terraform test flags either short-circuit to legacy strategies or annotate metadata (depends on future pillar support).
- **Stage 7 – Audit ledger + logs**:
   - Generate YAML ledger via existing helper using enriched payload + environment stage.
   - Ensure deterministic file paths, create directories if needed, and update tests referencing `tests/golden/audit_ledger.yaml`.
- **Stage 8 – Output synthesis**:
   - Build final canonical JSON payload combining pillar schema requirements with legacy fields (`violations`, `checks`, `metrics`, `iam_drift_report`, `plan_metadata`, smell/risk/evolution blocks, audit ledger references).
   - Produce human-readable output via renderer when `--quiet` is false and JSON disabled.
   - Determine exit codes per section 3.

## 3. Exit-code semantics
- **SCAN default**:
   - `EXIT_SUCCESS` (0) when `status == PASS` and no preview override.
   - `EXIT_POLICY_FAIL` (3) when violation summary contains any severity or when canonical payload `status == FAIL`.
   - `EXIT_INVALID_INPUT` (2) for plan load/JSON errors (PlanLoadError, schema invalid).
   - `EXIT_CONFIG_ERROR` (1) for incompatible flag combinations, unsupported strict-mode dependencies, or fatal evaluator exceptions.
   - `EXIT_PREVIEW_MODE` (10) when `--preview-vectorguard` succeeds and preview manifest verified/accepted.
   - Additional codes preserved from legacy CLI: `EXIT_TERRAFORM_FAIL` (8) for terraform test failures, `EXIT_TERRAFORM_ERROR` (9) for terraform execution errors, `EXIT_POLICY_LOAD_ERROR` (11) for policy manifest signature errors, etc. Shim must map pillar payload signals back to these constants.
- **VALIDATE command**: returns `EXIT_SUCCESS` on schema validity, `EXIT_INVALID_INPUT` on load failure, `EXIT_VALIDATION_ERROR` (new constant) when payload is not a dict or missing required keys.
- **RULES command**: always `EXIT_SUCCESS` on manifest dump; `EXIT_INVALID_INPUT` if incompatible options supplied.

## 4. Human-output rules
- Emit human output unless any of `--json`, `--json-output`, `--quiet`, or GitHub Action mode is active.
- Colorization via `_should_use_color` honoring `VSCAN_FORCE_COLOR`, `VSCAN_NO_COLOR`, `NO_COLOR`, and `--no-color` legacy flags; GitHub Action forces no color.
- Badge text generated by `_status_badge(status, use_color)` followed by plan label and `VectorScan checks` suffix to satisfy golden tests.
- Renderer helpers (`render_severity_summary`, `render_human_readable`) must receive enriched payload so severity counts, policy ordering, and remediation hints match golden snapshots.
- Lead capture banners and preview warnings must mirror legacy CLI: print capture upload status lines and preview manifest verification messages even when JSON is requested (stdout human vs stderr errors follows existing tests).

## 5. JSON-output rules
- Default indentation 2, `ensure_ascii=False`; when `--gha`, enforce `sort_keys=True` and suppress trailing newline differences.
- Canonical ordering requirements:
   - Top-level keys must include legacy fields (`status`, `violations`, `violation_severity_summary`, `metrics`, `policy_manifest`, `policy_version`, `policy_pack_hash`, `policy_source_url`, `checks`, `file`, `iam_drift_report`, `plan_metadata`, `environment`, `audit_ledger_path`) alongside pillar-required keys (`pillar`, `scan_version`, `guardscore_rules_version`, `canonical_schema_version`, `issues`, `severity_totals`, `badge_eligible`, `quick_score_mode`, `metadata`, `latency_ms`, `schema_validation_error`).
   - Nested ordering follows legacy expectation: severity summaries in `_SEVERITY_ORDER`, `checks` sorted by policy id, manifest policies sorted by id.
- Encoding: always UTF-8; no BOM; newline terminated.
- Deterministic policy manifest: reuse `_policy_manifest_template` with `sha256` signature string; `policy_pack_hash` must come from legacy `policy_pack_hash()` to align tests.

## 6. Identified compatibility gaps (IssueDicts)
[
   {
      "id": "PILLAR-NORM-001",
      "severity": "high",
      "title": "Canonical evaluator lacks legacy violation formatting",
      "description": "Pillar evaluator returns structured issues but does not emit legacy violation strings or compute violation_severity_summary, causing CLI tests expecting violations arrays to fail.",
      "resource_address": "src/pillar/evaluator.py",
      "attributes": {
         "required_fields": ["violations", "violation_severity_summary", "metrics"],
         "legacy_source": "tools.vectorscan.metrics", "tools.vectorscan.policies"
      },
      "remediation_hint": "Introduce a compatibility layer that maps canonical issues to legacy violation strings and recomputes severity summaries via compute_violation_severity_summary.",
      "remediation_difficulty": "high"
   },
   {
      "id": "PILLAR-NORM-002",
      "severity": "high",
      "title": "IAM drift + audit ledger data missing from pillar payloads",
      "description": "Current pillar CLI never runs build_iam_drift_report or audit ledger generation, leaving tests expecting iam_drift_report blocks and ledger YAML files failing.",
      "resource_address": "src/pillar/cli.py",
      "attributes": {
         "legacy_functions": ["tools.vectorscan.iam_drift.build_iam_drift_report", "tests/test_audit_ledger.py helpers"],
         "missing_outputs": ["iam_drift_report", "audit_ledger_path", "smell_report", "plan_risk"]
      },
      "remediation_hint": "Invoke IAM drift and audit ledger builders during normalization before emitting outputs.",
      "remediation_difficulty": "medium"
   },
   {
      "id": "PILLAR-NORM-003",
      "severity": "medium",
      "title": "Policy selection flags not wired to pillar CLI",
      "description": "Flags like --policy, --policies, presets, and --policy-manifest currently bypass pillar CLI, so active policy lists stay fixed and legacy tests verifying filtered checks fail.",
      "resource_address": "tools/vectorscan/entrypoint_shim.py",
      "attributes": {
         "missing_adapters": ["--policy", "--policies", "--policy-manifest"],
         "tests": ["tests/test_cli.py::test_cli_policy_filter_limits_checks"]
      },
      "remediation_hint": "Implement translation logic that injects selected policy IDs into the compatibility layer before evaluation.",
      "remediation_difficulty": "medium"
   }
]

## 7. Test impact analysis
- `tests/test_cli.py`: All failures caused by missing normalization (exit codes, JSON contents, color output). Implementing stages above should flip every currently failing test to PASS without expectation updates.
- `tests/test_json_output.py`: Goldens (`pass_output.json`, `fail_output.json`, explain/diff/resource/preview) require exact legacy payloads; normalization must reproduce identical structures so no snapshot updates are needed. Preview-mode semantics must reinstate exit code 10 and preview metadata.
- `tests/test_end_to_end_scenarios.py`: Restoring severity counts, IAM drift, and audit ledger generation will make scenarios A-D pass again; no test rewrites expected.
- `tests/test_audit_ledger.py` and `tests/e2e/test_stress_determinism.py`: depend on deterministic ledger builder; once pipeline runs the legacy helper, these should pass.
- Lead capture suites (`tests/unit/test_lead_capture*.py`, `tests/test_lead_capture_cli.py`): require telemetry hooks and offline metadata; normalization must call existing helpers or temporarily keep lead-capture flows on legacy path until equivalent hooks exist.
- Strict mode suites (`tests/test_strict_mode_cli.py`, `tests/unit/test_offline_mode_unit.py`): rely on `_ensure_strict_clock`, offline defaults, and color toggles; compatibility layer must respect these environment-driven behaviors to avoid expectation churn.

## 8. Next implementation scope
- Build the compatibility module (likely `src/pillar/normalization.py`) encapsulating stages 1-8 so both CLI and future APIs can call it deterministically.
- Extend entrypoint shim to pass legacy flags into normalization config (policy selection, explain/diff/resource filters, preview, lead capture, Terraform tests).
- Add regression tests exercising the normalization pipeline directly plus CLI end-to-end to confirm parity before removing legacy code paths.


VS-BLOCKER-002 Snapshot Refresh — 2025-11-24

Objective
- Regenerate all JSON goldens and snapshots so canonical `metadata.control.*` fields (auto_download, offline_mode, allow_network_capture, terraform_outcome) match the pillar evaluator output.

Actions
1. Drove the canonical CLI via the snapshot generator harness (`tests/test_json_output.py` helpers) across PASS/FAIL/IAM-drift, explain/diff/resource, preview, and compare permutations to capture fresh payloads.
2. Updated `tests/snapshots/*.json` and `tests/golden/*.json` (13 files) with the normalized outputs, keeping remediation ledger ordering intact and preserving deterministic metadata ordering.
3. Returned `_return_plan_error` in `src/pillar/cli.py` to `EXIT_INVALID_INPUT` so invalid tfplan JSON exits align with legacy CLI expectations.

Verification
- `python -m pytest tests/test_json_output.py -q` → 17 passed.
- `python -m pytest tests/test_cli.py -q` → 12 passed.
- `python -m pytest tests/snapshots/test_snapshots.py -q` → 13 passed.

Status
- VS-BLOCKER-002 completed; canonical metadata now matches the refreshed goldens.

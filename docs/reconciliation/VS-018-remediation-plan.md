# VS-018 — Reconciliation Remediation Plan (Phase 3)

## src/pillar/cli.py
classification: KEEP

reasoning:
  - Strict-mode banner parity is restored by capturing `strict_mode_active` once and forwarding it to `_return_plan_error`, matching VS-013 requirements.
  - Lead-capture gating now mirrors legacy behavior by checking `no_network_active` before any IO, preventing silent offline writes.

required_actions:
  - Retain the current strict-mode banner invocation path; do not reintroduce the placeholder stderr-only behavior.
  - Keep the combined `no_network_active` guard and continue validating it via `tests/test_lead_capture_unit.py` and `tests/test_strict_mode_cli.py`.

## src/pillar/constants.py
classification: KEEP

reasoning:
  - The file now declares canonical pillar identifiers (pillar name, scan/schema versions) consumed by evaluator, metadata, and CLI payloads.
  - Reverting to the placeholder would break determinism across schema outputs and audit logs.

required_actions:
  - Preserve the declared constants and continue referencing them from downstream modules instead of duplicating literals.
  - Update version values only when a coordinated release increments Scan or Schema versions.

## src/pillar/evaluator.py
classification: KEEP

reasoning:
  - The evaluator has been fully implemented to orchestrate normalization, rule execution, metadata synthesis, and exit-code derivation; removing it would sever the pipeline.
  - Control-flag propagation, issue aggregation, and Terraform exit-code handling now match the product spec and must remain intact for future phases.

required_actions:
  - Maintain the existing evaluation pipeline steps (flatten → metadata_inject → iam_drift → canonical issues → severity/audit) with no regression to stub behavior.
  - Keep `_evaluate_stub_rules`, `finalize_exit_code`, and `_attach_canonical_sections` wired exactly as shown; any future edits must preserve deterministic ordering and metadata fields.

## src/pillar/metadata.py
classification: KEEP

reasoning:
  - The metadata builder now generates deterministic plan/environment/control blocks backed by canonical constants, satisfying schema guarantees.
  - Flag extraction reconciles `_control_flags` with environment data to avoid missing offline/auto-download state in outputs.

required_actions:
  - Retain the helper structure (`build_metadata`, `_build_environment_metadata`, `_extract_control_flags`) so metadata remains canonical.
  - When introducing new control flags, extend `_ordered_flag_snapshot` in this module to keep ordering stable.

## src/pillar/rules/registry.py
classification: KEEP

reasoning:
  - The registry now enumerates the 24 canonical AWS rules with remediation metadata, enabling deterministic rule evaluation and fixpack hints.
  - Reverting to the placeholder would remove all rule coverage, blocking evaluator parity.

required_actions:
  - Preserve the catalog entries and remediation metadata; additions must follow the same deterministic structure and ordering.
  - Continue exposing rules via `issue_catalog()` / `get_rules()` without introducing dynamic imports or side effects.

---
status: completed
files_modified:
  - src/pillar/compat/normalization.py
  - tests/golden/pass_output.json
  - tests/golden/fail_output.json
  - tests/golden/iam_drift_output.json
  - tests/golden/pass_explain_output.json
  - tests/golden/fail_explain_output.json
  - tests/golden/iam_drift_explain_output.json
  - tests/golden/pass_diff_output.json
  - tests/golden/fail_diff_output.json
  - tests/golden/iam_drift_diff_output.json
  - tests/golden/fail_resource_output.json
  - tests/golden/module_resource_output.json
  - tests/golden/fail_preview_output.json
  - tests/golden/plan_compare_output.json
  - tests/snapshots/pass_output.json
  - tests/snapshots/fail_output.json
  - tests/snapshots/iam_drift_output.json
  - tests/snapshots/pass_explain_output.json
  - tests/snapshots/fail_explain_output.json
  - tests/snapshots/iam_drift_explain_output.json
  - tests/snapshots/pass_diff_output.json
  - tests/snapshots/fail_diff_output.json
  - tests/snapshots/iam_drift_diff_output.json
  - tests/snapshots/fail_resource_output.json
  - tests/snapshots/module_resource_output.json
  - tests/snapshots/fail_preview_output.json
  - tests/snapshots/plan_compare_output.json

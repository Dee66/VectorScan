[
  {
    "id": "PILLAR-ATU-02-LOG",
    "summary": {
      "severity": "medium",
      "title": "ATU-02 metadata injection landing with outstanding parity drift",
      "description": "Implemented flatten -> metadata stage and evaluator plumbing per ATU-02. Targeted suites run (tests/test_cli.py, tests/test_json_output.py, tests/vector/integration/test_cli_template.py); 17 passed, 7 failed in tests/test_json_output.py because environment.offline_mode now reports true when --allow-network flag is absent, diverging from golden snapshots expecting false.",
      "resource_address": "src/pillar/compat/normalization.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 24,
      "failures": 7,
      "failed_tests": [
        "tests/test_json_output.py::test_pass_matches_golden",
        "tests/test_json_output.py::test_fail_matches_golden",
        "tests/test_json_output.py::test_iam_drift_matches_golden_and_penalty",
        "tests/test_json_output.py::test_explain_mode_snapshots",
        "tests/test_json_output.py::test_diff_mode_snapshots",
        "tests/test_json_output.py::test_resource_mode_snapshots",
        "tests/test_json_output.py::test_preview_mode_snapshot"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-02-LOG",
      "remediation_difficulty": "medium"
    }
  },
  {
    "id": "PILLAR-ATU-03-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-03 offline-mode normalization complete",
      "description": "Implemented resolve_offline_mode with legacy flag heuristics, ensured evaluator seeds environment.offline_mode, and reran targeted suites (tests/test_json_output.py, tests/test_cli.py, tests/vector/integration/test_cli_template.py). All 24 tests now pass with offline_mode defaulting to false unless explicit overrides are provided.",
      "resource_address": "src/pillar/evaluator.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 24,
      "failures": 0,
      "duration_s": 6.01
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-03-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-04-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-04 IAM drift normalization landed",
      "description": "Added iam_drift_normalize() with deterministic ordering, integrated the stage into evaluator, and updated normalization pipeline to reuse the normalized report. Targeted suites (tests/test_json_output.py, tests/test_cli.py, tests/vector/integration/test_cli_template.py) all pass, confirming IAM drift parity baselines.",
      "resource_address": "src/pillar/compat/normalization.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 24,
      "failures": 0,
      "duration_s": 5.95
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-04-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-06-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-06 canonical issue scaffolding",
      "description": "Introduced canonical_issue_collect(), seeded deterministic issue placeholders, wired registry stubs, and ensured evaluator exposes evaluation.issues prior to severity and ledger stages. Required suites (tests/test_json_output.py, tests/test_cli.py, tests/test_end_to_end_scenarios.py) now pass with seeded issue lists visible to downstream consumers.",
      "resource_address": "src/pillar/compat/normalization.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 27,
      "failures": 0,
      "duration_s": 8.47
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-06-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-07-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-07 rule invocation bootstrap",
      "description": "Added rule_engine.evaluate_rules(), expanded the registry catalog, and wired the evaluator to invoke deterministic rule stubs so canonical issues originate from the registry instead of placeholders. Severity aggregation and audit ledger now consume populated issue lists sourced from rule execution.",
      "resource_address": "src/pillar/evaluator.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 27,
      "failures": 0,
      "duration_s": 7.82
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-07-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-08-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-08 conditional rule targeting",
      "description": "Extended the rule registry with match metadata, taught the rule engine to filter normalized resources, and updated the evaluator wiring so stub rules emit canonical issues only when resources satisfy their simple conditions. Severity aggregation and audit ledger continue to consume the selectively populated issue list.",
      "resource_address": "src/pillar/rules/rule_engine.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 27,
      "failures": 0,
      "duration_s": 7.92
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-08-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-09-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-09 multi-field rule predicates",
      "description": "Added attribute/flag conditions to the registry and rule engine, derived resource-level flags (is_managed, has_missing_tags, allows_0_0_0_0), and propagated evaluation flags so rules now AND resource type + attributes + flags before emitting canonical issues.",
      "resource_address": "src/pillar/rules/rule_engine.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 27,
      "failures": 0,
      "duration_s": 6.34
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-09-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-11-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-11 expanded catalog + severity-aligned metadata",
      "description": "Replaced the three placeholder rules with a deterministic 24-rule catalog covering RDS, S3, IAM, network, and messaging controls, added lightweight flag derivations (IAM wildcard + S3 encryption/versioning), and enforced rule/id ordering in the rule engine so canonical issues remain deterministic across runs.",
      "resource_address": "src/pillar/rules/registry.py"
    },
    "files_changed": [
      "src/pillar/rules/registry.py",
      "src/pillar/rules/rule_engine.py"
    ],
    "tests": {
      "tests_run": 27,
      "failures": 0,
      "duration_s": 9.58
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-11-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-12-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-12 scan_version integration",
      "description": "Introduced the deterministic SCAN_VERSION constant, surfaced it through evaluator payloads, JSON snapshots, human-readable CLI headers/footers, compare mode, and documented the schema contract while adding regression coverage for the new field.",
      "resource_address": "src/pillar/constants.py"
    },
    "files_changed": [
      "src/pillar/constants.py",
      "src/pillar/evaluator.py",
      "src/pillar/compat/normalization.py",
      "src/pillar/cli.py",
      "tools/vectorscan/vectorscan.py",
      "tests/test_json_output.py",
      "tests/golden/*.json",
      "docs/output_schema_reference.md"
    ],
    "tests": {
      "tests_run": 28,
      "failures": 0,
      "duration_s": 8.05
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-12-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-13-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-13 remediation metadata propagation",
      "description": "Augmented the rule registry and rule engine so every canonical IssueDict carries remediation_hint, remediation_difficulty, and deterministic remediation_metadata all the way into the normalized payload, refreshed the schema reference, expanded regression tests, and regenerated the JSON goldens to cover the new issues array.",
      "resource_address": "src/pillar/rules/rule_engine.py"
    },
    "files_changed": [
      "src/pillar/rules/registry.py",
      "src/pillar/rules/rule_engine.py",
      "src/pillar/compat/normalization.py",
      "docs/output_schema_reference.md",
      "tests/test_json_output.py",
      "tests/golden/*.json"
    ],
    "tests": {
      "tests_run": 26,
      "failures": 0,
      "duration_s": 7.46,
      "test_suites": [
        "tests/test_json_output.py",
        "tests/test_cli.py",
        "tests/test_end_to_end_scenarios.py::test_scenario_a_pass_end_to_end"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-13-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "PILLAR-ATU-14-LOG",
    "summary": {
      "severity": "low",
      "title": "ATU-14 remediation ledger integration",
      "description": "Extended normalization to synthesize remediation_summary, exposed it via audit ledger remediation_summary and payload remediation_ledger blocks, refreshed schema docs, tightened CLI/JSON regression tests, and regenerated goldens so remediation metadata is reportable downstream.",
      "resource_address": "src/pillar/compat/normalization.py"
    },
    "files_changed": [
      "src/pillar/compat/normalization.py",
      "docs/output_schema_reference.md",
      "tests/test_json_output.py",
      "tests/golden/*.json"
    ],
    "tests": {
      "tests_run": 26,
      "failures": 0,
      "duration_s": 6.79,
      "test_suites": [
        "tests/test_json_output.py",
        "tests/test_cli.py"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:PILLAR-ATU-14-LOG",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "SPEC-RESTORE-001",
    "summary": {
      "severity": "low",
      "title": "SPEC RESTORE master baseline recovered",
      "description": "Created docs/spec/ and restored 'GUARDSUITE MASTER SPEC (SOURCE OF TRUTH).txt' with the authoritative content so future audits have a versioned source of truth within the VectorScan repo.",
      "resource_address": "docs/spec/GUARDSUITE MASTER SPEC (SOURCE OF TRUTH).txt"
    },
    "files_changed": [
      "docs/spec/GUARDSUITE MASTER SPEC (SOURCE OF TRUTH).txt",
      ".logs/ai-dev-latest.md"
    ],
    "tests": {
      "tests_run": 0,
      "failures": 0
    },
    "notes": {
      "remediation_hint": "fixpack:SPEC-RESTORE-001",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "SPEC-PRODUCT-001",
    "summary": {
      "severity": "low",
      "title": "VectorScan product spec authored",
      "description": "Created product/spec.yml with the VectorScan architecture, pipeline, evaluator, rule engine, remediation, fixpack, CLI, and schema requirements derived from the restored master spec.",
      "resource_address": "product/spec.yml"
    },
    "files_changed": [
      "product/spec.yml",
      ".logs/ai-dev-latest.md"
    ],
    "tests": {
      "tests_run": 0,
      "failures": 0
    },
    "notes": {
      "remediation_hint": "fixpack:SPEC-PRODUCT-001",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "CHECKLIST-SYNTH-001",
    "summary": {
      "severity": "low",
      "title": "Initial VectorScan checklist synthesized",
      "description": "Authored checklist/checklist.yml with 12 actionable ATU items derived from the master + product specs to guide subsequent implementation phases.",
      "resource_address": "checklist/checklist.yml"
    },
    "files_changed": [
      "checklist/checklist.yml",
      ".logs/ai-dev-latest.md"
    ],
    "tests": {
      "tests_run": 0,
      "failures": 0
    },
    "notes": {
      "remediation_hint": "fixpack:CHECKLIST-SYNTH-001",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "VS-002",
    "summary": {
      "severity": "low",
      "title": "VS-002 evaluator contract alignment",
      "description": "Aligned the evaluator contract with the canonical GuardSuite schema by syncing canonical fields into the evaluation context, deriving badge eligibility from severity totals, and refreshing JSON emitters/tests so PASS payloads report badge readiness.",
      "resource_address": "src/pillar/evaluator.py"
    },
    "files_changed": [
      "src/pillar/evaluator.py",
      "src/pillar/compat/normalization.py",
      "tests/test_json_output.py",
      "tests/test_cli.py",
      "tests/golden/pass_output.json",
      "tests/golden/pass_diff_output.json",
      "tests/golden/pass_explain_output.json",
      "tests/golden/iam_drift_output.json",
      "tests/golden/iam_drift_diff_output.json",
      "tests/golden/iam_drift_explain_output.json"
    ],
    "tests": {
      "tests_run": 28,
      "failures": 0,
      "duration_s": 5.38,
      "test_suites": [
        "pytest tests/test_json_output.py tests/test_cli.py"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:VS-002",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "VS-003",
    "summary": {
      "severity": "low",
      "title": "VS-003 canonical IssueDict propagation",
      "description": "Normalized IssueDicts across the registry, rule engine, normalization pipeline, and evaluator so every issue carries the required canonical fields, remediation metadata, and deterministic ordering shared by the payload and evaluation context.",
      "resource_address": "src/pillar/rules/rule_engine.py"
    },
    "files_changed": [
      "src/pillar/rules/rule_engine.py",
      "src/pillar/compat/normalization.py",
      "src/pillar/evaluator.py",
      "tests/test_json_output.py",
      "tests/test_cli.py"
    ],
    "tests": {
      "tests_run": 29,
      "failures": 0,
      "duration_s": 7.21,
      "test_suites": [
        "pytest tests/test_json_output.py tests/test_cli.py"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:VS-003",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "VS-005",
    "summary": {
      "severity": "high",
      "title": "VS-005 — Full-Test Pass/Fail Report",
      "description": "Executed the full pytest suite (`pytest -q`) after the remediation ledger landing. The run produced 471 passed, 41 failed, and 1 skipped tests. Failures span bundled CLI imports (missing pillar module inside release archives), Terraform CLI shim regression (missing run_terraform_tests, TerraformManager, TerraformResolution, strategy helpers, auto-download flags), Terraform gating expectations (SKIP vs PASS), legacy CLI error-message expectations, strict-mode messaging, lead-capture exit-code text, Hypothesis policy property, JSON decoding when mixing stdout + JSON, and Terraform auto-download/offline metadata propagation.",
      "resource_address": "pytest -q"
    },
    "files_changed": [],
    "tests": {
      "timestamp": "2025-11-23T00:00:00Z",
      "suites_executed": [
        "pytest -q"
      ],
      "pass_count": 471,
      "fail_count": 41,
      "skip_count": 1,
      "failing_tests": [
        "tests/e2e/test_full_user_journey.py::test_release_bundle_reproducibility",
        "tests/integration/test_packaging_verification.py::test_cli_runs_from_unzipped_bundle",
        "tests/integration/test_terraform_cli_integration.py::test_terraform_tests_error_no_download",
        "tests/integration/test_terraform_cli_integration.py::test_terraform_tests_fail_integration",
        "tests/integration/test_terraform_cli_integration.py::test_terraform_tests_skip_legacy",
        "tests/integration/test_terraform_cli_integration.py::test_terraform_tests_skip_when_missing_binary",
        "tests/integration/test_terraform_gating_integration.py::test_terraform_tests_gating_runs[tfplan-pass.json]",
        "tests/integration/test_terraform_gating_integration.py::test_terraform_tests_gating_runs[tfplan-fail.json]",
        "tests/test_error_handling.py::test_missing_file_exit_code",
        "tests/test_error_handling.py::test_invalid_json_exit_code",
        "tests/test_strict_mode_cli.py::test_strict_mode_requires_deterministic_clock",
        "tests/test_terraform_cli.py::test_cli_includes_terraform_tests_payload",
        "tests/test_tfplan_structure.py::test_cli_handles_missing_planned_values",
        "tests/unit/test_lead_capture.py::test_lead_capture_empty_plan",
        "tests/unit/test_lead_capture.py::test_lead_capture_missing_planned_values",
        "tests/unit/test_lead_capture.py::test_lead_capture_missing_plan",
        "tests/unit/test_lead_capture.py::test_lead_capture_invalid_json",
        "tests/unit/test_lead_capture_unit.py::test_lead_capture_missing_plan",
        "tests/unit/test_lead_capture_unit.py::test_lead_capture_invalid_json",
        "tests/unit/test_lead_capture_unit.py::test_allow_network_flag_required_for_post",
        "tests/unit/test_python_version_guard.py::test_vectorscan_import_exits_on_unsupported_python",
        "tests/unit/test_terraform_chaos_unit.py::test_run_terraform_tests_handles_binary_crash",
        "tests/unit/test_terraform_chaos_unit.py::test_truncate_output_limits_long_strings",
        "tests/unit/test_terraform_chaos_unit.py::test_truncate_output_strict_returns_full_text",
        "tests/unit/test_terraform_chaos_unit.py::test_modern_strategy_reports_corrupted_state",
        "tests/unit/test_terraform_chaos_unit.py::test_run_terraform_tests_skips_when_missing",
        "tests/unit/test_terraform_chaos_unit.py::test_terraform_download_handles_unwritable_tmpdir",
        "tests/unit/test_terraform_chaos_unit.py::test_terraform_download_rejects_checksum_mismatch",
        "tests/unit/test_vectorscan.py::test_vectorscan_property",
        "tests/unit/test_vectorscan.py::test_vectorscan_lead_capture_flags",
        "tests/unit/test_vectorscan.py::test_vectorscan_missing_plan",
        "tests/unit/test_vectorscan.py::test_vectorscan_invalid_json",
        "tests/unit/test_vectorscan.py::test_vectorscan_missing_tags",
        "tests/unit/test_vectorscan_unit.py::test_policy_isolation_runs_other_checks_when_encryption_fails",
        "tests/unit/test_vectorscan_unit.py::test_strict_mode_requires_clock_overrides",
        "tests/unit/test_vectorscan_unit.py::test_strict_mode_disallows_policy_errors",
        "tests/unit/test_vectorscan_unit.py::test_offline_mode_disables_terraform_auto_download",
        "tests/unit/test_vectorscan_unit.py::test_terraform_auto_download_requires_explicit_opt_in",
        "tests/unit/test_vectorscan_unit.py::test_terraform_auto_download_enabled_via_new_env",
        "tests/unit/test_vectorscan_unit.py::test_terraform_auto_download_enabled_via_legacy_env",
        "tests/unit/test_vectorscan_unit.py::test_permission_denied_plan_read"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:VS-005",
      "remediation_difficulty": "medium"
    }
  },
  {
    "id": "VS-004",
    "summary": {
      "severity": "low",
      "title": "VS-004 remediation ledger canonicalization",
      "description": "Completed the remediation ledger per the product spec by normalizing canonical issues once, deriving per-severity summaries, rule indices, metadata aggregates, and mirroring the data into the audit ledger and CLI payloads. Updated regression tests to assert the new fields and regenerated all JSON golden fixtures, including plan-compare mode.",
      "resource_address": "src/pillar/compat/normalization.py"
    },
    "files_changed": [
      "src/pillar/compat/normalization.py",
      "tests/test_json_output.py",
      "tests/test_cli.py",
      "tests/golden/pass_output.json",
      "tests/golden/fail_output.json",
      "tests/golden/iam_drift_output.json",
      "tests/golden/pass_diff_output.json",
      "tests/golden/fail_diff_output.json",
      "tests/golden/iam_drift_diff_output.json",
      "tests/golden/pass_explain_output.json",
      "tests/golden/fail_explain_output.json",
      "tests/golden/iam_drift_explain_output.json",
      "tests/golden/fail_resource_output.json",
      "tests/golden/module_resource_output.json",
      "tests/golden/fail_preview_output.json",
      "tests/golden/plan_compare_output.json"
    ],
    "tests": {
      "tests_run": 29,
      "failures": 0,
      "duration_s": 6.15,
      "test_suites": [
        "pytest tests/test_json_output.py tests/test_cli.py"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:VS-004",
      "remediation_difficulty": "low"
    }
  },
  {
    "id": "VS-007",
    "summary": {
      "severity": "medium",
      "title": "VS-007 — Terraform & Control-Metadata Alignment",
      "description": "Threaded allow_network_capture, auto_download, offline_mode, and terraform_outcome through normalization/evaluator, added a deterministic terraform_shim bridge, restored strict-mode/CLI parity, and re-enabled the python compatibility guard so VectorScan matches legacy behavior across control metadata and Terraform gating.",
      "resource_address": "src/pillar/compat/normalization.py"
    },
    "files_changed": [
      "src/pillar/compat/normalization.py",
      "src/pillar/evaluator.py",
      "src/pillar/cli.py",
      "src/pillar/terraform_shim.py",
      "tools/vectorscan/entrypoint_shim.py"
    ],
    "tests": {
      "tests_run": 34,
      "failures": 0,
      "test_suites": [
        "tests/integration/test_terraform_gating_integration.py",
        "tests/test_terraform_cli.py",
        "tests/test_strict_mode_cli.py",
        "tests/unit/test_lead_capture_unit.py",
        "tests/unit/test_vectorscan_unit.py::test_permission_denied_plan_read",
        "tests/unit/test_python_version_guard.py"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:VS-007",
      "remediation_difficulty": "medium"
    }
  },
  {
    "id": "VS-013",
    "summary": {
      "severity": "low",
      "title": "VS-013 strict-mode/Terraform parity verification",
      "description": "Regenerated strict-mode CLI, Terraform CLI, lead capture, and Terraform gating integration suites to confirm banner parity, terraform_outcome propagation, and offline/no-network metadata consistency. All suites passed; the existing PytestUnknownMarkWarning on the integration marker persists but requires no new action.",
      "resource_address": "tests/test_strict_mode_cli.py"
    },
    "files_changed": [],
    "tests": {
      "tests_run": 32,
      "failures": 0,
      "duration_s": 12.87,
      "test_suites": [
        "pytest -q tests/test_strict_mode_cli.py",
        "pytest -q tests/test_terraform_cli.py",
        "pytest -q tests/unit/test_lead_capture_unit.py",
        "pytest -q tests/integration/test_terraform_gating_integration.py"
      ]
    },
    "notes": {
      "remediation_hint": "fixpack:VS-013",
      "remediation_difficulty": "low"
    }
  }
]

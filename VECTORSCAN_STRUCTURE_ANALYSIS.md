# VectorScan Structure Analysis
## Investigation for Pillar Template Migration

---

## 1. CURRENT FOLDER STRUCTURE

```
tools/
└── vectorscan/                          # Main VectorScan package (current location)
    ├── __init__.py                      # Package initializer
    ├── vectorscan.py                    # CLI entry point (1112 lines)
    │
    ├── policies/                         # Policy evaluation system
    │   ├── __init__.py
    │   ├── base_policy.py               # Base policy class
    │   ├── common.py                    # Shared policy utilities
    │   ├── sec/                         # Security policies
    │   │   ├── __init__.py
    │   │   └── encryption.py            # P-SEC-001 encryption checks
    │   └── fin/                         # Financial/tagging policies
    │       ├── __init__.py
    │       └── tagging.py               # P-FIN-001 tagging checks
    │
    ├── api_stubs/                       # API stub generation
    │
    ├── captures/                        # Lead capture storage (test/demo data)
    │
    ├── .terraform-bin/                  # Downloaded Terraform binaries
    │   └── 1.13.5/
    │
    ├── __pycache__/                     # Python bytecode
    │
    │ ──────────────────────────────────────────────────────────────
    │   CORE PLAN HANDLING
    │ ──────────────────────────────────────────────────────────────
    ├── plan_stream.py                   # Streaming JSON plan parser (521 lines)
    ├── plan_utils.py                    # Plan loading, metadata, traversal (465 lines)
    ├── plan_evolution.py                # Plan comparison logic
    ├── plan_risk.py                     # Risk profiling
    ├── plan_smell.py                    # Code smell detection
    │
    │ ──────────────────────────────────────────────────────────────
    │   POLICY SYSTEM
    │ ──────────────────────────────────────────────────────────────
    ├── policy_pack.py                   # Policy pack management (104 lines)
    ├── policy_manifest.py               # Policy manifest generation
    ├── free_policies.rego               # OPA/Rego policies (exists but Python is active)
    │
    │ ──────────────────────────────────────────────────────────────
    │   OUTPUT & REPORTING
    │ ──────────────────────────────────────────────────────────────
    ├── reports.py                       # Explanation, diff, evolution rendering (531 lines)
    ├── metrics.py                       # Compliance scoring, violation aggregation
    ├── telemetry_schema.py              # Telemetry structure
    │
    │ ──────────────────────────────────────────────────────────────
    │   IAM & TERRAFORM INTEGRATION
    │ ──────────────────────────────────────────────────────────────
    ├── iam_drift.py                     # IAM policy drift analysis
    ├── terraform.py                     # Terraform integration, test execution
    │
    │ ──────────────────────────────────────────────────────────────
    │   PREVIEW & DIFF
    │ ──────────────────────────────────────────────────────────────
    ├── preview.py                       # Preview/diff functionality
    ├── preview_manifest.json            # Preview manifest data
    │
    │ ──────────────────────────────────────────────────────────────
    │   SUPPORTING UTILITIES
    │ ──────────────────────────────────────────────────────────────
    ├── constants.py                     # Exit codes, severity levels, paths
    ├── environment.py                   # Environment metadata, strict mode
    ├── env_flags.py                     # Environment variable flags
    ├── versioning.py                    # Version management
    ├── python_compat.py                 # Python version compatibility
    ├── secret_scrubber.py               # Secret detection/redaction
    ├── suspicious_defaults.py           # Default value detection
    ├── tempfiles.py                     # Temporary file management
    ├── time_utils.py                    # Time utilities
    ├── tmp_path_check.py                # Temp path validation
    │
    │ ──────────────────────────────────────────────────────────────
    │   LEAD CAPTURE (MARKETING)
    │ ──────────────────────────────────────────────────────────────
    ├── lead_api.py                      # Lead API client
    ├── lead_capture.py                  # Lead capture logic
    │
    │ ──────────────────────────────────────────────────────────────
    │   COPILOT TOOLING
    │ ──────────────────────────────────────────────────────────────
    ├── copilot_scaffolder.py            # Scaffolding automation
    ├── copilot_suite_generator.py       # Test suite generation
    ├── copilot_workflow_generator.py    # Workflow generation
    ├── copilot_api_stubber.py           # API stub generation
    └── copilot_determinism_guard.py     # Determinism validation
```

---

## 2. KEY LOGIC FILES AND PURPOSES

### 2.1 CLI Entry Point

**`vectorscan.py`** (1112 lines)
- **Purpose**: Main CLI entry point, argument parsing, command orchestration
- **Modes**: scan, compare, diff, explain, preview, resource-scoped analysis
- **Responsibilities**:
  - Parse CLI arguments
  - Load Terraform plan JSON
  - Orchestrate policy evaluation
  - Format and render output (JSON, YAML, human-readable)
  - Exit code management
  - Lead capture integration
  - Telemetry emission
- **Key Functions**:
  - `main()` - CLI entry and argument handling
  - Various command handlers for scan/compare/diff/explain/preview
  - Output rendering (JSON/YAML/text)

---

### 2.2 Plan Handling (Core Engine)

**`plan_stream.py`** (521 lines)
- **Purpose**: Streaming JSON parser for Terraform plans
- **Responsibilities**:
  - Stream-parse large plan files without loading entirely in memory
  - Extract module statistics
  - Track SLO compliance (latency, resource counts)
  - Schema validation
- **Key Functions**:
  - `stream_plan()` - Main streaming parser
  - `build_slo_metadata()` - SLO tracking
  - Module stats accumulation
- **Classes**:
  - `ModuleStats` - Resource count tracking
  - `PlanStreamError`, `PlanSchemaError` - Error types

**`plan_utils.py`** (465 lines)
- **Purpose**: Plan loading, metadata computation, resource traversal
- **Responsibilities**:
  - Load plan JSON (legacy mode, no streaming)
  - Validate plan schema
  - Compute plan metadata (resource counts, module structure)
  - Build plan diffs between versions
  - Resource iteration/traversal
- **Key Functions**:
  - `load_json()` - Load plan file
  - `load_plan_context()` - Full plan context loading
  - `compute_plan_metadata()` - Metadata extraction
  - `build_plan_diff()` - Diff generation
  - `iter_resources()` - Resource traversal
- **Classes**:
  - `PlanLoadError` - Plan loading exceptions

**`plan_evolution.py`**
- **Purpose**: Plan-to-plan comparison and evolution analysis
- **Responsibilities**:
  - Compare two plan versions
  - Identify resource changes (add/remove/update)
  - Track configuration drift over time

**`plan_risk.py`**
- **Purpose**: Risk profiling for Terraform plans
- **Responsibilities**:
  - Compute risk scores based on plan characteristics
  - Identify high-risk resource types
  - Flag risky changes (destructive operations)

**`plan_smell.py`**
- **Purpose**: Code smell detection in Terraform plans
- **Responsibilities**:
  - Detect anti-patterns
  - Identify suspicious resource configurations
  - Flag potential misconfigurations

---

### 2.3 Policy Evaluation System

**`policies/base_policy.py`**
- **Purpose**: Base policy class defining evaluation interface
- **Responsibilities**:
  - Abstract policy evaluation contract
  - Policy metadata (ID, title, severity, description)
  - Resource matching logic

**`policies/common.py`**
- **Purpose**: Shared policy utilities
- **Responsibilities**:
  - Taggable resource type definitions
  - Common validation helpers (is_nonempty_string, etc.)
  - Shared constants (TAGGABLE_TYPES)

**`policies/sec/encryption.py`** (P-SEC-001)
- **Purpose**: Encryption enforcement policy
- **Responsibilities**:
  - Detect unencrypted resources (S3 buckets, EBS volumes, RDS, etc.)
  - Verify encryption configuration
  - Flag missing encryption at rest

**`policies/fin/tagging.py`** (P-FIN-001)
- **Purpose**: Tagging enforcement policy
- **Responsibilities**:
  - Ensure taggable resources have required tags
  - Validate tag values
  - Support tag exemptions

**`policy_pack.py`** (104 lines)
- **Purpose**: Policy pack management and hashing
- **Responsibilities**:
  - Locate policy files (free_policies.rego)
  - Hash policy pack for versioning
  - Validate policy file existence
- **Key Functions**:
  - `policy_pack_hash()` - Compute policy pack hash
  - Policy file discovery and validation
- **Environment Variables**:
  - `VSCAN_POLICY_PACK_FILES` - Override policy paths
  - `VSCAN_POLICY_PACK_HASH` - Override policy hash

**`policy_manifest.py`**
- **Purpose**: Generate policy manifest (list of available policies)
- **Responsibilities**:
  - Enumerate all policies
  - Export policy metadata
  - Support policy discovery

**`free_policies.rego`**
- **Purpose**: OPA/Rego policy definitions (legacy)
- **Note**: File exists but Python policies in `policies/` are the active implementation
- **Status**: Potentially unused or legacy; Python classes are primary

**`policies/__init__.py`**
- **Purpose**: Policy registry and loader
- **Responsibilities**:
  - `get_policies()` - Return all available policies
  - `get_policy(id)` - Retrieve specific policy by ID
  - Policy instantiation and registration

---

### 2.4 Output & Reporting

**`reports.py`** (531 lines)
- **Purpose**: Render scan results in multiple formats
- **Responsibilities**:
  - Build explanation structures from policy violations
  - Render human-readable text output
  - Render plan diffs in text format
  - Render plan evolution reports
  - Format violation structures for JSON/YAML output
- **Key Functions**:
  - `build_explanation()` - Structure violation data
  - `build_violation_structs()` - Convert violations to output format
  - `render_explanation_text()` - Human-readable violation output
  - `render_plan_diff_text()` - Diff rendering
  - `render_plan_evolution_text()` - Evolution report

**`metrics.py`**
- **Purpose**: Compliance scoring and violation aggregation
- **Responsibilities**:
  - Compute overall compliance score
  - Compute security grade (A-F)
  - Aggregate violations by severity
  - Generate summary statistics
- **Key Functions**:
  - `compute_metrics()` - Overall metrics
  - `compute_security_grade()` - Letter grade
  - `compute_violation_severity_summary()` - Severity counts

**`telemetry_schema.py`**
- **Purpose**: Define telemetry data structure
- **Responsibilities**:
  - Schema for telemetry events
  - Metadata structure for analytics

---

### 2.5 IAM & Terraform Integration

**`iam_drift.py`**
- **Purpose**: IAM policy drift detection
- **Responsibilities**:
  - Compare IAM policy versions
  - Identify permission changes (added/removed)
  - Flag privilege escalation
- **Key Functions**:
  - `build_iam_drift_report()` - Generate IAM drift report

**`terraform.py`**
- **Purpose**: Terraform binary management and integration
- **Responsibilities**:
  - Download and cache Terraform binaries
  - Resolve Terraform version
  - Execute Terraform test command
  - Manage test strategies (modern/legacy)
- **Key Classes**:
  - `TerraformManager` - Binary management
  - `TerraformResolution` - Version resolution
  - `TerraformTestStrategy` - Test execution strategy
  - `ModernTerraformTestStrategy` - Modern test approach
  - `LegacyTerraformTestStrategy` - Legacy test approach
- **Exceptions**:
  - `TerraformNotFoundError`
  - `TerraformDownloadError`
  - `TerraformManagerError`

---

### 2.6 Preview & Diff

**`preview.py`**
- **Purpose**: Preview mode for scanning (interactive/demo)
- **Responsibilities**:
  - Load preview manifest
  - Run preview scans
  - Support demo mode without full plan

**`preview_manifest.json`**
- **Purpose**: Preview manifest data (example plans/resources)
- **Note**: Used for demo/preview mode, not core scanning

---

### 2.7 Supporting Utilities

**`constants.py`**
- **Purpose**: Global constants
- **Defines**:
  - Exit codes (EXIT_SUCCESS, EXIT_POLICY_FAIL, EXIT_INVALID_INPUT, etc.)
  - Severity levels (SEVERITY_LEVELS)
  - Root directory (ROOT_DIR)

**`environment.py`**
- **Purpose**: Environment metadata and strict mode enforcement
- **Responsibilities**:
  - Build environment metadata (OS, Python version, etc.)
  - Strict mode validation (deterministic execution)
  - Clock enforcement
  - Status badge generation
  - Color output detection
- **Key Functions**:
  - `_build_environment_metadata()` - Environment info
  - `_ensure_strict_clock()` - Clock validation
  - `_strict_require()` - Strict mode checks
  - `_status_badge()` - Badge generation
- **Exceptions**:
  - `StrictModeViolation` - Strict mode error

**`env_flags.py`**
- **Purpose**: Environment variable flag parsing
- **Responsibilities**:
  - Parse truthy/falsy environment variables
  - Detect offline mode
  - Detect strict mode
- **Key Functions**:
  - `env_truthy()`, `env_falsey()` - Flag parsing
  - `is_offline()` - Offline mode detection
  - `is_strict_mode()` - Strict mode detection

**`versioning.py`**
- **Purpose**: Version management
- **Responsibilities**:
  - Define VectorScan version
  - Version comparison utilities

**`python_compat.py`**
- **Purpose**: Python version compatibility
- **Responsibilities**:
  - Ensure Python 3.9-3.12 support
  - Check minimum Python version
- **Exceptions**:
  - `UnsupportedPythonVersion`

**`secret_scrubber.py`**
- **Purpose**: Secret detection and redaction
- **Responsibilities**:
  - Detect secrets in plan JSON
  - Redact sensitive values
  - Prevent credential leakage

**`suspicious_defaults.py`**
- **Purpose**: Suspicious default value detection
- **Responsibilities**:
  - Detect potentially dangerous default values
  - Flag insecure defaults (e.g., 0.0.0.0, *, empty passwords)

**`tempfiles.py`**
- **Purpose**: Temporary file management
- **Responsibilities**:
  - Create and manage temp files
  - Cleanup temp resources

**`time_utils.py`**
- **Purpose**: Time utilities
- **Responsibilities**:
  - Timestamp formatting
  - Duration calculation

**`tmp_path_check.py`**
- **Purpose**: Temporary path validation
- **Responsibilities**:
  - Validate temp directory paths
  - Check temp permissions

---

### 2.8 Lead Capture (Marketing)

**`lead_api.py`**
- **Purpose**: Lead API client for marketing
- **Responsibilities**:
  - POST lead data to remote API
  - Handle API errors

**`lead_capture.py`**
- **Purpose**: Lead capture orchestration
- **Responsibilities**:
  - Capture user email/org for leads
  - Write local lead captures to `captures/`
  - Optionally POST to lead API
- **Key Functions**:
  - `maybe_post()` - Conditionally POST lead
  - `write_local_capture()` - Write lead JSON locally

---

### 2.9 Copilot Tooling

**`copilot_scaffolder.py`**
- **Purpose**: Scaffolding automation for Copilot
- **Responsibilities**:
  - Generate boilerplate code
  - Scaffold new policies/tests

**`copilot_suite_generator.py`**
- **Purpose**: Test suite generation
- **Responsibilities**:
  - Generate test suites from policy definitions

**`copilot_workflow_generator.py`**
- **Purpose**: CI/CD workflow generation
- **Responsibilities**:
  - Generate GitHub Actions workflows

**`copilot_api_stubber.py`**
- **Purpose**: API stub generation
- **Responsibilities**:
  - Generate API stubs for testing

**`copilot_determinism_guard.py`**
- **Purpose**: Determinism validation
- **Responsibilities**:
  - Ensure deterministic output across runs
  - Validate reproducibility

---

## 3. CRITICAL ARCHITECTURE NOTES

### 3.1 Policy System

- **Primary implementation**: Python classes in `policies/`
- **Legacy**: `free_policies.rego` exists but may be unused
- **Structure**: Base policy class with SEC and FIN subdirectories
- **Registration**: Policies registered in `policies/__init__.py`
- **Evaluation**: Policies evaluate resources via `evaluate()` method

### 3.2 Plan Loading

- **Dual mode**:
  1. **Streaming** (`plan_stream.py`) - for large plans, memory-efficient
  2. **Legacy** (`plan_utils.py`) - full plan load, simpler API
- **Schema validation**: Both modes validate plan structure
- **Metadata**: `plan_utils.py` computes resource counts, module stats

### 3.3 CLI Modes

1. **scan** - Single plan scan
2. **compare** - Compare two plans
3. **diff** - Diff two plans
4. **explain** - Explain policy violations
5. **preview** - Preview mode (demo)
6. **resource-scoped** - Scan specific resources

### 3.4 Output Formats

- **Human-readable** - Text output with color/badges
- **JSON** - Machine-readable JSON
- **YAML** - YAML audit ledger
- **Telemetry** - Structured telemetry events

### 3.5 Exit Codes

Defined in `constants.py`:
- `EXIT_SUCCESS` (0) - No violations
- `EXIT_POLICY_FAIL` - Policy violations found
- `EXIT_INVALID_INPUT` - Invalid plan/args
- `EXIT_POLICY_LOAD_ERROR` - Policy loading error
- `EXIT_TERRAFORM_ERROR` - Terraform execution error
- `EXIT_TERRAFORM_FAIL` - Terraform test failed
- `EXIT_CONFIG_ERROR` - Configuration error
- `EXIT_PREVIEW_MODE` - Preview mode exit

---

## 4. FREE-TIER CONSTRAINTS

VectorScan is **free-tier only**. Key constraints:

- **Policies**: Limited to P-SEC-001 (encryption) and P-FIN-001 (tagging)
- **No premium features**: No advanced risk profiling, no enterprise policies
- **No cloud API calls**: All scanning is local/offline
- **No license validation**: Free-tier has no license checks

---

## 5. TESTING STRUCTURE

```
tests/
├── unit/
│   ├── test_vectorscan_unit.py       # Main unit tests (1318 lines)
│   ├── test_vectorscan.py            # Legacy unit tests
│   ├── test_aggregate_metrics_unit.py
│   ├── test_build_vectorscan_package_unit.py
│   ├── test_iam_drift_unit.py
│   ├── test_lead_api_unit.py
│   └── test_lead_capture_unit.py
│
├── integration/
│   ├── test_api_cli_integration.py   # CLI integration tests
│   └── test_policy_cli_integration.py
│
├── e2e/
│   └── test_full_user_journey.py     # End-to-end tests
│
├── rego-tests/
│   └── free_policies_test.rego       # OPA/Rego policy tests
│
└── tf-tests/
    ├── iam_agent_role.tftest.hcl     # Terraform test files
    └── vector_db_aws.tftest.hcl
```

**Test Coverage**: 66% complete (160/243 tasks in test-checklist.md)

---

## 6. EXAMPLES STRUCTURE

```
examples/
└── aws-pgvector-rag/
    ├── tfplan-fail.json              # Example failing plan
    └── tfplan-pass.json              # Example passing plan
```

---

## 7. DEPENDENCIES

**Production** (`requirements.txt`):
- Python 3.9-3.12
- No external dependencies (stdlib only)

**Development** (`requirements-dev.txt`):
- pytest
- hypothesis (property-based testing)
- ruff (linting)
- mypy (type checking)

---

## 8. MIGRATION CONSIDERATIONS

### 8.1 Target Pillar Structure

```
src/
└── vectorscan/                       # New location
    ├── __init__.py
    ├── cli.py                        # CLI entry (from vectorscan.py)
    ├── schema.py                     # Schema definitions (new)
    ├── renderer.py                   # Output rendering (from reports.py)
    │
    ├── engine/                       # Core scanning engine (new)
    │   ├── __init__.py
    │   ├── plan_loader.py            # Plan loading (from plan_utils.py, plan_stream.py)
    │   ├── policy_evaluator.py       # Policy evaluation (from policies/)
    │   ├── metadata_computer.py      # Metadata computation (from plan_utils.py)
    │   ├── diff_engine.py            # Diff logic (from plan_evolution.py)
    │   ├── risk_analyzer.py          # Risk analysis (from plan_risk.py)
    │   └── smell_detector.py         # Smell detection (from plan_smell.py)
    │
    ├── adapters/                     # External integrations (new)
    │   ├── __init__.py
    │   ├── terraform_adapter.py      # Terraform integration (from terraform.py)
    │   └── iam_adapter.py            # IAM drift (from iam_drift.py)
    │
    ├── fixpack/                      # Remediation hints (new)
    │   ├── sec/
    │   │   └── P-SEC-001.hcl
    │   └── fin/
    │       └── P-FIN-001.hcl
    │
    └── utils/                        # Supporting utilities
        ├── __init__.py
        ├── constants.py              # Preserve from current
        ├── environment.py            # Preserve from current
        ├── env_flags.py              # Preserve from current
        ├── secret_scrubber.py        # Preserve from current
        └── versioning.py             # Preserve from current
```

### 8.2 Mapping: Current → Target

| Current File | Target Location | Notes |
|--------------|----------------|-------|
| `vectorscan.py` | `cli.py` | CLI entry, refactor main() |
| `plan_stream.py` | `engine/plan_loader.py` | Merge with plan_utils.py |
| `plan_utils.py` | `engine/plan_loader.py` | Merge with plan_stream.py |
| `plan_evolution.py` | `engine/diff_engine.py` | Rename |
| `plan_risk.py` | `engine/risk_analyzer.py` | Rename |
| `plan_smell.py` | `engine/smell_detector.py` | Rename |
| `policies/` | `engine/policy_evaluator.py` | Consolidate policy evaluation |
| `policy_pack.py` | `engine/policy_evaluator.py` | Merge into evaluator |
| `policy_manifest.py` | `engine/policy_evaluator.py` | Merge into evaluator |
| `reports.py` | `renderer.py` | Output rendering |
| `metrics.py` | `renderer.py` or `engine/` | Metrics computation |
| `iam_drift.py` | `adapters/iam_adapter.py` | IAM integration |
| `terraform.py` | `adapters/terraform_adapter.py` | Terraform integration |
| `preview.py` | `cli.py` or remove | Preview mode (optional) |
| `constants.py` | `utils/constants.py` | Preserve |
| `environment.py` | `utils/environment.py` | Preserve |
| `env_flags.py` | `utils/env_flags.py` | Preserve |
| `secret_scrubber.py` | `utils/secret_scrubber.py` | Preserve |
| `versioning.py` | `utils/versioning.py` | Preserve |
| `lead_api.py` | Remove or `utils/` | Marketing feature (optional) |
| `lead_capture.py` | Remove or `utils/` | Marketing feature (optional) |
| Copilot tools | Keep as dev tools | Not part of core package |

### 8.3 Schema Requirements (New)

**`schema.py`** must define:
- `VectorScanOutput` - Top-level output structure
- `Issue` - Individual violation structure
- `PillarScoreInputs` - Scoring inputs
- `GuardscoreBadge` - Badge metadata
- `PlaygroundSummary` - Summary for UI

**Must match**: `schemas/guardsuite_pillar_schema.json`

### 8.4 Canonical Output Format

VectorScan must emit:
```json
{
  "pillar": "vector",
  "scan_version": "2.0.0",
  "guardscore_rules_version": "1.0.0",
  "canonical_schema_version": "1.0.0",
  "latency_ms": 1234,
  "quick_score_mode": false,
  "environment": {...},
  "issues": [...],
  "pillar_score_inputs": {...},
  "percentile_placeholder": "P50",
  "guardscore_badge": {...},
  "playground_summary": {...}
}
```

### 8.5 Remediation Hints

- **Current**: Policies embed remediation text
- **Target**: Use FixPack-Lite hints
- **Format**: `remediation_hint: "fixpack:P-SEC-001"`
- **FixPack files**: `fixpack/sec/P-SEC-001.hcl` (deterministic remediation)

---

## 9. PRESERVATION REQUIREMENTS

### 9.1 Must Preserve

- All CLI modes (scan, compare, diff, explain, preview)
- All output formats (JSON, YAML, text)
- All exit codes
- All environment variable flags
- Streaming plan parser for large plans
- Policy evaluation logic (P-SEC-001, P-FIN-001)
- IAM drift detection
- Terraform integration
- Secret scrubbing
- Strict mode enforcement
- Python 3.9-3.12 compatibility

### 9.2 Can Refactor

- Internal module organization (merge plan_stream + plan_utils)
- Policy registration mechanism
- CLI argument parsing (consolidate into cli.py)
- Output rendering (consolidate into renderer.py)
- Test structure (align with new module layout)

### 9.3 Can Remove (Optional)

- Lead capture (marketing feature, not core scanning)
- Preview mode (if not used)
- Copilot tooling (dev tools, not production code)
- `free_policies.rego` (if confirmed unused)

---

## 10. RISK AREAS

### 10.1 High Risk

1. **Plan loading logic** - Complex, dual-mode (streaming + legacy)
2. **Policy evaluation** - Core business logic
3. **Exit codes** - External contracts with CI/CD
4. **CLI modes** - User-facing API

### 10.2 Medium Risk

1. **Output rendering** - Multiple formats (JSON/YAML/text)
2. **Terraform integration** - Binary management, version resolution
3. **IAM drift** - Complex JSON diff logic

### 10.3 Low Risk

1. **Utilities** - Helper functions, low coupling
2. **Constants** - No logic, just definitions
3. **Lead capture** - Optional marketing feature

---

## 11. NEXT STEPS

1. **Schema Design**: Create `schema.py` matching canonical schema
2. **CLI Migration**: Extract CLI logic from `vectorscan.py` → `cli.py`
3. **Engine Creation**: Build `engine/` modules from plan/policy logic
4. **Adapters**: Create `adapters/` for Terraform/IAM
5. **Renderer**: Consolidate `reports.py` → `renderer.py`
6. **FixPack**: Create deterministic remediation hints
7. **Test Migration**: Update tests for new structure
8. **Smoke Test**: Verify all CLI modes work with new structure
9. **Integration Test**: Run full test suite
10. **Documentation**: Update README, docs for new structure

---

## 12. QUESTIONS FOR USER

1. **Lead capture**: Keep or remove? (Marketing feature)
2. **Preview mode**: Keep or remove? (Demo mode)
3. **Copilot tools**: Keep as dev tools or remove?
4. **free_policies.rego**: Confirm if used; Python policies are active
5. **Rego tests**: Keep `rego-tests/free_policies_test.rego` or migrate?
6. **Quick score mode**: Implement or defer? (For large plans >1000 resources)
7. **Guardscore badge**: Format/style preferences?
8. **Playground summary**: What data to include?

---

**END OF STRUCTURE ANALYSIS**

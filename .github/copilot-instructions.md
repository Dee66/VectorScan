# VectorScan AI Coding Assistant Instructions

## Project Overview
VectorScan is a standalone Terraform plan scanner enforcing two critical guardrails from the VectorGuard suite:
- **P-SEC-001 (Encryption Mandate)**: RDS resources must have `storage_encrypted=true` and `kms_key_id` set
- **P-FIN-001 (Mandatory Tagging)**: AWS resources must have `CostCenter` and `Project` tags

The project is structured as a dependency-free Python CLI with optional OPA/Rego policies for enterprise integration.

## Architecture Patterns

### Core Components
- `tools/vectorscan/vectorscan.py`: Main CLI with JSON parsing, policy checks, and lead capture
- `tools/vectorscan/free_policies.rego`: OPA/Rego equivalent policies for Conftest integration
- `tools/vectorscan/lead_api.py`: FastAPI server for lead capture (development/demo)
- `run_scan.sh`: Audit ledger generator wrapping CLI with YAML output

### Key Design Principles
1. **Zero Dependencies**: CLI runs with Python stdlib only (no pip install required)
2. **Terraform Automation**: Auto-downloads compatible Terraform binaries to `.terraform-bin/`
3. **Dual Policy Engines**: Native Python checks + optional OPA/Rego for enterprise workflows
4. **Lead Magnet Architecture**: Optional email capture with local file backup before HTTP POST

## Development Workflows

### Testing Strategy
```bash
# Run all test suites
pytest tests/unit/          # Property-based tests with Hypothesis
pytest tests/integration/   # CLI-to-API integration tests  
pytest tests/e2e/          # Full user journey tests

# Terraform module tests (requires Terraform >= 1.8.0)
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --terraform-tests
```

### Release Process
```bash
# Create signed release bundle
python3 scripts/create_release_bundle.py --version 1.2.3
# Outputs: dist/vectorscan-free.zip with CLI, policies, Terraform binary, signatures
```

### Local Development
```bash
# Quick validation
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --json

# Generate audit ledger
./run_scan.sh -i examples/aws-pgvector-rag/tfplan-fail.json -e dev -o audit.yaml

# Start lead capture API
uvicorn tools.vectorscan.lead_api:app --host 0.0.0.0 --port 8080
```

## Codebase Conventions

### Policy Implementation Pattern
Each policy check now lives in the pluggable registry under `tools/vectorscan/policies/`:
- Resource iterator: `iter_resources()` traverses nested Terraform modules
- Policy plugin: classes like `sec.encryption.EncryptionPolicy` and `fin.tagging.TaggingPolicy` subclass `BasePolicy`, register via `@register_policy`, and expose `evaluate()`.
- Legacy helpers (`check_encryption`, `check_tags`) remain as thin wrappers for backwards compatibility.
- IAM drift analysis: Separate analysis for risky IAM policy additions

### Test Data Structure
- `examples/aws-pgvector-rag/`: Minimal PASS/FAIL Terraform plan JSONs
- Test files follow property-based testing with Hypothesis for edge case coverage
- Integration tests mock HTTP requests to validate CLI-to-API workflows

### Environment Variables
Critical configuration through env vars (see `vectorscan.py`):
- `VSCAN_TERRAFORM_BIN`: Override Terraform binary path
- `VSCAN_LEAD_ENDPOINT`: HTTP endpoint for lead capture POST
- `VSCAN_IAM_DRIFT_PENALTY`: Score penalty for IAM drift (0-100)
- `VSCAN_OFFLINE`: When truthy (1/true/yes/on) disables telemetry scripts, lead capture, Terraform auto-downloads, and StatsD so air-gapped runs stay deterministic.

### Output Format Conventions
- CLI exit codes: 0=PASS, 2=invalid input, 3=FAIL, 4=policy pack load error, 5=terraform test fail, 6=terraform error
- JSON output includes: `status`, `violations`, `metrics`, `iam_drift_report`, optional `terraform_tests`
- Audit ledger (YAML): Structured compliance report with evidence arrays

## File Organization Logic
- `tools/vectorscan/`: Core CLI and packaging utilities
- `tests/{unit,integration,e2e,tf-tests}/`: Layered test strategy
- `scripts/`: Release automation and metrics collection
- `examples/`: Minimal test fixtures for PASS/FAIL scenarios
- `docs/`: Landing page templates and integration examples

## Integration Points
- **OPA/Rego**: Alternative policy engine via `free_policies.rego`
- **Terraform**: Auto-managed binary downloads for `terraform test` capability  
- **Lead Capture**: Optional HTTP POST with local file backup pattern
- **CI/CD**: GitHub Actions with artifact signing and multi-platform releases

When modifying policies, update both Python checks in `vectorscan.py` AND corresponding Rego rules in `free_policies.rego` to maintain parity.
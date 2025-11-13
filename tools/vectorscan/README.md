# VectorScan (Free Lead Magnet)

A tiny, dependency-free CLI to quickly check two critical issues in your Terraform tfplan.json:

- P-SEC-001: Encryption Mandate  -  RDS instance/cluster must have storage_encrypted=true and kms_key_id set
- P-FIN-001: Mandatory Tagging  -  Mandatory tags CostCenter and Project must be present and non-empty on common resources

This is an MVP to validate interest. For the full 6+ policy Zero-Trust kit, see the main Blueprint.

> **Validation note:** The Blueprint policies ship with 469 Rego tests (OPA) plus Python/Terratest suites for the Terraform modules and CLI, so these free checks share the same enforcement pedigree.

## Usage

```bash
# From repository root
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json

# JSON output
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --json

# Optional: adjustable IAM drift penalty (default 20; range 0–100)
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json \
  --json --iam-drift-penalty 35
# Or via env var
VSCAN_IAM_DRIFT_PENALTY=35 python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --json

# Run Terraform module tests first (auto-downloads CLI >= 1.13.5 if needed)
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --terraform-tests
# Or via env vars
VSCAN_TERRAFORM_TESTS=1 python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json

# Generate an Audit Ledger YAML (includes iam_drift and evidence)
./run_scan.sh -i examples/aws-pgvector-rag/tfplan-fail.json -e dev -o audit_logs/ledger.yaml

# Optional lead capture (local file) with optional HTTP POST
# By default, a JSON capture will be written to tools/vectorscan/captures/
# To also POST, set VSCAN_LEAD_ENDPOINT or pass --endpoint
VSCAN_LEAD_ENDPOINT="https://example.com/lead" \
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json \
  --email you@example.com --lead-capture

# Or explicitly specifying endpoint flag
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json \
  --email you@example.com --lead-capture --endpoint https://example.com/lead
```

Exit codes:
- 0: PASS (no violations)
- 3: FAIL (one or more violations)
- 2: Input file not found or invalid JSON
- 4: Terraform module tests failed (when `--terraform-tests` is enabled)
- 5: Terraform automation error (unable to resolve required Terraform CLI)

## Notes
- This CLI inspects the Terraform plan JSON directly without OPA. It focuses on the two free checks for speed and simplicity.
- For comprehensive checks (network isolation, scaling caps, IAM drift lock enforcement, etc.), run the full PaC Shield (OPA/Rego).

### Terraform Version Automation
- Passing `--terraform-tests` (or setting `VSCAN_TERRAFORM_TESTS=1`) makes VectorScan detect the local Terraform CLI, download v1.13.5 into `tools/vectorscan/.terraform-bin/` when necessary, and run `terraform test` using the modern harness.
- Use `--terraform-bin /path/to/terraform` or `VSCAN_TERRAFORM_BIN` to point at a custom binary.
- Set `--no-terraform-download` or `VSCAN_TERRAFORM_AUTO_DOWNLOAD=0` to disable auto-download and fall back to whichever Terraform version is already installed (legacy mode skips module tests on unsupported versions).
- The JSON output adds a `terraform_tests` block covering status, CLI version, binary source, and truncated stdout/stderr so automation can enforce test gates.

### IAM Drift Report and Score Penalty
- JSON includes `iam_drift_report` (status, counts, items with risky additions, severity_by_action, notaction_broad_allow) and `metrics.iam_drift` summary.
- Optional penalty (deducted from `metrics.compliance_score` when drift fails):
  - CLI: `--iam-drift-penalty 35`
  - Env: `VSCAN_IAM_DRIFT_PENALTY=35`
- Audit Ledger (`run_scan.sh`) includes `iam_drift` and an `iam_drift_evidence` array for traceability.
See: `docs/iam_drift.md` for details.

### Lead Capture Privacy
- No network calls are made unless you provide an endpoint via `--endpoint` or `VSCAN_LEAD_ENDPOINT`.
- A local JSON file is always written when lead capture is enabled so you can inspect exactly what would be sent.

# 📧 Lead Capture Integration

VectorScan supports optional lead capture for users who want to submit their email and scan results for follow-up, support, or product updates.

## API Quick Start

1. Start the local API server:
   ```bash
   uvicorn tools.vectorscan.lead_api:app --host 0.0.0.0 --port 8080
   ```
   - The API will accept POST requests at `http://localhost:8080/lead`.

2. Example payload:
   ```json
   {
     "email": "user@example.com",
     "result": { "status": "FAIL", ... },
     "timestamp": 1700000000,
     "source": "vectorscan-cli"
   }
   ```

## CLI Usage

- To enable local lead capture (writes JSON under `tools/vectorscan/captures`):
  ```bash
  python3 tools/vectorscan/vectorscan.py path/to/tfplan.json --lead-capture --email you@example.com
  ```

- To POST to a remote or local API endpoint:
  ```bash
  python3 tools/vectorscan/vectorscan.py path/to/tfplan.json --email you@example.com --endpoint http://localhost:8080/lead
  ```
  Or set the environment variable:
  ```bash
  export VSCAN_LEAD_ENDPOINT="http://localhost:8080/lead"
  python3 tools/vectorscan/vectorscan.py path/to/tfplan.json --email you@example.com
  ```

- The CLI will print the result and indicate if the lead was saved locally or POSTed to the endpoint.

## Example Output

```
Lead payload saved: /path/to/tools/vectorscan/captures/lead_1700000000_abcd1234.json
Lead POST => HTTP 200 (OK)
```

## Security & Privacy
- Emails are never sent unless you provide `--email` and an endpoint.
- Local captures are stored for your review and can be deleted at any time.
- The API does basic validation and never sends outbound email.

## Using the same logic in OPA (optional)

If you prefer running the free checks through OPA/Conftest, we include a minimal Rego policy with the same logic:

- `tools/vectorscan/free_policies.rego`  -  implements P-SEC-001 (encryption) and P-FIN-001 (mandatory tags).

Example:

```bash
conftest test \
  --policy tools/vectorscan/free_policies.rego \
  examples/aws-pgvector-rag/tfplan-fail.json
```

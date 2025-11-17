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

# Structured remediation metadata (`violations_struct`)
# surfaces docs, HCL snippets, data_taint, and confidence scores for each violation.
# Ideal for ticket templating or downstream automation that needs turnkey fix instructions.

# Narrative explain mode (adds "VectorScan Explain Report" + `explanation` JSON block)
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --explain
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --json --explain

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
# `run_scan.sh` enforces that `-o` paths stay under `audit_logs/` inside the repo root to prevent overwriting arbitrary system files.

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
- 2: Input file not found or invalid JSON
- 3: FAIL (one or more violations)
- 4: Policy pack load error (missing/corrupted bundled policies)
- 5: Terraform module tests failed (when `--terraform-tests` is enabled)
- 6: Terraform automation error (auto-download or CLI execution failure)

## Notes
- This CLI inspects the Terraform plan JSON directly without OPA. It focuses on the two free checks for speed and simplicity.
- For comprehensive checks (network isolation, scaling caps, IAM drift lock enforcement, etc.), run the full PaC Shield (OPA/Rego).
- Air-gapped workflows can export `VSCAN_OFFLINE=1` to disable lead capture, telemetry helpers, Terraform auto-downloads, and StatsD/HTTP touches without changing the CLI output. You can also leave telemetry enabled but silence StatsD specifically via `scripts/telemetry_consumer.py --disable-statsd`, `VSCAN_DISABLE_STATSD=1`, or force-enable emission with `VSCAN_ENABLE_STATSD=1` in shared CI environments.

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

### Policy Pack Integrity Hash
- Every JSON output, audit ledger, and bundle manifest now publishes a `policy_pack_hash` (SHA-256) derived from the bundled Rego policies (`free_policies.rego`).
- Override the list of hashed files via `VSCAN_POLICY_PACK_FILES="path/to/policies"` or the computed value via `VSCAN_POLICY_PACK_HASH` when testing custom builds.
- Auditors can recompute the hash to confirm no policies were tampered with between packaging and runtime.

### Policy Error Reporting
- When any policy check throws an exception, the CLI continues running the remaining policies and records the failure under `policy_errors` in the JSON output.
- `run_scan.sh` mirrors the same block inside the audit ledger and telemetry collectors persist the data (counts plus latest entries) so dashboards can surface degraded coverage.
- The lead capture API and tests accept the richer payloads, making it safe to forward scan results without losing visibility into partial coverage.

### Machine-Readable Severity Index
- `violation_severity_summary` buckets every violation into deterministic `critical`, `high`, `medium`, and `low` counts by policy ID.
- The YAML audit ledger, telemetry logs, summaries, CSV exports, and lead-capture payloads preserve the same map so CI dashboards, StatsD, and analytics tools can rank findings without scraping strings.
- Aggregate helpers (for example `tools/vectorscan/aggregate_metrics.py`) roll these counts up automatically, powering weekly scorecards or executive summaries with zero extra parsing.

### Runtime Telemetry (`scan_duration_ms`)
- Each CLI run records its elapsed time in milliseconds and exposes it under `metrics.scan_duration_ms`.
- `run_scan.sh`, telemetry collectors, CSV/summary exports, and the lead capture API all persist the same value so dashboards can detect performance regressions.
- Set `VSCAN_FORCE_DURATION_MS` when regenerating fixtures to keep goldens stable or to simulate SLA breaches in tests.

### Lead Capture Privacy
- No network calls are made unless you provide an endpoint via `--endpoint` or `VSCAN_LEAD_ENDPOINT`.
- A local JSON file is always written when lead capture is enabled so you can inspect exactly what would be sent.

### Offline Verification (SHA256 + cosign)

Every bundle includes `dist/*.sha256`, `dist/*.sig`, and our public key. To verify the archive without network dependencies:

1. Check the checksum:
  ```bash
  sha256sum vectorscan-free.zip
  cat vectorscan-free.zip.sha256
  ```
  or run the helper:
  ```bash
  scripts/verify.sh -f vectorscan-free.zip -d vectorscan-free.zip.sha256
  ```
2. Verify the signature (optional but recommended):
  ```bash
  cosign verify-blob \
    --key dist/cosign.pub \
    --signature vectorscan-free.zip.sig \
    vectorscan-free.zip
  ```

For mirrors (Gumroad, self-hosted, etc.), use `scripts/gumroad_upload_validator.py` to confirm the mirrored artifact matches the signed release, and `scripts/release_artifact_verifier.py` to download draft GitHub artifacts directly and enforce SHA256 + cosign before publishing.

# 📧 Lead Capture Integration

VectorScan supports optional lead capture for users who want to submit their email and scan results for follow-up, support, or product updates.

## API Quick Start

Requirements: The dev lead-capture API uses FastAPI with Pydantic v2. Ensure your environment has `fastapi>=0.104` and `pydantic>=2` (see `requirements.txt`).

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

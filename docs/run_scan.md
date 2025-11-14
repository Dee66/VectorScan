# `run_scan.sh` Audit Ledger Workflow

`run_scan.sh` wraps the VectorScan CLI to produce the Audit Ledger YAML that executive dashboards and auditors expect. The script runs the CLI once with `--json`, extracts per-policy PASS/FAIL indicators, computes compliance sub-scores, and emits a ledger containing:

- Timestamp and environment metadata.
- Policy statuses for encryption, tagging, network exposure, IAM risk, and IAM drift.
- `overall_score` (0-100) pulled from `metrics.compliance_score`.
- `iam_drift_evidence` entries describing risky additions.
- `audit_status` (`COMPLIANT` when every gate passes).

The script also stores the CLI JSON output in a temporary file so you can inspect `metrics`, `violations`, `iam_drift_report`, and the optional `terraform_tests` block.

## Running the script

```
./run_scan.sh -i examples/aws-pgvector-rag/tfplan-fail.json -e dev -o audit/ledger.yaml
```

The generated ledger includes the `CISO_Mandate` line and compliance scores referenced in marketing materials. Because it runs the CLI once per invocation, the script automatically honors the same `VSCAN_*` environment overrides as the CLI itself (e.g., `VSCAN_TERRAFORM_BIN`, `VSCAN_IAM_DRIFT_PENALTY`, `VSCAN_LEAD_ENDPOINT`).

## Audit-ready delivery

Attach the YAML output plus the signed bundle (with SHA256/cosign verification) when you distribute VectorScan results to compliance teams. Mention the Gumroad CTA or GitHub release where the certified bundle originates. The release doc (`docs/release-distribution.md`) gives the commands for verifying those signatures.

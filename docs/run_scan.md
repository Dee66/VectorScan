# `run_scan.sh` Audit Ledger Workflow

`run_scan.sh` wraps the VectorScan CLI to produce the Audit Ledger YAML that executive dashboards and auditors expect. The script runs the CLI once with `--json`, extracts per-policy PASS/FAIL indicators, computes compliance sub-scores, and emits a ledger containing:

- Timestamp plus a full `environment_metadata` block (platform + release, Python version/implementation, Terraform version/source, and strict/offline flags) sourced from the CLI’s `environment` object or `VSCAN_ENV_*` overrides.
- Deterministic `plan_metadata` with resource counts, module inventory, resource-type tallies, and inferred providers so auditors can see plan scope at a glance.
- Policy statuses for encryption, tagging, network exposure, IAM risk, and IAM drift.
- `overall_score` (0-100) pulled from `metrics.compliance_score`.
- `iam_drift_evidence` entries describing risky additions.
- `audit_status` (`COMPLIANT` when every gate passes).

Need a tight evidence trail for only the changed resources? Run the CLI with `--diff` (and optionally `--json --explain`) before or alongside `run_scan.sh`. The diff flag emits the structured `plan_diff` block for JSON consumers plus a “Plan Diff Summary” in human output, making it easy to attach add/change/destroy counts and attribute deltas to the ledger package.

The script also stores the CLI JSON output in a temporary file so you can inspect `metrics`, `violations`, `iam_drift_report`, and the optional `terraform_tests` block.

## Running the script

```
./run_scan.sh -i examples/aws-pgvector-rag/tfplan-fail.json -e dev -o audit/ledger.yaml
```

The generated ledger includes the `CISO_Mandate` line and compliance scores referenced in marketing materials. Because it runs the CLI once per invocation, the script automatically honors the same `VSCAN_*` environment overrides as the CLI itself (e.g., `VSCAN_TERRAFORM_BIN`, `VSCAN_ENV_PLATFORM`, `VSCAN_ENV_TERRAFORM_VERSION`, `VSCAN_IAM_DRIFT_PENALTY`, `VSCAN_LEAD_ENDPOINT`).

If you also want a narrative summary for stakeholders, rerun the CLI with `--explain` (or `--json --explain`) using the same plan and deterministic env vars. The explain block adds a reproducible “VectorScan Explain Report” plus an `explanation` object in JSON so you can paste the storyline directly into audit notes or attach it alongside the ledger.

## Audit-ready delivery

Attach the YAML output plus the signed bundle (with SHA256/cosign verification) when you distribute VectorScan results to compliance teams. Mention the Gumroad CTA or GitHub release where the certified bundle originates. The release doc (`docs/release-distribution.md`) gives the commands for verifying those signatures.

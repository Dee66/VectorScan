# VectorScan Source of Truth

This document captures every known detail of **VectorScan** and its relationship with **VectorGuard** so that contributors, partners, and downstream consumers have a single source of truth about the standalone scanner, how it ships, and how it integrates with the broader Guard Suite governance story.

## Context

VectorScan used to live inside the VectorGuard mono-repo, but it now exists as its own focused zero-trust audit assistant under `https://github.com/Dee66/VectorScan`. Its mission is to give any Retrieval-Augmented Generation (RAG) team a fast, deterministic answer to whether their Terraform plans are safe to deploy. VectorGuard remains the enterprise-grade governance platform. VectorScan is the `free` CLI audit assistant that detects the highest-signal risks on the way to VectorGuard adoption.

## VectorGuard in a Nutshell

VectorGuard is marketed as the Guard Suite's first pillar, and it focuses on **Zero-Trust governance** for RAG workloads. It blends policy enforcement, Terraform automation, and auditable output so organizations can prove security and compliance in the same pipeline as deployment.

### Key Claims

- VectorGuard enforces least-privilege IAM, encryption mandates, and network isolation for retrieval systems, particularly vector databases such as pgvector.
- The objective is to shift Zero-Trust enforcement left: policies run during CI/CD before Terraform ever hits production.
- VectorGuard turns vague compliance checklists into executable policy checks with measurable PASS/FAIL results.
- Every run emits a cryptographic `Audit Ledger` that provides timestamped proof for executives and auditors.
- It is positioned as an enforcement platform, not just documentation; you get instant visibility and compliance proof at deployment time.

### The Guard Suite Pillars

| Pillar | Focus | Delivery Model | Outcome |
| --- | --- | --- | --- |
| VectorGuard | Security & Data Governance | $79 / $449 per year | Prevents data exfiltration and enforces secure defaults |
| ComputeGuard | FinOps & Cost Governance | $129 / $599 per year | Prevents GPU waste and ensures accountable budgets |
| ModelGuard | Quality & Inference Governance | $199 / $799 per year | Prevents silent model failure and ensures prediction integrity |

VectorScan feeds into this ecosystem as the free CLI that surfaces the most critical guardrails and funnels teams toward VectorGuard subscriptions.

## VectorScan Mission and Capabilities

### Purpose

VectorScan applies the two highest-signal policies from VectorGuard to Terraform plans to provide instant risk detection:

- **P-SEC-001 (Encryption Mandate)** – ensures vector databases (RDS, pgvector, S3, etc.) ship with encryption at rest with the appropriate KMS key.
- **P-FIN-001 (Mandatory Tagging)** – guarantees every foundational AWS resource declares `CostCenter` and `Project` tags to satisfy FinOps accountability.

### Assets and Structure

VectorScan is composed of:

1. `tools/vectorscan/vectorscan.py`: the CLI entry point, packaging helpers, and policy runners.
2. `tools/vectorscan/free_policies.rego`: the two Rego policies that apply the enforcement logic.
3. `tests/`: coverage spanning unit, integration, end-to-end, and Terraform test harnesses.
4. `examples/aws-pgvector-rag/`: sample PASS/FAIL plan snapshots used during testing and documentation.
5. `scripts/`: release automation, metrics collection, and mutation testing helpers.
6. `.github/workflows/`: CI pipelines responsible for linting, testing, and signing release bundles.

### Distribution

The release workflow publishes a signed `vectorscan-free.zip` bundle that includes:

- `vectorscan.py` (CLI driver)
- `free_policies.rego` (policy definitions)
- The Terraform CLI binary scoped to the target platform
- A README with usage instructions
- Cosign signatures and SHA256 checksums for verification

Bundles are published via `https://github.com/Dee66/VectorScan/releases/latest` and mirrored on the VectorScan Gumroad listing, so every download provides the same signed `vectorscan-free.zip`. Each release ships with `<bundle>.zip.sha256`, `<bundle>.zip.sig`, and `<bundle>.zip.crt`; follow `docs/release-distribution.md` to run `sha256sum -c` and `cosign verify-blob` before deploying and record the release URL in your audit ledger.

VectorScan is free, but it also serves as the marketing top of funnel for VectorGuard's paid governance blueprints and enterprise kits.  The packaging/release automation described in `docs/release-distribution.md` shows how to reproduce the multi-platform bundles, SHA256 + cosign verification, and PASS/FAIL smoke tests that gate every release.

## Installation & Usage

### Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
python tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json
```

VectorScan downloads a compatible Terraform binary on demand. Use `VSCAN_TERRAFORM_BIN=/path/to/terraform` to override if you already manage Terraform manually.

### CLI Behavior

- It parses Terraform plan JSON snapshots.
- Executes `free_policies.rego` using Conftest/OPA to validate the encryption and tagging policies.
- Emits PASS/FAIL status for each policy along with accompanying compliance metadata.
- Produces the same Audit Ledger-style output that VectorGuard uses for governance reporting.

### Interpreting Policy Output

- A `PASS` for `P-SEC-001` indicates encryption is enforced on every RDS or vector database resource.
- A `PASS` for `P-FIN-001` shows essential `CostCenter` and `Project` tags are present.
- Failures include diagnostic details pointing team members to missing tags, unencrypted storage, or misconfigured KMS keys.

## How VectorScan Finds Bugs

VectorScan surfaces the highest-impact misconfigurations before Terraform deploys:

1. **Encryption drift** – ensures all data-at-rest resources align to the KMS-based encryption mandate.
2. **Tagging gaps** – ensures billing and ownership metadata are intact so FinOps dashboards stay accurate.

These checks effectively act as bug detectors for security drift or compliance omissions.

## Integration with VectorGuard

VectorScan is VectorGuard's lower rung. Once teams adopt the free CLI and see the same Rego policies in action, migrating to VectorGuard is natural:

- VectorGuard extends the same policy grammar (P-Format) to an entire governance blueprint (security, IAM, networking, auditing, FinOps).
- It introduces additional policies such as `P-SEC-002 (Least-Privilege IAM)`, `P-SEC-003 (Network Isolation)`, and `P-AUD-001 (Immutable Logging)` while continuing to enforce encryption/tagging.
- VectorGuard pairs with Terraform modules, Terratest automation, and an Audit Ledger to deliver an enterprise-ready traceable story.

VectorScan can be used within VectorGuard's pipeline in two ways:

1. **Local validation** – engineers run VectorScan before pushing to Git, catching regressions early.
2. **CI guardrails** – integrate VectorScan into lightweight CI jobs for fast feedback before full VectorGuard policy suites execute.

## Observability & telemetry

VectorScan emits structured telemetry that makes the Compliance Score, Network Exposure Score, and IAM Drift Report actionable. Run `tools/vectorscan/vectorscan.py --json` (or `scripts/run_scan.sh`, which records the same fields inside `VectorGuard_Audit_Ledger`) and capture `metrics`, `violations`, and `iam_drift_report` for dashboards and alerting. `metrics.compliance_score` already applies the configurable IAM drift penalty so the score in your observability stack mirrors what auditors read in the ledger.

Refer to `docs/observability.md` for instrumentation patterns, field definitions, and template scripts that push the telemetry into your favorite metrics backend. The document also explains how to persist the audit ledger alongside the signed bundle so downstream teams have an auditable pipeline entry to cite during incident reviews or governance meetings. The repository now emits `metrics/vector_scan_metrics.json` and `metrics/vector_scan_metrics_summary.json` automatically so compliance and monitoring teams can grab both a detailed log and an aggregated snapshot without extra glue.

## Gumroad Distribution & Entitlement Flow

The VectorScan project keeps a free Gumroad listing that delivers `vectorscan-free.zip` with SHA256 and cosign metadata. Each release bundle is signed by the `.github/workflows/vectorscan-distribution.yml` matrix, so the Gumroad download matches the CI-signed artifact. The listing description also reminds buyers to verify the checksum/signature and follow the Audit Ledger instructions in `docs/run_scan.md` (see below).

VectorGuard sells its paid assets (e.g., the Governance Blueprint and Enterprise Kit) through Gumroad and VectorGuard’s wider marketing funnel. The VectorScan release page (`https://github.com/Dee66/VectorScan/releases/latest`) is the canonical download link, and the Gumroad listing mirrors each CI-signed bundle. Follow `docs/release-distribution.md` to verify the checksum and cosign signature mentioned above. The following steps describe how a customer typically obtains and uses the products:

1. **Purchase** – Customers buy the $79/year Governance Blueprint or the $449/year Enterprise Kit on Gumroad. Each product page includes a description of included assets (Terraform modules, policies, Terratest harnesses, Audit Ledger templates).
2. **Download & Verify** – Gumroad provides signed downloads for the zipped policy bundles. Customers verify Cosign signatures and SHA256 checksums before unpacking.
3. **Activate** – They place the downloaded assets in their repo, run `pip install -r requirements-dev.txt`, and wire the CLI into their CI/CD pipelines.
4. **Iterate** – Teams use VectorScan locally to find bugs and regressions, then promote to full VectorGuard policies once they outgrow the free bundle.

While VectorScan itself is free, Gumroad serves as the commerce layer for the premium VectorGuard contracts, reinforcing the enforcement story with actual paid commitments.

## Policy Coverage Matrix

| Policy | Category | Enforcement Summary |
| --- | --- | --- |
| P-SEC-001 | Security | Deny if storage is unencrypted (KMS required) |
| P-FIN-001 | FinOps | Deny if `CostCenter` or `Project` tags are missing |
| P-SEC-002 | IAM | Deny Terraform plans that grant write/delete to vector data |
| P-SEC-003 | Networking | Deny public access to Vector DB/Subnets |
| P-AUD-001 | Auditing | Deny if log destinations lack versioning and locking |

VectorScan currently enforces the first two policies; VectorGuard completes the matrix.

## Testing & Quality Assurance

- `pytest`: unit/integration coverage for tools and helper utilities.
- Terratest harnesses under `tests/tf-tests/`: validate real Terraform modules such as `vector_db_aws.tftest.hcl` and `iam_agent_role.tftest.hcl`.
- Example plan files show PASS/FAIL states, and the CLI uses these to track regressions.

## Release Process

- Prepare SHA256 checksums and Cosign signatures for the `vectorscan-free.zip` archive.
- Distribute packages through the `.github/workflows` release pipelines, ensuring reproducibility.
- Document release notes and highlight policy/CLI changes for public consumers.

## Audit Ledger Output Sample

```
VectorGuard_Audit_Ledger:
  timestamp: 2025-11-14T22:00Z
  environment: prod-rag-eu-west-1
  encryption: PASS (kms:alias/vector-guard)
  iam: PASS (least-privilege verified)
  network: PASS (no public exposure)
  tagging: PASS (CostCenter=RAG-FinOps)
  audit_status: COMPLIANT ✅
  overall_score: 94/100
  CISO_Mandate: COMPLIANT — Proceed with immediate deployment.
```

VectorScan mirrors this style by generating compliance-ready evidence that leadership can consume during incident or audit reviews.

## FAQ

**Q: Why run VectorScan if VectorGuard exists?**
A: VectorScan is the lightweight, zero-setup option to catch the two riskiest policies before investing in the full governance stack.

**Q: Does VectorScan scale with VectorGuard?**
A: Yes. VectorScan introduces teams to the same policy conventions and audit output. When the free CLI proves its value, teams can subscribe to the Governance Blueprint, which extends the policies and enforcement automation.

**Q: How do I get the paid assets?**
A: Purchase on Gumroad, download the signed bundle, verify the checksum, and integrate into your infrastructure repo with the provided README.

## Additional Notes for Contributors

- Keep the `tools/vectorscan` folder well commented and ensure releases stay reproducible.
- Maintain the sample Terraform plans under `examples/aws-pgvector-rag/` so VectorScan tests always have representative PASS/FAIL cases.
- Update this document whenever VectorScan gains another policy, CLI command, or integration hook.
- Document any new Gumroad product tier or verification step in the `Gumroad Distribution & Entitlement Flow` section.

With this source of truth in place, contributors should feel confident describing how VectorScan fits within the Guard Suite, how to operate it, and how it evolves into full VectorGuard governance.

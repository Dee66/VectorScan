# VectorScan

VectorScan is a focused Terraform plan scanner that enforces the two highest-signal guardrails from the VectorGuard suite:

- **P-SEC-001 Encryption Mandate** – ensure RDS resources ship with encryption and a KMS key.
- **P-FIN-001 Mandatory Tagging** – ensure foundational AWS assets carry CostCenter and Project tags.

This repository hosts the standalone CLI, the lightweight policy bundle, and the automation required to package signed release artifacts.

## Getting Started

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
python tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json
```

The CLI will download a compatible Terraform binary on demand so that `terraform test` can run even on clean machines. Override the binary with `VSCAN_TERRAFORM_BIN=/path/to/terraform` if you prefer a pre-installed CLI.

## Repository Layout

```
.
├── tools/vectorscan/   # CLI sources, packaging helpers, and free policies
├── tests/              # Unit, integration, e2e, and Terraform test harnesses
├── examples/           # Minimal PASS/FAIL plan snapshots used during testing
├── scripts/            # Release automation, metrics collection, mutation tests
└── .github/workflows/  # CI pipelines for linting, testing, and package signing
```

## Releases

The release workflow creates verified bundles (`vectorscan-free.zip`) that include:

- `tools/vectorscan/vectorscan.py`
- `tools/vectorscan/free_policies.rego`
- Terraform CLI binary scoped to the bundle target platform
- README with usage instructions
- Cosign signatures and SHA256 checksums

## License

VectorScan inherits the VectorGuard license. See `LICENSE` for details.

## Contributing

Issues and pull requests are welcome. Please review `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` before submitting changes.

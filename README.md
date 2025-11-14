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

## Distribution & Gumroad

VectorScan bundles are built and signed by the matrix defined in `.github/workflows/vectorscan-distribution.yml`.  Each artifact lands in `dist/` (zip, `.sha256`, `.sig`, `.crt`) so downstream teams can verify the archive with `sha256sum -c` and `cosign verify-blob` (see `docs/release-distribution.md` for the exact commands).  The same automation also publishes draft releases with PASS/FAIL smoke test outputs so the `vectorscan-free.zip` on GitHub Releases always matches the `examples/aws-pgvector-rag` fixtures.

### Download & verify the latest bundle

- Grab `vectorscan-free.zip` from `https://github.com/Dee66/VectorScan/releases/latest` (or the VectorScan Gumroad listing) so you know you are installing the CI-signed artifact.
- Each release ships with `<bundle>.zip.sha256`, `<bundle>.zip.sig`, and `<bundle>.zip.crt`; follow `docs/release-distribution.md` when you run `sha256sum -c` and `cosign verify-blob` before deploying.
- Reference the release tag/URL in your audit ledger output so compliance teams can trace the signed bundle back to the repository and Google the GPG/Cosign evidence.

The free CLI still operates as the VectorGuard funnel: download the signed bundle, verify the credentials, and follow the Audit Ledger wiring described in `docs/VectorScan.md`.  Every FAIL message still calls out the $79 VectorGuard Governance Blueprint as the upgrade option so teams that grow beyond the two policies can take the next step.

### Automated GitHub release & workflow checks

Use `scripts/check_github_release.py` to confirm the latest release exposes the signed `vectorscan-free.zip` bundle and that the `vectorscan-distribution.yml` workflow concluded successfully. It queries GitHub’s REST API (optionally authenticated via `GITHUB_TOKEN`) and exits with an error code if required assets or a successful workflow run are missing.

## Continuous release validation

`validate-release.yml` (in `.github/workflows/`) runs `./run_scan.sh` for the PASS and FAIL fixtures, stores the generated audit ledgers as workflow artifacts, and then executes `scripts/check_github_release.py` so each push keeps the signed bundle + workflow results verifiable. Any failure stops the workflow, calling attention to discrepancies before they reach releases.
The workflow also runs `tools/vectorscan/vectorscan.py` against the PASS fixture with `--terraform-tests` so the Terraform smoke tests that ship with the bundle are exercised on every push, matching the release matrix’s intent.

For automated audit delivery, `docs/run_scan.md` explains how `run_scan.sh` emits the `VectorGuard_Audit_Ledger` YAML with the compliance score, IAM drift evidence, and `CISO_Mandate` messaging.

## License

VectorScan inherits the VectorGuard license. See `LICENSE` for details.

## Contributing

Issues and pull requests are welcome. Please review `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` before submitting changes.

## Terraform tests (optional)

VectorScan can optionally run module-level Terraform tests and include their results in the scanner’s JSON output. This is useful for CI pipelines that want both policy checks and Terraform test evidence in a single run.

- Enable with the `--terraform-tests` flag.
- Auto-downloads are opt-in: set `VSCAN_ALLOW_TERRAFORM_DOWNLOAD=1` (or legacy `VSCAN_TERRAFORM_AUTO_DOWNLOAD=1`) and allow network access via `--allow-network` / `VSCAN_ALLOW_NETWORK=1` when you need VectorScan to fetch Terraform into `.terraform-bin/`.
- The JSON output gains a `terraform_tests` block with:
  - `status`: `PASS` or `FAIL`
  - `strategy`: test harness strategy used (e.g., `modern`)
  - `version`: Terraform version string
  - `binary_path`: absolute path to the Terraform binary used
  - `tests`: array of individual test case results

Notes
- Running `--terraform-tests` now requires either a user-provided binary (`--terraform-bin` / `VSCAN_TERRAFORM_BIN`) or the explicit opt-in described above; downloads never happen silently.
- Scan exit codes are severity-aware: 0=no violations, 1=medium-only violations, 2=high-only violations (also used for invalid/unsatisfied input), 3=critical violations. Operational exits remain unchanged (4=policy pack load error, 5=Terraform test failure, 6=configuration/Terraform errors, 10=preview mode).
- The main CI workflow (`.github/workflows/vectorscan.yml`) provisions Terraform 1.13.5 and runs `vectorscan --terraform-tests` against `examples/aws-pgvector-rag/tfplan-pass.json` so regressions are caught automatically whenever the flag is enabled.

Example (JSON mode)

```bash
VSCAN_ALLOW_TERRAFORM_DOWNLOAD=1 \
python3 tools/vectorscan/vectorscan.py \
  examples/aws-pgvector-rag/tfplan-pass.json \
  --allow-network --terraform-tests --json
```

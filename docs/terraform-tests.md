## Terraform tests (optional)

VectorScan can optionally run module-level Terraform tests and include their results in the scanner’s JSON output. This is useful for CI pipelines that want both policy checks and Terraform test evidence in a single run.

- Enable with the `--terraform-tests` flag.
- Terraform will be auto-downloaded to `.terraform-bin/` if not already present.
- The JSON output gains a `terraform_tests` block with:
  - `status`: `PASS` or `FAIL`
  - `strategy`: test harness strategy used (e.g., `modern`)
  - `version`: Terraform version string
  - `binary_path`: absolute path to the Terraform binary used
  - `tests`: array of individual test case results

Notes
- Running `--terraform-tests` does not require Terraform to be pre-installed; VectorScan manages a compatible binary automatically.
- Exit codes remain consistent: 0=PASS, 2=invalid input, 3=policy FAIL, 4=policy pack load error, 5=terraform test fail, 6=terraform error.

Example (JSON mode)

```bash
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --terraform-tests --json
```

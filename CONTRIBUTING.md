# Contributing

Thanks for your interest in improving PaC MLOps Shield! This repo is designed to be public and auditable. Please follow the guidelines below to keep contributions consistent and high quality.

## Prerequisites
- Git, Bash, and a recent Linux/macOS environment
- Python 3.10+ (for scripts)
- Optional: OPA and Conftest (for policy tests)
- Optional: Terraform (for plan generation)

## Quick Start (Dev)
- Sync the checklist progress after editing tasks:
  - `python3 VectorGuard/scripts/update_checklist_progress.py`
- Run policy/unit tests (if OPA is installed):
  - `tests/run_tests.sh`
- Gate Terraform plans (if Conftest is installed):
  - `scripts/run_conftest.sh`
 - Run pre-commit hooks after installing:
   - `pip install pre-commit && pre-commit install`
   - Hooks enforce `opa fmt`, `terraform fmt`, and a sample conftest run.

## Branching & Commit Style
- Use feature branches: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`
- Conventional commit prefixes are appreciated: `feat:`, `fix:`, `docs:`, `chore:`, `test:`

## Pull Requests
- Include a clear summary and motivation
- Link relevant issues and docs sections
- Ensure CI passes (checklist updater sync, tests)
- Add/refresh documentation when public behavior changes

## Policy Development Tips
- Follow naming: `P-<CATEGORY>-<ID>` (e.g., `P-SEC-002`)
- Provide clear, actionable deny messages
- Add OPA unit tests for PASS and FAIL cases
- Keep helper functions in shared include files when useful

### Policy Test Conventions
- Location: add unit tests under `VectorGuard/tests/rego-tests/`.
- Package: tests must use the SAME `package` as the policy to access `deny` results.
- Naming: test functions must start with `test_` and be self-contained.
- Coverage: include at least one PASS and one FAIL per policy rule.
- Run locally:
  - `opa test VectorGuard/tests/rego-tests -v`

### Generate a real tfplan.json (from the example)
Use this to validate policies against an actual Terraform plan JSON.

```bash
cd VectorGuard/examples/aws-pgvector-rag
terraform init
terraform plan -out tfplan.bin
terraform show -json tfplan.bin > tfplan.json
# Evaluate with Conftest (policies in VectorGuard/policies)
conftest test tfplan.json -p ../../policies
```

### Markdown lint rules
We use `markdownlint-cli2` in CI. A minimal config is provided in `.markdownlint-cli2.jsonc`:
- Allow inline HTML (for the checklist)
- Increase line length to 120
- Do not require H1 as the first line


## Security & Responsible Disclosure
Please read `SECURITY.md` for vulnerability reporting steps.

## Code of Conduct
All participation is governed by `CODE_OF_CONDUCT.md`.

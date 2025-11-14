# VectorScan Distribution & Release Notes

This document explains how VectorScan packages, tests, signs, and distributes the free CLI bundle so you can reproduce the VectorGuard-style release workflow from this repo.

## Automated packaging matrix (`vectorscan-distribution.yml`)
1. **Trigger**: runs on `push` to `master` (aka `main`) and via `workflow_dispatch` with an optional `version` input.
2. **Matrix**: builds on `ubuntu-latest`, `macos-latest`, and `windows-latest`, keeping the same Terraform binary resolution logic (`terraform` vs `terraform.exe`).
3. **Bundle creation**:
   - Calls `python tools/vectorscan/build_vectorscan_package.py --bundle-name vectorscan-free-<platform>`.
   - The packaging script zips `tools/vectorscan/vectorscan.py`, `tools/vectorscan/free_policies.rego`, the tooling README, a `LICENSE_FREE.txt`, and the Terraform binary that matches `REQUIRED_TERRAFORM_VERSION`.
   - A `.sha256` manifest is written next to each zip in `dist/`.
4. **Smoke tests**:
   - The workflow extracts each generated bundle, points `VSCAN_TERRAFORM_BIN` at the embedded Terraform inside `tools/vectorscan/.terraform-bin/<version>/<binary>`, disables auto-download, and runs the CLI on the PASS and FAIL fixtures in `examples/aws-pgvector-rag/`.
   - PASS plans must exit cleanly and report `"status": "PASS"`, while FAIL plans must exit non-zero and report `"status": "FAIL"`.
5. **Cosign signing**:
   - Installs `sigstore/cosign-installer@v3` and signs each `dist/vectorscan-free-<platform>.zip` using `cosign sign-blob` with the experimental certificate mode.
   - Generates `.zip.sig` and `.zip.crt` alongside the zip file so downstream consumers can verify the certificate-based signature.
6. **Artifact upload**: stores `.zip`, `.zip.sha256`, `.zip.sig`, `.zip.crt`, and the smoke test JSON fragments (`*-pass.json`, `*-fail.json`) via `actions/upload-artifact` so later jobs can download them.

### Release & verification jobs
- **publish-release** (manual only): once `workflow_dispatch` is invoked with a `version`, this job downloads the artifacts, lists them, and attaches them to a draft GitHub Release named `VectorScan Free <version>` in `vectorscan-free-<version>`.
- **verify-release-artifacts**: re-checksums and re-verifies the cosign signatures of every zip, then reruns the smoke tests from the extracted bundles to ensure nothing diverged in the release pipeline.

## Automated GitHub validation

Walk through `scripts/check_github_release.py` to automate the validation of your GitHub release state. It fetches the latest release, ensures the signature and checksum artifacts exist, and inspects the most recent run of `vectorscan-distribution.yml` (default branch `main`). Set `GITHUB_TOKEN` if you exceed GitHub’s unauthenticated rate limit or to verify private workflow runs.

`validate-release.yml` now runs `tools/vectorscan/vectorscan.py` on the PASS fixture with `--terraform-tests` as part of its guardrail steps, so the Terraform smoke tests that ship with the release bundles execute on every push along with the audit ledger generation.

## Local helpers
### `tools/vectorscan/build_vectorscan_package.py`
- Produces zip bundles with reproducible metadata (ZIP_DEFLATED, fixed timestamps & permissions).
- If `vectorscan.py` exports `TerraformManager`, the script downloads the required Terraform version into `tools/vectorscan/.terraform-bin/` and embeds it inside the zip. Legacy bundles can use `-legacy` suffix to force Terraform 1.6.0.
- Always writes `LICENSE_FREE.txt` inside the bundle referencing the repo’s main `LICENSE` and writes a `<bundle>.sha256` manifest.

### `scripts/automate_release.py`
- Orchestrates local releases (version prompts, optional SBOM with `syft`, GPG signing, cosign verification, Git tagging, GH release drafts).
- Honors `.release_config.json` for repeatable defaults (SBOM, checksum/cosign verification, bump strategy).
- Accepts non-interactive flags like `--version`, `--gpg-sign`, `--verify-sha`, `--verify-cosign`, `--make-tag`, `--gh-release`, etc.
- Respects the repo root layout by resolving `REPO_ROOT`, `SCRIPTS_DIR`, and `DIST` via `Path(__file__).resolve()`.

## Verifying downloads (index for bundle consumers)
1. Run `sha256sum -c vectorscan-free-<platform>.zip.sha256` or `python3 -m hashlib` if `sha256sum` is unavailable.
2. Use `cosign verify-blob --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-identity-regexp ".*" --certificate <bundle>.zip.crt --signature <bundle>.zip.sig <bundle>.zip` to confirm the artifact came from the CI signal.
3. (Optional) Extract the bundle and rerun the PASS/FAIL `vectorscan.py` commands to double-check the smoke tests yourself.

## Next steps / outstanding items
- Document this workflow in `README.md` or the release checklist so future contributors know to use `.github/workflows/vectorscan-distribution.yml` for automated bundles and `scripts/automate_release.py` for local overrides.
- The checklist still lists "Ensure release tooling (...) works relative to the VectorScan repository root" and "Plan distribution of VectorScan bundles..."; references above show the scripts already resolve `REPO_ROOT`, but keep an eye on cross-platform differences (especially tooling that shell‑executes `bash`) when migrating release gates.

## Release checklist cross-check

- Confirm the README and any marketing docs reference the canonical Gumroad CTA with the vectorguard UTM string: `https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=blueprint`.
- Verify the `docs/vectorscan_landing.*` assets still mention the signed bundle and the Gumroad CTA with the same UTM parameters so downstream analytics can tie VectorScan clicks back to the VectorGuard funnel.
- Confirm `metrics/vector_scan_metrics.log` is generated alongside each audit ledger run (e.g., `./run_scan.sh`). The log is produced by `scripts/collect_metrics.py` and can be archived with the release evidence when you need historical compliance trends.
- Confirm `metrics/vector_scan_metrics_summary.json` is also produced (via `scripts/metrics_summary.py`) and bundle it with release artifacts so downstream monitoring teams can immediately consume aggregated scores without parsing the raw log.
- After the metrics summary exists, run `scripts/telemetry_consumer.py --csv metrics/vector_scan_metrics_summary.csv --statsd-host=${STATSD_HOST}` (with StatsD disabled by default) so downstream dashboards and alerting systems receive CSV rows plus optional StatsD gauges for `vectorscan.telemetry.*`.
- When preparing a release, rerun `scripts/check_github_release.py` (see `.github/workflows/validate-release.yml`) to ensure the workflow artifacts, checksums, and cosign signatures exist for each platform bundle.

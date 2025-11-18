[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#)
[![Status: Stable MVP](https://img.shields.io/badge/Status-Stable%20MVP-yellowgreen.svg)](#)

# VectorScan

**A lightweight, MIT-licensed policy-as-code scanner for Terraform plans.**  
VectorScan enforces a minimal set of high-impact governance checks that catch the most common misconfigurations in AI, data, and cloud-native stacks.

**Philosophy:**  
> **Governance must be codified, not documented.**

---

## Why this tool exists

Terraform plans often conceal subtle but high-risk issues  -  especially in data-heavy or RAG/vector workloads. Across cloud teams, two failures repeatedly cause the majority of governance drift:

- **Data services deployed without encryption or KMS keys.**  
- **Missing cost and ownership tags that destabilize FinOps.**

VectorScan helps you catch these issues *before deployment* with a tiny, auditable policy bundle.

---

## Features (benefits first)

- **P-SEC-001 / Encryption Mandate  -  *Prevent Data Exfiltration.***  
  Validates that data services enforce encryption with a defined KMS key so sensitive workloads remain protected.

- **P-FIN-001 / Mandatory Tagging  -  *Stop Uncontrolled Spend.***  
  Validates that essential FinOps tags like `CostCenter` and `Project` are present and non-empty.

- **Single-file CLI with zero dependency on your local Terraform installation.**  
  VectorScan evaluates any `tfplan.json` input without requiring Terraform to be installed on the runner.

- **Optional bundled Terraform binary** (for advanced module-level tests).

- **CI-friendly YAML ledger** for compliance evidence and audit trails.

- **Machine-readable severity index** via `violation_severity_summary` so dashboards and automation can instantly bucket FAILs into critical/high/medium/low counts.

- **Runtime telemetry (`scan_duration_ms`, `parser_mode`, `resource_count`) baked into every JSON payload** so CI pipelines, run ledgers, and telemetry dashboards can watch performance, parser strategy, and plan size trends without extra scraping.

- **Evidence-grade environment metadata** via the top-level `environment` block (`platform`, `python_version`, Terraform source/version, and strict/offline flags) so every JSON payload and audit ledger records what runtime produced the evidence.

- **Narrative explain mode** so `vectorscan --explain tfplan.json` (or `--json --explain`) tells stakeholders what the plan is doing, which guardrails triggered, and what to fix next.

- **Plan inventory (`plan_metadata`) for every run** so you can see resource counts, module fan-out, resource-type tallies, and inferred providers without re-parsing the plan yourself.

- **Plan smell report (`smell_report`) for structural heuristics** so nested-module bloat, massive `for_each` expansions, missing `kms_key_id` wiring, IAM policy bulk, and huge change volumes are surfaced as advisory metadata (and mirrored in explain output plus the YAML audit ledger).

- **Plan evolution summary (`--compare old.json new.json`)** so CI jobs can diff two Terraform plans without re-running paid policies. The run emits a structured `plan_evolution` block (old vs. new change summaries, deltas, downgraded encryption evidence) plus the human-friendly `+/-/~/!` lines showcased in the marketing docs, helping reviewers spot regression spikes and encryption downgrades instantly.

- **Diff mode (`--diff`) for changed-attribute evidence** so JSON runs gain a structured `plan_diff` block (with add/change/destroy counts plus per-resource attribute deltas) and human output prints a deterministic “Plan Diff Summary.” Works alongside `--explain` to narrate only the changed surfaces that matter.
- **Resource drilldown (`--resource <address>`) for scoped evidence** so you can focus every output (JSON, explain, diff) on a single Terraform address, complete with a `resource_filter` block that records how the selector was resolved (exact vs suffix match).
- **GitHub Action mode (`--gha`) for CI pipelines** so runs emit JSON-only, no-color output with sorted keys and stable indentation, guaranteeing deterministic `stdout` for workflow parsers without needing to remember `--json --no-color` combos.
- **VectorGuard preview mode (`--preview-vectorguard`) as an upsell funnel** so scans can emit a signed preview manifest with teaser policies, set `preview_generated=true`, and exit with code `10` without ever executing paid logic. Great for CI badges and CTA-rich FAIL banners.
- **Signed policy manifest + selection flags** so `vectorscan --policy-manifest` prints the bundled metadata (`policy_version`, `policy_pack_hash`, `policy_source_url`, signature), while `--policies` / `--policy` let you scope runs to specific guardrails (e.g., `--policies finops` or `--policy P-SEC-001`). Every JSON payload now surfaces the canonical `policy_source_url` plus a `policy_manifest` block for supply-chain evidence.

- **Structured remediation metadata (`violations_struct`) for each finding** covering docs, copy-pasteable HCL snippets, taint analysis, and `hcl_completeness` confidence scores so tickets and automations have everything they need to patch drift.

- **MIT license**  -  safe for open source, startups, and enterprises.

---

## Quick start (60 seconds)

```bash
git clone https://github.com/Dee66/VectorScan.git
cd VectorScan

python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json

```

Need to isolate only the changed attributes? Append `--diff` (optionally with `--json` or `--explain`) to emit the structured `plan_diff` block and human-readable “Plan Diff Summary,” keeping explain narratives focused on the delta instead of the full plan.

Need to inspect a single Terraform resource? Add `--resource module.db.aws_rds_cluster.vector_db` (module prefixes optional when the suffix is unique) and VectorScan will scope violations, plan metadata, and optional `--diff` output to that address while emitting a `resource_filter` block so automation knows the exact target.

## GitHub Action mode

Run `vectorscan --gha tfplan.json` inside CI jobs (including the provided GitHub Action workflow) to guarantee machine-stable evidence. The flag is a shortcut for “JSON only, no color, canonical key ordering,” so workflow consumers can parse `stdout` without remembering multiple options.

- Forces `--json` and `--no-color` even if you omit them.
- Emits `json.dumps(..., sort_keys=True, indent=2)` so every run has identical formatting.
- Keeps the normal exit codes (0, 3, 5, etc.) so workflows can fail fast on violations or Terraform test issues.

Pair it with `jq` or `yq` in your workflow to extract metrics, or tee the output into `$GITHUB_STEP_SUMMARY` for deterministic compliance evidence.

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
- Exit codes remain consistent: 0=PASS, 2=invalid input, 3=policy FAIL, 4=policy pack load error, 5=terraform test fail, 6=terraform error, 10=preview-only (`--preview-vectorguard`).

Example (JSON mode)

```bash
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --terraform-tests --json
```

See more details in `docs/terraform-tests.md`.

## Gumroad bundle validation

If you host the VectorScan bundle on Gumroad (or any third-party mirror), run `scripts/gumroad_upload_validator.py` to make sure the mirrored artifact matches the signed GitHub release before publishing.

```bash
python3 scripts/gumroad_upload_validator.py \
  --release-bundle dist/vectorscan-free.zip \
  --gumroad-bundle ~/Downloads/vectorscan-free.zip \
  --release-sha256-file dist/vectorscan-free.zip.sha256 \
  --public-key dist/cosign.pub \
  --signature dist/vectorscan-free.zip.sig
```

- The script compares SHA256 digests for both files (and optional per-file digests if provided).
- When `--public-key` and `--signature` are supplied, it invokes `cosign verify-blob`; add `--require-cosign` if you want the run to fail when cosign isn’t installed.
- Exit code `0` means the Gumroad upload is byte-for-byte identical to the GitHub bundle (and signatures validated when requested).

For draft GitHub Releases, use `scripts/release_artifact_verifier.py` to download the artifact URL (and optional signature URL) directly from GitHub before publishing. It enforces the provided SHA256 digest and, when the cosign public key is supplied, runs `cosign verify-blob` against the downloaded bits.

## Gumroad delivery email verification

The delivery email template lives in `docs/gumroad_delivery_email.md` so we can track the exact copy that Gumroad sends after checkout. Run `scripts/check_gumroad_email.py` during releases to ensure the email still mentions the signed download, `sha256sum -c`, `cosign verify-blob`, and the Blueprint CTA.

```bash
python3 scripts/check_gumroad_email.py --email-file docs/gumroad_delivery_email.md
```

The script fails (exit code `3`) if any of the required verification snippets disappear, preventing regressions in the customer instructions.

## Signing key rotation 🗝️

- `docs/signing.md` documents how we generate, promote, and retire cosign keys plus the emergency revocation steps and customer email template.
- `scripts/signing_key_rotation.py` verifies that both the outgoing and incoming keys successfully validate the release bundle and appends an auditable entry to `docs/signing_key_rotation_log.json`.
- `pytest tests/integration/test_signing_key_rotation.py` exercises the helper with a cosign stub so CI can prove the runbook stays healthy.

## Gumroad download guard & retry telemetry

`scripts/gumroad_download_guard.py` downloads the Gumroad mirror with retry/backoff and emits a metrics JSON so CI can prove the mirror stayed reachable. Point it at the signed bundle URL and (optionally) pass the expected SHA256 digest:

```bash
python3 scripts/gumroad_download_guard.py \
  --download-url "https://example.gumroad.com/vectorscan-free.zip" \
  --output dist/gumroad-download.bin \
  --metrics-file metrics/gumroad_download_guard.json \
  --retries 3 --delay 5 \
  --sha256 "$(cat dist/vectorscan-free.zip.sha256 | cut -d' ' -f1)"
```

The script writes a structured report to `metrics/gumroad_download_guard.json`, including the total attempts, duration, and any HTTP failures. The release workflow (`verify-release-artifacts`) automatically runs this guard when the `GUMROAD_VALIDATION_URL` secret is provided, uploading the metrics as an artifact for audit evidence.

## Deterministic timestamps for CI evidence

VectorScan outputs now honor reproducible clock overrides so JSON results, Gumroad telemetry, and the audit ledger stay identical between runs.

- Set `VSCAN_CLOCK_EPOCH=<epoch_seconds>` to pin the numeric timestamp used by the CLI, lead-capture payloads, and telemetry helpers. `SOURCE_DATE_EPOCH` is respected as a fallback for broader reproducible-build tooling.
- Alternatively set `VSCAN_CLOCK_ISO=<ISO8601>` when you need a specific full timestamp (e.g., `2025-05-01T10:11:12Z`). The helper feeds `run_scan.sh`, Gumroad download guard metrics, and the collectors under `scripts/`.
- For filename-friendly values, call `tools.vectorscan.time_utils.deterministic_timestamp()` inside custom automation.

These knobs make it easy to keep CI artifacts, audit ledgers, and evidence files byte-identical across rebuilds.

## Environment metadata & overrides

Every CLI run now emits an `environment` object and every audit ledger now includes `environment_metadata`. The block captures:

- `platform` / `platform_release`  -  detected from `platform.system()` + `platform.release()` unless `VSCAN_ENV_PLATFORM` / `VSCAN_ENV_PLATFORM_RELEASE` override them.
- `python_version` / `python_implementation`  -  autodetected from the interpreter but overridable via `VSCAN_ENV_PYTHON_VERSION` / `VSCAN_ENV_PYTHON_IMPL` so goldens can pin exact versions.
- `terraform_version` / `terraform_source`  -  reported from the Terraform test harness (system/override/download) or set explicitly with `VSCAN_ENV_TERRAFORM_VERSION` / `VSCAN_ENV_TERRAFORM_SOURCE` when Terraform is not executed.
- `vectorscan_version`  -  defaults to the CLI’s `VECTORSCAN_VERSION` but can be force-set with `VSCAN_ENV_VECTORSCAN_VERSION` for bundle verification scenarios.
- `strict_mode` / `offline_mode` booleans that mirror the active flags for compliance evidence.

Set the corresponding `VSCAN_ENV_*` environment variables in CI to pin metadata for golden tests or air-gapped audits. `run_scan.sh` automatically copies the same block into the YAML ledger so humans and automation can trace what system generated each artifact.

| Field | Override | Notes |
| --- | --- | --- |
| `platform` | `VSCAN_ENV_PLATFORM` | Defaults to `platform.system().lower()` when unset. |
| `platform_release` | `VSCAN_ENV_PLATFORM_RELEASE` | Falls back to `platform.release()`. |
| `python_version` | `VSCAN_ENV_PYTHON_VERSION` | Defaults to `platform.python_version()`. |
| `python_implementation` | `VSCAN_ENV_PYTHON_IMPL` | Defaults to `platform.python_implementation()`. |
| `terraform_version` | `VSCAN_ENV_TERRAFORM_VERSION` | Auto-populated when Terraform tests run, otherwise `not-run`. |
| `terraform_source` | `VSCAN_ENV_TERRAFORM_SOURCE` | Mirrors Terraform test source or `not-run`. |
| `vectorscan_version` | `VSCAN_ENV_VECTORSCAN_VERSION` | Defaults to the CLI’s built-in version string. |
| `strict_mode` | `VSCAN_STRICT` | Boolean emitted from the active strict-mode flag. |
| `offline_mode` | `VSCAN_OFFLINE` | Boolean emitted when telemetry/auto-downloads are disabled. |

Example JSON excerpt:

```json
{
  "environment": {
    "platform": "linux",
    "platform_release": "unit-kernel",
    "python_version": "3.11.test",
    "python_implementation": "CPython",
    "terraform_version": "not-run",
    "terraform_source": "not-run",
    "vectorscan_version": "0.1.0",
    "strict_mode": false,
    "offline_mode": false
  }
}
```

And the matching ledger snippet:

```yaml
environment_metadata:
  platform: linux
  platform_release: unit-kernel
  python_version: 3.11.test
  python_implementation: CPython
  terraform_version: not-run
  terraform_source: not-run
  strict_mode: false
  offline_mode: false
```

## Plan metadata snapshot

VectorScan now emits a `plan_metadata` block in JSON output (and mirrors it into the YAML audit ledger) so you can inventory Terraform plans instantly. It captures:

- `resource_count` and `module_count` – total resources discovered plus the number of modules visited (root + nested).
- `resource_types` – deterministic map of Terraform types to counts (e.g., `aws_db_instance: 2`).
- `providers` – sorted provider list inferred from resource types and explicit provider labels.
- `modules` – structured details about the root module, how many modules actually contain resources, total child modules, and a boolean `has_child_modules` flag.

Example excerpt:

```json
{
  "plan_metadata": {
    "resource_count": 6,
    "module_count": 2,
    "resource_types": {
      "aws_db_instance": 1,
      "aws_rds_cluster": 1,
      "aws_security_group": 2,
      "aws_s3_bucket": 2
    },
    "providers": ["aws"],
    "modules": {
      "root": "root",
      "with_resources": 2,
      "child_module_count": 1,
      "has_child_modules": true
    }
  }
}
```

The block leverages the existing deterministic iterators, so it’s available in offline/strict mode without extra flags. Pipelines can use it to trend plan size, correlate violations with resource mix, or prove coverage for module-heavy repos.

## VectorGuard preview mode (`--preview-vectorguard`)

Use preview mode when you want VectorScan to advertise the larger VectorGuard suite without executing any paid policy logic:

```bash
python3 tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-fail.json --json --preview-vectorguard
```

- The CLI sets `preview_generated=true`, includes an array of `preview_policies`, and emits a `preview_manifest` block summarizing the signed manifest (`version`, `generated_at`, `signature`, `verified`).
- Preview runs always exit with code `10 (PREVIEW_MODE_ONLY)` so CI pipelines can distinguish teaser flows from real policy failures.
- Human-mode output appends a “VectorGuard preview” section that lists the teaser policies and the manifest verification status.
- Environment overrides:
  - `VSCAN_PREVIEW_MANIFEST=/path/to/custom.json` loads a different teaser manifest (useful in enterprise bundles).
  - `VSCAN_PREVIEW_SKIP_VERIFY=1` bypasses signature verification for local development; production bundles leave verification enabled.

JSON excerpt:

```json
{
  "preview_generated": true,
  "preview_policies": [
    {"id": "P-SEC-002", "summary": "IAM roles would fail due to excessive permissions under the Zero-Trust suite."}
  ],
  "preview_manifest": {
    "version": "2025.11.17",
    "generated_at": "2025-11-17T12:00:00Z",
    "signature": "sha256:a25b972105b1d1e4571cb4187f1063f9f57c3850152d3a05e95e9947c4a7aac1",
    "verified": true
  }
}
```

Because the manifest is signed (SHA-256 over the ordered policy list), pipelines can prove the teaser content hasn’t been tampered with before surfacing it in marketing assets.

## Plan diff mode for change-only evidence

Pass `--diff` to focus every output (human + JSON) on changed resources:

- JSON runs emit a `plan_diff` block containing a summary `{adds, changes, destroys}` map plus a `resources[]` array where each entry includes the Terraform address, change action, and only the attributes whose values changed (before/after pairs).
- Human output prints a deterministic “Plan Diff Summary” table after the PASS/FAIL banner so reviewers can see adds/changes/destroys without opening the plan.
- The mode is compatible with `--json --explain` so the explanation narrative references the same scoped diff data instead of the entire plan inventory.

The block is omitted unless the flag is provided, keeping existing automation stable until you opt in. Snapshot tests cover PASS/FAIL/IAM drift runs to guarantee deterministic diffs.

## Explain mode for stakeholders

Run `vectorscan --explain tfplan.json` when you need a quick, deterministic narrative for reviewers or compliance tickets. The CLI still prints the normal PASS/FAIL banner, then adds a structured “VectorScan Explain Report” that summarises:

- Plan intent (resource/module counts, providers, child-module fan-out).
- Current scores (compliance, network exposure, IAM risk) and IAM drift status.
- High-risk resources tied back to policy IDs with severity.
- Ordered recommendations so teams know exactly how to remediate.

Pair it with `--json --explain` to capture the same data under the `explanation` field:

```json
{
  "status": "FAIL",
  "explanation": {
    "summary": "FAIL scan – compliance score 0/100, severity counts [critical=1, high=1, medium=0, low=0], IAM drift PASS (0 risky changes).",
    "plan_overview": {
      "narrative": "Plan defines 1 resource across 1 module (providers: aws; modules with resources: 1; no child modules)."
    },
    "risk_highlights": [
      {
        "resource": "aws_rds_cluster.vector_db",
        "policy_id": "P-SEC-001",
        "severity": "critical",
        "summary": "has storage_encrypted != true"
      }
    ],
    "recommendations": [
      "Remediate aws_rds_cluster.vector_db to satisfy P-SEC-001 (Encryption Mandate): RDS resources must enable storage encryption and reference a kms_key_id."
    ]
  }
}
```

Because the extraction uses the same deterministic helpers as the golden JSON tests, adding `--explain` never breaks reproducibility. The block is omitted unless you pass the flag, so existing automation keeps working until you opt in.

## Strict terminal mode for golden pipelines

- Export `VSCAN_STRICT=1` when running the CLI inside enterprise pipelines that require immutable evidence. Strict mode enforces deterministic timestamps (you must provide `VSCAN_CLOCK_EPOCH`, `VSCAN_CLOCK_ISO`, or `SOURCE_DATE_EPOCH`), blocks `policy_errors`, and disables log truncation so CI captures the full Terraform output.
- Any strict-mode violation (missing deterministic clock, truncated output, policy engine warning) results in exit code `6` (CONFIG_ERROR), making it impossible to accidentally ship partial coverage.
- The mode still works for both human and `--json` output; use it alongside snapshot tests to guarantee byte-identical results in golden environments.

## Policy pack integrity metadata

- Every CLI JSON payload, manifest, telemetry log, and audit ledger exposes `policy_pack_hash`, a SHA-256 digest computed from the bundled Rego policies (`tools/vectorscan/free_policies.rego`).
- Recompute the hash locally to detect tampering or drift whenever you mirror the bundle to Gumroad/S3 or repackage for air-gapped environments.
- A new top-level `policy_source_url` field documents where the policies originated (override via `VSCAN_POLICY_SOURCE_URL` when mirroring the pack).
- The JSON output now includes a signed `policy_manifest` object describing the active policy selection (`policy_version`, `policy_pack_hash`, `policy_source_url`, `policy_count`, detailed `policies[]`, and `signature/signed/verified/path` metadata). This block stays deterministic when you pass `--policies` / `--policy` filters, making it trivial to diff evidence across releases.
- Run `vectorscan --policy-manifest` (without a plan argument) to print the current manifest and exit. Provide a path alongside a plan (`vectorscan tfplan.json --policy-manifest dist/policies.manifest.json`) to embed your own signed metadata, or simply use the embedded manifest for everyday scans.
- Use `--policies` to enable named presets (`free`, `finops`, `security`, `all`) or list explicit policy IDs with `--policy P-SEC-001 --policy P-FIN-001`. The `checks` array and `policy_manifest.policies` list always reflect the guardrails that actually executed.

### Policy error transparency
- The CLI now always emits a `policy_errors` array indicating any policy that failed to execute, keeping isolation failures explicit even when other checks continue.
- `run_scan.sh` adds the same block to the YAML audit ledger, while telemetry logs, summaries, and CSV exports track counts plus the latest errors for dashboards and monitors.
- Lead capture payloads and API models accept the richer data so downstream workflows (CRM, analytics, etc.) can surface degraded coverage immediately.
- Override the input files via `VSCAN_POLICY_PACK_FILES` (colon-separated list of files or directories) or directly set `VSCAN_POLICY_PACK_HASH` when testing custom builds or legacy bundles.

### Machine-readable severity index
- Every CLI JSON payload surfaces `violation_severity_summary` with deterministic `critical/high/medium/low` counts mapped from each policy ID, enabling dashboards and alerting rules to triage instantly.
- `run_scan.sh` mirrors the map inside the audit ledger and telemetry collectors propagate both the latest and cumulative severity totals, unlocking weekly scorecards without additional parsing.
- Lead capture payloads, metrics aggregation scripts, and CSV exports all preserve the map so downstream systems (StatsD, BI, CRM) can classify findings without guessing from strings.

### Runtime telemetry (`scan_duration_ms`, `parser_mode`, `resource_count`)
- `metrics.scan_duration_ms` captures wall-clock execution time (also mirrored across telemetry logs, CSV exports, StatsD timers, and the YAML audit ledger) so you can alert on regressions.
- `metrics.parser_mode` records whether the run used the streaming parser or fell back to the legacy loader, helping operators detect degraded parsing coverage or unexpected legacy code paths.
- `metrics.resource_count` mirrors the total Terraform resources parsed for each plan, unlocking per-run capacity tracking and enabling telemetry summaries to correlate runtime vs. plan size.
- Override `metrics.scan_duration_ms` via `VSCAN_FORCE_DURATION_MS` when you need reproducible fixtures or deterministic CI snapshots; `parser_mode` and `resource_count` always reflect the CLI’s real plan metadata so telemetry can verify parsing coverage and scale.
- Aggregate helpers and StatsD exports stream the trio as gauges/timers (avg/p95/max/latest where applicable) so Datadog/Graphite dashboards can spot slow scans, parser fallbacks, or sudden resource spikes.

### Offline mode (`VSCAN_OFFLINE`)
- Set `VSCAN_OFFLINE=1` (or `true/yes/on`) to disable every side-effecting integration - telemetry collection, metrics summaries, StatsD emission, lead capture (local + HTTP), and Terraform auto-downloads - while keeping CLI/stdout/JSON output identical for reproducible, air-gapped workflows.
- `tools/vectorscan/vectorscan.py`, `run_scan.sh`, and the telemetry helpers (`scripts/collect_metrics.py`, `scripts/metrics_summary.py`, `scripts/telemetry_consumer.py`) all honor the flag so no network activity or telemetry files are produced.
- Terraform module tests can still run when `--terraform-tests` is provided and a binary is already available; offline mode simply guarantees VectorScan never downloads a new CLI or sends outbound packets.
- Need a softer kill switch? Pass `--disable-statsd` to `scripts/telemetry_consumer.py` or export `VSCAN_DISABLE_STATSD=1` (with optional `VSCAN_ENABLE_STATSD=1` overrides) to silence StatsD packets without touching other telemetry behaviors.

## JSON output schema reference

- The live JSON contract (top-level fields, metrics, IAM drift report, etc.) is documented in `docs/output_schema.md`.
- Regenerate the document any time the payload shape changes: `python3 scripts/generate_schema_docs.py`.
- CI exercises the generator through `tests/unit/test_generate_schema_docs_unit.py`, keeping the docs in lockstep with the CLI output.

## Policy plugin architecture

- Core guardrails now live under `tools/vectorscan/policies/` with a tiny registry (`base_policy.py`) plus logical namespaces like `sec/encryption.py` and `fin/tagging.py`.
- Each plugin subclasses `BasePolicy`, declares metadata (ID, severity, description), and implements `evaluate(resources)`  -  the CLI automatically loads every registered plugin via `get_policies()`.
- Legacy helpers (`check_encryption`, `check_tags`) now delegate to the plugin registry, so existing tests/scripts keep working while new policies can be added by dropping in a module and annotating it with `@register_policy`.
- `tests/unit/test_policy_plugins_unit.py` ensures the registry stays populated and plugins return the same violations the legacy helpers produced.

## Bundle hygiene guardrails

- The packaging script (`tools/vectorscan/build_vectorscan_package.py`) now refuses to add Finder artifacts such as `__MACOSX`, `.DS_Store`, or AppleDouble (`._*`) files. Any attempt to include them fails the build immediately so we never publish polluted archives.
- `tests/integration/test_packaging_verification.py::test_bundle_contains_no_hidden_mac_artifacts` unzips a freshly built bundle during CI and asserts that the archive is clean. This prevents regressions if future packaging changes accidentally add hidden files.

## Release manifest + deterministic builds

- Each build emits `dist/<bundle>.manifest.json` and ships the same file inside the zip as `manifest.json`. The manifest lists every bundled file with its path, size, and SHA256 hash plus the declared bundle version.
- Pass `--bundle-version` (or set `VSCAN_BUNDLE_VERSION`) when invoking `tools/vectorscan/build_vectorscan_package.py` so the manifest records the release tag (for example `--bundle-version v0.4.0`).
- The manifest timestamp honors `SOURCE_DATE_EPOCH` and defaults to `0` so builds stay reproducible. When cutting a release, export `SOURCE_DATE_EPOCH=$(date +%s)` to capture the real publish time while preserving deterministic archives.
- Manifest files also receive their own `.sha256` sidecar so CI/CD can verify both the archive and its metadata without bespoke tooling.
- Each bundle now includes `sbom.json` (CycloneDX 1.5) plus `dist/<bundle>.sbom.json` and checksum. The SBOM is generated from `requirements.txt` / `requirements-dev.txt` so downstream supply-chain scanners can diff dependencies without running extra tooling.
- `manifest.json` now embeds a signed `policy_manifest` block (with `policy_version`, `policy_pack_hash`, deterministic policy metadata, and signature), a `preview_manifest` summary (`path`, `sha256`, `signature`, policy count), and a `signers` array describing the cosign verification command + issuer for each bundle. The `tools/vectorscan/preview_manifest.json` file is now part of every archive so `--preview-vectorguard` works out of the box.
- `tests/integration/test_packaging_verification.py::test_sbom_matches_requirement_files` keeps the SBOM in lockstep with the requirements files, preventing drift between the lockfile and the published metadata.
- Archive entries use a fixed timestamp (Jan 1 1980 UTC) driven by `SOURCE_DATE_EPOCH` so `zipinfo` diffs stay stable across platforms. See `tests/integration/test_packaging_verification.py::test_zip_entries_have_fixed_timestamp` for coverage.
- `tests/integration/test_packaging_verification.py::test_cli_runs_from_unzipped_bundle` extracts the generated archive and executes `tools/vectorscan/vectorscan.py` directly to guarantee the published bundle works end-to-end with real plans.
- Text assets are normalized to LF line endings before zipping, preventing CRLF drift on Windows hosts (`test_text_files_normalized_to_lf`).
- Unicode filenames remain intact inside the archive so localized docs or assets can ship safely (`test_unicode_filename_is_preserved`).
- The Terraform auto-download path verifies HashiCorp’s published SHA256 sums before bundling the binary; any mismatch fails the build immediately.
- Sensitive artifacts such as `.env`, private keys, caches, and `__pycache__` directories are blocked during packaging (`test_sensitive_files_are_blocked`).

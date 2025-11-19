# VectorScan Implementation Checklist

<style>
.sc-card{border:1px solid #2f2f46;border-radius:10px;margin:1.25em 0;padding:1.15em;background:#121212;}
.sc-hero{margin:1.4em 0;padding:1.4em 1.2em;background:#121212;}
.sc-header{display:flex;justify-content:space-between;flex-wrap:wrap;gap:.75em;margin-bottom:.9em;font-size:.9em;color:#bbb;}
.sc-header a{color:#a5b4fc;font-weight:600;text-decoration:none;}
.sc-title{text-align:center;margin:0;font-size:2em;color:#fff;}
.sc-progress{text-align:center;margin:.8em 0 .9em;}
.sc-legend{font-size:.72em;display:flex;flex-wrap:wrap;gap:1.1em;margin:.9em 0 .2em;color:#bbb;}
.sc-pill{background:#181818;border:1px solid #2a2a2a;padding:.35em .55em;border-radius:6px;}
@media (max-width:760px){.sc-title{font-size:1.6em;} .sc-progress progress{width:100%!important;}}
progress::-webkit-progress-value{background:linear-gradient(90deg,#6ee7b7,#22d3ee);} 
progress::-webkit-progress-bar{background-color:#1f2937;border-radius:6px;} 
progress::-moz-progress-bar{background:linear-gradient(90deg,#6ee7b7,#22d3ee);} 
</style>

<section class="sc-card sc-hero">
   <h1 class="sc-title">VectorScan Implementation Checklist</h1>
   <div class="sc-progress">
      <progress id="vs-progress" value="62" max="100" aria-label="VectorScan progress" style="width:60%;height:18px;"></progress>
      <div id="vs-progress-label">66% Complete (87/131)</div>
   </div>
   <div class="sc-legend">
      <span class="sc-pill">🟩 Complete</span>
      <span class="sc-pill">🟥 Remaining</span>
   </div>
</section>

This checklist now tracks the standalone VectorScan repo work that originated in VectorGuard’s migration plan. It pairs a history of what shipped with the remaining implementations we need to finish the freemium offering, packaging, and Gumroad delivery so we can plug into the VectorGuard funnel.

## Phase 1 – Free Asset Foundation

- [x] Free Asset Policy Selection: bundle **P-FIN-001** and **P-SEC-001** into a self-contained policies.rego that ships with the free CLI.
- [x] Isolate Free Rego: extract a minimal Rego file that executes only the two high-signal guardrails and share it with VectorGuard documentation.
- [x] VectorScan Utility Development: deliver the Python CLI that reads `tfplan.json` and can run without preinstalled Terraform.
- [x] VectorScan Embedded Logic: integrate the isolated `P-FIN-001` and `P-SEC-001` rules so the CLI behavior matches VectorGuard expectations.
- [x] Lead Capture Integration: wire the lightweight lead-capture endpoint so successful CLI runs optionally submit an email address.
- [x] Failure Message CTA: ensure any VectorScan FAIL output promotes the $79 VectorGuard blueprint as the next step.

### Phase 1 Supplements

- [ ] Add canonical schema reference implementation (matching VectorGuard v2.2).
- [ ] Add scan_version constant + placement in output.
- [ ] Add guardscore_rules_version constant + placement in output.
- [ ] Keep environment inference logic in lockstep with ComputeScan/PipelineScan (see ⭐ VectorScan v2.0 Compatibility Requirements).

## ⭐ VectorScan v2.0 Compatibility Requirements

- [ ] Adopt canonical 3-pillar JSON schema for all outputs.
- [ ] Add version metadata (surface in CLI outputs, audit ledger, telemetry, and manifest.json):
   - scan_version
   - guardscore_rules_version
   - canonical_schema_version
- [ ] Add latency_ms measurement to every run.
- [ ] Add wasm_supported flag for Playground runtime detection.
- [ ] Add quick_score_mode logic:
   - Triggered when plan >1000 resources OR >40MB.
- [ ] Add guardscore_badge metadata block (eligibility + placeholder).
- [ ] Add severity aggregation block (pillar_score_inputs).
- [ ] Add percentile_placeholder flag.
- [ ] Rename “violations” → “issues” in all outputs, tests, docs.
- [ ] Add standardized issue fields:
   id, severity, title, description, attributes, remediation_hint, remediation_difficulty.
- [ ] Add environment inference block (inferred_stage + providers).
- [ ] Add playground_summary field for funnel messaging.

## Phase 2 – Observability, Outputs, and Testing

- [x] VectorScan `--json` output implementation so automation can parse structured compliance data.
- [x] VectorScan JSON schema basic test (PASS/FAIL plans) to keep the output deterministic.
- [x] Add a GitHub Action step that runs VectorScan on PASS and FAIL plans as part of the repo’s smoke tests.
- [x] Package VectorScan (`vectorscan.zip` with `README`, binary, policies) for the landing page download.
- [x] Add UTM tracking to the VectorScan README link so we can trace referrals from VectorGuard’s README/docs.
- [x] Compliance Score (0–100) calculation in the CLI output so leadership sees a quantitative health metric.
- [x] Network Exposure Score implementation for vector DB resources.
- [x] IAM Drift Report export (PASS vs. FAIL) shipped with the CLI export bundle.
- [x] Terratest integration harness for end-to-end validation of VectorScan against real Terraform modules.
- [x] Update marketing assets, READMEs, and the Gumroad description to state “validated by over **469+** passing Rego tests.”
- [x] Implement VectorScan packaging CI matrix (Linux/macOS/Windows) with Terraform smoke tests on PASS/FAIL plans.
- [x] Automate `cosign` signing & verification for each platform bundle and publish artifacts so downloads are verifiable.
- [x] Add deterministic timestamp injection helper to ensure reproducible JSON, ledger, and CI outputs
   - Introduced `tools.vectorscan.time_utils` with env-driven clock overrides consumed by the CLI, telemetry scripts, Gumroad guard, and `run_scan.sh` so CI can pin `VSCAN_CLOCK_EPOCH`/`VSCAN_CLOCK_ISO` for repeatable artifacts.
- [x] Validate that JSON output is stable and ordered under repeated runs (schema drift tests)
   - Added `tests/unit/test_vectorscan_unit.py::test_vectorscan_json_output_stable` which pins the deterministic clock, runs `vectorscan.py --json` twice on the FAIL plan, and asserts the pretty-printed JSON payloads (and parsed objects) are byte-identical.
- [x] Add golden-file comparison tests for PASS, FAIL, and IAM drift JSON outputs
   - `tests/test_json_output.py` now runs the CLI with deterministic env vars and compares the full JSON payloads for `tfplan_pass.json`, `tfplan_fail.json`, and `tfplan_iam_drift.json` against the snapshots under `tests/golden/*.json`, catching any schema/order regressions end-to-end.
- [x] Add a "large plan" test (5MB+) to confirm performance and deterministic ordering
   - `tests/performance/test_performance_sanity.py::test_vectorscan_large_plan_over_5mb` now synthesizes a >5MB tfplan, asserts the CLI stays under the 6s budget, and reruns the CLI to verify JSON output determinism under the deterministic clock helper.
- [x] Add negative tests for malformed or partial tfplan JSON structures
   - `tests/test_tfplan_structure.py` now covers missing `planned_values`, missing `root_module`, and `child_modules=None`, ensuring the CLI exits cleanly (0 or 3 depending on policy violations) instead of crashing.
- [x] Add unit tests for compliance score normalization (0–100 range enforcement)
   - Added a Hypothesis property test (`tests/unit/test_vectorscan_unit.py::test_compute_metrics_compliance_score_bounds`) and a CLI-level regression (`test_compliance_score_penalty_clamped`) to verify the computed score, including IAM drift penalties, always stays in the 0–100 band.
- [x] Validate correct handling of unknown Terraform resource types in investigation phase
   - `tests/unit/test_vectorscan_unit.py::test_unknown_resource_types_handled` runs the CLI on a custom provider resource to assert it stays PASS, with zero eligible checks and a normalized compliance score of 100.

➕ Add to Output Requirements
- [ ] Complete the ⭐ VectorScan v2.0 Compatibility Requirements checklist so JSON/text/ledger outputs stay aligned across guardscore fields, latency/wasm/quick-score flags, and the standardized issue schema.

➕ Expand Test Coverage
- [ ] Snapshot tests for canonical v2.0 schema structure.
- [ ] Validate issue object schema (id, severity, title, description, attributes, remediation fields).
- [ ] Test guardscore_badge metadata is present and deterministic.
- [ ] Test environment inference outputs correct dev/stage/prod detection.
- [ ] WASM warm-up test (simulate wasm_supported flag).
- [ ] QuickScoreMode test (>1000 resources OR >40MB plan).

🧪 Performance & Playground Additions
- [ ] Enforce total latency <1300ms under WASM test harness.
- [ ] Add large-plan test verifying Quick Score Mode <2000ms.
- [ ] Add guardrail test verifying no blocking behavior from WASM initialization.

## Phase 3 – VectorScan Repo Launch

   - Draft standard Apache 2.0 (or chosen) license copy, surface the repo mission, and reference the VectorGuard SLA tiers.
   - Provide clear contributing guidelines covering issue triage, testing, and release expectations so future contributors adopt the governance mindset.
   - Include a Code of Conduct clause and a README section that directs readers to VectorGuard for paid policies and Gumroad upgrades.
   - Mirror the VectorGuard CI matrix for Linux/macOS/Windows so each bundle is reproducible and signing steps are automated.
   - Add CI steps to publish GitHub release drafts, upload the signed `vectorscan-free.zip`, and capture checksums for each run.
   - Document the release checklist (what to verify before tagging, how to trigger Cosign signing, how to update badges/links).
   - Update scripts to locate the bundled CLI, policy files, and fixtures in the new path layout; rewrite relative imports if needed.
   - Verify the `cosign` invocation finds the signing key via environment variables and gracefully skips signing when credentials are absent (for local dev testing).
   - Add smoke tests that run `automate_release.py` in dry-run mode to confirm packaging still succeeds after the repo move.
   - Rewrite hero CTAs or README links in the docs to point to the new repo landing pages, including the new Gumroad download instructions.
   - Audit GIFs, badges, and release notes to ensure no references to the old VectorGuard path remain.
   - Keep `docs/VectorScan.md` updated with the repo's canonical structural overview and shipping milestones.
   - Decide on the cadence for GitHub release tag pushes (e.g., `v0.1.0` increments) and schedule the GitHub Release description to include auditing instructions.
   - Build/out the landing page download flow so consumers can grab the bundle from GitHub or the Gumroad purchase portal (signature + checksum links).
   - Keep a reference to the `vectorscan-free.zip` in the README and the Gumroad delivery email, ensuring both mention SHA256 + Cosign verification.
   - Hook up the new CI to run the same `run_scan.sh` scenario used in VectorGuard for PASS/FAIL plans to prove parity.
   - Monitor Terraform smoke tests on Linux/macOS/Windows to ensure each plan scenario still demonstrates the `Compliance Score`, `Network Exposure Score`, and `IAM Drift` outputs.
   - Re-baseline VectorGuard docs and quickstarts to reference the new repo path (`Dee66/VectorScan`) and confirm relative links in markdown build.
   - [x] Generate manifest.json containing full file list + SHA256 + version metadata
   - [x] Add reproducible build step (fixed mtime on all bundled files)
   - [x] Add cross-platform newline normalization tests (CRLF vs LF)
   - [x] Add Unicode path and filename support tests
   - [x] Add test to run CLI inside a freshly unzipped release bundle
   - [x] Validate Terraform binary (if included) using publisher SHA256 checksum
    - [x] Add negative tests for malformed or partially-generated bundles
       - `tests/integration/test_bundle_integrity_checker.py` now includes corrupt zip and invalid manifest JSON scenarios, ensuring the validator exits with the correct error codes when bundles are truncated or partially written.
    - [x] Validate that bundle excludes .env, private keys, caches, and __pycache__
    - [x] Add test ensuring all subprocess calls are sanitized and cannot escape working directory
       - `tests/unit/test_subprocess_sanitization.py::test_modern_strategy_commands_include_safe_chdir` confirms every Terraform subprocess invocation receives the sanitized `-chdir` flag derived from `_safe_chdir_flag`.

- [ ] Add multi-pillar messaging to README: “VectorScan is Pillar #1 of GuardSuite (Vector + Compute + Pipeline).”

## Phase 4 – Launch Readiness & Gumroad

- [x] Publish the VectorScan Gumroad product, configure pricing (free), payout info, download limits, and delivery email copy.
   - Set up the Gumroad listing to deliver the signed bundle with SHA256 metadata and provide a friendly onboarding email (CTA to VectorGuard Blueprint).
   - Capture internal notes about tracking codes (UTM, coupon) so we can later reconcile downloads with conversion rates.
- [x] Document the VectorScan → VectorGuard upgrade path (how the free CLI surfaces the same policies before teams buy the $79/year blueprint).
   - Write a short note or FAQ entry describing which policies run in VectorScan (P-SEC-001 + P-FIN-001) versus the full VectorGuard suite.
   - Link to the VectorGuard documentation that explains how to upgrade from VectorScan to the paid governance blueprint for more policies (P-SEC-002, P-SEC-003, P-AUD-001).
- [x] Automate `run_scan.sh` to emit the `Audit Ledger` template, capture the Compliance Score, and surface the CISO mandate messaging used across the guard suite.
   - Update `run_scan.sh` (or the new CLI workflow) to generate the YAML-style audit ledger from the VectorGuard architecture doc and include fields like `overall_score` and `audit_status`.
   - Ensure the script stores the ledger output alongside the compliance metrics so it can be attached to audit emails or zipped artifacts.
- [x] Confirm downloads include SHA256 and `cosign` metadata for every platform bundle and document the verification steps in the README.
   - Add a `verify.sh` or README section that fetches the downloaded bundle, checks the SHA256 sum, and runs `cosign verify` for the release keys.
   - Publish the public key in the README so anyone can verify or reproduce the signing process.
   - [x] Produce SBOM (CycloneDX or SPDX) for every release

- [x] Add SBOM validation test ensuring dependency versions match lockfiles
- [x] Add CI test to verify cosign signatures using the public key
- [x] Add test that downloads draft GitHub Release artifact and verifies SHA256 + signature
   - [x] Add verify.sh script inside the bundle for consumer use
- [x] Create Gumroad upload validator script ensuring bundle matches GitHub artifacts
- [x] Add reproducibility test ensuring two consecutive artifact builds are byte-identical
- [x] Add documentation in bundle explaining offline verification of signature + checksums
- [x] Add safety test ensuring vectorscan-free.zip contains no extra hidden files on macOS
- [x] Add automated check that Gumroad delivery email contains correct verification instructions

## Security Requirements Reinforcements

- [ ] Strip absolute paths, usernames, and workspace identifiers from JSON, human, telemetry, and audit-ledger outputs; add regression tests that prove sanitized strings for PASS/FAIL/IAM drift plans and bundle runs.
- [ ] Harden string sanitization for issue titles/descriptions/remediation hints so HTML/XML/ANSI payloads are escaped before landing in GuardBoard or Playground logs; add fuzz-style unit tests.
- [ ] Enforce deterministic ordering for `issues`, `plan_metadata`, `iam_drift_report`, and telemetry exports even when Quick Score Mode kicks in; extend snapshot/property tests to fail on nondeterministic ordering.
- [ ] Add CI security sweep that runs the CLI/`run_scan.sh` under offline + strict modes and asserts no file system paths or environment secrets leak into outputs, satisfying spec §11 for CI/CD + Playground safety.

## GuardScore Integration & Badge Hooks

- [ ] Wire GuardScore ingestion metadata (`pillar_score_inputs`, `percentile_placeholder`, `guardscore_badge`, `scan_version`, `guardscore_rules_version`) into every output surface: CLI JSON/text, audit ledger, telemetry CSV/StatsD, preview manifests, and bundle manifest.
- [ ] Add GuardScore acceptance tests (PASS/FAIL/IAM drift/quick-score) that assert severity counts, badge eligibility, and latency/wasm flags match the canonical sample in `docs/VectorScan.txt`.
- [ ] Ensure GuardScore metadata stays deterministic by updating golden fixtures, schema docs, and README tables whenever the contract changes so GuardScore can ingest without custom parsers.

## GuardSuite Pillar Symmetry & Upgrade Path

- [ ] Embed the `upgrade_hint` block (“Upgrade to VectorGuard ($79/year)...”) in CLI JSON, human output, telemetry, and audit ledgers to match ComputeScan/PipelineScan messaging.
   - Reuse the exact phrasing from VectorGuard/ComputeScan so funnel messaging stays synchronized.
- [ ] Append the human-readable banner “Vector pillar scan complete. Combine with ComputeScan and PipelineScan for unified GuardScore.” with deterministic placement/tests.
- [ ] Mirror Quick Score Mode + Playground summary messaging with the phrasing used by ComputeScan/PipelineScan so docs/videos feel unified; add tests to confirm the text toggles with the same flags as other pillars.

## Documentation Additions for v2.0

- [ ] Refresh `README.md`, `docs/VectorScan.md`, `docs/run_scan.md`, and `docs/observability.md` with the canonical 3-pillar JSON schema (issues, pillar_score_inputs, guardscore_badge, latency, wasm_supported, quick_score_mode, playground_summary).
- [ ] Update `docs/output_schema.md` and associated schema-generation tests to capture the renamed `issues` array, remediation metadata, GuardScore fields, and environment inference examples.
- [ ] Extend landing page + Gumroad copy with GuardScore badge eligibility, GuardSuite pillar explanation, and Playground performance notes so marketing stays in sync with the CLI.
- [ ] Document the new CLI exit codes (0/1/2/11) plus WASM/Quick Score flags in `docs/VectorScan.txt` and the README usage section.

## Phase 5 – Post-Launch Monitoring

- [x] Track usage of VectorScan outputs to confirm the Compliance Score, Network Exposure Score, and IAM Drift Report behave in downstream automation.
   - Record metrics from CI or telemetry (if available) for how often each score is produced so we know whether the output stays stable over time.
   - Capture the CLI `metrics` payload, `iam_drift_report`, and the `VectorGuard_Audit_Ledger` YAML as described in `docs/observability.md` so the downstream monitoring story stays repeatable.
- [x] Telemetry hardening: idempotent CSV export and unit tests.
   - Make `scripts/telemetry_consumer.py` idempotent in append mode (skip duplicates by `generated_at`) and support `--mode overwrite`.
   - Add `tests/unit/test_telemetry_consumer_unit.py` to verify duplicate‑skipping and overwrite behavior.
- [x] Keep the Gumroad README link, CTA, and run instructions synchronized between VectorScan and VectorGuard so referrals remain accurate.
   - Add a cross-check in the release checklist to confirm the README, marketing docs, and new release automation reference `https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=blueprint` so the vectorguard UTM tags stay locked.
- [x] Maintain `docs/VectorScan.md` (and link references) with any policy or CLI updates.
   - After every release, update the source-of-truth summary with the new bundle contents, policy additions, and Gumroad notes.
   - [x] Add weekly CI job to re-download latest release and verify SHA256 + signature
      - `.github/workflows/weekly-release-verification.yml` now pulls the newest release every Monday, verifies SHA256 manifests, validates Cosign signatures, and smoke-tests extracted bundles on PASS/FAIL fixtures.
   - [x] Implement telemetry schema versioning so downstream automation can detect changes
      - Introduced `tools/vectorscan/telemetry_schema.py`, tagging `collect_metrics.py`, `metrics_summary.py`, and `telemetry_consumer.py` outputs with schema metadata plus new unit tests to enforce the CSV headers.
- [x] Add warning behavior when telemetry endpoints are set but unreachable
   - `scripts/telemetry_consumer.py` now traps StatsD socket errors, warns about unreachable endpoints (hostname + port), and continues without crashing; `tests/unit/test_telemetry_statsd_unit.py::test_main_warns_when_statsd_unreachable` covers the regression.
- [x] Add Gumroad download-failure tracker & retry logic for CI automation
   - `scripts/gumroad_download_guard.py` retries the mirror download, records metrics in `metrics/gumroad_download_guard.json`, and the release workflow uploads the telemetry when `GUMROAD_VALIDATION_URL` is set.
- [x] Add automated test to simulate full telemetry pipeline with StatsD on/off modes
   - `tests/unit/test_telemetry_pipeline_unit.py` now flows a synthetic CLI payload through `collect_metrics`, `metrics_summary`, and `telemetry_consumer` twice (StatsD enabled/disabled) to verify schema metadata, CSV idempotency, and StatsD emission behavior end-to-end.
- [x] Add monitoring test to detect unexpected compliance score drift across versions
   - Introduced `scripts/compliance_drift_monitor.py` plus `tests/unit/test_compliance_drift_monitor_unit.py` to compare baseline vs. current telemetry summaries and fail when the compliance score delta exceeds the configured threshold.


## Phase 6 – Test & CI Hardening
- Improvements to the Implementation Checklist
   - (Your current checklist is world-class. These final upgrades push it into “this must have been built by a 10-person infosec team” territory.)
   - You are currently at 91%. These items will move you to bulletproof.

- [x] **Add Policy Versioning + SemVer Output**
   - JSON outputs are stable but not versioned. Add `policy_version` and `schema_version` fields to JSON output, the ledger, manifest, and telemetry so workflows can pin versions and auditors can track schema migrations.

- [x] **Add Minimal Policy Pack Hash**
   - Compute a `policy_pack_hash` from the bundled Rego files to detect tampering, support reproducibility, and align with industry practices (Kubernetes, Trivy, OPA).

- [x] **Add “Policy Errors” to All Output Modes**
   - CLI JSON always emits a `policy_errors` array, audit ledgers show the structured block, telemetry logs/summary/CSV record counts plus latest errors, and lead-capture models/tests accept the richer data so isolation failures stay visible in every artifact.

- [x] **Add Machine-Readable Severity Index**
   - Provide a `violation_severity_summary` map (critical/high/medium/low counts) to supercharge CI dashboards and prep for ModelGuard severity analytics.

- [x] **Add `scan_duration_ms` to Metrics**
   - Include runtime telemetry under `metrics.scan_duration_ms` to monitor performance regressions, CI timings, and demo claims.

- [x] **Add Exit Code 4 for Policy Pack Load Errors**
   - Reserve exit code `4` (`POLICY_LOAD_ERROR`) for corrupted/missing policy packs so every failure path has a deterministic code.

- [x] **Add Offline Mode (VSCAN_OFFLINE=1)**
   - Ensure offline mode disables telemetry, lead capture, Terraform auto-downloads, and StatsD while keeping outputs identical for reproducible and air-gapped workflows.

- [x] **Auto-Generate Schema Docs**
   - Added `scripts/generate_schema_docs.py`, which executes the CLI against the PASS/FAIL fixtures (deterministic clock + offline mode) and emits `docs/output_schema.md` so the schema reference always reflects live output.
   - Introduced `tests/unit/test_generate_schema_docs_unit.py` to ensure the generator keeps working and surfaces key fields, making schema regressions visible during CI.

- [x] **Add Minimal Policy Plugin Interface**
   - Added `tools/vectorscan/policies/` with a shared registry (`base_policy.py`) plus scoped modules (`sec/encryption.py`, `fin/tagging.py`) so each policy declares metadata and exposes `evaluate()` via `@register_policy`.
   - CLI now calls `get_policies()` to discover guardrails dynamically, populates `checks`/severity summaries from plugin metadata, and keeps backwards-compatible helpers (`check_encryption`, `check_tags`) that delegate to the registry.
   - `tests/unit/test_policy_plugins_unit.py` validates the registry contents and ensures plugin evaluations stay in sync with the legacy wrappers.

- [x] **Add Strict Terminal Mode (VSCAN_STRICT=1)**
   - Introduced strict mode guardrails that require deterministic clock overrides, disable Terraform log truncation, treat any `policy_errors` as CONFIG errors, and surface violations via exit code `6` so enterprise pipelines can block partial coverage; README now documents the workflow and new unit tests cover clock enforcement + happy path.

- [x] **Add OS/Platform Metadata to Outputs**
   - CLI JSON now emits an `environment` block with platform/Python/Terraform/Vectorscan metadata plus strict/offline flags, and `run_scan.sh` mirrors the same data inside the ledger’s `environment_metadata` block with golden tests + overrides for deterministic CI evidence.
   - README, schema docs, and the implementation checklist all document the new `environment` / `environment_metadata` fields plus their `VSCAN_ENV_*` overrides so auditors know how to pin evidence.

- [x] **Add Rich StatsD Emitters with Toggle**
   - `scripts/telemetry_consumer.py` now builds rich StatsD packets (gauges, counters, timers, histograms) covering compliance averages, scan durations (avg/p95/max/latest), status counts, policy error counters, IAM drift stats, and per-severity violation histograms.
   - Added a dedicated `--disable-statsd` flag plus `VSCAN_DISABLE_STATSD`/`VSCAN_ENABLE_STATSD` overrides so pipelines can flip telemetry without touching CLI args, and statsd emissions remain off in offline mode.
   - Updated telemetry unit/pipeline/offline tests ensure the richer packets are produced, toggles work, and warnings surface when endpoints are unreachable.

- [x] **Add Explicit Plan Metadata Extraction**
   - `tools/vectorscan/vectorscan.py` now emits `plan_metadata` with resource/module counts, resource-type tallies, inferred providers, and module hierarchy details, and `run_scan.sh` mirrors the block in the audit ledger.
   - Golden JSON/YAML fixtures, schema docs, README, and observability/runbook guides were updated plus new unit tests ensure the metadata remains deterministic.

- [x] **Add Embedded `--explain` Flag**
   - Added `--explain`/`--json --explain` to `tools/vectorscan/vectorscan.py`, emitting a deterministic narrative block (`explanation`) plus a human-readable “VectorScan Explain Report” after the normal PASS/FAIL output.
   - Snapshot tests now cover PASS/FAIL/IAM drift explain runs (`tests/test_json_output.py`) alongside targeted unit tests for JSON/human explain flows, and new goldens (`tests/golden/*_explain_output.json`) keep the narratives locked.
   - README, CLI docs, and the generated schema reference now document the flag, field shapes, and sample output so users know how to opt-in.

## Phase 7 – Spec Compliance & Enterprise Modes

- [x] **Add Structured Remediation & Data Taint Metadata**
   - Added `violations_struct` with remediation summaries, deterministic HCL snippets, doc links, and `hcl_completeness` confidence scoring along with `resource_details.data_taint` / `taint_explanation`; updated schema docs, README/observability guidance, golden snapshots, and fixture-driven tests to lock the contract.

- [x] **Adopt Streaming Plan Parser & Large-Plan SLO**
   - Replace full-load parsing with iterative/streaming JSON readers (e.g., ijson) so multi-GB plans stay under 1.5 GB RAM, populate `plan_metadata.exceeds_threshold`, and add 12k+ resource perf tests (<200 ms for <1k resources, <2 s for 10k).

- [x] **Expose Full Plan Metadata & Security Grade**
   - CLI and explain JSON variants now emit `plan_metadata.change_summary`, `plan_metadata.resources_by_type`, and `plan_metadata.file_size_mb` alongside the `security_grade` + `violation_count_by_severity` fields, with goldens refreshed for PASS/FAIL/IAM drift.
   - `run_scan.sh` writes the richer plan metadata into the YAML audit ledger (`tests/golden/audit_ledger.yaml`), and `tests/test_audit_ledger.py` enforces the new evidence fields so downstream auditors see the full inventory snapshot.

- [x] **Implement Diff Mode (`--diff`)**
   - Added the `--diff` flag with deterministic `plan_diff` JSON + human-readout, refreshed PASS/FAIL/IAM drift goldens + snapshot tests, regenerated schema docs, and updated README/runbooks to document the mode.

- [x] **Implement Resource Drilldown (`--resource`)**
   - CLI now scopes policy evaluation, metrics, plan metadata, and optional diff/explain output to the requested Terraform address (module prefixes optional when the suffix is unique) and emits a `resource_filter` block so automation knows which resource was evaluated.
   - Added suffix-matching with deterministic ambiguity errors + suggestions (exit code 2) plus human-readable scope banners for the TTY flow.
   - Snapshot coverage: new fixtures/goldens (`tfplan_module_fail.json`, `fail_resource_output.json`, `module_resource_output.json`) and pytest assertions ensure both exact and suffix selectors stay stable.

- [x] **Ship VectorGuard Preview Mode (`--preview-vectorguard`)**
   - Bundle the signed preview manifest, emit `preview_generated` + `preview_policies` + `preview_manifest`, enforce exit code 10, guarantee no paid policy logic runs, and add manifest-signature + CLI mode tests.
   - README + spec now document the flag, exit code semantics, manifest signature guarantees, and env overrides (`VSCAN_PREVIEW_MANIFEST`, `VSCAN_PREVIEW_SKIP_VERIFY`).
   - `tests/test_json_output.py` adds preview snapshots (`fail_preview_output.json`), docs/test-checklist.md tracks exit code + override coverage, and schema docs now include preview fields so automation sees the contract.

- [x] **Add Policy Manifest & Policy Pack Selection Flags**
   - Implement `--policy-manifest`, `--policies`, and `--policy` so users can inspect pack metadata (`policy_version`, `policy_pack_hash`, `policy_source_url`, `signature`) and wire these fields into CLI output, manifest.json, and telemetry.

- [x] **Add GitHub Action Mode (`--gha`)**
   - Added the `--gha` flag that forces JSON output, disables color, and sorts keys for deterministic CI logs, along with README/spec updates and pytest coverage that confirms the canonical formatting and exit codes.

- [x] **Extend Packaging & Verification for Preview + Policy Metadata**
   - `manifest.json` now embeds the signed `policy_manifest`, a `preview_manifest` summary (path, sha256, signature, policy count), and `signers` metadata describing the cosign verification command/issuer.
   - `tools/vectorscan/preview_manifest.json` ships in every bundle (plus manifest entries) so `--preview-vectorguard` works offline and the checksum can be audited from the release manifest.
   - `scripts/bundle_integrity_checker.py` enforces the new metadata (preview checksum vs file listing, policy hash parity, signer presence), and `tests/integration/test_packaging_verification.py` asserts the manifest block matches the canonical policy + preview data.

- [x] **Expand TestPlan & Docs for New Modes**
   - Refreshed `docs/test-checklist.md` to track streaming parser fallback verification, remediation metadata assertions, diff/explain/resource/preview/GHA mode coverage, exit code 10 validation, and offline strict error handling so the spec + tests remain synchronized with the new CLI features. Schema/golden updates will follow as part of the remaining schema refresh task.

## Phase 8 – Intelligence & Telemetry Enhancements

- [x] **Add Plan Risk Profile Metadata**
   - Added `tools/vectorscan/plan_risk.py` to derive qualitative plan risk (`low`/`medium`/`high`/`critical`) from violation severity, IAM drift outcomes, compliance score, and exposure heuristics (open security groups + IAM risky actions), with hooks for future Suspicious Defaults detectors.
   - CLI JSON now emits `plan_risk_profile` (always present) and optional `plan_risk_factors` explaining each escalation; `run_scan.sh` mirrors both fields inside the audit ledger.
   - Regenerated every golden snapshot (PASS/FAIL/diff/explain/resource/preview/ledger) and refreshed `tests/test_json_output.py` coverage so the new metadata is locked under deterministic fixtures.
   - Documented the new fields in `docs/output_schema.md`, making the schema contract explicit for downstream automation.

- [x] **Implement Suspicious Defaults Detector**
   - Added `tools/vectorscan/suspicious_defaults.py` with heuristics for RDS encryption defaults, open SG ingress, public S3 ACLs, public subnets, and IAM inline/wildcard merges; detector now runs before policy evaluation and feeds a `suspicious_defaults` advisory array into every JSON/ledger artifact.
   - Expanded unit coverage in `tests/unit/test_suspicious_defaults_unit.py` plus refreshed PASS/FAIL/IAM drift golden fixtures (including diff/explain/resource/preview modes) so the new warnings and counts are locked in snapshots alongside updated audit ledger evidence.
   - Documented the warning semantics here and in the schema doc so users know these advisories do not affect exit codes unless the guardrail policies also fail.

- [x] **Build Plan Smell Analyzer**
   - Added `tools/vectorscan/plan_smell.py` with deterministic heuristics (module depth, for_each count, kms gaps, IAM bulkiness, change volume) and wired the resulting `smell_report` through CLI JSON, explain mode, and the audit ledger (`run_scan.sh`).
   - Locked coverage with `tests/unit/test_plan_smell_unit.py` plus refreshed every golden snapshot (PASS/FAIL/diff/explain/resource/preview/ledger) so smell metadata stays deterministic alongside the new schema examples.
   - Regenerated `docs/output_schema.md` via `scripts/generate_schema_docs.py` to document the top-level `smell_report`, stats, and per-smell evidence, and updated README/explain copy to reference the structural smell analyzer.

- [x] **Add Plan Evolution Summary (`--compare`)**
   - Added `--compare old.json new.json` mode that skips policy evaluation, emits a structured `plan_evolution` block (old/new change summaries, delta math, downgraded_encryption evidence, summary lines), and prints the matching human report with ALERT status when encryption regresses.
   - Introduced compare fixtures (`tfplan_compare_old.json`, `tfplan_compare_new.json`) plus a deterministic golden snapshot (`tests/golden/plan_compare_output.json`) and unit coverage (`tests/unit/test_plan_evolution_unit.py`).
   - Updated README, VectorScan docs, observability/test checklists, schema docs, and regenerated `docs/output_schema.md` via `scripts/generate_schema_docs.py` so the new block is documented end-to-end.

- [x] **Extend Performance Metrics Block**
   - CLI metrics now emit `scan_duration_ms`, `parser_mode`, and `resource_count` for every run, sourced from the streaming parser metadata so JSON, lead capture, and audit ledgers all expose the same runtime evidence.
   - Telemetry collectors (`collect_metrics.py`, `metrics_summary.py`, `telemetry_consumer.py`) record/aggregate the new fields, StatsD publishes parser-mode gauges + resource-count averages, and the CSV export captures the latest parser mode for dashboards.
   - Regenerated every golden snapshot plus the audit ledger to lock the schema change into tests, and refreshed docs (output schema, observability guide, run_scan workflow) so downstream consumers know how to use the new metrics.

## Final VectorScan v2.0 Compliance Verification

- [ ] Re-run the spec acceptance suite covering CLI commands (`vectorscan plan.json`, `--json`, `--stdin`, `--quiet`, `--explain`) and exit codes (0/1/2/11) to prove Execution Model (§2) parity.
- [ ] Capture a final PASS/FAIL/Quick-Score output bundle (JSON, text, ledger, telemetry CSV, StatsD log) and confirm every required field from `docs/VectorScan.txt` (§§3–12) is populated with deterministic values.
- [ ] Record the GuardScore readiness report: performance (<500 ms local, <1300 ms WASM), GuardScore ingestion metadata, badge hooks, pipeline symmetry copy, and documentation updates; store the signed report under `docs/VectorScan_v2_compliance.md` for auditors.


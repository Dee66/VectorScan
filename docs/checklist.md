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
      <progress id="vs-progress" value="88" max="100" aria-label="VectorScan progress" style="width:60%;height:18px;"></progress>
      <div id="vs-progress-label">88% Complete (38/43)</div>
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

## Phase 3 – VectorScan Repo Launch

- [x] Port `tools/vectorscan` sources (content pruning of `.terraform-bin/`, fixture captures, and `__pycache__`).
- [x] Migrate the unit, integration, e2e, and Terraform harness tests into the standalone repo layout.
- [x] Copy PASS/FAIL fixture plans, violations, and scripts such as `run_scan.sh` into the new `examples/` and `scripts/` folders.
- [x] Bootstrap `Dee66/VectorScan` with license, contributing guide, Code of Conduct, and an onboarding README that introduces the free workflow.
   - Draft standard Apache 2.0 (or chosen) license copy, surface the repo mission, and reference the VectorGuard SLA tiers.
   - Provide clear contributing guidelines covering issue triage, testing, and release expectations so future contributors adopt the governance mindset.
   - Include a Code of Conduct clause and a README section that directs readers to VectorGuard for paid policies and Gumroad upgrades.
- [x] Recreate packaging & distribution workflows in the repo (CI badge, cross-platform bundling, release drafts, verification steps).
   - Mirror the VectorGuard CI matrix for Linux/macOS/Windows so each bundle is reproducible and signing steps are automated.
   - Add CI steps to publish GitHub release drafts, upload the signed `vectorscan-free.zip`, and capture checksums for each run.
   - Document the release checklist (what to verify before tagging, how to trigger Cosign signing, how to update badges/links).
- [x] Ensure release tooling (`build_vectorscan_package.py`, `cosign`, `automate_release.py`) works relative to the VectorScan repository root.
   - Update scripts to locate the bundled CLI, policy files, and fixtures in the new path layout; rewrite relative imports if needed.
   - Verify the `cosign` invocation finds the signing key via environment variables and gracefully skips signing when credentials are absent (for local dev testing).
   - Add smoke tests that run `automate_release.py` in dry-run mode to confirm packaging still succeeds after the repo move.
- [x] Update VectorScan documentation (landing page, trouble‑shooting guides, audit templates, marketing assets) so they point to `Dee66/VectorScan` URLs.
   - Rewrite hero CTAs or README links in the docs to point to the new repo landing pages, including the new Gumroad download instructions.
   - Audit GIFs, badges, and release notes to ensure no references to the old VectorGuard path remain.
   - Keep `docs/VectorScan_Source_of_Truth.md` updated with the repo's canonical structural overview and shipping milestones.
- [x] Plan distribution of VectorScan bundles post-split: GitHub Releases, landing page download flow, Gumroad links with signing instructions.
   - Decide on the cadence for GitHub release tag pushes (e.g., `v0.1.0` increments) and schedule the GitHub Release description to include auditing instructions.
   - Build/out the landing page download flow so consumers can grab the bundle from GitHub or the Gumroad purchase portal (signature + checksum links).
   - Keep a reference to the `vectorscan-free.zip` in the README and the Gumroad delivery email, ensuring both mention SHA256 + Cosign verification.
- [x] Validate end-to-end: new repo CI is green, Terraform smoke tests pass across platforms, and VectorGuard docs cite the new CLI without broken references.
   - Hook up the new CI to run the same `run_scan.sh` scenario used in VectorGuard for PASS/FAIL plans to prove parity.
   - Monitor Terraform smoke tests on Linux/macOS/Windows to ensure each plan scenario still demonstrates the `Compliance Score`, `Network Exposure Score`, and `IAM Drift` outputs.
   - Re-baseline VectorGuard docs and quickstarts to reference the new repo path (`Dee66/VectorScan`) and confirm relative links in markdown build.

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

## Phase 5 – Post-Launch Monitoring

- [x] Track usage of VectorScan outputs to confirm the Compliance Score, Network Exposure Score, and IAM Drift Report behave in downstream automation.
   - Record metrics from CI or telemetry (if available) for how often each score is produced so we know whether the output stays stable over time.
   - Capture the CLI `metrics` payload, `iam_drift_report`, and the `VectorGuard_Audit_Ledger` YAML as described in `docs/observability.md` so the downstream monitoring story stays repeatable.
- [x] Telemetry hardening: idempotent CSV export and unit tests.
   - Make `scripts/telemetry_consumer.py` idempotent in append mode (skip duplicates by `generated_at`) and support `--mode overwrite`.
   - Add `tests/unit/test_telemetry_consumer_unit.py` to verify duplicate‑skipping and overwrite behavior.
- [x] Keep the Gumroad README link, CTA, and run instructions synchronized between VectorScan and VectorGuard so referrals remain accurate.
   - Add a cross-check in the release checklist to confirm the README, marketing docs, and new release automation reference `https://gumroad.com/l/vectorguard-blueprint?utm_source=vectorscan&utm_medium=cta&utm_campaign=vectorscan&utm_content=blueprint` so the vectorguard UTM tags stay locked.
- [x] Maintain `docs/VectorScan_Source_of_Truth.md` (and link references) with any policy or CLI updates.
   - After every release, update the source-of-truth summary with the new bundle contents, policy additions, and Gumroad notes.

## Phase 6 – Test & CI Hardening

- [ ] Lead capture API tests: comprehensive FastAPI unit/integration coverage
   - Validate POST `/lead` success path with local file backup when HTTP fails
   - Mock HTTP endpoint via env `VSCAN_LEAD_ENDPOINT`; verify payload schema and error handling
- [x] CLI-to-API end-to-end tests (happy path + failure path)
   - Run `vectorscan.py --json` then submit lead; assert telemetry capture and audit ledger artifacts exist
   - Simulate network errors and ensure graceful degradation with local capture
- [ ] Terraform integration tests gated by `--terraform-tests`
   - Auto-download Terraform to `.terraform-bin/` when missing; version lock to >= 1.8.0
   - Execute `terraform test` on `tests/tf-tests/*.tftest.hcl`; assert exit codes and evidence files
- [x] Performance sanity checks
   - Measure runtime on PASS/FAIL fixtures; set soft budget and assert under threshold in CI
   - Ensure JSON parsing scales for large plans (property-based test using Hypothesis)
- [x] Lint and type-check in CI
   - Add `ruff` for lint, `black` for formatting check, `mypy` for type hints (allow gradual typing)
   - Fail CI on lint/type errors; add minimal config files
- [ ] StatsD telemetry emission tests
   - Validate gauges for `compliance_score`, `network_exposure_score`, and `iam_drift_penalty`
   - Confirm idempotent CSV remains correct with StatsD enabled/disabled
- [ ] Packaging verification tests
   - Dry-run `scripts/create_release_bundle.py` under pytest; assert bundle layout, signatures metadata placeholders
   - Ensure `build_vectorscan_package.py` tolerates pytest flags (parse_known_args) and produces expected artifacts
- [ ] Docs and landing page verification
   - Cross-check `docs/vectorscan_landing.md/html` links, CTAs, and Gumroad references
   - Ensure README “How to run” and verification steps match current bundle

## Using VectorScan & Gumroad

1. **Download** the signed `vectorscan-free.zip` bundle (GitHub Releases or Gumroad). Verify the SHA256 checksum and `cosign` signature before unpacking.
2. **Activate** the bundled CLI: python-driven `tools/vectorscan/vectorscan.py` reads a Terraform plan JSON (e.g., `examples/aws-pgvector-rag/tfplan-pass.json`).
3. **Run** the CLI or `scripts/run_scan.sh` locally or in CI. VectorScan reports `PASS/FAIL` for:
   - `P-SEC-001` (Encryption Mandate)
   - `P-FIN-001` (Mandatory Tagging)
   - Compliance Score, Network Exposure Score, IAM Drift Report, plus an Audit Ledger snapshot.
4. **Use the Gumroad CTA** in VectorGuard docs to funnel from the free CLI to the $79 VectorGuard Governance Blueprint (highlighting the upgrade path and policy expansion).
5. **Integrate** the CLI into VectorGuard pipelines by referencing `vector-guard` docs that mention VectorScan outputs, the new repo path, and the `Audit Ledger` template.

## Notes

- Any VectorScan work that touches VectorGuard (removing workflows, communicating the split) remains in the main checklist at `docs/checklist.md` under the migration follow-up section.
- Keep this checklist updated whenever VectorScan introduces new policies, outputs, or Gumroad marketing changes so the repo stays release-ready.

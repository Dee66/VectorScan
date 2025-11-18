A. FOUNDATIONS & REPO SANITY

[ ] Confirm VectorScan repo located at github.com/Dee66/VectorScan and is independent of VectorGuard mono-repo.
[ ] Ensure VectorScan README, LICENSE (MIT), CONTRIBUTING.md, CODE_OF_CONDUCT.md present and accurate.
[ ] Confirm all references in VectorGuard docs that pointed to local tools/vectorscan now point to https://github.com/Dee66/VectorScan
.
[ ] Ensure ShieldCraft and VectorGuard references do not claim VectorScan as paid  -  VectorScan must be free and MIT.
[ ] Ensure no secret/private keys are in the repo (git secrets scan).
[ ] Add manifest.json generator that lists every file included in the release bundle with a hash and version string.

B. CODE & INVESTIGATION-PHASE CORRECTNESS

[ ] Ensure CLI executes full investigation pipeline end-to-end when invoked with a tfplan.json (parse → evaluate policies → metrics → output).
[ ] Confirm P-SEC-001 and P-FIN-001 Rego policies are the canonical free policies used by VectorScan.
[ ] Confirm Rego files are present in repo and referenced by CLI (free_policies.rego or policies.rego).
[ ] Add deterministic timestamp injection capability (ENV override or CLI flag) for reproducible outputs.
[ ] Add a CLI dry-run mode to validate investigation without writing artifacts (useful in CI).
[ ] Implement an invocation that simulates a user running VectorScan from inside an extracted bundle (so E2E tests run against bundle layout).
[ ] Ensure the scanner can run without Terraform installed; when Terraform is present or auto-downloaded, it is used for terraform-tests paths.

C. TEST FIXTURES & GOLDEN DATA

[ ] Populate full set of fixtures under tests/fixtures/ (tfplan_pass.json, tfplan_fail.json, tfplan_invalid.json, tfplan_iam_drift.json, tfplan_missing_tags.json, tfplan_no_encryption.json).
[ ] Create representative, realistic tfplan JSONs that exercise nested modules, dynamic blocks, computed fields, and large resource sets.
[ ] Create golden outputs for each scenario (golden/pass_output.json, golden/fail_output.json, golden/iam_drift_output.json, golden/audit_ledger.yaml).
[ ] Add manifest-based golden verification that ensures golden files update only via a documented change process.
[ ] Add property-based tests (Hypothesis) for plan normalization / schema resilience.

D. PYTEST SUITE (UNIT → E2E)

[ ] test_cli.py: argument parsing, flag routing, default behavior, error codes (0,3,2,5).
[ ] test_json_output.py: JSON schema validation, required keys, schema stability checks.
[ ] test_audit_ledger.py: YAML schema validation, deterministic ordering, includes required keys.
[ ] test_iam_drift.py: full drift report structure, severity maps, penalty application conditional on flag.
[ ] test_end_to_end.py: run CLI against fixtures (pass/fail/iam), assert exit codes and outputs match golden.
[ ] test_terraform_integration.py: gated tests that run only when Terraform available or when `VSCAN_ALLOW_TERRAFORM_DOWNLOAD=1` (legacy: `VSCAN_TERRAFORM_AUTO_DOWNLOAD=1`) so auto-download, version detection, stdout/stderr capture, and exit codes are covered.
[ ] test_error_handling.py: invalid JSON, missing files, permission errors (monkeypatch), no unhandled exceptions.
[ ] test_lead_capture.py: local capture file creation tests and remote capture HTTP mock tests (200, 400, 500).
[ ] test_performance.py: micro-benchmarks (100KB plan <200ms), tracemalloc checks, large plan tests (2–5MB).
[ ] test_stability.py: run repeated scans deterministically to ensure identical outputs when timestamp is fixed.
[ ] test_bundle_execution.py: unzip a generated vectorscan-free.zip in a temp dir, run the CLI inside bundle layout and assert outputs match golden (this validates packaged artifact behavior).
[ ] test_release_package.py: verify manifest.json inside the bundle matches actual files and hashes.

E. POLICY ENGINE & FAILURE ISOLATION

[ ] Add tests for policy failure isolation: if one policy crashes, others still run and failure is reported as policy error, not process crash.
[ ] Add tests for malformed policy outputs (policy returns unexpected schema).
[ ] Include tests that verify multiple policies on same resource produce deduped and stable violation entries.
[ ] Add tests to ensure remediation hints are present and stable.

F. HUMAN OUTPUT & UX

[ ] Ensure human readable output never shows tracebacks by default; only verbose flag shows debug.
[ ] Ensure human output width/terminal handling stable across typical terminals.
[ ] Test color/no-color flag output for piping to files.
[ ] Add test to generate a GIF/recording of a pass→fail example (used in README)  -  verify the command sequence reproduces expected output.

G. TELEMETRY, LEAD CAPTURE & PRIVACY

[ ] Local lead capture: verify file path tools/vectorscan/captures/ exists and capture JSON contains email, result, timestamp.
[ ] Remote lead capture: mock endpoint tests to validate POST payload and graceful fallback to local capture on network errors.
[ ] Ensure telemetry toggles and privacy options exist and default to off (no network by default).
[ ] Ensure telemetry payload contains no secrets or environment variables.
[ ] Add tests to ensure lead capture only triggers when explicit flags provided.

H. PACKAGING  -  BUNDLE (vectorscan-free.zip) & CONTENTS

[ ] Implement packaging script (scripts/create_release_bundle.py or build_vectorscan_package.py) that zips the package at repository root following a deterministic layout.
[ ] Bundle must include (explicit list):
[ ] CLI driver tools/vectorscan/vectorscan.py (or packaged executable)
[ ] free_policies.rego (policy files)
[ ] README.md (bundle-specific instructions)
[ ] LICENSE (MIT)
[ ] manifest.json (file list + SHA256 per file + version)
[ ] sample examples/ PASS/FAIL tfplan JSONs
[ ] scripts/run_scan.sh and verify.sh (for signature verification)
[ ] metrics/ or sample audit ledger templates
[ ] platform-scoped Terraform binary only if included (see security items)
[ ] NO PRIVATE FILES: ensure scripts scrub __pycache__, .env, private keys, local caches.
[ ] Create a deterministic zip process (sort file list, use fixed timestamps or set deterministic mtimes for reproducibility).
[ ] Produce per-platform bundles if including platform specific binaries; otherwise create a single cross-platform zip that expects Python.
[ ] Generate vectorscan-free.zip.sha256 alongside the zip.

I. SIGNING  -  COSIGN & KEY MANAGEMENT

[ ] Implement cosign signing step in CI to create <bundle>.zip.sig and publish certificate <bundle>.zip.crt.
[ ] Add verify.sh in repo to run sha256sum -c <bundle>.zip.sha256 and cosign verify-blob --key <public_key_file> <bundle>.zip <bundle>.zip.sig.
[ ] Add public verification key (vectorscan-signing.pub) to README or a Key server URL.
[ ] Do not commit private signing keys into repo. Use CI secrets to hold private keys.
[ ] Create tests that run on CI runner to verify the signed artifact - download the artifact from release draft in a dry-run and run cosign verify-blob using the public key.
[x] Add a process doc docs/signing.md describing key rotation, emergency procedures, and how to sign locally for dev uses (using ephemeral dev keys).

J. SBOM, SBOM TESTS & SUPPLY CHAIN

[ ] Produce a Software Bill of Materials (SBOM) for the bundle (CycloneDX or SPDX).
[ ] Include SBOM file inside the zip and publish it in releases.
[ ] Add a test asserting SBOM lists all third-party packages and versions matching requirements*.txt or lock files.
[ ] Add a script to regenerate SBOM and check for license incompatibilities.

K. GUMROAD PRODUCT CONFIGURATION & FLOW

[ ] Create a Gumroad product listing for vectorscan-free.zip with delivery of the zip file. Set price to free (or $0) so Gumroad will host download.
[ ] Ensure Gumroad delivers the same CI-signed artifact (upload the signed zip to Gumroad, not an unsigned dev build).
[ ] Create a downloadable product ZIP in Gumroad with README and instructions in the delivery email on how to verify SHA256 & cosign.
[ ] Add tracking UTMs to Gumroad description and ensure UTM mappings exist in release checklist.
[ ] Create a delivery email template that includes: download link, sha256, how to verify, public key location, support contact, and upgrade CTA (VectorGuard blueprint).
[ ] Add automated verification: After upload, download the same file from Gumroad via CI (or manual test) and run signature & checksum verification; create a CI job to run this once per release.
[ ] Ensure Gumroad payout and tax info is correctly set (even if free) and the product is allowed per Gumroad policies.
[ ] Ensure the Gumroad download does not include any hidden/extra files (validate manifest and bundle integrity post-upload).

L. RELEASE PROCESS & CI

[ ] Add GitHub Actions release workflow that:
[ ] runs linting, mypy/ruff/black, pytest full suite
[ ] builds zip bundle deterministically on matrix runners (linux, macOS, windows if needed)
[ ] runs packaging verification tests (unzip → run bundle → assert outputs)
[ ] runs cosign signing (requires CI secrets)
[ ] uploads release draft with artifacts and checksums
[ ] triggers optional Gumroad upload step (manual or automated via API)
[ ] Add a release checklist file in repo that codifies manual steps (signing, sanity check, update docs).
[ ] Add pre-release CI job to run scripts/create_release_bundle.py --dry-run and assert layout and manifest.
[ ] Add a release smoke test action that runs the packaged bundle in container and exercises the investigation phase on PASS/FAIL fixtures.
[ ] Ensure CI fails if golden comparisons differ or if reproducibility fails.

M. BUNDLE ACCEPTANCE & CONSUMER VALIDATION

[ ] Test consumer acceptance: download zipped bundle from GitHub Releases, verify checksum and cosign signature, unzip, and run CLI with example tfplan to reproduce golden output.
[ ] Test Gumroad download: buy (or trigger free download) and run the same verification & execution as above.
[ ] Add a CI job or cron-run that downloads latest release from GitHub and verifies signature & checksum (ensures release integrity over time).
[ ] Create a "first run" smoke script that a consumer can run to validate everything (verify.sh -> run_scan.sh -> verify output).

N. SECURITY & HARDENING

[ ] Ensure bundled Terraform binary (if included) is verified by publisher checksum and is the correct platform binary.
[ ] Validate permissions of files in bundle (no executable bits where not needed, safe modes).
[ ] Ensure temp file creation uses secure APIs (mkstemp).
[ ] Validate all subprocess calls are properly escaped and sanitized.
[ ] Add tests simulating malicious or malformed plan JSON input (injection attempts) and assert safe behavior.
[ ] Add tests ensuring no environment credentials or secrets are logged or exported.

O. DOCUMENTATION & SUPPORT

[ ] Update VectorScan README with bundle verification steps (sha256 + cosign).
[ ] Add docs/release-distribution.md with explicit sha256sum -c and cosign commands and public key location.
[ ] Add a quick "Verify the bundle" snippet in README and in Gumroad delivery email.
[ ] Include a "How to run vectorcan from the bundle" short example that uses the included README in the unzipped folder.
[ ] Provide troubleshooting section: missing Terraform -> VSCAN_TERRAFORM_BIN override, permission errors, cosign errors.
[ ] Provide an "enterprise path" doc that explains the VectorGuard upgrade and policies that VectorGuard adds; do not expose paywall logic in VectorScan README.
[ ] Add sample audit ledger example to the repo and include instructions on attaching ledger to an incident or audit report.
[ ] Ensure license (MIT) is unambiguously included inside the bundle top-level.

P. MONITORING, TELEMETRY & POST-LAUNCH

[ ] Add telemetry metrics emission (opt-in): compliance_score, network_exposure_score, iam_drift_score. Default OFF.
[ ] Create scripts to aggregate metrics from captured local files for offline analysis.
[ ] Add usage dashboard scripts for internal tracking (how many bundles downloaded, unique UTM hits, lead capture counts).
[ ] Add GitHub release analytics monitoring (stars, forks, downloads) and map to outreach conversions (Gumroad visits -> blueprint purchases).

Q. LEGAL, PRICING, & COMMERCIAL FLOW (GUMROAD)

[ ] Ensure Gumroad listing copy clearly says the download is free and includes verification instructions.
[ ] For paid VectorGuard products on Gumroad, ensure buyer receives a different package (policy blueprint) that does not include private keys or patched artifacts.
[ ] Ensure terms of sale + refund policy documented in Gumroad product pages.
[ ] Ensure paid bundles are distributed via Gumroad but still include sha256 and cosign verification instructions.

R. TESTING MATRIX & RELEASE QA

[ ] Create a release QA checklist that must be marked complete before a release tag is pushed. Items include: CI green, packaging smoke test, signature present, release notes drafted, Gumroad upload verified, docs updated.
[ ] Create a test matrix document showing which tests run in CI vs manual (e.g., Terraform tests gated manual or special runner).
[ ] Add platform acceptance tests (Linux/macOS/Windows) for bundles that include binaries.

S. MAINTENANCE & OPERATIONS

[x] Define and document signing key rotation policy and a process for revoking compromised keys.
[ ] Create process for re-issuing a release (hotfix) that preserves reproducibility and updates checksums.
[x] Add a public key rotation announcement template for customers who verify signatures.
[ ] Add a small runbook for support: how to reproduce a user's failed run locally from their uploaded tfplan, including sanitization steps.

T. OPTIONAL  -  ENTERPRISE & UPGRADE PATH (non-blocking for free bundle)

[ ] Maintain the VectorGuard blueprint repo with clear mapping of policies added beyond P-SEC-001 and P-FIN-001.
[ ] Add migration guide: how a VectorScan user migrates to VectorGuard blueprint in their CI.
[ ] Create a pilot package (paid) that includes additional policies and onboarding templates for enterprise customers.

U. FINAL CONSUMER ACCEPTANCE TESTS (E2E)

[ ] Full E2E test: from repo tag → CI build → package creation → cosign sign → upload to GitHub Release → automated download from Releases → verify signature & checksum → unzip → run CLI on PASS/FAIL examples → assert outputs match golden.
[ ] Full E2E test: same flow but download from Gumroad listing, verify signature & checksum → run CLI → assert outputs.
[ ] Add a CI "release gate" job that runs these E2E acceptance tests in a controlled environment before marking the release as final.

V. TRACKING & METRICS (post-release)

[ ] Create a simple KPI spreadsheet or telemetry collector: GitHub release downloads, Gumroad downloads, README link CTAs, VectorGuard upgrade conversions.
[ ] Create a weekly release health check (verify latest release signature still valid and verify.sh still executes).
[ ] Add a lightweight support inbox template for users who fail verification (and a canonical reproduction workflow).
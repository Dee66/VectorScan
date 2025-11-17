# Observability & telemetry

VectorScan emits structured evidence you can ship into dashboards, alerting rules, and downstream automation so the Compliance Score, Network Exposure Score, and IAM Drift findings become operational telemetry rather than ad-hoc log entries.

## What to record

| Field | Source | Meaning |
| --- | --- | --- |
| `metrics.compliance_score` | `tools/vectorscan/vectorscan.py --json` | Normalized 0–100 score derived from the encryption + tagging checks. IAM drift penalties are applied before emission.
| `metrics.network_exposure_score` | CLI `metrics` block | Simple 0–100 score that decreases whenever a security group opens ingress to `0.0.0.0/0` or `::/0`. Use for network hardening dashboards.
| `metrics.open_sg_count` | CLI `metrics` block | Integer count of security groups exposing all traffic. Great for trendlines.
| `metrics.iam_risky_actions` | CLI `metrics` block | Number of IAM entities with wildcard or high-risk actions heuristically detected in inline policies.
| `metrics.iam_drift.status` | `iam_drift_report` | `PASS` / `FAIL` depending on whether risky IAM additions were found in the plan.
| `metrics.iam_drift.risky_change_count` | CLI `metrics` block | Numeric indicator of how many IAM changes were flagged; correlate it with change review gates.
| `violations` | CLI `violations` list | Policy violation strings you can attach to incident tickets or compliance logs.
| `violations_struct` | CLI `violations_struct` list | Structured remediation metadata (docs, HCL snippets, data_taint + taint_explanation) for every violation; feed this into ticket templates or knowledge bases.
| `terraform_tests.status` | CLI `terraform_tests` block (when `--terraform-tests` enabled) | Mirror of the Terraform smoke test outcome so you can graph the reliability of the bundled Terraform binary.
| `environment.platform` / `environment.platform_release` | CLI `environment` block | Capture which OS produced the evidence; override via `VSCAN_ENV_PLATFORM` / `VSCAN_ENV_PLATFORM_RELEASE` for deterministic goldens. |
| `environment.python_version` / `environment.python_implementation` | CLI `environment` block | Records the interpreter that executed the scan, proving reproducibility when auditors cross-check runtimes. |
| `environment.terraform_version` / `environment.terraform_source` | CLI `environment` block | Indicates which Terraform binary (system/override/download) ran module tests; fall back to `VSCAN_ENV_TERRAFORM_VERSION` / `VSCAN_ENV_TERRAFORM_SOURCE` when Terraform is skipped. |
| `environment.strict_mode` / `environment.offline_mode` | CLI `environment` block | Boolean flags confirming strict/air-gapped enforcement so evidence consumers know the run met enterprise invariants. |
| `plan_metadata.resource_count` / `plan_metadata.module_count` | CLI `plan_metadata` block | Lightweight Terraform inventory summarizing total resources + modules for each plan. |
| `plan_metadata.resource_types` / `plan_metadata.providers` | CLI `plan_metadata` block | Type/provider breakdown powering dashboards that correlate violations with resource mix. |
| `plan_metadata.change_summary` | CLI `plan_metadata` block | `{adds, changes, destroys}` counters derived from Terraform `resource_changes`, helpful for spotting destructive plans. |
| `plan_metadata.resources_by_type` | CLI `plan_metadata` block | Per-resource-type breakdown of `planned`, `adds`, `changes`, `destroys` so you can plot which modules are growing or shrinking. |
| `plan_metadata.file_size_mb` | CLI `plan_metadata` block | File size (MB) companion to `file_size_bytes`; graph it to detect plan bloat trends. |
| `plan_metadata.file_size_bytes` / `plan_metadata.parse_duration_ms` | CLI `plan_metadata` block | Streaming parser telemetry proving how large the incoming plan was and how long parsing took (respecting `VSCAN_FORCE_PLAN_PARSE_MS` for deterministic goldens). |
| `plan_metadata.plan_slo.active_window` / `plan_metadata.exceeds_threshold` | CLI `plan_metadata.plan_slo` block | Indicates whether the plan stayed within the fast-path (<1k resources / <200 ms) or large-plan (<10k resources / <2 s) SLO; flag when `exceeds_threshold=true` to catch oversized plans before they melt CI agents. |
| `plan_diff.summary` | CLI `plan_diff` block (when `--diff` enabled) | `{adds, changes, destroys}` counters scoped to changed resources. Analyze in dashboards to spot unusually destructive plans without parsing the full diff. |
| `plan_diff.resources[].attributes[].field` | CLI `plan_diff` block (when `--diff` enabled) | Structured before/after pairs for each changed attribute. Feed into incident tickets or attach to pull-request bots so reviewers see exactly what values shifted. |
| `security_grade` | CLI top-level field | Letter grade (A–F) derived from compliance score + severity impact so leadership has an at-a-glance quality badge. |
| `violation_count_by_severity` | CLI top-level field | Mirror of `violation_severity_summary` emitted separately for downstream consumers that expect the `*_count` naming convention. |

When you run `scripts/run_scan.sh`, it replays the CLI JSON output into the `VectorGuard_Audit_Ledger` YAML (`overall_score`, `audit_status`, `CISO_Mandate`). Treat that ledger as the canonical artifact you persist for auditors and supply to any SIEM that understands YAML time series.

Set `VSCAN_ENV_PLATFORM`, `VSCAN_ENV_PLATFORM_RELEASE`, `VSCAN_ENV_PYTHON_VERSION`, `VSCAN_ENV_PYTHON_IMPL`, `VSCAN_ENV_TERRAFORM_VERSION`, `VSCAN_ENV_TERRAFORM_SOURCE`, and `VSCAN_ENV_VECTORSCAN_VERSION` when you need deterministic metadata for CI snapshots or forensic replay; otherwise the CLI populates the fields automatically and `run_scan.sh` mirrors them under `environment_metadata`. The new `plan_metadata` block piggybacks on the same CLI output and requires no flags—just parse the resource/module/provider stats whenever you need a quick plan census for dashboards.

### Streaming parser SLO windows

VectorScan’s streaming parser reports three SLO tiers via `plan_metadata.plan_slo.active_window`:

- **`fast_path`** – ≤1,000 resources, ≤200 ms parse time. Expect this for typical module-level scans.
- **`large_plan`** – ≤10,000 resources, ≤2,000 ms parse time. CI pipelines should watch for repeated entries in this tier.
- **`oversized`** – Anything above 10,000 resources (or breaching file-size limits) auto-flips `exceeds_threshold=true` so you can alert/SLO-budge.

`plan_metadata.plan_slo.observed` echoes the actual resource_count/parse_duration/file_size so you can graph plan size trends over time. When producing deterministic goldens, set `VSCAN_FORCE_PLAN_PARSE_MS` (or reuse `VSCAN_FORCE_DURATION_MS`) to pin the parsing duration reported in this block.

## Instrumentation patterns

1. **CI pipeline instrumentation** – Pipe `tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --json` to a file, parse the JSON, and post the relevant `metrics` fields to your telemetry backend (Prometheus pushgateway, StatsD, DataDog, etc.).
2. **Alerting on drift** – Monitor `iam_drift_report.status` and email/Slack the security team when it flips to `FAIL`. Include `iam_drift_report.items` for context so reviewers can triage bad IAM additions.
3. **Network exposure dashboards** – Use `network_exposure_score` and `open_sg_count` as gauges in vulnerability dashboards. When either dips below a threshold (e.g., score < 70 or `open_sg_count > 2`), trigger a slow-down step before deployment.
4. **Audit ledger persistence** – After `run_scan.sh` runs, store `audit_logs/*.yaml` (see `.github/workflows/validate-release.yml`) along with the signed bundle metadata. That ledger becomes the timeline entry for compliance teams.
5. **Downstream automation** – When you feed VectorScan output into pipeline gates, capture `payload.status` (PASS/FAIL) and `metrics.compliance_score` so you can make release decisions programmatic (e.g., block deploy when score < 80 or `iam_drift.status == 'FAIL'`).
6. **Runtime traceability** – Forward the `environment` block (especially platform, python_version, terraform_version/source, strict/offline flags) to your evidence store so governance reviewers can prove which runtime produced each artifact.

## Metrics collector & summary

`run_scan.sh` already invokes `scripts/collect_metrics.py` to append every CLI payload into `metrics/vector_scan_metrics.log`. That log records `compliance_score`, `network_exposure_score`, `iam_drift` metadata, and the optional `terraform_tests` result so you can replay historical runs without rerunning VectorScan. The new `scripts/metrics_summary.py` reads that log, computes min/max/average statistics for every score, and writes `metrics/vector_scan_metrics_summary.json`, giving you a ready-made artifact for dashboards or CSV conversions.

To collect metrics manually or rerun the summary, invoke the scripts directly:

```bash
python scripts/collect_metrics.py scan-output.json --output-dir metrics
python scripts/metrics_summary.py --log-file metrics/vector_scan_metrics.log --summary-file metrics/vector_scan_metrics_summary.json
```

Both scripts tolerate invalid JSON and emit graceful messages while keeping one JSON line per invocation so you can tail or stream the log into your monitoring stack.

## Sample telemetry scraper

```python
import json
from pathlib import Path

payload = json.loads(Path("scan-output.json").read_text())
metrics = payload.get("metrics", {})

observability_payload = {
    "compliance_score": metrics.get("compliance_score"),
    "network_exposure_score": metrics.get("network_exposure_score"),
    "open_sg_count": metrics.get("open_sg_count"),
    "iam_risky_actions": metrics.get("iam_risky_actions"),
    "iam_drift_status": metrics.get("iam_drift", {}).get("status"),
}

# e.g., send to Datadog
# datadog_client.histogram("vectorscan.compliance", observability_payload["compliance_score"])
```

## Dashboard recommendations

- Plot the Compliance Score distribution per commit. Highlight gaps when the score dips after a merge.
- Track IAM drift failure rate; coordinate guardrail tasting when the rate spikes.
- Keep the Audit Ledger (YAML) alongside your release tickets and include `overall_score` and `audit_status` so auditors can trace incidents back to instrumentation.

## Telemetry consumers

`scripts/telemetry_consumer.py` is the downstream hook that turns the raw `metrics/vector_scan_metrics_summary.json` into dashboard-ready outputs. It writes a rolling CSV (`metrics/vector_scan_metrics_summary.csv`) so Grafana/Looker/Excel can ingest the latest snapshot and optionally emits StatsD packets (gauges, counters, timers, histograms) when you provide `--statsd-host`, making the metrics available to Datadog, Honeycomb, or any StatsD-compatible collector.

When StatsD is enabled, expect rich packets such as:

- Gauges for compliance/network exposure averages, IAM risky actions, drift failure rate, open security group counts, and policy error counts.
- Timers for `scan_duration_ms` (avg/p95/max/latest) so you can plot runtime SLOs.
- Counters for PASS/FAIL status deltas and `policy_error_events` so alerting can key off sudden spikes.
- Histograms per violation severity (critical/high/medium/low) to highlight how noisy plans are across builds.

Flip telemetry on/off with the new `--disable-statsd` CLI flag or environment overrides: export `VSCAN_DISABLE_STATSD=1` to force a skip (even if a host is configured) or `VSCAN_ENABLE_STATSD=1` to explicitly allow emission when higher-level automation injects defaults. Offline mode continues to short‑circuit everything.

Example workflow:

1. Run `./run_scan.sh ...` so `metrics/vector_scan_metrics.log` and `metrics/vector_scan_metrics_summary.json` are created.
2. Invoke `python scripts/telemetry_consumer.py --csv metrics/summary.csv --statsd-host=${STATSD_HOST}` in your pipeline step (append `--disable-statsd` or set `VSCAN_DISABLE_STATSD=1` when you need to silence the emitter temporarily).
3. The CSV rows can be imported into Grafana Cloud as a CSV data source, while the StatsD series (prefixed by `vectorscan.telemetry.*`) surface in Datadog dashboards for compliance averages, violation severities, scan durations, and status counters.

Treat the CSV and StatsD emission as the canonical downstream contract for telemetry consumers instead of parsing the raw audit ledger. This keeps the same generated timestamp, status counts, and compliance averages for every release run.

> **Offline mode:** export `VSCAN_OFFLINE=1` when running in air-gapped pipelines. `run_scan.sh`, `scripts/collect_metrics.py`, `scripts/metrics_summary.py`, and `scripts/telemetry_consumer.py` will short-circuit so no telemetry files or StatsD packets are produced, while the CLI output stays identical. Clear the flag to resume normal telemetry behavior.

## Related documentation

- `docs/release-distribution.md`: release checklist cross-check ensures the README and docs continue pointing to the signed bundle + Gumroad CTA with the vectorguard UTM tags.
- `docs/VectorScan.md`: the source of truth for VectorScan’s mission, policy coverage, and how telemetry feeds you toward the VectorGuard upgrade path.
- `docs/checklist.md`: Phase 5 monitoring tasks reference this instrumentation guidance so the metrics stay accurate after each release.

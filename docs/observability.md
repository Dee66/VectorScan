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
| `terraform_tests.status` | CLI `terraform_tests` block (when `--terraform-tests` enabled) | Mirror of the Terraform smoke test outcome so you can graph the reliability of the bundled Terraform binary.

When you run `scripts/run_scan.sh`, it replays the CLI JSON output into the `VectorGuard_Audit_Ledger` YAML (`overall_score`, `audit_status`, `CISO_Mandate`). Treat that ledger as the canonical artifact you persist for auditors and supply to any SIEM that understands YAML time series.

## Instrumentation patterns

1. **CI pipeline instrumentation** – Pipe `tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --json` to a file, parse the JSON, and post the relevant `metrics` fields to your telemetry backend (Prometheus pushgateway, StatsD, DataDog, etc.).
2. **Alerting on drift** – Monitor `iam_drift_report.status` and email/Slack the security team when it flips to `FAIL`. Include `iam_drift_report.items` for context so reviewers can triage bad IAM additions.
3. **Network exposure dashboards** – Use `network_exposure_score` and `open_sg_count` as gauges in vulnerability dashboards. When either dips below a threshold (e.g., score < 70 or `open_sg_count > 2`), trigger a slow-down step before deployment.
4. **Audit ledger persistence** – After `run_scan.sh` runs, store `audit_logs/*.yaml` (see `.github/workflows/validate-release.yml`) along with the signed bundle metadata. That ledger becomes the timeline entry for compliance teams.
5. **Downstream automation** – When you feed VectorScan output into pipeline gates, capture `payload.status` (PASS/FAIL) and `metrics.compliance_score` so you can make release decisions programmatic (e.g., block deploy when score < 80 or `iam_drift.status == 'FAIL'`).

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

`scripts/telemetry_consumer.py` is the downstream hook that turns the raw `metrics/vector_scan_metrics_summary.json` into dashboard-ready outputs. It writes a rolling CSV (`metrics/vector_scan_metrics_summary.csv`) so Grafana/Looker/Excel can ingest the latest snapshot and optionally emits StatsD gauges when you provide `--statsd-host`, making the metrics available to Datadog, Honeycomb, or any StatsD-compatible collector.

Example workflow:

1. Run `./run_scan.sh ...` so `metrics/vector_scan_metrics.log` and `metrics/vector_scan_metrics_summary.json` are created.
2. Invoke `python scripts/telemetry_consumer.py --csv metrics/summary.csv --statsd-host=${STATSD_HOST}` in your pipeline step.
3. The CSV rows can be imported into Grafana Cloud as a CSV data source, while the StatsD gauges appear in Datadog dashboards as `vectorscan.telemetry.compliance_score_avg`, `vectorscan.telemetry.network_exposure_score_avg`, etc.

Treat the CSV and StatsD emission as the canonical downstream contract for telemetry consumers instead of parsing the raw audit ledger. This keeps the same generated timestamp, status counts, and compliance averages for every release run.

## Related documentation

- `docs/release-distribution.md`: release checklist cross-check ensures the README and docs continue pointing to the signed bundle + Gumroad CTA with the vectorguard UTM tags.
- `docs/VectorScan.md`: the source of truth for VectorScan’s mission, policy coverage, and how telemetry feeds you toward the VectorGuard upgrade path.
- `docs/checklist.md`: Phase 5 monitoring tasks reference this instrumentation guidance so the metrics stay accurate after each release.

````markdown
# VectorScan Output Schema Reference

The sections below are ordered alphabetically by field family so engineers and doc consumers can align schema expectations quickly while honoring INIT-013 parity annotations.

## badge_eligible

- **Type:** boolean
- **Evaluator:** Emits a deterministic placeholder (`false` today) that GuardScore ingests as scaffolding.
- **CLI:** Owns the user-visible value and recomputes eligibility after replaying policy-pack verdicts. CLI runs may flip the flag to `true` even when the evaluator placeholder remained `false` (captured during INIT-012 multi-run sweeps).
- **Notes:** Tagged as CLI-owned in `product/spec.yml`; downstream experiences must treat the CLI value as source of truth.

## parity table

| Field | Evaluator Behavior | CLI Behavior | Notes |
| --- | --- | --- | --- |
| `badge_eligible` | Placeholder (`false`). | Final badge decision. | CLI overrides evaluator before printing. |
| `environment` | Minimal inferred stage + providers/resource_count. | Adds control flags, Terraform outcome, platform info. | Both remain deterministic. |
| `latency_ms` | Measures evaluator runtime and may floor to `0`. | Covers CLI + Terraform shim, typically ≥1 ms. | INIT-012 documented the ±1 ms jitter. |
| `metadata._control_flags` | Not emitted. | CLI adds `_control_flags` + `control` mirrors. | Keeps CLI UX aligned with legacy output. |
| `pillar_score_inputs` | Scaffolding for GuardScore ingestion. | Not emitted. | Explicitly marked as evaluator-only. |
| `policy_blocks.*` | Not emitted. | CLI exposes manifest provenance (version/hash/source/errors). | Supports transparency. |
| `remediation_ledger` | Not emitted; evaluator relies on audit ledger. | CLI publishes per-severity remediation aggregates. | Maintains legacy UX parity. |
| `required` | Lists canonical required keys. | Not emitted. | Marked as scaffolding. |
| `status` | Not emitted. | CLI surfaces PASS/FAIL for humans. | Derived from violation counts. |

## policy_blocks.*

- **Members:** `policy_manifest`, `policy_pack_hash`, `policy_version`, `policy_source_url`, `policy_errors`.
- **Type:** object + supporting strings.
- **Location:** CLI JSON output only.
- **Purpose:** Surfaces provenance for embedded policy packs (hash, source repo, manifest structure) so users can audit the policies that produced their scan.
- **Notes:** Tagged as CLI-only in `product/spec.yml`. The evaluator keeps metadata minimal and never emits these blocks.

## remediation fields

- **`remediation_hint`:** Present but intentionally blank (`""`) in free_scanner builds. Paid tiers may replace the placeholder with detailed instructions, but the public VectorScan release stays neutral.
- **`remediation_difficulty`:** One of `low`, `medium`, or `high`. The value mirrors the rule registry entry and is never omitted or null.
- **`remediation_metadata`:** Canonical payloads emit an empty object (`{}`) for every issue to satisfy schema requirements without bundling proprietary fixpack content.

The remediation trio is required on every canonical IssueDict; VectorScan supplies empty placeholders where proprietary artifacts used to live.

## remediation_ledger

- **`remediation_ledger`:** CLI-only top-level object summarizing remediation coverage. The structure is:

```json
{
  "per_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
  "rule_ids": ["PILLAR-AWS-001"],
  "paths": [
    {
      "id": "PILLAR-AWS-001",
      "severity": "critical",
      "remediation_metadata": {"fixpack_id": "PILLAR-AWS-001"}
    }
  ]
}
```

- `per_severity` mirrors the canonical severity ordering and always includes all buckets, even if zero.
- `rule_ids` is a deduplicated, severity-ordered list of issue identifiers.
- `paths` preserves the same ordering as `rule_ids`. Each entry includes the issue id, severity, and an empty `remediation_metadata` block so downstream automation can maintain shape compatibility without exposing proprietary patches.

- **Audit ledger:** The evaluator exposes `evaluation.audit_ledger`, which includes a nested `remediation_summary` block mirroring `remediation_ledger` to keep audit exports and JSON payloads in sync.

## reporting.*

- **Members:** `checks`, `counts`, `status`, `violation_count_by_severity`, `violation_severity_summary`, `violations`, `violations_struct`, `metrics`, `iam_drift_report`, `smell_report`, `suspicious_defaults`.
- **Type:** mix of scalars, arrays, and nested dicts.
- **Location:** CLI JSON only.
- **Purpose:** Preserves legacy CLI UX (PASS/FAIL banners, drift summaries, smell diagnostics) while the canonical evaluator focuses on GuardScore ingestion.
- **Notes:** Any additions to this group must remain deterministic and stay out of the evaluator payload unless the master schema adopts them explicitly.

## scan_version

- **Type:** string
- **Location:** Top-level field in every VectorScan payload (JSON) and echoed in CLI header/footer.
- **Format:** Semantic identifier `vMAJOR.MINOR.PATCH`.
- **Current value:** `v2.0.0`.
- **Purpose:** Indicates the deterministic GuardSuite pillar version responsible for producing the scan. Downstream automation can reason about feature availability and gate schema migrations with this value.
- **Determinism:** The value is constant for a given release train and does not change within a single execution, ensuring reproducible outputs across identical inputs.

## scaffolding fields

- **Members:** `pillar_score_inputs`, `required`, `issue_required_fields`, `severity_keys`, `guardscore_badge`, `percentile_placeholder`, `playground_summary`, `upgrade_hint`.
- **Type:** arrays/objects emitted by the canonical evaluator only.
- **Purpose:** Provide GuardScore and schema validators with self-describing metadata without exposing it in user-facing CLI output.
- **Notes:** INIT-013 marked `pillar_score_inputs` and `required` explicitly as scaffolding in both the spec and schema documentation; any changes require evaluator approval only.

````

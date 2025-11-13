#!/usr/bin/env bash
set -euo pipefail

# run_scan.sh: Run VectorScan on a tfplan.json and generate an Audit Ledger YAML.
# Usage:
#   ./run_scan.sh -i examples/aws-pgvector-rag/tfplan-pass.json -e dev-eu-west-1 -o audit_logs/vectorguard_ledger.yaml

PLAN="examples/aws-pgvector-rag/tfplan-pass.json"
ENVIRONMENT="dev"
OUT="audit_logs/vectorguard_ledger.yaml"

while getopts ":i:e:o:" opt; do
  case $opt in
    i) PLAN="$OPTARG" ;;
    e) ENVIRONMENT="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    *) echo "Usage: $0 -i <tfplan.json> -e <environment> -o <ledger.yaml>" >&2; exit 2 ;;
  esac
done

if [ ! -f "$PLAN" ]; then
  echo "Error: plan not found: $PLAN" >&2
  exit 2
fi

# Ensure output directory
mkdir -p "$(dirname "$OUT")"

# Capture VectorScan JSON once to avoid multiple executions (tolerate non-zero exit)
JSON_FILE=$(mktemp)
VS_JSON=$(python3 tools/vectorscan/vectorscan.py "$PLAN" --json || true)
printf "%s" "$VS_JSON" > "$JSON_FILE"

# Use embedded Python to parse JSON (avoid jq dependency)
PY_PARSE=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import sys, json
import os
with open(os.environ['JSON_FILE']) as fh:
  data = json.load(fh)
violations = data.get("violations", []) or []
metrics = data.get("metrics", {}) or {}
drift = data.get("iam_drift_report", {}) or {}
def has_policy(prefix: str) -> bool:
  return any(isinstance(v, str) and v.startswith(prefix) for v in violations)
encryption = "FAIL" if has_policy("P-SEC-001") else "PASS"
tagging = "FAIL" if has_policy("P-FIN-001") else "PASS"
network_score = int(metrics.get("network_exposure_score", 100) or 0)
network = "PASS" if network_score == 100 else "FAIL"
iam_risky = int(metrics.get("iam_risky_actions", 0) or 0)
iam = "FAIL" if iam_risky > 0 else "PASS"
iam_drift = (drift.get("status") or "PASS").upper()
overall = int(metrics.get("compliance_score", 100) or 0)
print("\n".join([
  f"ENCRYPTION={encryption}",
  f"TAGGING={tagging}",
  f"NETWORK={network}",
  f"IAM={iam}",
  f"IAM_DRIFT={iam_drift}",
  f"SCORE={overall}",
]))
PY
)

# Read parsed values
eval "$PY_PARSE"

STAMP=$(date -u +"%Y-%m-%dT%H:%MZ")

EVIDENCE=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import sys, json, os
with open(os.environ['JSON_FILE']) as fh:
  d = json.load(fh)
items = (d.get('iam_drift_report') or {}).get('items') or []
lines = []
for it in items:
    rtype = it.get('resource_type','')
    rname = it.get('resource_name','')
    adds = it.get('risky_additions', [])
    lines.append(f"  - resource: {rtype}.{rname}")
    if adds:
        lines.append("    risky_additions:")
        for a in adds:
            lines.append(f"      - {a}")
    else:
        lines.append("    risky_additions: []")
print("\n".join(lines))
PY
)

cat > "$OUT" <<YAML
VectorGuard_Audit_Ledger:
  timestamp: $STAMP
  environment: $ENVIRONMENT
  encryption: $ENCRYPTION
  iam: $IAM
  iam_drift: $IAM_DRIFT
  network: $NETWORK
  tagging: $TAGGING
  audit_status: $([ "$ENCRYPTION$IAM$IAM_DRIFT$NETWORK$TAGGING" = "PASSPASSPASSPASSPASS" ] && echo COMPLIANT || echo NON_COMPLIANT)
  overall_score: ${SCORE}/100
  iam_drift_evidence:
$EVIDENCE
YAML

echo "Audit Ledger Generated: $OUT"
exit 0

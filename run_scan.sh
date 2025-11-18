#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
AUDIT_ROOT="$REPO_ROOT/audit_logs"
mkdir -p "$AUDIT_ROOT"

if [ -z "${PYTHONPATH:-}" ]; then
  export PYTHONPATH="$REPO_ROOT"
else
  export PYTHONPATH="$REPO_ROOT:$PYTHONPATH"
fi

OFFLINE_MODE=1

if [ -n "${VSCAN_ALLOW_NETWORK:-}" ]; then
  _allow_norm="$(printf '%s' "${VSCAN_ALLOW_NETWORK}" | tr '[:upper:]' '[:lower:]')"
  case "${_allow_norm}" in
    1|true|yes|on)
      OFFLINE_MODE=0
      ;;
    0|false|no|off)
      OFFLINE_MODE=1
      ;;
  esac
fi

if [ -n "${VSCAN_OFFLINE:-}" ]; then
  _offline_norm="$(printf '%s' "${VSCAN_OFFLINE}" | tr '[:upper:]' '[:lower:]')"
  case "${_offline_norm}" in
    1|true|yes|on)
      OFFLINE_MODE=1
      ;;
    0|false|no|off)
      OFFLINE_MODE=0
      ;;
  esac
fi

# run_scan.sh: Run VectorScan on a tfplan.json and generate an Audit Ledger YAML.
# Usage:
#   ./run_scan.sh -i examples/aws-pgvector-rag/tfplan-pass.json -e dev-eu-west-1 -o audit_logs/vectorscan_ledger.yaml

PLAN="examples/aws-pgvector-rag/tfplan-pass.json"
ENVIRONMENT="dev"
OUT="audit_logs/vectorscan_ledger.yaml"

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

if ! INPUT_FILE=$(python3 - "$PLAN" "$REPO_ROOT" <<'PY'
import os, sys
plan = os.path.realpath(sys.argv[1])
root = os.path.realpath(sys.argv[2])
prefix = root + os.sep
if plan == root or plan.startswith(prefix):
    print(os.path.relpath(plan, root))
else:
    print(plan)
PY
); then
  echo "Error: failed to normalize input file path" >&2
  exit 2
fi

# Resolve and validate audit ledger output path
if ! SAFE_OUT=$(python3 - "$REPO_ROOT" "$AUDIT_ROOT" "$OUT" <<'PY'
import os, sys
repo_root = os.path.realpath(sys.argv[1])
audit_root = os.path.realpath(sys.argv[2])
candidate = sys.argv[3]
if not os.path.isabs(candidate):
    candidate = os.path.join(repo_root, candidate)
resolved = os.path.realpath(candidate)
prefix = audit_root + os.sep
if not (resolved == audit_root or resolved.startswith(prefix)):
    sys.stderr.write(f"Error: audit ledger output must stay under {audit_root}. Requested: {resolved}\n")
    sys.exit(2)
print(resolved)
PY
); then
  exit 2
fi
OUT="$SAFE_OUT"

# Ensure output directory inside audit_logs
mkdir -p "$(dirname "$OUT")"

# Capture VectorScan JSON once to avoid multiple executions (tolerate non-zero exit)
JSON_FILE=$(python3 - <<'PY'
import os
import tempfile

fd, path = tempfile.mkstemp(prefix="vectorscan-json-", suffix=".json")
os.close(fd)
print(path)
PY
)
trap 'rm -f "$JSON_FILE"' EXIT
VS_JSON=$(python3 tools/vectorscan/vectorscan.py "$PLAN" --json || true)
printf "%s" "$VS_JSON" > "$JSON_FILE"

if [ "$OFFLINE_MODE" -eq 0 ]; then
  # Record telemetry for downstream monitoring (non-fatal)
  python3 scripts/collect_metrics.py "$JSON_FILE" || true
  python3 scripts/metrics_summary.py \
    --log-file metrics/vector_scan_metrics.log \
    --summary-file metrics/vector_scan_metrics_summary.json || true
fi

# Use embedded Python to parse JSON (avoid jq dependency)
PY_PARSE=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import sys, json, os, shlex
with open(os.environ['JSON_FILE']) as fh:
  data = json.load(fh)
violations = data.get("violations", []) or []
metrics = data.get("metrics", {}) or {}
drift = data.get("iam_drift_report", {}) or {}
suspicious_defaults = data.get("suspicious_defaults", []) or []
vector_version = data.get("vectorscan_version", "unknown")
policy_version = data.get("policy_version", "unknown")
schema_version = data.get("schema_version", "unknown")
policy_pack_hash = data.get("policy_pack_hash", "unknown")
smell_report = data.get("smell_report", {}) or {}
smell_level = smell_report.get("level", "low")
smell_summary = (smell_report.get("summary") or "No structural smells detected.").replace("\n", " ")
smell_count = len(smell_report.get("smells") or [])
env_meta = data.get("environment", {}) or {}
platform_name = env_meta.get("platform", "unknown")
platform_release = env_meta.get("platform_release", "unknown")
python_version = env_meta.get("python_version", "unknown")
python_impl = env_meta.get("python_implementation", "unknown")
terraform_version = env_meta.get("terraform_version", "not-run")
terraform_source = env_meta.get("terraform_source", "not-run")
strict_mode = "true" if env_meta.get("strict_mode") else "false"
offline_mode = "true" if env_meta.get("offline_mode") else "false"
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
duration = int(metrics.get("scan_duration_ms", 0) or 0)
parser_mode = metrics.get("parser_mode", "legacy") or "legacy"
resource_count = int(metrics.get("resource_count", data.get("plan_metadata", {}).get("resource_count", 0)) or 0)
pairs = [
  ("ENCRYPTION", encryption),
  ("TAGGING", tagging),
  ("NETWORK", network),
  ("IAM", iam),
  ("IAM_DRIFT", iam_drift),
  ("SCORE", overall),
  ("PLAN_RISK_PROFILE", data.get('plan_risk_profile', 'unknown')),
  ("SUSPICIOUS_DEFAULTS", len(suspicious_defaults)),
  ("PLAN_SMELL_LEVEL", smell_level),
  ("PLAN_SMELL_COUNT", smell_count),
  ("PLAN_SMELL_SUMMARY", smell_summary),
  ("VECTORSCAN_VERSION", vector_version),
  ("POLICY_VERSION", policy_version),
  ("SCHEMA_VERSION", schema_version),
  ("POLICY_PACK_HASH", policy_pack_hash),
  ("ENV_PLATFORM", platform_name),
  ("ENV_PLATFORM_RELEASE", platform_release),
  ("ENV_PYTHON_VERSION", python_version),
  ("ENV_PYTHON_IMPL", python_impl),
  ("ENV_TERRAFORM_VERSION", terraform_version),
  ("ENV_TERRAFORM_SOURCE", terraform_source),
  ("ENV_STRICT_MODE", strict_mode),
  ("ENV_OFFLINE_MODE", offline_mode),
  ("SCAN_DURATION_MS", duration),
  ("PARSER_MODE", parser_mode),
  ("RESOURCE_COUNT", resource_count),
]
print("\n".join(f"{key}={shlex.quote(str(value))}" for key, value in pairs))
PY
)

# Read parsed values
eval "$PY_PARSE"

STAMP=$(python3 - <<'PY'
from tools.vectorscan.time_utils import deterministic_isoformat
print(deterministic_isoformat(), end='')
PY
)

EVIDENCE_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

items = (payload.get('iam_drift_report') or {}).get('items') or []
print("  evidence:")
if not items:
  print("    iam_drift: []")
else:
  print("    iam_drift:")
  for record in items:
    rtype = record.get('resource_type', '').strip() or 'resource'
    rname = record.get('resource_name', '').strip() or 'unknown'
    resource = f"{rtype}.{rname}".strip('.')
    print("      - resource: " + json.dumps(resource, ensure_ascii=False))
    additions = record.get('risky_additions') or []
    if additions:
      print("        risky_additions:")
      for addition in additions:
        print("          - " + json.dumps(addition, ensure_ascii=False))
    else:
      print("        risky_additions: []")
PY
)

POLICY_ERRORS_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

errors = payload.get('policy_errors') or []
if not errors:
  print("  policy_errors: []")
else:
  print("  policy_errors:")
  for err in errors:
    policy = err.get('policy', 'unknown')
    message = err.get('error', '') or ''
    print(f"    - policy: {json.dumps(policy, ensure_ascii=False)}")
    print(f"      error: {json.dumps(message, ensure_ascii=False)}")
PY
)

SEVERITY_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

LEVELS = ["critical", "high", "medium", "low"]

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

summary = payload.get('violation_severity_summary') or {}
print("  violation_severity_summary:")
for level in LEVELS:
  value = summary.get(level, 0) or 0
  print(f"    {level}: {value}")
PY
)

PLAN_RISK_FACTORS_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

factors = payload.get('plan_risk_factors') or []
if not factors:
  print("  plan_risk_factors: []")
else:
  print("  plan_risk_factors:")
  for item in factors:
    print(f"    - {json.dumps(item, ensure_ascii=False)}")
PY
)

SMELL_DETAILS_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

report = payload.get('smell_report') or {}
smells = report.get('smells') or []
if not smells:
  print("    details: []")
else:
  print("    details:")
  for smell in smells:
    identifier = smell.get('id', 'smell') or 'smell'
    level = smell.get('level', 'low') or 'low'
    message = smell.get('message', '') or ''
    evidence = smell.get('evidence') or {}
    print(f"      - id: {json.dumps(identifier, ensure_ascii=False)}")
    print(f"        level: {json.dumps(level, ensure_ascii=False)}")
    print(f"        message: {json.dumps(message, ensure_ascii=False)}")
    print(f"        evidence: {json.dumps(evidence, ensure_ascii=False)}")
PY
)

PLAN_METADATA_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

plan_metadata = payload.get('plan_metadata') or {}
modules = plan_metadata.get('modules') or {}
resource_types = plan_metadata.get('resource_types') or {}
providers = plan_metadata.get('providers') or []
change_summary = plan_metadata.get('change_summary') or {}
resources_by_type = plan_metadata.get('resources_by_type') or {}
plan_slo = plan_metadata.get('plan_slo') or {}
observed = plan_slo.get('observed') or {}
thresholds = plan_slo.get('thresholds') or {}

def _bool(value):
  return 'true' if bool(value) else 'false'

def _print_resources_by_type():
  if not resources_by_type:
    print("    resources_by_type: {}")
    return
  print("    resources_by_type:")
  for key in sorted(resources_by_type):
    stats = resources_by_type.get(key) or {}
    print(f"      {key}:")
    print(f"        planned: {stats.get('planned', 0) or 0}")
    print(f"        adds: {stats.get('adds', 0) or 0}")
    print(f"        changes: {stats.get('changes', 0) or 0}")
    print(f"        destroys: {stats.get('destroys', 0) or 0}")

print("  plan_metadata:")
print(f"    resource_count: {plan_metadata.get('resource_count', 0) or 0}")
print(f"    module_count: {plan_metadata.get('module_count', 0) or 0}")
if resource_types:
  print("    resource_types:")
  for key in sorted(resource_types):
    print(f"      {key}: {resource_types[key]}")
else:
  print("    resource_types: {}")
if providers:
  print("    providers:")
  for provider in sorted(providers):
    print(f"      - {provider}")
else:
  print("    providers: []")
print("    modules:")
print(f"      root: {modules.get('root', 'root')}")
print(f"      with_resources: {modules.get('with_resources', 0) or 0}")
print(f"      child_module_count: {modules.get('child_module_count', 0) or 0}")
print(f"      has_child_modules: {_bool(modules.get('has_child_modules'))}")
print("    change_summary:")
print(f"      adds: {change_summary.get('adds', 0) or 0}")
print(f"      changes: {change_summary.get('changes', 0) or 0}")
print(f"      destroys: {change_summary.get('destroys', 0) or 0}")
_print_resources_by_type()
file_size_mb = plan_metadata.get('file_size_mb')
if file_size_mb is None:
  file_size_mb = 0
print(f"    file_size_mb: {file_size_mb}")
print(f"    file_size_bytes: {plan_metadata.get('file_size_bytes', 0) or 0}")
print(f"    parse_duration_ms: {plan_metadata.get('parse_duration_ms', 0) or 0}")
print(f"    exceeds_threshold: {_bool(plan_metadata.get('exceeds_threshold'))}")
if plan_slo:
  print("    plan_slo:")
  print("      observed:")
  print(f"        resource_count: {observed.get('resource_count', 0) or 0}")
  print(f"        parse_duration_ms: {observed.get('parse_duration_ms', 0) or 0}")
  print(f"        file_size_bytes: {observed.get('file_size_bytes', 0) or 0}")
  if thresholds:
    print("      thresholds:")
    fast = thresholds.get('fast_path') or {}
    large = thresholds.get('large_plan') or {}
    print("        fast_path:")
    print(f"          max_resources: {fast.get('max_resources', 0) or 0}")
    print(f"          max_parse_ms: {fast.get('max_parse_ms', 0) or 0}")
    print("        large_plan:")
    print(f"          max_resources: {large.get('max_resources', 0) or 0}")
    print(f"          max_parse_ms: {large.get('max_parse_ms', 0) or 0}")
    file_limit = thresholds.get('file_size_limit_bytes', 0) or 0
    print(f"        file_size_limit_bytes: {file_limit}")
  print(f"      active_window: {plan_slo.get('active_window', 'fast_path')}")
  breach = plan_slo.get('breach_reason')
  if breach is None:
    print("      breach_reason: null")
  else:
    print(f"      breach_reason: {breach}")
else:
  print("    plan_slo: {}")
PY
)

VIOLATIONS_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

violations = payload.get('violations') or []
if not violations:
  print("  violations: []")
else:
  print("  violations:")
  for violation in violations:
    print(f"    - {json.dumps(violation, ensure_ascii=False)}")
PY
)

TERRAFORM_TEST_BLOCK=$(JSON_FILE="$JSON_FILE" python3 - <<'PY'
import json, os

def _print_multiline(label: str, value: str):
  print(f"    {label}: |")
  lines = (value or "").splitlines() or [""]
  for line in lines:
    print(f"      {line}")

with open(os.environ['JSON_FILE']) as fh:
  payload = json.load(fh)

tests = payload.get('terraform_tests') or {}
print("  terraform_test_results:")
if not tests:
  print("    status: not_run")
else:
  ordered = [
    'status',
    'version',
    'binary',
    'source',
    'strategy',
    'message',
    'returncode',
  ]
  for key in ordered:
    value = tests.get(key)
    if value is None:
      print(f"    {key}: null")
    else:
      print(f"    {key}: {json.dumps(value, ensure_ascii=False)}")
  for stream in ('stdout', 'stderr'):
    value = tests.get(stream)
    if value is None:
      print(f"    {stream}: null")
    else:
      _print_multiline(stream, str(value))
PY
)

cat > "$OUT" <<YAML
VectorScan_Audit_Ledger:
  timestamp: $STAMP
  environment: $ENVIRONMENT
  input_file: $INPUT_FILE
  environment_metadata:
    platform: $ENV_PLATFORM
    platform_release: $ENV_PLATFORM_RELEASE
    python_version: $ENV_PYTHON_VERSION
    python_implementation: $ENV_PYTHON_IMPL
    terraform_version: $ENV_TERRAFORM_VERSION
    terraform_source: $ENV_TERRAFORM_SOURCE
    strict_mode: $ENV_STRICT_MODE
    offline_mode: $ENV_OFFLINE_MODE
$PLAN_METADATA_BLOCK
  vectorscan_version: $VECTORSCAN_VERSION
  policy_version: $POLICY_VERSION
  schema_version: $SCHEMA_VERSION
  policy_pack_hash: $POLICY_PACK_HASH
${POLICY_ERRORS_BLOCK}
${VIOLATIONS_BLOCK}
${SEVERITY_BLOCK}
  plan_risk_profile: $PLAN_RISK_PROFILE
${PLAN_RISK_FACTORS_BLOCK}
  smell_report:
    level: $PLAN_SMELL_LEVEL
    summary: $PLAN_SMELL_SUMMARY
    finding_count: $PLAN_SMELL_COUNT
${SMELL_DETAILS_BLOCK}
  encryption: $ENCRYPTION
  iam: $IAM
  iam_drift: $IAM_DRIFT
  network: $NETWORK
  tagging: $TAGGING
  audit_status: $([ "$ENCRYPTION$IAM$IAM_DRIFT$NETWORK$TAGGING" = "PASSPASSPASSPASSPASS" ] && echo COMPLIANT || echo NON_COMPLIANT)
  overall_score: ${SCORE}/100
  scan_duration_ms: $SCAN_DURATION_MS
  parser_mode: $PARSER_MODE
  resource_count: $RESOURCE_COUNT
${EVIDENCE_BLOCK}
${TERRAFORM_TEST_BLOCK}
YAML

echo "Audit Ledger Generated: $OUT"
exit 0

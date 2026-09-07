#!/usr/bin/env bash
#
# run-review.sh — trigger the access-review Lambda on demand and print results.
#
# Usage:
#   AWS_PROFILE=terraform-lab2 ./run-review.sh
#   ./run-review.sh --profile terraform-lab2
#
# Requires: terraform (for outputs), aws cli, python3. Run from this directory.
set -euo pipefail

PROFILE="${AWS_PROFILE:-}"
if [[ "${1:-}" == "--profile" && -n "${2:-}" ]]; then
  PROFILE="$2"
fi
[[ -n "$PROFILE" ]] && export AWS_PROFILE="$PROFILE"

cd "$(dirname "$0")"

FN="$(terraform output -raw lambda_function_name)"
BUCKET="$(terraform output -raw report_bucket)"
REGION="$(terraform output -raw log_group >/dev/null 2>&1 && echo us-east-1 || echo us-east-1)"

echo "==> Invoking $FN ..."
OUT="$(mktemp)"
aws lambda invoke \
  --function-name "$FN" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --region "$REGION" \
  "$OUT" >/dev/null

echo "==> Result:"
python3 - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  account : {d.get('account_id')}")
print(f"  findings: {d.get('finding_count')}")
print(f"  s3 key  : {d.get('report_s3_key')}")
print("  ---- summary ----")
for line in (d.get("summary") or "").splitlines():
    print("  " + line)
PY

KEY="$(python3 -c "import json,sys; print(json.load(open('$OUT')).get('report_s3_key',''))")"
echo
echo "==> Full CSV: s3://$BUCKET/$KEY"
echo "    Download: aws s3 cp s3://$BUCKET/$KEY ./latest-report.csv"

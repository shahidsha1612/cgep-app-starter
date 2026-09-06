#!/usr/bin/env bash
# Verifies one signed evidence bundle in the S3 evidence vault end to end:
#   1. Cosign signature verifies against the public Sigstore transparency log.
#   2. SHA-256 of each downloaded file is shown (cosign's own verification
#      already confirms these bytes are exactly what was signed).
#   3. S3 Object Lock retention is still active on every object.
#
# Usage: scripts/verify-evidence.sh [<commit-sha>]
#   With no argument, verifies the most recent evidence bundle in the vault.

set -euo pipefail

cd "$(dirname "$0")/../terraform"

REPO="${GRC_REPO:-shahidsha1612/cgep-capstone}"
BUCKET=$(terraform output -raw evidence_bucket)
SHA="${1:-}"

if [ -z "$SHA" ]; then
  SHA=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "evidence/" \
    --query 'sort_by(Contents, &LastModified)[-1].Key' --output text \
    | cut -d/ -f2)
fi

echo "Verifying evidence bundle: evidence/$SHA/"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

FILES="tfplan.json evidence-manifest.json"
FAIL=0

for f in $FILES; do
  aws s3 cp "s3://$BUCKET/evidence/$SHA/$f" . --quiet
  aws s3 cp "s3://$BUCKET/evidence/$SHA/$f.sig" . --quiet
  aws s3 cp "s3://$BUCKET/evidence/$SHA/$f.pem" . --quiet
done

for f in $FILES; do
  echo ""
  echo "--- $f ---"

  echo -n "SHA-256: "
  sha256sum "$f" | cut -d' ' -f1

  if cosign verify-blob \
      --certificate "$f.pem" \
      --signature "$f.sig" \
      --certificate-identity-regexp "^https://github.com/${REPO}/" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$f" > /dev/null 2>&1; then
    echo "Cosign signature: VERIFIED"
  else
    echo "Cosign signature: FAILED"
    FAIL=1
  fi

  for suffix in "" ".sig" ".pem"; do
    MODE=$(aws s3api get-object-retention --bucket "$BUCKET" \
      --key "evidence/$SHA/$f$suffix" --query 'Retention.Mode' --output text 2>/dev/null || echo "")
    UNTIL=$(aws s3api get-object-retention --bucket "$BUCKET" \
      --key "evidence/$SHA/$f$suffix" --query 'Retention.RetainUntilDate' --output text 2>/dev/null || echo "")
    if [ -z "$MODE" ]; then
      echo "Object Lock ($f$suffix): NOT SET"
      FAIL=1
    else
      echo "Object Lock ($f$suffix): $MODE until $UNTIL"
    fi
  done
done

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "CHAIN INTACT"
  exit 0
else
  echo "CHAIN BROKEN"
  exit 1
fi

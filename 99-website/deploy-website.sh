#!/usr/bin/env bash
set -euo pipefail

ENV="${1:-}"

if [[ -z "$ENV" ]] || [[ "$ENV" != "dev" && "$ENV" != "prod" ]]; then
  echo "Usage: ./deploy-website.sh {dev|prod}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/env.config.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "ERROR: env.config.json not found"
  exit 1
fi

S3_BUCKET=$(jq -r ".${ENV}.s3_bucket" "$CONFIG_FILE")
CLOUDFRONT_ID=$(jq -r ".${ENV}.cloudfront_distribution_id" "$CONFIG_FILE")
FQDN=$(jq -r ".${ENV}.fqdn" "$CONFIG_FILE")

if [[ "$S3_BUCKET" == "REPLACE_WITH"* ]]; then
  echo "ERROR: S3 bucket not configured for '$ENV' in env.config.json"
  exit 1
fi

if [[ "$CLOUDFRONT_ID" == "REPLACE_WITH"* ]]; then
  echo "ERROR: CloudFront distribution ID not configured for '$ENV' in env.config.json"
  exit 1
fi

echo "==> Deploying to $ENV ($FQDN)"
echo "    S3 Bucket: $S3_BUCKET"
echo "    CloudFront: $CLOUDFRONT_ID"
echo ""

# Build the site
echo "==> Building..."
npm run build

# Sync to S3
echo "==> Syncing to s3://$S3_BUCKET..."
aws s3 sync dist/ "s3://$S3_BUCKET" \
  --delete \
  --cache-control "public, max-age=31536000, immutable" \
  --exclude "*.html" \
  --exclude "robots.txt" \
  --exclude "sitemap*.xml"

# HTML and metadata files get shorter cache
aws s3 sync dist/ "s3://$S3_BUCKET" \
  --delete \
  --cache-control "public, max-age=300, must-revalidate" \
  --include "*.html" \
  --include "robots.txt" \
  --include "sitemap*.xml" \
  --exclude "*" 

# Invalidate CloudFront cache
echo "==> Invalidating CloudFront distribution $CLOUDFRONT_ID..."
aws cloudfront create-invalidation \
  --distribution-id "$CLOUDFRONT_ID" \
  --paths "/*" \
  --no-cli-pager

echo ""
echo "==> Deployed to $ENV successfully!"
echo "    https://$FQDN"

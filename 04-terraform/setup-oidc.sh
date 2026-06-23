#!/usr/bin/env bash
#
# Sets up everything needed for GitHub Actions OIDC -> AWS:
#   1. S3 state bucket + DynamoDB lock table
#   2. OIDC identity provider in AWS
#   3. IAM roles for dev and prod
#   4. GitHub environments + variables
#
# Prerequisites:
#   - aws cli configured with admin credentials
#   - gh cli authenticated (gh auth login)
#
# Usage: ./setup-oidc.sh
#
set -euo pipefail

#─── CONFIG ────────────────────────────────────────────────────────
AWS_REGION="eu-west-2"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
GITHUB_ORG="sjmnetworks"
GITHUB_REPO="clarisys"
TF_STATE_BUCKET="clarisys-terraform-state"
OIDC_THUMBPRINT="6938fd4d98bab03faadb97b34396831e3780aea1"
#───────────────────────────────────────────────────────────────────

echo "AWS Account: $AWS_ACCOUNT_ID"
echo "GitHub Repo: $GITHUB_ORG/$GITHUB_REPO"
echo ""

# ─── 1. Terraform State Backend ──────────────────────────────────
echo "==> Creating S3 state bucket: $TF_STATE_BUCKET"
if aws s3api head-bucket --bucket "$TF_STATE_BUCKET" 2>/dev/null; then
  echo "    Bucket already exists, skipping"
else
  aws s3api create-bucket \
    --bucket "$TF_STATE_BUCKET" \
    --region "$AWS_REGION" \
    --create-bucket-configuration LocationConstraint="$AWS_REGION"

  aws s3api put-bucket-versioning \
    --bucket "$TF_STATE_BUCKET" \
    --versioning-configuration Status=Enabled

  aws s3api put-bucket-encryption \
    --bucket "$TF_STATE_BUCKET" \
    --server-side-encryption-configuration '{
      "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }'

  aws s3api put-public-access-block \
    --bucket "$TF_STATE_BUCKET" \
    --public-access-block-configuration \
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi



# ─── 2. OIDC Identity Provider ───────────────────────────────────
OIDC_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"

echo "==> Creating OIDC identity provider for GitHub Actions"
if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_ARN" &>/dev/null; then
  echo "    OIDC provider already exists, skipping"
else
  aws iam create-open-id-connect-provider \
    --url "https://token.actions.githubusercontent.com" \
    --client-id-list "sts.amazonaws.com" \
    --thumbprint-list "$OIDC_THUMBPRINT"
  echo "    Created OIDC provider"
fi

# ─── 3. IAM Roles for dev and prod ───────────────────────────────
for ENV in dev prod; do
  ROLE_NAME="clarisys-website-github-${ENV}"

  echo "==> Creating IAM role: $ROLE_NAME"

  TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:${GITHUB_ORG}/${GITHUB_REPO}:environment:${ENV}"
        }
      }
    }
  ]
}
EOF
)

  PERMISSIONS_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3WebsiteBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketVersioning",
        "s3:PutBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:PutEncryptionConfiguration",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::clarisys-website-${ENV}",
        "arn:aws:s3:::clarisys-website-${ENV}/*"
      ]
    },
    {
      "Sid": "TerraformState",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${TF_STATE_BUCKET}",
        "arn:aws:s3:::${TF_STATE_BUCKET}/*"
      ]
    },

    {
      "Sid": "CloudFront",
      "Effect": "Allow",
      "Action": [
        "cloudfront:CreateDistribution",
        "cloudfront:UpdateDistribution",
        "cloudfront:DeleteDistribution",
        "cloudfront:GetDistribution",
        "cloudfront:ListDistributions",
        "cloudfront:TagResource",
        "cloudfront:UntagResource",
        "cloudfront:ListTagsForResource",
        "cloudfront:CreateInvalidation",
        "cloudfront:CreateOriginAccessControl",
        "cloudfront:DeleteOriginAccessControl",
        "cloudfront:GetOriginAccessControl",
        "cloudfront:UpdateOriginAccessControl",
        "cloudfront:CreateCachePolicy",
        "cloudfront:DeleteCachePolicy",
        "cloudfront:GetCachePolicy",
        "cloudfront:UpdateCachePolicy",
        "cloudfront:CreateResponseHeadersPolicy",
        "cloudfront:DeleteResponseHeadersPolicy",
        "cloudfront:GetResponseHeadersPolicy",
        "cloudfront:UpdateResponseHeadersPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ACM",
      "Effect": "Allow",
      "Action": [
        "acm:RequestCertificate",
        "acm:DeleteCertificate",
        "acm:DescribeCertificate",
        "acm:ListCertificates",
        "acm:AddTagsToCertificate",
        "acm:ListTagsForCertificate",
        "acm:RemoveTagsFromCertificate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Route53",
      "Effect": "Allow",
      "Action": [
        "route53:GetHostedZone",
        "route53:ChangeResourceRecordSets",
        "route53:ListResourceRecordSets",
        "route53:GetChange"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/*",
        "arn:aws:route53:::change/*"
      ]
    }
  ]
}
EOF
)

  if aws iam get-role --role-name "$ROLE_NAME" &>/dev/null; then
    echo "    Role already exists, updating trust policy"
    aws iam update-assume-role-policy \
      --role-name "$ROLE_NAME" \
      --policy-document "$TRUST_POLICY"
  else
    aws iam create-role \
      --role-name "$ROLE_NAME" \
      --assume-role-policy-document "$TRUST_POLICY" \
      --description "GitHub Actions OIDC role for clarisys website ${ENV}"
  fi

  POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/clarisys-website-${ENV}-deploy"

  if aws iam get-policy --policy-arn "$POLICY_ARN" &>/dev/null; then
    echo "    Policy exists, creating new version"
    # Delete oldest version if at limit (max 5)
    OLDEST=$(aws iam list-policy-versions --policy-arn "$POLICY_ARN" \
      --query 'Versions[?IsDefaultVersion==`false`]|[-1].VersionId' --output text)
    if [[ "$OLDEST" != "None" && -n "$OLDEST" ]]; then
      aws iam delete-policy-version --policy-arn "$POLICY_ARN" --version-id "$OLDEST" 2>/dev/null || true
    fi
    aws iam create-policy-version \
      --policy-arn "$POLICY_ARN" \
      --policy-document "$PERMISSIONS_POLICY" \
      --set-as-default
  else
    aws iam create-policy \
      --policy-name "clarisys-website-${ENV}-deploy" \
      --policy-document "$PERMISSIONS_POLICY" \
      --description "Permissions for clarisys website ${ENV} deployment"
  fi

  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "$POLICY_ARN"

  ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/$ROLE_NAME"
  echo "    Role ARN: $ROLE_ARN"

  # ─── 4. GitHub Environment + Variable ───────────────────────────
  echo "==> Setting up GitHub environment: $ENV"

  # Create environment (gh api handles idempotency)
  gh api --method PUT \
    "repos/${GITHUB_ORG}/${GITHUB_REPO}/environments/${ENV}" \
    --silent

  # Set AWS_ROLE_ARN variable on the environment
  gh api --method POST \
    "repos/${GITHUB_ORG}/${GITHUB_REPO}/environments/${ENV}/variables" \
    -f name=AWS_ROLE_ARN \
    -f value="$ROLE_ARN" \
    --silent 2>/dev/null || \
  gh api --method PATCH \
    "repos/${GITHUB_ORG}/${GITHUB_REPO}/environments/${ENV}/variables/AWS_ROLE_ARN" \
    -f value="$ROLE_ARN" \
    --silent

  echo "    Set AWS_ROLE_ARN=$ROLE_ARN on $ENV environment"
  echo ""
done

echo "==> Setup complete!"
echo ""
echo "Summary:"
echo "  State bucket:     s3://$TF_STATE_BUCKET"
echo "  Dev role:         arn:aws:iam::${AWS_ACCOUNT_ID}:role/clarisys-website-github-dev"
echo "  Prod role:        arn:aws:iam::${AWS_ACCOUNT_ID}:role/clarisys-website-github-prod"
echo "  GH environments:  dev, prod (with AWS_ROLE_ARN set)"
echo ""
echo "Next: update 04-terraform/environments/*.tfvars with your Route53 hosted_zone_id"

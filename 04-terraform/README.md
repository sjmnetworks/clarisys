# 04-terraform

Terraform configuration for Clarisys static website infrastructure (S3 + CloudFront + ACM).

## Environments

| Environment | Domain | tfvars |
|---|---|---|
| dev | `dev.clarisys.io` | `environments/dev.tfvars` |
| prod | `clarisys.io` | `environments/prod.tfvars` |

## Usage (GitHub Actions)

```bash
# Init with backend config
terraform init \
  -backend-config="bucket=clarisys-terraform-state" \
  -backend-config="key=website/${ENV}/terraform.tfstate" \
  -backend-config="region=eu-west-2" \
  -backend-config="dynamodb_table=terraform-locks"

# Plan
terraform plan -var-file=environments/${ENV}.tfvars -out=tfplan

# Apply
terraform apply tfplan
```

## Prerequisites

- Route53 hosted zone for `clarisys.io` (set `hosted_zone_id` in tfvars)
- S3 bucket for Terraform state
- DynamoDB table for state locking

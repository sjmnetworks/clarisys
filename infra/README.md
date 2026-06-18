# AWS Infrastructure - ECS Fargate Deployment

Terraform configuration for deploying the Firewall Policy Compliance API on AWS ECS Fargate.

## Architecture

- **ALB** with ACM TLS certificate (HTTPS termination)
- **ECS Fargate** task with API container + OPA sidecar
- **EFS** for persistent state (decision history, ROI metrics)
- **S3** with Object Lock for audit archive
- **ECR** for container image storage
- **CloudWatch Logs** for container log aggregation

## Prerequisites

- Terraform >= 1.5
- AWS CLI configured with appropriate credentials
- Docker (for building and pushing images)

## Quick Start

```bash
cd infra/
terraform init
terraform plan -var="domain_name=your-domain.com"
terraform apply -var="domain_name=your-domain.com"
```

## Deploy container image

After `terraform apply`, push the Docker image:

```bash
./scripts/deploy.sh
```

## Variables

| Name | Description | Default |
|------|-------------|---------|
| `aws_region` | AWS region | `eu-west-2` |
| `project_name` | Resource naming prefix | `firewall-api` |
| `domain_name` | Domain for ACM cert (optional) | `""` |
| `container_cpu` | Fargate task CPU units | `256` (0.25 vCPU) |
| `container_memory` | Fargate task memory MB | `512` |
| `desired_count` | Number of tasks | `1` |
| `enable_s3_audit` | Enable S3 audit backend | `true` |

#!/usr/bin/env bash
# Deploy script: build, push to ECR, and update ECS service.
# Usage: ./scripts/deploy.sh [tag]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TAG="${1:-latest}"

# Get Terraform outputs
cd "$REPO_ROOT/infra"
ECR_URL=$(terraform output -raw ecr_repository_url)
CLUSTER=$(terraform output -raw ecs_cluster_name)
SERVICE=$(terraform output -raw ecs_service_name)
REGION=$(terraform output -raw 2>/dev/null aws_region || echo "eu-west-2")

echo "==> Authenticating with ECR..."
aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "${ECR_URL%%/*}"

echo "==> Building Docker image..."
cd "$REPO_ROOT"
docker build -t "$ECR_URL:$TAG" .

echo "==> Pushing to ECR..."
docker push "$ECR_URL:$TAG"

echo "==> Updating ECS service (force new deployment)..."
aws ecs update-service \
  --cluster "$CLUSTER" \
  --service "$SERVICE" \
  --force-new-deployment \
  --region "$REGION" \
  --no-cli-pager

echo "==> Done. Service will roll out the new image."
echo "    Monitor: aws ecs describe-services --cluster $CLUSTER --services $SERVICE --query 'services[0].deployments'"

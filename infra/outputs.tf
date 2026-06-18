output "alb_dns_name" {
  description = "ALB DNS name - use this as your API endpoint"
  value       = aws_lb.main.dns_name
}

output "alb_url" {
  description = "Full HTTPS URL for the API"
  value       = "https://${aws_lb.main.dns_name}"
}

output "ecr_repository_url" {
  description = "ECR repository URL for docker push"
  value       = aws_ecr_repository.api.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.api.name
}

output "s3_audit_bucket" {
  description = "S3 bucket for audit archive"
  value       = var.enable_s3_audit ? aws_s3_bucket.audit[0].id : "disabled"
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for container logs"
  value       = aws_cloudwatch_log_group.api.name
}

output "audit_ui_url" {
  description = "Public audit upload UI URL"
  value       = "https://${aws_lb.main.dns_name}/audit/ui"
}

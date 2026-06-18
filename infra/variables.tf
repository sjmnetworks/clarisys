variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-west-2"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "firewall-api"
}

variable "domain_name" {
  description = "Domain name for ACM certificate (leave empty to skip cert creation and use ALB DNS)"
  type        = string
  default     = ""
}

variable "container_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU)"
  type        = number
  default     = 512
}

variable "container_memory" {
  description = "Fargate task memory in MB"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of ECS tasks to run"
  type        = number
  default     = 1
}

variable "enable_s3_audit" {
  description = "Enable S3 bucket for audit trail storage"
  type        = bool
  default     = true
}

variable "api_key_secret_arn" {
  description = "ARN of Secrets Manager secret containing pilot API keys JSON (optional)"
  type        = string
  default     = ""
}

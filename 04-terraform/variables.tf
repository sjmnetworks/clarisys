variable "environment" {
  description = "Environment name (dev or prod)"
  type        = string

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "Environment must be 'dev' or 'prod'."
  }
}

variable "aws_region" {
  description = "AWS region for S3 and other resources"
  type        = string
  default     = "eu-west-2"
}

variable "domain_name" {
  description = "Primary FQDN for the website"
  type        = string
}

variable "alternative_domains" {
  description = "Additional domain names for the CloudFront distribution"
  type        = list(string)
  default     = []
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for DNS validation"
  type        = string
}

variable "index_document" {
  description = "Index document for the S3 static website"
  type        = string
  default     = "index.html"
}

variable "error_document" {
  description = "Error document for the S3 static website"
  type        = string
  default     = "index.html"
}

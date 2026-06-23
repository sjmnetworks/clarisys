terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    # Configured via -backend-config in GitHub Actions
    # bucket  = "clarisys-terraform-state"
    # key     = "website/${var.environment}/terraform.tfstate"
    # region  = "eu-west-2"
    # encrypt = true
    # use_lockfile = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "clarisys-website"
      ManagedBy   = "terraform"
    }
  }
}

# ACM must be in us-east-1 for CloudFront
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "clarisys-website"
      ManagedBy   = "terraform"
    }
  }
}
